package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/example/appaudit/internal/classifier"
	"github.com/example/appaudit/internal/model"
	"github.com/example/appaudit/internal/provenance"
	"github.com/example/appaudit/internal/scanner"
)

const version = "2.0.0"

// Telemetry captures runtime execution duration, memory statistics, and network resolution metrics.
type Telemetry struct {
	Duration           time.Duration `json:"duration"`
	DurationMs         float64       `json:"time_taken_ms"`
	MemoryInUse        string        `json:"memory_in_use"`
	PeakMemory         string        `json:"peak_memory"`
	TotalMemoryHandled string        `json:"total_memory_handled"`
	MemoryCleanups     uint32        `json:"memory_cleanups"`
	ActiveTasks        int           `json:"active_tasks"`
	NetworkMode        string        `json:"network_mode"`
	NetworkEnabled     bool          `json:"network_enabled"`
	NetworkOffline     bool          `json:"network_offline"`
	NetworkLookups     int           `json:"network_lookups"`
	CacheHits          int           `json:"cache_hits"`
	RemoteLookups      int           `json:"remote_lookups"`
}

func main() {
	defer pauseIfStandalone()

	networkFlag := flag.String("network", "off", "Network mode: 'off' (local-first, 0ms), 'hash-only' (query known hashes), 'on' (full public resolution)")
	lookupOnlineFlag := flag.Bool("lookup-online", false, "Enable online resolution (alias for --network=on)")
	flag.BoolVar(lookupOnlineFlag, "online", false, "Enable online resolution (shorthand)")
	jsonFlag := flag.Bool("json", false, "Output results as formatted JSON to stdout")
	versionFlag := flag.Bool("version", false, "Print version information")
	flag.BoolVar(versionFlag, "v", false, "Print version information (shorthand)")
	helpFlag := flag.Bool("help", false, "Show help and usage information")
	flag.BoolVar(helpFlag, "h", false, "Show help and usage information (shorthand)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "AppAudit CLI - Endpoint Software Provenance Auditor (v%s)\n\n", version)
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  audit [flags]\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		fmt.Fprintf(os.Stderr, "  --network string          Network mode: 'off' (default), 'hash-only', or 'on'\n")
		fmt.Fprintf(os.Stderr, "  --lookup-online, -online  Enable online resolution (shorthand for --network=on)\n")
		fmt.Fprintf(os.Stderr, "  --json                    Print full classification array as pretty JSON to stdout\n")
		fmt.Fprintf(os.Stderr, "  -v, --version             Print version information\n")
		fmt.Fprintf(os.Stderr, "  -h, --help                Show help and usage\n")
	}

	flag.Parse()

	if *helpFlag {
		flag.Usage()
		return
	}

	if *versionFlag {
		fmt.Printf("appaudit v%s\n", version)
		return
	}

	netMode := *networkFlag
	if *lookupOnlineFlag {
		netMode = "on"
	}

	startTime := time.Now()

	// 1. Run platform discovery scanner
	sysScanner := scanner.New()
	rawApps, err := sysScanner.Scan()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error during system scan: %v\n", err)
	}

	// 2. Classify and reconcile applications using Evidence-Based Provenance Engine
	engine := classifier.New(classifier.ClassifierConfig{
		NetworkMode:        netMode,
		EnableOnlineLookup: (netMode == "on"),
	})
	classified := engine.ReconcileAndClassify(rawApps)

	// Sort alphabetically by classification, then name
	sort.Slice(classified, func(i, j int) bool {
		if classified[i].Classification != classified[j].Classification {
			return classified[i].Classification < classified[j].Classification
		}
		return strings.ToLower(classified[i].Name) < strings.ToLower(classified[j].Name)
	})

	elapsed := time.Since(startTime)
	netStats := engine.NetworkStats()
	telemetry := captureTelemetry(startTime, netStats, netMode)

	// 3. Render Output
	if *jsonFlag {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(classified); err != nil {
			fmt.Fprintf(os.Stderr, "Error encoding JSON output: %v\n", err)
			os.Exit(1)
		}
		printTelemetry(os.Stderr, telemetry)
		return
	}

	// Separate by tripartite classification: THIRD_PARTY, COMPANY, UNKNOWN
	var thirdParty []model.Application
	var company []model.Application
	var unknown []model.Application

	for _, app := range classified {
		switch app.Classification {
		case string(provenance.ClassificationThirdParty):
			thirdParty = append(thirdParty, app)
		case string(provenance.ClassificationCompany):
			company = append(company, app)
		default:
			unknown = append(unknown, app)
		}
	}

	printThirdPartyTable(thirdParty)
	fmt.Println()
	printCompanyTable(company)
	fmt.Println()
	printUnknownTable(unknown)
	fmt.Println()

	fmt.Fprintf(os.Stdout, "Discovery Summary: %d total apps discovered (%d Third-Party, %d Company, %d Unknown/Unresolved) in %s\n",
		len(classified), len(thirdParty), len(company), len(unknown), elapsed.Round(time.Millisecond))

	printTelemetry(os.Stdout, telemetry)

	// Follow-up interactive prompt for online verification if running in offline mode
	// and unresolved unknown applications exist (strictly in interactive terminal sessions).
	if !*jsonFlag && netMode == "off" && len(unknown) > 0 && isTerminal(os.Stdin) {
		eta := classifier.EstimateOnlineETA(unknown)
		fmt.Println()
		fmt.Printf("Would you like to run online provenance verification for unresolved/unknown apps? [y/N] (ETA: %s): ", eta)

		reader := bufio.NewReader(os.Stdin)
		input, err := reader.ReadString('\n')
		if err == nil {
			input = strings.TrimSpace(strings.ToLower(input))
			if input == "y" || input == "yes" {
				fmt.Println()
				fmt.Println("Running online provenance resolution (NSRL, GitHub Releases, Repology, Web Index)...")
				onlineStart := time.Now()

				engine.EnrichCandidates(classified)

				sort.Slice(classified, func(i, j int) bool {
					if classified[i].Classification != classified[j].Classification {
						return classified[i].Classification < classified[j].Classification
					}
					return strings.ToLower(classified[i].Name) < strings.ToLower(classified[j].Name)
				})

				var updatedThirdParty []model.Application
				var updatedCompany []model.Application
				var updatedUnknown []model.Application

				for _, app := range classified {
					switch app.Classification {
					case string(provenance.ClassificationThirdParty):
						updatedThirdParty = append(updatedThirdParty, app)
					case string(provenance.ClassificationCompany):
						updatedCompany = append(updatedCompany, app)
					default:
						updatedUnknown = append(updatedUnknown, app)
					}
				}

				fmt.Println()
				printThirdPartyTable(updatedThirdParty)
				fmt.Println()
				printCompanyTable(updatedCompany)
				fmt.Println()
				printUnknownTable(updatedUnknown)
				fmt.Println()

				onlineElapsed := time.Since(onlineStart)
				fmt.Fprintf(os.Stdout, "Online Resolution Complete: %d total apps (%d Third-Party, %d Company, %d Unknown/Unresolved) in %s\n",
					len(classified), len(updatedThirdParty), len(updatedCompany), len(updatedUnknown), onlineElapsed.Round(time.Millisecond))

				netStats := engine.NetworkStats()
				onlineTelemetry := captureTelemetry(startTime, netStats, "on")
				printTelemetry(os.Stdout, onlineTelemetry)
			}
		}
	}
}

func captureTelemetry(startTime time.Time, netStats classifier.NetworkStats, netMode string) Telemetry {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	elapsed := time.Since(startTime)

	return Telemetry{
		Duration:           elapsed,
		DurationMs:         float64(elapsed.Microseconds()) / 1000.0,
		MemoryInUse:        formatBytes(m.Alloc),
		PeakMemory:         formatBytes(m.HeapSys),
		TotalMemoryHandled: formatBytes(m.TotalAlloc),
		MemoryCleanups:     m.NumGC,
		ActiveTasks:        runtime.NumGoroutine(),
		NetworkMode:        netMode,
		NetworkEnabled:     netStats.Enabled || netMode != "off",
		NetworkOffline:     netStats.Offline,
		NetworkLookups:     netStats.NetworkLookups,
		CacheHits:          netStats.CacheHits,
		RemoteLookups:      netStats.RemoteLookups,
	}
}

func printTelemetry(w io.Writer, t Telemetry) {
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Memory & Performance Telemetry:")
	fmt.Fprintf(w, "  Time Taken:             %.1f ms\n", t.DurationMs)
	fmt.Fprintf(w, "  Memory in Use:          %s\n", t.MemoryInUse)
	fmt.Fprintf(w, "  Peak Memory:            %s\n", t.PeakMemory)
	fmt.Fprintf(w, "  Total Memory Handled:   %s\n", t.TotalMemoryHandled)
	fmt.Fprintf(w, "  Memory Cleanups:        %d\n", t.MemoryCleanups)
	fmt.Fprintf(w, "  Active Tasks:           %d\n", t.ActiveTasks)
	fmt.Fprintf(w, "  Network Mode:           %s\n", t.NetworkMode)
	if t.NetworkMode == "off" {
		fmt.Fprintf(w, "  Network Status:         Disabled (100%% Local-First)\n")
	} else if t.NetworkOffline {
		fmt.Fprintf(w, "  Network Status:         Offline (Socket Probe Failed)\n")
	} else {
		fmt.Fprintf(w, "  Network Lookups:        %d (Cache Hits: %d, Remote: %d)\n", t.NetworkLookups, t.CacheHits, t.RemoteLookups)
	}
}

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

func formatBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	suffix := "KB"
	switch exp {
	case 0:
		suffix = "KB"
	case 1:
		suffix = "MB"
	case 2:
		suffix = "GB"
	default:
		suffix = "TB"
	}
	return fmt.Sprintf("%.2f %s", float64(b)/float64(div), suffix)
}

// printThirdPartyTable formats Table 1: Third-Party / Public Software
func printThirdPartyTable(apps []model.Application) {
	title := fmt.Sprintf("[Third-Party / Public Commercial Software] (Count: %d)", len(apps))
	headers := []string{"Name", "Publisher", "Confidence", "SHA-256", "Evidence"}
	maxCaps := []int{24, 22, 11, 14, 46}

	if len(apps) == 0 {
		printEmptyTable(title, "(No verified third-party applications identified)")
		return
	}

	rows := make([][]string, len(apps))
	for i, app := range apps {
		pub := app.Publisher
		if pub == "" {
			pub = "-"
		}
		conf := app.Confidence
		if conf == "" {
			conf = "HIGH"
		}
		hash := truncateHash(app.SHA256)
		rows[i] = []string{
			app.Name,
			pub,
			conf,
			hash,
			app.Evidence,
		}
	}

	renderTable(title, headers, rows, maxCaps)
}

// printCompanyTable formats Table 2: Company / Internal Software
func printCompanyTable(apps []model.Application) {
	title := fmt.Sprintf("[Company-Owned / Internal Proprietary Software] (Count: %d)", len(apps))
	headers := []string{"Name", "Confidence", "Path", "Ownership Evidence"}
	maxCaps := []int{24, 11, 40, 42}

	if len(apps) == 0 {
		printEmptyTable(title, "(No explicitly verified company-owned applications identified)")
		return
	}

	rows := make([][]string, len(apps))
	for i, app := range apps {
		conf := app.Confidence
		if conf == "" {
			conf = "HIGH"
		}
		rows[i] = []string{
			app.Name,
			conf,
			app.Path,
			app.Evidence,
		}
	}

	renderTable(title, headers, rows, maxCaps)
}

// printUnknownTable formats Table 3: Unknown / Unresolved Provenance
func printUnknownTable(apps []model.Application) {
	title := fmt.Sprintf("[Unknown / Unresolved Provenance (No Public Match != Company)] (Count: %d)", len(apps))
	headers := []string{"Name", "Path", "SHA-256", "Primary Reason"}
	maxCaps := []int{22, 38, 14, 45}

	if len(apps) == 0 {
		printEmptyTable(title, "(All applications successfully resolved to verifiable provenance)")
		return
	}

	rows := make([][]string, len(apps))
	for i, app := range apps {
		hash := truncateHash(app.SHA256)
		reason := app.Evidence
		if len(app.Explanation) > 0 {
			reason = app.Explanation[len(app.Explanation)-1]
		}
		rows[i] = []string{
			app.Name,
			app.Path,
			hash,
			reason,
		}
	}

	renderTable(title, headers, rows, maxCaps)
}

func truncateHash(hash string) string {
	if len(hash) <= 12 {
		return hash
	}
	return hash[:6] + "..." + hash[len(hash)-4:]
}

func printEmptyTable(title, emptyMsg string) {
	totalLen := len(emptyMsg) + 4
	if len(title)+4 > totalLen {
		totalLen = len(title) + 4
	}
	if totalLen < 70 {
		totalLen = 70
	}

	border := "+" + strings.Repeat("-", totalLen-2) + "+"
	fmt.Println(border)
	fmt.Printf("| %-*s |\n", totalLen-4, title)
	fmt.Println(border)
	fmt.Printf("| %-*s |\n", totalLen-4, emptyMsg)
	fmt.Println(border)
}

func renderTable(title string, headers []string, rows [][]string, maxCaps []int) {
	colCount := len(headers)
	colWidths := make([]int, colCount)

	for i, h := range headers {
		colWidths[i] = len(h)
	}

	for _, row := range rows {
		for i := 0; i < colCount && i < len(row); i++ {
			if len(row[i]) > colWidths[i] {
				colWidths[i] = len(row[i])
			}
		}
	}

	for i := 0; i < colCount; i++ {
		if i < len(maxCaps) && maxCaps[i] > 0 && colWidths[i] > maxCaps[i] {
			colWidths[i] = maxCaps[i]
		}
		if colWidths[i] < 4 {
			colWidths[i] = 4
		}
	}

	totalTableWidth := 1
	for _, w := range colWidths {
		totalTableWidth += w + 3
	}

	topBorder := "+" + strings.Repeat("-", totalTableWidth-2) + "+"

	var colBorderBuilder strings.Builder
	colBorderBuilder.WriteString("+")
	for _, w := range colWidths {
		colBorderBuilder.WriteString(strings.Repeat("-", w+2))
		colBorderBuilder.WriteString("+")
	}
	colBorder := colBorderBuilder.String()

	fmt.Println(topBorder)
	fmt.Printf("| %-*s |\n", totalTableWidth-4, title)
	fmt.Println(colBorder)

	var headerLine strings.Builder
	headerLine.WriteString("|")
	for i, h := range headers {
		headerLine.WriteString(fmt.Sprintf(" %-*s |", colWidths[i], truncateText(h, colWidths[i])))
	}
	fmt.Println(headerLine.String())
	fmt.Println(colBorder)

	for _, row := range rows {
		var rowLine strings.Builder
		rowLine.WriteString("|")
		for i := 0; i < colCount; i++ {
			val := ""
			if i < len(row) {
				val = row[i]
			}
			rowLine.WriteString(fmt.Sprintf(" %-*s |", colWidths[i], truncateText(val, colWidths[i])))
		}
		fmt.Println(rowLine.String())
	}

	fmt.Println(colBorder)
}

func truncateText(text string, maxLen int) string {
	text = strings.ReplaceAll(text, "\n", " ")
	text = strings.ReplaceAll(text, "\r", "")
	text = strings.TrimSpace(text)

	if len(text) <= maxLen {
		return text
	}
	if maxLen <= 3 {
		return text[:maxLen]
	}
	return text[:maxLen-3] + "..."
}
