package report

import (
	"encoding/json"
	"fmt"
	"io"
	"runtime"
	"strings"
	"time"

	"github.com/example/appaudit/internal/application"
	"github.com/example/appaudit/internal/provenance"
)

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
	NetworkLookups      int           `json:"network_lookups"`
	CacheHits           int           `json:"cache_hits"`
	RemoteLookups       int           `json:"remote_lookups"`
	DiscoveryDurationMs float64       `json:"discovery_time_ms,omitempty"`
	DirsVisited         int64         `json:"dirs_visited,omitempty"`
	DirsPruned          int64         `json:"dirs_pruned,omitempty"`
	FilesScanned        int64         `json:"files_scanned,omitempty"`
	ExecutablesFound    int64         `json:"executables_found,omitempty"`
	Tier1Hits           int           `json:"tier1_hits"`
	Tier15AHits         int           `json:"tier15a_hits"`
	Tier15BHits         int           `json:"tier15b_hits"`
	Tier2AIInvocations  int           `json:"tier2_ai_invocations"`
	CIRCLDegraded       bool          `json:"circl_degraded,omitempty"`
	CIRCLSkippedCount   int           `json:"circl_skipped_count,omitempty"`
}

// CaptureTelemetry records system resource utilization and execution metrics.
func CaptureTelemetry(startTime time.Time, netMode string, lookups, cacheHits, remote int, offline bool) Telemetry {
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
		NetworkEnabled:     netMode != "off",
		NetworkOffline:     offline,
		NetworkLookups:     lookups,
		CacheHits:          cacheHits,
		RemoteLookups:      remote,
	}
}

// Reporter defines the presentation interface for audit results.
type Reporter interface {
	Report(w io.Writer, apps []application.Application, telemetry Telemetry) error
}

// JSONReporter formats audit results as structured JSON.
type JSONReporter struct{}

// NewJSONReporter creates a new JSON reporter.
func NewJSONReporter() *JSONReporter {
	return &JSONReporter{}
}

func (j *JSONReporter) Report(w io.Writer, apps []application.Application, telemetry Telemetry) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(apps)
}

// TerminalReporter formats audit results as styled human-readable terminal tables.
type TerminalReporter struct{}

// NewTerminalReporter creates a new terminal table reporter.
func NewTerminalReporter() *TerminalReporter {
	return &TerminalReporter{}
}

func (tr *TerminalReporter) Report(w io.Writer, apps []application.Application, telemetry Telemetry) error {
	var thirdParty []application.Application
	var company []application.Application
	var unknown []application.Application

	for _, app := range apps {
		switch app.Classification {
		case provenance.ClassificationThirdParty:
			thirdParty = append(thirdParty, app)
		case provenance.ClassificationCompany:
			company = append(company, app)
		default:
			unknown = append(unknown, app)
		}
	}

	printThirdPartyTable(w, thirdParty)
	fmt.Fprintln(w)
	printCompanyTable(w, company)
	fmt.Fprintln(w)
	printUnknownTable(w, unknown)
	fmt.Fprintln(w)
	printGeminiGroundingDetails(w, apps)

	fmt.Fprintf(w, "Discovery Summary: %d total apps discovered (%d Third-Party, %d Company, %d Unknown/Unresolved) in %s\n",
		len(apps), len(thirdParty), len(company), len(unknown), telemetry.Duration.Round(time.Millisecond))

	PrintTelemetry(w, telemetry)
	printWarningsAndDegradations(w, apps, telemetry)
	return nil
}

// PrintTelemetry writes performance and memory telemetry to the given writer.
func PrintTelemetry(w io.Writer, t Telemetry) {
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Memory & Performance Telemetry:")
	fmt.Fprintf(w, "  Time Taken:             %.1f ms\n", t.DurationMs)
	if t.DiscoveryDurationMs > 0 {
		fmt.Fprintf(w, "  Discovery Time:         %.1f ms (Visited: %s dirs, Pruned: %s dirs, Found: %s exes)\n",
			t.DiscoveryDurationMs, formatNumber(int(t.DirsVisited)), formatNumber(int(t.DirsPruned)), formatNumber(int(t.ExecutablesFound)))
	}
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
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Triage Gate Statistics:")
	fmt.Fprintf(w, "  Tier 1 Hits (Crypto/Compiler):   %d\n", t.Tier1Hits)
	fmt.Fprintf(w, "  Tier 1.5A Hits (Local Receipts):  %d\n", t.Tier15AHits)
	fmt.Fprintf(w, "  Tier 1.5B Hits (Public Hash DB):  %d\n", t.Tier15BHits)
	fmt.Fprintf(w, "  Tier 2 AI Invocations:           %d\n", t.Tier2AIInvocations)
}

func printThirdPartyTable(w io.Writer, apps []application.Application) {
	title := fmt.Sprintf("[Third-Party / Public Commercial Software] (Count: %d)", len(apps))
	headers := []string{"Application", "Binaries", "Publisher", "Resolution", "Primary Evidence"}
	maxCaps := []int{24, 14, 18, 16, 44}

	if len(apps) == 0 {
		printEmptyTable(w, title, "(No verified third-party applications identified)")
		return
	}

	rows := make([][]string, len(apps))
	for i, app := range apps {
		displayName := app.Name
		if app.Identity.Name != "" && app.Identity.Name != app.Name && !provenance.IsWrapperString(app.Identity.Name) {
			displayName = fmt.Sprintf("%s (%s)", app.Name, app.Identity.Name)
		}

		binStr := "-"
		if len(app.Binaries) == 1 {
			binStr = app.Binaries[0].Name
		} else if len(app.Binaries) > 1 {
			binStr = fmt.Sprintf("%s (+%d)", app.Binaries[0].Name, len(app.Binaries)-1)
		} else if app.PrimaryBinaryPath != "" {
			binStr = app.Name
		}

		pub := app.Publisher
		if pub == "" || provenance.IsWrapperString(pub) {
			pub = "-"
		}
		resStr := "deterministic"
		if isLocalAIApp(app) && !app.SearchGrounded && app.Classification != provenance.ClassificationUnknown {
			resStr = "[UNGROUNDED - MODEL MEMORY ONLY]"
		} else if app.ResolutionSource == "deepseek_reasoning" {
			resStr = "DeepSeek"
		} else if app.ResolutionSource == "gemini_search" {
			if app.ArtifactProvenance != "" {
				resStr = fmt.Sprintf("Gemini [%s]", app.ArtifactProvenance)
			} else {
				resStr = "Gemini + Search"
			}
		} else if app.ResolutionSource == "ollama_reasoning" {
			resStr = "Ollama + SearXNG"
		} else if app.ResolutionSource != "" {
			resStr = app.ResolutionSource
		}

		evStr := ""
		if len(app.Reasons) > 0 {
			evStr = app.Reasons[0]
		} else if len(app.OwnershipEvidence) > 0 {
			evStr = app.OwnershipEvidence[0].Description
		}

		rows[i] = []string{
			displayName,
			binStr,
			pub,
			resStr,
			evStr,
		}
	}

	renderTable(w, title, headers, rows, maxCaps)
}

func printCompanyTable(w io.Writer, apps []application.Application) {
	title := fmt.Sprintf("[Company-Owned / Internal Proprietary Software] (Count: %d)", len(apps))
	headers := []string{"Application", "Resolution", "Primary Path", "Ownership Evidence"}
	maxCaps := []int{24, 16, 36, 42}

	if len(apps) == 0 {
		printEmptyTable(w, title, "(No explicitly verified company-owned applications identified)")
		return
	}

	rows := make([][]string, len(apps))
	for i, app := range apps {
		resStr := "deterministic"
		if isLocalAIApp(app) && !app.SearchGrounded && app.Classification != provenance.ClassificationUnknown {
			resStr = "[UNGROUNDED - MODEL MEMORY ONLY]"
		} else if app.ResolutionSource == "deepseek_reasoning" {
			resStr = "DeepSeek"
		} else if app.ResolutionSource == "gemini_search" {
			resStr = "Gemini + Search"
		} else if app.ResolutionSource == "ollama_reasoning" {
			resStr = "Ollama + SearXNG"
		} else if app.ResolutionSource != "" {
			resStr = app.ResolutionSource
		}
		path := app.PrimaryBinaryPath
		ev := ""
		if len(app.Reasons) > 0 {
			ev = app.Reasons[0]
		}
		rows[i] = []string{
			app.Name,
			resStr,
			path,
			ev,
		}
	}

	renderTable(w, title, headers, rows, maxCaps)
}

func printUnknownTable(w io.Writer, apps []application.Application) {
	title := fmt.Sprintf("[Unknown / Unresolved Provenance (No Public Match != Company)] (Count: %d)", len(apps))
	headers := []string{"Application", "Binaries", "Resolution", "Primary Reason"}
	maxCaps := []int{22, 12, 18, 44}

	if len(apps) == 0 {
		printEmptyTable(w, title, "(All applications successfully resolved to verifiable provenance)")
		return
	}

	rows := make([][]string, len(apps))
	for i, app := range apps {
		binStr := "-"
		if len(app.Binaries) == 1 {
			binStr = app.Binaries[0].Name
		} else if len(app.Binaries) > 1 {
			binStr = fmt.Sprintf("%s (+%d)", app.Binaries[0].Name, len(app.Binaries)-1)
		} else if app.PrimaryBinaryPath != "" {
			binStr = app.Name
		}

		resStr := "deterministic"
		if app.ReadError != "" {
			resStr = "Unreadable File"
		} else if isLocalAIApp(app) && !app.SearchGrounded && app.Classification != provenance.ClassificationUnknown {
			resStr = "[UNGROUNDED - MODEL MEMORY ONLY]"
		} else if app.ResolutionSource == "deepseek_error" {
			resStr = "DeepSeek Error"
		} else if app.ResolutionSource == "gemini_error" {
			resStr = "Gemini Error"
		} else if app.ResolutionSource == "ollama_error" {
			resStr = "Ollama Error"
		} else if app.ResolutionSource == "deepseek_inconclusive" {
			resStr = "DeepSeek Inconc."
		} else if app.ResolutionSource == "gemini_inconclusive" {
			resStr = "Gemini Inconc."
		} else if app.ResolutionSource == "ollama_inconclusive" {
			resStr = "Ollama Inconc."
		} else if app.ResolutionSource == "deepseek_reasoning" {
			resStr = "DeepSeek"
		} else if app.ResolutionSource == "gemini_search" {
			resStr = "Gemini + Search"
		} else if app.ResolutionSource == "ollama_reasoning" {
			resStr = "Ollama + SearXNG"
		} else if app.ResolutionSource != "" {
			resStr = app.ResolutionSource
		}

		reason := ""
		if app.ReadError != "" {
			reason = "Inspection halted: " + app.ReadError
		} else if app.AIError != "" {
			reason = app.AIError
		} else if len(app.Reasons) > 0 {
			reason = app.Reasons[len(app.Reasons)-1]
		}
		rows[i] = []string{
			app.Name,
			binStr,
			resStr,
			reason,
		}
	}

	renderTable(w, title, headers, rows, maxCaps)
}

func isAIApp(app application.Application) bool {
	return strings.HasPrefix(app.ResolutionSource, "gemini_") ||
		strings.HasPrefix(app.ResolutionSource, "deepseek_") ||
		strings.HasPrefix(app.ResolutionSource, "ollama_") ||
		strings.Contains(app.ResolutionSource, "AI Analysis") ||
		app.AIError != "" ||
		app.PromptTokens > 0
}

func isLocalAIApp(app application.Application) bool {
	if strings.HasPrefix(app.ResolutionSource, "ollama_") || strings.Contains(strings.ToLower(app.ResolutionSource), "ollama") {
		return true
	}
	for _, r := range app.Reasons {
		if strings.Contains(strings.ToLower(r), "ollama") {
			return true
		}
	}
	return false
}

func isDeepSeekApp(app application.Application) bool {
	if strings.HasPrefix(app.ResolutionSource, "deepseek_") {
		return true
	}
	for _, r := range app.Reasons {
		if strings.Contains(strings.ToLower(r), "deepseek") {
			return true
		}
	}
	return false
}

func isOllamaApp(app application.Application) bool {
	if strings.HasPrefix(app.ResolutionSource, "ollama_") {
		return true
	}
	for _, r := range app.Reasons {
		rLow := strings.ToLower(r)
		if strings.Contains(rLow, "ollama") || strings.Contains(rLow, "local_ollama") {
			return true
		}
	}
	return false
}

func printGeminiGroundingDetails(w io.Writer, apps []application.Application) {
	var aiApps []application.Application
	hasDeepSeek := false
	hasGemini := false
	hasOllama := false
	for _, app := range apps {
		isAIRun := strings.HasPrefix(app.ResolutionSource, "gemini_") ||
			strings.HasPrefix(app.ResolutionSource, "deepseek_") ||
			strings.HasPrefix(app.ResolutionSource, "ollama_") ||
			app.AIError != "" ||
			app.PromptTokens > 0
		if isAIRun {
			aiApps = append(aiApps, app)
			if isOllamaApp(app) {
				hasOllama = true
			} else if isDeepSeekApp(app) {
				hasDeepSeek = true
			} else {
				hasGemini = true
			}
		}
	}
	if len(aiApps) == 0 {
		return
	}

	headerProvider := "AI Reasoning Layer"
	if hasOllama && !hasDeepSeek && !hasGemini {
		headerProvider = "Local Ollama (audit-phi:q6k + SearXNG)"
	} else if hasDeepSeek && !hasGemini && !hasOllama {
		headerProvider = "DeepSeek-V4.1-Flash"
	} else if hasGemini && !hasDeepSeek && !hasOllama {
		headerProvider = "Google Gemini"
	}

	borderDouble := "+" + strings.Repeat("=", 78) + "+"
	fmt.Fprintln(w, borderDouble)
	fmt.Fprintf(w, "| %-76s |\n", fmt.Sprintf("[AI Reasoning & Digital Evidence] (Provider: %s)", headerProvider))
	fmt.Fprintln(w, borderDouble)

	for i, app := range aiApps {
		identifiedAs := app.Identity.Name
		if identifiedAs == "" || provenance.IsWrapperString(identifiedAs) {
			identifiedAs = app.Name
		}
		publisher := app.Publisher
		if publisher == "" || provenance.IsWrapperString(publisher) {
			publisher = app.Identity.Publisher
		}
		if publisher == "" || provenance.IsWrapperString(publisher) {
			publisher = "-"
		}

		cacheLabel := "MISS"
		if app.ResearchCacheHit {
			cacheLabel = "HIT (0ms)"
		} else if app.AIError != "" {
			cacheLabel = "BYPASS"
		}

		statusLabel := string(app.Classification)
		if app.AIError != "" {
			statusLabel = "UNKNOWN (API ERROR)"
		}

		evidenceText := app.EvidenceSummary
		if evidenceText == "" && app.AIError != "" {
			evidenceText = app.AIError
		}
		if evidenceText == "" {
			for _, r := range app.Reasons {
				if !strings.HasPrefix(r, "Tier 3 AI") && !strings.HasPrefix(r, "Rule F") && !strings.HasPrefix(r, "No trusted") && !strings.HasPrefix(r, "No verified") && !strings.HasPrefix(r, "Available identity") && !strings.HasPrefix(r, "Conclusion:") {
					evidenceText = r
					break
				}
			}
		}
		if evidenceText == "" {
			evidenceText = "No verifiable public release, code-signing certificate, or company ownership record."
		}

		conclusionText := app.Conclusion
		if conclusionText == "" {
			if app.AIError != "" {
				conclusionText = fmt.Sprintf("AI reasoning aborted: %s", app.AIError)
			} else if app.Classification == provenance.ClassificationThirdParty {
				conclusionText = fmt.Sprintf("Authentic third-party software (%s).", identifiedAs)
			} else if app.Classification == provenance.ClassificationCompany {
				conclusionText = "Verified company-owned software."
			} else {
				conclusionText = "Provenance cannot be established with sufficient confidence -> UNKNOWN."
			}
		}

		groundingBadge := ""
		if app.AIError == "" && isAIApp(app) {
			if isLocalAIApp(app) {
				if app.SearchGrounded {
					groundingBadge = " | Grounding: LIVE WEB SEARCH"
				} else {
					groundingBadge = " | Grounding: UNGROUNDED (MODEL MEMORY ONLY)"
				}
			} else {
				groundingBadge = " | Grounding: LIVE WEB SEARCH"
			}
		}

		fmt.Fprintf(w, "[%s] -> %s (Confidence: %s | Cache: %s%s)\n", app.Name, statusLabel, app.Confidence, cacheLabel, groundingBadge)
		fmt.Fprintf(w, "  Identified As:  %s\n", identifiedAs)
		fmt.Fprintf(w, "  Publisher:      %s\n", publisher)
		if !app.SearchGrounded && app.DegradationWarning != "" {
			fmt.Fprintf(w, "  Grounding Note: %s\n", app.DegradationWarning)
		}
		if len(app.Sources) > 0 {
			fmt.Fprintf(w, "  Sources:        • %s\n", app.Sources[0])
			for sIdx := 1; sIdx < len(app.Sources); sIdx++ {
				fmt.Fprintf(w, "                  • %s\n", app.Sources[sIdx])
			}
		} else if app.AIError != "" {
			fmt.Fprintln(w, "  Sources:        • (None - remote API call failed)")
		} else {
			fmt.Fprintln(w, "  Sources:        • (No authoritative public matches found)")
		}
		fmt.Fprintf(w, "  Evidence:       %s\n", evidenceText)
		fmt.Fprintf(w, "  Conclusion:     %s\n", conclusionText)
		if app.AIError != "" {
			remediation := getRemediationAdvice(app)
			if remediation != "" {
				fmt.Fprintf(w, "  Fix / Action:   %s\n", remediation)
			}
		}

		if i < len(aiApps)-1 {
			fmt.Fprintln(w, strings.Repeat("-", 80))
		}
	}

	// Aggregate Token & Telemetry Summary
	totalPrompt := 0
	totalCompletion := 0
	totalTokens := 0
	cacheHits := 0
	remoteCalls := 0
	resolvedThirdParty := 0
	resolvedCompany := 0
	inconclusive := 0
	apiErrors := 0

	for _, app := range aiApps {
		totalPrompt += app.PromptTokens
		totalCompletion += app.CompletionTokens
		totalTokens += app.TotalTokens
		if app.ResearchCacheHit {
			cacheHits++
		} else {
			remoteCalls++
		}
		if app.AIError != "" {
			apiErrors++
		} else {
			switch app.Classification {
			case provenance.ClassificationThirdParty:
				resolvedThirdParty++
			case provenance.ClassificationCompany:
				resolvedCompany++
			default:
				inconclusive++
			}
		}
	}

	totalApps := len(aiApps)
	avgTokens := 0
	if remoteCalls > 0 {
		avgTokens = totalTokens / remoteCalls
	}
	cacheSavingsTokens := cacheHits * avgTokens
	hitRate := 0.0
	if totalApps > 0 {
		hitRate = float64(cacheHits) / float64(totalApps) * 100.0
	}

	engineName := "Google Gemini (gemini-3.5-flash-lite + Google Search)"
	if hasOllama && !hasDeepSeek && !hasGemini {
		engineName = "Local Ollama (audit-phi:q6k + SearXNG, 100% GPU)"
	} else if hasDeepSeek && !hasGemini && !hasOllama {
		engineName = "DeepSeek-V4.1-Flash (Responses API + Native Web Search)"
	} else if (hasDeepSeek || hasOllama) && hasGemini {
		engineName = "Multi-Engine AI"
	}

	fmt.Fprintln(w, borderDouble)
	fmt.Fprintf(w, "| %-76s |\n", "AI Telemetry & Token Usage Summary")
	fmt.Fprintln(w, borderDouble)
	fmt.Fprintf(w, "  AI Engine:              %s\n", engineName)
	if apiErrors > 0 {
		fmt.Fprintf(w, "  Applications Evaluated: %d apps (%d Resolved Third-Party, %d Inconclusive, %d API Errors)\n", totalApps, resolvedThirdParty, inconclusive, apiErrors)
	} else {
		fmt.Fprintf(w, "  Applications Evaluated: %d apps (%d Resolved Third-Party, %d Inconclusive)\n", totalApps, resolvedThirdParty, inconclusive)
	}
	fmt.Fprintf(w, "  API Calls Made:         %d remote calls (%d cache hits)\n", remoteCalls, cacheHits)
	fmt.Fprintf(w, "  Prompt / Input Tokens:  %s tokens\n", formatNumber(totalPrompt))
	fmt.Fprintf(w, "  Completion / Output:    %s tokens\n", formatNumber(totalCompletion))
	if remoteCalls > 0 {
		fmt.Fprintf(w, "  Total Tokens Consumed:  %s tokens (Avg: %s tokens/app)\n", formatNumber(totalTokens), formatNumber(avgTokens))
	} else {
		fmt.Fprintf(w, "  Total Tokens Consumed:  0 tokens (All %d queries served from local cache)\n", cacheHits)
	}
	if cacheHits > 0 {
		fmt.Fprintf(w, "  Cache Savings:          ~%s tokens saved (%.1f%% hit rate)\n", formatNumber(cacheSavingsTokens), hitRate)
	} else {
		fmt.Fprintf(w, "  Cache Savings:          0 tokens saved (0.0%% hit rate, first scan)\n")
	}
	fmt.Fprintln(w)

	if apiErrors > 0 {
		printAIRemediationNotice(w, aiApps, hasDeepSeek, hasGemini)
	}
}

func printAIRemediationNotice(w io.Writer, aiApps []application.Application, hasDeepSeek, hasGemini bool) {
	borderDouble := "+" + strings.Repeat("=", 78) + "+"
	fmt.Fprintln(w, borderDouble)
	fmt.Fprintf(w, "| %-76s |\n", "[!] AI Provider Failure & Remediation Notice")
	fmt.Fprintln(w, borderDouble)

	seenErrors := map[string]bool{}
	for _, app := range aiApps {
		if app.AIError != "" && !seenErrors[app.AIError] {
			seenErrors[app.AIError] = true
			provider := "Google Gemini"
			if isDeepSeekApp(app) {
				provider = "DeepSeek-V4.1-Flash"
			}
			fmt.Fprintf(w, "  Provider: %s\n", provider)
			fmt.Fprintf(w, "  Failure:  %s\n", app.AIError)
			remediation := getRemediationAdvice(app)
			if remediation != "" {
				fmt.Fprintf(w, "  Action:   %s\n", remediation)
			}
			fmt.Fprintln(w)
		}
	}
	fmt.Fprintln(w, borderDouble)
}

func getRemediationAdvice(app application.Application) string {
	errLower := strings.ToLower(app.AIError)
	isDeepSeek := isDeepSeekApp(app)
	if strings.Contains(errLower, "401") || strings.Contains(errLower, "unauthorized") || strings.Contains(errLower, "invalid api key") || strings.Contains(errLower, "missing api key") {
		if isDeepSeek {
			return "Run 'appaudit config set-deepseek-key <KEY>' or verify key at https://platform.deepseek.com"
		}
		return "Run 'appaudit config set-gemini-key <KEY>' or verify key at https://aistudio.google.com/"
	}
	if strings.Contains(errLower, "402") || strings.Contains(errLower, "payment required") || strings.Contains(errLower, "credits exhausted") {
		return "DeepSeek account balance is $0.00. Top up your balance at https://platform.deepseek.com"
	}
	if strings.Contains(errLower, "403") || strings.Contains(errLower, "forbidden") {
		if isDeepSeek {
			return "Access forbidden. Check your DeepSeek account permissions at https://platform.deepseek.com"
		}
		return "Access forbidden. Check your Gemini API key permissions at https://aistudio.google.com/"
	}
	if strings.Contains(errLower, "429") || strings.Contains(errLower, "too many requests") || strings.Contains(errLower, "rate limit") || strings.Contains(errLower, "quota") {
		if isDeepSeek {
			return "Rate limit exceeded. Wait a few moments before retrying."
		}
		return "Gemini quota exceeded. Wait a few minutes or configure a billing-enabled key at https://aistudio.google.com/"
	}
	if strings.Contains(errLower, "network") || strings.Contains(errLower, "connection") {
		return "Check internet connection, DNS resolution, and proxy settings."
	}
	return "Check your network connection and API credentials."
}

func formatNumber(n int) string {
	in := fmt.Sprintf("%d", n)
	if len(in) <= 3 {
		return in
	}
	var out []byte
	rem := len(in) % 3
	if rem > 0 {
		out = append(out, in[:rem]...)
		if len(in) > rem {
			out = append(out, ',')
		}
	}
	for i := rem; i < len(in); i += 3 {
		out = append(out, in[i:i+3]...)
		if i+3 < len(in) {
			out = append(out, ',')
		}
	}
	return string(out)
}

func printEmptyTable(w io.Writer, title, emptyMsg string) {
	totalLen := len(emptyMsg) + 4
	if len(title)+4 > totalLen {
		totalLen = len(title) + 4
	}
	if totalLen < 70 {
		totalLen = 70
	}

	border := "+" + strings.Repeat("-", totalLen-2) + "+"
	fmt.Fprintln(w, border)
	fmt.Fprintf(w, "| %-*s |\n", totalLen-4, title)
	fmt.Fprintln(w, border)
	fmt.Fprintf(w, "| %-*s |\n", totalLen-4, emptyMsg)
	fmt.Fprintln(w, border)
}

func renderTable(w io.Writer, title string, headers []string, rows [][]string, maxCaps []int) {
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
	for _, wCol := range colWidths {
		totalTableWidth += wCol + 3
	}

	topBorder := "+" + strings.Repeat("-", totalTableWidth-2) + "+"

	var colBorderBuilder strings.Builder
	colBorderBuilder.WriteString("+")
	for _, wCol := range colWidths {
		colBorderBuilder.WriteString(strings.Repeat("-", wCol+2))
		colBorderBuilder.WriteString("+")
	}
	colBorder := colBorderBuilder.String()

	fmt.Fprintln(w, topBorder)
	fmt.Fprintf(w, "| %-*s |\n", totalTableWidth-4, title)
	fmt.Fprintln(w, colBorder)

	var headerLine strings.Builder
	headerLine.WriteString("|")
	for i, h := range headers {
		headerLine.WriteString(fmt.Sprintf(" %-*s |", colWidths[i], truncateText(h, colWidths[i])))
	}
	fmt.Fprintln(w, headerLine.String())
	fmt.Fprintln(w, colBorder)

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
		fmt.Fprintln(w, rowLine.String())
	}

	fmt.Fprintln(w, colBorder)
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

func printWarningsAndDegradations(w io.Writer, apps []application.Application, t Telemetry) {
	var warnings []string
	if t.CIRCLDegraded || t.CIRCLSkippedCount > 0 {
		warnings = append(warnings, fmt.Sprintf("Tier 3 Hashlookup throttled (429) — %d files bypassed registry check", t.CIRCLSkippedCount))
	}

	var searxngWarnings []string
	var ungroundedApps []string
	var provErrors []string
	var readErrors []string

	for _, app := range apps {
		if app.ReadError != "" {
			readErrors = append(readErrors, fmt.Sprintf("%s: %s", app.Name, app.ReadError))
		}
		if app.AIError != "" {
			provErrors = append(provErrors, fmt.Sprintf("%s: %s", app.Name, app.AIError))
		}
		if strings.Contains(app.SearchWarning, "SearXNG") || strings.Contains(app.DegradationWarning, "SearXNG") {
			msg := app.SearchWarning
			if msg == "" {
				msg = app.DegradationWarning
			}
			searxngWarnings = append(searxngWarnings, fmt.Sprintf("%s: %s", app.Name, msg))
		}
		if !app.SearchGrounded && (isLocalAIApp(app)) && app.Classification != provenance.ClassificationUnknown {
			warn := app.SearchWarning
			if warn == "" {
				warn = app.DegradationWarning
			}
			if warn == "" {
				warn = "Web search unavailable; verdict relies on model memory."
			}
			ungroundedApps = append(ungroundedApps, fmt.Sprintf("%s (%s)", app.Name, warn))
		}
	}

	if len(warnings) == 0 && len(searxngWarnings) == 0 && len(ungroundedApps) == 0 && len(provErrors) == 0 && len(readErrors) == 0 {
		return
	}

	borderDouble := "+" + strings.Repeat("=", 78) + "+"
	fmt.Fprintln(w)
	fmt.Fprintln(w, borderDouble)
	fmt.Fprintf(w, "| %-76s |\n", "=== Warnings & Degradations ===")
	fmt.Fprintln(w, borderDouble)

	for _, wMsg := range warnings {
		fmt.Fprintf(w, "  • [WARN] %s\n", wMsg)
	}

	if len(searxngWarnings) > 0 {
		fmt.Fprintf(w, "  • [WARN] SearXNG Local Search Failures (%d apps affected):\n", len(searxngWarnings))
		for _, s := range searxngWarnings {
			fmt.Fprintf(w, "      - %s\n", s)
		}
	}

	if len(ungroundedApps) > 0 {
		fmt.Fprintf(w, "  • [WARN] Ungrounded AI Reasoning (%d apps evaluated solely on model weights):\n", len(ungroundedApps))
		for _, u := range ungroundedApps {
			fmt.Fprintf(w, "      - %s\n", u)
		}
	}

	if len(readErrors) > 0 {
		fmt.Fprintf(w, "  • [WARN] File Inspection Halted (%d binaries unreadable/locked/corrupt - withheld from AI):\n", len(readErrors))
		for _, re := range readErrors {
			fmt.Fprintf(w, "      - %s\n", re)
		}
	}

	if len(provErrors) > 0 {
		fmt.Fprintf(w, "  • [ERROR] AI Provider Outages / Errors (%d apps affected):\n", len(provErrors))
		for _, pe := range provErrors {
			fmt.Fprintf(w, "      - %s\n", pe)
		}
	}
	fmt.Fprintln(w, borderDouble)
}
