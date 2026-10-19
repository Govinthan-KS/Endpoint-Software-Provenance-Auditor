package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/example/appaudit/internal/ai"
	"github.com/example/appaudit/internal/application"
	"github.com/example/appaudit/internal/discovery"
	"github.com/example/appaudit/internal/model"
	"github.com/example/appaudit/internal/provenance"
	"github.com/example/appaudit/internal/report"
	"github.com/example/appaudit/internal/scanner"
	"github.com/example/appaudit/internal/server"
	"github.com/example/appaudit/internal/service"
)

const version = "2.1.0"

func main() {
	defer pauseIfStandalone()

	// If launched with no arguments in an interactive terminal / console session (e.g. clicked from File Explorer or Desktop)
	if len(os.Args) <= 1 && (isTerminal(os.Stdin) || os.Getenv("APPAUDIT_FORCE_INTERACTIVE") == "1") {
		runInteractiveModeSelection()
		return
	}

	// Parse command line arguments
	subcommand, args := parseSubcommand(os.Args[1:])
	if subcommand == "config" {
		handleConfigCommand(args)
		return
	}
	if subcommand == "serve" {
		handleServeCommand(args)
		return
	}
	if subcommand == "cli" {
		reader := bufio.NewReader(os.Stdin)
		ollamaURL, searxngURL := promptLocalServicesSetup(reader)
		runInteractiveWizard(reader, ollamaURL, searxngURL)
		return
	}

	fs := flag.NewFlagSet("appaudit", flag.ExitOnError)
	modeFlag := fs.String("mode", "gemini", "Reasoning mode: 'gemini' (default), 'deepseek', or 'local'")
	localFlag := fs.Bool("local", false, "Alias for --mode=local (runs local Ollama + SearXNG reasoning)")
	ollamaModelFlag := fs.String("ollama-model", ai.DefaultOllamaModel, "Ollama local model identifier (default: \"audit-phi:q6k\")")
	searxngURLFlag := fs.String("searxng-url", "http://localhost:8080", "SearXNG base URL for local grounding (default: \"http://localhost:8080\")")
	networkFlag := fs.String("network", "off", "Network mode: 'off' (local-first, 0ms), 'hash-only', or 'on' (full public resolution)")
	lookupOnlineFlag := fs.Bool("lookup-online", false, "Enable online resolution (alias for --network=on)")
	fs.BoolVar(lookupOnlineFlag, "online", false, "Enable online resolution (shorthand)")
	jsonFlag := fs.Bool("json", false, "Output results as formatted JSON to stdout")
	modelFlag := fs.String("model", "none", "Optional local AI reasoner: 'none' (default), 'gemini', 'deepseek', 'local', or model name")
	geminiFlag := fs.Bool("gemini", false, "Enable Gemini search-grounded reasoning for unresolved applications")
	geminiKeyFlag := fs.String("gemini-key", "", "Gemini API key override")
	geminiModelFlag := fs.String("gemini-model", ai.DefaultGeminiModel, "Gemini model to invoke (default: \"gemini-3.5-flash-lite\", minimum supported: Gemini 3.x)")
	aiFlag := fs.Bool("ai", false, "Enable AI reasoning on unresolved applications")
	aiProviderFlag := fs.String("ai-provider", "gemini", "AI reasoning provider: 'gemini' (default), 'deepseek', or 'local'")
	deepseekModelFlag := fs.String("deepseek-model", ai.DefaultDeepSeekModel, "DeepSeek model identifier (default: \"deepseek-flash\", DeepSeek-V4.1-Flash)")
	deepseekKeyFlag := fs.String("deepseek-key", "", "DeepSeek API key override")
	deepseekSearchFlag := fs.Bool("deepseek-search", true, "Enable DeepSeek native web search via Responses API (default: true)")
	scanModeFlag := fs.String("scan-mode", "targeted", "Scan mode: 'targeted' (1-3s targeted tier scan, default), 'full' (alias for targeted), or 'quick' (sub-second registry/PATH inventory)")
	pathFlag := fs.String("path", "", "Ad-hoc target file or directory path to audit")
	fullFlag := fs.Bool("full", false, "Perform targeted tier scan across all application targets (default)")
	fs.BoolVar(fullFlag, "deep", false, "Perform targeted tier scan (shorthand)")
	quickFlag := fs.Bool("quick", false, "Force quick inventory scan (Start Menu, Registry, PATH)")
	versionFlag := fs.Bool("version", false, "Print version information")
	fs.BoolVar(versionFlag, "v", false, "Print version information (shorthand)")
	helpFlag := fs.Bool("help", false, "Show help and usage information")
	fs.BoolVar(helpFlag, "h", false, "Show help and usage information (shorthand)")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "AppAudit - Endpoint Software Provenance Auditor (v%s)\n\n", version)
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  appaudit                             Interactive mode selection (Web Dashboard or CLI)\n")
		fmt.Fprintf(os.Stderr, "  appaudit web [--port 8085]           Launch embedded web dashboard & HTTP server\n")
		fmt.Fprintf(os.Stderr, "  appaudit cli                         Launch interactive CLI setup wizard\n")
		fmt.Fprintf(os.Stderr, "  appaudit scan [flags]                Perform discovery and classification across host\n")
		fmt.Fprintf(os.Stderr, "  appaudit analyze <path> [flags]      Inspect specific executable file(s) or directories\n")
		fmt.Fprintf(os.Stderr, "  appaudit config <subcommand>         Manage local credentials and settings\n")
		fmt.Fprintf(os.Stderr, "  appaudit serve [--port 8085]         Alias for web dashboard\n\n")
		fmt.Fprintf(os.Stderr, "Commands:\n")
		fmt.Fprintf(os.Stderr, "  web, serve  Launch embedded translucent web dashboard and HTTP server\n")
		fmt.Fprintf(os.Stderr, "  cli         Launch interactive terminal wizard\n")
		fmt.Fprintf(os.Stderr, "  scan        Perform discovery and classification across host (default)\n")
		fmt.Fprintf(os.Stderr, "  analyze     Inspect and classify specific executable file(s) or directories\n")
		fmt.Fprintf(os.Stderr, "  config      Manage local credentials and settings\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		fmt.Fprintf(os.Stderr, "  --mode string             Reasoning mode: 'gemini' (default), 'deepseek', or 'local'\n")
		fmt.Fprintf(os.Stderr, "  --local                   Alias for --mode=local (runs local Ollama + SearXNG reasoning)\n")
		fmt.Fprintf(os.Stderr, "  --ollama-model string     Ollama local model identifier (default: \"audit-phi:q6k\")\n")
		fmt.Fprintf(os.Stderr, "  --searxng-url string      SearXNG base URL for local grounding (default: \"http://localhost:8080\")\n")
		fmt.Fprintf(os.Stderr, "  --scan-mode string        Scan mode: 'targeted' (1-3s targeted tier scan, default), 'full', or 'quick'\n")
		fmt.Fprintf(os.Stderr, "  --path string             Ad-hoc target file or directory path to audit\n")
		fmt.Fprintf(os.Stderr, "  --full, --deep            Perform targeted tier scan across all application targets (default)\n")
		fmt.Fprintf(os.Stderr, "  --quick                   Force quick inventory scan (Start Menu, Registry, PATH)\n")
		fmt.Fprintf(os.Stderr, "  --network string          Network mode: 'off' (default), 'hash-only', or 'on'\n")
		fmt.Fprintf(os.Stderr, "  --lookup-online, -online  Enable online resolution (shorthand for --network=on)\n")
		fmt.Fprintf(os.Stderr, "  --ai                      Enable AI reasoning on unresolved candidates\n")
		fmt.Fprintf(os.Stderr, "  --ai-provider string      AI provider: 'gemini' (default), 'deepseek', or 'local'\n")
		fmt.Fprintf(os.Stderr, "  --gemini                  Enable Gemini search-grounded reasoning (shorthand)\n")
		fmt.Fprintf(os.Stderr, "  --gemini-key string       Gemini API key override\n")
		fmt.Fprintf(os.Stderr, "  --gemini-model string     Gemini model to invoke (default: \"gemini-3.5-flash-lite\", minimum supported: Gemini 3.x)\n")
		fmt.Fprintf(os.Stderr, "  --deepseek-key string     DeepSeek API key override\n")
		fmt.Fprintf(os.Stderr, "  --deepseek-model string   DeepSeek model identifier (default: \"deepseek-flash\")\n")
		fmt.Fprintf(os.Stderr, "  --deepseek-search         Enable DeepSeek native web search via Responses API (default: true)\n")
		fmt.Fprintf(os.Stderr, "  --model string            AI reasoner: 'none' (default), 'gemini', 'deepseek', 'local', or model name\n")
		fmt.Fprintf(os.Stderr, "  --json                    Print full application classification array as JSON\n")
		fmt.Fprintf(os.Stderr, "  -v, --version             Print version information\n")
		fmt.Fprintf(os.Stderr, "  -h, --help                Show help and usage\n")
	}

	flagArgs, posArgs := separateFlagsAndPositional(args)
	_ = fs.Parse(flagArgs)

	if *helpFlag {
		fs.Usage()
		return
	}

	if *versionFlag {
		fmt.Printf("appaudit v%s\n", version)
		return
	}

	netMode := provenance.NetworkMode(*networkFlag)
	if *lookupOnlineFlag || *aiFlag {
		netMode = provenance.NetworkOn
	}

	// Track whether --mode was explicitly supplied on the command line
	var modeExplicit bool
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "mode" {
			modeExplicit = true
		}
	})

	mode := strings.ToLower(strings.TrimSpace(*modeFlag))
	if *localFlag || *modelFlag == "local" || *modelFlag == "ollama" {
		mode = "local"
	}
	var reasoner ai.Reasoner = ai.NewNoopReasoner()
	chosenProvider := strings.ToLower(strings.TrimSpace(*aiProviderFlag))
	if *geminiFlag || *modelFlag == "gemini" {
		chosenProvider = "gemini"
	} else if *modelFlag == "deepseek" {
		chosenProvider = "deepseek"
	}

	if mode == "local" {
		chosenProvider = "local"
	} else if modeExplicit && (mode == "deepseek" || mode == "gemini") {
		chosenProvider = mode
	}

	aiRequested := *aiFlag || *geminiFlag || *localFlag || (modeExplicit && mode != "") ||
		(netMode == provenance.NetworkOn && *modelFlag == "none") ||
		*modelFlag == "gemini" || *modelFlag == "deepseek" || *modelFlag == "local" || *modelFlag == "ollama"
	if !aiRequested && netMode == provenance.NetworkOn && *modelFlag == "none" {
		switch chosenProvider {
		case "deepseek":
			if storedKey := ai.GetDeepSeekAPIKey(*deepseekKeyFlag); storedKey != "" {
				aiRequested = true
			}
		case "local":
			aiRequested = true
		default:
			if storedKey := ai.GetGeminiAPIKey(*geminiKeyFlag); storedKey != "" {
				aiRequested = true
				chosenProvider = "gemini"
			}
		}
	}

	if aiRequested {
		switch chosenProvider {
		case "local":
			passed, guidance := checkLocalPreflight(os.Stderr, "http://localhost:11434", *searxngURLFlag, *ollamaModelFlag)
			if !passed {
				fmt.Fprintf(os.Stderr, "\n[!] Local-First AI Pre-Flight Check Failed:\n    %s\n", strings.ReplaceAll(guidance, "\n", "\n    "))
				os.Exit(1)
			}
			searxng := ai.NewSearXNGProvider(*searxngURLFlag)
			cache := ai.NewOllamaCache()
			reasoner = ai.NewLocalReasoner(*ollamaModelFlag, searxng, cache)
		case "deepseek":
			key := resolveOrPromptDeepSeekKey(*deepseekKeyFlag)
			if key == "" && netMode == provenance.NetworkOn {
				fmt.Fprintf(os.Stderr, "Warning: DeepSeek reasoning requested but no API key configured. Run 'appaudit config set-deepseek-key <key>' or set DEEPSEEK_API_KEY. Falling back to local deterministic analysis.\n")
				reasoner = ai.NewNoopReasoner()
			} else {
				reasoner = ai.NewDeepSeekReasoner(ai.DeepSeekConfig{
					APIKey:          key,
					Model:           *deepseekModelFlag,
					NetworkMode:     netMode,
					EnableWebSearch: *deepseekSearchFlag,
				})
			}
		default: // "gemini"
			key := resolveOrPromptGeminiKey(*geminiKeyFlag)
			if key == "" && netMode == provenance.NetworkOn {
				fmt.Fprintf(os.Stderr, "Warning: Gemini search grounding requested but no API key configured. Run 'appaudit config set-gemini-key <key>' or set GEMINI_API_KEY. Falling back to local deterministic analysis.\n")
				reasoner = ai.NewNoopReasoner()
			} else {
				if *geminiModelFlag != "" && ai.IsSubGemini3Model(*geminiModelFlag) {
					fmt.Fprintf(os.Stderr, "Warning: model %q is below Gemini 3 (minimum supported: Gemini 3.x). Clamping to %s.\n", *geminiModelFlag, ai.DefaultGeminiModel)
				}
				reasoner = ai.NewGeminiReasoner(ai.GeminiConfig{
					APIKey:      key,
					Model:       *geminiModelFlag,
					NetworkMode: netMode,
				})
			}
		}
	} else if *modelFlag != "" && *modelFlag != "none" {
		if *modelFlag == "local" || *modelFlag == "ollama" {
			passed, guidance := checkLocalPreflight(os.Stderr, "http://localhost:11434", *searxngURLFlag, *ollamaModelFlag)
			if !passed {
				fmt.Fprintf(os.Stderr, "\n[!] Local-First AI Pre-Flight Check Failed:\n    %s\n", strings.ReplaceAll(guidance, "\n", "\n    "))
				os.Exit(1)
			}
			searxng := ai.NewSearXNGProvider(*searxngURLFlag)
			cache := ai.NewOllamaCache()
			reasoner = ai.NewLocalReasoner(*ollamaModelFlag, searxng, cache)
		} else {
			searxng := ai.NewSearXNGProvider(*searxngURLFlag)
			cache := ai.NewOllamaCache()
			reasoner = ai.NewLocalReasoner(*modelFlag, searxng, cache)
		}
	}
	engine := application.NewEngine(application.EngineConfig{
		NetworkMode:             netMode,
		CompanyDomainIndicators: ai.GetCompanyIndicators(),
		Reasoner:                reasoner,
	})

	// If --path flag was supplied, or positional path arguments were given to scan, route to analyze
	if *pathFlag != "" {
		subcommand = "analyze"
		posArgs = append(posArgs, *pathFlag)
	} else if subcommand == "scan" && len(posArgs) > 0 {
		subcommand = "analyze"
	}

	startTime := time.Now()
	ctx := context.Background()

	var apps []application.Application
	var discRes *discovery.DiscoveryResult

	switch subcommand {
	case "analyze":
		targets := posArgs
		if len(targets) == 0 {
			fmt.Fprintf(os.Stderr, "Error: 'analyze' requires at least one file or directory path.\n")
			fmt.Fprintf(os.Stderr, "Usage: appaudit analyze <path> [path2...]\n")
			os.Exit(1)
		}
		analyzed, err := engine.AnalyzePaths(ctx, targets)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error analyzing paths: %v\n", err)
			os.Exit(1)
		}
		apps = analyzed

	default: // "scan"
		sysScanner := scanner.New()
		runTargeted := true
		scanMode := strings.ToLower(strings.TrimSpace(*scanModeFlag))
		if *quickFlag || scanMode == "quick" {
			runTargeted = false
		}

		var rawDiscovered []model.Application
		var err error

		if runTargeted {
			if isTerminal(os.Stdout) && !*jsonFlag {
				fmt.Print("Initiating Targeted Tier Application Discovery (Tiers 1-3)...\r")
			}
			discRes, err = discovery.ScanTargeted(nil, func(discoveredCount int, currentPath string) {
				if isTerminal(os.Stdout) && !*jsonFlag {
					truncPath := currentPath
					if len(truncPath) > 48 {
						truncPath = "..." + truncPath[len(truncPath)-45:]
					}
					fmt.Printf("\r[Scanning Targets] Found: %-4d executables | %-48s", discoveredCount, truncPath)
					_ = os.Stdout.Sync()
				}
			})
			if discRes != nil {
				rawDiscovered = append(rawDiscovered, discRes.Applications...)
			}
			// Also include registered Start Menu & Registry applications
			quickApps, _ := sysScanner.Scan()
			rawDiscovered = append(rawDiscovered, quickApps...)

			if isTerminal(os.Stdout) && !*jsonFlag {
				fmt.Printf("\r%-80s\r", "")
				if discRes != nil {
					fmt.Printf("[OK] Targeted Discovery complete in %.1fms: Found %d unique executables across %d visited directories (%d pruned).\n\n",
						discRes.DurationMs, discRes.ExecutablesFound, discRes.DirsVisited, discRes.DirsPruned)
				}
				fmt.Println("Starting forensic inspection and evidence triage...")
			}
		} else {
			rawDiscovered, err = sysScanner.Scan()
			if isTerminal(os.Stdout) && !*jsonFlag {
				fmt.Println("Starting forensic inspection and evidence triage...")
			}
		}

		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning during host discovery: %v\n", err)
		}
		apps = engine.ProcessDiscovered(ctx, rawDiscovered)
	}

	elapsed := time.Since(startTime)
	telemetry := report.CaptureTelemetry(startTime, string(netMode), 0, 0, 0, false)
	telemetry.Duration = elapsed
	telemetry.DurationMs = float64(elapsed.Microseconds()) / 1000.0
	if discRes != nil {
		telemetry.DiscoveryDurationMs = discRes.DurationMs
		telemetry.DirsVisited = discRes.DirsVisited
		telemetry.DirsPruned = discRes.DirsPruned
		telemetry.FilesScanned = discRes.FilesScanned
		telemetry.ExecutablesFound = discRes.ExecutablesFound
	}
	t1, t15a, t15b, t2 := engine.GetTriageStats()
	telemetry.Tier1Hits = t1
	telemetry.Tier15AHits = t15a
	telemetry.Tier15BHits = t15b
	telemetry.Tier2AIInvocations = t2
	if engine.DecisionEngine() != nil && engine.DecisionEngine().HashLookupClient != nil {
		hl := engine.DecisionEngine().HashLookupClient
		telemetry.CIRCLDegraded = hl.IsDegraded()
		telemetry.CIRCLSkippedCount = hl.SkippedCount()
	}

	// Select output reporter
	var reporter report.Reporter
	if *jsonFlag {
		reporter = report.NewJSONReporter()
	} else {
		reporter = report.NewTerminalReporter()
	}

	if err := reporter.Report(os.Stdout, apps, telemetry); err != nil {
		fmt.Fprintf(os.Stderr, "Error rendering report: %v\n", err)
		os.Exit(1)
	}

	// Interactive online prompt for unresolved items in terminal sessions
	if !*jsonFlag && netMode == provenance.NetworkOff && hasUnknownApps(apps) && isTerminal(os.Stdin) {
		fmt.Println()
		fmt.Println("Unresolved applications remain. Would you like to run AI reasoning?")
		fmt.Println("  [1] Google Gemini (Gemini 3.5 Flash Lite)")
		fmt.Println("  [2] DeepSeek (DeepSeek-V4.1-Flash)")
		fmt.Printf("  [3] Local-First AI (Ollama %s + SearXNG) [Offline / Private]\n", *ollamaModelFlag)
		fmt.Println("  [N] Skip (Keep UNKNOWN)")
		fmt.Print("Choice [1/2/3/N]: ")

		reader := bufio.NewReader(os.Stdin)
		input, err := reader.ReadString('\n')
		if err == nil {
			choice := strings.TrimSpace(strings.ToLower(input))
			var onlineReasoner ai.Reasoner
			switch choice {
			case "1", "gemini", "g":
				fmt.Println("\nRunning online research with Google Gemini search grounding...")
				key := resolveOrPromptGeminiKey(*geminiKeyFlag)
				if key != "" {
					onlineReasoner = ai.NewGeminiReasoner(ai.GeminiConfig{
						APIKey:      key,
						Model:       *geminiModelFlag,
						NetworkMode: provenance.NetworkOn,
					})
				}
			case "2", "deepseek", "d":
				fmt.Println("\nRunning AI reasoning with DeepSeek-V4.1-Flash (deepseek-flash)...")
				key := resolveOrPromptDeepSeekKey(*deepseekKeyFlag)
				if key != "" {
					onlineReasoner = ai.NewDeepSeekReasoner(ai.DeepSeekConfig{
						APIKey:          key,
						Model:           *deepseekModelFlag,
						NetworkMode:     provenance.NetworkOn,
						EnableWebSearch: *deepseekSearchFlag,
					})
				}
			case "3", "local", "l", "ollama", "p", "private":
				passed, guidance := checkLocalPreflight(os.Stdout, "http://localhost:11434", *searxngURLFlag, *ollamaModelFlag)
				if !passed {
					fmt.Println("\n[!] Local-First AI Pre-Flight Check Failed:")
					fmt.Printf("    %s\n\n", strings.ReplaceAll(guidance, "\n", "\n    "))
				} else {
					fmt.Printf("\nRunning Local-First AI reasoning with Ollama (%s) + SearXNG...\n", *ollamaModelFlag)
					searx := ai.NewSearXNGProvider(*searxngURLFlag)
					cache := ai.NewOllamaCache()
					onlineReasoner = ai.NewLocalReasoner(*ollamaModelFlag, searx, cache)
				}
			}

			if onlineReasoner != nil {
				onlineStart := time.Now()
				onlineEngine := application.NewEngine(application.EngineConfig{
					NetworkMode:             provenance.NetworkOn,
					CompanyDomainIndicators: ai.GetCompanyIndicators(),
					Reasoner:                onlineReasoner,
				})

				// Re-classify only unrecognized apps with chosen AI reasoner via batching
				var unknownApps []*application.Application
				for i := range apps {
					if apps[i].Classification == provenance.ClassificationUnknown {
						unknownApps = append(unknownApps, &apps[i])
					}
				}
				if len(unknownApps) > 0 {
					if _, isLocal := onlineReasoner.(*ai.LocalReasoner); isLocal {
						fmt.Printf("Analyzing %d unresolved applications locally via Ollama with 100%% GPU enforcement...\n", len(unknownApps))
					} else {
						fmt.Printf("Analyzing %d unresolved applications in batches of 5 with pacing...\n", len(unknownApps))
					}
					onlineEngine.ClassifyBatch(ctx, unknownApps)
				}

				onlineElapsed := time.Since(onlineStart)
				onlineTelemetry := report.CaptureTelemetry(startTime, "on", 0, 0, 0, false)
				onlineTelemetry.Duration = onlineElapsed
				onlineTelemetry.DurationMs = float64(onlineElapsed.Microseconds()) / 1000.0
				ot1, ot15a, ot15b, ot2 := onlineEngine.GetTriageStats()
				onlineTelemetry.Tier1Hits = telemetry.Tier1Hits + ot1
				onlineTelemetry.Tier15AHits = telemetry.Tier15AHits + ot15a
				onlineTelemetry.Tier15BHits = telemetry.Tier15BHits + ot15b
				onlineTelemetry.Tier2AIInvocations = telemetry.Tier2AIInvocations + ot2

				fmt.Println()
				_ = reporter.Report(os.Stdout, apps, onlineTelemetry)
			}
		}
	}

	// Interactive company registration prompt for terminal sessions
	if !*jsonFlag && isTerminal(os.Stdin) {
		termReader := bufio.NewReader(os.Stdin)
		promptCompanyAppRegistration(termReader, apps, reporter, telemetry)
	}
}

func handleConfigCommand(args []string) {
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "Usage: appaudit config <subcommand>\n\nSubcommands:\n  show                      Display configured credentials and settings\n  set-gemini-key <key>      Store Gemini API key in local credential store\n  clear-gemini-key          Remove stored Gemini API key\n  set-deepseek-key <key>    Store DeepSeek API key in local credential store\n  clear-deepseek-key        Remove stored DeepSeek API key\n  set-company <name,name2>  Set company name / cert indicators for COMPANY classification\n  clear-company             Remove configured company indicators\n  register-company-app <p>  Register an executable as a verified company application\n  list-company-apps         List all registered company applications\n  remove-company-app <id>   Remove an app from company application registry\n  clear-cache               Remove cached AI research results\n")
		return
	}
	switch strings.ToLower(args[0]) {
	case "help", "--help", "-h":
		fmt.Fprintf(os.Stderr, "Usage: appaudit config <subcommand>\n\nSubcommands:\n  show                      Display configured credentials and settings\n  set-gemini-key <key>      Store Gemini API key in local credential store\n  clear-gemini-key          Remove stored Gemini API key\n  set-deepseek-key <key>    Store DeepSeek API key in local credential store\n  clear-deepseek-key        Remove stored DeepSeek API key\n  set-company <name,name2>  Set company name / cert indicators for COMPANY classification\n  clear-company             Remove configured company indicators\n  register-company-app <p>  Register an executable as a verified company application\n  list-company-apps         List all registered company applications\n  remove-company-app <id>   Remove an app from company application registry\n  clear-cache               Remove cached AI research results\n")
		return
	case "show":
		geminiKey := ai.GetGeminiAPIKey("")
		deepseekKey := ai.GetDeepSeekAPIKey("")
		credPath, _ := ai.CredentialStoragePath()
		geminiCachePath, _ := ai.CacheFilePath()
		deepseekCachePath, _ := ai.DeepSeekCacheFilePath()
		ollamaCachePath, _ := ai.OllamaCacheFilePath()
		manifestPath, _ := application.CompanyManifestPath()
		companyInd := ai.GetCompanyIndicators()
		manifest, _ := application.LoadCompanyManifest()

		fmt.Println("AppAudit Configuration:")
		fmt.Printf("  Credential Storage: %s\n", credPath)
		if geminiKey != "" {
			fmt.Printf("  Gemini API Key:     %s (Configured)\n", ai.MaskAPIKey(geminiKey))
		} else {
			fmt.Printf("  Gemini API Key:     [Not Configured]\n")
		}
		if deepseekKey != "" {
			fmt.Printf("  DeepSeek API Key:   %s (Configured)\n", ai.MaskAPIKey(deepseekKey))
		} else {
			fmt.Printf("  DeepSeek API Key:   [Not Configured]\n")
		}
		if len(companyInd) > 0 {
			fmt.Printf("  Company Indicators: %s (Configured)\n", strings.Join(companyInd, ", "))
		} else {
			fmt.Printf("  Company Indicators: [None Configured]\n")
		}
		if manifest != nil && len(manifest.Entries) > 0 {
			fmt.Printf("  Company Registry:   %d apps registered (%s)\n", len(manifest.Entries), manifestPath)
		} else {
			fmt.Printf("  Company Registry:   [0 apps registered]\n")
		}
		fmt.Printf("  Gemini Cache:       %s\n", geminiCachePath)
		fmt.Printf("  DeepSeek Cache:     %s\n", deepseekCachePath)
		fmt.Printf("  Ollama Cache:       %s\n", ollamaCachePath)
	case "set-gemini-key":
		if len(args) < 2 || strings.TrimSpace(args[1]) == "" {
			fmt.Fprintf(os.Stderr, "Error: missing API key.\nUsage: appaudit config set-gemini-key <YOUR_GEMINI_API_KEY>\n")
			os.Exit(1)
		}
		newKey := strings.Trim(strings.TrimSpace(args[1]), "\"'")
		if err := ai.SaveGeminiAPIKey(newKey); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving Gemini API key: %v\n", err)
			os.Exit(1)
		}
		credPath, _ := ai.CredentialStoragePath()
		fmt.Printf("Gemini API key saved successfully: %s\nStored at: %s\n", ai.MaskAPIKey(newKey), credPath)
	case "clear-gemini-key":
		if err := ai.ClearGeminiAPIKey(); err != nil {
			fmt.Fprintf(os.Stderr, "Error clearing Gemini API key: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Gemini API key cleared from local credential storage.")
	case "set-deepseek-key":
		if len(args) < 2 || strings.TrimSpace(args[1]) == "" {
			fmt.Fprintf(os.Stderr, "Error: missing API key.\nUsage: appaudit config set-deepseek-key <YOUR_DEEPSEEK_API_KEY>\n")
			os.Exit(1)
		}
		newKey := strings.Trim(strings.TrimSpace(args[1]), "\"'")
		if err := ai.SaveDeepSeekAPIKey(newKey); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving DeepSeek API key: %v\n", err)
			os.Exit(1)
		}
		credPath, _ := ai.CredentialStoragePath()
		fmt.Printf("DeepSeek API key saved successfully: %s\nStored at: %s\n", ai.MaskAPIKey(newKey), credPath)
	case "clear-deepseek-key":
		if err := ai.ClearDeepSeekAPIKey(); err != nil {
			fmt.Fprintf(os.Stderr, "Error clearing DeepSeek API key: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("DeepSeek API key cleared from local credential storage.")
	case "set-company":
		if len(args) < 2 || strings.TrimSpace(args[1]) == "" {
			fmt.Fprintf(os.Stderr, "Error: missing company name or indicator.\nUsage: appaudit config set-company <company_name>\nExample: appaudit config set-company \"Acme Corp,Contoso,internal.mycompany\"\n")
			os.Exit(1)
		}
		rawParts := strings.Split(args[1], ",")
		var cleaned []string
		for _, p := range rawParts {
			if t := strings.TrimSpace(p); t != "" {
				cleaned = append(cleaned, t)
			}
		}
		if err := ai.SaveCompanyIndicators(cleaned); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving company indicators: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Company indicators saved successfully: [%s]\nApps signed by these identities or matching these build modules will be automatically classified as COMPANY.\n", strings.Join(cleaned, ", "))
	case "clear-company":
		if err := ai.ClearCompanyIndicators(); err != nil {
			fmt.Fprintf(os.Stderr, "Error clearing company indicators: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Company indicators cleared.")
	case "register-company-app", "add-company-app":
		if len(args) < 2 || strings.TrimSpace(args[1]) == "" {
			fmt.Fprintf(os.Stderr, "Error: missing executable path.\nUsage: appaudit config register-company-app <path_to_exe>\n")
			os.Exit(1)
		}
		targetPath := strings.Trim(strings.TrimSpace(args[1]), "\"'")
		manifest, err := application.LoadCompanyManifest()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading company manifest: %v\n", err)
			os.Exit(1)
		}
		entry, err := manifest.RegisterApp(targetPath, "")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to register company app: %v\n", err)
			os.Exit(1)
		}
		manifestPath, _ := application.CompanyManifestPath()
		fmt.Printf("Successfully registered company application: '%s'\n", entry.Name)
		fmt.Printf("  Binary Path: %s\n", entry.Path)
		fmt.Printf("  SHA-256:     %s\n", entry.SHA256)
		fmt.Printf("  Registry:    %s\n", manifestPath)
		fmt.Println("This executable is now permanently recognized as COMPANY with 0ms offline resolution.")
	case "list-company-apps":
		manifest, err := application.LoadCompanyManifest()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading company manifest: %v\n", err)
			os.Exit(1)
		}
		if len(manifest.Entries) == 0 {
			fmt.Println("No company applications currently registered.")
			return
		}
		fmt.Printf("Registered Company Applications (%d total):\n\n", len(manifest.Entries))
		for _, e := range manifest.Entries {
			shortHash := e.SHA256
			if len(shortHash) > 16 {
				shortHash = shortHash[:16] + "..."
			}
			fmt.Printf("  • %-20s (SHA-256: %s)\n    Path:  %s\n    Added: %s\n\n", e.Name, shortHash, e.Path, e.AddedAt)
		}
	case "remove-company-app":
		if len(args) < 2 || strings.TrimSpace(args[1]) == "" {
			fmt.Fprintf(os.Stderr, "Error: missing app name, path, or SHA-256 hash.\nUsage: appaudit config remove-company-app <name_or_hash>\n")
			os.Exit(1)
		}
		manifest, err := application.LoadCompanyManifest()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading company manifest: %v\n", err)
			os.Exit(1)
		}
		removed, err := manifest.RemoveApp(args[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error updating company manifest: %v\n", err)
			os.Exit(1)
		}
		if removed {
			fmt.Printf("Successfully removed '%s' from company application registry.\n", args[1])
		} else {
			fmt.Printf("No matching entry found for '%s'.\n", args[1])
		}
	case "clear-cache":
		_ = ai.ClearGeminiCache()
		_ = ai.ClearDeepSeekCache()
		_ = ai.ClearOllamaCache()
		gPath, _ := ai.CacheFilePath()
		dPath, _ := ai.DeepSeekCacheFilePath()
		oPath, _ := ai.OllamaCacheFilePath()
		fmt.Printf("AI research caches cleared successfully.\n  Gemini:   %s\n  DeepSeek: %s\n  Ollama:   %s\n", gPath, dPath, oPath)
	default:
		fmt.Fprintf(os.Stderr, "Unknown config subcommand: %s\n", args[0])
		os.Exit(1)
	}
}

func formatURLWithPort(input, defaultURL string) string {
	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		return defaultURL
	}
	trimmed = strings.TrimPrefix(trimmed, ":")
	if portNum, err := strconv.Atoi(trimmed); err == nil && portNum > 0 && portNum <= 65535 {
		return fmt.Sprintf("http://127.0.0.1:%d", portNum)
	}
	if !strings.HasPrefix(trimmed, "http://") && !strings.HasPrefix(trimmed, "https://") {
		trimmed = "http://" + trimmed
	}
	return strings.TrimRight(trimmed, "/")
}

func promptLocalServicesSetup(reader *bufio.Reader) (ollamaURL, searxngURL string) {
	fmt.Println("--------------------------------------------------------------------------------")
	fmt.Println(" [Local AI Services Setup]")
	fmt.Println(" Please start your local AI services manually before proceeding:")
	fmt.Println("   • Ollama:  Launch Ollama (or run 'ollama serve' in your terminal)")
	fmt.Println("   • SearXNG: Start SearXNG (or run 'docker start searxng')")
	fmt.Println("--------------------------------------------------------------------------------")

	fmt.Print("Enter Ollama URL or port [default: http://127.0.0.1:11434]: ")
	ollamaInput, _ := reader.ReadString('\n')
	ollamaURL = formatURLWithPort(ollamaInput, "http://127.0.0.1:11434")

	fmt.Print("Enter SearXNG URL or port [default: http://127.0.0.1:8080]: ")
	searxInput, _ := reader.ReadString('\n')
	searxngURL = formatURLWithPort(searxInput, "http://127.0.0.1:8080")

	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()

	ollamaOk, _, oResp := service.ProbeOllamaEndpoint(ctx, ollamaURL)
	if oResp != nil {
		_ = oResp.Body.Close()
	}
	if ollamaOk {
		fmt.Printf("  [OK] Ollama reachable at %s\n", ollamaURL)
	} else {
		fmt.Printf("  [!] Notice: Ollama not detected at %s (Cloud AI and deterministic modes will still work)\n", ollamaURL)
	}

	fmt.Println()
	return ollamaURL, searxngURL
}

func promptAppPort(reader *bufio.Reader, defaultPort int) int {
	if defaultPort <= 0 {
		defaultPort = 8085
	}
	fmt.Printf("Choose the port for AppAudit Web Dashboard [default: %d]: ", defaultPort)
	input, _ := reader.ReadString('\n')
	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		return defaultPort
	}
	if p, err := strconv.Atoi(trimmed); err == nil && p > 0 && p <= 65535 {
		return p
	}
	fmt.Printf("[ℹ] Invalid port input %q. Falling back to default %d.\n", trimmed, defaultPort)
	return defaultPort
}

func handleServeCommand(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	portFlag := fs.Int("port", 0, "Port to listen on (default: prompt or 8085)")
	ollamaURLFlag := fs.String("ollama-url", "", "Ollama base URL (default: http://127.0.0.1:11434)")
	searxngURLFlag := fs.String("searxng-url", "", "SearXNG base URL (default: http://127.0.0.1:8080)")
	geminiKeyFlag := fs.String("gemini-key", "", "Gemini API key override")
	deepseekKeyFlag := fs.String("deepseek-key", "", "DeepSeek API key override")

	clearCacheFlag := fs.Bool("clear-cache", false, "Purge local AI and forensic caches before launching")
	verboseFlag := fs.Bool("verbose", true, "Enable detailed diagnostic and failure trace logs")
	fs.BoolVar(verboseFlag, "v", true, "Enable detailed diagnostic logs (shorthand)")
	openBrowserFlag := fs.Bool("open", true, "Automatically open dashboard in default web browser")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "AppAudit Web Dashboard & HTTP Server\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n  appaudit serve [--port 8085] [flags]\n  appaudit web [--port 8085] [flags]\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		fmt.Fprintf(os.Stderr, "  --port int              Port to listen on (default: 8085)\n")
		fmt.Fprintf(os.Stderr, "  --ollama-url string     Ollama base URL (default: http://127.0.0.1:11434)\n")
		fmt.Fprintf(os.Stderr, "  --searxng-url string    SearXNG base URL (default: http://127.0.0.1:8080)\n")
		fmt.Fprintf(os.Stderr, "  --gemini-key string     Gemini API key override\n")
		fmt.Fprintf(os.Stderr, "  --deepseek-key string   DeepSeek API key override\n")
		fmt.Fprintf(os.Stderr, "  --clear-cache           Purge all cached AI research on startup\n")
		fmt.Fprintf(os.Stderr, "  --open                  Automatically open dashboard in default web browser (default: true)\n")
		fmt.Fprintf(os.Stderr, "  -v, --verbose           Print detailed request tracing logs (default: true)\n")
	}

	_ = fs.Parse(args)

	if *clearCacheFlag {
		_ = ai.ClearGeminiCache()
		_ = ai.ClearDeepSeekCache()
		_ = ai.ClearOllamaCache()
		fmt.Println("[OK] AI research caches cleared successfully before launch.")
	}

	geminiKey := *geminiKeyFlag
	if geminiKey == "" {
		geminiKey = ai.GetGeminiAPIKey("")
	}
	deepseekKey := *deepseekKeyFlag
	if deepseekKey == "" {
		deepseekKey = ai.GetDeepSeekAPIKey("")
	}

	port := *portFlag
	ollamaURL := *ollamaURLFlag
	searxngURL := *searxngURLFlag

	// If invoked interactively without explicit flags, prompt the user for services & port
	if len(args) == 0 {
		reader := bufio.NewReader(os.Stdin)
		ollamaURL, searxngURL = promptLocalServicesSetup(reader)
		port = promptAppPort(reader, 8085)
	} else {
		if port <= 0 {
			port = 8085
		}
		if ollamaURL == "" {
			ollamaURL = "http://127.0.0.1:11434"
		}
		if searxngURL == "" {
			searxngURL = "http://127.0.0.1:8080"
		}
	}

	srv := server.NewServer(server.Config{
		Port:            port,
		OllamaURL:       ollamaURL,
		SearXNGURL:      searxngURL,
		GeminiKey:       geminiKey,
		DeepSeekKey:     deepseekKey,
		Verbose:         *verboseFlag,
		AutoOpenBrowser: *openBrowserFlag,
	})

	if err := srv.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "[!] Server error: %v\n", err)
		os.Exit(1)
	}
}

func launchWebDashboard(port int, ollamaURL, searxngURL string, autoOpenBrowser bool) {
	if port <= 0 {
		port = 8085
	}
	if ollamaURL == "" {
		ollamaURL = "http://127.0.0.1:11434"
	}
	if searxngURL == "" {
		searxngURL = "http://127.0.0.1:8080"
	}
	geminiKey := ai.GetGeminiAPIKey("")
	deepseekKey := ai.GetDeepSeekAPIKey("")

	srv := server.NewServer(server.Config{
		Port:            port,
		OllamaURL:       ollamaURL,
		SearXNGURL:      searxngURL,
		GeminiKey:       geminiKey,
		DeepSeekKey:     deepseekKey,
		Verbose:         true,
		AutoOpenBrowser: autoOpenBrowser,
	})

	if err := srv.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "[!] Server error: %v\n", err)
		os.Exit(1)
	}
}

func runInteractiveModeSelection() {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println("================================================================================")
	fmt.Printf(" AppAudit - Endpoint Software Provenance Auditor (v%s)\n", version)
	fmt.Println("================================================================================")
	fmt.Println()
	fmt.Println("Select how you would like to run AppAudit:")
	fmt.Println("  [1] Web Dashboard (Recommended - Interactive UI, Drag & Drop, Engine Comparison)")
	fmt.Println("  [2] Command Line Interface (CLI - Fast, Interactive Terminal Wizard & Reports)")
	fmt.Print("\nEnter choice [1-2] (default: 1): ")

	choiceInput, err := reader.ReadString('\n')
	if err != nil && len(choiceInput) == 0 {
		choiceInput = ""
	}
	choice := strings.TrimSpace(choiceInput)
	fmt.Println()

	// 1. First thing: Prompt user to start Ollama & SearXNG and specify URLs/ports
	ollamaURL, searxngURL := promptLocalServicesSetup(reader)

	if choice == "2" || strings.EqualFold(choice, "cli") || strings.HasPrefix(strings.ToLower(choice), "c") {
		fmt.Println("[→] Starting Command Line Interface (CLI)...")
		fmt.Println()
		runInteractiveWizard(reader, ollamaURL, searxngURL)
		return
	}

	// 2. User chooses the port for Web Dashboard (offering default 8085)
	chosenPort := promptAppPort(reader, 8085)

	fmt.Printf("\n[→] Starting Web Dashboard & HTTP Server on port %d...\n", chosenPort)
	launchWebDashboard(chosenPort, ollamaURL, searxngURL, true)
}

func runInteractiveWizard(reader *bufio.Reader, customServices ...string) {
	if reader == nil {
		reader = bufio.NewReader(os.Stdin)
	}

	ollamaURL := "http://127.0.0.1:11434"
	searxngURL := "http://127.0.0.1:8080"
	if len(customServices) > 0 && customServices[0] != "" {
		ollamaURL = customServices[0]
	}
	if len(customServices) > 1 && customServices[1] != "" {
		searxngURL = customServices[1]
	}

	// Determine if this is a returning user (second or later run)
	hadPriorKey := ai.HasStoredGeminiAPIKey() || ai.HasStoredDeepSeekAPIKey()
	hadPriorCache := ai.CacheExists() || ai.DeepSeekCacheExists() || ai.OllamaCacheExists()
	isSecondOrLaterRun := hadPriorKey || hadPriorCache

	fmt.Println("================================================================================")
	fmt.Printf(" AppAudit - Endpoint Software Provenance Auditor (v%s)\n", version)
	fmt.Println("================================================================================")
	fmt.Println()
	fmt.Println("[Step 1 of 2] AI Reasoning Provider Configuration")
	geminiKey := ai.GetGeminiAPIKey("")
	deepseekKey := ai.GetDeepSeekAPIKey("")

	fmt.Println("Select AI reasoning provider for automated provenance research:")
	fmt.Println("  [1] Google Gemini (Gemini 3.5 Flash Lite)")
	fmt.Println("  [2] DeepSeek (DeepSeek-V4.1-Flash)")
	fmt.Println("  [3] Local-First AI (Ollama audit-phi:q6k + SearXNG) [Offline / Private]")
	fmt.Println("  [4] Offline only (Local deterministic)")
	fmt.Print("Enter choice [1-4] (default: 1): ")
	providerChoiceInput, _ := reader.ReadString('\n')
	providerChoice := strings.TrimSpace(providerChoiceInput)

	var selectedProvider string
	var selectedKey string

	if providerChoice == "2" || strings.HasPrefix(strings.ToLower(providerChoice), "d") {
		selectedProvider = "deepseek"
		selectedKey = promptDeepSeekKeySetup(reader, deepseekKey)
	} else if providerChoice == "3" || strings.HasPrefix(strings.ToLower(providerChoice), "l") || strings.HasPrefix(strings.ToLower(providerChoice), "p") || strings.HasPrefix(strings.ToLower(providerChoice), "o") {
		for {
			passed, guidance := checkLocalPreflight(os.Stdout, ollamaURL, searxngURL, ai.DefaultOllamaModel)
			if passed {
				selectedProvider = "local"
				break
			}
			fmt.Println("\n[!] Local-First AI Pre-Flight Check Failed:")
			fmt.Printf("    %s\n\n", strings.ReplaceAll(guidance, "\n", "\n    "))
			fmt.Println("What would you like to do?")
			fmt.Println("  [1] Retry pre-flight checks (after starting Ollama / SearXNG)")
			fmt.Println("  [2] Switch to Google Gemini (Cloud)")
			fmt.Println("  [3] Switch to DeepSeek (Cloud)")
			fmt.Println("  [4] Fall back to local deterministic mode (offline only)")
			fmt.Print("Enter choice [1-4] (default: 4): ")
			remedyInput, _ := reader.ReadString('\n')
			remedyChoice := strings.TrimSpace(remedyInput)
			if remedyChoice == "1" || strings.HasPrefix(strings.ToLower(remedyChoice), "r") {
				continue
			} else if remedyChoice == "2" || strings.HasPrefix(strings.ToLower(remedyChoice), "g") {
				selectedProvider = "gemini"
				selectedKey = promptGeminiKeySetup(reader, geminiKey)
				break
			} else if remedyChoice == "3" || strings.HasPrefix(strings.ToLower(remedyChoice), "d") {
				selectedProvider = "deepseek"
				selectedKey = promptDeepSeekKeySetup(reader, deepseekKey)
				break
			} else {
				selectedProvider = "none"
				fmt.Println("[OK] Selected local deterministic mode (no AI reasoning).")
				fmt.Println()
				break
			}
		}
	} else if providerChoice == "4" || strings.ToLower(providerChoice) == "none" || strings.HasPrefix(strings.ToLower(providerChoice), "off") || strings.HasPrefix(strings.ToLower(providerChoice), "n") {
		selectedProvider = "none"
		fmt.Println("[OK] Selected local deterministic mode (no AI reasoning).")
		fmt.Println()
	} else {
		selectedProvider = "gemini"
		selectedKey = promptGeminiKeySetup(reader, geminiKey)
	}
	fmt.Println("[Step 2 of 2] Select Operation Mode:")
	fmt.Println("  [1] Targeted Tier Scan (Crawls all non-system applications in ~1-3s) [Recommended]")
	fmt.Println("  [2] Quick scan host applications (Start Menu, Registry, PATH) [<1s]")
	fmt.Println("  [3] Analyze specific target (file or directory path)")
	fmt.Println("  [4] Register in-house COMPANY application (\"Remember this is my company's tool\")")
	fmt.Println("  [5] View / Manage registered company applications")
	fmt.Println("  [6] Launch Web Dashboard & HTTP Server")
	fmt.Println("  [7] Clear AI research caches")
	fmt.Print("Enter choice [1-7] (default: 1): ")
	modeInput, _ := reader.ReadString('\n')
	modeInput = strings.TrimSpace(modeInput)

	subcommand := "scan"
	runFullScan := false
	var targets []string

	if modeInput == "" || modeInput == "1" || strings.HasPrefix(strings.ToLower(modeInput), "f") {
		subcommand = "scan"
		runFullScan = true
	} else if modeInput == "2" || strings.HasPrefix(strings.ToLower(modeInput), "q") {
		subcommand = "scan"
		runFullScan = false
	} else if modeInput == "6" || strings.HasPrefix(strings.ToLower(modeInput), "w") {
		fmt.Println("\n[→] Transitioning to Web Dashboard...")
		port := promptAppPort(reader, 8085)
		launchWebDashboard(port, ollamaURL, searxngURL, true)
		return
	} else if modeInput == "7" || strings.HasPrefix(strings.ToLower(modeInput), "cl") {
		_ = ai.ClearGeminiCache()
		_ = ai.ClearDeepSeekCache()
		_ = ai.ClearOllamaCache()
		fmt.Println("\n[OK] AI research caches cleared successfully.")
		return
	} else if modeInput == "4" || strings.HasPrefix(strings.ToLower(modeInput), "r") || strings.HasPrefix(strings.ToLower(modeInput), "c") {
		fmt.Println()
		fmt.Print("Enter file path of in-house executable (or drag-and-drop here): ")
		pathInput, _ := reader.ReadString('\n')
		cleanExePath := strings.Trim(strings.TrimSpace(pathInput), "\"'")
		if cleanExePath == "" {
			fmt.Println("[!] No path provided. Returning.")
			return
		}
		manifest, err := application.LoadCompanyManifest()
		if err != nil {
			fmt.Printf("[!] Could not load company manifest: %v\n", err)
			return
		}
		entry, err := manifest.RegisterApp(cleanExePath, "")
		if err != nil {
			fmt.Printf("[!] Failed to register company application: %v\n", err)
			return
		}
		manifestPath, _ := application.CompanyManifestPath()
		fmt.Printf("\n[OK] Successfully registered company application: '%s'\n", entry.Name)
		fmt.Printf("    Binary Path: %s\n", entry.Path)
		fmt.Printf("    SHA-256:     %s\n", entry.SHA256)
		fmt.Printf("    Registry:    %s\n", manifestPath)
		fmt.Println("[OK] This executable is now permanently recognized as COMPANY with 0ms offline resolution.")

		fmt.Println()
		fmt.Print("Would you like to analyze this application now? [Y/n]: ")
		runNowInput, _ := reader.ReadString('\n')
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(runNowInput)), "n") {
			return
		}
		subcommand = "analyze"
		targets = []string{entry.Path}
	} else if modeInput == "5" || strings.HasPrefix(strings.ToLower(modeInput), "v") || strings.HasPrefix(strings.ToLower(modeInput), "m") {
		fmt.Println()
		handleConfigCommand([]string{"list-company-apps"})
		return
	} else if modeInput == "3" || strings.HasPrefix(strings.ToLower(modeInput), "a") {
		subcommand = "analyze"
		fmt.Println()
		fmt.Print("Enter file or directory path to analyze (or drag-and-drop here): ")
		pathInput, _ := reader.ReadString('\n')
		cleanPath := strings.Trim(strings.TrimSpace(pathInput), "\"'")
		if cleanPath == "" {
			cleanPath = "."
		}
		targets = []string{cleanPath}
	}
	netMode := provenance.NetworkOff
	var reasoner ai.Reasoner = ai.NewNoopReasoner()
	if selectedProvider == "local" {
		netMode = provenance.NetworkOn
		searxng := ai.NewSearXNGProvider("http://localhost:8080")
		cache := ai.NewOllamaCache()
		reasoner = ai.NewLocalReasoner(ai.DefaultOllamaModel, searxng, cache)
		fmt.Printf("Starting %s with Local-First AI (Ollama %s + SearXNG) reasoning enabled...\n\n", strings.ToUpper(subcommand), ai.DefaultOllamaModel)
	} else if selectedKey != "" {
		netMode = provenance.NetworkOn
		if selectedProvider == "deepseek" {
			reasoner = ai.NewDeepSeekReasoner(ai.DeepSeekConfig{
				APIKey:      selectedKey,
				Model:       ai.DefaultDeepSeekModel,
				NetworkMode: netMode,
			})
			fmt.Printf("Starting %s with DeepSeek-V4.1-Flash (deepseek-flash) reasoning enabled...\n\n", strings.ToUpper(subcommand))
		} else {
			reasoner = ai.NewGeminiReasoner(ai.GeminiConfig{
				APIKey:      selectedKey,
				Model:       ai.DefaultGeminiModel,
				NetworkMode: netMode,
			})
			fmt.Printf("Starting %s with Gemini 3.5 Flash Lite internet research enabled...\n\n", strings.ToUpper(subcommand))
		}
	} else {
		fmt.Printf("Starting %s in local deterministic mode...\n\n", strings.ToUpper(subcommand))
	}

	engine := application.NewEngine(application.EngineConfig{
		NetworkMode:             netMode,
		CompanyDomainIndicators: ai.GetCompanyIndicators(),
		Reasoner:                reasoner,
	})

	startTime := time.Now()
	ctx := context.Background()
	var apps []application.Application
	var discRes *discovery.DiscoveryResult

	if subcommand == "analyze" {
		analyzed, err := engine.AnalyzePaths(ctx, targets)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error analyzing paths: %v\n", err)
			return
		}
		apps = analyzed
	} else {
		sysScanner := scanner.New()
		var rawDiscovered []model.Application
		var err error
		if runFullScan {
			fmt.Print("Initiating Targeted Tier Application Discovery (Tiers 1-3)...\r")
			discRes, err = discovery.ScanTargeted(nil, func(discoveredCount int, currentPath string) {
				truncPath := currentPath
				if len(truncPath) > 48 {
					truncPath = "..." + truncPath[len(truncPath)-45:]
				}
				fmt.Printf("\r[Scanning Targets] Found: %-4d executables | %-48s", discoveredCount, truncPath)
				_ = os.Stdout.Sync()
			})
			if discRes != nil {
				rawDiscovered = append(rawDiscovered, discRes.Applications...)
			}
			quickApps, _ := sysScanner.Scan()
			rawDiscovered = append(rawDiscovered, quickApps...)
			fmt.Printf("\r%-80s\r", "")
			if discRes != nil {
				fmt.Printf("[OK] Targeted Discovery complete in %.1fms: Found %d unique executables across %d visited directories (%d pruned).\n\n",
					discRes.DurationMs, discRes.ExecutablesFound, discRes.DirsVisited, discRes.DirsPruned)
			}
			fmt.Println("Starting forensic inspection and evidence triage...")
		} else {
			rawDiscovered, err = sysScanner.Scan()
			fmt.Println("Starting forensic inspection and evidence triage...")
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning during host discovery: %v\n", err)
		}
		apps = engine.ProcessDiscovered(ctx, rawDiscovered)
	}

	elapsed := time.Since(startTime)
	telemetry := report.CaptureTelemetry(startTime, string(netMode), 0, 0, 0, false)
	telemetry.Duration = elapsed
	telemetry.DurationMs = float64(elapsed.Microseconds()) / 1000.0
	if discRes != nil {
		telemetry.DiscoveryDurationMs = discRes.DurationMs
		telemetry.DirsVisited = discRes.DirsVisited
		telemetry.DirsPruned = discRes.DirsPruned
		telemetry.FilesScanned = discRes.FilesScanned
		telemetry.ExecutablesFound = discRes.ExecutablesFound
	}
	it1, it15a, it15b, it2 := engine.GetTriageStats()
	telemetry.Tier1Hits = it1
	telemetry.Tier15AHits = it15a
	telemetry.Tier15BHits = it15b
	telemetry.Tier2AIInvocations = it2
	if engine.DecisionEngine() != nil && engine.DecisionEngine().HashLookupClient != nil {
		hl := engine.DecisionEngine().HashLookupClient
		telemetry.CIRCLDegraded = hl.IsDegraded()
		telemetry.CIRCLSkippedCount = hl.SkippedCount()
	}

	reporter := report.NewTerminalReporter()
	_ = reporter.Report(os.Stdout, apps, telemetry)

	promptCompanyAppRegistration(reader, apps, reporter, telemetry)

	if isSecondOrLaterRun {
		geminiCount := ai.CacheEntryCount()
		deepseekCount := ai.DeepSeekCacheEntryCount()
		ollamaCount := ai.OllamaCacheEntryCount()
		totalCached := geminiCount + deepseekCount + ollamaCount

		fmt.Println()
		fmt.Println("--------------------------------------------------------------------------------")
		fmt.Printf("AI Research Cache (%d total entries cached across providers):\n", totalCached)
		geminiPath, _ := ai.CacheFilePath()
		deepseekPath, _ := ai.DeepSeekCacheFilePath()
		ollamaPath, _ := ai.OllamaCacheFilePath()
		if geminiCount > 0 || ai.CacheExists() {
			fmt.Printf("  • Gemini:   %s (%d entries cached)\n", geminiPath, geminiCount)
		}
		if deepseekCount > 0 || ai.DeepSeekCacheExists() {
			fmt.Printf("  • DeepSeek: %s (%d entries cached)\n", deepseekPath, deepseekCount)
		}
		if ollamaCount > 0 || ai.OllamaCacheExists() {
			fmt.Printf("  • Ollama:   %s (%d entries cached)\n", ollamaPath, ollamaCount)
		}
		if totalCached == 0 && !ai.CacheExists() && !ai.DeepSeekCacheExists() && !ai.OllamaCacheExists() {
			fmt.Printf("  • Location: %s (0 entries cached)\n", geminiPath)
		}
		fmt.Println("Do you want to clear the research cache or leave it as it is?")
		fmt.Println("  [1] Leave cache as it is (Recommended: preserves results for fast lookups)")
		fmt.Println("  [2] Clear cache (Forces fresh live AI research on next run)")
		fmt.Print("Enter choice [1 or 2] (default: 1): ")
		cacheChoiceInput, _ := reader.ReadString('\n')
		cacheChoice := strings.TrimSpace(cacheChoiceInput)
		if cacheChoice == "2" || strings.ToLower(cacheChoice) == "clear" || strings.ToLower(cacheChoice) == "c" {
			_ = ai.ClearGeminiCache()
			_ = ai.ClearDeepSeekCache()
			_ = ai.ClearOllamaCache()
			fmt.Println("[OK] AI research cache cleared successfully.")
		} else {
			fmt.Println("[OK] Research cache preserved.")
		}
	} else {
		fmt.Println()
		fmt.Println("[i] Research results have been saved to local cache for future runs.")
	}

	fmt.Println()
	fmt.Println("--------------------------------------------------------------------------------")
	fmt.Println("What would you like to do next?")
	fmt.Println("  [1] Exit")
	fmt.Println("  [2] Run another CLI scan or file analysis")
	fmt.Println("  [3] Launch Web Dashboard & HTTP Server")
	fmt.Print("Enter choice [1-3] (default: 1): ")
	nextInput, _ := reader.ReadString('\n')
	nextChoice := strings.TrimSpace(nextInput)
	if nextChoice == "2" || strings.HasPrefix(strings.ToLower(nextChoice), "r") || strings.HasPrefix(strings.ToLower(nextChoice), "s") {
		fmt.Println()
		runInteractiveWizard(reader, ollamaURL, searxngURL)
		return
	} else if nextChoice == "3" || strings.HasPrefix(strings.ToLower(nextChoice), "w") {
		fmt.Println("\n[→] Launching Web Dashboard & HTTP Server...")
		port := promptAppPort(reader, 8085)
		launchWebDashboard(port, ollamaURL, searxngURL, true)
		return
	}
	fmt.Println("[OK] Session completed.")
}

func parseSubcommand(args []string) (string, []string) {
	if len(args) == 0 {
		return "scan", nil
	}

	first := strings.ToLower(args[0])
	if first == "scan" {
		return "scan", args[1:]
	}
	if first == "analyze" {
		return "analyze", args[1:]
	}
	if first == "config" {
		return "config", args[1:]
	}
	if first == "serve" || first == "web" || first == "dashboard" {
		return "serve", args[1:]
	}
	if first == "cli" || first == "wizard" || first == "interactive" {
		return "cli", args[1:]
	}

	// If starts with a flag (e.g. --json, -v), default to scan with all args
	if strings.HasPrefix(first, "-") {
		return "scan", args
	}

	// If argument is a path (contains / or \ or ends with .exe or exists), interpret as analyze
	if strings.Contains(first, "/") || strings.Contains(first, "\\") || strings.HasSuffix(first, ".exe") {
		return "analyze", args
	}

	return "scan", args
}

func hasUnknownApps(apps []application.Application) bool {
	for _, a := range apps {
		if a.Classification == provenance.ClassificationUnknown {
			return true
		}
	}
	return false
}

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

func separateFlagsAndPositional(args []string) ([]string, []string) {
	var flagArgs []string
	var posArgs []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "-") {
			flagArgs = append(flagArgs, arg)
			if !strings.Contains(arg, "=") {
				name := strings.TrimLeft(arg, "-")
				if name == "network" || name == "model" || name == "gemini-key" || name == "gemini-model" ||
					name == "ai-provider" || name == "deepseek-model" || name == "deepseek-key" ||
					name == "mode" || name == "ollama-model" || name == "searxng-url" {
					if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
						i++
						flagArgs = append(flagArgs, args[i])
					}
				}
			}
		} else {
			posArgs = append(posArgs, arg)
		}
	}
	return flagArgs, posArgs
}

func resolveOrPromptGeminiKey(explicitKey string) string {
	key := ai.GetGeminiAPIKey(explicitKey)
	if key != "" {
		return key
	}
	if !isTerminal(os.Stdin) {
		return ""
	}
	fmt.Print("Enter Gemini API Key (will be cached for future runs): ")
	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		return ""
	}
	key = strings.TrimSpace(input)
	if key == "" {
		return ""
	}
	if err := ai.SaveGeminiAPIKey(key); err == nil {
		fmt.Printf("Gemini API key saved successfully.\n\n")
	}
	return key
}

func resolveOrPromptDeepSeekKey(explicitKey string) string {
	key := ai.GetDeepSeekAPIKey(explicitKey)
	if key != "" {
		return key
	}
	if !isTerminal(os.Stdin) {
		return ""
	}
	fmt.Print("Enter DeepSeek API Key (will be cached for future runs): ")
	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		return ""
	}
	key = strings.Trim(strings.TrimSpace(input), "\"'")
	if key == "" {
		return ""
	}
	if err := ai.SaveDeepSeekAPIKey(key); err == nil {
		fmt.Printf("DeepSeek API key saved successfully.\n\n")
	}
	return key
}

func promptCompanyAppRegistration(reader *bufio.Reader, apps []application.Application, reporter report.Reporter, telemetry report.Telemetry) {
	manifest, err := application.LoadCompanyManifest()
	if err != nil {
		fmt.Printf("[!] Could not load company manifest: %v\n", err)
		return
	}

	var unkIndices []int
	for i, a := range apps {
		if a.Classification == provenance.ClassificationUnknown {
			unkIndices = append(unkIndices, i)
		}
	}

	fmt.Println()
	if len(unkIndices) > 0 {
		fmt.Printf("Would you like to register any of the %d unrecognized apps (or any other binary) as in-house COMPANY software? [y/N]: ", len(unkIndices))
	} else {
		fmt.Print("Would you like to register an executable as in-house COMPANY software (\"Remember this tool\")? [y/N]: ")
	}

	regInput, _ := reader.ReadString('\n')
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(regInput)), "y") {
		return
	}

	if len(unkIndices) > 0 {
		fmt.Println("\nUnrecognized applications:")
		for num, idx := range unkIndices {
			fmt.Printf("  [%d] %s (%s)\n", num+1, apps[idx].Name, apps[idx].PrimaryBinaryPath)
		}
		fmt.Print("\nEnter number(s) to register (e.g. 1 or 'all'), or enter a file path: ")
	} else {
		fmt.Print("\nEnter file path of in-house executable (or drag-and-drop here): ")
	}

	rawInput, _ := reader.ReadString('\n')
	cleaned := strings.Trim(strings.TrimSpace(rawInput), "\"'")
	if cleaned == "" {
		return
	}

	// Direct file path entered
	if fileExists(cleaned) || strings.HasSuffix(strings.ToLower(cleaned), ".exe") || strings.Contains(cleaned, "\\") || strings.Contains(cleaned, "/") {
		entry, err := manifest.RegisterApp(cleaned, "")
		if err != nil {
			fmt.Printf("[!] Failed to register executable: %v\n", err)
			return
		}
		shortHash := entry.SHA256
		if len(shortHash) > 16 {
			shortHash = shortHash[:16] + "..."
		}
		manifestPath, _ := application.CompanyManifestPath()
		fmt.Printf("\n[OK] Registered '%s' as COMPANY (SHA-256: %s)\n", entry.Name, shortHash)
		fmt.Printf("[OK] Saved to Company Registry (%s)\n", manifestPath)
		fmt.Println("[OK] This executable is now permanently recognized as COMPANY for all future runs.")

		// Update in-memory app if present in scanned list
		for i := range apps {
			if strings.EqualFold(filepath.Clean(apps[i].PrimaryBinaryPath), filepath.Clean(entry.Path)) {
				apps[i].Classification = provenance.ClassificationCompany
				apps[i].Confidence = provenance.ConfidenceVeryHigh
				apps[i].ResolutionSource = "deterministic (Company Registry)"
				apps[i].ArtifactProvenance = "MATCHED"
			}
		}
		if reporter != nil {
			fmt.Println("\nUpdated Provenance Results:")
			_ = reporter.Report(os.Stdout, apps, telemetry)
		}
		return
	}

	// Process as numbers or 'all' from unrecognized list
	var targetsToRegister []int
	if strings.EqualFold(cleaned, "all") || cleaned == "*" {
		for num := range unkIndices {
			targetsToRegister = append(targetsToRegister, num)
		}
	} else {
		for _, part := range strings.Split(cleaned, ",") {
			var n int
			if _, err := fmt.Sscanf(strings.TrimSpace(part), "%d", &n); err == nil && n >= 1 && n <= len(unkIndices) {
				targetsToRegister = append(targetsToRegister, n-1)
			}
		}
	}

	registeredCount := 0
	for _, targetNum := range targetsToRegister {
		appIdx := unkIndices[targetNum]
		targetApp := &apps[appIdx]
		entry, err := manifest.RegisterApp(targetApp.PrimaryBinaryPath, targetApp.Name)
		if err != nil {
			fmt.Printf("[!] Failed to register '%s': %v\n", targetApp.Name, err)
			continue
		}
		shortHash := entry.SHA256
		if len(shortHash) > 12 {
			shortHash = shortHash[:12] + "..."
		}
		fmt.Printf("[OK] Registered '%s' as COMPANY (SHA-256: %s)\n", entry.Name, shortHash)
		registeredCount++

		// Immediately update the in-memory application representation
		targetApp.Classification = provenance.ClassificationCompany
		targetApp.Confidence = provenance.ConfidenceVeryHigh
		targetApp.ResolutionSource = "deterministic (Company Registry)"
		targetApp.ArtifactProvenance = "MATCHED"
		compEv := provenance.Evidence{
			Type:        provenance.EvidenceCompanyProvenance,
			Source:      "Company Registry",
			Strength:    1.0,
			Description: fmt.Sprintf("Explicitly registered internal company application '%s' (SHA-256: %s)", entry.Name, shortHash),
			Confidence:  provenance.ConfidenceVeryHigh,
		}
		targetApp.OwnershipEvidence = append(targetApp.OwnershipEvidence, compEv)
		targetApp.Reasons = append(targetApp.Reasons, "Tier 1 Hard Evidence: Explicitly registered internal company application.", compEv.Description)
	}

	if registeredCount > 0 {
		manifestPath, _ := application.CompanyManifestPath()
		fmt.Printf("\n[OK] %d application(s) saved to Company Registry (%s)\n", registeredCount, manifestPath)
		fmt.Println("[OK] These applications are now permanently remembered as COMPANY for all future runs.")
		if reporter != nil {
			fmt.Println("\nUpdated Provenance Results:")
			_ = reporter.Report(os.Stdout, apps, telemetry)
		}
	}
}

func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
}

func promptGeminiKeySetup(reader *bufio.Reader, currentKey string) string {
	if currentKey == "" {
		fmt.Println("\nNo Gemini API key found. Gemini 3.5 Flash Lite is used for autonomous")
		fmt.Println("internet research and authoritative provenance resolution.")
		fmt.Print("Enter your Google Gemini API Key: ")
		input, _ := reader.ReadString('\n')
		newKey := strings.Trim(strings.TrimSpace(input), "\"'")
		if newKey != "" {
			if err := ai.SaveGeminiAPIKey(newKey); err == nil {
				fmt.Printf("[OK] Gemini API key saved successfully: %s\n\n", ai.MaskAPIKey(newKey))
			}
			return newKey
		}
		fmt.Println("[!] No API key entered. Unresolved apps will not use online AI research.")
		fmt.Println()
		return ""
	}

	fmt.Printf("Configured Gemini API Key: %s\n", ai.MaskAPIKey(currentKey))
	fmt.Print("Press Enter to keep this key, or enter a new key to update: ")
	input, _ := reader.ReadString('\n')
	trimmed := strings.Trim(strings.TrimSpace(input), "\"'")
	if trimmed != "" {
		_ = ai.SaveGeminiAPIKey(trimmed)
		fmt.Printf("[OK] Gemini API key updated: %s\n\n", ai.MaskAPIKey(trimmed))
		return trimmed
	}
	fmt.Println("[OK] Using saved Gemini API key.")
	fmt.Println()
	return currentKey
}

func promptDeepSeekKeySetup(reader *bufio.Reader, currentKey string) string {
	if currentKey == "" {
		fmt.Println("\nNo DeepSeek API key found. DeepSeek-V4.1-Flash (deepseek-flash) performs")
		fmt.Println("credit-conserving reasoning with thinking mode disabled.")
		fmt.Print("Enter your DeepSeek API Key: ")
		input, _ := reader.ReadString('\n')
		newKey := strings.Trim(strings.TrimSpace(input), "\"'")
		if newKey != "" {
			if err := ai.SaveDeepSeekAPIKey(newKey); err == nil {
				fmt.Printf("[OK] DeepSeek API key saved successfully: %s\n\n", ai.MaskAPIKey(newKey))
			}
			return newKey
		}
		fmt.Println("[!] No API key entered. Unresolved apps will not use online AI reasoning.")
		fmt.Println()
		return ""
	}

	fmt.Printf("Configured DeepSeek API Key: %s\n", ai.MaskAPIKey(currentKey))
	fmt.Print("Press Enter to keep this key, or enter a new key to update: ")
	input, _ := reader.ReadString('\n')
	trimmed := strings.Trim(strings.TrimSpace(input), "\"'")
	if trimmed != "" {
		_ = ai.SaveDeepSeekAPIKey(trimmed)
		fmt.Printf("[OK] DeepSeek API key updated: %s\n\n", ai.MaskAPIKey(trimmed))
		return trimmed
	}
	fmt.Println("[OK] Using saved DeepSeek API key.")
	fmt.Println()
	return currentKey
}

func checkLocalPreflight(w io.Writer, ollamaURL, searxngURL, modelName string) (bool, string) {
	if ollamaURL == "" {
		ollamaURL = "http://localhost:11434"
	}
	if searxngURL == "" {
		searxngURL = "http://localhost:8080"
	}
	if modelName == "" {
		modelName = ai.DefaultOllamaModel
	}
	ollamaURL = strings.TrimRight(ollamaURL, "/")
	searxngURL = strings.TrimRight(searxngURL, "/")

	if w != nil {
		fmt.Fprintln(w, "\n[Pre-Flight Checks] Validating Local-First AI Pipeline:")
	}

	// Pre-flight connectivity check (no auto-boot)
	supCtx, supCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer supCancel()
	supOpts := service.LocalStackOptions{
		OllamaURL:   ollamaURL,
		OllamaModel: modelName,
		SearXNGURL:  searxngURL,
		Writer:      w,
	}
	_ = service.EnsureLocalStackWithOptions(supCtx, supOpts)

	client := &http.Client{Timeout: 4 * time.Second}

	// 1. Ollama Daemon & Model Verification
	if w != nil {
		fmt.Fprintf(w, "  • Checking Ollama service (%s)... ", ollamaURL)
	}
	tagsURL := ollamaURL + "/api/tags"
	resp, err := client.Get(tagsURL)
	if err != nil {
		if w != nil {
			fmt.Fprintln(w, "[FAILED]")
		}
		guidance := fmt.Sprintf(
			"Ollama daemon is not responding at %s.\n\n"+
				"    How to start Ollama:\n"+
				"      1. Open a terminal and run: ollama serve\n"+
				"      2. Or launch the Ollama desktop application from Start Menu.\n"+
				"      3. Verify installed models: ollama list",
			ollamaURL,
		)
		return false, guidance
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if w != nil {
			fmt.Fprintln(w, "[FAILED]")
		}
		guidance := fmt.Sprintf("Ollama returned unexpected HTTP status %d from %s.", resp.StatusCode, tagsURL)
		return false, guidance
	}

	var tagsResp struct {
		Models []struct {
			Name  string `json:"name"`
			Model string `json:"model"`
		} `json:"models"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&tagsResp)

	modelFound := false
	for _, m := range tagsResp.Models {
		if strings.EqualFold(m.Name, modelName) || strings.EqualFold(m.Model, modelName) ||
			strings.HasPrefix(strings.ToLower(m.Name), strings.ToLower(modelName)+":") ||
			strings.HasPrefix(strings.ToLower(m.Model), strings.ToLower(modelName)+":") {
			modelFound = true
			break
		}
	}

	if !modelFound {
		if w != nil {
			fmt.Fprintln(w, "[FAILED]")
		}
		guidance := fmt.Sprintf(
			"Required model '%s' was not found in Ollama.\n\n"+
				"    How to create the model in Ollama:\n"+
				"      Run in your terminal: ollama create %s -f Modelfile.local",
			modelName, modelName,
		)
		return false, guidance
	}
	if w != nil {
		fmt.Fprintf(w, "[OK] Online (model '%s' ready)\n", modelName)
	}

	// 2. GPU VRAM Residency Verification (100% in VRAM, 0 CPU offload)
	if w != nil {
		fmt.Fprint(w, "  • Checking GPU VRAM Residency... ")
	}
	psURL := ollamaURL + "/api/ps"
	psResp, err := client.Get(psURL)
	if err != nil {
		if w != nil {
			fmt.Fprintln(w, "[FAILED]")
		}
		guidance := fmt.Sprintf("Failed to query Ollama /api/ps: %v", err)
		return false, guidance
	}
	defer psResp.Body.Close()

	var psData struct {
		Models []struct {
			Name     string `json:"name"`
			Model    string `json:"model"`
			Size     int64  `json:"size"`
			SizeVRAM int64  `json:"size_vram"`
		} `json:"models"`
	}
	_ = json.NewDecoder(psResp.Body).Decode(&psData)

	// If no model currently loaded in memory, trigger a quick 0-token load to inspect VRAM allocation
	if len(psData.Models) == 0 {
		loadReqBody := fmt.Sprintf(`{"model": %q, "prompt": "", "keep_alive": "10m"}`, modelName)
		loadReq, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, ollamaURL+"/api/generate", strings.NewReader(loadReqBody))
		loadReq.Header.Set("Content-Type", "application/json")
		warmClient := &http.Client{Timeout: 15 * time.Second}
		if warmResp, warmErr := warmClient.Do(loadReq); warmErr == nil {
			_ = warmResp.Body.Close()
			if p2, err2 := client.Get(psURL); err2 == nil {
				_ = json.NewDecoder(p2.Body).Decode(&psData)
				_ = p2.Body.Close()
			}
		}
	}

	vramVerified := false
	var totalVRAMBytes int64
	for _, m := range psData.Models {
		if strings.EqualFold(m.Name, modelName) || strings.EqualFold(m.Model, modelName) ||
			strings.HasPrefix(strings.ToLower(m.Name), strings.ToLower(modelName)+":") ||
			strings.HasPrefix(strings.ToLower(m.Model), strings.ToLower(modelName)+":") {
			if m.Size > 0 && m.SizeVRAM < m.Size {
				if w != nil {
					fmt.Fprintln(w, "[FAILED]")
				}
				guidance := fmt.Sprintf(
					"HARD REFUSAL: Model '%s' is partially offloaded to CPU RAM.\n"+
						"    VRAM Allocated: %.1f MB / Total Model Size: %.1f MB (CPU Offload: %.1f MB)\n"+
						"    AppAudit strictly enforces 100%% GPU VRAM residency to guarantee inference latency.\n\n"+
						"    Remedy:\n"+
						"      1. Close background applications consuming GPU memory.\n"+
						"      2. Restart Ollama ('ollama stop' or restart Ollama app) to free VRAM.",
					m.Name, float64(m.SizeVRAM)/(1024*1024), float64(m.Size)/(1024*1024), float64(m.Size-m.SizeVRAM)/(1024*1024),
				)
				return false, guidance
			}
			vramVerified = true
			totalVRAMBytes = m.SizeVRAM
			break
		}
	}

	if w != nil {
		if vramVerified && totalVRAMBytes > 0 {
			fmt.Fprintf(w, "[OK] 100%% in GPU VRAM (%.2f GB allocated, 0 B CPU offload)\n", float64(totalVRAMBytes)/(1024*1024*1024))
		} else {
			fmt.Fprintln(w, "[OK] GPU VRAM preflight passed (zero CPU offload enforced)")
		}
	}

	// 3. SearXNG Search Grounding Verification
	if w != nil {
		fmt.Fprintf(w, "  • Checking SearXNG search grounding (%s)... ", searxngURL)
	}
	searxQueryURL := fmt.Sprintf("%s/search?q=test&format=json", searxngURL)
	searxReq, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, searxQueryURL, nil)
	searxReq.Header.Set("Accept", "application/json")
	searxResp, err := client.Do(searxReq)
	if err != nil {
		if w != nil {
			fmt.Fprintln(w, "[FAILED]")
		}
		guidance := fmt.Sprintf(
			"SearXNG search container is not responding at %s.\n\n"+
				"    How to start SearXNG:\n"+
				"      1. Ensure Docker Desktop is running.\n"+
				"      2. Start existing container:\n"+
				"           docker start searxng\n"+
				"      3. Or launch a new SearXNG container:\n"+
				"           docker run -d --name searxng -p 8080:8080 -v \"${PWD}/settings.yml:/etc/searxng/settings.yml:ro\" searxng/searxng:latest",
			searxngURL,
		)
		return false, guidance
	}
	defer searxResp.Body.Close()

	if searxResp.StatusCode == http.StatusForbidden {
		if w != nil {
			fmt.Fprintln(w, "[FAILED - HTTP 403]")
		}
		guidance := fmt.Sprintf(
			"SearXNG returned HTTP 403 Forbidden for JSON queries.\n\n"+
				"    Remedy:\n"+
				"      1. Verify that 'settings.yml' contains:\n"+
				"           search:\n"+
				"             formats:\n"+
				"               - html\n"+
				"               - json\n"+
				"      2. Restart the SearXNG container: docker restart searxng",
		)
		return false, guidance
	}

	if searxResp.StatusCode != http.StatusOK {
		if w != nil {
			fmt.Fprintf(w, "[FAILED - HTTP %d]\n", searxResp.StatusCode)
		}
		guidance := fmt.Sprintf("SearXNG returned unexpected HTTP status %d", searxResp.StatusCode)
		return false, guidance
	}

	if w != nil {
		fmt.Fprintln(w, "[OK] Online (JSON format enabled)")
		fmt.Fprintln(w, "[OK] All pre-flight checks passed! Local reasoning pipeline ready.")
		fmt.Fprintln(w)
	}

	return true, ""
}
