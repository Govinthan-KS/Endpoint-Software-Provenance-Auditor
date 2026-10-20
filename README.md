# AppAudit - Endpoint Software Auditor (v2.1.0)

A lightweight, zero-external-runtime CLI utility in Go that discovers applications installed on an endpoint, deterministically filters out recognized software, and cross-checks unrecognized applications against digital sources using Google Search-grounded reasoning.

```text
                    ENDPOINT APPLICATION DISCOVERY
                (Start Menu, Registry, Program Files, PATH)
                                  ↓
                   DETERMINISTIC RECOGNITION FILTER
            (Authenticode signatures, OS manifests, Go buildinfo)
                                  ↓
         ┌────────────────────────┴────────────────────────┐
         ↓                                                 ↓
    RECOGNIZED                                       UNRECOGNIZED
(Filtered Out / Local)                         (Interactive / CLI Gemini)
         ↓                                                 ↓
    THIRD_PARTY                                  GEMINI + GOOGLE SEARCH
(Sub-millisecond verdict)                                  ↓
                                                 Identify App & Project
                                                           ↓
                                                Collect Evidence & Sources
                                                           ↓
                                                 ┌─────────┴─────────┐
                                                 ↓                   ↓
                                            Identified          Inconclusive
                                                 ↓                   ↓
                                            THIRD_PARTY           UNKNOWN
                                                 ↓                   ↓
                                            STORE CACHE         STORE CACHE
                                                 ↓                   ↓
                                            SUBSEQUENT RUN: CACHE HIT (0ms)
```

---

## The Core Product Workflow

1. **Endpoint Application Discovery**
   * Discovers installed desktop applications, portable binaries, and suites across Windows Start Menu shortcuts, Registry Uninstall keys (32-bit & 64-bit), standard program directories, and user PATH.

2. **Deterministic Recognition Filter**
   * Fast, local-first evaluation filters out software that is already legitimately recognized:
     * **Authenticode Signatures**: Valid cryptographic digital signatures from recognized commercial software publishers (Microsoft, Google, JetBrains, Docker, etc.).
     * **OS Package Registration**: Officially installed software registered in host system installer manifests.
     * **Compiler Build Metadata**: Binaries with embedded compiler module paths pointing to public open-source project repositories (e.g. `github.com/...`).

3. **Digital Research on Unrecognized Applications**
   * Applications that remain unrecognized after deterministic filtering are evaluated by Gemini using live Google Search grounding:
     * Discovers official vendor websites, source repositories, documentation, and releases.
     * Corroborates whether the binary represents legitimate third-party open-source or commercial software.
     * Displays concise verdict, identified project/publisher, evidence claims, and authoritative source URLs.

4. **Disk-Backed Research Caching**
   * Structured digital research findings are persisted locally in `%APPDATA%\appaudit\gemini_cache.json`.
   * Cache keys are computed from the application identity, version, primary executable SHA-256, and suite layout.
   * Subsequent scans retrieve results instantly from local cache (`CACHE HIT`), requiring zero network queries.

---

## Directory & Package Layout

```text
cmd/audit/
  main.go                     -> CLI entrypoint, flag parsing, tripartite table rendering, interactive prompts
  console_windows.go          -> Windows Explorer double-click auto-pause detection
  console_other.go            -> Non-Windows console stub
internal/
  model/
    app.go                    -> Application and binary target models, executable classification filters
  scanner/
    scanner.go                -> Platform scanner abstraction
    scanner_windows.go        -> Windows Start Menu (.lnk) + Registry (64/32) + PATH discovery
    lnk_windows.go            -> Windows .lnk shell link parser
    scanner_darwin.go         -> macOS bundle & path discovery
    scanner_linux.go          -> Linux desktop & path discovery
  application/
    engine.go                 -> Main discovery, grouping, inspection, and classification engine
    reconciler.go             -> Groups related executables into cohesive application suites
    decision.go               -> Deterministic recognition rules and Gemini grounding gate
    identity.go               -> Candidate application naming and structural heuristic signals
    evidence.go               -> Evidence bundle and claim representations
    model.go                  -> Application data structures
  provenance/
    evidence.go               -> Classification, Confidence, EvidenceType, and NetworkMode models
    fingerprint.go            -> Streaming local SHA-256 fingerprinting
    inspector.go              -> BinaryInspector abstraction and metadata models
    inspector_pe.go           -> Authenticode X.509 cert extraction, PE headers, version resources
    inspect_build.go          -> Go debug/buildinfo reader & embedded component signatures
    inspector_unix.go         -> ELF and Mach-O inspection
    cache.go                  -> Binary forensic inspection cache
  ai/
    gemini.go                 -> Gemini Reasoner with Google Search grounding
    gemini_cache.go           -> Disk-backed research cache (%APPDATA%\appaudit\gemini_cache.json)
    deepseek.go               -> DeepSeek Reasoner with credit-conservation safeguards
    deepseek_cache.go         -> Disk-backed research cache (%APPDATA%\appaudit\deepseek_cache.json)
    credentials.go            -> Secure local credential storage (%APPDATA%\appaudit\credentials.json)
    reasoner.go               -> Reasoner interface & reasoning result schema
    local.go                  -> Optional local LLM reasoner
    mock.go                   -> Test mock reasoner
    noop.go                   -> No-op offline fallback reasoner
  report/
    report.go                 -> Explanatory terminal report & JSON formatter
```

---

## Usage

### 1. Interactive Dual-Mode Launcher (Default)
When opened without flags or double-clicked from File Explorer / Desktop, AppAudit prompts you to choose your interface:
```text
================================================================================
 AppAudit - Endpoint Software Provenance Auditor (v2.1.0)
================================================================================

Select how you would like to run AppAudit:
  [1] Web Dashboard (Recommended - Interactive UI, Drag & Drop, Engine Comparison)
  [2] Command Line Interface (CLI - Fast, Interactive Terminal Wizard & Reports)

Enter choice [1-2] (default: 1): 
```

- **[1] Web Dashboard**: Launches the embedded HTTP server on `http://localhost:8085`, automatically opens your default browser, shares a Wi-Fi URL for colleagues, and provides a drag-and-drop UI, side-by-side engine benchmark comparisons, 4-stage early exit tracking, token economics, and dual-tier logs.
- **[2] Command Line Interface**: Steps through the interactive 2-step terminal setup wizard with full offline/cloud AI reasoning, targeted tier scanning, and in-house company app registration.

### 2. Direct Subcommand Invocations
```bash
# Launch Web Dashboard directly:
audit web
# or:
audit serve --port 8085

# Launch interactive CLI wizard directly:
audit cli

# Non-interactive CLI scans:
audit scan
audit scan --quick
audit analyze "C:\Tools\myutility.exe"
```

# DeepSeek (DeepSeek-V4.1-Flash with native web search via Responses API)
audit scan --network on --ai --ai-provider deepseek

# With custom model identifier or toggling native search:
audit scan --network on --ai --ai-provider deepseek --deepseek-model deepseek-flash --deepseek-search=true
```
Passes unresolved applications to the selected AI provider (Gemini or DeepSeek), executing server-side web research via Google Search Grounding (Gemini) or Responses API Native Search (DeepSeek), rendering authoritative sources and caching positive & inconclusive results locally.

### 3. Inspect Specific Binaries or Application Folders
```bash
audit analyze "C:\Tools\myutility.exe" --network on --ai
audit analyze "C:\Tools\myutility.exe" --ai-provider deepseek --deepseek-key <KEY>
```

### 4. Manage AI Credentials
```bash
# View configuration and stored key status
audit config show

# Store Gemini API key locally (cached in %APPDATA%\appaudit\credentials.json)
audit config set-gemini-key <YOUR_GEMINI_API_KEY>
audit config clear-gemini-key

# Store DeepSeek API key locally
audit config set-deepseek-key <YOUR_DEEPSEEK_API_KEY>
audit config clear-deepseek-key
```

### 5. In-House Company Applications ("Remember this is my company's tool")
In-house proprietary tools often don't have commercial certificates or public web hits. You can register them so AppAudit permanently remembers them as `COMPANY` with zero network overhead (0ms deterministic lookup):

```bash
# Register an internal binary (binds cryptographic SHA-256 and path)
audit config register-company-app "C:\Tools\payroll_sync.exe"

# List registered company software
audit config list-company-apps

# Remove an application from the registry
audit config remove-company-app "payroll_sync"

# Configure company certificate / domain indicators (matches code signing certs or internal Go modules)
audit config set-company "Acme Corp,Contoso,internal.mycompany.com"
```

*Note: When running interactively or by double-clicking `audit.exe`:*
* *Select Option `[3]` in the main menu to directly register an in-house executable by path or drag-and-drop.*
* *At the conclusion of any scan/audit, AppAudit prompts whether to register any unrecognized applications (by number) or custom binaries (by file path).*

### 6. Managing the Cache
```bash
# Clear stored digital research results
audit config clear-cache
```

### 7. Structured JSON Output
```bash
audit analyze "C:\Program Files\Git" --json
```

---

## Verification & Testing

AppAudit includes comprehensive test suites protecting deterministic filtering, adversarial boundary integrity, and caching:

```bash
# Run code analysis
go vet ./...

# Run all unit and integration tests
go test ./...

# Compile production binary
go build ./cmd/audit
```
