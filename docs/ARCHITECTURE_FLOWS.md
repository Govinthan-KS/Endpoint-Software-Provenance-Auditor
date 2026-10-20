# AppAudit: Comprehensive Architecture & Execution Flow Graphs

This document details the architectural blueprints, execution pipelines, data paths, decision trees, and service relationships within **AppAudit**. Every major workflow is paired with a visual **Mermaid.js** diagram and plain-English operational explanations.

---

## Table of Contents

1. [Master System Topology (Full Application Graph)](#1-master-system-topology-full-application-graph)
2. [Complete Forensic Triage Decision Tree (The Core Engine Flow)](#2-complete-forensic-triage-decision-tree-the-core-engine-flow)
3. [Web Dashboard & Scan Target Flows (All 4 Scan Modes)](#3-web-dashboard--scan-target-flows-all-4-scan-modes)
   - [3.1 Single File Upload (`POST /api/v1/audit/upload`)](#31-single-file-upload-post-apiv1auditupload)
   - [3.2 Host Quick Scan (`POST /api/v1/audit/quick`)](#32-host-quick-scan-post-apiv1auditquick)
   - [3.3 Deep Host Scan (`POST /api/v1/audit/full`)](#33-deep-host-scan-post-apiv1auditfull)
   - [3.4 Custom Directory Audit (`POST /api/v1/audit/directory`)](#34-custom-directory-audit-post-apiv1auditdirectory)
4. [Multi-Engine Comparison Benchmark Flow (`POST /api/v1/audit/compare`)](#4-multi-engine-comparison-benchmark-flow-post-apiv1auditcompare)
5. [AI Provider & Local Service Supervision Flow](#5-ai-provider--local-service-supervision-flow)
6. [Cache Architecture & Dual-Tier Logging Flow](#6-cache-architecture--dual-tier-logging-flow)
   - [6.1 4-Store Cache Lifecycle](#61-4-store-cache-lifecycle)
   - [6.2 Dual-Tier Logging & PII Masking Pipeline](#62-dual-tier-logging--pii-masking-pipeline)
7. [Complete CLI Subcommand Routing Graph](#7-complete-cli-subcommand-routing-graph)

---

## 1. Master System Topology (Full Application Graph)

The following diagram illustrates how all components, entry points, packages, background supervisors, and caches interact across the application boundary.

```mermaid
flowchart TD
    subgraph Users ["Client Interaction Channels"]
        CLI_User["CLI Terminal User"]
        Browser_User["Web Browser Client (Chrome / Edge / Firefox)"]
    end

    subgraph Entrypoints ["Application Entrypoints"]
        Main["cmd/audit/main.go (CLI Dispatcher & Interactive Wizard)"]
        ServerCore["internal/server/server.go (Strict Loopback: 127.0.0.1:8085)"]
    end

    subgraph WebApp ["Embedded Presentation Layer"]
        IndexHTML["internal/server/web/index.html (Single-File Glassmorphic UI)"]
        DialogWindows["internal/server/dialog_windows.go (Native COM IFileDialog Picker)"]
    end

    subgraph ServerHandlers ["HTTP API Route Handlers (internal/server)"]
        H_Audit["handlers_audit.go (/api/v1/audit/*, /api/v1/preflight/stats)"]
        H_Compare["handlers_compare.go (/api/v1/audit/compare)"]
        H_System["handlers_system.go (/api/v1/health, cache, company, config, dialog)"]
        LoggingCore["logging.go (MaskPII, Dual-Tier Logger, Request Telemetry)"]
    end

    subgraph CoreEngine ["Application Engine (internal/application)"]
        Engine["engine.go (Worker Pools, Parallel Coordination, Chunking)"]
        DecisionTree["decision.go (Multi-Tier Forensic Triage & Grounding Gate)"]
        IdentityEngine["identity.go (Package Name, Publisher & Version Resolution)"]
        Reconciler["reconciler.go (Multi-Binary Executable Grouping)"]
        CompanyManifest["manifest.go (In-House Corporate Software Registry)"]
    end

    subgraph Discovery ["Host Discovery & Crawlers"]
        ScannerWindows["internal/scanner/scanner_windows.go (Registry, Start Menu, PATH)"]
        Crawler["internal/discovery/scanner.go (Recursive Filesystem Walker)"]
        Collector["internal/discovery/collector.go (Targeted Folder Roots)"]
    end

    subgraph Forensics ["Binary Forensic Extractors (internal/provenance)"]
        PE_Inspector["inspector_pe.go (Authenticode, Cert Chains, .rsrc Strings)"]
        Build_Inspector["inspect_build.go (Go Compiler debug/buildinfo Metadata)"]
        Pkg_Inspector["inspector_pkgmgr.go (Scoop, Cargo, Chocolatey, Winget)"]
        Runtime_Inspector["inspector_runtime.go (Python dist-info, Node package.json)"]
        Strings_Inspector["inspector_strings.go (.rdata Public Git URLs, VersionInfo)"]
        CIRCL_Client["client_hashlookup.go (CIRCL Hashlookup Client & Circuit Breaker)"]
        ProvCache["cache.go (Thread-Safe SHA-256 Provenance Cache)"]
    end

    subgraph AI_Reasoning ["AI Grounding & Reasoning (internal/ai)"]
        NoopAI["noop.go (Deterministic Mode: 0 Tokens, 0ms)"]
        GeminiClient["gemini.go (Google Gemini + Google Search Grounding)"]
        DeepSeekClient["deepseek.go (DeepSeek Cloud Reasoning & Web Search)"]
        OllamaClient["ollama.go (Local Ollama LLM + SearXNG Grounding)"]
        PromptMgr["prompt.go (Dynamic System Prompts & Few-Shot Instruction)"]
        AICache["cache.go (Persistent Disk & In-Memory AI Verdict Caches)"]
    end

    subgraph Supervision ["Background Service Supervisor (internal/service)"]
        Supervisor["supervisor.go (Ollama GPU Check & SearXNG Docker Auto-Boot)"]
    end

    %% Flows
    CLI_User -->|Launches scan / analyze / config| Main
    Browser_User -->|Accesses http://127.0.0.1:8085| ServerCore
    Main -->|Subcommand: serve / web| ServerCore
    Main -->|Subcommand: scan / analyze| Engine

    ServerCore --> IndexHTML
    ServerCore --> H_Audit
    ServerCore --> H_Compare
    ServerCore --> H_System

    H_System --> DialogWindows
    H_System --> LoggingCore
    H_Audit --> LoggingCore
    H_Compare --> LoggingCore

    H_Audit --> Engine
    H_Compare --> Engine
    H_System --> CompanyManifest
    H_System --> AICache
    H_System --> ProvCache

    Engine --> ScannerWindows
    Engine --> Crawler
    Engine --> Collector
    Engine --> Reconciler
    Engine --> DecisionTree

    DecisionTree --> IdentityEngine
    DecisionTree --> CompanyManifest
    DecisionTree --> PE_Inspector
    DecisionTree --> Build_Inspector
    DecisionTree --> Pkg_Inspector
    DecisionTree --> Runtime_Inspector
    DecisionTree --> Strings_Inspector
    DecisionTree --> CIRCL_Client
    DecisionTree --> ProvCache

    DecisionTree -->|Unresolved fallback| NoopAI
    DecisionTree -->|Unresolved fallback| GeminiClient
    DecisionTree -->|Unresolved fallback| DeepSeekClient
    DecisionTree -->|Unresolved fallback| OllamaClient

    GeminiClient --> AICache
    DeepSeekClient --> AICache
    OllamaClient --> AICache
    OllamaClient --> Supervisor
    GeminiClient --> PromptMgr
    DeepSeekClient --> PromptMgr
    OllamaClient --> PromptMgr
```

### Explanation of System Topology

- **Dual Interaction Interfaces**: Users can interact through the interactive terminal CLI (`audit.exe scan`, `audit.exe cli`) or launch the embedded translucent desktop web app (`audit.exe web` or `audit.exe serve`).
- **Strict Loopback Binding**: The web dashboard is locked to `127.0.0.1:8085`. It rejects external network connections, preventing firewall security alerts and eliminating unauthorized LAN access.
- **Engine Coordination**: The `internal/application/engine.go` acts as the central conductor. It coordinates host discovery (`internal/scanner`), disk directory crawling (`internal/discovery`), binary forensic decomposition (`internal/provenance`), and optional AI reasoning models (`internal/ai`).
- **Resilient Fallback Design**: If an AI backend is slow, unconfigured, or offline, the supervisor (`internal/service`) and decision tree (`internal/application/decision.go`) smoothly fall back to deterministic cryptographic rules with zero system crashes.

---

## 2. Complete Forensic Triage Decision Tree (The Core Engine Flow)

The decision engine evaluates binaries through a hierarchical 4-stage pipeline. The moment definitive proof is established at an upper layer, analysis **immediately early exits**, saving CPU time and avoiding unnecessary API roundtrips.

```mermaid
flowchart TD
    Start(["Input Binary (.exe)"]) --> CheckManifest{"Pre-Check:<br/>Registered In-House<br/>Enterprise Manifest?"}

    %% Pre-Check
    CheckManifest -- "Yes (Path / SHA-256 match)" --> ExitCompany["Verdict: IN-HOUSE<br/>Source: Registered Internal Enterprise Tool<br/>Confidence: Very High<br/>AI Bypassed: Yes (Stage 1)"]
    CheckManifest -- "No" --> Stage1_Sig{"Stage 1: Authenticode<br/>Digital Signature<br/>Valid & Signed?"}

    %% Stage 1
    Stage1_Sig -- "Internal Company Cert" --> ExitCompanyCert["Verdict: IN-HOUSE<br/>Source: Verified Enterprise Code-Signing<br/>Confidence: High<br/>AI Bypassed: Yes (Stage 1)"]
    Stage1_Sig -- "External Commercial Cert<br/>(e.g., Microsoft, Google, DigiCert)" --> ExitThirdPartySig["Verdict: THIRD-PARTY<br/>Source: Verified Publisher Signature<br/>Confidence: Very High<br/>AI Bypassed: Yes (Stage 1)"]
    Stage1_Sig -- "Unsigned or Invalid Cert" --> Stage1_Build{"Stage 1: Compiler Metadata<br/>Go debug/buildinfo<br/>embedded?"}

    Stage1_Build -- "Official Go Toolchain<br/>(go.exe / gofmt.exe)" --> ExitGoTool["Verdict: THIRD-PARTY<br/>Source: Public Open-Source Build Metadata<br/>Confidence: High<br/>AI Bypassed: Yes (Stage 1)"]
    Stage1_Build -- "Public Open-Source Module<br/>(github.com/*, gitlab.com/*)" --> ExitGoMod["Verdict: THIRD-PARTY<br/>Source: Public Open-Source Build Metadata<br/>Confidence: High<br/>AI Bypassed: Yes (Stage 1)"]
    Stage1_Build -- "No Go Metadata" --> Stage1_Product{"Stage 1: Verified Vendor<br/>PE Version Resource in<br/>Program Files / WindowsApps?"}

    Stage1_Product -- "Recognized External Vendor" --> ExitProdMeta["Verdict: THIRD-PARTY<br/>Source: Verified Publisher Signature<br/>Confidence: High<br/>AI Bypassed: Yes (Stage 1)"]
    Stage1_Product -- "Unverified / Custom Folder" --> Stage2_Pkg{"Stage 2: Local Package<br/>Manager Receipts<br/>(Scoop / Cargo / Choco / Winget)?"}

    %% Stage 2
    Stage2_Pkg -- "Match in Manifest / Receipt" --> ExitPkgReceipt["Verdict: THIRD-PARTY<br/>Source: Local Package Manifest Receipt<br/>Confidence: Very High<br/>AI Bypassed: Yes (Stage 2)"]
    Stage2_Pkg -- "No Package Receipt" --> Stage2_Runtime{"Stage 2: Runtime Ecosystem<br/>Receipts (Python dist-info,<br/>Node package.json)?"}

    Stage2_Runtime -- "Valid dist-info / package.json" --> ExitRuntimeReceipt["Verdict: THIRD-PARTY<br/>Source: Local Package Manifest Receipt<br/>Confidence: Very High<br/>AI Bypassed: Yes (Stage 2)"]
    Stage2_Runtime -- "No Runtime Receipt" --> Stage2_Strings{"Stage 2: String Mining<br/>Discovered Public Git URL<br/>in .rdata / PE strings?"}

    Stage2_Strings -- "Valid Public Repo URL" --> ExitStringMining["Verdict: THIRD-PARTY<br/>Source: Public Open-Source Build Metadata<br/>Confidence: High<br/>AI Bypassed: Yes (Stage 2)"]
    Stage2_Strings -- "No Public Repository Found" --> Stage3_CIRCL{"Stage 3: Public Hash Registry<br/>CIRCL Hashlookup Query<br/>(NSRL / RDS database)?"}

    %% Stage 3
    Stage3_CIRCL -- "Exact Hash Match Found" --> ExitCIRCL["Verdict: THIRD-PARTY<br/>Source: Public Registry Hash Match (CIRCL)<br/>Confidence: Deterministic<br/>AI Bypassed: Yes (Stage 3)"]
    Stage3_CIRCL -- "HTTP 429 Rate Limited" --> CirclDegraded["Trip Circuit Breaker (60s)<br/>Bypass CIRCL for remaining binaries"] --> Stage4_Router
    Stage3_CIRCL -- "Hash Not Found / Offline Mode" --> Stage4_Router{"Stage 4: AI Reasoning Mode<br/>Selected by User?"}

    %% Stage 4
    Stage4_Router -- "none (Deterministic Only)" --> ExitUnknown["Verdict: UNVERIFIED / UNKNOWN<br/>Source: Heuristic Analysis<br/>Confidence: None / Low<br/>Early Exit: Rule F Fallback"]
    Stage4_Router -- "gemini" --> GeminiExec["Invoke Google Gemini<br/>with Google Search Grounding"]
    Stage4_Router -- "deepseek" --> DeepSeekExec["Invoke DeepSeek<br/>Native Reasoning with Grounding"]
    Stage4_Router -- "ollama" --> OllamaExec["Invoke Local Ollama<br/>+ SearXNG Web Grounding"]

    GeminiExec --> AIGate{"Grounding Gate<br/>Verification"}
    DeepSeekExec --> AIGate
    OllamaExec --> AIGate

    AIGate -- "Authoritative Vendor / Release Match" --> ExitAIThirdParty["Verdict: THIRD-PARTY<br/>Source: AI Provenance Inspection<br/>Confidence: High / Medium<br/>Artifact Provenance: MATCHED"]
    AIGate -- "Unverified Forum Post / Weak Signal" --> ExitAIUnknown["Verdict: UNVERIFIED / UNKNOWN<br/>Source: AI Provenance Inspection (Inconclusive)<br/>Confidence: Low<br/>Artifact Provenance: NOT_ESTABLISHED"]
    AIGate -- "API Error (401 / 429 / Timeout)" --> ExitAIError["Verdict: UNVERIFIED / UNKNOWN<br/>Source: AI Evaluation Error<br/>AI Error Banner Populated (Non-blocking)"]
```

### Forensic Stages Explained

1. **Enterprise Manifest Pre-Check**: Checks `company_manifest.json` for paths or hashes explicitly registered by administrator teams. Matches resolve immediately as `IN_HOUSE` in 0ms.
2. **Stage 1 (Cryptographic & Compiler Layer)**: Inspects Authenticode certificates via WinTrust APIs, embedded Go toolchain markers, and valid PE VersionInfo resources.
3. **Stage 2 (Local Receipt & String Mining)**: Checks Scoop app directories, Cargo crates registries, Chocolatey manifests, Python `dist-info`, and `.rdata` read-only section strings for repository URLs.
4. **Stage 3 (Public Hash Registry)**: Queries the CIRCL Hashlookup API (NSRL/RDS repository). If the server returns HTTP 429 (Too Many Requests), a circuit breaker trips for 60 seconds to maintain scan velocity.
5. **Stage 4 (AI Reasoning & Grounding Gate)**: When deterministic steps are inconclusive, the binary evidence bundle is routed to the selected AI provider. The strict **Grounding Gate** rejects subjective forum claims and only accepts verified publisher domains or exact cryptographic asset releases.

---

## 3. Web Dashboard & Scan Target Flows (All 4 Scan Modes)

### 3.1 Single File Upload (`POST /api/v1/audit/upload`)

```mermaid
sequenceDiagram
    autonumber
    actor User as Browser User
    participant UI as index.html
    participant Srv as handlers_audit.go
    participant Temp as Windows Disk / Temp
    participant Eng as engine.go
    participant Dec as decision.go

    User->>UI: Drag & Drop Binary or Select via Native File Dialog
    UI->>Srv: POST /api/v1/audit/upload (multipart/form-data, mode=gemini)
    Note over Srv: Enforce MaxUploadBytes = 500 MB ceiling
    Srv->>Temp: os.CreateTemp("appaudit-upload-*.exe")
    Srv->>Temp: Stream upload bytes via io.Copy
    Srv->>Temp: Explicit tempFile.Close() (unlocks Windows file-handle)
    Srv->>Eng: InspectSingleBinary(tempPath, originalFilename)
    Eng->>Dec: Decide(ctx, app, bundle)
    Dec-->>Eng: Returns Application verdict & TokenEconomics
    Eng-->>Srv: Returns *Application
    Srv->>Temp: defer os.Remove(tempPath)
    Srv->>UI: HTTP 200 OK (JSON AuditResponse)
    UI->>User: Render Audit Verdict Card, Stage Pill, and Token Economics
```

### 3.2 Host Quick Scan (`POST /api/v1/audit/quick`)

```mermaid
sequenceDiagram
    autonumber
    actor User as Browser User
    participant UI as index.html
    participant Srv as handlers_audit.go
    participant Pre as handlers_audit.go (Preflight)
    participant Scan as scanner_windows.go
    participant Eng as engine.go
    participant Rec as reconciler.go

    User->>UI: Click [Host Quick Scan]
    UI->>Pre: POST /api/v1/preflight/stats {target: "quick"}
    Pre-->>UI: Return estimated count (~50-70 apps) & ETA (<2s)
    UI->>Srv: POST /api/v1/audit/quick (mode=none)
    Srv->>Scan: DiscoverQuickScan()
    Scan->>Scan: Read Windows Registry (Uninstall keys)
    Scan->>Scan: Read User & System Start Menu shortcuts (.lnk)
    Scan->>Scan: Scan user-space PATH executables
    Scan-->>Srv: Return raw []ApplicationBinary candidates
    Srv->>Eng: RunQuickScan()
    Eng->>Eng: Worker pool triage (Stage 1 -> Stage 2 -> Stage 3)
    Eng->>Rec: Group secondary helper binaries into primary apps
    Rec-->>Eng: Consolidated []Application list
    Eng-->>Srv: BuildMultiAppResponse()
    Srv-->>UI: HTTP 200 OK (JSON MultiAppScanResponse)
    UI->>User: Render Discovered Inventory Table & Category Counters
```

### 3.3 Deep Host Scan (`POST /api/v1/audit/full`)

```mermaid
flowchart TD
    StartFull(["User triggers Deep Host Scan"]) --> ExcludeRules["Apply System Directory Exclusion Filter<br/>(C:\Windows, WinSxS, System32, $Recycle.Bin, AppData Temp)"]
    ExcludeRules --> DiscoverRoots["Target Non-System Application Roots<br/>(Program Files, Program Files (x86), ProgramData, LocalAppData\Programs)"]
    DiscoverRoots --> Walk["Recursive Filesystem Walker<br/>(internal/discovery/scanner.go)"]
    Walk --> Prune["Directory Pruner: Skip node_modules, .git, cache, venv"]
    Prune --> Dedup["Deduplicate Executables by SHA-256 Hash"]
    Dedup --> WorkerPool["Worker Pool (8 Parallel Workers)<br/>Forensic Triage Pipeline"]
    WorkerPool --> Reconcile["Reconcile & Deduplicate<br/>(internal/application/reconciler.go)"]
    Reconcile --> Response["Aggregate Scan Economics Summary & Return JSON Array"]
```

### 3.4 Custom Directory Audit (`POST /api/v1/audit/directory`)

```mermaid
sequenceDiagram
    autonumber
    actor User as Browser User
    participant UI as index.html
    participant Dialog as handlers_system.go (/dialog/folder)
    participant Native as dialog_windows.go (COM IFileDialog)
    participant Srv as handlers_audit.go (/audit/directory)
    participant Eng as engine.go

    User->>UI: Click [Browse...] folder button
    UI->>Dialog: POST /api/v1/dialog/folder
    Dialog->>Native: Invoke ShowFolderPicker() via PowerShell STA thread
    Native-->>User: Display Native Windows Explorer Folder Browser
    User->>Native: Selects "D:\MyTools"
    Native-->>Dialog: Returns "D:\MyTools"
    Dialog-->>UI: HTTP 200 OK {"path": "D:\\MyTools"}
    UI->>User: Populates directory input field
    User->>UI: Click [Audit Selected Directory]
    UI->>Srv: POST /api/v1/audit/directory {path: "D:\\MyTools", mode: "none"}
    Note over Srv: Security Guard: Reject UNC paths (\\attacker\share)
    Srv->>Eng: AnalyzePaths(ctx, ["D:\\MyTools"])
    Eng->>Eng: Crawl directory recursively & evaluate binaries
    Eng-->>Srv: Return classified application inventory
    Srv-->>UI: HTTP 200 OK (MultiAppScanResponse)
    UI->>User: Display directory audit metrics and findings
```

---

## 4. Multi-Engine Comparison Benchmark Flow (`POST /api/v1/audit/compare`)

The Comparison Benchmark allows cross-evaluating multiple reasoning engines (Deterministic, Ollama, Gemini, DeepSeek) against identical software applications.

```mermaid
sequenceDiagram
    autonumber
    actor User as Auditor / Engineer
    participant UI as index.html
    participant Srv as handlers_compare.go
    participant Forensics as internal/provenance
    participant Engines as Engine Evaluators (Parallel)

    User->>UI: Select binary + Check engines [Deterministic, Gemini, DeepSeek]
    UI->>Srv: POST /api/v1/audit/compare (modes=["none", "gemini", "deepseek"])
    Note over Srv: Forensic Optimization: Extract PE & Hashes ONCE
    Srv->>Forensics: InspectBinary(tempPath)
    Forensics-->>Srv: Return shared EvidenceBundle
    
    par Evaluate Engine 1 (none)
        Srv->>Engines: Run Deterministic Engine (Offline)
        Engines-->>Srv: Verdict 1 (THIRD_PARTY, 1.2ms, 0 tokens)
    and Evaluate Engine 2 (gemini)
        Srv->>Engines: Run Gemini Grounded Engine (Cloud)
        Engines-->>Srv: Verdict 2 (THIRD_PARTY, 840ms, 1,420 tokens)
    and Evaluate Engine 3 (deepseek)
        Srv->>Engines: Run DeepSeek Reasoning Engine (Cloud)
        Engines-->>Srv: Verdict 3 (THIRD_PARTY, 1,120ms, 980 tokens)
    end

    Note over Srv: Consensus Evaluation: Do all verdicts agree?
    Srv->>Srv: Compare verdicts -> Agreement: true (Unanimous)
    Srv->>Srv: Identify Fastest -> "Deterministic Only" (1.2ms)
    Srv->>Srv: Generate Takeaway -> "Deterministic reached identical verdict 700x faster with 0 API cost."
    Srv-->>UI: HTTP 200 OK (JSON CompareResponse)
    UI->>User: Render Comparison Matrix, Efficiency Winner badge & Latency delta
```

---

## 5. AI Provider & Local Service Supervision Flow

This diagram illustrates how AppAudit manages cloud AI endpoints and automatically provisions local offline LLM/Search stacks.

```mermaid
flowchart TD
    Request(["AI Reasoning Request"]) --> ProviderCheck{"Selected Provider?"}

    %% Ollama Local Stack
    ProviderCheck -- "ollama (Local Offline)" --> ProbeStack{"Probe Local Stack<br/>(Ollama: 11434, SearXNG: 8080)"}
    ProbeStack -- "Services Running" --> CheckModel{"Check Ollama Model<br/>(Active Configured Model)"}
    ProbeStack -- "Service Unresponsive" --> AutoBoot["Supervision: Auto-Boot Background Stack<br/>(internal/service/supervisor.go)"]
    AutoBoot --> StartOllama["Start 'ollama serve' in Background"]
    AutoBoot --> StartSearXNG["Start 'docker start searxng' in Background"]
    StartOllama --> CheckModel
    StartSearXNG --> CheckModel

    CheckModel -- "Model Present & Fits VRAM" --> RunOllama["Execute Local Inference<br/>Ground query via SearXNG localhost:8080"]
    CheckModel -- "Model Missing or Insufficient VRAM" --> OllamaRefusal["Return GPU Preflight Error:<br/>'Ensure configured model is pulled'"]

    %% Gemini Cloud
    ProviderCheck -- "gemini (Cloud Grounded)" --> CheckGeminiKey{"Gemini API Key<br/>Configured?"}
    CheckGeminiKey -- "No Key" --> PromptKey["Return HTTP 400 'API_KEY_REQUIRED'<br/>UI displays API Key drawer"]
    CheckGeminiKey -- "Valid Key" --> CallGemini["Execute Google Gemini API<br/>with Google Search Tool Grounding"]
    CallGemini --> GeminiStatus{"Gemini Response Status?"}
    GeminiStatus -- "Success (200)" --> ParseGemini["Extract Structured JSON Schema & Grounding Sources"]
    GeminiStatus -- "Rate Limit (429) / Quota (403)" --> GeminiFallback["Graceful Fallback to Deterministic Verdict<br/>Populate AI Warning Banner in UI"]

    %% DeepSeek Cloud
    ProviderCheck -- "deepseek (Cloud Reasoning)" --> CheckDeepSeekKey{"DeepSeek API Key<br/>Configured?"}
    CheckDeepSeekKey -- "No Key" --> PromptKey
    CheckDeepSeekKey -- "Valid Key" --> CallDeepSeek["Execute DeepSeek API<br/>with Native Web Search Grounding"]
    CallDeepSeek --> DeepSeekStatus{"DeepSeek Response Status?"}
    DeepSeekStatus -- "Success (200)" --> ParseDeepSeek["Extract Chain-of-Thought & Provenance Evidence"]
    DeepSeekStatus -- "Timeout / HTTP 500" --> DeepSeekFallback["Graceful Fallback to Deterministic Verdict<br/>Populate AI Warning Banner in UI"]

    RunOllama --> GroundingGate{"Grounding Gate<br/>Verification"}
    ParseGemini --> GroundingGate
    ParseDeepSeek --> GroundingGate
    OllamaRefusal --> Failover["Non-Blocking Failover to Static Rules"]
    GeminiFallback --> Failover
    DeepSeekFallback --> Failover
```

---

## 6. Cache Architecture & Dual-Tier Logging Flow

### 6.1 4-Store Cache Lifecycle

AppAudit implements 4 isolated cache stores to eliminate redundant external calls, minimize egress, and enable atomic purges.

```mermaid
flowchart TD
    subgraph CacheStores ["Four Independent Cache Stores"]
        C1["1. Gemini Cloud Cache<br/>(%APPDATA%/appaudit/gemini_cache.json)"]
        C2["2. DeepSeek Cloud Cache<br/>(%APPDATA%/appaudit/deepseek_cache.json)"]
        C3["3. Ollama Local Cache<br/>(%APPDATA%/appaudit/ollama_cache.json)"]
        C4["4. In-Memory Forensic Cache<br/>(provenance.ProvenanceCache)"]
    end

    subgraph Operations ["API Cache Control Operations"]
        OpStats["GET /api/v1/cache/stats<br/>(Returns live item counts across all 4 stores)"]
        OpClear["POST /api/v1/cache/clear<br/>(Atomically flushes all 4 stores simultaneously)"]
        OpRead["Runtime Query<br/>(SHA-256 + Evidence Fingerprint Key)"]
        OpWrite["Runtime Insertion<br/>(Write-Through to Disk JSON & Memory Mutex)"]
    end

    OpRead --> C4
    C4 -- "Cache Miss" --> C1
    C4 -- "Cache Miss" --> C2
    C4 -- "Cache Miss" --> C3

    OpWrite --> C1
    OpWrite --> C2
    OpWrite --> C3
    OpWrite --> C4

    OpStats --> C1 & C2 & C3 & C4
    OpClear -->|Purge| C1 & C2 & C3 & C4
```

### 6.2 Dual-Tier Logging & PII Masking Pipeline

Every system event is split into two distinct tiers: friendly sanitized events for browser clients and diagnostic sanitized logs for terminal operators.

```mermaid
flowchart TD
    RawEvent["Raw System Event<br/>(e.g., 'Analyzing C:\\Users\\Administrator\\AppData\\Local\\Temp\\appaudit-upload-91823.exe with AIzaSyD9481jaks...')"]

    RawEvent --> MaskPipeline["MaskPII() Scrubbing Engine (internal/server/logging.go)"]

    subgraph RegexEngines ["PII Redaction Regex Engines"]
        R1["Windows User Paths: C:\\Users\\<user> -> C:\\Users\\***"]
        R2["Unix User Paths: /home/<user> -> /home/***"]
        R3["Gemini API Keys: AIza[0-9A-Za-z-_]{2}***"]
        R4["DeepSeek API Keys: sk-[0-9A-Za-z-_]{4}***"]
        R5["Bearer Tokens & URL Credentials -> ***"]
    end

    MaskPipeline --> RegexEngines
    RegexEngines --> MaskedText["Sanitized Text Stream"]

    MaskedText --> UI_Format["SanitizeClientLog()<br/>Replaces temporary upload names with [uploaded-binary]<br/>Strips technical stack traces"]
    MaskedText --> Console_Format["Dual-Tier Console Logger<br/>Formats with status icons: ℹ️ ↳ ⚠️ ❌ ✓ 🟢 🟡 🔴"]

    UI_Format --> BrowserConsole["Browser Web Dashboard Log Drawer<br/>(Clean, user-friendly enterprise messages)"]
    Console_Format --> TerminalStdout["Backend Terminal stdout / stderr<br/>(Rich diagnostics without credential leakage)"]
```

---

## 7. Complete CLI Subcommand Routing Graph

The CLI binary (`audit.exe`) supports direct automation, batch analysis, service management, and credential administration:

```mermaid
flowchart LR
    CLI["audit.exe"] --> Args{"Command-Line Arguments?"}

    %% Interactive & GUI
    Args -- "No args (Terminal click)" --> Interactive["Interactive Mode Selection<br/>[1] Web Dashboard  [2] CLI Wizard"]
    Args -- "web / serve" --> ServeCmd["audit.exe serve<br/>--port 8085 (auto-fallback 8085-8100)<br/>--clear-cache<br/>Strict loopback 127.0.0.1 binding"]
    Args -- "cli" --> WizardCmd["Interactive Terminal Wizard<br/>Step-by-step scan configuration"]

    %% Scan Subcommand
    Args -- "scan (default)" --> ScanCmd["audit.exe scan"]
    ScanCmd --> ScanFlags{"Scan Flags"}
    ScanFlags --> F1["--scan-mode=targeted | quick | full"]
    ScanFlags --> F2["--mode=gemini | deepseek | local | none"]
    ScanFlags --> F3["--network=off | hash-only | on"]
    ScanFlags --> F4["--json (Machine-readable JSON output)"]

    %% Analyze Subcommand
    Args -- "analyze <path>" --> AnalyzeCmd["audit.exe analyze <path><br/>Direct forensic audit of single .exe or folder"]

    %% Config Subcommand
    Args -- "config <subcommand>" --> ConfigCmd["audit.exe config"]
    ConfigCmd --> C1["set-gemini-key <key>"]
    ConfigCmd --> C2["set-deepseek-key <key>"]
    ConfigCmd --> C3["forget-gemini-key / forget-deepseek-key"]
    ConfigCmd --> C4["register-company-app <path>"]
    ConfigCmd --> C5["list-company-apps"]
    ConfigCmd --> C6["remove-company-app <name_or_hash>"]
    ConfigCmd --> C7["clear-cache"]
    ConfigCmd --> C8["show / status"]
```

### CLI Command Summary

| Command | Primary Use Case | Key Flags |
| :--- | :--- | :--- |
| `audit.exe` | Default interactive launch when double-clicked or invoked without arguments. | Automatically opens terminal menu. |
| `audit.exe web` / `serve` | Launches local desktop HTTP server and opens browser. | `--port 8085`, `--searxng-url`, `--verbose` |
| `audit.exe scan` | Executes automated discovery scan across installed applications. | `--scan-mode=targeted`, `--mode=gemini`, `--json` |
| `audit.exe analyze <path>` | Evaluates a single executable or specific directory. | `--mode=none`, `--mode=gemini` |
| `audit.exe config` | Configures persistent API keys, manifest entries, and caches. | `set-gemini-key`, `register-company-app`, `clear-cache` |
| `audit.exe cli` | Terminal-based interactive wizard for headless environments. | Guided prompt interface. |

---

## 8. Summary of Engineering Highlights

- **0ms Early Exits**: Up to 95% of standard commercial binaries resolve deterministically at Stage 1 and Stage 2 without contacting cloud AI endpoints or public networks.
- **Leak-Proof Localhost Binding**: The HTTP server binds exclusively to `127.0.0.1`, shielding internal endpoints from corporate Wi-Fi or LAN discovery.
- **Fail-Safe AI Integration**: External API failures (rate limits, network down, missing keys) do not halt execution; the engine reports non-blocking diagnostics and cleanly falls back to deterministic static verdicts.
- **Zero-Footprint Git Hygiene**: Test corpora (`testdata/corpus/`), temporary spools, and binary artifacts are comprehensively excluded in `.gitignore` to keep source repositories lightweight and distribution-ready.
