# AppAudit - Endpoint Software Provenance Auditor (v2.0.0)

A production-grade, ultra-lightweight, zero-external-runtime, cross-platform CLI tool in Go that automatically scans host endpoints and establishes evidence-based software provenance.

Rather than guessing or relying on fragile filename heuristics, AppAudit computes local cryptographic SHA-256 fingerprints, deeply inspects binary build metadata (Go `debug/buildinfo`, Authenticode X.509 certs, PE/Mach-O/ELF headers), and queries pluggable provenance providers to classify every executable into:

1. **`THIRD_PARTY`** — sufficiently strong evidence that the executable/software originated externally.
2. **`COMPANY`** — sufficiently strong evidence that the executable is company-developed or company-owned.
3. **`UNKNOWN`** — provenance cannot be established with sufficient confidence.

> **Fundamental Principle:**
> **No public match ≠ company-developed.**
> When external provenance cannot be established and company provenance cannot be established, the system returns `UNKNOWN`. Absence of public evidence is never twisted into a false claim of company ownership.

---

## Key Capabilities & Architectural Pillars

### 1. Cryptographic SHA-256 Fingerprinting
- Every executable analyzed has a streaming local SHA-256 digest computed without loading the whole file into RAM.
- **Privacy & OPSEC Guarantee:** Executables and binary contents are **NEVER uploaded** to external services. All hashing is performed 100% locally.

### 2. Deep Binary & Build Metadata Extraction
- **Go Binaries (`debug/buildinfo.ReadFile`)**: Inspects compiled Go binaries for main module paths (e.g., `github.com/junegunn/fzf`), versions, dependency graphs, and build settings.
- **Authenticode Signatures & X.509 Certificates**: Parses PE Security Directories to extract Subject Common Names, Organizations, and Issuers. Distinguishes between trusted external vendors, internal company certificates, and unsigned binaries.
- **Embedded Component Signatures**: Detects static third-party library signatures (FFmpeg, SQLite, OpenSSL, libcurl, zlib) and records them as component-level evidence without falsely claiming the entire executable is that component.
- **PE Version Resources**: Extracts `ProductName`, `CompanyName`, `FileDescription`, `OriginalFilename`, `InternalName`, `ProductVersion`, and `LegalCopyright`.

### 3. Generic Filename Collision Protection
Common dictionary action nouns (e.g., `sync.exe`, `update.exe`, `helper.exe`, `agent.exe`, `runner.exe`, `audit.exe`, `service.exe`, `manager.exe`, `launcher.exe`, `client.exe`, `proxy.exe`, `gateway.exe`) are explicitly protected against false-positive promotion. Search results or package matches on a generic word alone are treated as weak candidates and result in `UNKNOWN` unless corroborated by cryptographic hashes, trusted publisher signatures, or verified build metadata.

### 4. Conservative Decision Rules
* **Rule A (Exact Public Artifact Match)**: Local SHA-256 matches NIST NSRL or public GitHub release asset digest $\to$ `THIRD_PARTY` (`VERY_HIGH` confidence).
* **Rule B (Strong Publisher/Product Provenance)**: Trusted external code-signing certificate or recognized publisher manifest $\to$ `THIRD_PARTY` (`HIGH` confidence).
* **Rule C (Strong Build/Project Provenance)**: Embedded Go module path identifies a public open-source project $\to$ `THIRD_PARTY` (`HIGH` confidence).
* **Rule D (Corroborated Package Identity)**: Multi-source package/release corroboration for non-generic names $\to$ `THIRD_PARTY` (`MEDIUM` confidence).
* **Rule E (Generic Name / Weak Search Only)**: Collision protection triggered $\to$ `UNKNOWN` (`NONE` confidence).
* **Rule F (No External Evidence)**: Default fallback $\to$ `UNKNOWN` (`NONE` confidence). Never `COMPANY`.
* **Rule G (Strong Company Provenance)**: Internal company certificate or company domain indicator $\to$ `COMPANY` (`HIGH` confidence).

### 5. Configurable Network Modes
* `--network=off` *(Default)*: 100% local-first, zero network requests, sub-millisecond execution. Local known hash datasets and binary inspection execute offline.
* `--network=hash-only`: Allows outbound queries strictly for cryptographic hash reputation; no filenames or queries are transmitted.
* `--network=on` *(or `--lookup-online`)*: Activates GitHub release digest verification, Repology candidate indexing, and web candidate discovery with fast-fail preflight probe (`1.1.1.1:53` within 350ms).

---

## Directory & Package Layout

```
cmd/audit/
  main.go                     -> CLI flags, tripartite tables, telemetry, and interactive prompts
  console_windows.go          -> Windows Explorer double-click auto-pause detection
  console_other.go            -> Non-Windows console stub
internal/
  model/
    app.go                    -> Application model, Category, and noise-filtering functions
  provenance/
    evidence.go               -> Classification, Confidence, EvidenceType, and Artifact models
    fingerprint.go            -> Streaming local SHA-256 hashing
    inspector.go              -> BinaryInspector interface and BinaryMetadata
    inspector_pe.go           -> PE header, Authenticode X.509 cert, and resource table parser
    inspector_unix.go         -> Mach-O (debug/macho) and ELF (debug/elf) inspectors
    inspect_build.go          -> Go debug/buildinfo reader & embedded component signatures
    provider.go               -> Pluggable ProvenanceProvider interface
    provider_hash.go          -> NIST NSRL & known-software hash provider
    provider_github.go        -> GitHub release asset digest verification
    provider_package.go       -> Repology candidate generation
    provider_search.go        -> Search candidate discovery with OPSEC filters
    cache.go                  -> Persistent SHA-256 keyed cache with differential TTLs
    resolver.go               -> Multi-tier decision rules engine (Rules A–G)
    resolver_test.go          -> Unit tests for Rules A–G, FFmpeg benchmark, generic collisions
  classifier/
    classifier.go             -> Coordinates host discovery with Provenance Resolver
    classifier_test.go        -> Integration and classification tests
  scanner/
    scanner.go                -> Platform discovery abstraction
    scanner_windows.go        -> Start Menu (.lnk) + Registry (64/32) + PATH + Process snapshot
    lnk_windows.go            -> Byte-level Windows .lnk shell link parser
    scanner_darwin.go         -> macOS /Applications bundle + PATH + process crawler
    scanner_linux.go          -> Linux XDG .desktop + PATH + /proc PID/exe crawler
```

---

## CLI Usage

### 1. Default Offline Scan (Local-First)
```bash
audit
```
Outputs 3 explainable tables:
* `[Third-Party / Public Commercial Software]` (Name, Publisher, Confidence, SHA-256, Evidence)
* `[Company-Owned / Internal Proprietary Software]` (Name, Confidence, Path, Ownership Evidence)
* `[Unknown / Unresolved Provenance]` (Name, Path, SHA-256, Primary Reason)

### 2. Full Online Provenance Resolution
```bash
audit --network=on
# or shorthand:
audit -online
```

### 3. Hash-Only Intelligence (Zero Metadata Leakage)
```bash
audit --network=hash-only
```

### 4. Machine-Readable JSON Pipeline (SIEM / ITAM)
```bash
audit --json
```
Emits clean, structured JSON to `stdout` with complete SHA-256 fingerprints, classifications, confidence levels, and evidence explanations (telemetry is routed to `stderr`).

---

## What the System Can and Cannot Establish

### What It Can Establish
* **Definitive Public Artifacts:** Exact matching of local SHA-256 digests against verified release assets or NSRL records.
* **Verified Commercial Publishers:** Authenticode code-signing certificates and official vendor product resources.
* **Public Build Provenance:** Go main module paths and open-source project repository origins.
* **Explainable Evidence Chains:** Explicit auditable reasons for every classification decision.

### Fundamental Limitations from an Executable Alone
* **Proprietary Binaries Without Internal Records:** If a company develops a secret internal tool, leaves it unsigned, and provides no company repository connectors or certificate indicators, the tool is classified as **`UNKNOWN`**, not `COMPANY`.
* **Private Modifications of Public Projects:** If an organization forks an open-source project and compiles it internally without adding company metadata or signatures, the binary will either match the base project components or be classified as `UNKNOWN`.
* **Absence of Proof is Not Proof of Absence:** The engine never guesses or claims an unknown binary is company-owned simply because public databases do not know about it.
