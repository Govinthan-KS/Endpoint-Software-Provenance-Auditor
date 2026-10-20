# AppAudit REST API Reference

AppAudit provides a simple and fast HTTP REST API for auditing software provenance, inspecting binary authenticity, comparing evaluation engines, and scanning host machines.

The server can be started interactively by launching `audit.exe` and choosing option `[1] Web Dashboard`, or directly using:
```powershell
# Launch web dashboard directly:
audit.exe web

# Or with custom port:
audit.exe serve --port 8085
```
By default, the server listens strictly on loopback at `http://127.0.0.1:8085` (or falls back to an available port from 8085-8095 if occupied) and automatically opens your default web browser. External LAN exposure is intentionally disabled for local security and Windows Firewall isolation.

---

## Table of Contents

1. [Health Check (`GET /api/v1/health`)](#1-health-check)
2. [Single Binary Audit (`POST /api/v1/audit/upload`)](#2-single-binary-audit)
3. [Engine Comparison Benchmark (`POST /api/v1/audit/compare`)](#3-engine-comparison-benchmark)
4. [Host Quick Scan (`POST /api/v1/audit/quick`)](#4-host-quick-scan)
5. [Deep Host Scan (`POST /api/v1/audit/full`)](#5-deep-host-scan)
6. [Custom Directory Audit (`POST /api/v1/audit/directory`)](#6-custom-directory-audit)
7. [Clear Cache (`POST /api/v1/cache/clear`)](#7-clear-cache)
8. [Cache Statistics (`GET /api/v1/cache/stats`)](#8-cache-statistics)
9. [Register In-House Application (`POST /api/v1/company/register`)](#9-register-in-house-application)
10. [List Registered In-House Applications (`GET /api/v1/company/apps`)](#10-list-registered-in-house-applications)
11. [Remove In-House Application (`POST /api/v1/company/remove`)](#11-remove-in-house-application)
12. [Local Security & Loopback Isolation (`127.0.0.1`)](#12-local-security--loopback-isolation-127001)
13. [AI Configuration & Credentials (`/api/v1/config/*`)](#13-ai-configuration--credentials)
14. [Dynamic Model Catalogues (`/api/v1/models/*`)](#14-dynamic-model-catalogues)
15. [System Prompt Management (`/api/v1/config/prompt*`)](#15-system-prompt-management)
16. [Native File Explorer Dialogs (`/api/v1/dialog/*`)](#16-native-file-explorer-dialogs)
17. [Preflight Statistics & Execution Estimates (`POST /api/v1/preflight/stats`)](#17-preflight-statistics--execution-estimates)
18. [Resilience, Grounding & Error Fields](#18-resilience-grounding--error-fields)

---

## 1. Health Check

Checks if the AppAudit server is online, healthy, and ready to accept requests.

- **Method**: `GET`
- **Endpoint**: `/api/v1/health`
- **Request Body**: None

### Curl Example
```bash
curl -X GET http://localhost:8085/api/v1/health
```

### Sample Response (`200 OK`)
```json
{
  "status": "ok",
  "timestamp": "2026-10-12T15:20:35Z"
}
```

---

## 2. Single Binary Audit

Uploads an executable (`.exe`) or library (`.dll`) to determine whether it is a verified third-party application, an internal company tool, or unknown software.

- **Method**: `POST`
- **Endpoint**: `/api/v1/audit/upload` *(also accepts `/api/v1/audit`)*
- **Content-Type**: `multipart/form-data`
- **Parameters**:
  - `file` *(required)*: The binary file to inspect (maximum size: 50 MB).
  - `mode` *(optional)*: The inspection engine:
    - `none`: Deterministic offline check (signature, metadata, hash). Fast and 100% offline. *(Default)*
    - `ollama`: Offline analysis powered by local Ollama AI model.
    - `gemini`: Cloud-grounded provenance research via Google Gemini.
    - `deepseek`: Cloud reasoning via DeepSeek.

### Curl Example
```bash
curl -X POST http://localhost:8085/api/v1/audit/upload \
  -F "file=@C:\path\to\application.exe" \
  -F "mode=none"
```

### Sample Response (`200 OK`)
```json
{
  "name": "application.exe",
  "sha256": "4b68051280ddfe792cf62e08ef8740c497cfd900fdceecf4b143c746522c0f9f",
  "classification": "Verified Third-Party",
  "raw_classification": "THIRD_PARTY",
  "confidence": "High",
  "verification_source": "Verified Publisher Signature",
  "triage_tier": "Tier 1 Authenticode",
  "stage_number": 1,
  "stage_name": "Stage 1: Verified Publisher Signature",
  "ai_bypassed": true,
  "exit_layer": "Static Cryptographic Layer (Early Exit)",
  "exit_reason": "Resolved at Stage 1 via cryptographically verified publisher signature. AI reasoning bypassed.",
  "summary": "Cryptographically signed by a verified commercial software publisher with an intact certificate trust chain.",
  "evidence": "Signed by Microsoft Corporation (DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1)",
  "model_used": "none",
  "latency_ms": 12.4,
  "privacy": "Local Offline (0 egress bytes)",
  "token_economics": {
    "prompt_tokens": 0,
    "completion_tokens": 0,
    "total_tokens": 0,
    "tokens_saved": 1200,
    "estimated_cost_usd": 0.0,
    "formatted_cost": "$0.0000 (100% Free / Local)",
    "cache_hit": false,
    "economics_summary": "AI Bypassed: 0 tokens consumed at static layer (~1,200 tokens saved, $0.0000 API cost)."
  },
  "reasons": [
    "Cryptographically signed by Microsoft Corporation"
  ]
}
```

### Key Response Fields
- **`classification`**: One of `"Verified Third-Party"`, `"In-House / Custom Tool"`, or `"Unverified / Unknown"`.
- **`stage_number`**: Pipeline stage where classification concluded (`1`, `2`, `3`, or `4`).
- **`stage_name`**: Human-readable name of the exit stage (e.g. `"Stage 1: Verified Publisher Signature"`).
- **`ai_bypassed`**: Boolean indicating whether software was resolved in upper static layers without incurring AI API token costs.
- **`exit_layer`**: Name of the exit layer (e.g. `"Static Cryptographic Layer (Early Exit)"`).
- **`token_economics`**: Details tokens consumed, prompt/completion breakdown, estimated cost, and tokens saved by early exit gating.
- **`verification_source`**: Source of truth, such as `"Verified Publisher Signature"`, `"Public Open-Source Build Metadata"`, `"Local Package Manifest Receipt"`, `"Public Registry Hash Match (CIRCL)"`, or `"AI Provenance Inspection"`.
- **`summary`**: A concise 1–2 sentence human-readable explanation.
- **`privacy`**: Details whether inspection was strictly offline or made cloud roundtrips.

---

## 3. Engine Comparison Benchmark

Runs the uploaded binary against multiple engines head-to-head to compare speed, verdict consistency, and accuracy.

- **Method**: `POST`
- **Endpoint**: `/api/v1/audit/compare`
- **Content-Type**: `multipart/form-data`
- **Parameters**:
  - `file` *(required)*: Binary file to compare across engines.
  - `modes` *(optional)*: Comma-separated list or JSON array of 2 or more engines (e.g., `none,gemini` or `["none", "ollama"]`). Defaults to `["none", "gemini"]`.

### Curl Example
```bash
curl -X POST http://localhost:8085/api/v1/audit/compare \
  -F "file=@C:\path\to\application.exe" \
  -F "modes=none,gemini"
```

### Sample Response (`200 OK`)
```json
{
  "name": "application.exe",
  "sha256": "3444afbfc0e3933c09b85a3a71b3e839e3f16d7d5668e2f89c026ba19d368e7e",
  "size_bytes": 9240576,
  "agreement": true,
  "consensus_verdict": "Verified Third-Party",
  "discrepancy_detected": false,
  "efficiency_winner": "Deterministic Only",
  "takeaway": "Unanimous Agreement: Deterministic Only reached verdict in 14.2ms (120x faster than cloud API).",
  "engines": [
    {
      "mode": "none",
      "display_name": "Deterministic Only",
      "classification": "Verified Third-Party",
      "raw_classification": "THIRD_PARTY",
      "confidence": "High",
      "verification_source": "Public Open-Source Build Metadata",
      "summary": "Compiler build metadata confirms open-source repository provenance.",
      "latency_ms": 14.2,
      "privacy": "Local Offline (0 egress bytes)",
      "is_fastest": true
    },
    {
      "mode": "gemini",
      "display_name": "Gemini (Cloud Grounded)",
      "classification": "Verified Third-Party",
      "raw_classification": "THIRD_PARTY",
      "confidence": "High",
      "verification_source": "AI Provenance Inspection",
      "summary": "Confirmed third-party release artifact matching official source repository.",
      "latency_ms": 1720.5,
      "privacy": "Cloud API Roundtrip",
      "is_fastest": false
    }
  ]
}
```

---

## 4. Host Quick Scan

Audits user-space software, Start Menu shortcuts, user registry entries, and commands found on the system `PATH`.

- **Method**: `POST`
- **Endpoint**: `/api/v1/audit/quick`
- **Content-Type**: `application/x-www-form-urlencoded`
- **Parameters**:
  - `mode` *(optional)*: Analysis mode (`none`, `ollama`, `gemini`, `deepseek`). Defaults to `none`.
  - `modes` *(optional)*: Comma-separated list or JSON array of 2 or more engines (e.g. `none,ollama` or `["none", "gemini"]`). When provided, triggers a **Multi-Engine Comparison Benchmark** across all discovered applications.

### Curl Examples

#### Standard Quick Scan
```bash
curl -X POST http://localhost:8085/api/v1/audit/quick \
  -d "mode=none"
```

#### Multi-Engine Quick Scan Comparison Benchmark
```bash
curl -X POST http://localhost:8085/api/v1/audit/quick \
  -d "modes=none,ollama"
```

### Sample Response (`200 OK`)
```json
{
  "scan_type": "Quick Scan",
  "target": "Host Applications & PATH",
  "total_scanned": 61,
  "third_party_count": 60,
  "in_house_count": 0,
  "unverified_count": 1,
  "duration_ms": 3459.8,
  "mode_used": "none",
  "applications": [
    {
      "name": "Google Chrome",
      "path": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
      "sha256": "f3b39...8d2",
      "classification": "Verified Third-Party",
      "raw_classification": "THIRD_PARTY",
      "confidence": "High",
      "verification_source": "Verified Publisher Signature",
      "stage_number": 1,
      "stage_name": "Stage 1: Verified Publisher Signature",
      "ai_bypassed": true,
      "exit_layer": "Static Cryptographic Layer (Early Exit)",
      "token_economics": {
        "prompt_tokens": 0,
        "completion_tokens": 0,
        "total_tokens": 0,
        "tokens_saved": 1200,
        "formatted_cost": "$0.0000 (100% Free / Local)"
      },
      "summary": "Cryptographically signed by a verified commercial software publisher with an intact certificate trust chain."
    }
  ]
}
```

---

## 5. Deep Host Scan

Performs a thorough scan of all host software while automatically skipping protected Windows system directories (`C:\Windows`, `WinSxS`, system volume information).

- **Method**: `POST`
- **Endpoint**: `/api/v1/audit/full`
- **Content-Type**: `application/x-www-form-urlencoded`
- **Parameters**:
  - `mode` *(optional)*: Analysis mode (`none`, `ollama`, `gemini`, `deepseek`). Defaults to `none`.
  - `modes` *(optional)*: Comma-separated list or JSON array of 2 or more engines (e.g. `none,ollama,gemini`). When provided, triggers a **Multi-Engine Comparison Benchmark** across all host applications.

### Curl Examples

#### Standard Deep Host Scan
```bash
curl -X POST http://localhost:8085/api/v1/audit/full \
  -d "mode=none"
```

#### Multi-Engine Deep Host Scan Comparison Benchmark
```bash
curl -X POST http://localhost:8085/api/v1/audit/full \
  -d "modes=none,ollama,gemini"
```

### Sample Multi-Engine Comparison Response (`200 OK`)
```json
{
  "scan_type": "Full Scan",
  "target": "All Host Applications (Excluding System Folders)",
  "total_scanned": 142,
  "modes": ["none", "ollama"],
  "duration_ms": 1240.5,
  "efficiency_winner": "Deterministic Only",
  "consensus_rate": 98.6,
  "agreement_count": 140,
  "discrepancy_count": 2,
  "takeaway": "Benchmark evaluated 142 software applications across 2 engines. Deterministic Only achieved fastest throughput (1240.5 ms). Overall engine consensus: 98.6% (140 agreed, 2 discrepancies).",
  "token_savings_takeaway": "Static layer zero-cost early exits eliminated cloud LLM roundtrips and preserved bandwidth for verified enterprise software.",
  "engine_summaries": [
    {
      "mode": "none",
      "display_name": "Deterministic Only",
      "latency_ms": 1240.5,
      "third_party_count": 138,
      "in_house_count": 1,
      "unverified_count": 3,
      "static_early_exit_count": 139,
      "is_fastest": true,
      "economics": {
        "savings_percentage": 97.9,
        "total_tokens_saved": 166800,
        "formatted_cost": "$0.0000"
      }
    }
  ],
  "applications": [
    {
      "name": "7z",
      "path": "C:\\Program Files\\7-Zip\\7z.exe",
      "sha256": "5c088863f68388ad...2b1",
      "agreement": true,
      "consensus_verdict": "Verified Third-Party",
      "discrepancy": false,
      "engine_verdicts": {
        "none": {
          "classification": "Verified Third-Party",
          "stage_number": 1,
          "ai_bypassed": true
        },
        "ollama": {
          "classification": "Verified Third-Party",
          "stage_number": 1,
          "ai_bypassed": true
        }
      }
    }
  ]
}
```

---

## 6. Custom Directory Audit

Recursively scans any specific folder on the host machine and audits all discovered executables and suites.

- **Method**: `POST`
- **Endpoint**: `/api/v1/audit/directory`
- **Content-Type**: `application/json` *(or `application/x-www-form-urlencoded`)*
- **Parameters**:
  - `path` *(required)*: Absolute folder path on the host.
  - `mode` *(optional)*: Analysis mode (`none`, `ollama`, `gemini`, `deepseek`). Defaults to `none`.
  - `modes` *(optional)*: JSON array or list of engines to compare across the folder.

### Curl Examples

#### Standard Directory Scan (JSON)
```bash
curl -X POST http://localhost:8085/api/v1/audit/directory \
  -H "Content-Type: application/json" \
  -d "{\"path\": \"C:\\\\Tools\\\\DevKit\", \"mode\": \"none\"}"
```

#### Multi-Engine Directory Benchmark (JSON)
```bash
curl -X POST http://localhost:8085/api/v1/audit/directory \
  -H "Content-Type: application/json" \
  -d "{\"path\": \"C:\\\\Tools\\\\DevKit\", \"modes\": [\"none\", \"ollama\"]}"
```

---

## 7. Clear Cache

Purges in-memory and on-disk caches for AI search queries, provenance triage decisions, and forensic file classifications.

- **Method**: `POST`
- **Endpoint**: `/api/v1/cache/clear`
- **Request Body**: None

### Curl Example
```bash
curl -X POST http://localhost:8085/api/v1/cache/clear
```

### Sample Response (`200 OK`)
```json
{
  "status": "ok",
  "message": "All AI and forensic provenance caches cleared successfully",
  "total_cleared": 42,
  "gemini_entries_cleared": 12,
  "deepseek_entries_cleared": 0,
  "ollama_entries_cleared": 5,
  "forensic_entries_cleared": 25
}
```

---

## 8. Cache Statistics

Retrieves the current number of cached items across forensic analysis and AI model providers.

- **Method**: `GET`
- **Endpoint**: `/api/v1/cache/stats`
- **Request Body**: None

### Curl Example
```bash
curl -X GET http://localhost:8085/api/v1/cache/stats
```

### Sample Response (`200 OK`)
```json
{
  "total": 42,
  "gemini": 12,
  "deepseek": 0,
  "ollama": 5,
  "forensic": 25
}
```

---

## 9. Register In-House Application

Explicitly registers an internal or proprietary executable into the organizational company manifest (`company_manifest.json`).

Applications registered here permanently exit provenance evaluation at **Stage 1: Registered Company Manifest** with:
- **0ms offline resolution**
- **0 tokens consumed**
- **100% Deterministic In-House Tool status**

Supports registration via **JSON** (specifying a local file path or cryptographic SHA-256 hash) or **Multipart file upload** (uploading an executable binary directly).

- **Method**: `POST`
- **Endpoint**: `/api/v1/company/register`

### A. Register by Host File Path (JSON)
- **Content-Type**: `application/json`
- **Parameters**:
  - `path` (string, required if no sha256): Absolute or relative path to the executable file on the host machine.
  - `name` (string, optional): Human-readable name. If omitted, inferred from the filename.
  - `sha256` (string, optional): SHA-256 hash if the path is on a remote machine or known offline.
  - `description` (string, optional): Purpose or department note.

```bash
curl -X POST http://localhost:8085/api/v1/company/register \
  -H "Content-Type: application/json" \
  -d '{
    "path": "C:\\Tools\\audit.exe",
    "name": "audit",
    "description": "Internal enterprise provenance auditing utility"
  }'
```

### B. Register by Binary File Upload (Multipart Form)
- **Content-Type**: `multipart/form-data`
- **Parameters**:
  - `file` (binary, required): The executable file (`.exe` or `.dll`).
  - `name` (string, optional): Custom application display name.
  - `description` (string, optional): Custom purpose description.

```bash
curl -X POST http://localhost:8085/api/v1/company/register \
  -F "file=@./my_proprietary_tool.exe" \
  -F "name=MyInternalTool" \
  -F "description=Proprietary internal pipeline utility"
```

### Sample Response (`200 OK`)
```json
{
  "status": "ok",
  "success": true,
  "message": "Successfully registered 'audit' as in-house company application",
  "manifest_path": "C:\\Users\\...\\.gemini\\company_manifest.json",
  "entry": {
    "name": "audit",
    "path": "C:\\Tools\\audit.exe",
    "sha256": "01d39178170c51bf735badb4d2a42d6aab1aa7a03eea1bca3b5323c81674570a",
    "added_at": "2026-10-13T10:07:36+05:30",
    "description": "Internal enterprise provenance auditing utility"
  }
}
```

---

## 10. List Registered In-House Applications

Retrieves all applications currently registered in the organizational enterprise manifest.

- **Method**: `GET`
- **Endpoint**: `/api/v1/company/apps`
- **Request Body**: None

### Curl Example
```bash
curl -X GET http://localhost:8085/api/v1/company/apps
```

### Sample Response (`200 OK`)
```json
{
  "status": "ok",
  "count": 1,
  "manifest_path": "C:\\Users\\...\\.gemini\\company_manifest.json",
  "apps": [
    {
      "name": "audit",
      "path": "C:\\Tools\\audit.exe",
      "sha256": "01d39178170c51bf735badb4d2a42d6aab1aa7a03eea1bca3b5323c81674570a",
      "added_at": "2026-10-13T10:07:36+05:30",
      "description": "Internal enterprise provenance auditing utility"
    }
  ]
}
```

---

## 11. Remove In-House Application

Unregisters an application from the company manifest by cryptographic SHA-256 hash, application name, or file path.

- **Method**: `POST` (also accepts `DELETE`)
- **Endpoint**: `/api/v1/company/remove`
- **Content-Type**: `application/json`
- **Parameters**:
  - `identifier` (string, required): SHA-256 hash, registered app name, or binary path.

### Curl Example
```bash
curl -X POST http://localhost:8085/api/v1/company/remove \
  -H "Content-Type: application/json" \
  -d '{"identifier": "audit"}'
```

### Sample Response (`200 OK`)
```json
{
  "status": "ok",
  "success": true,
  "message": "Successfully removed \"audit\" from company manifest"
}
```

---

## 12. Local Security & Loopback Isolation (`127.0.0.1`)

For security and privacy, AppAudit binds strictly to `127.0.0.1:<port>` (loopback interface only). This architecture guarantees:
- **Zero Inbound Network Exposure**: External machines on your Wi-Fi or corporate LAN cannot access the server.
- **No Windows Firewall Warnings**: Binding to loopback does not trigger Windows Defender Firewall inbound permission prompts.
- **Privacy Assurance**: Software provenance analyses, token consumption statistics, and cached metadata remain strictly on your local machine.

### Interacting via REST API Locally

All REST endpoints should be addressed via `http://127.0.0.1:8085` or `http://localhost:8085`:

```bash
# 1. Health Check
curl http://127.0.0.1:8085/api/v1/health

# 2. Upload and Audit a Binary Locally
curl -X POST http://127.0.0.1:8085/api/v1/audit/upload \
  -F "file=@./my_tool.exe" \
  -F "mode=none"

# 3. Head-to-Head Engine Comparison Benchmark on Upload
curl -X POST http://127.0.0.1:8085/api/v1/audit/compare \
  -F "file=@./my_tool.exe" \
  -F "modes=none,ollama"

# 4. Trigger Deep Host Scan Comparison
curl -X POST http://127.0.0.1:8085/api/v1/audit/full \
  -d "modes=none,ollama"

# 5. Purge Provenance Cache
curl -X POST http://127.0.0.1:8085/api/v1/cache/clear
```

---

## 13. AI Configuration & Credentials

### A. Get Active AI Configuration (`GET /api/v1/config/ai`)
Retrieves masked API keys, persistent storage status, active models, and effective reasoning prompts.

- **Method**: `GET`
- **Endpoint**: `/api/v1/config/ai`

#### Sample Response (`200 OK`)
```json
{
  "gemini_has_key": true,
  "gemini_key_masked": "AIzaSy...7x9Q",
  "gemini_cached": true,
  "gemini_active_model": "gemini-3.5-flash-lite",
  "deepseek_has_key": true,
  "deepseek_key_masked": "sk-...8ab4",
  "deepseek_cached": true,
  "deepseek_active_model": "deepseek-chat",
  "ollama_active_model": "audit-phi:q6k",
  "system_prompt": "You are a software provenance and authenticity auditor...",
  "is_custom_prompt": false
}
```

### B. Configure API Key (`POST /api/v1/config/key`)
Sets an API key in memory (session-only) or optionally caches it in `%APPDATA%\appaudit\credentials.json`.

- **Method**: `POST`
- **Endpoint**: `/api/v1/config/key`
- **Request Body**:
```json
{
  "provider": "gemini",
  "key": "AIzaSy...",
  "persist": true
}
```

### C. Forget API Key (`POST /api/v1/config/forget`)
Purges credentials from memory and `%APPDATA%\appaudit\credentials.json`, clearing AI inference caches.

- **Method**: `POST`
- **Endpoint**: `/api/v1/config/forget`
- **Request Body**:
```json
{
  "provider": "gemini"
}
```

---

## 14. Dynamic Model Catalogues

### A. List Local Ollama Text Models (`GET /api/v1/models/ollama`)
Queries `http://localhost:11434/api/tags` and returns installed models. **Multimodal and vision models (e.g. `llava`, `clip`, `moondream`, `mllama`, `qwen-vl`) are automatically filtered out** to protect JSON structured provenance completions.

- **Method**: `GET`
- **Endpoint**: `/api/v1/models/ollama`

#### Sample Response (`200 OK`)
```json
{
  "status": "ok",
  "models": ["audit-phi:q6k", "llama3.2:3b", "mistral:latest", "phi3:mini"]
}
```

### B. List Google Gemini Models (`GET /api/v1/models/gemini`)
Queries the Google Generative Language API using the configured Gemini key, returning models that support `generateContent`.

- **Method**: `GET`
- **Endpoint**: `/api/v1/models/gemini`

### C. List DeepSeek Models (`GET /api/v1/models/deepseek`)
Queries `https://api.deepseek.com/models` with the configured Bearer token.

- **Method**: `GET`
- **Endpoint**: `/api/v1/models/deepseek`

### D. Set Active Engine Model (`POST /api/v1/config/model`)
Sets the default active model for a provider and persists it to `credentials.json`.

- **Method**: `POST`
- **Endpoint**: `/api/v1/config/model`
- **Request Body**:
```json
{
  "provider": "gemini",
  "model": "gemini-2.5-pro"
}
```

---

## 15. System Prompt Management

### A. Read System Prompt (`GET /api/v1/config/prompt`)
Returns the effective reasoning instruction and whether it is a customized or canonical prompt.

- **Method**: `GET`
- **Endpoint**: `/api/v1/config/prompt`

### B. Update System Prompt (`POST /api/v1/config/prompt`)
Persists custom system instructions to `credentials.json`.

- **Method**: `POST`
- **Endpoint**: `/api/v1/config/prompt`
- **Request Body**:
```json
{
  "prompt": "Custom system instructions..."
}
```

### C. Reset to Default System Prompt (`POST /api/v1/config/prompt/reset`)
Wipes custom prompts from `credentials.json` and resets to the factory unified provenance prompt.

- **Method**: `POST`
- **Endpoint**: `/api/v1/config/prompt/reset`

---

## 16. Native File Explorer Dialogs

AppAudit exposes endpoints that trigger native OS File Explorer picker dialogs on the host machine for selecting directories and executables without manual path entry.

### A. Open Native Folder Browser Dialog (`POST /api/v1/dialog/folder`)
Pops up the native Windows folder browser on the host machine and returns the chosen absolute directory path.

- **Method**: `POST`
- **Endpoint**: `/api/v1/dialog/folder`

#### Sample Response (`200 OK`)
```json
{
  "status": "ok",
  "cancelled": false,
  "path": "C:\\Program Files\\InternalTools"
}
```

### B. Open Native Executable File Browser Dialog (`POST /api/v1/dialog/file`)
Pops up the native Windows file browser filtered for `.exe` and `.dll` executables and returns the chosen absolute path.

- **Method**: `POST`
- **Endpoint**: `/api/v1/dialog/file`

#### Sample Response (`200 OK`)
```json
{
  "status": "ok",
  "cancelled": false,
  "path": "C:\\Tools\\company-app.exe"
}
```

---

## 17. Preflight Statistics & Execution Estimates

Computes real-time discovery counts and realistic duration (ETA) ranges prior to starting full batch or directory scans, accounting for multi-engine selection and early exit gating.

- **Method**: `POST`
- **Endpoint**: `/api/v1/preflight/stats`
- **Content-Type**: `application/json`
- **Request Body**:
```json
{
  "target": "directory",
  "path": "C:\\Tools\\DevKit",
  "modes": ["none", "gemini"]
}
```
*`target` can be `"single"` / `"file"`, `"quick"`, `"full"`, or `"directory"`.*

#### Sample Response (`200 OK`)
```json
{
  "count": 12,
  "estimated_duration": "~5 - 15 mins",
  "target": "Directory: DevKit",
  "modes": ["none", "gemini"],
  "triage_architecture": "Custom Folder Multi-Engine Benchmark (2 engines)"
}
```

---

## 18. Resilience, Grounding & Error Fields

AppAudit returns transparent diagnostics embedded in standard audit and comparison responses:

| Field | Type | Description |
|---|---|---|
| `search_grounded` | boolean | Indicates whether live search grounding succeeded. For Local AI (Ollama), `false` indicates SearXNG was offline or returned 0 hits. |
| `search_warning` | string | Explanatory note if external search queries failed or were throttled. |
| `provider_errors` | array of strings | Normalized upstream AI provider errors (e.g. `HTTP 429: Gemini/DeepSeek quota exhausted`, `HTTP 401: Invalid API key`). |
| `scan_warnings` | array of strings | Non-fatal scan alerts such as file access sharing violations or local ungrounded inferences. |
| `read_error` | string | Operating system file access error (e.g. `access is denied / sharing violation`). File is isolated as `UNKNOWN` without crashing. |
| `degraded_circl` | boolean | Set to `true` if CIRCL hashlookup circuit breaker tripped due to public rate limits. |
| `circl_skipped_count` | integer | Number of binary targets that safely bypassed Tier 3 directly to Tier 2 AI triage while the circuit breaker was open. |



