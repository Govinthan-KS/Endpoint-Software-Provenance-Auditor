# 🚀 AppAudit - Quick Setup & Deployment Guide

Welcome to **AppAudit** (Endpoint Software Provenance Auditor). This guide covers everything needed to configure, run, and ship the application in under 2 minutes.

---

## 📦 What's in the Box?

AppAudit can be run either as a **standalone CLI** or with a **modern interactive Web Dashboard**.

- **No external runtimes required**: AppAudit is a single compiled Go binary with zero external DLLs or frameworks.
- **Dual-Tiers of Verification**:
  1. **Deterministic Static Analysis (0ms)**: Authenticode X.509 signatures, OS registry manifests, Go buildinfo, and CIRCL hashlookup.
  2. **AI-Powered Digital Research**:
     - **Cloud AI (Gemini / DeepSeek)**: Live Google Search grounding and digital provenance verification.
     - **Local AI (Ollama + SearXNG)**: 100% offline, private, air-gapped forensic inspection.

---

## ⚡ Quick Start

### 1. Launch the Interactive Web Dashboard
Run the built binary with `serve`:
```powershell
.\bin\audit.exe serve
```
- Automatically launches your browser at `http://127.0.0.1:8085`.
- Provides real-time single application audits, directory scans, and multi-engine comparison benchmarks.
- Press `Ctrl + C` in the console anytime to stop the server.

### 2. Run an Immediate Terminal Audit (CLI Mode)
Audit all installed applications on the host endpoint directly from your terminal:
```powershell
.\bin\audit.exe
```

Output as structured JSON (ideal for CI/CD or SIEM pipelines):
```powershell
.\bin\audit.exe --json
```

Audit a specific folder or directory:
```powershell
.\bin\audit.exe --dir "C:\Program Files\ExampleApp"
```

---

## 🔑 AI Engine Configuration

AppAudit works out-of-the-box with deterministic static analysis. For deep digital research on unrecognized binaries, configure one (or both) of the following:

### Option A: Cloud AI (Recommended for Online Endpoints)

#### 1. Google Gemini (Live Search-Grounded)
Free API keys can be generated at [Google AI Studio](https://aistudio.google.com/):
```powershell
# Set via CLI
.\bin\audit.exe config set-gemini-key YOUR_GEMINI_API_KEY

# Or set via environment variable
$env:GEMINI_API_KEY="YOUR_GEMINI_API_KEY"
```

#### 2. DeepSeek (Cost-Effective Parametric Reasoning)
API keys available from [DeepSeek Open Platform](https://platform.deepseek.com/):
```powershell
# Set via CLI
.\bin\audit.exe config set-deepseek-key YOUR_DEEPSEEK_API_KEY

# Or set via environment variable
$env:DEEPSEEK_API_KEY="YOUR_DEEPSEEK_API_KEY"
```

---

### Option B: 100% Offline / Local AI (Air-Gapped & High Privacy)

For confidential environments where binaries and metadata cannot leave the machine:

1. **Install and run Ollama**:
   - Download from [ollama.com](https://ollama.com/).
   - Pull a supported compact model:
     ```powershell
     ollama pull qwen2.5:3b
     # Or: ollama pull llama3.2:3b
     ```
   - Ensure the Ollama daemon is running (`http://127.0.0.1:11434`).

2. **Run Local SearXNG (Optional - for local search grounding)**:
   - Start SearXNG via Docker:
     ```powershell
     docker run -d -p 8080:8080 -e "BASE_URL=http://localhost:8080/" searxng/searxng
     ```
   - *Note: If SearXNG is not running or returns 0 results, AppAudit automatically falls back to local model memory and badges the result with `⚠️ Model Memory Only (Ungrounded)` to maintain total transparency.*

---

## 🛠️ Building & Cross-Compiling

To build production-grade, stripped binaries from source:

### Windows (AMD64)
```powershell
go build -ldflags="-s -w" -o bin\audit.exe .\cmd\audit
```

### Linux (AMD64)
```bash
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o bin/audit-linux .\cmd\audit
```

### macOS (Apple Silicon ARM64 & Intel)
```bash
# Apple Silicon (M1/M2/M3/M4)
GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -o bin/audit-darwin-arm64 .\cmd\audit

# Intel Mac
GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -o bin/audit-darwin-amd64 .\cmd\audit
```

---

## 📁 Key File Locations & Data Storage

| Item | Location |
|---|---|
| **Configuration & Keys** | `%APPDATA%\appaudit\credentials.json` |
| **Research Caches** | `%APPDATA%\appaudit\gemini_cache.json`<br>`%APPDATA%\appaudit\deepseek_cache.json`<br>`%APPDATA%\appaudit\ollama_cache.json` |
| **In-House Manifest** | `%APPDATA%\appaudit\company_apps.json` |
| **Web Server Port** | `http://127.0.0.1:8085` (Configurable via `--port`) |

---

## 💡 Troubleshooting Tips

- **File in use / Sharing Violation**: If a binary is currently locked by another application or Windows Defender, AppAudit logs `🔒 File Locked by System` and gracefully isolates that file without halting the rest of the scan.
- **429 Rate Limit on Free Tier**: When using Gemini or DeepSeek free tiers, AppAudit rotates through fallback models and preserves all completed items.
- **Local AI Timeout**: Local models take a few seconds to load weights into GPU/VRAM. Pre-configured timeouts allow up to 5 minutes so heavy models won't abort prematurely.
