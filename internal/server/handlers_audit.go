package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/example/appaudit/internal/application"
	"github.com/example/appaudit/internal/provenance"
)

const (
	// MaxUploadBytes defines the 500 MB upload limit.
	MaxUploadBytes = 500 * 1024 * 1024
)

// TokenEconomics encapsulates AI token consumption, cache savings, and cost metrics.
type TokenEconomics struct {
	PromptTokens     int     `json:"prompt_tokens"`
	CompletionTokens int     `json:"completion_tokens"`
	TotalTokens      int     `json:"total_tokens"`
	TokensSaved      int     `json:"tokens_saved"`
	EstimatedCostUSD float64 `json:"estimated_cost_usd"`
	FormattedCost    string  `json:"formatted_cost"`
	CacheHit         bool    `json:"cache_hit"`
	EconomicsSummary string  `json:"economics_summary"`
}

// ScanEconomicsSummary aggregates token economics across an entire multi-application scan.
type ScanEconomicsSummary struct {
	TotalPromptTokens     int     `json:"total_prompt_tokens"`
	TotalCompletionTokens int     `json:"total_completion_tokens"`
	TotalTokensConsumed   int     `json:"total_tokens_consumed"`
	TotalTokensSaved      int     `json:"total_tokens_saved"`
	StaticEarlyExitCount  int     `json:"static_early_exit_count"`
	AIEngagedCount        int     `json:"ai_engaged_count"`
	EstimatedCostUSD      float64 `json:"estimated_cost_usd"`
	FormattedCost         string  `json:"formatted_cost"`
	SavingsPercentage     float64 `json:"savings_percentage"`
}

// AuditResponse represents the user-friendly response for single file audits.
type AuditResponse struct {
	Name               string         `json:"name"`
	SHA256             string         `json:"sha256"`
	Classification     string         `json:"classification"`      // "Verified Third-Party", "In-House / Custom Tool", "Unverified / Unknown"
	RawClassification  string         `json:"raw_classification"`  // "THIRD_PARTY", "IN_HOUSE", "UNKNOWN"
	Confidence         string         `json:"confidence"`          // "High", "Medium", "Low"
	VerificationSource string         `json:"verification_source"` // "Verified Publisher Signature", "Public Open-Source Build Metadata", etc.
	TriageTier         string         `json:"triage_tier"`         // Retained for backward compatibility
	Summary            string         `json:"summary"`             // 1-2 sentence human-readable finding
	Evidence           string         `json:"evidence"`            // Forensic proof
	ModelUsed          string         `json:"model_used"`          // "none", "gemini-3.5-flash-lite", etc.
	LatencyMs          float64        `json:"latency_ms"`          // Processing time in milliseconds
	Privacy            string         `json:"privacy"`             // "Local Offline (0 egress bytes)" vs "Cloud API Roundtrip"
	AIError            string         `json:"ai_error,omitempty"`
	Reasons            []string       `json:"reasons,omitempty"`
	SearchGrounded     bool           `json:"search_grounded"`
	DegradationWarning string         `json:"degradation_warning,omitempty"`
	SearchWarning      string         `json:"search_warning,omitempty"`
	ReadError          string         `json:"read_error,omitempty"`
	ProviderErrors     []string       `json:"provider_errors,omitempty"`
	ScanWarnings       []string       `json:"scan_warnings,omitempty"`

	// Pipeline Resolution Stage & Early Exit details
	StageNumber        int            `json:"stage_number"`        // 1, 2, 3, or 4
	StageName          string         `json:"stage_name"`          // e.g. "Stage 1: Verified Publisher Signature"
	AIBypassed         bool           `json:"ai_bypassed"`         // true if classified in upper static layers without AI
	ExitLayer          string         `json:"exit_layer"`          // "Static Cryptographic Layer (Early Exit)", etc.
	ExitReason         string         `json:"exit_reason"`         // Human-readable early exit explanation

	// Token Economics
	TokenEconomics     TokenEconomics `json:"token_economics"`
}

// MultiAppScanResponse represents the outcome of host quick, full, or directory scans.
type MultiAppScanResponse struct {
	ScanType             string                `json:"scan_type"`
	Target               string                `json:"target"`
	TotalScanned         int                   `json:"total_scanned"`
	ThirdPartyCount      int                   `json:"third_party_count"`
	InHouseCount         int                   `json:"in_house_count"`
	UnverifiedCount      int                   `json:"unverified_count"`
	DurationMs           float64               `json:"duration_ms"`
	ModeUsed             string                `json:"mode_used"`
	StaticEarlyExitCount int                   `json:"static_early_exit_count"`
	AIEngagedCount       int                   `json:"ai_engaged_count"`
	Economics            ScanEconomicsSummary  `json:"economics"`
	ProviderErrors       []string              `json:"provider_errors,omitempty"`
	ScanWarnings         []string              `json:"scan_warnings,omitempty"`
	DegradedCIRCL        bool                  `json:"degraded_circl,omitempty"`
	CIRCLSkippedCount    int                   `json:"circl_skipped_count,omitempty"`
	Applications         []ScannedAppSummary   `json:"applications"`
}

// ScannedAppSummary represents one classified software package in a multi-app inventory scan.
type ScannedAppSummary struct {
	Name               string         `json:"name"`
	Path               string         `json:"path"`
	SHA256             string         `json:"sha256"`
	Classification     string         `json:"classification"`
	RawClassification  string         `json:"raw_classification"`
	Confidence         string         `json:"confidence"`
	VerificationSource string         `json:"verification_source"`
	Summary            string         `json:"summary"`
	StageNumber        int            `json:"stage_number"`
	StageName          string         `json:"stage_name"`
	AIBypassed         bool           `json:"ai_bypassed"`
	ExitLayer          string         `json:"exit_layer"`
	TokenEconomics     TokenEconomics `json:"token_economics"`
	SearchGrounded     bool           `json:"search_grounded"`
	DegradationWarning string         `json:"degradation_warning,omitempty"`
	SearchWarning      string         `json:"search_warning,omitempty"`
	ReadError          string         `json:"read_error,omitempty"`
	AIError            string         `json:"ai_error,omitempty"`
	Reasons            []string       `json:"reasons,omitempty"`
}

// DirectoryAuditRequest specifies parameters for auditing a local folder.
type DirectoryAuditRequest struct {
	Path  string   `json:"path"`
	Mode  string   `json:"mode"`
	Model string   `json:"model"`
	Modes []string `json:"modes"`
}

// PreflightStatsRequest specifies target and engine parameters for preflight estimations.
type PreflightStatsRequest struct {
	Type   string   `json:"type"`   // "single", "quick", "full", "dir"
	Target string   `json:"target"` // "single", "quick", "full", or folder path
	Path   string   `json:"path"`   // single filename or directory path
	Mode   string   `json:"mode"`
	Model  string   `json:"model"`
	Modes  []string `json:"modes"`
}

// PreflightStatsResponse returns preliminary count and architectural estimates before running a scan.
type PreflightStatsResponse struct {
	Count               int      `json:"count"`
	EstimatedDuration   string   `json:"estimated_duration"`
	Target              string   `json:"target"`
	Modes               []string `json:"modes"`
	TriageArchitecture  string   `json:"triage_architecture"`
}

// Single File Audit: POST /api/v1/audit/upload (and /api/v1/audit)

func (s *Server) handleAuditSingle(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	clientIP := r.RemoteAddr

	if r.Method != http.MethodPost {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "Method not allowed. Use POST."})
		s.logRequest(r.Method, r.URL.Path, clientIP, http.StatusMethodNotAllowed, time.Since(start), "Invalid method")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, MaxUploadBytes)
	if err := r.ParseMultipartForm(32 * 1024 * 1024); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) || strings.Contains(err.Error(), "too large") {
			s.logError("Upload rejected: file size exceeds 500 MB ceiling from %s", clientIP)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "File exceeds 500 MB upload ceiling"})
			s.logRequest(r.Method, r.URL.Path, clientIP, http.StatusRequestEntityTooLarge, time.Since(start), "Payload >500MB")
			return
		}
		s.logError("Failed to parse multipart form from %s: %v", clientIP, err)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("Failed to parse multipart upload: %v", err)})
		s.logRequest(r.Method, r.URL.Path, clientIP, http.StatusBadRequest, time.Since(start), "Multipart parse error")
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		s.logError("Missing 'file' field in upload from %s", clientIP)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "Missing 'file' field in multipart form"})
		s.logRequest(r.Method, r.URL.Path, clientIP, http.StatusBadRequest, time.Since(start), "Missing file")
		return
	}
	defer file.Close()

	mode := strings.ToLower(strings.TrimSpace(r.FormValue("mode")))
	if mode == "" {
		mode = "none"
	}

	if err := s.validateEngineKeys(mode, nil); err != nil {
		s.logError("Scan rejected: %v", err)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "error",
			"error":  err.Error(),
			"code":   "API_KEY_REQUIRED",
		})
		s.logRequest(r.Method, r.URL.Path, clientIP, http.StatusBadRequest, time.Since(start), "API key required")
		return
	}

	s.logDetail("Starting single-file audit of %q (%s) [Mode: %s]...", header.Filename, formatBytes(header.Size), mode)

	tempFile, err := os.CreateTemp("", "appaudit-upload-*.exe")
	if err != nil {
		s.logError("Failed to allocate temporary upload file: %v", err)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "Internal error creating temporary upload spool"})
		return
	}
	tempPath := tempFile.Name()
	defer os.Remove(tempPath)
	defer tempFile.Close()

	written, err := tempFile.ReadFrom(file)
	if err != nil {
		s.logError("Failed to stream upload content to disk: %v", err)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "Internal error streaming uploaded binary"})
		return
	}
	_ = tempFile.Close()

	model := r.FormValue("model")
	engine, err := s.buildEngineForMode(r.Context(), mode, model)
	if err != nil {
		s.logError("Engine instantiation failed: %v", err)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "error",
			"error":  err.Error(),
		})
		s.logRequest(r.Method, r.URL.Path, clientIP, http.StatusServiceUnavailable, time.Since(start), "Engine initialization error")
		return
	}

	app, err := engine.InspectSingleBinary(tempPath, header.Filename)
	latencyMs := float64(time.Since(start).Microseconds()) / 1000.0
	if err != nil {
		s.logError("Audit pipeline failed for %q: %v", header.Filename, err)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("Audit pipeline error: %v", err)})
		s.logRequest(r.Method, r.URL.Path, clientIP, http.StatusInternalServerError, time.Since(start), "Pipeline error")
		return
	}

	_ = written
	resp := s.buildAuditResponse(app, header.Filename, mode, latencyMs, model)
	s.logSuccess("Audit resolved %q: %s [%s] in %.1fms", resp.Name, resp.Classification, resp.VerificationSource, latencyMs)
	s.logRequest(r.Method, r.URL.Path, clientIP, http.StatusOK, time.Since(start), fmt.Sprintf("%s -> %s (%s)", resp.Name, resp.Classification, resp.VerificationSource))

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// Host Quick Scan: POST /api/v1/audit/quick

func (s *Server) handleAuditQuick(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	clientIP := r.RemoteAddr

	if r.Method != http.MethodPost {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "Method not allowed. Use POST."})
		return
	}

	modes := parseComparisonModes(r)
	if len(modes) > 1 {
		if err := s.validateEngineKeys("", modes); err != nil {
			s.logError("Quick scan rejected: %v", err)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status": "error",
				"error":  err.Error(),
				"code":   "API_KEY_REQUIRED",
			})
			return
		}
		s.logDetail("Starting Host Quick Scan Multi-Engine Benchmark across %d engines: %s...",
			len(modes), strings.Join(modes, ", "))
		raw, err := application.DiscoverQuickScan()
		if err != nil {
			s.logError("Host quick scan discovery failed: %v", err)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("Quick scan discovery failed: %v", err)})
			return
		}
		cmpResp := s.runMultiAppCompare(r.Context(), "Quick Scan", "Host Applications & PATH", modes, raw, start)
		s.logSuccess("Quick Scan multi-engine comparison complete (%d modes, %d apps) in %.1fms",
			len(modes), cmpResp.TotalScanned, cmpResp.DurationMs)
		s.logRequest(r.Method, r.URL.Path, clientIP, http.StatusOK, time.Since(start),
			fmt.Sprintf("Quick Scan Compare (%d apps, %d modes)", cmpResp.TotalScanned, len(modes)))
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(cmpResp)
		return
	}

	mode := strings.ToLower(strings.TrimSpace(r.FormValue("mode")))
	if mode == "" {
		mode = "none"
	}
	if err := s.validateEngineKeys(mode, nil); err != nil {
		s.logError("Quick scan rejected: %v", err)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "error",
			"error":  err.Error(),
			"code":   "API_KEY_REQUIRED",
		})
		return
	}

	s.logDetail("Starting Host Quick Scan (Start Menu, Registry, PATH) [Mode: %s]...", mode)
	engine, engErr := s.buildEngineForMode(r.Context(), mode, r.FormValue("model"))
	if engErr != nil {
		s.logError("Host quick scan engine init failed: %v", engErr)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "error",
			"error":  engErr.Error(),
		})
		return
	}

	apps, err := engine.RunQuickScan(r.Context())
	if err != nil {
		s.logError("Host quick scan failed: %v", err)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("Quick scan failed: %v", err)})
		return
	}

	resp := s.buildMultiAppResponse("Quick Scan", "Host Applications & PATH", mode, apps, time.Since(start), engine)
	s.logSuccess("Quick Scan complete: %d apps audited (3rd-party: %d, In-house: %d, Unverified: %d) in %.1fms",
		resp.TotalScanned, resp.ThirdPartyCount, resp.InHouseCount, resp.UnverifiedCount, resp.DurationMs)
	s.logRequest(r.Method, r.URL.Path, clientIP, http.StatusOK, time.Since(start), fmt.Sprintf("Quick Scan (%d apps)", resp.TotalScanned))

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// Host Full Scan: POST /api/v1/audit/full

func (s *Server) handleAuditFull(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	clientIP := r.RemoteAddr

	if r.Method != http.MethodPost {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "Method not allowed. Use POST."})
		return
	}

	modes := parseComparisonModes(r)
	if len(modes) > 1 {
		if err := s.validateEngineKeys("", modes); err != nil {
			s.logError("Full scan rejected: %v", err)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status": "error",
				"error":  err.Error(),
				"code":   "API_KEY_REQUIRED",
			})
			return
		}
		s.logDetail("Starting Deep Host Scan Multi-Engine Benchmark across %d engines: %s...",
			len(modes), strings.Join(modes, ", "))
		raw, err := application.DiscoverFullScan()
		if err != nil {
			s.logError("Host full scan discovery failed: %v", err)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("Full scan discovery failed: %v", err)})
			return
		}
		cmpResp := s.runMultiAppCompare(r.Context(), "Full Scan", "All Host Applications (Excluding System Folders)", modes, raw, start)
		s.logSuccess("Deep Host Scan multi-engine comparison complete (%d modes, %d apps) in %.1fms",
			len(modes), cmpResp.TotalScanned, cmpResp.DurationMs)
		s.logRequest(r.Method, r.URL.Path, clientIP, http.StatusOK, time.Since(start),
			fmt.Sprintf("Full Scan Compare (%d apps, %d modes)", cmpResp.TotalScanned, len(modes)))
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(cmpResp)
		return
	}

	mode := strings.ToLower(strings.TrimSpace(r.FormValue("mode")))
	if mode == "" {
		mode = "none"
	}
	if err := s.validateEngineKeys(mode, nil); err != nil {
		s.logError("Full scan rejected: %v", err)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "error",
			"error":  err.Error(),
			"code":   "API_KEY_REQUIRED",
		})
		return
	}

	s.logDetail("Starting Deep Host Scan (all non-system machine applications) [Mode: %s]...", mode)
	engine, engErr := s.buildEngineForMode(r.Context(), mode, r.FormValue("model"))
	if engErr != nil {
		s.logError("Deep host scan engine init failed: %v", engErr)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "error",
			"error":  engErr.Error(),
		})
		return
	}

	apps, err := engine.RunFullScan(r.Context())
	if err != nil {
		s.logError("Full scan failed: %v", err)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("Full scan failed: %v", err)})
		return
	}

	resp := s.buildMultiAppResponse("Full Scan", "All Host Applications (Excluding System Folders)", mode, apps, time.Since(start), engine)
	s.logSuccess("Full Scan complete: %d apps audited (3rd-party: %d, In-house: %d, Unverified: %d) in %.1fms",
		resp.TotalScanned, resp.ThirdPartyCount, resp.InHouseCount, resp.UnverifiedCount, resp.DurationMs)
	s.logRequest(r.Method, r.URL.Path, clientIP, http.StatusOK, time.Since(start), fmt.Sprintf("Full Scan (%d apps)", resp.TotalScanned))

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// Custom Directory Audit: POST /api/v1/audit/directory

func (s *Server) handleAuditDirectory(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	clientIP := r.RemoteAddr

	if r.Method != http.MethodPost {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "Method not allowed. Use POST."})
		return
	}

	var targetPath string
	var mode string
	var model string
	var reqModes []string

	// Support both JSON body and form data
	if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		var req DirectoryAuditRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err == nil {
			targetPath = req.Path
			mode = req.Mode
			model = req.Model
			reqModes = req.Modes
		}
	} else {
		targetPath = r.FormValue("path")
		mode = r.FormValue("mode")
		model = r.FormValue("model")
	}

	targetPath = strings.Trim(strings.TrimSpace(targetPath), "\"'")
	if targetPath == "" {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "Missing required 'path' field"})
		return
	}

	cleanP := filepath.Clean(targetPath)
	// Security hardening: Block UNC network paths (e.g. \\attacker-server\share) to protect against NetNTLMv2 credential harvesting
	if strings.HasPrefix(cleanP, `\\`) || strings.HasPrefix(targetPath, `\\`) || strings.HasPrefix(targetPath, "//") {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "Security refusal: Network UNC paths are disallowed to prevent credential harvesting."})
		return
	}

	if fi, err := os.Stat(cleanP); err != nil || !fi.IsDir() {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("Folder does not exist or is not a directory: %s", MaskPII(cleanP))})
		return
	}

	modes := reqModes
	if len(modes) == 0 {
		modes = parseComparisonModes(r)
	}

	if len(modes) > 1 {
		if err := s.validateEngineKeys("", modes); err != nil {
			s.logError("Directory scan rejected: %v", err)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status": "error",
				"error":  err.Error(),
				"code":   "API_KEY_REQUIRED",
			})
			return
		}
		s.logDetail("Starting Directory Audit Multi-Engine Benchmark of %s across %d engines: %s...",
			MaskPII(cleanP), len(modes), strings.Join(modes, ", "))
		raw, err := application.DiscoverDirectory(cleanP)
		if err != nil {
			s.logError("Directory discovery failed: %v", err)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("Directory discovery failed: %v", err)})
			return
		}
		cmpResp := s.runMultiAppCompare(r.Context(), "Custom Directory", cleanP, modes, raw, start)
		s.logSuccess("Directory scan multi-engine comparison complete (%d modes, %d apps) in %.1fms",
			len(modes), cmpResp.TotalScanned, cmpResp.DurationMs)
		s.logRequest(r.Method, r.URL.Path, clientIP, http.StatusOK, time.Since(start),
			fmt.Sprintf("Directory Compare (%d apps, %d modes)", cmpResp.TotalScanned, len(modes)))
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(cmpResp)
		return
	}

	if mode == "" {
		mode = "none"
	}
	if err := s.validateEngineKeys(mode, nil); err != nil {
		s.logError("Directory scan rejected: %v", err)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "error",
			"error":  err.Error(),
			"code":   "API_KEY_REQUIRED",
		})
		return
	}

	s.logDetail("Starting recursive directory audit of %s [Mode: %s]...", MaskPII(cleanP), mode)
	engine, engErr := s.buildEngineForMode(r.Context(), mode, model)
	if engErr != nil {
		s.logError("Directory scan engine init failed: %v", engErr)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "error",
			"error":  engErr.Error(),
		})
		return
	}

	apps, err := engine.AnalyzePaths(r.Context(), []string{cleanP})
	if err != nil {
		s.logError("Directory audit failed: %v", err)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("Directory audit failed: %v", err)})
		return
	}

	resp := s.buildMultiAppResponse("Custom Directory", cleanP, mode, apps, time.Since(start), engine)
	s.logSuccess("Directory audit of %s complete: %d apps audited in %.1fms",
		MaskPII(cleanP), resp.TotalScanned, resp.DurationMs)
	s.logRequest(r.Method, r.URL.Path, clientIP, http.StatusOK, time.Since(start), fmt.Sprintf("Directory Scan (%d apps)", resp.TotalScanned))

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// Preflight Statistics: POST /api/v1/preflight/stats

func (s *Server) handlePreflightStats(w http.ResponseWriter, r *http.Request) {
	var req PreflightStatsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "Invalid JSON body"})
		return
	}

	target := strings.TrimSpace(req.Target)
	if target == "" {
		target = strings.TrimSpace(req.Type)
	}
	if target == "" {
		target = "quick"
	}

	modes := req.Modes
	if len(modes) == 0 && req.Mode != "" {
		modes = []string{req.Mode}
	}
	if len(modes) == 0 {
		modes = []string{"none"}
	}

	hasAI := false
	for _, m := range modes {
		if m == "gemini" || m == "deepseek" || m == "ollama" {
			hasAI = true
			break
		}
	}

	count := 0
	targetName := ""
	estDuration := "< 2 seconds"
	arch := "Deterministic Static Triage (Authenticode + Buildinfo)"

	switch strings.ToLower(target) {
	case "single", "file":
		fileName := req.Path
		if fileName == "" {
			fileName = "Target Binary"
		} else {
			fileName = filepath.Base(fileName)
		}
		targetName = fmt.Sprintf("Single Binary (%s)", fileName)
		count = 1
		if len(modes) > 1 {
			arch = fmt.Sprintf("Multi-Engine Benchmark (%d engines) + Early Exit Optimization", len(modes))
			if hasAI {
				estDuration = fmt.Sprintf("~%d - %d seconds", len(modes)*25, len(modes)*75)
			} else {
				estDuration = "< 3 seconds"
			}
		} else {
			if hasAI {
				estDuration = "~30 - 90 seconds"
				arch = "Static Cryptographic Triage + AI Provenance Inspection"
			} else {
				estDuration = "< 3 seconds"
				arch = "Ultra-Fast Static Cryptographic & Buildinfo Triage"
			}
		}

	case "quick":
		targetName = "Host Applications & PATH"
		raw, err := application.DiscoverQuickScan()
		if err == nil {
			count = len(raw)
		} else {
			count = 45 // fallback estimate
		}
		if len(modes) > 1 {
			minSec := (count * len(modes) * 8) / 60
			maxSec := (count * len(modes) * 25) / 60
			if minSec < 2 {
				minSec = 2
			}
			if maxSec < minSec+2 {
				maxSec = minSec + 3
			}
			estDuration = fmt.Sprintf("~%d - %d mins", minSec, maxSec)
			arch = fmt.Sprintf("Multi-Engine Benchmark (%d engines) + Early Exit Optimization", len(modes))
		} else {
			if hasAI {
				minSec := (count * 6) / 60
				maxSec := (count * 18) / 60
				if minSec < 1 {
					minSec = 1
				}
				if maxSec < minSec+1 {
					maxSec = minSec + 2
				}
				estDuration = fmt.Sprintf("~%d - %d mins", minSec, maxSec)
				arch = "Static Cryptographic Triage + AI Discrepancy Verification"
			} else {
				estDuration = "~10 - 25 seconds"
				arch = "Ultra-Fast Static Cryptographic & Buildinfo Triage"
			}
		}

	case "full":
		targetName = "Deep Host Machine Scan"
		raw, err := application.DiscoverFullScan()
		if err == nil {
			count = len(raw)
		} else {
			count = 120 // fallback estimate
		}
		if len(modes) > 1 {
			minSec := (count * len(modes) * 10) / 60
			maxSec := (count * len(modes) * 30) / 60
			if minSec < 5 {
				minSec = 5
			}
			estDuration = fmt.Sprintf("~%d - %d mins", minSec, maxSec)
			arch = fmt.Sprintf("Deep Multi-Engine Benchmark (%d engines)", len(modes))
		} else {
			if hasAI {
				minSec := (count * 8) / 60
				maxSec := (count * 22) / 60
				if minSec < 3 {
					minSec = 3
				}
				estDuration = fmt.Sprintf("~%d - %d mins", minSec, maxSec)
			} else {
				estDuration = "~30 - 75 seconds"
			}
			arch = "Deep Non-System Machine Applications Scan"
		}

	default:
		// Custom Directory
		targetPath := req.Path
		if targetPath == "" {
			targetPath = target
		}
		cleanP := filepath.Clean(targetPath)
		targetName = fmt.Sprintf("Directory: %s", filepath.Base(cleanP))
		if fi, err := os.Stat(cleanP); err == nil && fi.IsDir() {
			raw, err := application.DiscoverDirectory(cleanP)
			if err == nil {
				count = len(raw)
			} else {
				count = 10
			}
		} else {
			count = 0
		}
		effectiveCount := count
		if effectiveCount < 1 {
			effectiveCount = 1
		}
		if len(modes) > 1 {
			minSec := effectiveCount * len(modes) * 15
			maxSec := effectiveCount * len(modes) * 45
			if maxSec >= 120 {
				estDuration = fmt.Sprintf("~%d - %d mins", (minSec+59)/60, (maxSec+59)/60)
			} else {
				estDuration = fmt.Sprintf("~%d - %d seconds", minSec, maxSec)
			}
			arch = fmt.Sprintf("Custom Folder Multi-Engine Benchmark (%d engines)", len(modes))
		} else {
			if hasAI {
				minSec := effectiveCount * 15
				maxSec := effectiveCount * 45
				if maxSec >= 120 {
					estDuration = fmt.Sprintf("~%d - %d mins", (minSec+59)/60, (maxSec+59)/60)
				} else {
					estDuration = fmt.Sprintf("~%d - %d seconds", minSec, maxSec)
				}
			} else {
				estDuration = fmt.Sprintf("~%d - %d seconds", max(2, effectiveCount/2), max(5, effectiveCount*2))
			}
			arch = "Recursive Folder Cryptographic & Manifest Inspection"
		}
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(PreflightStatsResponse{
		Count:              count,
		EstimatedDuration:  estDuration,
		Target:             targetName,
		Modes:              modes,
		TriageArchitecture: arch,
	})
}

// Response Builders & Enterprise Presentation Formatters

func (s *Server) buildAuditResponse(app *application.Application, originalFilename, requestedMode string, latencyMs float64, customModel ...string) AuditResponse {
	name := originalFilename
	if name == "" {
		name = app.Name + ".exe"
	}

	rawClassification := string(app.Classification)
	if app.Classification == provenance.ClassificationCompany {
		rawClassification = "IN_HOUSE"
	}

	tier := determineTriageTier(app)
	sourceLabel := FormatVerificationSource(tier, app.Reasons, app.SearchGrounded)
	classLabel := FormatClassification(app.Classification)
	confLabel := FormatConfidence(app.Confidence)
	summary := FormatSummaryOfFindings(app)
	evidence := determineEvidence(app)
	modelUsed := s.determineModelUsed(app, requestedMode, customModel...)

	privacy := "Local Offline (0 egress bytes)"
	if requestedMode == "gemini" || requestedMode == "deepseek" {
		privacy = "Cloud API Roundtrip"
	}

	stageNum, stageName, aiBypassed, exitLayer, exitReason := determineStageInfo(tier, app)
	tokenEcon := computeTokenEconomics(app, requestedMode, aiBypassed)

	var provErrors []string
	if app.AIError != "" {
		provErrors = append(provErrors, NormalizeProviderError(app.AIError))
	}

	var scanWarnings []string
	if !app.SearchGrounded && requestedMode == "ollama" && app.Classification != provenance.ClassificationUnknown {
		if app.SearchWarning != "" {
			scanWarnings = append(scanWarnings, app.SearchWarning)
		} else if app.DegradationWarning != "" {
			scanWarnings = append(scanWarnings, app.DegradationWarning)
		} else {
			scanWarnings = append(scanWarnings, "Local AI verdict generated from internal model weights without live SearXNG grounding.")
		}
	}
	if app.ReadError != "" {
		scanWarnings = append(scanWarnings, "Inspection Halted: "+app.ReadError)
	}

	return AuditResponse{
		Name:               name,
		SHA256:             app.PrimarySHA256(),
		Classification:     classLabel,
		RawClassification:  rawClassification,
		Confidence:         confLabel,
		VerificationSource: sourceLabel,
		TriageTier:         tier,
		Summary:            summary,
		Evidence:           MaskPII(evidence),
		ModelUsed:          modelUsed,
		LatencyMs:          math.Round(latencyMs*10) / 10,
		Privacy:            privacy,
		AIError:            app.AIError,
		Reasons:            maskReasons(app.Reasons),
		SearchGrounded:     app.SearchGrounded,
		DegradationWarning: app.DegradationWarning,
		ReadError:          app.ReadError,
		ProviderErrors:     provErrors,
		ScanWarnings:       scanWarnings,
		StageNumber:        stageNum,
		StageName:          stageName,
		AIBypassed:         aiBypassed,
		ExitLayer:          exitLayer,
		ExitReason:         exitReason,
		TokenEconomics:     tokenEcon,
	}
}

func (s *Server) buildMultiAppResponse(scanType, target, mode string, apps []application.Application, elapsed time.Duration, engine ...*application.Engine) MultiAppScanResponse {
	var summaries []ScannedAppSummary
	tpCount := 0
	ihCount := 0
	unkCount := 0
	staticEarlyExits := 0
	aiEngaged := 0
	totalPrompt := 0
	totalCompletion := 0
	totalConsumed := 0
	totalSaved := 0

	var provErrors []string
	provErrorSet := make(map[string]bool)
	var scanWarnings []string
	scanWarningSet := make(map[string]bool)
	ungroundedCount := 0

	for _, a := range apps {
		if a.AIError != "" {
			normErr := NormalizeProviderError(a.AIError)
			if !provErrorSet[normErr] {
				provErrorSet[normErr] = true
				provErrors = append(provErrors, normErr)
			}
		}
		if a.ReadError != "" && !scanWarningSet[a.ReadError] {
			scanWarningSet[a.ReadError] = true
			scanWarnings = append(scanWarnings, fmt.Sprintf("File inspection halted on %s: %s", a.Name, a.ReadError))
		}
		if !a.SearchGrounded && mode == "ollama" && a.Classification != provenance.ClassificationUnknown {
			ungroundedCount++
		}

		tier := determineTriageTier(&a)
		sourceLabel := FormatVerificationSource(tier, a.Reasons, a.SearchGrounded)
		classLabel := FormatClassification(a.Classification)
		confLabel := FormatConfidence(a.Confidence)
		summary := FormatSummaryOfFindings(&a)

		rawClass := string(a.Classification)
		switch a.Classification {
		case provenance.ClassificationCompany:
			rawClass = "IN_HOUSE"
			ihCount++
		case provenance.ClassificationThirdParty:
			tpCount++
		default:
			unkCount++
		}

		p := a.PrimaryBinaryPath
		if p == "" && len(a.Binaries) > 0 {
			p = a.Binaries[0].Path
		}

		stageNum, stageName, aiBypassed, exitLayer, _ := determineStageInfo(tier, &a)
		tokenEcon := computeTokenEconomics(&a, mode, aiBypassed)

		if aiBypassed {
			staticEarlyExits++
			totalSaved += tokenEcon.TokensSaved
		} else {
			aiEngaged++
			totalPrompt += tokenEcon.PromptTokens
			totalCompletion += tokenEcon.CompletionTokens
			totalConsumed += tokenEcon.TotalTokens
		}

		summaries = append(summaries, ScannedAppSummary{
			Name:               a.Name,
			Path:               MaskPII(p),
			SHA256:             a.PrimarySHA256(),
			Classification:     classLabel,
			RawClassification:  rawClass,
			Confidence:         confLabel,
			VerificationSource: sourceLabel,
			Summary:            summary,
			StageNumber:        stageNum,
			StageName:          stageName,
			AIBypassed:         aiBypassed,
			ExitLayer:          exitLayer,
			TokenEconomics:     tokenEcon,
			SearchGrounded:     a.SearchGrounded,
			DegradationWarning: a.DegradationWarning,
			ReadError:          a.ReadError,
			AIError:            a.AIError,
			Reasons:            maskReasons(a.Reasons),
		})
	}

	if ungroundedCount > 0 {
		scanWarnings = append(scanWarnings, fmt.Sprintf("%d application(s) were evaluated using local model weights without live SearXNG grounding.", ungroundedCount))
	}

	degradedCIRCL := false
	circlSkipped := 0
	if len(engine) > 0 && engine[0] != nil && engine[0].DecisionEngine() != nil && engine[0].DecisionEngine().HashLookupClient != nil {
		hl := engine[0].DecisionEngine().HashLookupClient
		if hl.IsDegraded() {
			degradedCIRCL = true
			circlSkipped = hl.SkippedCount()
			scanWarnings = append(scanWarnings, fmt.Sprintf("Tier 3 Hashlookup throttled (429) — %d files bypassed registry check", circlSkipped))
		}
	}

	savingsPct := 100.0
	if len(apps) > 0 {
		savingsPct = math.Round((float64(staticEarlyExits)/float64(len(apps)))*1000) / 10
	}

	var costUSD float64
	var costFormatted string
	switch mode {
	case "ollama":
		costFormatted = "$0.0000 (Local Compute)"
	case "deepseek":
		costUSD = (float64(totalPrompt)*0.00000014 + float64(totalCompletion)*0.00000028)
		costFormatted = fmt.Sprintf("$%.4f", costUSD)
	default:
		costUSD = (float64(totalPrompt)*0.000000075 + float64(totalCompletion)*0.00000030)
		costFormatted = fmt.Sprintf("$%.4f", costUSD)
	}

	economics := ScanEconomicsSummary{
		TotalPromptTokens:     totalPrompt,
		TotalCompletionTokens: totalCompletion,
		TotalTokensConsumed:   totalConsumed,
		TotalTokensSaved:      totalSaved,
		StaticEarlyExitCount:  staticEarlyExits,
		AIEngagedCount:        aiEngaged,
		EstimatedCostUSD:      costUSD,
		FormattedCost:         costFormatted,
		SavingsPercentage:     savingsPct,
	}

	return MultiAppScanResponse{
		ScanType:             scanType,
		Target:               MaskPII(target),
		TotalScanned:         len(apps),
		ThirdPartyCount:      tpCount,
		InHouseCount:         ihCount,
		UnverifiedCount:      unkCount,
		DurationMs:           math.Round((float64(elapsed.Microseconds())/1000.0)*10) / 10,
		ModeUsed:             mode,
		StaticEarlyExitCount: staticEarlyExits,
		AIEngagedCount:       aiEngaged,
		Economics:            economics,
		ProviderErrors:       provErrors,
		ScanWarnings:         scanWarnings,
		DegradedCIRCL:        degradedCIRCL,
		CIRCLSkippedCount:    circlSkipped,
		Applications:         summaries,
	}
}

// FormatVerificationSource transforms internal technical pipeline labels into clear enterprise terms.
func FormatVerificationSource(tier string, reasons []string, searchGrounded ...bool) string {
	combined := tier + " " + strings.Join(reasons, " ")

	if strings.Contains(combined, "Authenticode") || strings.Contains(combined, "certificate") || strings.Contains(combined, "code-signing") || strings.Contains(combined, "Signed by") {
		return "Verified Publisher Signature"
	}
	if strings.Contains(combined, "Compiler") || strings.Contains(combined, "Go programming") || strings.Contains(combined, "build metadata") || strings.Contains(combined, "github.com") {
		return "Public Open-Source Build Metadata"
	}
	if strings.Contains(combined, "Local Receipt") || strings.Contains(combined, "Package") || strings.Contains(combined, "String Mining") || strings.Contains(combined, "Manifest") {
		return "Local Package Manifest Receipt"
	}
	if strings.Contains(combined, "CIRCL") || strings.Contains(combined, "Public Hash DB") || strings.Contains(combined, "Hashlookup") || strings.Contains(combined, "release artifact") {
		return "Public Registry Hash Match (CIRCL)"
	}
	if strings.Contains(combined, "Company Registry") || strings.Contains(combined, "company") || strings.Contains(combined, "Company") {
		return "Registered Internal Enterprise Tool"
	}
	if strings.Contains(combined, "AI Provenance Inspection") {
		return "AI Provenance Inspection"
	}
	if strings.Contains(combined, "Gemini") || strings.Contains(combined, "DeepSeek") || strings.Contains(combined, "Ollama") || strings.Contains(combined, "AI Reasoning") || strings.Contains(combined, "Tier 2") {
		if strings.Contains(combined, "Ollama") {
			grounded := false
			if len(searchGrounded) > 0 {
				grounded = searchGrounded[0]
			}
			if grounded {
				return "AI Analysis — Local Web Grounded (Ollama + SearXNG)"
			}
			return "AI Analysis — Local Model Memory Only (Ungrounded / Hallucination Risk)"
		}
		if strings.Contains(combined, "DeepSeek") {
			return "Cloud AI Analysis (DeepSeek)"
		}
		return "Cloud AI Analysis — Live Web Grounded (Gemini)"
	}
	if strings.Contains(combined, "Deterministic") {
		return "Cryptographic Static Analysis"
	}
	return "Heuristic Analysis"
}

// NormalizeProviderError formats raw error strings into crisp enterprise alerts.
func NormalizeProviderError(raw string) string {
	lower := strings.ToLower(raw)
	if strings.Contains(lower, "402") || strings.Contains(lower, "balance has run out") || strings.Contains(lower, "insufficient balance") {
		return "DeepSeek Account Balance Depleted ($0.00) — Replenish API Credits"
	}
	if strings.Contains(lower, "401") || strings.Contains(lower, "403") || strings.Contains(lower, "unauthorized") || strings.Contains(lower, "invalid api key") || strings.Contains(lower, "billing disabled") {
		return "Invalid API Key or Billing Disabled"
	}
	if strings.Contains(lower, "429") || strings.Contains(lower, "too many requests") || strings.Contains(lower, "quota exceeded") {
		return "Quota Exceeded — 429"
	}
	if strings.Contains(lower, "vram") || strings.Contains(lower, "gpu constraints") {
		return "Ollama VRAM Refusal — Insufficient GPU Memory"
	}
	if strings.Contains(lower, "not found") && strings.Contains(lower, "model") {
		return "Ollama Missing Model — Model Not Installed"
	}
	if strings.Contains(lower, "connection refused") || strings.Contains(lower, "ollama unreachable") || strings.Contains(lower, "ollama error") {
		return "Ollama Offline / Daemon Unreachable (127.0.0.1:11434)"
	}
	return raw
}

// FormatClassification converts classification enums into polished enterprise tags.
func FormatClassification(c provenance.Classification) string {
	switch c {
	case provenance.ClassificationThirdParty, "third_party":
		return "Verified Third-Party"
	case provenance.ClassificationCompany, "IN_HOUSE", "in_house":
		return "In-House / Custom Tool"
	default:
		return "Unverified / Unknown"
	}
}

// FormatConfidence standardizes confidence ratings into clean strings.
func FormatConfidence(c provenance.Confidence) string {
	switch c {
	case provenance.ConfidenceVeryHigh, provenance.ConfidenceHigh:
		return "High"
	case provenance.ConfidenceMedium:
		return "Medium"
	default:
		return "Low"
	}
}

// FormatSummaryOfFindings produces a clean 1-2 sentence human-readable finding summary.
func FormatSummaryOfFindings(app *application.Application) string {
	if app == nil {
		return "No software findings available."
	}

	if app.EvidenceSummary != "" {
		cleaned := cleanRawReason(app.EvidenceSummary)
		if cleaned != "" {
			return MaskPII(cleaned)
		}
	}

	if app.Conclusion != "" {
		cleaned := cleanRawReason(app.Conclusion)
		if cleaned != "" {
			return MaskPII(cleaned)
		}
	}

	if app.AIError != "" {
		return fmt.Sprintf("AI evaluation could not complete: %s.", MaskPII(cleanRawReason(app.AIError)))
	}

	switch app.Classification {
	case provenance.ClassificationThirdParty:
		for _, r := range app.Reasons {
			if strings.Contains(r, "Signed by") || strings.Contains(r, "code-signing") {
				return "Cryptographically signed by a verified commercial software publisher with an intact certificate trust chain."
			}
			if strings.Contains(r, "Compiler build metadata confirms") {
				return cleanRawReason(r)
			}
			if strings.Contains(r, "Discovered public repository") {
				return cleanRawReason(r)
			}
		}
		if app.Publisher != "" {
			return fmt.Sprintf("Confirmed third-party software package developed by %s.", app.Publisher)
		}
		return "Cryptographic signatures and public repository records confirm external third-party provenance."

	case provenance.ClassificationCompany:
		return "Identified as an internal company utility explicitly registered in the organizational software manifest."

	default:
		return "No cryptographically verifiable publisher signature, matching public release registry, or internal company registry record was identified."
	}
}

func cleanRawReason(r string) string {
	s := r
	prefixes := []string{
		"Tier 1 Hard Evidence: ",
		"Tier 1.5A Local Receipt: ",
		"Tier 1.5A String Mining: ",
		"Tier 1.5B Public Hash DB: ",
		"Rule F Fallback: ",
	}
	for _, p := range prefixes {
		s = strings.TrimPrefix(s, p)
	}
	s = strings.TrimSpace(s)
	if s != "" && !strings.HasSuffix(s, ".") {
		s += "."
	}
	return s
}

func maskReasons(reasons []string) []string {
	var masked []string
	for _, r := range reasons {
		masked = append(masked, MaskPII(r))
	}
	return masked
}

func determineTriageTier(app *application.Application) string {
	for _, r := range app.Reasons {
		if strings.Contains(r, "Tier 1 Hard Evidence:") {
			if strings.Contains(r, "code-signing") || strings.Contains(r, "certificate") || strings.Contains(r, "Signed by") || strings.Contains(r, "Authenticode") {
				return "Tier 1 Authenticode"
			}
			if strings.Contains(r, "Go programming") || strings.Contains(r, "Compiler") || strings.Contains(r, "build metadata") {
				return "Tier 1 Compiler Buildinfo"
			}
			if strings.Contains(r, "digest") || strings.Contains(r, "release artifact") {
				return "Tier 1 Verified Hash"
			}
			if strings.Contains(r, "company") || strings.Contains(r, "Company") {
				return "Tier 1 Company Registry"
			}
			return "Tier 1 Deterministic"
		}
		if strings.Contains(r, "Tier 1.5A") {
			if strings.Contains(r, "Receipt") {
				return "Tier 1.5A Local Receipt"
			}
			if strings.Contains(r, "String") {
				return "Tier 1.5A String Mining"
			}
			return "Tier 1.5A Local Receipt"
		}
		if strings.Contains(r, "Tier 1.5B") {
			return "Tier 1.5B Public Hash DB"
		}
	}

	if strings.Contains(app.ResolutionSource, "gemini") {
		return "Tier 2 Gemini Grounded"
	}
	if strings.Contains(app.ResolutionSource, "deepseek") {
		return "Tier 2 DeepSeek Reasoning"
	}
	if strings.Contains(app.ResolutionSource, "ollama") {
		return "Tier 2 Ollama Local"
	}
	if strings.Contains(app.ResolutionSource, "ai") {
		return "Tier 2 AI Reasoning"
	}

	if app.Classification == provenance.ClassificationUnknown {
		return "Tier 3 Unresolved"
	}
	return "Tier 1 Deterministic"
}

func determineEvidence(app *application.Application) string {
	if app.EvidenceSummary != "" {
		return cleanRawReason(app.EvidenceSummary)
	}
	if len(app.Reasons) > 0 {
		var details []string
		for _, r := range app.Reasons {
			trimmed := cleanRawReason(r)
			if trimmed != "" {
				details = append(details, trimmed)
			}
		}
		if len(details) > 0 {
			return strings.Join(details, " ")
		}
		return app.Reasons[0]
	}
	if len(app.OwnershipEvidence) > 0 {
		return app.OwnershipEvidence[0].Description
	}
	if app.Classification == provenance.ClassificationUnknown {
		return "No cryptographic code signatures, trusted manifests, or verified repository records detected."
	}
	return "Classified via deterministic static analysis."
}

func (s *Server) determineModelUsed(app *application.Application, requestedMode string, customModel ...string) string {
	_ = requestedMode
	chosen := ""
	if len(customModel) > 0 && strings.TrimSpace(customModel[0]) != "" {
		chosen = strings.TrimSpace(customModel[0])
	}
	if strings.Contains(app.ResolutionSource, "gemini") {
		if chosen != "" {
			return chosen
		}
		return s.getActiveModel("gemini")
	}
	if strings.Contains(app.ResolutionSource, "deepseek") {
		if chosen != "" {
			return chosen
		}
		return s.getActiveModel("deepseek")
	}
	if strings.Contains(app.ResolutionSource, "ollama") {
		if chosen != "" {
			return chosen
		}
		return s.getActiveModel("ollama")
	}
	return "none"
}

func determineStageInfo(tier string, app *application.Application) (stageNum int, stageName string, aiBypassed bool, exitLayer string, exitReason string) {
	if strings.Contains(tier, "Tier 1") || strings.Contains(tier, "Company Registry") || strings.Contains(tier, "Authenticode") || strings.Contains(tier, "Compiler") {
		if strings.Contains(tier, "Authenticode") {
			return 1, "Stage 1: Verified Publisher Signature", true, "Static Cryptographic Layer (Early Exit)",
				"Resolved at Stage 1 via cryptographically verified publisher signature. AI reasoning layer bypassed."
		}
		if strings.Contains(tier, "Compiler") || strings.Contains(tier, "Buildinfo") {
			return 1, "Stage 1: Public Open-Source Build Metadata", true, "Static Compiler Metadata Layer (Early Exit)",
				"Resolved at Stage 1 via embedded compiler build metadata. AI reasoning layer bypassed."
		}
		if strings.Contains(tier, "Company") {
			return 1, "Stage 1: Registered Company Manifest", true, "Internal Enterprise Registry Layer (Early Exit)",
				"Resolved at Stage 1 via corporate software inventory registry. AI reasoning layer bypassed."
		}
		return 1, "Stage 1: Cryptographic Static Analysis", true, "Static Deterministic Layer (Early Exit)",
			"Resolved at Stage 1 via static cryptographic analysis. AI reasoning layer bypassed."
	}

	if strings.Contains(tier, "Tier 1.5A") || strings.Contains(tier, "Receipt") || strings.Contains(tier, "String") {
		return 2, "Stage 2: Local Package Manifest & Receipts", true, "Local Metadata Layer (Early Exit)",
			"Resolved at Stage 2 via local package receipt or runtime manifest. AI reasoning layer bypassed."
	}

	if strings.Contains(tier, "Tier 1.5B") || strings.Contains(tier, "CIRCL") || strings.Contains(tier, "Hash DB") {
		return 3, "Stage 3: Public Registry Hash Match (CIRCL)", true, "Public Hash Registry Layer (Early Exit)",
			"Resolved at Stage 3 via CIRCL Hashlookup public release registry. AI reasoning layer bypassed."
	}

	if strings.Contains(tier, "Tier 2") || strings.Contains(tier, "AI") || strings.Contains(tier, "Gemini") || strings.Contains(tier, "DeepSeek") || strings.Contains(tier, "Ollama") {
		modelName := "AI Reasoning"
		if strings.Contains(tier, "Gemini") {
			modelName = "Google Gemini"
		} else if strings.Contains(tier, "DeepSeek") {
			modelName = "DeepSeek"
		} else if strings.Contains(tier, "Ollama") {
			modelName = "Local Ollama"
		}
		return 4, fmt.Sprintf("Stage 4: AI Provenance Inspection (%s)", modelName), false, "AI Reasoning Layer",
			fmt.Sprintf("Static layers did not find verified signatures or release records. Fallback reached Stage 4 %s provenance inspection.", modelName)
	}

	// Fallback / Unknown
	if app != nil && app.Classification == provenance.ClassificationUnknown {
		if app.TotalTokens > 0 || (app.ResolutionSource != "" && !strings.Contains(app.ResolutionSource, "deterministic")) {
			return 4, "Stage 4: AI Provenance Inspection (Inconclusive)", false, "AI Reasoning Layer",
				"All static layers and Stage 4 AI provenance inspection were inconclusive. Fallback to Unverified / Unknown."
		}
		return 1, "Stage 1: Static Heuristic Fallback", true, "Static Deterministic Layer",
			"No cryptographic signatures or registry records matched. Fallback to Unverified / Unknown (AI bypassed)."
	}

	return 1, "Stage 1: Deterministic Static Analysis", true, "Static Deterministic Layer (Early Exit)",
		"Resolved at Stage 1 via deterministic static analysis."
}

func computeTokenEconomics(app *application.Application, mode string, aiBypassed bool) TokenEconomics {
	_ = aiBypassed
	if app == nil {
		return TokenEconomics{
			FormattedCost:    "$0.0000",
			EconomicsSummary: "No token consumption data available.",
		}
	}

	prompt := app.PromptTokens
	completion := app.CompletionTokens
	total := app.TotalTokens

	if total > 0 {
		var cost float64
		var costStr string
		switch mode {
		case "ollama":
			cost = 0.0
			costStr = "$0.0000 (Local Compute)"
		case "deepseek":
			cost = (float64(prompt)*0.00000014 + float64(completion)*0.00000028)
			costStr = fmt.Sprintf("$%.5f", cost)
		default: // gemini or default cloud
			cost = (float64(prompt)*0.000000075 + float64(completion)*0.00000030)
			costStr = fmt.Sprintf("$%.5f", cost)
		}

		summary := fmt.Sprintf("%s total tokens (%s prompt, %s completion) consumed. Est. cost: %s.",
			formatNumber(total), formatNumber(prompt), formatNumber(completion), costStr)
		if app.ResearchCacheHit {
			summary = fmt.Sprintf("Cached Response: %s tokens read from local cache (Zero API egress).", formatNumber(total))
		}

		return TokenEconomics{
			PromptTokens:     prompt,
			CompletionTokens: completion,
			TotalTokens:      total,
			TokensSaved:      0,
			EstimatedCostUSD: cost,
			FormattedCost:    costStr,
			CacheHit:         app.ResearchCacheHit,
			EconomicsSummary: summary,
		}
	}

	// AI was bypassed / 0 tokens consumed
	tokensSaved := 1200 // estimated tokens saved per early exit
	summary := "AI Bypassed: 0 tokens consumed at static layer (~1,200 tokens saved, $0.0000 API cost)."
	if app.ResearchCacheHit {
		summary = "Cache Hit: 100% token savings (~1,200 tokens saved, $0.0000 API cost)."
	}

	return TokenEconomics{
		PromptTokens:     0,
		CompletionTokens: 0,
		TotalTokens:      0,
		TokensSaved:      tokensSaved,
		EstimatedCostUSD: 0.0,
		FormattedCost:    "$0.0000 (100% Free / Local)",
		CacheHit:         app.ResearchCacheHit,
		EconomicsSummary: summary,
	}
}

func formatNumber(n int) string {
	if n < 1000 {
		return fmt.Sprintf("%d", n)
	}
	return fmt.Sprintf("%d,%03d", n/1000, n%1000)
}

func formatBytes(bytes int64) string {
	if bytes <= 0 {
		return "0 B"
	}
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}
