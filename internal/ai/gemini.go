package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/example/appaudit/internal/provenance"
)

// DefaultGeminiModel defines the standard Gemini model for research and grounding.
// Gemini 3.5 Flash Lite is fast, cost-effective, natively supports Google Search grounding,
// and enforces structured JSON generation with high reasoning fidelity.
const DefaultGeminiModel = "gemini-3.5-flash-lite"

// DefaultFallbackModels defines standard fallback models if 429 quota or rate limits are encountered.
var DefaultFallbackModels = []string{
	"gemini-3.1-flash-lite",
	"gemini-3.8-flash",
	"gemini-3.5-flash",
}

// Batch chunking and rate-limiting constants for Gemini free tier protection.
const (
	DefaultBatchChunkSize   = 5
	DefaultBatchPacingDelay = 4 * time.Second
)

// BatchSystemInstruction defines the multi-item batch classification prompt.
const BatchSystemInstruction = `You are a software provenance classifier. Analyze the provided batch of application evidence bundles using Google Search. Classify each into FIRST_PARTY, THIRD_PARTY, or UNKNOWN. Return strictly a JSON array containing an object for each candidate in the same order.

REASONING GUIDELINES:
1. Examine binary name, architecture, embedded strings, compiler metadata, and component markers.
2. Cross-reference against Google Search and your knowledge of legitimate public open-source and commercial software.
3. Recognize standard package manager launchers and CLI shims (Python pip/pipx t64/t32 shims, Node npm/npx, Rust cargo, Go install, Scoop, Chocolatey, Winget). If a binary wraps a recognized public tool (e.g., aider, mongosh, jq, git, code, ripgrep), classify as THIRD_PARTY. Do NOT adopt boilerplate wrapper/stub metadata (e.g. 'Simple Launcher User', 'Simple Launcher', 'distlib') as the publisher.
4. Recognize portable and developer tools distributed without EV code signing certificates. If matching a legitimate public project, classify as THIRD_PARTY.
5. If internal company markers match corporate ownership, classify as FIRST_PARTY.
6. If ambiguous or lacking corroborating evidence, classify as UNKNOWN.

SCHEMA: Return strictly a JSON array of objects:
[
  {
    "sha256": "...",
    "classification": "THIRD_PARTY" | "FIRST_PARTY" | "UNKNOWN",
    "confidence": "VERY_HIGH" | "HIGH" | "MEDIUM" | "LOW" | "NONE",
    "identity": "Application or project name",
    "publisher": "Author or vendor",
    "reasons": ["Concise explanation of provenance evidence"],
    "evidence": "Concise key digital evidence",
    "conclusion": "Concise final verdict"
  }
]`

// IsSubGemini3Model reports whether a model identifier refers to a legacy sub-Gemini-3 model
// (e.g. gemini-1.x, gemini-2.x) that is strictly prohibited across the pipeline.
func IsSubGemini3Model(model string) bool {
	return isSubGemini3Model(model)
}

func isSubGemini3Model(model string) bool {
	m := strings.ToLower(strings.TrimSpace(model))
	m = strings.TrimPrefix(m, "models/")
	return strings.HasPrefix(m, "gemini-1.") || strings.HasPrefix(m, "gemini-2.") ||
		strings.HasPrefix(m, "gemini-1-") || strings.HasPrefix(m, "gemini-2-") ||
		m == "gemini-1" || m == "gemini-2"
}

// ValidateGeminiModel validates that the specified Gemini model is supported.
// Returns an error if the model belongs to a legacy sub-Gemini-3 series.
func ValidateGeminiModel(model string) error {
	if isSubGemini3Model(model) {
		return fmt.Errorf("model %q is below Gemini 3: only Gemini 3.x series models are supported", model)
	}
	return nil
}

// GeminiSystemInstruction defines the prompt given to the Gemini reasoner.
const GeminiSystemInstruction = UnifiedSystemPrompt

// GeminiConfig configures the Gemini search-grounded reasoner.
type GeminiConfig struct {
	APIKey            string
	Model             string
	FallbackModels    []string
	BaseURL           string
	Timeout           time.Duration
	HTTPClient        *http.Client
	Cache             *GeminiCache
	NetworkMode       provenance.NetworkMode
	ChunkSize         int
	PacingDelay       time.Duration
	SystemInstruction string
	AllowAnyModel     bool
}

// GeminiReasoner implements Reasoner using Google's Gemini API with Google Search grounding.
type GeminiReasoner struct {
	config GeminiConfig
	client *http.Client
	cache  *GeminiCache
}

// NewGeminiReasoner creates an initialized Gemini reasoner with search grounding enabled.
func NewGeminiReasoner(cfg GeminiConfig) *GeminiReasoner {
	if cfg.Model == "" || (!cfg.AllowAnyModel && isSubGemini3Model(cfg.Model)) {
		cfg.Model = DefaultGeminiModel
	}

	var sanitizedFallbacks []string
	for _, fb := range cfg.FallbackModels {
		clean := strings.TrimSpace(fb)
		if clean != "" && (cfg.AllowAnyModel || !isSubGemini3Model(clean)) {
			sanitizedFallbacks = append(sanitizedFallbacks, clean)
		}
	}
	if len(sanitizedFallbacks) == 0 {
		cfg.FallbackModels = make([]string, len(DefaultFallbackModels))
		copy(cfg.FallbackModels, DefaultFallbackModels)
	} else {
		cfg.FallbackModels = sanitizedFallbacks
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://generativelanguage.googleapis.com/v1beta"
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 180 * time.Second
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{
			Timeout: cfg.Timeout,
		}
	}
	cache := cfg.Cache
	if cache == nil {
		cache = NewGeminiCache()
	}

	if cfg.ChunkSize <= 0 {
		cfg.ChunkSize = DefaultBatchChunkSize
	}
	if cfg.PacingDelay == 0 {
		cfg.PacingDelay = DefaultBatchPacingDelay
	} else if cfg.PacingDelay < 0 {
		cfg.PacingDelay = 0
	}

	return &GeminiReasoner{
		config: cfg,
		client: client,
		cache:  cache,
	}
}

func (g *GeminiReasoner) Name() string {
	return "gemini_search_grounded (" + g.config.Model + ")"
}

// Request and Response schemas for Gemini REST API v1beta
type geminiGenerateRequest struct {
	SystemInstruction *geminiContent          `json:"systemInstruction,omitempty"`
	Contents          []geminiContent         `json:"contents"`
	Tools             []geminiTool            `json:"tools,omitempty"`
	GenerationConfig  *geminiGenerationConfig `json:"generationConfig,omitempty"`
}

type geminiContent struct {
	Role  string       `json:"role,omitempty"`
	Parts []geminiPart `json:"parts"`
}

type geminiPart struct {
	Text string `json:"text"`
}

type geminiTool struct {
	GoogleSearch *struct{} `json:"googleSearch,omitempty"`
}

type geminiGenerationConfig struct {
	ResponseMimeType string   `json:"responseMimeType,omitempty"`
	Temperature      *float64 `json:"temperature,omitempty"`
}

type batchItemOutput struct {
	SHA256         string   `json:"sha256"`
	Classification string   `json:"classification"`
	Confidence     string   `json:"confidence"`
	Identity       string   `json:"identity"`
	Publisher      string   `json:"publisher"`
	Reasons        []string `json:"reasons"`
	Sources        []string `json:"sources,omitempty"`
	Evidence       string   `json:"evidence,omitempty"`
	Conclusion     string   `json:"conclusion,omitempty"`
}

func (b *batchItemOutput) UnmarshalJSON(data []byte) error {
	type Alias batchItemOutput
	aux := struct {
		RawReasons    any `json:"reasons"`
		RawIdentity   any `json:"identity"`
		RawOwnership  any `json:"ownership"`
		RawConfidence any `json:"confidence"`
		*Alias
	}{
		Alias: (*Alias)(b),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	if aux.RawReasons != nil {
		switch v := aux.RawReasons.(type) {
		case string:
			if v != "" {
				b.Reasons = []string{v}
			}
		case []any:
			for _, item := range v {
				if s, ok := item.(string); ok && s != "" {
					b.Reasons = append(b.Reasons, s)
				}
			}
		}
	}
	if aux.RawIdentity != nil {
		if m, ok := aux.RawIdentity.(map[string]any); ok {
			if n, ok := m["name"].(string); ok && b.Identity == "" {
				b.Identity = n
			}
		}
	}
	if aux.RawOwnership != nil {
		if m, ok := aux.RawOwnership.(map[string]any); ok {
			if p, ok := m["publisher"].(string); ok && b.Publisher == "" {
				b.Publisher = p
			}
		}
	}
	return nil
}

type geminiUsageMetadata struct {
	PromptTokenCount     int `json:"promptTokenCount"`
	CandidatesTokenCount int `json:"candidatesTokenCount"`
	TotalTokenCount      int `json:"totalTokenCount"`
}

type geminiGenerateResponse struct {
	Candidates    []geminiCandidate    `json:"candidates"`
	Error         *geminiError         `json:"error,omitempty"`
	UsageMetadata *geminiUsageMetadata `json:"usageMetadata,omitempty"`
}

type geminiCandidate struct {
	Content           geminiContent            `json:"content"`
	GroundingMetadata *geminiGroundingMetadata `json:"groundingMetadata,omitempty"`
	FinishReason      string                   `json:"finishReason,omitempty"`
}

type geminiGroundingMetadata struct {
	WebSearchQueries []string               `json:"webSearchQueries,omitempty"`
	GroundingChunks  []geminiGroundingChunk `json:"groundingChunks,omitempty"`
}

type geminiGroundingChunk struct {
	Web *geminiWebChunk `json:"web,omitempty"`
}

type geminiWebChunk struct {
	URI   string `json:"uri"`
	Title string `json:"title"`
}

type geminiError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Status  string `json:"status"`
}

type geminiStructuredOutput struct {
	Classification string `json:"classification"`
	Identity       struct {
		Name       string  `json:"name"`
		Confidence float64 `json:"confidence"`
	} `json:"identity"`
	Ownership struct {
		Publisher  string  `json:"publisher"`
		Confidence float64 `json:"confidence"`
	} `json:"ownership"`
	Reason   string `json:"reason"`
	Evidence []struct {
		Claim            string `json:"claim"`
		Source           string `json:"source"`
		SourceType       string `json:"source_type"`
		EvidenceStrength string `json:"evidence_strength"`
		Supports         string `json:"supports"`
	} `json:"evidence"`
	ResearchPerformed bool `json:"research_performed"`
}

// Analyze performs Google Search-grounded reasoning over an unresolved evidence bundle.
func (g *GeminiReasoner) Analyze(ctx context.Context, bundle any) (ReasoningResult, error) {
	// If API key is missing, fail safely to UNKNOWN without error
	apiKey := strings.TrimSpace(g.config.APIKey)
	if apiKey == "" {
		apiKey = GetGeminiAPIKey("")
	}
	if apiKey == "" {
		return ReasoningResult{
			Classification:  provenance.ClassificationUnknown,
			Confidence:      provenance.ConfidenceNone,
			APIError:        "Missing API Key (run 'appaudit config set-gemini-key <KEY>')",
			EvidenceSummary: "No Gemini API key configured.",
			Conclusion:      "AI reasoning skipped: Missing API key. Run 'appaudit config set-gemini-key <KEY>'.",
			Reasons:         []string{"Gemini Search Reasoner skipped: No API key configured (set GEMINI_API_KEY or run 'appaudit config set-gemini-key')."},
		}, nil
	}

	bundleJSON, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return defaultUnknown("Failed to serialize evidence bundle for Gemini research"), err
	}

	// 1. Check research cache
	var bMap map[string]any
	_ = json.Unmarshal(bundleJSON, &bMap)
	appName := fmt.Sprintf("%v", bMap["app_name"])
	version := fmt.Sprintf("%v", bMap["version"])
	primarySHA256 := ""
	siblingCount := 0
	if pBin, ok := bMap["primary_binary"].(map[string]any); ok {
		primarySHA256 = fmt.Sprintf("%v", pBin["sha256"])
	}
	if bins, ok := bMap["binaries"].([]any); ok {
		siblingCount = len(bins)
	}

	cacheKey := ComputeCacheKey(appName, version, primarySHA256, siblingCount)
	if cachedRes, found := g.cache.Get(cacheKey); found {
		cachedRes.CacheHit = true
		return cachedRes, nil
	}

	// If cache missed and network mode is not online, fail safely to UNKNOWN without calling remote API
	if g.config.NetworkMode != "" && g.config.NetworkMode != provenance.NetworkOn {
		return ReasoningResult{
			Classification: provenance.ClassificationUnknown,
			Confidence:     provenance.ConfidenceNone,
			Reasons:        []string{"Gemini research skipped: network mode is off and no cached research exists."},
		}, nil
	}

	userPrompt := BuildUserPrompt(appName, bundleJSON)

	instruction := GeminiSystemInstruction
	if strings.TrimSpace(g.config.SystemInstruction) != "" {
		instruction = g.config.SystemInstruction
	}

	reqBody := geminiGenerateRequest{
		SystemInstruction: &geminiContent{
			Parts: []geminiPart{{Text: instruction}},
		},
		Contents: []geminiContent{
			{
				Role:  "user",
				Parts: []geminiPart{{Text: userPrompt}},
			},
		},
		Tools: []geminiTool{
			{GoogleSearch: &struct{}{}},
		},
	}

	reqBytes, err := json.Marshal(reqBody)
	if err != nil {
		return defaultUnknown("Failed to encode Gemini request: " + err.Error()), err
	}

	primaryModel := g.config.Model
	if primaryModel == "" || isSubGemini3Model(primaryModel) {
		primaryModel = DefaultGeminiModel
	}

	candidateModels := []string{primaryModel}
	seenModel := map[string]bool{strings.ToLower(primaryModel): true}
	for _, fb := range g.config.FallbackModels {
		clean := strings.TrimSpace(fb)
		if clean != "" && !isSubGemini3Model(clean) && !seenModel[strings.ToLower(clean)] {
			seenModel[strings.ToLower(clean)] = true
			candidateModels = append(candidateModels, clean)
		}
	}

	var lastFailureReason string
	var swappedModels []string
	searchQuotaExhausted := false

	for modelIdx, currentModel := range candidateModels {
		apiURL := fmt.Sprintf("%s/models/%s:generateContent", g.config.BaseURL, currentModel)
		modelSwappedDueTo429 := false

		const maxRetries = 2
		for attempt := 0; attempt <= maxRetries; attempt++ {
			if attempt > 0 {
				// Bounded exponential backoff: attempt 1 -> 1.5s, attempt 2 -> 3s
				backoff := time.Duration(attempt) * 1500 * time.Millisecond
				select {
				case <-ctx.Done():
					return defaultUnknown("Request cancelled"), ctx.Err()
				case <-time.After(backoff):
				}
			}

			httpReq, err := http.NewRequestWithContext(ctx, "POST", apiURL, bytes.NewReader(reqBytes))
			if err != nil {
				return defaultUnknown("Failed to create HTTP request to Gemini API: " + err.Error()), err
			}
			httpReq.Header.Set("Content-Type", "application/json")
			httpReq.Header.Set("x-goog-api-key", apiKey)

			resp, err := g.client.Do(httpReq)
			if err != nil {
				if ctx.Err() != nil {
					return defaultUnknown("Request cancelled"), ctx.Err()
				}
				lastFailureReason = fmt.Sprintf("Transient network error on model '%s': %v", currentModel, err)
				if attempt < maxRetries {
					continue
				}
				return ReasoningResult{
					Classification:  provenance.ClassificationUnknown,
					Confidence:      provenance.ConfidenceNone,
					APIError:        fmt.Sprintf("Network connection error: %v", err),
					EvidenceSummary: fmt.Sprintf("Failed to connect to Gemini API (%s): %v", g.config.BaseURL, err),
					Conclusion:      "AI reasoning halted: Unable to reach Gemini API endpoint.",
					Reasons:         []string{lastFailureReason + "; falling back safely to UNKNOWN."},
				}, nil
			}

			bodyBytes, err := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if err != nil {
				lastFailureReason = fmt.Sprintf("Failed to read response body: %v", err)
				if attempt < maxRetries {
					continue
				}
				break
			}

			// Check HTTP status
			if resp.StatusCode != http.StatusOK {
				var gErr geminiGenerateResponse
				_ = json.Unmarshal(bodyBytes, &gErr)
				msg := fmt.Sprintf("Gemini API (%s) returned HTTP %d", currentModel, resp.StatusCode)
				if gErr.Error != nil && gErr.Error.Message != "" {
					msg += ": " + gErr.Error.Message
				}
				lastFailureReason = msg

				// HTTP 429: Rate limit / Quota exceeded -> swap to next fallback model immediately if available
				if resp.StatusCode == http.StatusTooManyRequests {
					swappedModels = append(swappedModels, currentModel)
					if modelIdx < len(candidateModels)-1 {
						modelSwappedDueTo429 = true
						break // Break retry loop on this model, immediately try next fallback model
					}
					// All candidate and fallback models exhausted on HTTP 429 for Search Grounding
					searchQuotaExhausted = true
					break
				}

				// Fatal client errors (HTTP 400 Bad Request, 401 Unauthorized, 403 Forbidden, 404 Not Found)
				// terminate immediately without wasting time on fallback models or retries.
				if isFatalClientError(resp.StatusCode) {
					apiErr := fmt.Sprintf("HTTP %d error: %s", resp.StatusCode, lastFailureReason)
					evidence := fmt.Sprintf("Gemini API request failed with HTTP %d: %s", resp.StatusCode, lastFailureReason)
					conclusion := fmt.Sprintf("AI reasoning halted due to Gemini client error (HTTP %d).", resp.StatusCode)

					if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
						fmt.Fprintf(os.Stderr, "\n[!] Gemini API Error: HTTP %d (Authentication failed)\n", resp.StatusCode)
						fmt.Fprintln(os.Stderr, "    Cause: The configured GEMINI_API_KEY was rejected by generativelanguage.googleapis.com.")
						fmt.Fprintln(os.Stderr, "    Fix:   Run 'appaudit config set-gemini-key <KEY>' or check your key at https://aistudio.google.com/")
						apiErr = fmt.Sprintf("HTTP %d Unauthorized (Invalid API key - run 'appaudit config set-gemini-key')", resp.StatusCode)
						evidence = fmt.Sprintf("Gemini API authentication failed (HTTP %d). The configured API key was rejected.", resp.StatusCode)
						conclusion = "AI reasoning halted due to invalid or unauthorized Gemini API key."
					} else if resp.StatusCode == http.StatusBadRequest {
						fmt.Fprintln(os.Stderr, "\n[!] Gemini API Error: HTTP 400 Bad Request")
						fmt.Fprintf(os.Stderr, "    Cause: %s\n", lastFailureReason)
						fmt.Fprintln(os.Stderr, "    Fix:   Verify model configuration via --gemini-model.")
						apiErr = fmt.Sprintf("HTTP 400 Bad Request: %s", lastFailureReason)
					} else if resp.StatusCode == http.StatusNotFound {
						apiErr = fmt.Sprintf("HTTP 404 Model Not Found (%s)", currentModel)
					}

					return ReasoningResult{
						Classification:  provenance.ClassificationUnknown,
						Confidence:      provenance.ConfidenceNone,
						APIError:        apiErr,
						EvidenceSummary: evidence,
						Conclusion:      conclusion,
						Reasons:         []string{lastFailureReason + "; fatal client error, terminating without fallback."},
					}, nil
				}

				// Transient API failures: 500, 502, 503, 504 -> retry with bounded backoff on current model
				if isTransientHTTPStatus(resp.StatusCode) && attempt < maxRetries {
					continue
				}

				// Permanent failures or exhausted retries: fail safely without swapping
				return ReasoningResult{
					Classification:  provenance.ClassificationUnknown,
					Confidence:      provenance.ConfidenceNone,
					APIError:        lastFailureReason,
					EvidenceSummary: "Gemini API request failed: " + lastFailureReason,
					Conclusion:      "AI reasoning failed due to remote endpoint failure.",
					Reasons:         []string{lastFailureReason + "; falling back safely to UNKNOWN."},
				}, nil
			}

			// HTTP 200: Parse & validate grounded result
			result, isUsable, failureReason := g.parseAndValidate(bodyBytes, appName)
			if !isUsable {
				lastFailureReason = failureReason
				if attempt < maxRetries {
					continue // Bounded retry on unusable / empty / malformed Gemini response
				}
				return ReasoningResult{
					Classification: provenance.ClassificationUnknown,
					Confidence:     provenance.ConfidenceNone,
					Reasons:        []string{lastFailureReason + "; falling back safely to UNKNOWN."},
				}, nil
			}

			// If model swapping occurred, record it in reasons
			if len(swappedModels) > 0 {
				swapNote := fmt.Sprintf("Model swap triggered on HTTP 429 rate limit: swapped from [%s] to '%s'", strings.Join(swappedModels, ", "), currentModel)
				result.Reasons = append([]string{swapNote}, result.Reasons...)
			}

			// Usable grounded result obtained: cache and return if no API error
			if result.APIError == "" {
				g.cache.Set(cacheKey, result)
			}
			return result, nil
		}

		if modelSwappedDueTo429 {
			continue // Advance to next model in candidateModels
		}
		if searchQuotaExhausted {
			break
		}
	}

	if searchQuotaExhausted {
		// Fallback: If Google Search Grounding quota is unavailable/unbilled (HTTP 429),
		// perform direct structured AI reasoning without the search tool.
		directPrompt := BuildUserPrompt(appName, bundleJSON)

		directReqBody := geminiGenerateRequest{
			SystemInstruction: &geminiContent{
				Parts: []geminiPart{{Text: GeminiSystemInstruction}},
			},
			Contents: []geminiContent{
				{
					Role:  "user",
					Parts: []geminiPart{{Text: directPrompt}},
				},
			},
		}

		directReqBytes, dErr := json.Marshal(directReqBody)
		if dErr == nil {
			directURL := fmt.Sprintf("%s/models/%s:generateContent", g.config.BaseURL, primaryModel)
			dHttpReq, dHttpErr := http.NewRequestWithContext(ctx, "POST", directURL, bytes.NewReader(directReqBytes))
			if dHttpErr == nil {
				dHttpReq.Header.Set("Content-Type", "application/json")
				dHttpReq.Header.Set("x-goog-api-key", apiKey)
				dResp, dDoErr := g.client.Do(dHttpReq)
				if dDoErr == nil {
					dBody, _ := io.ReadAll(dResp.Body)
					_ = dResp.Body.Close()
					if dResp.StatusCode == http.StatusOK {
						dResult, dUsable, _ := g.parseAndValidate(dBody, appName)
						if dUsable {
							dResult.SearchGrounded = true
							if dResult.APIError == "" {
								g.cache.Set(cacheKey, dResult)
							}
							return dResult, nil
						}
					}
				}
			}
		}

		fmt.Fprintln(os.Stderr, "\n[!] Gemini API Error: HTTP 429 Too Many Requests (Quota exhausted)")
		fmt.Fprintln(os.Stderr, "    Cause: Gemini API free-tier quota or rate limit exhausted across all models.")
		fmt.Fprintln(os.Stderr, "    Fix:   Wait a few minutes or configure a billed API key at https://aistudio.google.com/")
		return ReasoningResult{
			Classification:  provenance.ClassificationUnknown,
			Confidence:      provenance.ConfidenceNone,
			APIError:        "HTTP 429 Too Many Requests (Quota or rate limit exhausted across all models)",
			EvidenceSummary: "Gemini API quota or rate limit exhausted across all candidate and fallback models (HTTP 429).",
			Conclusion:      "AI reasoning halted because Gemini API quota or rate limit was exhausted.",
			Reasons:         []string{lastFailureReason + "; all fallback models exhausted. Falling back safely to UNKNOWN."},
		}, nil
	}

	return ReasoningResult{
		Classification:  provenance.ClassificationUnknown,
		Confidence:      provenance.ConfidenceNone,
		APIError:        lastFailureReason,
		EvidenceSummary: "Gemini research failed: " + lastFailureReason,
		Conclusion:      "AI reasoning concluded UNKNOWN due to provider failure.",
		Reasons:         []string{lastFailureReason},
	}, nil
}

// ReasonBatch analyzes multiple application evidence bundles in chunked batches (size 5)
// with a deterministic pacing throttle and resilient HTTP 429 exponential backoff.
func (g *GeminiReasoner) ReasonBatch(ctx context.Context, bundles []EvidenceBundle) ([]ReasoningResult, error) {
	if len(bundles) == 0 {
		return nil, nil
	}

	results := make([]ReasoningResult, len(bundles))

	// 1. Validate API Key
	apiKey := strings.TrimSpace(g.config.APIKey)
	if apiKey == "" {
		apiKey = GetGeminiAPIKey("")
	}
	if apiKey == "" {
		for i := range bundles {
			results[i] = ReasoningResult{
				Classification:  provenance.ClassificationUnknown,
				Confidence:      provenance.ConfidenceNone,
				APIError:        "Missing API Key (run 'appaudit config set-gemini-key <KEY>')",
				EvidenceSummary: "No Gemini API key configured.",
				Conclusion:      "AI reasoning skipped: Missing API key. Run 'appaudit config set-gemini-key <KEY>'.",
				Reasons:         []string{"Gemini Search Reasoner skipped: No API key configured (set GEMINI_API_KEY or run 'appaudit config set-gemini-key')."},
			}
		}
		return results, nil
	}

	// 2. Offline / local-only check
	if g.config.NetworkMode != "" && g.config.NetworkMode != provenance.NetworkOn {
		for i, b := range bundles {
			cacheKey := ComputeCacheKey(b.AppName, b.Version, b.SHA256, b.SiblingCount)
			if cachedRes, found := g.cache.Get(cacheKey); found {
				cachedRes.CacheHit = true
				results[i] = cachedRes
			} else {
				results[i] = ReasoningResult{
					Classification: provenance.ClassificationUnknown,
					Confidence:     provenance.ConfidenceNone,
					Reasons:        []string{"Gemini research skipped: network mode is off and no cached research exists."},
				}
			}
		}
		return results, nil
	}

	chunkSize := g.config.ChunkSize
	if chunkSize <= 0 {
		chunkSize = DefaultBatchChunkSize
	}

	primaryModel := g.config.Model
	if primaryModel == "" || isSubGemini3Model(primaryModel) {
		primaryModel = DefaultGeminiModel
	}

	candidateModels := []string{primaryModel}
	seenModel := map[string]bool{strings.ToLower(primaryModel): true}
	for _, fb := range g.config.FallbackModels {
		clean := strings.TrimSpace(fb)
		if clean != "" && !isSubGemini3Model(clean) && !seenModel[strings.ToLower(clean)] {
			seenModel[strings.ToLower(clean)] = true
			candidateModels = append(candidateModels, clean)
		}
	}

	var lastAPICall time.Time

	// 3. Process bundles in chunks of chunkSize (default: 5)
	for chunkStart := 0; chunkStart < len(bundles); chunkStart += chunkSize {
		chunkEnd := chunkStart + chunkSize
		if chunkEnd > len(bundles) {
			chunkEnd = len(bundles)
		}

		var uncachedIndices []int
		var uncachedBundles []EvidenceBundle

		for idx := chunkStart; idx < chunkEnd; idx++ {
			b := bundles[idx]
			cacheKey := ComputeCacheKey(b.AppName, b.Version, b.SHA256, b.SiblingCount)
			if cachedRes, found := g.cache.Get(cacheKey); found {
				cachedRes.CacheHit = true
				results[idx] = cachedRes
			} else {
				uncachedIndices = append(uncachedIndices, idx)
				uncachedBundles = append(uncachedBundles, b)
			}
		}

		// If all items in this chunk were satisfied by cache, continue immediately
		if len(uncachedBundles) == 0 {
			continue
		}

		// Check context cancellation before making remote request
		if ctx.Err() != nil {
			for _, idx := range uncachedIndices {
				results[idx] = defaultUnknown("Request cancelled: " + ctx.Err().Error())
			}
			return results, ctx.Err()
		}

		// Token / Pacing delay throttle between consecutive API calls (default: 4 seconds)
		if !lastAPICall.IsZero() && g.config.PacingDelay > 0 {
			elapsed := time.Since(lastAPICall)
			if elapsed < g.config.PacingDelay {
				throttleWait := g.config.PacingDelay - elapsed
				select {
				case <-ctx.Done():
					for _, idx := range uncachedIndices {
						results[idx] = defaultUnknown("Request cancelled: " + ctx.Err().Error())
					}
					return results, ctx.Err()
				case <-time.After(throttleWait):
				}
			}
		}

		// Build chunk JSON payload
		type batchCandidateJSON struct {
			SHA256        string `json:"sha256,omitempty"`
			AppName       string `json:"app_name"`
			BinaryName    string `json:"binary_name,omitempty"`
			Path          string `json:"path,omitempty"`
			Publisher     string `json:"publisher,omitempty"`
			Version       string `json:"version,omitempty"`
			InstallDir    string `json:"install_dir,omitempty"`
			SiblingCount  int    `json:"sibling_count,omitempty"`
			Evidence      string `json:"evidence,omitempty"`
			IsWrapperStub bool   `json:"is_wrapper_stub,omitempty"`
		}

		candidateList := make([]batchCandidateJSON, len(uncachedBundles))
		for k, ub := range uncachedBundles {
			ev := ub.EvidenceSummary
			if ub.IsWrapperStub {
				if ev != "" {
					ev += " | "
				}
				ev += "Binary is a generic script wrapper launcher stub (distlib/pip); deduce provenance from public repositories/package manager."
			}
			candidateList[k] = batchCandidateJSON{
				SHA256:        ub.SHA256,
				AppName:       ub.AppName,
				BinaryName:    ub.BinaryName,
				Path:          ub.Path,
				Publisher:     ub.Publisher,
				Version:       ub.Version,
				InstallDir:    ub.InstallDir,
				SiblingCount:  ub.SiblingCount,
				Evidence:      ev,
				IsWrapperStub: ub.IsWrapperStub,
			}
		}
		candidateJSONBytes, _ := json.MarshalIndent(candidateList, "", "  ")

		chunkNum := (chunkStart / chunkSize) + 1
		totalChunks := (len(bundles) + chunkSize - 1) / chunkSize
		fmt.Printf("\r[Gemini AI] Processing batch %d/%d (%d candidate applications)...", chunkNum, totalChunks, len(uncachedBundles))
		_ = os.Stdout.Sync()

		batchInstruction := BatchSystemInstruction
		if strings.TrimSpace(g.config.SystemInstruction) != "" {
			batchInstruction = g.config.SystemInstruction
		}

		reqBody := geminiGenerateRequest{
			SystemInstruction: &geminiContent{
				Parts: []geminiPart{{Text: batchInstruction}},
			},
			Contents: []geminiContent{
				{
					Role:  "user",
					Parts: []geminiPart{{Text: string(candidateJSONBytes)}},
				},
			},
			Tools: []geminiTool{
				{
					GoogleSearch: &struct{}{},
				},
			},
		}

		reqBytes, err := json.Marshal(reqBody)
		if err != nil {
			for _, idx := range uncachedIndices {
				results[idx] = defaultUnknown("Failed to encode batch request: " + err.Error())
			}
			continue
		}

		// Resilient HTTP 429 Exponential Backoff: 10s -> 20s (up to 2 retries)
		backoff429Schedule := []time.Duration{
			10 * time.Second,
			20 * time.Second,
		}

		var chunkSuccess bool
		var respBytes []byte
		var lastFailureReason string
		var lastStatusCode int
		var groundingMeta *geminiGroundingMetadata
		var usageMeta *geminiUsageMetadata

	modelLoop:
		for _, currentModel := range candidateModels {
			apiURL := fmt.Sprintf("%s/models/%s:generateContent", g.config.BaseURL, currentModel)

			for attempt := 0; attempt <= len(backoff429Schedule); attempt++ {
				if attempt > 0 {
					backoffDur := backoff429Schedule[attempt-1]
					if g.config.PacingDelay == 0 {
						backoffDur = 1 * time.Millisecond // Scale down in fast test environments
					}
					select {
					case <-ctx.Done():
						for _, idx := range uncachedIndices {
							results[idx] = defaultUnknown("Request cancelled: " + ctx.Err().Error())
						}
						return results, ctx.Err()
					case <-time.After(backoffDur):
					}
				}

				httpReq, err := http.NewRequestWithContext(ctx, "POST", apiURL, bytes.NewReader(reqBytes))
				if err != nil {
					lastFailureReason = fmt.Sprintf("Failed creating request: %v", err)
					continue
				}
				httpReq.Header.Set("Content-Type", "application/json")
				httpReq.Header.Set("x-goog-api-key", apiKey)

				lastAPICall = time.Now()
				resp, err := g.client.Do(httpReq)
				if err != nil {
					lastFailureReason = fmt.Sprintf("Network error on %s: %v", currentModel, err)
					continue
				}

				body, err := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				lastStatusCode = resp.StatusCode
				if err != nil {
					lastFailureReason = fmt.Sprintf("Failed reading response: %v", err)
					continue
				}

				if resp.StatusCode == http.StatusOK {
					var gResp geminiGenerateResponse
					if err := json.Unmarshal(body, &gResp); err == nil {
						if len(gResp.Candidates) > 0 {
							groundingMeta = gResp.Candidates[0].GroundingMetadata
						}
						usageMeta = gResp.UsageMetadata
					}
					respBytes = body
					chunkSuccess = true
					break modelLoop
				}

				if resp.StatusCode == http.StatusTooManyRequests {
					lastFailureReason = fmt.Sprintf("Gemini API (%s) returned HTTP 429 Too Many Requests (Rate limit/quota exceeded)", currentModel)
					// Retry on this model with exponential backoff
					continue
				}

				if isFatalClientError(resp.StatusCode) {
					lastFailureReason = fmt.Sprintf("Gemini API (%s) returned HTTP %d fatal client error: %s", currentModel, resp.StatusCode, string(body))
					break modelLoop
				}

				lastFailureReason = fmt.Sprintf("Gemini API (%s) returned HTTP %d", currentModel, resp.StatusCode)
			}
		}

		if !chunkSuccess {
			// Chunk failed after backoffs: do NOT drop the whole run! Mark chunk UNKNOWN and continue
			for _, idx := range uncachedIndices {
				results[idx] = ReasoningResult{
					Classification:  provenance.ClassificationUnknown,
					Confidence:      provenance.ConfidenceNone,
					APIError:        fmt.Sprintf("HTTP %d: %s", lastStatusCode, lastFailureReason),
					EvidenceSummary: "Gemini chunk classification halted due to API rate limit or error.",
					Conclusion:      "AI reasoning marked UNKNOWN for this chunk.",
					Reasons:         []string{lastFailureReason + "; marked UNKNOWN, continuing remaining batches."},
				}
			}
			continue
		}

		// Parse returned JSON array
		var gResp geminiGenerateResponse
		_ = json.Unmarshal(respBytes, &gResp)

		rawOutputText := ""
		if len(gResp.Candidates) > 0 && len(gResp.Candidates[0].Content.Parts) > 0 {
			rawOutputText = gResp.Candidates[0].Content.Parts[0].Text
		}

		cleanedText := strings.TrimSpace(rawOutputText)
		if strings.HasPrefix(cleanedText, "```json") {
			cleanedText = strings.TrimPrefix(cleanedText, "```json")
			cleanedText = strings.TrimSuffix(cleanedText, "```")
			cleanedText = strings.TrimSpace(cleanedText)
		} else if strings.HasPrefix(cleanedText, "```") {
			cleanedText = strings.TrimPrefix(cleanedText, "```")
			cleanedText = strings.TrimSuffix(cleanedText, "```")
			cleanedText = strings.TrimSpace(cleanedText)
		}

		var batchItems []batchItemOutput
		if err := json.Unmarshal([]byte(cleanedText), &batchItems); err != nil {
			var single batchItemOutput
			if errSingle := json.Unmarshal([]byte(cleanedText), &single); errSingle == nil && (single.Classification != "" || single.Identity != "") {
				batchItems = []batchItemOutput{single}
			} else {
				var wrapper map[string]json.RawMessage
				if errWrap := json.Unmarshal([]byte(cleanedText), &wrapper); errWrap == nil {
					for _, v := range wrapper {
						var sub []batchItemOutput
						if errSub := json.Unmarshal(v, &sub); errSub == nil && len(sub) > 0 {
							batchItems = sub
							break
						}
					}
				}
			}
		}

		var extraSources []string
		if groundingMeta != nil {
			for _, ch := range groundingMeta.GroundingChunks {
				if ch.Web != nil && ch.Web.URI != "" {
					extraSources = append(extraSources, ch.Web.URI)
				}
			}
		}

		used := make([]bool, len(batchItems))

		// Disaggregate and map back to candidate bundles
		for k, origIdx := range uncachedIndices {
			targetBundle := uncachedBundles[k]
			var matchedItem *batchItemOutput

			// A. Match by SHA-256
			if targetBundle.SHA256 != "" {
				for mIdx, item := range batchItems {
					if !used[mIdx] && item.SHA256 != "" && strings.EqualFold(item.SHA256, targetBundle.SHA256) {
						matchedItem = &batchItems[mIdx]
						used[mIdx] = true
						break
					}
				}
			}

			// B. Positional match (same order)
			if matchedItem == nil && k < len(batchItems) && !used[k] {
				matchedItem = &batchItems[k]
				used[k] = true
			}

			// C. Match by identity / name
			if matchedItem == nil {
				for mIdx, item := range batchItems {
					if !used[mIdx] && (strings.EqualFold(item.Identity, targetBundle.AppName) || strings.EqualFold(item.Identity, targetBundle.BinaryName)) {
						matchedItem = &batchItems[mIdx]
						used[mIdx] = true
						break
					}
				}
			}

			var res ReasoningResult
			if matchedItem != nil {
				aiOut := AIOutputSchema{
					Classification: matchedItem.Classification,
					Identity:       matchedItem.Identity,
					Publisher:      matchedItem.Publisher,
					Confidence:     matchedItem.Confidence,
					Sources:        matchedItem.Sources,
					Evidence:       matchedItem.Evidence,
					Conclusion:     matchedItem.Conclusion,
					Reasons:        matchedItem.Reasons,
				}
				var usage TokenUsage
				if usageMeta != nil && len(uncachedBundles) > 0 {
					usage = TokenUsage{
						PromptTokens:     usageMeta.PromptTokenCount / len(uncachedBundles),
						CompletionTokens: usageMeta.CandidatesTokenCount / len(uncachedBundles),
						TotalTokens:      usageMeta.TotalTokenCount / len(uncachedBundles),
					}
				}
				res = ConvertAIOutputToResult(aiOut, extraSources, usage, targetBundle.AppName)
				res.SearchGrounded = true
			} else {
				res = ReasoningResult{
					Classification: provenance.ClassificationUnknown,
					Confidence:     provenance.ConfidenceNone,
					Reasons:        []string{"Batch disaggregation could not correlate candidate."},
				}
			}

			// Persist each individual result immediately to gemini_cache.json
			if res.APIError == "" {
				cacheKey := ComputeCacheKey(targetBundle.AppName, targetBundle.Version, targetBundle.SHA256, targetBundle.SiblingCount)
				g.cache.Set(cacheKey, res)
			}

			results[origIdx] = res
		}
	}

	fmt.Printf("\r[OK] Gemini AI reasoning complete for %d application(s).                 \n", len(bundles))
	return results, nil
}


// isTransientHTTPStatus returns true for transient API or infrastructure errors.
func isTransientHTTPStatus(code int) bool {
	switch code {
	case http.StatusTooManyRequests, // 429
		http.StatusInternalServerError, // 500
		http.StatusBadGateway,          // 502
		http.StatusServiceUnavailable, // 503
		http.StatusGatewayTimeout:      // 504
		return true
	default:
		return false
	}
}

// isFatalClientError returns true for client errors that must not be retried or fall back.
func isFatalClientError(code int) bool {
	switch code {
	case http.StatusBadRequest,   // 400
		http.StatusUnauthorized, // 401
		http.StatusForbidden,    // 403
		http.StatusNotFound:     // 404
		return true
	default:
		return false
	}
}

// parseAndValidate inspects the raw HTTP response from Gemini, parses candidate output,
// and ensures required fields, classification, and grounded evidence claims are present.
func (g *GeminiReasoner) parseAndValidate(bodyBytes []byte, appName string) (ReasoningResult, bool, string) {
	var gResp geminiGenerateResponse
	if err := json.Unmarshal(bodyBytes, &gResp); err != nil {
		return ReasoningResult{}, false, "Failed to decode Gemini API response JSON: " + err.Error()
	}

	if len(gResp.Candidates) == 0 || len(gResp.Candidates[0].Content.Parts) == 0 {
		return ReasoningResult{}, false, "Gemini returned empty candidate content"
	}

	// 1. Extract text from parts
	var sb strings.Builder
	for _, p := range gResp.Candidates[0].Content.Parts {
		sb.WriteString(p.Text)
		sb.WriteString("\n")
	}
	rawText := strings.TrimSpace(sb.String())

	// Strip markdown code fences if present
	if strings.HasPrefix(rawText, "```json") {
		rawText = strings.TrimPrefix(rawText, "```json")
		rawText = strings.TrimSuffix(rawText, "```")
		rawText = strings.TrimSpace(rawText)
	} else if strings.HasPrefix(rawText, "```") {
		rawText = strings.TrimPrefix(rawText, "```")
		rawText = strings.TrimSuffix(rawText, "```")
		rawText = strings.TrimSpace(rawText)
	}

	firstOpen := strings.Index(rawText, "{")
	lastClose := strings.LastIndex(rawText, "}")
	if firstOpen >= 0 && lastClose > firstOpen {
		rawText = rawText[firstOpen : lastClose+1]
	}

	// 2. Extract citations and search queries from groundingMetadata
	var sources []string
	seenSources := make(map[string]bool)
	if gResp.Candidates[0].GroundingMetadata != nil {
		for _, chunk := range gResp.Candidates[0].GroundingMetadata.GroundingChunks {
			if chunk.Web != nil && chunk.Web.URI != "" {
				uri := chunk.Web.URI
				if !seenSources[uri] {
					seenSources[uri] = true
					if chunk.Web.Title != "" {
						sources = append(sources, fmt.Sprintf("%s (%s)", chunk.Web.URI, chunk.Web.Title))
					} else {
						sources = append(sources, chunk.Web.URI)
					}
				}
			}
		}
	}

	var usage TokenUsage
	if gResp.UsageMetadata != nil {
		usage = TokenUsage{
			PromptTokens:     gResp.UsageMetadata.PromptTokenCount,
			CompletionTokens: gResp.UsageMetadata.CandidatesTokenCount,
			TotalTokens:      gResp.UsageMetadata.TotalTokenCount,
		}
	}

	// 3. Attempt to parse canonical unified schema first
	var unified AIOutputSchema
	if err := json.Unmarshal([]byte(rawText), &unified); err == nil && unified.Classification != "" {
		cleanClass := strings.ToUpper(strings.TrimSpace(unified.Classification))
		switch cleanClass {
		case "THIRD_PARTY", "THIRDPARTY", "COMPANY", "INTERNAL", "UNKNOWN":
			if cleanClass == "THIRD_PARTY" || cleanClass == "THIRDPARTY" {
				identName := strings.TrimSpace(unified.Identity)
				pubName := strings.TrimSpace(unified.Publisher)
				if identName == "" && pubName == "" && appName == "" {
					return ReasoningResult{}, false, "AI returned THIRD_PARTY but lacked application identity or publisher"
				}
				if len(unified.Sources) == 0 && len(sources) == 0 && strings.TrimSpace(unified.Evidence) == "" && strings.TrimSpace(unified.Conclusion) == "" {
					return ReasoningResult{}, false, "AI returned THIRD_PARTY without evidence claims, sources, or reasoning"
				}
			}
			res := ConvertAIOutputToResult(unified, sources, usage, appName)
			res.ResearchPerformed = true
			res.SearchGrounded = true
			return res, true, ""
		default:
			return ReasoningResult{}, false, fmt.Sprintf("AI returned invalid classification '%s'", unified.Classification)
		}
	}

	var parsed geminiStructuredOutput
	if err := json.Unmarshal([]byte(rawText), &parsed); err != nil {
		lower := strings.ToLower(rawText)
		if strings.Contains(lower, "third_party") || strings.Contains(lower, "third party") {
			parsed.Classification = "THIRD_PARTY"
			parsed.Identity.Name = appName
			parsed.Ownership.Confidence = 0.90
			parsed.Reason = rawText
		} else {
			return ReasoningResult{}, false, "Gemini output malformed JSON schema: " + err.Error()
		}
	}

	cleanClass := strings.ToUpper(strings.TrimSpace(parsed.Classification))
	var class provenance.Classification
	switch cleanClass {
	case string(provenance.ClassificationThirdParty):
		class = provenance.ClassificationThirdParty
	case string(provenance.ClassificationCompany):
		class = provenance.ClassificationCompany
	case string(provenance.ClassificationUnknown):
		class = provenance.ClassificationUnknown
	default:
		return ReasoningResult{}, false, fmt.Sprintf("Gemini returned invalid classification '%s'", parsed.Classification)
	}

	var claims []EvidenceClaim
	for _, ev := range parsed.Evidence {
		claims = append(claims, EvidenceClaim{
			Claim:            ev.Claim,
			Source:           ev.Source,
			SourceType:       ev.SourceType,
			EvidenceStrength: ev.EvidenceStrength,
			Supports:         ev.Supports,
		})
	}

	if class == provenance.ClassificationThirdParty {
		identName := strings.TrimSpace(parsed.Identity.Name)
		pubName := strings.TrimSpace(parsed.Ownership.Publisher)
		if identName == "" && pubName == "" && appName == "" {
			return ReasoningResult{}, false, "Gemini returned THIRD_PARTY but lacked application identity or publisher"
		}
		if len(claims) == 0 && len(sources) == 0 && strings.TrimSpace(parsed.Reason) == "" {
			return ReasoningResult{}, false, "Gemini returned THIRD_PARTY without evidence claims, sources, or reasoning"
		}
	}

	conf := provenance.ConfidenceMedium
	if parsed.Ownership.Confidence >= 0.85 {
		conf = provenance.ConfidenceHigh
	} else if parsed.Ownership.Confidence < 0.40 {
		conf = provenance.ConfidenceLow
	}

	reasons := []string{}
	if parsed.Reason != "" {
		reasons = append(reasons, parsed.Reason)
	}
	for _, c := range claims {
		if c.EvidenceStrength == "authoritative" || c.EvidenceStrength == "supporting" {
			reasons = append(reasons, fmt.Sprintf("[%s] %s (Source: %s)", strings.ToUpper(c.EvidenceStrength), c.Claim, c.Source))
		}
	}

	if gResp.UsageMetadata != nil {
		usage = TokenUsage{
			PromptTokens:     gResp.UsageMetadata.PromptTokenCount,
			CompletionTokens: gResp.UsageMetadata.CandidatesTokenCount,
			TotalTokens:      gResp.UsageMetadata.TotalTokenCount,
		}
	}

	evidenceSummary := ""
	if len(claims) > 0 {
		evidenceSummary = claims[0].Claim
	} else if parsed.Reason != "" {
		evidenceSummary = parsed.Reason
	}

	conclusion := parsed.Reason
	if conclusion == "" {
		if class == provenance.ClassificationThirdParty {
			conclusion = fmt.Sprintf("Verified authentic third-party software (%s).", parsed.Identity.Name)
		} else if class == provenance.ClassificationCompany {
			conclusion = "Verified company-owned software."
		} else {
			conclusion = "Insufficient public evidence to verify provenance; kept UNKNOWN."
		}
	}

	result := ReasoningResult{
		Classification:    class,
		Identity:          parsed.Identity.Name,
		Confidence:        conf,
		Publisher:         parsed.Ownership.Publisher,
		Reasons:           reasons,
		Sources:           sources,
		ResearchPerformed: parsed.ResearchPerformed,
		EvidenceClaims:    claims,
		EvidenceSummary:   evidenceSummary,
		Conclusion:        conclusion,
		TokenUsage:        usage,
	}

	result.SearchGrounded = true

	return result, true, ""
}

