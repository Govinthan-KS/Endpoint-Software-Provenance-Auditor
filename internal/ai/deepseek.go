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

const (
	// DefaultDeepSeekModel defines the standard DeepSeek model identifier.
	// Alias for DeepSeek-V4.1-Flash.
	DefaultDeepSeekModel = "deepseek-flash"

	// DefaultDeepSeekBaseURL is the standard API base URL for DeepSeek.
	DefaultDeepSeekBaseURL = "https://api.deepseek.com"
)

// DeepSeekConfig holds the runtime options for DeepSeekReasoner.
type DeepSeekConfig struct {
	APIKey          string
	Model           string
	BaseURL         string
	Timeout         time.Duration
	HTTPClient      *http.Client
	Cache           *DeepSeekCache
	NetworkMode     provenance.NetworkMode
	EnableWebSearch bool
	SystemPrompt    string
}

// DeepSeekReasoner implements the Reasoner interface targeting DeepSeek-V4.1-Flash
// with native web search via the Responses API (/responses), automatic fallback to
// Chat Completions (/chat/completions), and strict credit-conservation safeguards.
type DeepSeekReasoner struct {
	config DeepSeekConfig
	client *http.Client
	cache  *DeepSeekCache
}

// NewDeepSeekReasoner creates a configured DeepSeekReasoner.
func NewDeepSeekReasoner(cfg DeepSeekConfig) *DeepSeekReasoner {
	if cfg.Model == "" {
		cfg.Model = DefaultDeepSeekModel
	}
	if cfg.BaseURL == "" {
		if envBase := os.Getenv("DEEPSEEK_BASE_URL"); envBase != "" {
			cfg.BaseURL = envBase
		} else {
			cfg.BaseURL = DefaultDeepSeekBaseURL
		}
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 120 * time.Second
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{
			Timeout: cfg.Timeout,
		}
	}
	cache := cfg.Cache
	if cache == nil {
		cache = NewDeepSeekCache()
	}

	return &DeepSeekReasoner{
		config: cfg,
		client: client,
		cache:  cache,
	}
}

// Name returns the provider identifier.
func (d *DeepSeekReasoner) Name() string {
	return "deepseek_flash (" + d.config.Model + ")"
}

// Request and response payloads for DeepSeek Responses API (/responses) with native web_search
type deepseekResponsesRequest struct {
	Model          string                  `json:"model"`
	Input          []deepseekChatMessage   `json:"input"`
	Tools          []deepseekTool          `json:"tools,omitempty"`
	ToolChoice     string                  `json:"tool_choice,omitempty"`
	ResponseFormat *deepseekResponseFormat `json:"response_format,omitempty"`
	Temperature    float64                 `json:"temperature"`
	MaxTokens      int                     `json:"max_tokens"`
}

type deepseekTool struct {
	Type string `json:"type"` // "web_search"
}

type deepseekResponsesResponse struct {
	ID         string                   `json:"id"`
	Status     string                   `json:"status"`
	Output     []deepseekResponseOutput `json:"output,omitempty"`
	OutputText string                   `json:"output_text,omitempty"`
	Error      *deepseekAPIError        `json:"error,omitempty"`
	Usage      *deepseekUsage           `json:"usage,omitempty"`
}

type deepseekResponseOutput struct {
	Type          string                 `json:"type"` // "web_search_call", "message"
	WebSearchCall *deepseekWebSearchCall `json:"web_search_call,omitempty"`
	Role          string                 `json:"role,omitempty"`
	Content       any                    `json:"content,omitempty"`
}

type deepseekWebSearchCall struct {
	Query string `json:"query"`
}

// Request and response payloads for DeepSeek Chat Completions API (/chat/completions)
type deepseekChatRequest struct {
	Model          string                  `json:"model"`
	Messages       []deepseekChatMessage   `json:"messages"`
	Thinking       *deepseekThinkingConfig `json:"thinking,omitempty"`
	ResponseFormat *deepseekResponseFormat `json:"response_format,omitempty"`
	Temperature    float64                 `json:"temperature"`
	MaxTokens      int                     `json:"max_tokens"`
}

type deepseekChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type deepseekThinkingConfig struct {
	Type string `json:"type"` // "disabled"
}

type deepseekResponseFormat struct {
	Type string `json:"type"` // "json_object"
}

type deepseekChatResponse struct {
	ID      string            `json:"id"`
	Choices []deepseekChoice  `json:"choices"`
	Error   *deepseekAPIError `json:"error,omitempty"`
	Usage   *deepseekUsage    `json:"usage,omitempty"`
}

type deepseekChoice struct {
	Index        int                 `json:"index"`
	Message      deepseekChatMessage `json:"message"`
	FinishReason string              `json:"finish_reason"`
}

type deepseekAPIError struct {
	Message string `json:"message"`
	Type    string `json:"type"`
	Code    any    `json:"code"`
}

type deepseekUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

type deepseekOutputSchema = AIOutputSchema

const deepseekSystemPrompt = UnifiedSystemPrompt

// Analyze performs credit-conserving DeepSeek reasoning over an unresolved evidence bundle.
func (d *DeepSeekReasoner) Analyze(ctx context.Context, bundle any) (ReasoningResult, error) {
	apiKey := strings.TrimSpace(d.config.APIKey)
	if apiKey == "" {
		apiKey = GetDeepSeekAPIKey("")
	}
	if apiKey == "" {
		return ReasoningResult{
			Classification:  provenance.ClassificationUnknown,
			Confidence:      provenance.ConfidenceNone,
			APIError:        "Missing API Key (run 'appaudit config set-deepseek-key <KEY>')",
			EvidenceSummary: "No DeepSeek API key configured.",
			Conclusion:      "AI reasoning skipped: Missing API key. Run 'appaudit config set-deepseek-key <KEY>'.",
			Reasons:         []string{"DeepSeek Reasoner skipped: No API key configured (set DEEPSEEK_API_KEY or run 'appaudit config set-deepseek-key')."},
		}, nil
	}

	bundleJSON, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return defaultDeepSeekUnknown("Failed to serialize evidence bundle"), err
	}

	// 1. Extract identity signals for deterministic cache key derivation
	var bMap map[string]any
	_ = json.Unmarshal(bundleJSON, &bMap)

	appName := ""
	if name, ok := bMap["app_name"].(string); ok {
		appName = name
	}
	version := ""
	if ver, ok := bMap["version"].(string); ok {
		version = ver
	}
	primarySHA256 := ""
	siblingCount := 0

	if pb, ok := bMap["primary_binary"].(map[string]any); ok {
		if sha, ok := pb["sha256"].(string); ok {
			primarySHA256 = sha
		}
		if appName == "" {
			if n, ok := pb["name"].(string); ok {
				appName = n
			}
		}
	}
	if bins, ok := bMap["binaries"].([]any); ok {
		siblingCount = len(bins)
	}

	cacheKey := ComputeDeepSeekKey(primarySHA256, appName, version, siblingCount)

	// Check cache (positive and inconclusive results are cached to guarantee 0 tokens consumed)
	if cachedRes, found := d.cache.Get(cacheKey); found {
		cachedRes.CacheHit = true
		return cachedRes, nil
	}

	// Guard against offline execution: do not hit the remote API if network mode is off
	if d.config.NetworkMode != "" && d.config.NetworkMode != provenance.NetworkOn {
		return ReasoningResult{
			Classification: provenance.ClassificationUnknown,
			Confidence:     provenance.ConfidenceNone,
			Reasons:        []string{"DeepSeek research skipped: network mode is off and no cached research exists."},
		}, nil
	}

	userPrompt := BuildUserPrompt(appName, bundleJSON)

	// If web search is enabled, attempt the Responses API (/responses) with native web_search
	if d.config.EnableWebSearch {
		result, err, shouldFallback := d.executeResponsesAPI(ctx, apiKey, appName, userPrompt)
		if !shouldFallback {
			if err == nil && result.APIError == "" {
				d.cache.Set(cacheKey, result)
			}
			return result, err
		}
	}

	// Execute via standard /chat/completions endpoint (direct or fallback)
	result, err := d.executeChatCompletions(ctx, apiKey, appName, userPrompt)
	if err == nil && result.APIError == "" {
		d.cache.Set(cacheKey, result)
	}
	return result, err
}

func (d *DeepSeekReasoner) executeResponsesAPI(ctx context.Context, apiKey, appName, userPrompt string) (ReasoningResult, error, bool) {
	sysPrompt := deepseekSystemPrompt
	if strings.TrimSpace(d.config.SystemPrompt) != "" {
		sysPrompt = d.config.SystemPrompt
	}

	reqBody := deepseekResponsesRequest{
		Model: d.config.Model,
		Input: []deepseekChatMessage{
			{
				Role:    "system",
				Content: sysPrompt,
			},
			{
				Role:    "user",
				Content: userPrompt,
			},
		},
		Tools: []deepseekTool{
			{Type: "web_search"},
		},
		ToolChoice: "auto",
		ResponseFormat: &deepseekResponseFormat{
			Type: "json_object",
		},
		Temperature: 0.0,
		MaxTokens:   500,
	}

	reqBytes, err := json.Marshal(reqBody)
	if err != nil {
		return defaultDeepSeekUnknown("Failed to encode Responses API payload"), err, false
	}

	endpoint := strings.TrimRight(d.config.BaseURL, "/") + "/responses"

	const maxRetries = 2
	var lastErrReason string

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(attempt*50) * time.Millisecond
			select {
			case <-ctx.Done():
				return defaultDeepSeekUnknown("DeepSeek reasoning context cancelled: " + ctx.Err().Error()), ctx.Err(), false
			case <-time.After(backoff):
			}
		}

		httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(reqBytes))
		if err != nil {
			return defaultDeepSeekUnknown("Failed to create HTTP request: " + err.Error()), err, false
		}

		httpReq.Header.Set("Content-Type", "application/json")
		httpReq.Header.Set("Authorization", "Bearer "+apiKey)

		resp, err := d.client.Do(httpReq)
		if err != nil {
			lastErrReason = fmt.Sprintf("DeepSeek Responses network error: %v", err)
			continue
		}

		respBytes, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			lastErrReason = fmt.Sprintf("Failed reading Responses body: %v", err)
			continue
		}

		if resp.StatusCode == 402 {
			fmt.Fprintln(os.Stderr, "\n[!] DeepSeek API Error: HTTP 402 Payment Required (Credits exhausted)")
			fmt.Fprintln(os.Stderr, "    Cause: Your DeepSeek API account balance has run out ($0.00).")
			fmt.Fprintln(os.Stderr, "    Fix:   Top up your balance at https://platform.deepseek.com")
			return ReasoningResult{
				Classification:  provenance.ClassificationUnknown,
				Confidence:      provenance.ConfidenceNone,
				APIError:        "HTTP 402 Payment Required (Credits exhausted - top up at platform.deepseek.com)",
				EvidenceSummary: "DeepSeek API call failed: HTTP 402 Payment Required (Account credits exhausted).",
				Conclusion:      "AI reasoning halted because DeepSeek account credits are exhausted.",
				Reasons:         []string{"DeepSeek credits exhausted (HTTP 402 Payment Required - top up at platform.deepseek.com)"},
			}, nil, false
		}

		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			if resp.StatusCode == http.StatusUnauthorized {
				fmt.Fprintln(os.Stderr, "\n[!] DeepSeek API Error: HTTP 401 Unauthorized (Authentication failed)")
				fmt.Fprintln(os.Stderr, "    Cause: The configured DEEPSEEK_API_KEY was rejected by api.deepseek.com.")
				fmt.Fprintln(os.Stderr, "    Fix:   Run 'appaudit config set-deepseek-key <KEY>' or set DEEPSEEK_API_KEY.")
				return ReasoningResult{
					Classification:  provenance.ClassificationUnknown,
					Confidence:      provenance.ConfidenceNone,
					APIError:        "HTTP 401 Unauthorized (Invalid or unauthorized API key - run 'appaudit config set-deepseek-key')",
					EvidenceSummary: "DeepSeek API authentication failed (HTTP 401 Unauthorized). The configured API key was rejected.",
					Conclusion:      "AI reasoning failed due to API authentication error (HTTP 401).",
					Reasons:         []string{"DeepSeek authentication error (HTTP 401): invalid or unauthorized API key"},
				}, nil, false
			}
			fmt.Fprintln(os.Stderr, "\n[!] DeepSeek API Error: HTTP 403 Forbidden (Access denied)")
			return ReasoningResult{
				Classification:  provenance.ClassificationUnknown,
				Confidence:      provenance.ConfidenceNone,
				APIError:        "HTTP 403 Forbidden (Access restricted or forbidden)",
				EvidenceSummary: "DeepSeek API call failed: HTTP 403 Forbidden (Access restricted).",
				Conclusion:      "AI reasoning failed due to API access restriction (HTTP 403).",
				Reasons:         []string{"DeepSeek access error (HTTP 403): forbidden"},
			}, nil, false
		}

		// If 404 Not Found or 400 Bad Request, the endpoint is likely not supported by this proxy/server -> fallback
		if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusBadRequest {
			return ReasoningResult{}, nil, true
		}

		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			lastErrReason = fmt.Sprintf("DeepSeek API returned HTTP %d: %s", resp.StatusCode, string(respBytes))
			continue
		}

		if resp.StatusCode != http.StatusOK {
			apiErr := fmt.Sprintf("HTTP %d unexpected error: %s", resp.StatusCode, string(respBytes))
			return ReasoningResult{
				Classification:  provenance.ClassificationUnknown,
				Confidence:      provenance.ConfidenceNone,
				APIError:        apiErr,
				EvidenceSummary: "DeepSeek API returned unexpected error: " + apiErr,
				Conclusion:      "AI reasoning failed due to unexpected API response.",
				Reasons:         []string{fmt.Sprintf("DeepSeek API returned unexpected HTTP %d: %s", resp.StatusCode, string(respBytes))},
			}, nil, false
		}

		result, err := d.parseResponsesAPI(respBytes, appName)
		if err != nil {
			return result, err, true
		}
		return result, nil, false
	}

	apiErr := lastErrReason
	if strings.Contains(lastErrReason, "429") {
		apiErr = "HTTP 429 Too Many Requests (Rate limit reached)"
	}
	return ReasoningResult{
		Classification:  provenance.ClassificationUnknown,
		Confidence:      provenance.ConfidenceNone,
		APIError:        apiErr,
		EvidenceSummary: "DeepSeek API request failed: " + apiErr,
		Conclusion:      "AI reasoning failed due to remote endpoint failure.",
		Reasons:         []string{lastErrReason + " (retries exhausted)"},
	}, nil, true
}

func (d *DeepSeekReasoner) executeChatCompletions(ctx context.Context, apiKey, appName, userPrompt string) (ReasoningResult, error) {
	sysPrompt := deepseekSystemPrompt
	if strings.TrimSpace(d.config.SystemPrompt) != "" {
		sysPrompt = d.config.SystemPrompt
	}

	reqBody := deepseekChatRequest{
		Model: d.config.Model,
		Messages: []deepseekChatMessage{
			{
				Role:    "system",
				Content: sysPrompt,
			},
			{
				Role:    "user",
				Content: userPrompt,
			},
		},
		Thinking: &deepseekThinkingConfig{
			Type: "disabled",
		},
		ResponseFormat: &deepseekResponseFormat{
			Type: "json_object",
		},
		Temperature: 0.0,
		MaxTokens:   500,
	}

	reqBytes, err := json.Marshal(reqBody)
	if err != nil {
		return defaultDeepSeekUnknown("Failed to encode DeepSeek request payload"), err
	}

	endpoint := strings.TrimRight(d.config.BaseURL, "/") + "/chat/completions"

	const maxRetries = 2
	var lastErrReason string

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(attempt*50) * time.Millisecond
			select {
			case <-ctx.Done():
				return defaultDeepSeekUnknown("DeepSeek reasoning context cancelled: " + ctx.Err().Error()), ctx.Err()
			case <-time.After(backoff):
			}
		}

		httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(reqBytes))
		if err != nil {
			return defaultDeepSeekUnknown("Failed to create HTTP request: " + err.Error()), err
		}

		httpReq.Header.Set("Content-Type", "application/json")
		httpReq.Header.Set("Authorization", "Bearer "+apiKey)

		resp, err := d.client.Do(httpReq)
		if err != nil {
			lastErrReason = fmt.Sprintf("DeepSeek network error: %v", err)
			continue
		}

		respBytes, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			lastErrReason = fmt.Sprintf("Failed reading response body: %v", err)
			continue
		}

		if resp.StatusCode == 402 {
			fmt.Fprintln(os.Stderr, "\n[!] DeepSeek API Error: HTTP 402 Payment Required (Credits exhausted)")
			fmt.Fprintln(os.Stderr, "    Cause: Your DeepSeek API account balance has run out ($0.00).")
			fmt.Fprintln(os.Stderr, "    Fix:   Top up your balance at https://platform.deepseek.com")
			return ReasoningResult{
				Classification:  provenance.ClassificationUnknown,
				Confidence:      provenance.ConfidenceNone,
				APIError:        "HTTP 402 Payment Required (Credits exhausted - top up at platform.deepseek.com)",
				EvidenceSummary: "DeepSeek API call failed: HTTP 402 Payment Required (Account credits exhausted).",
				Conclusion:      "AI reasoning halted because DeepSeek account credits are exhausted.",
				Reasons:         []string{"DeepSeek credits exhausted", "HTTP 402 Payment Required: account balance is $0.00 - top up at https://platform.deepseek.com"},
			}, nil
		}

		if resp.StatusCode == http.StatusUnauthorized {
			fmt.Fprintln(os.Stderr, "\n[!] DeepSeek API Error: HTTP 401 Unauthorized (Authentication failed)")
			fmt.Fprintln(os.Stderr, "    Cause: The configured DEEPSEEK_API_KEY was rejected by api.deepseek.com.")
			fmt.Fprintln(os.Stderr, "    Fix:   Run 'appaudit config set-deepseek-key <KEY>' or set DEEPSEEK_API_KEY.")
			return ReasoningResult{
				Classification:  provenance.ClassificationUnknown,
				Confidence:      provenance.ConfidenceNone,
				APIError:        "HTTP 401 Unauthorized (Invalid API key - run 'appaudit config set-deepseek-key')",
				EvidenceSummary: "DeepSeek API authentication failed (HTTP 401 Unauthorized). The configured API key was rejected.",
				Conclusion:      "AI reasoning halted due to invalid or unauthorized DeepSeek API key.",
				Reasons:         []string{"DeepSeek authentication error (HTTP 401): invalid or unauthorized API key (run 'appaudit config set-deepseek-key <KEY>')"},
			}, nil
		}

		if resp.StatusCode == http.StatusForbidden {
			fmt.Fprintln(os.Stderr, "\n[!] DeepSeek API Error: HTTP 403 Forbidden (Access denied)")
			fmt.Fprintln(os.Stderr, "    Cause: Access to DeepSeek API is restricted or forbidden for your key/region.")
			fmt.Fprintln(os.Stderr, "    Fix:   Verify account status at https://platform.deepseek.com")
			return ReasoningResult{
				Classification:  provenance.ClassificationUnknown,
				Confidence:      provenance.ConfidenceNone,
				APIError:        "HTTP 403 Forbidden (Access restricted or forbidden)",
				EvidenceSummary: "DeepSeek API call failed: HTTP 403 Forbidden (Access restricted).",
				Conclusion:      "AI reasoning halted due to DeepSeek API access restriction (HTTP 403).",
				Reasons:         []string{"DeepSeek access error (HTTP 403): forbidden"},
			}, nil
		}

		if resp.StatusCode == http.StatusNotFound {
			return ReasoningResult{
				Classification:  provenance.ClassificationUnknown,
				Confidence:      provenance.ConfidenceNone,
				APIError:        fmt.Sprintf("HTTP 404 Not Found (Model '%s' not found on endpoint)", d.config.Model),
				EvidenceSummary: fmt.Sprintf("DeepSeek endpoint returned HTTP 404 for model '%s'.", d.config.Model),
				Conclusion:      "AI reasoning failed: requested DeepSeek model or endpoint not found.",
				Reasons:         []string{fmt.Sprintf("DeepSeek endpoint not found (HTTP 404) for model '%s'", d.config.Model)},
			}, nil
		}

		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			lastErrReason = fmt.Sprintf("DeepSeek API returned HTTP %d: %s", resp.StatusCode, string(respBytes))
			continue
		}

		if resp.StatusCode != http.StatusOK {
			apiErr := fmt.Sprintf("HTTP %d unexpected error: %s", resp.StatusCode, string(respBytes))
			return ReasoningResult{
				Classification:  provenance.ClassificationUnknown,
				Confidence:      provenance.ConfidenceNone,
				APIError:        apiErr,
				EvidenceSummary: "DeepSeek API returned unexpected error: " + apiErr,
				Conclusion:      "AI reasoning failed due to unexpected API response.",
				Reasons:         []string{fmt.Sprintf("DeepSeek API returned unexpected HTTP %d: %s", resp.StatusCode, string(respBytes))},
			}, nil
		}

		return d.parseResponse(respBytes, appName)
	}

	apiErr := lastErrReason
	if strings.Contains(lastErrReason, "429") {
		apiErr = "HTTP 429 Too Many Requests (Rate limit reached)"
	}
	return ReasoningResult{
		Classification:  provenance.ClassificationUnknown,
		Confidence:      provenance.ConfidenceNone,
		APIError:        apiErr,
		EvidenceSummary: "DeepSeek API request failed: " + apiErr,
		Conclusion:      "AI reasoning failed due to remote endpoint failure.",
		Reasons:         []string{lastErrReason + " (retries exhausted, falling back to UNKNOWN)"},
	}, nil
}

func (d *DeepSeekReasoner) parseResponsesAPI(respBytes []byte, appName string) (ReasoningResult, error) {
	var resp deepseekResponsesResponse
	if err := json.Unmarshal(respBytes, &resp); err != nil {
		return defaultDeepSeekUnknown("Failed to decode DeepSeek Responses API JSON"), err
	}

	if resp.Error != nil && resp.Error.Message != "" {
		return defaultDeepSeekUnknown("DeepSeek Responses API error: " + resp.Error.Message), nil
	}

	contentStr := strings.TrimSpace(resp.OutputText)
	var searchSources []string

	for _, item := range resp.Output {
		if item.Type == "web_search_call" && item.WebSearchCall != nil && item.WebSearchCall.Query != "" {
			searchSources = append(searchSources, "DeepSeek Web Search: "+item.WebSearchCall.Query)
		} else if item.Type == "message" {
			switch c := item.Content.(type) {
			case string:
				if contentStr == "" {
					contentStr = strings.TrimSpace(c)
				}
			case []any:
				for _, block := range c {
					if blockMap, ok := block.(map[string]any); ok {
						if textVal, ok := blockMap["text"].(string); ok && contentStr == "" {
							contentStr += textVal
						}
						if annotations, ok := blockMap["annotations"].([]any); ok {
							for _, ann := range annotations {
								if annMap, ok := ann.(map[string]any); ok {
									if urlVal, ok := annMap["url"].(string); ok && urlVal != "" {
										searchSources = append(searchSources, urlVal)
									}
								}
							}
						}
					}
				}
			}
		}
	}

	contentStr = strings.TrimPrefix(contentStr, "```json")
	contentStr = strings.TrimPrefix(contentStr, "```")
	contentStr = strings.TrimSuffix(contentStr, "```")
	contentStr = strings.TrimSpace(contentStr)

	var output deepseekOutputSchema
	if err := json.Unmarshal([]byte(contentStr), &output); err != nil {
		return defaultDeepSeekUnknown("Failed to decode Responses API JSON: " + err.Error()), nil
	}

	var usage TokenUsage
	if resp.Usage != nil {
		usage = TokenUsage{
			PromptTokens:     resp.Usage.PromptTokens,
			CompletionTokens: resp.Usage.CompletionTokens,
			TotalTokens:      resp.Usage.TotalTokens,
		}
	}

	return d.convertSchemaToResult(output, searchSources, usage, appName)
}

func (d *DeepSeekReasoner) parseResponse(respBytes []byte, appName string) (ReasoningResult, error) {
	var chatResp deepseekChatResponse
	if err := json.Unmarshal(respBytes, &chatResp); err != nil {
		return defaultDeepSeekUnknown("Failed to decode DeepSeek JSON response"), err
	}

	if chatResp.Error != nil && chatResp.Error.Message != "" {
		return defaultDeepSeekUnknown("DeepSeek API error: " + chatResp.Error.Message), nil
	}

	if len(chatResp.Choices) == 0 {
		return defaultDeepSeekUnknown("DeepSeek returned zero choices"), nil
	}

	contentStr := strings.TrimSpace(chatResp.Choices[0].Message.Content)
	contentStr = strings.TrimPrefix(contentStr, "```json")
	contentStr = strings.TrimPrefix(contentStr, "```")
	contentStr = strings.TrimSuffix(contentStr, "```")
	contentStr = strings.TrimSpace(contentStr)

	var output deepseekOutputSchema
	if err := json.Unmarshal([]byte(contentStr), &output); err != nil {
		return defaultDeepSeekUnknown("Failed to decode model JSON content: " + err.Error()), nil
	}

	var usage TokenUsage
	if chatResp.Usage != nil {
		usage = TokenUsage{
			PromptTokens:     chatResp.Usage.PromptTokens,
			CompletionTokens: chatResp.Usage.CompletionTokens,
			TotalTokens:      chatResp.Usage.TotalTokens,
		}
	}

	return d.convertSchemaToResult(output, nil, usage, appName)
}

func (d *DeepSeekReasoner) convertSchemaToResult(output deepseekOutputSchema, extraSources []string, usage TokenUsage, appName string) (ReasoningResult, error) {
	res := ConvertAIOutputToResult(output, extraSources, usage, appName)
	if len(extraSources) == 0 {
		res.SearchGrounded = false
		res.DegradationWarning = "DeepSeek inference uses internal model parametric weights (live web search grounding not enabled)."
	} else {
		res.SearchGrounded = true
	}
	return res, nil
}

func defaultDeepSeekUnknown(reason string) ReasoningResult {
	return ReasoningResult{
		Classification: provenance.ClassificationUnknown,
		Confidence:     provenance.ConfidenceNone,
		Reasons:        []string{reason},
	}
}

// DefaultDeepSeekBatchChunkSize defines the batch chunk size for DeepSeek cloud reasoning.
const DefaultDeepSeekBatchChunkSize = 5

// ReasonBatch analyzes a batch of evidence bundles in chunks of 5 with cache-first lookup and fallback resilience.
func (d *DeepSeekReasoner) ReasonBatch(ctx context.Context, bundles []EvidenceBundle) ([]ReasoningResult, error) {
	if len(bundles) == 0 {
		return nil, nil
	}

	results := make([]ReasoningResult, len(bundles))
	chunkSize := DefaultDeepSeekBatchChunkSize

	for chunkStart := 0; chunkStart < len(bundles); chunkStart += chunkSize {
		chunkEnd := chunkStart + chunkSize
		if chunkEnd > len(bundles) {
			chunkEnd = len(bundles)
		}

		var uncachedIndices []int
		var uncachedBundles []EvidenceBundle

		for idx := chunkStart; idx < chunkEnd; idx++ {
			b := bundles[idx]
			cacheKey := ComputeDeepSeekKey(b.SHA256, b.AppName, b.Version, b.SiblingCount)
			if cachedRes, found := d.cache.Get(cacheKey); found {
				cachedRes.CacheHit = true
				results[idx] = cachedRes
			} else {
				uncachedIndices = append(uncachedIndices, idx)
				uncachedBundles = append(uncachedBundles, b)
			}
		}

		if len(uncachedBundles) == 0 {
			continue
		}

		chunkNum := (chunkStart / chunkSize) + 1
		totalChunks := (len(bundles) + chunkSize - 1) / chunkSize
		fmt.Printf("\r[DeepSeek AI] Processing batch %d/%d (%d candidate applications)...", chunkNum, totalChunks, len(uncachedBundles))
		_ = os.Stdout.Sync()

		for k, b := range uncachedBundles {
			idx := uncachedIndices[k]
			res, err := d.Analyze(ctx, b)
			if err != nil {
				results[idx] = defaultDeepSeekUnknown(fmt.Sprintf("DeepSeek error on %s: %v", b.AppName, err))
			} else {
				results[idx] = res
			}
		}
	}

	fmt.Printf("\r[OK] DeepSeek AI reasoning complete for %d application(s).                 \n", len(bundles))
	return results, nil
}

