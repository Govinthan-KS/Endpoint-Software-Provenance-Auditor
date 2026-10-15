package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/example/appaudit/internal/provenance"
)

// DefaultOllamaModel is the default local model identifier.
const DefaultOllamaModel = "audit-phi:q6k"

// LocalReasoner interacts with a local Ollama instance with SearXNG grounding
// and strict GPU VRAM constraints.
type LocalReasoner struct {
	ModelName      string
	BaseURL        string
	SearchProvider SearchProvider
	Cache          *OllamaCache
	HTTPClient     *http.Client
	Timeout        time.Duration
	SystemPrompt   string
}

// NewLocalReasoner creates a configured local Ollama reasoner.
func NewLocalReasoner(modelName string, search SearchProvider, cache *OllamaCache, baseURL ...string) *LocalReasoner {
	if modelName == "" {
		modelName = DefaultOllamaModel
	}
	url := "http://localhost:11434"
	if len(baseURL) > 0 && strings.TrimSpace(baseURL[0]) != "" {
		url = strings.TrimRight(strings.TrimSpace(baseURL[0]), "/")
	}
	if search == nil {
		search = &NoopSearchProvider{}
	}
	if cache == nil {
		cache = NewOllamaCache()
	}
	timeout := 300 * time.Second

	return &LocalReasoner{
		ModelName:      modelName,
		BaseURL:        url,
		SearchProvider: search,
		Cache:          cache,
		Timeout:        timeout,
		HTTPClient: &http.Client{
			Timeout: timeout,
		},
	}
}

func (l *LocalReasoner) Name() string {
	return "local_ollama (" + l.ModelName + ")"
}

// PreflightGPUCheck queries Ollama /api/ps to verify the model is 100% in VRAM.
// If size_vram < size on any active model, it returns a hard refusal error.
func (l *LocalReasoner) PreflightGPUCheck(ctx context.Context) error {
	psURL := fmt.Sprintf("%s/api/ps", l.BaseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, psURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create Ollama pre-flight request: %w", err)
	}

	resp, err := l.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("Ollama is not running (%s): %w", psURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Ollama /api/ps returned HTTP %d", resp.StatusCode)
	}

	var psResp struct {
		Models []struct {
			Name     string `json:"name"`
			Model    string `json:"model"`
			Size     int64  `json:"size"`
			SizeVRAM int64  `json:"size_vram"`
		} `json:"models"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&psResp); err != nil {
		return fmt.Errorf("failed to decode Ollama /api/ps response: %w", err)
	}

	for _, m := range psResp.Models {
		if m.Size > 0 && m.SizeVRAM < m.Size {
			return errors.New("HARD REFUSAL: model is not 100% in VRAM; CPU offload strictly prohibited")
		}
	}

	return nil
}

type ollamaChatRequest struct {
	Model     string              `json:"model"`
	Format    string              `json:"format"`
	Stream    bool                `json:"stream"`
	KeepAlive string              `json:"keep_alive"`
	Messages  []ollamaChatMessage `json:"messages"`
	Options   ollamaOptions       `json:"options"`
}

type ollamaChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type ollamaOptions struct {
	NumGPU      int     `json:"num_gpu"`
	NumCtx      int     `json:"num_ctx"`
	Temperature float64 `json:"temperature"`
}

type ollamaChatResponse struct {
	Message struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	} `json:"message"`
	PromptEvalCount int    `json:"prompt_eval_count"`
	EvalCount       int    `json:"eval_count"`
	Error           string `json:"error,omitempty"`
}

// Analyze performs local reasoning on a single bundle.
func (l *LocalReasoner) Analyze(ctx context.Context, bundle any) (ReasoningResult, error) {
	eb := ToAIEvidenceBundle(bundle)
	results, err := l.ReasonBatch(ctx, []EvidenceBundle{eb})
	if err != nil {
		return defaultUnknown(err.Error()), err
	}
	if len(results) == 0 {
		return defaultUnknown("No result returned from local Ollama model"), nil
	}
	return results[0], nil
}

// ReasonBatch processes a batch of candidate bundles with preflight GPU verification,
// SearXNG grounding retrieval, and local Ollama inference.
func (l *LocalReasoner) ReasonBatch(ctx context.Context, bundles []EvidenceBundle) ([]ReasoningResult, error) {
	if len(bundles) == 0 {
		return nil, nil
	}

	results := make([]ReasoningResult, len(bundles))

	// 1. Strict 100% GPU Pre-flight Check
	if err := l.PreflightGPUCheck(ctx); err != nil {
		for i, b := range bundles {
			results[i] = ReasoningResult{
				Classification:  provenance.ClassificationUnknown,
				Confidence:      provenance.ConfidenceNone,
				APIError:        err.Error(),
				EvidenceSummary: "Local GPU execution halted: " + err.Error(),
				Conclusion:      "Local AI reasoning refused due to VRAM / GPU constraints.",
				Reasons:         []string{fmt.Sprintf("Local reasoner on %s: %v", b.AppName, err)},
			}
		}
		return results, err
	}

	chatEndpoint := fmt.Sprintf("%s/api/chat", l.BaseURL)
	chunkSize := 3

	// 2. Process bundles in chunks of 3
	for chunkStart := 0; chunkStart < len(bundles); chunkStart += chunkSize {
		chunkEnd := chunkStart + chunkSize
		if chunkEnd > len(bundles) {
			chunkEnd = len(bundles)
		}

		var uncachedIndices []int
		var uncachedBundles []EvidenceBundle

		for idx := chunkStart; idx < chunkEnd; idx++ {
			b := bundles[idx]
			cacheKey := ComputeOllamaKey(b.AppName, b.Version, b.SHA256, b.SiblingCount)
			if cached, found := l.Cache.Get(cacheKey); found {
				cached.CacheHit = true
				results[idx] = cached
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
		fmt.Printf("\r[Local AI] Processing batch %d/%d (%d candidate applications)...", chunkNum, totalChunks, len(uncachedBundles))
		_ = os.Stdout.Sync()

		// If single uncached bundle in this chunk, reason directly
		if len(uncachedBundles) == 1 {
			b := uncachedBundles[0]
			idx := uncachedIndices[0]
			cacheKey := ComputeOllamaKey(b.AppName, b.Version, b.SHA256, b.SiblingCount)

			searchQuery := BuildSearchQuery(b)
			searchResults, sErr := l.SearchProvider.Search(ctx, searchQuery)
			if sErr == nil {
				if sx, ok := l.SearchProvider.(*SearXNGProvider); ok && sx.LastError() != nil {
					sErr = sx.LastError()
				}
			}
			var searchURLs []string
			for _, r := range searchResults {
				if r.URL != "" {
					searchURLs = append(searchURLs, r.URL)
				}
			}

			userPrompt := buildLocalPrompt(b, searchResults)
			messages := []ollamaChatMessage{}
			if strings.TrimSpace(l.SystemPrompt) != "" {
				messages = append(messages, ollamaChatMessage{
					Role:    "system",
					Content: l.SystemPrompt,
				})
			}
			messages = append(messages, ollamaChatMessage{
				Role:    "user",
				Content: userPrompt,
			})

			res, err := l.callOllama(ctx, chatEndpoint, messages)
			if err != nil {
				results[idx] = defaultUnknown(fmt.Sprintf("Ollama error on %s: %v", b.AppName, err))
			} else {
				var output AIOutputSchema
				if err := json.Unmarshal([]byte(res.rawText), &output); err != nil {
					results[idx] = defaultUnknown("Model output did not match expected JSON schema: " + err.Error())
				} else {
					usage := TokenUsage{
						PromptTokens:     res.promptTokens,
						CompletionTokens: res.completionTokens,
						TotalTokens:      res.totalTokens,
					}
					r := ConvertAIOutputToResult(output, searchURLs, usage, b.AppName)
					if len(searchURLs) == 0 {
						r.SearchGrounded = false
						r.Confidence = provenance.ConfidenceLow
						if sErr != nil {
							r.SearchWarning = "SearXNG Offline at port :8080 — Running without web grounding"
							r.DegradationWarning = fmt.Sprintf("Web search via SearXNG failed (%v). Verdict relies solely on local model memory and may be hallucinated.", sErr)
						} else {
							r.SearchWarning = "Web Search Yielded 0 Hits / Blocked by Upstream — Verdict based on model weights only — may be hallucinated"
							r.DegradationWarning = "Web search via SearXNG returned 0 results. Verdict relies solely on local model memory and may be hallucinated."
						}
						r.Reasons = append(r.Reasons, "Disclaimer: "+r.SearchWarning)
					} else {
						r.SearchGrounded = true
					}
					if r.APIError == "" {
						l.Cache.Set(cacheKey, r)
					}
					results[idx] = r
				}
			}
			continue
		}

		// Multi-item chunk (up to 3 items)
		type localCandidateItem struct {
			SHA256         string `json:"sha256"`
			AppName        string `json:"app_name"`
			BinaryName     string `json:"binary_name,omitempty"`
			Path           string `json:"path,omitempty"`
			Publisher      string `json:"publisher,omitempty"`
			Version        string `json:"version,omitempty"`
			InstallDir     string `json:"install_dir,omitempty"`
			Evidence       string `json:"evidence,omitempty"`
			SearchEvidence string `json:"search_evidence,omitempty"`
			IsWrapperStub  bool   `json:"is_wrapper_stub,omitempty"`
		}

		candidateList := make([]localCandidateItem, len(uncachedBundles))
		searchURLsMap := make(map[int][]string)
		searchErrorsMap := make(map[int]error)

		for k, b := range uncachedBundles {
			searchQuery := BuildSearchQuery(b)
			searchResults, sErr := l.SearchProvider.Search(ctx, searchQuery)
			if sErr == nil {
				if sx, ok := l.SearchProvider.(*SearXNGProvider); ok && sx.LastError() != nil {
					sErr = sx.LastError()
				}
			}
			if sErr != nil {
				searchErrorsMap[k] = sErr
			}
			var sURLs []string
			var sEvidence []string
			for _, sr := range searchResults {
				if sr.URL != "" {
					sURLs = append(sURLs, sr.URL)
				}
				sEvidence = append(sEvidence, fmt.Sprintf("%s: %s", sr.Title, sr.Snippet))
			}
			searchURLsMap[k] = sURLs

			ev := b.EvidenceSummary
			if b.IsWrapperStub {
				if ev != "" {
					ev += " | "
				}
				ev += "Binary is a generic script wrapper launcher stub (distlib/pip); deduce provenance from public repositories/package manager."
			}

			candidateList[k] = localCandidateItem{
				SHA256:         b.SHA256,
				AppName:        b.AppName,
				BinaryName:     b.BinaryName,
				Path:           b.Path,
				Publisher:      b.Publisher,
				Version:        b.Version,
				InstallDir:     b.InstallDir,
				Evidence:       ev,
				SearchEvidence: strings.Join(sEvidence, "\n"),
				IsWrapperStub:  b.IsWrapperStub,
			}
		}

		candidateJSONBytes, _ := json.MarshalIndent(candidateList, "", "  ")

		batchInstruction := BatchSystemInstruction
		if strings.TrimSpace(l.SystemPrompt) != "" {
			batchInstruction = l.SystemPrompt
		}

		messages := []ollamaChatMessage{
			{Role: "system", Content: batchInstruction},
			{Role: "user", Content: string(candidateJSONBytes)},
		}

		res, err := l.callOllama(ctx, chatEndpoint, messages)
		if err != nil {
			for _, idx := range uncachedIndices {
				results[idx] = defaultUnknown(fmt.Sprintf("Ollama batch failed: %v", err))
			}
			continue
		}

		rawText := res.rawText
		var batchItems []batchItemOutput
		if err := json.Unmarshal([]byte(rawText), &batchItems); err != nil {
			var single batchItemOutput
			if errSingle := json.Unmarshal([]byte(rawText), &single); errSingle == nil && (single.Classification != "" || single.Identity != "") {
				batchItems = []batchItemOutput{single}
			} else {
				var wrapper map[string]json.RawMessage
				if errWrap := json.Unmarshal([]byte(rawText), &wrapper); errWrap == nil {
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

		itemsBySHA := make(map[string]batchItemOutput)
		for _, item := range batchItems {
			if item.SHA256 != "" {
				itemsBySHA[strings.ToLower(item.SHA256)] = item
			}
		}

		for k, b := range uncachedBundles {
			idx := uncachedIndices[k]
			cacheKey := ComputeOllamaKey(b.AppName, b.Version, b.SHA256, b.SiblingCount)
			matched, hasMatch := itemsBySHA[strings.ToLower(b.SHA256)]
			if !hasMatch && k < len(batchItems) {
				matched = batchItems[k]
				hasMatch = true
			}

			if hasMatch {
				schema := AIOutputSchema{
					Classification: matched.Classification,
					Confidence:     matched.Confidence,
					Identity:       matched.Identity,
					Publisher:      matched.Publisher,
					Reasons:        matched.Reasons,
					Evidence:       matched.Evidence,
					Conclusion:     matched.Conclusion,
				}
				tokensPerItem := res.totalTokens / len(uncachedBundles)
				usage := TokenUsage{
					PromptTokens:     res.promptTokens / len(uncachedBundles),
					CompletionTokens: res.completionTokens / len(uncachedBundles),
					TotalTokens:      tokensPerItem,
				}
				r := ConvertAIOutputToResult(schema, searchURLsMap[k], usage, b.AppName)
				if len(searchURLsMap[k]) == 0 {
					r.SearchGrounded = false
					r.Confidence = provenance.ConfidenceLow
					if errSearch := searchErrorsMap[k]; errSearch != nil {
						r.SearchWarning = "SearXNG Offline at port :8080 — Running without web grounding"
						r.DegradationWarning = fmt.Sprintf("Web search via SearXNG failed (%v). Verdict relies solely on local model memory and may be hallucinated.", errSearch)
					} else {
						r.SearchWarning = "Web Search Yielded 0 Hits / Blocked by Upstream — Verdict based on model weights only — may be hallucinated"
						r.DegradationWarning = "Web search via SearXNG returned 0 results. Verdict relies solely on local model memory and may be hallucinated."
					}
					r.Reasons = append(r.Reasons, "Disclaimer: "+r.SearchWarning)
				} else {
					r.SearchGrounded = true
				}
				if r.APIError == "" {
					l.Cache.Set(cacheKey, r)
				}
				results[idx] = r
			} else {
				results[idx] = defaultUnknown("Local AI output could not be mapped to candidate")
			}
		}
	}

	fmt.Printf("\r[OK] Local AI reasoning complete for %d application(s).                 \n", len(bundles))
	return results, nil
}

func buildLocalPrompt(bundle EvidenceBundle, searchResults []SearchResult) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Candidate: %s\n", bundle.AppName))
	if bundle.BinaryName != "" && bundle.BinaryName != bundle.AppName {
		sb.WriteString(fmt.Sprintf("BinaryName: %s\n", bundle.BinaryName))
	}
	if bundle.Path != "" {
		sb.WriteString(fmt.Sprintf("Path: %s\n", bundle.Path))
	}
	if bundle.InstallDir != "" {
		sb.WriteString(fmt.Sprintf("InstallDir: %s\n", bundle.InstallDir))
	}
	if bundle.Publisher != "" {
		sb.WriteString(fmt.Sprintf("Publisher: %s\n", bundle.Publisher))
	}
	if bundle.Version != "" {
		sb.WriteString(fmt.Sprintf("Version: %s\n", bundle.Version))
	}
	if bundle.SHA256 != "" {
		sb.WriteString(fmt.Sprintf("SHA256: %s\n", bundle.SHA256))
	}
	if bundle.EvidenceSummary != "" {
		sb.WriteString(fmt.Sprintf("Local Evidence: %s\n", bundle.EvidenceSummary))
	}
	if bundle.IsWrapperStub {
		sb.WriteString("Note: Binary is a generic script launcher stub (e.g. distlib/pip simple launcher). Identify the underlying application and true publisher from project repository / package registry search results rather than wrapper stub metadata.\n")
	}

	sb.WriteString("\n[Search Evidence from Web Retrieval]\n")
	if len(searchResults) > 0 {
		for i, r := range searchResults {
			domainOrURL := r.Domain()
			if domainOrURL == "" {
				domainOrURL = r.URL
			}
			sb.WriteString(fmt.Sprintf("Result %d: (%s) - %s\n\"%s\"\n\n", i+1, domainOrURL, r.Title, r.Snippet))
		}
		sb.WriteString("Instruction: Give higher evidential weight to official project repositories (GitHub, GitLab), verified package registries (PyPI, crates.io, npm, NuGet), and manufacturer download portals.\n")
	} else {
		sb.WriteString("No relevant search results found from web retrieval.\n")
	}

	return sb.String()
}

func defaultUnknown(reason string) ReasoningResult {
	return ReasoningResult{
		Classification: provenance.ClassificationUnknown,
		Confidence:     provenance.ConfidenceNone,
		Reasons:        []string{reason},
	}
}

type ollamaCallResult struct {
	rawText          string
	promptTokens     int
	completionTokens int
	totalTokens      int
}

func (l *LocalReasoner) callOllama(ctx context.Context, endpoint string, messages []ollamaChatMessage) (*ollamaCallResult, error) {
	chatReq := ollamaChatRequest{
		Model:     l.ModelName,
		Format:    "json",
		Stream:    false,
		KeepAlive: "15m",
		Messages:  messages,
		Options: ollamaOptions{
			NumGPU:      99,
			NumCtx:      4096,
			Temperature: 0.0,
		},
	}

	reqBytes, err := json.Marshal(chatReq)
	if err != nil {
		return nil, fmt.Errorf("failed to encode Ollama request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(reqBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := l.HTTPClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("Ollama chat endpoint unreachable: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed reading Ollama response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Ollama returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var chatResp ollamaChatResponse
	if err := json.Unmarshal(bodyBytes, &chatResp); err != nil {
		return nil, fmt.Errorf("failed to decode Ollama response JSON: %w", err)
	}

	if chatResp.Error != "" {
		return nil, fmt.Errorf("Ollama model error: %s", chatResp.Error)
	}

	rawText := strings.TrimSpace(chatResp.Message.Content)
	if strings.HasPrefix(rawText, "```json") {
		rawText = strings.TrimPrefix(rawText, "```json")
		rawText = strings.TrimSuffix(rawText, "```")
		rawText = strings.TrimSpace(rawText)
	} else if strings.HasPrefix(rawText, "```") {
		rawText = strings.TrimPrefix(rawText, "```")
		rawText = strings.TrimSuffix(rawText, "```")
		rawText = strings.TrimSpace(rawText)
	}

	return &ollamaCallResult{
		rawText:          rawText,
		promptTokens:     chatResp.PromptEvalCount,
		completionTokens: chatResp.EvalCount,
		totalTokens:      chatResp.PromptEvalCount + chatResp.EvalCount,
	}, nil
}
