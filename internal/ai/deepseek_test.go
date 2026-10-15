package ai

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/example/appaudit/internal/provenance"
)

func TestDeepSeekReasoner_SuccessAndPayloadValidation(t *testing.T) {
	var capturedReq deepseekChatRequest
	var requestCount int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)

		// Verify HTTP headers
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("expected Content-Type application/json, got %s", r.Header.Get("Content-Type"))
		}
		if r.Header.Get("Authorization") != "Bearer test-deepseek-key-123" {
			t.Errorf("expected Authorization Bearer test-deepseek-key-123, got %s", r.Header.Get("Authorization"))
		}

		_ = json.NewDecoder(r.Body).Decode(&capturedReq)

		response := deepseekChatResponse{
			ID: "chatcmpl-test-123",
			Choices: []deepseekChoice{
				{
					Index: 0,
					Message: deepseekChatMessage{
						Role: "assistant",
						Content: `{
							"classification": "THIRD_PARTY",
							"identity": "PostgreSQL Client Utilities",
							"confidence": "HIGH",
							"publisher": "PostgreSQL Global Development Group",
							"reasons": ["Recognized public open-source database client"],
							"sources": ["https://www.postgresql.org"]
						}`,
					},
					FinishReason: "stop",
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	tempDir := t.TempDir()
	cache := NewDeepSeekCache(filepath.Join(tempDir, "test_deepseek_cache.json"))

	reasoner := NewDeepSeekReasoner(DeepSeekConfig{
		APIKey:      "test-deepseek-key-123",
		Model:       DefaultDeepSeekModel,
		BaseURL:     server.URL,
		Cache:       cache,
		NetworkMode: provenance.NetworkOn,
	})

	bundle := map[string]any{
		"app_name": "psql",
		"version":  "16.1",
		"primary_binary": map[string]any{
			"name":   "psql.exe",
			"sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
		},
	}

	result, err := reasoner.Analyze(context.Background(), bundle)
	if err != nil {
		t.Fatalf("Analyze failed unexpectedly: %v", err)
	}

	// 1. Verify credit-saving payload configuration
	if capturedReq.Thinking == nil || capturedReq.Thinking.Type != "disabled" {
		t.Errorf("expected thinking mode 'disabled', got %+v", capturedReq.Thinking)
	}
	if capturedReq.ResponseFormat == nil || capturedReq.ResponseFormat.Type != "json_object" {
		t.Errorf("expected response_format 'json_object', got %+v", capturedReq.ResponseFormat)
	}
	if capturedReq.Temperature != 0.0 {
		t.Errorf("expected temperature 0.0, got %f", capturedReq.Temperature)
	}
	if capturedReq.MaxTokens != 500 {
		t.Errorf("expected max_tokens 500, got %d", capturedReq.MaxTokens)
	}
	if capturedReq.Model != "deepseek-flash" {
		t.Errorf("expected model deepseek-flash, got %s", capturedReq.Model)
	}

	// 2. Verify returned result
	if result.Classification != provenance.ClassificationThirdParty {
		t.Errorf("expected THIRD_PARTY classification, got %s", result.Classification)
	}
	if result.Confidence != provenance.ConfidenceHigh {
		t.Errorf("expected HIGH confidence, got %s", result.Confidence)
	}
	if result.Publisher != "PostgreSQL Global Development Group" {
		t.Errorf("expected publisher PostgreSQL Global Development Group, got %s", result.Publisher)
	}

	// 3. Verify caching (second call should hit cache, consume 0 tokens, make 0 HTTP requests)
	secondResult, err := reasoner.Analyze(context.Background(), bundle)
	if err != nil {
		t.Fatalf("second Analyze failed: %v", err)
	}
	if !secondResult.CacheHit {
		t.Errorf("expected CacheHit == true on repeat scan")
	}
	if atomic.LoadInt32(&requestCount) != 1 {
		t.Errorf("expected exactly 1 HTTP request made, got %d", atomic.LoadInt32(&requestCount))
	}
}

func TestDeepSeekReasoner_HTTP402_CreditsExhausted(t *testing.T) {
	var requestCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		w.WriteHeader(402)
		_, _ = w.Write([]byte(`{"error":{"message":"Insufficient Balance","type":"insufficient_balance","code":"insufficient_balance"}}`))
	}))
	defer server.Close()

	tempDir := t.TempDir()
	cache := NewDeepSeekCache(filepath.Join(tempDir, "test_deepseek_cache.json"))

	reasoner := NewDeepSeekReasoner(DeepSeekConfig{
		APIKey:      "test-key",
		BaseURL:     server.URL,
		Cache:       cache,
		NetworkMode: provenance.NetworkOn,
	})

	bundle := map[string]any{
		"app_name": "custom_app",
		"primary_binary": map[string]any{
			"sha256": "1111222233334444555566667777888811112222333344445555666677778888",
		},
	}

	result, err := reasoner.Analyze(context.Background(), bundle)
	if err != nil {
		t.Fatalf("expected nil error on 402, got: %v", err)
	}

	// Must NOT retry
	if atomic.LoadInt32(&requestCount) != 1 {
		t.Errorf("expected exactly 1 request (no retries on 402), got %d", atomic.LoadInt32(&requestCount))
	}

	// Must return UNKNOWN
	if result.Classification != provenance.ClassificationUnknown {
		t.Errorf("expected UNKNOWN classification on 402, got %s", result.Classification)
	}
	if len(result.Reasons) == 0 || result.Reasons[0] != "DeepSeek credits exhausted" {
		t.Errorf("expected reason 'DeepSeek credits exhausted', got %v", result.Reasons)
	}
}

func TestDeepSeekReasoner_HTTP401_403_404_FailImmediately(t *testing.T) {
	statuses := []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound}

	for _, status := range statuses {
		var requestCount int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&requestCount, 1)
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"error":{"message":"auth or endpoint error"}}`))
		}))

		tempDir := t.TempDir()
		cache := NewDeepSeekCache(filepath.Join(tempDir, "test_deepseek_cache.json"))

		reasoner := NewDeepSeekReasoner(DeepSeekConfig{
			APIKey:      "test-key",
			BaseURL:     server.URL,
			Cache:       cache,
			NetworkMode: provenance.NetworkOn,
		})

		bundle := map[string]any{
			"app_name": "test_app",
			"primary_binary": map[string]any{
				"sha256": "aaaaabbbbbcccccdddddaaaaabbbbbcccccddddd",
			},
		}

		res, err := reasoner.Analyze(context.Background(), bundle)
		server.Close()

		if err != nil {
			t.Fatalf("status %d returned error: %v", status, err)
		}
		if atomic.LoadInt32(&requestCount) != 1 {
			t.Errorf("status %d should not retry, made %d calls", status, atomic.LoadInt32(&requestCount))
		}
		if res.Classification != provenance.ClassificationUnknown {
			t.Errorf("status %d expected UNKNOWN, got %s", status, res.Classification)
		}
		if res.APIError == "" {
			t.Errorf("status %d expected APIError to be set", status)
		}
		if _, found := cache.Get(ComputeDeepSeekKey("aaaaabbbbbcccccdddddaaaaabbbbbcccccddddd", "test_app", "", 0)); found {
			t.Errorf("status %d should not be saved in cache", status)
		}
	}
}

func TestDeepSeekReasoner_HTTP429_RetryAndRecover(t *testing.T) {
	var requestCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := atomic.AddInt32(&requestCount, 1)
		if count <= 2 {
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":{"message":"Rate limit reached"}}`))
			return
		}
		// Third attempt succeeds
		response := deepseekChatResponse{
			Choices: []deepseekChoice{
				{
					Message: deepseekChatMessage{
						Content: `{"classification": "COMPANY", "confidence": "HIGH", "reasons": ["Internal Tool"]}`,
					},
				},
			},
		}
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	tempDir := t.TempDir()
	cache := NewDeepSeekCache(filepath.Join(tempDir, "test_deepseek_cache.json"))

	reasoner := NewDeepSeekReasoner(DeepSeekConfig{
		APIKey:      "test-key",
		BaseURL:     server.URL,
		Cache:       cache,
		NetworkMode: provenance.NetworkOn,
	})

	bundle := map[string]any{
		"app_name": "recovered_app",
		"primary_binary": map[string]any{
			"sha256": "9999888877776666555544443333222211110000",
		},
	}

	res, err := reasoner.Analyze(context.Background(), bundle)
	if err != nil {
		t.Fatalf("expected recovery after retries, got err: %v", err)
	}

	if atomic.LoadInt32(&requestCount) != 3 {
		t.Errorf("expected 3 total requests (1 initial + 2 retries), got %d", atomic.LoadInt32(&requestCount))
	}
	if res.Classification != provenance.ClassificationCompany {
		t.Errorf("expected COMPANY classification after recovery, got %s", res.Classification)
	}
}

func TestDeepSeekReasoner_HTTP429_RetriesExhausted(t *testing.T) {
	var requestCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":{"message":"Quota exceeded"}}`))
	}))
	defer server.Close()

	tempDir := t.TempDir()
	cache := NewDeepSeekCache(filepath.Join(tempDir, "test_deepseek_cache.json"))

	reasoner := NewDeepSeekReasoner(DeepSeekConfig{
		APIKey:      "test-key",
		BaseURL:     server.URL,
		Cache:       cache,
		NetworkMode: provenance.NetworkOn,
	})

	bundle := map[string]any{
		"app_name": "exhausted_app",
		"primary_binary": map[string]any{
			"sha256": "4444333322221111000044443333222211110000",
		},
	}

	res, err := reasoner.Analyze(context.Background(), bundle)
	if err != nil {
		t.Fatalf("expected nil error on exhausted retries, got %v", err)
	}

	// 1 initial + 2 retries = 3 calls
	if atomic.LoadInt32(&requestCount) != 3 {
		t.Errorf("expected 3 requests, got %d", atomic.LoadInt32(&requestCount))
	}
	if res.Classification != provenance.ClassificationUnknown {
		t.Errorf("expected UNKNOWN classification when retries exhausted, got %s", res.Classification)
	}
}

func TestDeepSeekReasoner_InconclusiveResultCached(t *testing.T) {
	var requestCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		response := deepseekChatResponse{
			Choices: []deepseekChoice{
				{
					Message: deepseekChatMessage{
						Content: `{"classification": "UNKNOWN", "confidence": "NONE", "reasons": ["Inconclusive evidence"]}`,
					},
				},
			},
		}
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	tempDir := t.TempDir()
	cache := NewDeepSeekCache(filepath.Join(tempDir, "test_deepseek_cache.json"))

	reasoner := NewDeepSeekReasoner(DeepSeekConfig{
		APIKey:      "test-key",
		BaseURL:     server.URL,
		Cache:       cache,
		NetworkMode: provenance.NetworkOn,
	})

	bundle := map[string]any{
		"app_name": "inconclusive_tool",
		"primary_binary": map[string]any{
			"sha256": "deadbeefcafebabedeadbeefcafebabe00001111",
		},
	}

	res1, _ := reasoner.Analyze(context.Background(), bundle)
	if res1.Classification != provenance.ClassificationUnknown {
		t.Errorf("expected UNKNOWN, got %s", res1.Classification)
	}

	// Second call must hit cache even for inconclusive UNKNOWN result
	res2, _ := reasoner.Analyze(context.Background(), bundle)
	if !res2.CacheHit {
		t.Errorf("expected inconclusive result to be cached (CacheHit == true)")
	}
	if atomic.LoadInt32(&requestCount) != 1 {
		t.Errorf("expected exactly 1 HTTP call, got %d", atomic.LoadInt32(&requestCount))
	}
}

func TestDeepSeekReasoner_ResponsesAPI_NativeWebSearch(t *testing.T) {
	var capturedResponsesReq deepseekResponsesRequest
	var responsesCallCount int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/responses" {
			atomic.AddInt32(&responsesCallCount, 1)
			_ = json.NewDecoder(r.Body).Decode(&capturedResponsesReq)

			resp := deepseekResponsesResponse{
				ID:     "resp-test-websearch-1",
				Status: "completed",
				OutputText: `{
					"classification": "THIRD_PARTY",
					"identity": "jq",
					"confidence": "VERY_HIGH",
					"publisher": "Stephen Dolan / jqlang",
					"reasons": ["Command-line JSON processor verified via official GitHub repository"],
					"sources": ["https://github.com/jqlang/jq"]
				}`,
				Output: []deepseekResponseOutput{
					{
						Type: "web_search_call",
						WebSearchCall: &deepseekWebSearchCall{
							Query: "jq json processor official release",
						},
					},
					{
						Type: "message",
						Role: "assistant",
						Content: []any{
							map[string]any{
								"type": "text",
								"text": "Found official repository for jq.",
								"annotations": []any{
									map[string]any{
										"type": "url_citation",
										"url":  "https://jqlang.github.io/jq/",
									},
								},
							},
						},
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	tempDir := t.TempDir()
	cache := NewDeepSeekCache(filepath.Join(tempDir, "test_deepseek_search_cache.json"))

	reasoner := NewDeepSeekReasoner(DeepSeekConfig{
		APIKey:          "test-deepseek-key",
		BaseURL:         server.URL,
		Cache:           cache,
		NetworkMode:     provenance.NetworkOn,
		EnableWebSearch: true,
	})

	bundle := map[string]any{
		"app_name": "jq",
		"primary_binary": map[string]any{
			"name":   "jq.exe",
			"sha256": "5555666677778888999900001111222233334444555566667777888899990000",
		},
	}

	result, err := reasoner.Analyze(context.Background(), bundle)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	// 1. Verify /responses endpoint was invoked with tools: [{"type": "web_search"}]
	if atomic.LoadInt32(&responsesCallCount) != 1 {
		t.Fatalf("expected 1 call to /responses, got %d", atomic.LoadInt32(&responsesCallCount))
	}
	if len(capturedResponsesReq.Tools) == 0 || capturedResponsesReq.Tools[0].Type != "web_search" {
		t.Errorf("expected tool type 'web_search', got %+v", capturedResponsesReq.Tools)
	}
	if capturedResponsesReq.ToolChoice != "auto" {
		t.Errorf("expected tool_choice 'auto', got %s", capturedResponsesReq.ToolChoice)
	}

	// 2. Verify returned result
	if result.Classification != provenance.ClassificationThirdParty {
		t.Errorf("expected THIRD_PARTY, got %s", result.Classification)
	}
	if result.Publisher != "Stephen Dolan / jqlang" {
		t.Errorf("expected publisher 'Stephen Dolan / jqlang', got %s", result.Publisher)
	}

	// 3. Verify sources include both model sources and search queries/annotations
	foundSearchQuery := false
	foundAnnotation := false
	for _, src := range result.Sources {
		if src == "DeepSeek Web Search: jq json processor official release" {
			foundSearchQuery = true
		}
		if src == "https://jqlang.github.io/jq/" {
			foundAnnotation = true
		}
	}
	if !foundSearchQuery {
		t.Errorf("expected web search query in sources, got: %+v", result.Sources)
	}
	if !foundAnnotation {
		t.Errorf("expected citation annotation in sources, got: %+v", result.Sources)
	}

	// 4. Verify evidence claims populated
	if len(result.EvidenceClaims) == 0 {
		t.Errorf("expected EvidenceClaims to be populated for Grounding Gate")
	}
}

func TestDeepSeekReasoner_ResponsesAPI_FallbackToChatCompletions(t *testing.T) {
	var responsesCalls int32
	var chatCalls int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/responses" {
			atomic.AddInt32(&responsesCalls, 1)
			// Simulate endpoint not found on older proxy or unsupported host
			http.NotFound(w, r)
			return
		}
		if r.URL.Path == "/chat/completions" {
			atomic.AddInt32(&chatCalls, 1)
			resp := deepseekChatResponse{
				Choices: []deepseekChoice{
					{
						Message: deepseekChatMessage{
							Content: `{
								"classification": "THIRD_PARTY",
								"identity": "Ninja Build",
								"confidence": "HIGH",
								"publisher": "Evan Martin / Kitware",
								"reasons": ["Recognized build tool"],
								"sources": ["https://ninja-build.org"]
							}`,
						},
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	tempDir := t.TempDir()
	cache := NewDeepSeekCache(filepath.Join(tempDir, "test_deepseek_fallback_cache.json"))

	reasoner := NewDeepSeekReasoner(DeepSeekConfig{
		APIKey:          "test-key",
		BaseURL:         server.URL,
		Cache:           cache,
		NetworkMode:     provenance.NetworkOn,
		EnableWebSearch: true,
	})

	bundle := map[string]any{
		"app_name": "ninja",
		"primary_binary": map[string]any{
			"name":   "ninja.exe",
			"sha256": "aaaaaaaaabbbbbbbbbcccccccccaaaaaaaaabbbbbbbbbcccccccccaaaaaaaaa",
		},
	}

	result, err := reasoner.Analyze(context.Background(), bundle)
	if err != nil {
		t.Fatalf("Analyze failed on fallback: %v", err)
	}

	if atomic.LoadInt32(&responsesCalls) != 1 {
		t.Errorf("expected 1 call to /responses before fallback, got %d", atomic.LoadInt32(&responsesCalls))
	}
	if atomic.LoadInt32(&chatCalls) != 1 {
		t.Errorf("expected 1 call to /chat/completions on fallback, got %d", atomic.LoadInt32(&chatCalls))
	}
	if result.Classification != provenance.ClassificationThirdParty {
		t.Errorf("expected THIRD_PARTY after fallback, got %s", result.Classification)
	}
}

func TestComputeDeepSeekKey_DistinctApps(t *testing.T) {
	k1 := ComputeDeepSeekKey("hash_aider", "aider", "1.0", 1)
	k2 := ComputeDeepSeekKey("hash_mongosh", "mongosh", "2.0", 1)
	if k1 == k2 {
		t.Errorf("expected distinct cache keys for aider and mongosh, got identical key: %s", k1)
	}

	// Even if two apps have identical binary hashes (e.g. shared shim), different app names must yield distinct keys
	kShim1 := ComputeDeepSeekKey("common_shim_hash", "app_one", "", 0)
	kShim2 := ComputeDeepSeekKey("common_shim_hash", "app_two", "", 0)
	if kShim1 == kShim2 {
		t.Errorf("expected distinct cache keys for different app names sharing shim hash")
	}

	// Two identical apps should match
	kShim1Dup := ComputeDeepSeekKey("common_shim_hash", "app_one", "", 0)
	if kShim1 != kShim1Dup {
		t.Errorf("expected identical cache keys for duplicate calls")
	}
}

func TestDeepSeekReasoner_StructBundleCaching_NoCollision(t *testing.T) {
	requestCount := int32(0)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		resp := deepseekChatResponse{
			Choices: []deepseekChoice{
				{
					Message: deepseekChatMessage{
						Role:    "assistant",
						Content: `{"classification":"UNKNOWN","confidence":"NONE","reasons":["Inconclusive"]}`,
					},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	cache := NewDeepSeekCache(filepath.Join(t.TempDir(), "test_struct_cache.json"))
	reasoner := NewDeepSeekReasoner(DeepSeekConfig{
		APIKey:      "test-key",
		BaseURL:     server.URL,
		Cache:       cache,
		NetworkMode: provenance.NetworkOn,
	})

	type mockBinary struct {
		Name   string `json:"name"`
		SHA256 string `json:"sha256"`
	}
	type mockBundle struct {
		AppName       string       `json:"app_name"`
		Version       string       `json:"version"`
		PrimaryBinary mockBinary   `json:"primary_binary"`
		Binaries      []mockBinary `json:"binaries"`
	}

	bundleAider := mockBundle{
		AppName:       "aider",
		Version:       "0.50.0",
		PrimaryBinary: mockBinary{Name: "aider.exe", SHA256: "hash_aider_123"},
	}
	bundleMongosh := mockBundle{
		AppName:       "mongosh",
		Version:       "2.5.1",
		PrimaryBinary: mockBinary{Name: "mongosh.exe", SHA256: "hash_mongosh_456"},
	}

	// 1. Analyze aider (should make 1 HTTP call)
	res1, err := reasoner.Analyze(context.Background(), bundleAider)
	if err != nil {
		t.Fatalf("Analyze failed for aider: %v", err)
	}
	if res1.CacheHit {
		t.Errorf("expected first call for aider to be a cache MISS")
	}

	// 2. Analyze mongosh (must NOT collide with aider; should make a second HTTP call)
	res2, err := reasoner.Analyze(context.Background(), bundleMongosh)
	if err != nil {
		t.Fatalf("Analyze failed for mongosh: %v", err)
	}
	if res2.CacheHit {
		t.Errorf("expected first call for mongosh to be a cache MISS (collided with aider!)")
	}

	if atomic.LoadInt32(&requestCount) != 2 {
		t.Errorf("expected exactly 2 HTTP requests for two distinct struct bundles, got %d", atomic.LoadInt32(&requestCount))
	}
}

