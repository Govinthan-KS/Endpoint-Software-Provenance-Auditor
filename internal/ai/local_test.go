package ai

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/example/appaudit/internal/provenance"
)

func TestLocalReasoner_PreflightGPUCheck_Pass(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/ps" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"models": [
					{
						"name": "audit-phi:q6k",
						"model": "audit-phi:q6k",
						"size": 3751364525,
						"size_vram": 3751364525
					}
				]
			}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	reasoner := NewLocalReasoner(DefaultOllamaModel, nil, nil, ts.URL)
	if err := reasoner.PreflightGPUCheck(context.Background()); err != nil {
		t.Fatalf("expected preflight check to pass, got: %v", err)
	}
}

func TestLocalReasoner_PreflightGPUCheck_HardRefusal(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/ps" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"models": [
					{
						"name": "audit-phi:q6k",
						"model": "audit-phi:q6k",
						"size": 3751364525,
						"size_vram": 2000000000
					}
				]
			}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	reasoner := NewLocalReasoner(DefaultOllamaModel, nil, nil, ts.URL)
	err := reasoner.PreflightGPUCheck(context.Background())
	if err == nil {
		t.Fatal("expected HARD REFUSAL error, got nil")
	}

	expectedSubstr := "HARD REFUSAL: model is not 100% in VRAM; CPU offload strictly prohibited"
	if !strings.Contains(err.Error(), expectedSubstr) {
		t.Fatalf("expected error to contain %q, got: %v", expectedSubstr, err)
	}

	// Also verify ReasonBatch halts on GPU check failure
	results, batchErr := reasoner.ReasonBatch(context.Background(), []EvidenceBundle{
		{AppName: "test-app"},
	})
	if batchErr == nil {
		t.Fatal("expected ReasonBatch to return error on hard refusal")
	}
	if len(results) != 1 || results[0].Classification != provenance.ClassificationUnknown {
		t.Fatalf("expected UNKNOWN classification on refusal, got: %+v", results)
	}
	if !strings.Contains(results[0].APIError, expectedSubstr) {
		t.Fatalf("expected APIError to contain %q, got: %s", expectedSubstr, results[0].APIError)
	}
}

func TestLocalReasoner_ReasonBatch_SuccessAndCache(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "ollama_cache_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	cacheFile := filepath.Join(tmpDir, "ollama_cache.json")
	cache := NewOllamaCache(cacheFile)

	chatCallCount := 0
	tsOllama := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/ps" {
			_, _ = w.Write([]byte(`{"models": [{"name": "audit-phi:q6k", "size": 3751364525, "size_vram": 3751364525}]}`))
			return
		}
		if r.URL.Path == "/api/chat" {
			chatCallCount++
			var req ollamaChatRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			// Validate payload constraints
			if req.Model != DefaultOllamaModel {
				t.Errorf("expected model %q, got %q", DefaultOllamaModel, req.Model)
			}
			if req.Format != "json" {
				t.Errorf("expected format 'json', got %q", req.Format)
			}
			if req.KeepAlive != "15m" {
				t.Errorf("expected keep_alive '15m', got %q", req.KeepAlive)
			}
			if req.Options.NumGPU != 99 {
				t.Errorf("expected num_gpu 99, got %d", req.Options.NumGPU)
			}
			if req.Options.NumCtx != 4096 {
				t.Errorf("expected num_ctx 4096, got %d", req.Options.NumCtx)
			}
			if req.Options.Temperature != 0.0 {
				t.Errorf("expected temperature 0.0, got %f", req.Options.Temperature)
			}

			// Validate domain-aware search evidence format and weighting instructions
			if len(req.Messages) == 0 {
				t.Fatalf("expected at least 1 message in chat request")
			}
			promptContent := req.Messages[0].Content
			if !strings.Contains(promptContent, "[Search Evidence from Web Retrieval]") {
				t.Errorf("prompt missing search evidence header: %s", promptContent)
			}
			if !strings.Contains(promptContent, "Result 1: (github.com) - Aider AI Coding Tool") {
				t.Errorf("prompt missing Result 1 with domain: %s", promptContent)
			}
			if !strings.Contains(promptContent, "\"AI pair programming in your terminal.\"") {
				t.Errorf("prompt missing quoted snippet: %s", promptContent)
			}
			if !strings.Contains(promptContent, "Give higher evidential weight to official project repositories") {
				t.Errorf("prompt missing weighting instructions: %s", promptContent)
			}

			aiResp := AIOutputSchema{
				Classification: "THIRD_PARTY",
				Confidence:     "HIGH",
				Identity:       "Aider Coding Tool",
				Publisher:      "Paul Gauthier",
				Evidence:       "Matches open source repositories",
				Conclusion:     "Legitimate third-party open source application",
				Reasons:        []string{"Public Python tool on PyPI"},
			}
			aiJson, _ := json.Marshal(aiResp)

			resp := ollamaChatResponse{
				PromptEvalCount: 150,
				EvalCount:       65,
			}
			resp.Message.Role = "assistant"
			resp.Message.Content = string(aiJson)

			_ = json.NewEncoder(w).Encode(resp)
			return
		}
		http.NotFound(w, r)
	}))
	defer tsOllama.Close()

	// Mock SearXNG server
	searxCount := 0
	tsSearx := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		searxCount++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(searxngResponse{
			Results: []struct {
				Title   string `json:"title"`
				Content string `json:"content"`
				URL     string `json:"url"`
			}{
				{
					Title:   "Aider AI Coding Tool",
					Content: "AI pair programming in your terminal.",
					URL:     "https://github.com/paul-gauthier/aider",
				},
			},
		})
	}))
	defer tsSearx.Close()

	searxProvider := NewSearXNGProvider(tsSearx.URL)
	reasoner := NewLocalReasoner(DefaultOllamaModel, searxProvider, cache, tsOllama.URL)

	bundle := EvidenceBundle{
		AppName:         "aider",
		BinaryName:      "aider.exe",
		SHA256:          "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
		Publisher:       "Paul Gauthier",
		Version:         "0.70.0",
		EvidenceSummary: "Standalone terminal executable",
	}

	// First execution: should invoke SearXNG and Ollama
	results, err := reasoner.ReasonBatch(context.Background(), []EvidenceBundle{bundle})
	if err != nil {
		t.Fatalf("unexpected ReasonBatch error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	res := results[0]
	if res.Classification != provenance.ClassificationThirdParty {
		t.Errorf("expected THIRD_PARTY, got %v", res.Classification)
	}
	if res.Confidence != provenance.ConfidenceHigh {
		t.Errorf("expected HIGH confidence, got %v", res.Confidence)
	}
	if res.Identity != "Aider Coding Tool" {
		t.Errorf("expected identity 'Aider Coding Tool', got %q", res.Identity)
	}
	if res.CacheHit {
		t.Errorf("first run should not be a cache hit")
	}
	if chatCallCount != 1 {
		t.Errorf("expected 1 chat call, got %d", chatCallCount)
	}
	if searxCount != 1 {
		t.Errorf("expected 1 SearXNG call, got %d", searxCount)
	}

	// Second execution: must be served from cache without invoking Ollama or SearXNG again
	resultsCached, err := reasoner.ReasonBatch(context.Background(), []EvidenceBundle{bundle})
	if err != nil {
		t.Fatalf("unexpected ReasonBatch cached error: %v", err)
	}
	if len(resultsCached) != 1 {
		t.Fatalf("expected 1 cached result, got %d", len(resultsCached))
	}
	if !resultsCached[0].CacheHit {
		t.Errorf("second run must be a cache hit")
	}
	if chatCallCount != 1 {
		t.Errorf("chatCallCount increased unexpectedly: %d", chatCallCount)
	}
	if searxCount != 1 {
		t.Errorf("searxCount increased unexpectedly: %d", searxCount)
	}
}

func TestLocalReasoner_GracefulFallback_SearXNGOffline(t *testing.T) {
	tsOllama := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/ps" {
			_, _ = w.Write([]byte(`{"models": [{"name": "audit-phi:q6k", "size": 100, "size_vram": 100}]}`))
			return
		}
		if r.URL.Path == "/api/chat" {
			aiResp := AIOutputSchema{
				Classification: "THIRD_PARTY",
				Confidence:     "MEDIUM",
				Identity:       "Offline App",
				Publisher:      "Acme Inc",
				Evidence:       "Analyzed without web snippets",
				Conclusion:     "Classified successfully despite offline SearXNG",
				Reasons:        []string{"Signed PE header"},
			}
			aiJson, _ := json.Marshal(aiResp)

			resp := ollamaChatResponse{}
			resp.Message.Role = "assistant"
			resp.Message.Content = string(aiJson)
			_ = json.NewEncoder(w).Encode(resp)
			return
		}
		http.NotFound(w, r)
	}))
	defer tsOllama.Close()

	// SearXNG pointed to non-existent endpoint
	offlineSearXNG := NewSearXNGProvider("http://127.0.0.1:58999")
	reasoner := NewLocalReasoner(DefaultOllamaModel, offlineSearXNG, NewOllamaCache(), tsOllama.URL)

	results, err := reasoner.ReasonBatch(context.Background(), []EvidenceBundle{
		{AppName: "offline-app", Publisher: "Acme Inc"},
	})
	if err != nil {
		t.Fatalf("expected ReasonBatch to succeed even when SearXNG is offline, got: %v", err)
	}
	if len(results) != 1 || results[0].Classification != provenance.ClassificationThirdParty {
		t.Fatalf("expected successful classification, got: %+v", results)
	}
}

func TestLocalReasoner_PromptFormatting_DomainAndExtendedSnippets(t *testing.T) {
	bundle := EvidenceBundle{
		AppName:   "flask",
		Publisher: "Pallets",
		Version:   "3.0.0",
	}
	longSnippet := strings.Repeat("F", 550)
	searchResults := []SearchResult{
		{
			Title:   "Flask on PyPI",
			Snippet: longSnippet,
			URL:     "https://pypi.org/project/Flask/",
		},
		{
			Title:   "Flask on GitHub",
			Snippet: "The Python micro framework for building web applications.",
			URL:     "https://github.com/pallets/flask",
		},
		{
			Title:   "Flask on Pallets Projects",
			Snippet: "Official release portal and downloads.",
			URL:     "https://palletsprojects.com/p/flask/",
		},
	}

	prompt := buildLocalPrompt(bundle, searchResults)

	if !strings.Contains(prompt, "[Search Evidence from Web Retrieval]") {
		t.Errorf("prompt missing search evidence header: %s", prompt)
	}
	if !strings.Contains(prompt, "Result 1: (pypi.org) - Flask on PyPI") {
		t.Errorf("prompt missing Result 1 with extracted domain: %s", prompt)
	}
	if !strings.Contains(prompt, "Result 2: (github.com) - Flask on GitHub") {
		t.Errorf("prompt missing Result 2 with extracted domain: %s", prompt)
	}
	if !strings.Contains(prompt, "Result 3: (palletsprojects.com) - Flask on Pallets Projects") {
		t.Errorf("prompt missing Result 3 with extracted domain: %s", prompt)
	}
	if !strings.Contains(prompt, "\""+longSnippet+"\"") {
		t.Errorf("prompt missing 550 character quoted snippet")
	}
	if !strings.Contains(prompt, "Give higher evidential weight to official project repositories") {
		t.Errorf("prompt missing weighting instructions: %s", prompt)
	}
}
