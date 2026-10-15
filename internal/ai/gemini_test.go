package ai

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/example/appaudit/internal/provenance"
)

func TestGeminiReasoner_NoAPIKey_FailsSafely(t *testing.T) {
	orig := os.Getenv(EnvGeminiAPIKey)
	_ = os.Unsetenv(EnvGeminiAPIKey)
	defer func() {
		if orig != "" {
			_ = os.Setenv(EnvGeminiAPIKey, orig)
		}
	}()

	reasoner := NewGeminiReasoner(GeminiConfig{
		APIKey: "",
	})

	res, err := reasoner.Analyze(context.Background(), map[string]any{"app_name": "unknown"})
	if err != nil {
		t.Fatalf("expected nil error on missing key, got %v", err)
	}
	if res.Classification != provenance.ClassificationUnknown {
		t.Errorf("expected UNKNOWN on missing key, got %v", res.Classification)
	}
}

func TestGeminiReasoner_MockHTTPServer_WithSearchGrounding(t *testing.T) {
	mockResponse := geminiGenerateResponse{
		Candidates: []geminiCandidate{
			{
				Content: geminiContent{
					Parts: []geminiPart{
						{
							Text: `{
  "classification": "THIRD_PARTY",
  "identity": {
    "name": "FFmpeg",
    "confidence": 0.95
  },
  "ownership": {
    "publisher": "FFmpeg Project",
    "confidence": 0.95
  },
  "reason": "Exact official release provenance established from ffmpeg.org official release notes",
  "evidence": [
    {
      "claim": "SHA256 b90225987bdd042cca09a1efb5e34e9848f2d1dbf5fbcd388753a44145522997 matches official 7.1.1 essentials release checksum",
      "source": "https://ffmpeg.org/releases/ffmpeg-7.1.1.tar.xz.asc",
      "source_type": "official",
      "evidence_strength": "authoritative",
      "supports": "provenance"
    }
  ],
  "research_performed": true
}`,
						},
					},
				},
				GroundingMetadata: &geminiGroundingMetadata{
					WebSearchQueries: []string{"ffmpeg 7.1.1 release checksum"},
					GroundingChunks: []geminiGroundingChunk{
						{
							Web: &geminiWebChunk{
								URI:   "https://ffmpeg.org/download.html",
								Title: "FFmpeg Official Downloads",
							},
						},
					},
				},
			},
		},
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-goog-api-key") != "test-api-key" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(mockResponse)
	}))
	defer ts.Close()

	tempDir, _ := os.MkdirTemp("", "gemini_test")
	defer os.RemoveAll(tempDir)
	cachePath := filepath.Join(tempDir, "cache.json")

	reasoner := NewGeminiReasoner(GeminiConfig{
		APIKey:     "test-api-key",
		BaseURL:    ts.URL,
		HTTPClient: ts.Client(),
		Cache:      NewGeminiCache(cachePath),
	})

	bundle := map[string]any{
		"app_name": "ffmpeg",
		"version":  "7.1.1",
		"primary_binary": map[string]any{
			"sha256": "b90225987bdd042cca09a1efb5e34e9848f2d1dbf5fbcd388753a44145522997",
		},
	}

	res, err := reasoner.Analyze(context.Background(), bundle)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if res.Classification != provenance.ClassificationThirdParty {
		t.Errorf("expected THIRD_PARTY, got %v", res.Classification)
	}
	if res.Identity != "FFmpeg" {
		t.Errorf("expected identity FFmpeg, got %s", res.Identity)
	}
	if len(res.Sources) == 0 {
		t.Errorf("expected grounding sources, got none")
	}
	if !res.ResearchPerformed {
		t.Errorf("expected ResearchPerformed to be true")
	}
	if res.CacheHit {
		t.Errorf("expected CacheHit to be false on fresh call")
	}

	ts.Close()
	cachedRes, err := reasoner.Analyze(context.Background(), bundle)
	if err != nil {
		t.Fatalf("unexpected error on cached call: %v", err)
	}
	if cachedRes.Classification != provenance.ClassificationThirdParty {
		t.Errorf("expected cached THIRD_PARTY, got %v", cachedRes.Classification)
	}
	if !cachedRes.CacheHit {
		t.Errorf("expected CacheHit to be true on cached call")
	}
}

func TestGeminiReasoner_HTTPError_FailsSafely(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}))
	defer ts.Close()

	reasoner := NewGeminiReasoner(GeminiConfig{
		APIKey:     "test-api-key",
		BaseURL:    ts.URL,
		HTTPClient: ts.Client(),
	})

	res, err := reasoner.Analyze(context.Background(), map[string]any{"app_name": "sample"})
	if err != nil {
		t.Fatalf("expected nil error on safe fallback, got %v", err)
	}
	if res.Classification != provenance.ClassificationUnknown {
		t.Errorf("expected UNKNOWN on server error, got %v", res.Classification)
	}
}

func TestGeminiReasoner_TransientError_RetriesAndRecovers(t *testing.T) {
	attempts := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts == 1 {
			// First attempt fails with transient 503 Service Unavailable
			http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
			return
		}
		// Second attempt succeeds with valid JSON
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(geminiGenerateResponse{
			Candidates: []geminiCandidate{
				{
					Content: geminiContent{
						Parts: []geminiPart{
							{Text: `{"classification": "THIRD_PARTY", "identity": {"name": "ripgrep", "confidence": 0.95}, "ownership": {"publisher": "BurntSushi", "confidence": 0.95}, "reason": "Official GitHub project"}`},
						},
					},
				},
			},
		})
	}))
	defer ts.Close()

	reasoner := NewGeminiReasoner(GeminiConfig{
		APIKey:     "test-api-key",
		BaseURL:    ts.URL,
		HTTPClient: ts.Client(),
		Cache:      NewGeminiCache(filepath.Join(t.TempDir(), "cache.json")),
	})

	res, err := reasoner.Analyze(context.Background(), map[string]any{"app_name": "ripgrep"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if attempts != 2 {
		t.Errorf("expected exactly 2 attempts (1 failure + 1 retry success), got %d", attempts)
	}
	if res.Classification != provenance.ClassificationThirdParty {
		t.Errorf("expected THIRD_PARTY after retry recovery, got %v", res.Classification)
	}
}

func TestGeminiReasoner_PermanentError_FailsImmediatelyWithoutRetry(t *testing.T) {
	attempts := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		// Permanent 401 Unauthorized
		http.Error(w, `{"error": {"code": 401, "message": "API key not valid"}}`, http.StatusUnauthorized)
	}))
	defer ts.Close()

	reasoner := NewGeminiReasoner(GeminiConfig{
		APIKey:     "bad-api-key",
		BaseURL:    ts.URL,
		HTTPClient: ts.Client(),
		Cache:      NewGeminiCache(filepath.Join(t.TempDir(), "cache.json")),
	})

	res, err := reasoner.Analyze(context.Background(), map[string]any{"app_name": "sample"})
	if err != nil {
		t.Fatalf("expected nil error on safe fallback, got %v", err)
	}
	if attempts != 1 {
		t.Errorf("expected permanent error to fail immediately on attempt 1 without retry, got %d attempts", attempts)
	}
	if res.Classification != provenance.ClassificationUnknown {
		t.Errorf("expected UNKNOWN on 401, got %v", res.Classification)
	}
}

func TestGeminiReasoner_UnusableResult_RetriesAndRecovers(t *testing.T) {
	attempts := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.Header().Set("Content-Type", "application/json")
		if attempts == 1 {
			// First attempt returns malformed text / empty candidates
			_ = json.NewEncoder(w).Encode(geminiGenerateResponse{
				Candidates: []geminiCandidate{},
			})
			return
		}
		// Second attempt succeeds with valid candidate
		_ = json.NewEncoder(w).Encode(geminiGenerateResponse{
			Candidates: []geminiCandidate{
				{
					Content: geminiContent{
						Parts: []geminiPart{
							{Text: `{"classification": "THIRD_PARTY", "identity": {"name": "curl", "confidence": 0.95}, "ownership": {"publisher": "curl project", "confidence": 0.95}, "reason": "Legitimate open source utility"}`},
						},
					},
				},
			},
		})
	}))
	defer ts.Close()

	reasoner := NewGeminiReasoner(GeminiConfig{
		APIKey:     "test-api-key",
		BaseURL:    ts.URL,
		HTTPClient: ts.Client(),
		Cache:      NewGeminiCache(filepath.Join(t.TempDir(), "cache.json")),
	})

	res, err := reasoner.Analyze(context.Background(), map[string]any{"app_name": "curl"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if attempts != 2 {
		t.Errorf("expected 2 attempts after retrying empty candidate, got %d", attempts)
	}
	if res.Classification != provenance.ClassificationThirdParty {
		t.Errorf("expected THIRD_PARTY after recovery, got %v", res.Classification)
	}
}

func TestGeminiReasoner_UnusableResult_ExhaustsRetriesSafely(t *testing.T) {
	attempts := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.Header().Set("Content-Type", "application/json")
		// Always returns malformed candidate
		_ = json.NewEncoder(w).Encode(geminiGenerateResponse{
			Candidates: []geminiCandidate{
				{
					Content: geminiContent{
						Parts: []geminiPart{
							{Text: `{"classification": "INVALID_UNKNOWN_TYPE"}`},
						},
					},
				},
			},
		})
	}))
	defer ts.Close()

	reasoner := NewGeminiReasoner(GeminiConfig{
		APIKey:     "test-api-key",
		BaseURL:    ts.URL,
		HTTPClient: ts.Client(),
		Cache:      NewGeminiCache(filepath.Join(t.TempDir(), "cache.json")),
	})

	res, err := reasoner.Analyze(context.Background(), map[string]any{"app_name": "random_tool"})
	if err != nil {
		t.Fatalf("expected nil error on safe fallback, got %v", err)
	}
	// Initial attempt + 2 retries = 3 attempts total
	if attempts != 3 {
		t.Errorf("expected 3 attempts before exhausting retries, got %d", attempts)
	}
	if res.Classification != provenance.ClassificationUnknown {
		t.Errorf("expected UNKNOWN after exhausting retries, got %v", res.Classification)
	}
}

func TestGeminiCache_KeyDeterminism(t *testing.T) {
	k1 := ComputeCacheKey("ffmpeg", "7.1", "hash123", 3)
	k2 := ComputeCacheKey("ffmpeg", "7.1", "hash123", 3)
	k3 := ComputeCacheKey("ffmpeg", "7.2", "hash123", 3)

	if k1 != k2 {
		t.Errorf("expected identical keys for identical inputs, got %s vs %s", k1, k2)
	}
	if k1 == k3 {
		t.Errorf("expected different keys for different versions")
	}
}

func TestGeminiCache_FilePathAndClear(t *testing.T) {
	path, err := CacheFilePath()
	if err != nil {
		t.Fatalf("unexpected error getting cache file path: %v", err)
	}
	if !strings.HasSuffix(path, "gemini_cache.json") {
		t.Errorf("expected suffix gemini_cache.json, got %s", path)
	}

	// Calling ClearGeminiCache when file doesn't exist should succeed without error
	if err := ClearGeminiCache(); err != nil {
		t.Errorf("ClearGeminiCache should not error if file doesn't exist or is removed: %v", err)
	}

	_ = CacheExists()
	_ = CacheEntryCount()
}

func TestGeminiReasoner_ModelSwapOn429_RecoversOnFallbackModel(t *testing.T) {
	calledModels := []string{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if strings.Contains(path, "gemini-3.5-flash-lite") {
			calledModels = append(calledModels, "gemini-3.5-flash-lite")
			// Primary model hit 429 rate limit / quota exceeded
			http.Error(w, `{"error": {"code": 429, "message": "Resource has been exhausted (e.g. check quota)."}}`, http.StatusTooManyRequests)
			return
		}
		if strings.Contains(path, "gemini-3.1-flash-lite") {
			calledModels = append(calledModels, "gemini-3.1-flash-lite")
			// First fallback model also hit 429 rate limit / quota exceeded
			http.Error(w, `{"error": {"code": 429, "message": "Resource has been exhausted (e.g. check quota)."}}`, http.StatusTooManyRequests)
			return
		}
		if strings.Contains(path, "gemini-3.8-flash") {
			calledModels = append(calledModels, "gemini-3.8-flash")
			// Second fallback model succeeds
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(geminiGenerateResponse{
				Candidates: []geminiCandidate{
					{
						Content: geminiContent{
							Parts: []geminiPart{
								{Text: `{"classification": "THIRD_PARTY", "identity": {"name": "jq", "confidence": 0.95}, "ownership": {"publisher": "Stephen Dolan", "confidence": 0.95}, "reason": "Command-line JSON processor"}`},
							},
						},
					},
				},
			})
			return
		}
		http.Error(w, "unexpected model", http.StatusBadRequest)
	}))
	defer ts.Close()

	reasoner := NewGeminiReasoner(GeminiConfig{
		APIKey:         "test-api-key",
		Model:          "gemini-3.5-flash-lite",
		FallbackModels: []string{"gemini-3.1-flash-lite", "gemini-3.8-flash", "gemini-3.5-flash"},
		BaseURL:        ts.URL,
		HTTPClient:     ts.Client(),
		Cache:          NewGeminiCache(filepath.Join(t.TempDir(), "cache.json")),
	})

	res, err := reasoner.Analyze(context.Background(), map[string]any{"app_name": "jq"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(calledModels) != 3 {
		t.Fatalf("expected 3 models called (3.5-flash-lite -> 3.1-flash-lite -> 3.8-flash), got: %v", calledModels)
	}
	if calledModels[0] != "gemini-3.5-flash-lite" || calledModels[1] != "gemini-3.1-flash-lite" || calledModels[2] != "gemini-3.8-flash" {
		t.Errorf("expected sequence [gemini-3.5-flash-lite, gemini-3.1-flash-lite, gemini-3.8-flash], got: %v", calledModels)
	}
	if res.Classification != provenance.ClassificationThirdParty {
		t.Errorf("expected THIRD_PARTY from swapped model, got %v", res.Classification)
	}

	foundSwapReason := false
	for _, r := range res.Reasons {
		if strings.Contains(r, "Model swap triggered on HTTP 429") {
			foundSwapReason = true
			break
		}
	}
	if !foundSwapReason {
		t.Errorf("expected reason noting model swap, got reasons: %v", res.Reasons)
	}
}

func TestGeminiReasoner_ModelSwapOn429_AllModelsExhausted(t *testing.T) {
	calledModels := []string{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if strings.Contains(path, "gemini-3.5-flash-lite") {
			calledModels = append(calledModels, "gemini-3.5-flash-lite")
		} else if strings.Contains(path, "gemini-3.1-flash-lite") {
			calledModels = append(calledModels, "gemini-3.1-flash-lite")
		} else if strings.Contains(path, "gemini-3.8-flash") {
			calledModels = append(calledModels, "gemini-3.8-flash")
		} else if strings.Contains(path, "gemini-3.5-flash") {
			calledModels = append(calledModels, "gemini-3.5-flash")
		}
		// Always return 429 (for both search-grounded and direct attempts)
		http.Error(w, `{"error": {"code": 429, "message": "Quota exceeded"}}`, http.StatusTooManyRequests)
	}))
	defer ts.Close()

	reasoner := NewGeminiReasoner(GeminiConfig{
		APIKey:         "test-api-key",
		Model:          "gemini-3.5-flash-lite",
		FallbackModels: []string{"gemini-3.1-flash-lite", "gemini-3.8-flash", "gemini-3.5-flash"},
		BaseURL:        ts.URL,
		HTTPClient:     ts.Client(),
		Cache:          NewGeminiCache(filepath.Join(t.TempDir(), "cache.json")),
	})

	res, err := reasoner.Analyze(context.Background(), map[string]any{"app_name": "tool"})
	if err != nil {
		t.Fatalf("expected nil error on safe fallback, got %v", err)
	}
	if res.Classification != provenance.ClassificationUnknown {
		t.Errorf("expected UNKNOWN when all models exhausted, got %v", res.Classification)
	}
	// 4 search-grounded models tried, then 1 direct reasoning fallback tried on primary model
	if len(calledModels) != 5 ||
		calledModels[0] != "gemini-3.5-flash-lite" ||
		calledModels[1] != "gemini-3.1-flash-lite" ||
		calledModels[2] != "gemini-3.8-flash" ||
		calledModels[3] != "gemini-3.5-flash" ||
		calledModels[4] != "gemini-3.5-flash-lite" {
		t.Errorf("expected sequence [gemini-3.5-flash-lite, gemini-3.1-flash-lite, gemini-3.8-flash, gemini-3.5-flash, gemini-3.5-flash-lite] -> UNKNOWN, got: %v", calledModels)
	}
}

func TestGeminiReasoner_ModelSwapOn429_DirectReasoningFallbackSucceeds(t *testing.T) {
	calledBodies := []string{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		sBody := string(body)
		calledBodies = append(calledBodies, sBody)
		if strings.Contains(sBody, "google_search") {
			// Search grounding rejected with 429 quota exceeded
			http.Error(w, `{"error": {"code": 429, "message": "Search grounding quota exceeded"}}`, http.StatusTooManyRequests)
			return
		}
		// Direct reasoning succeeds
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(geminiGenerateResponse{
			Candidates: []geminiCandidate{
				{
					Content: geminiContent{
						Parts: []geminiPart{
							{Text: `{"classification": "THIRD_PARTY", "identity": {"name": "aider", "confidence": 1.0}, "ownership": {"publisher": "Paul Gauthier", "confidence": 1.0}, "reason": "Open source AI pair programmer", "evidence": [{"claim": "AI coding assistant", "source": "github.com", "source_type": "official", "evidence_strength": "authoritative", "supports": "identity"}], "research_performed": true}`},
						},
					},
				},
			},
		})
	}))
	defer ts.Close()

	reasoner := NewGeminiReasoner(GeminiConfig{
		APIKey:         "test-api-key",
		Model:          "gemini-3.5-flash-lite",
		FallbackModels: []string{"gemini-3.1-flash-lite", "gemini-3.8-flash", "gemini-3.5-flash"},
		BaseURL:        ts.URL,
		HTTPClient:     ts.Client(),
		Cache:          NewGeminiCache(filepath.Join(t.TempDir(), "cache.json")),
	})

	res, err := reasoner.Analyze(context.Background(), map[string]any{"app_name": "aider"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Classification != provenance.ClassificationThirdParty {
		t.Fatalf("expected THIRD_PARTY from direct reasoning fallback, got %v", res.Classification)
	}
	if res.Identity != "aider" || res.Publisher != "Paul Gauthier" {
		t.Errorf("unexpected identity: %s, publisher: %s", res.Identity, res.Publisher)
	}
}

func TestGeminiReasoner_FatalClientErrors_FailImmediatelyWithoutFallback(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound} {
		attempts := 0
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			attempts++
			http.Error(w, `{"error": {"code": 400, "message": "fatal error"}}`, status)
		}))

		reasoner := NewGeminiReasoner(GeminiConfig{
			APIKey:         "test-api-key",
			Model:          "gemini-3.5-flash-lite",
			FallbackModels: []string{"gemini-3.1-flash-lite", "gemini-3.8-flash", "gemini-3.5-flash"},
			BaseURL:        ts.URL,
			HTTPClient:     ts.Client(),
			Cache:          NewGeminiCache(filepath.Join(t.TempDir(), "cache.json")),
		})

		res, err := reasoner.Analyze(context.Background(), map[string]any{"app_name": "fatal_test"})
		ts.Close()
		if err != nil {
			t.Fatalf("expected nil error on fallback, got %v", err)
		}
		if attempts != 1 {
			t.Errorf("status %d should fail immediately without retrying or fallback, got %d attempts", status, attempts)
		}
		if res.Classification != provenance.ClassificationUnknown {
			t.Errorf("status %d should yield UNKNOWN, got %v", status, res.Classification)
		}
	}
}

func TestGeminiReasoner_SubGemini3Models_RejectedAndClamped(t *testing.T) {
	// 1. Assert detection of sub-Gemini-3 models
	subModels := []string{
		"gemini-2.5-flash",
		"gemini-2.5-pro",
		"gemini-2.0-flash",
		"gemini-2.0-flash-exp",
		"gemini-1.5-flash",
		"gemini-1.5-pro",
		"models/gemini-2.5-flash",
		"models/gemini-1.5-flash",
	}
	for _, m := range subModels {
		if !IsSubGemini3Model(m) {
			t.Errorf("expected IsSubGemini3Model(%q) to be true", m)
		}
		if err := ValidateGeminiModel(m); err == nil {
			t.Errorf("expected ValidateGeminiModel(%q) to return error", m)
		}
	}

	gemini3Models := []string{
		"gemini-3.5-flash-lite",
		"gemini-3.1-flash-lite",
		"gemini-3.8-flash",
		"gemini-3.5-flash",
		"gemini-3.0-pro",
		"models/gemini-3.5-flash-lite",
	}
	for _, m := range gemini3Models {
		if IsSubGemini3Model(m) {
			t.Errorf("expected IsSubGemini3Model(%q) to be false", m)
		}
		if err := ValidateGeminiModel(m); err != nil {
			t.Errorf("expected ValidateGeminiModel(%q) to return nil, got %v", m, err)
		}
	}

	// 2. Assert NewGeminiReasoner clamps legacy sub-Gemini-3 primary model to DefaultGeminiModel
	for _, m := range []string{"gemini-2.5-flash", "gemini-2.0-flash", "gemini-1.5-pro"} {
		r := NewGeminiReasoner(GeminiConfig{
			Model: m,
		})
		if r.config.Model != DefaultGeminiModel {
			t.Errorf("expected model %q to be clamped to %s, got %s", m, DefaultGeminiModel, r.config.Model)
		}
	}

	// 3. Assert NewGeminiReasoner purges sub-Gemini-3 models from FallbackModels
	mixedFallbacks := []string{
		"gemini-2.5-flash",
		"gemini-3.8-flash",
		"gemini-2.0-flash",
		"gemini-3.1-flash-lite",
		"gemini-1.5-pro",
	}
	rMixed := NewGeminiReasoner(GeminiConfig{
		Model:          "gemini-3.5-flash-lite",
		FallbackModels: mixedFallbacks,
	})
	expectedFallbacks := []string{"gemini-3.8-flash", "gemini-3.1-flash-lite"}
	if len(rMixed.config.FallbackModels) != len(expectedFallbacks) {
		t.Fatalf("expected %d sanitized fallbacks, got %v", len(expectedFallbacks), rMixed.config.FallbackModels)
	}
	for i, fb := range expectedFallbacks {
		if rMixed.config.FallbackModels[i] != fb {
			t.Errorf("expected fallback index %d to be %s, got %s", i, fb, rMixed.config.FallbackModels[i])
		}
	}

	// 4. Assert that if all provided FallbackModels are sub-Gemini-3, it resets to DefaultFallbackModels
	rAllSub := NewGeminiReasoner(GeminiConfig{
		Model:          "gemini-3.5-flash-lite",
		FallbackModels: []string{"gemini-2.5-flash", "gemini-1.5-flash"},
	})
	if len(rAllSub.config.FallbackModels) != len(DefaultFallbackModels) {
		t.Fatalf("expected DefaultFallbackModels, got %v", rAllSub.config.FallbackModels)
	}
	for i, fb := range DefaultFallbackModels {
		if rAllSub.config.FallbackModels[i] != fb {
			t.Errorf("expected default fallback %s, got %s", fb, rAllSub.config.FallbackModels[i])
		}
	}

	// 5. Mock HTTP Server: Verify that sub-Gemini-3 models are strictly prohibited across the entire execution pipeline
	queriedEndpoints := []string{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queriedEndpoints = append(queriedEndpoints, r.URL.Path)
		if strings.Contains(r.URL.Path, "gemini-2.") || strings.Contains(r.URL.Path, "gemini-1.") {
			t.Errorf("PROHIBITED: sub-Gemini-3 model queried on endpoint: %s", r.URL.Path)
			http.Error(w, "prohibited legacy model", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(geminiGenerateResponse{
			Candidates: []geminiCandidate{
				{
					Content: geminiContent{
						Parts: []geminiPart{
							{Text: `{"classification": "THIRD_PARTY", "identity": {"name": "sample", "confidence": 0.9}, "ownership": {"publisher": "vendor", "confidence": 0.9}, "reason": "verified"}`},
						},
					},
				},
			},
		})
	}))
	defer ts.Close()

	guardReasoner := NewGeminiReasoner(GeminiConfig{
		APIKey:         "test-api-key",
		Model:          "gemini-2.5-flash", // configured with sub-Gemini-3 model
		FallbackModels: []string{"gemini-2.0-flash", "gemini-3.8-flash"},
		BaseURL:        ts.URL,
		HTTPClient:     ts.Client(),
		Cache:          NewGeminiCache(filepath.Join(t.TempDir(), "cache.json")),
	})

	if guardReasoner.config.Model != DefaultGeminiModel {
		t.Fatalf("expected clamped model %s, got %s", DefaultGeminiModel, guardReasoner.config.Model)
	}
	if len(guardReasoner.config.FallbackModels) != 1 || guardReasoner.config.FallbackModels[0] != "gemini-3.8-flash" {
		t.Fatalf("expected fallback [gemini-3.8-flash], got %v", guardReasoner.config.FallbackModels)
	}

	res, err := guardReasoner.Analyze(context.Background(), map[string]any{"app_name": "sample"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Classification != provenance.ClassificationThirdParty {
		t.Errorf("expected THIRD_PARTY, got %v", res.Classification)
	}
	for _, ep := range queriedEndpoints {
		if strings.Contains(ep, "gemini-2.") || strings.Contains(ep, "gemini-1.") {
			t.Fatalf("sub-Gemini-3 model was invoked in pipeline: %s", ep)
		}
	}
}

func TestGeminiReasoner_ReasonBatch_MockHTTPServer(t *testing.T) {
	bundles := []EvidenceBundle{
		{
			SHA256:     "hash-aider-111",
			AppName:    "aider",
			BinaryName: "aider.exe",
			Path:       "C:\\Users\\user\\AppData\\Local\\Programs\\Python\\Scripts\\aider.exe",
		},
		{
			SHA256:     "hash-mongosh-222",
			AppName:    "mongosh",
			BinaryName: "mongosh.exe",
			Path:       "C:\\Program Files\\mongosh\\bin\\mongosh.exe",
		},
		{
			SHA256:     "hash-jq-333",
			AppName:    "jq",
			BinaryName: "jq.exe",
			Path:       "C:\\ProgramData\\chocolatey\\bin\\jq.exe",
		},
		{
			SHA256:     "hash-git-444",
			AppName:    "git",
			BinaryName: "git.exe",
			Path:       "C:\\Program Files\\Git\\bin\\git.exe",
		},
		{
			SHA256:     "hash-internal-555",
			AppName:    "InternalTool",
			BinaryName: "InternalTool.exe",
			Path:       "C:\\Internal\\InternalTool.exe",
		},
	}

	requestCount := 0
	var receivedBody string

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		body, _ := io.ReadAll(r.Body)
		receivedBody = string(body)

		// Assert googleSearch tool is present and search-grounded batch payload is structured
		if !strings.Contains(receivedBody, "googleSearch") && !strings.Contains(receivedBody, "google_search") {
			t.Errorf("expected googleSearch tool in request, got: %s", receivedBody)
		}
		if !strings.Contains(receivedBody, "JSON") {
			t.Errorf("expected JSON system instruction in request, got: %s", receivedBody)
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(geminiGenerateResponse{
			Candidates: []geminiCandidate{
				{
					Content: geminiContent{
						Parts: []geminiPart{
							{
								Text: `[
  {
    "sha256": "hash-aider-111",
    "classification": "THIRD_PARTY",
    "confidence": "HIGH",
    "identity": "aider",
    "publisher": "Paul Gauthier",
    "reasons": ["AI pair programming CLI tool"]
  },
  {
    "sha256": "hash-mongosh-222",
    "classification": "THIRD_PARTY",
    "confidence": "HIGH",
    "identity": "mongosh",
    "publisher": "MongoDB Inc",
    "reasons": ["MongoDB Shell"]
  },
  {
    "sha256": "hash-jq-333",
    "classification": "THIRD_PARTY",
    "confidence": "HIGH",
    "identity": "jq",
    "publisher": "Stephen Dolan",
    "reasons": ["Command-line JSON processor"]
  },
  {
    "sha256": "hash-git-444",
    "classification": "THIRD_PARTY",
    "confidence": "HIGH",
    "identity": "git",
    "publisher": "Git Community",
    "reasons": ["Fast version control system"]
  },
  {
    "sha256": "hash-internal-555",
    "classification": "FIRST_PARTY",
    "confidence": "HIGH",
    "identity": "InternalTool",
    "publisher": "Company",
    "reasons": ["Internal company proprietary build"]
  }
]`,
							},
						},
					},
					GroundingMetadata: &geminiGroundingMetadata{
						WebSearchQueries: []string{"aider github", "mongosh mongodb"},
						GroundingChunks: []geminiGroundingChunk{
							{Web: &geminiWebChunk{URI: "https://github.com/paul-gauthier/aider", Title: "aider"}},
							{Web: &geminiWebChunk{URI: "https://www.mongodb.com/docs/mongodb-shell/", Title: "mongosh"}},
						},
					},
				},
			},
			UsageMetadata: &geminiUsageMetadata{
				PromptTokenCount:     500,
				CandidatesTokenCount: 250,
				TotalTokenCount:      750,
			},
		})
	}))
	defer ts.Close()

	cachePath := filepath.Join(t.TempDir(), "gemini_cache.json")
	cache := NewGeminiCache(cachePath)

	reasoner := NewGeminiReasoner(GeminiConfig{
		APIKey:      "test-batch-api-key",
		Model:       "gemini-3.5-flash-lite",
		BaseURL:     ts.URL,
		HTTPClient:  ts.Client(),
		Cache:       cache,
		ChunkSize:   5,
		PacingDelay: -1, // fast execution for tests
	})

	results, err := reasoner.ReasonBatch(context.Background(), bundles)
	if err != nil {
		t.Fatalf("unexpected ReasonBatch error: %v", err)
	}

	if len(results) != 5 {
		t.Fatalf("expected 5 results, got %d", len(results))
	}
	if requestCount != 1 {
		t.Errorf("expected exactly 1 chunk API call for 5 items, got %d", requestCount)
	}

	// Verify aider
	if results[0].Classification != provenance.ClassificationThirdParty {
		t.Errorf("item 0 (aider): expected THIRD_PARTY, got %v", results[0].Classification)
	}
	if results[0].Identity != "aider" {
		t.Errorf("item 0 (aider): expected identity 'aider', got %q", results[0].Identity)
	}
	if results[0].Publisher != "Paul Gauthier" {
		t.Errorf("item 0 (aider): expected publisher 'Paul Gauthier', got %q", results[0].Publisher)
	}

	// Verify mongosh
	if results[1].Classification != provenance.ClassificationThirdParty {
		t.Errorf("item 1 (mongosh): expected THIRD_PARTY, got %v", results[1].Classification)
	}
	if results[1].Publisher != "MongoDB Inc" {
		t.Errorf("item 1 (mongosh): expected publisher 'MongoDB Inc', got %q", results[1].Publisher)
	}

	// Verify jq
	if results[2].Classification != provenance.ClassificationThirdParty {
		t.Errorf("item 2 (jq): expected THIRD_PARTY, got %v", results[2].Classification)
	}
	if results[2].Publisher != "Stephen Dolan" {
		t.Errorf("item 2 (jq): expected publisher 'Stephen Dolan', got %q", results[2].Publisher)
	}

	// Verify git
	if results[3].Classification != provenance.ClassificationThirdParty {
		t.Errorf("item 3 (git): expected THIRD_PARTY, got %v", results[3].Classification)
	}

	// Verify InternalTool (FIRST_PARTY -> ClassificationCompany)
	if results[4].Classification != provenance.ClassificationCompany {
		t.Errorf("item 4 (InternalTool): expected COMPANY (from FIRST_PARTY), got %v", results[4].Classification)
	}

	// Verify cache persistence
	for _, b := range bundles {
		cacheKey := ComputeCacheKey(b.AppName, b.Version, b.SHA256, b.SiblingCount)
		cached, found := cache.Get(cacheKey)
		if !found {
			t.Errorf("expected bundle %s to be persisted in cache, but was not found", b.AppName)
		}
		if cached.Classification != provenance.ClassificationThirdParty && cached.Classification != provenance.ClassificationCompany {
			t.Errorf("cached classification for %s unexpected: %v", b.AppName, cached.Classification)
		}
	}
}

func TestGeminiReasoner_ReasonBatch_429BackoffResilience(t *testing.T) {
	callCount := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		http.Error(w, `{"error": {"code": 429, "message": "Resource exhausted"}}`, http.StatusTooManyRequests)
	}))
	defer ts.Close()

	bundles := []EvidenceBundle{
		{AppName: "app1", SHA256: "hash1"},
		{AppName: "app2", SHA256: "hash2"},
	}

	reasoner := NewGeminiReasoner(GeminiConfig{
		APIKey:      "test-batch-api-key",
		Model:       "gemini-3.5-flash-lite",
		BaseURL:     ts.URL,
		HTTPClient:  ts.Client(),
		Cache:       NewGeminiCache(filepath.Join(t.TempDir(), "cache.json")),
		ChunkSize:   5,
		PacingDelay: -1, // fast execution for tests
	})

	results, err := reasoner.ReasonBatch(context.Background(), bundles)
	if err != nil {
		t.Fatalf("unexpected error (should fail safely to UNKNOWN, not error): %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	for i, res := range results {
		if res.Classification != provenance.ClassificationUnknown {
			t.Errorf("item %d: expected UNKNOWN on exhausted 429 retries, got %v", i, res.Classification)
		}
		if !strings.Contains(res.APIError, "429") {
			t.Errorf("item %d: expected 429 in APIError, got %q", i, res.APIError)
		}
	}
}

