package classifier

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/example/appaudit/internal/model"
)

func TestEnricherOfflineBypass(t *testing.T) {
	tempDir := t.TempDir()
	cache := NewResolutionCache(filepath.Join(tempDir, "cache.json"))
	enricher := NewEnricher(cache)

	// Simulate offline state
	offline := false
	enricher.isOnline = &offline

	apps := []model.Application{
		{
			Name:     "custom_app",
			Path:     `C:\Tools\custom_app.exe`,
			Category: model.CategoryInHouse,
			Origin:   "Path",
		},
		{
			Name:     "official_app",
			Path:     `C:\Program Files\App\app.exe`,
			Category: model.CategoryThirdParty,
			Origin:   "StartMenu",
		},
	}

	enricher.Enrich(apps)

	// Must retain offline heuristic classifications
	if apps[0].Category != model.CategoryInHouse {
		t.Fatalf("expected candidate app to remain in-house when offline")
	}
	if apps[1].Category != model.CategoryThirdParty {
		t.Fatalf("expected official app to remain third-party")
	}

	stats := enricher.Stats()
	if !stats.Offline {
		t.Fatalf("expected stats to record offline")
	}
	if stats.RemoteLookups != 0 {
		t.Fatalf("expected 0 remote lookups when offline")
	}
}

func TestEnricherCacheHitBypass(t *testing.T) {
	tempDir := t.TempDir()
	cache := NewResolutionCache(filepath.Join(tempDir, "cache.json"))
	cache.Set("cachedtool", CacheEntry{
		IsThirdParty: true,
		Evidence:     "Verified open-source tool via Repology",
	})

	enricher := NewEnricher(cache)
	online := true
	enricher.isOnline = &online

	apps := []model.Application{
		{
			Name:     "cachedtool.exe",
			Path:     `C:\Tools\cachedtool.exe`,
			Category: model.CategoryInHouse,
			Origin:   "Path",
		},
	}

	enricher.Enrich(apps)

	if apps[0].Category != model.CategoryThirdParty {
		t.Fatalf("expected candidate app to be upgraded to third-party from cache")
	}
	if apps[0].Evidence != "Verified open-source tool via Repology" {
		t.Fatalf("expected evidence from cache, got: %s", apps[0].Evidence)
	}

	stats := enricher.Stats()
	if stats.CacheHits != 1 {
		t.Fatalf("expected 1 cache hit, got %d", stats.CacheHits)
	}
	if stats.RemoteLookups != 0 {
		t.Fatalf("expected 0 remote lookups on cache hit, got %d", stats.RemoteLookups)
	}
}

func TestEnricherSkipsVerifiedThirdParty(t *testing.T) {
	tempDir := t.TempDir()
	cache := NewResolutionCache(filepath.Join(tempDir, "cache.json"))
	enricher := NewEnricher(cache)
	online := true
	enricher.isOnline = &online

	apps := []model.Application{
		{
			Name:     "chrome",
			Path:     `C:\Program Files\Google\Chrome\chrome.exe`,
			Category: model.CategoryThirdParty,
			Origin:   "StartMenu",
			Evidence: "User-facing launchable application in Windows Start Menu",
		},
	}

	enricher.Enrich(apps)

	stats := enricher.Stats()
	if stats.NetworkLookups != 0 || stats.RemoteLookups != 0 || stats.CacheHits != 0 {
		t.Fatalf("expected 0 lookups for verified third-party app, got: %+v", stats)
	}
}

func TestEnricherMockTier1Repology(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") != "appaudit/1.0" {
			t.Errorf("expected User-Agent appaudit/1.0, got %s", r.Header.Get("User-Agent"))
		}
		if r.URL.Path == "/api/v1/project/validtool" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `[{"repo":"nix","srcname":"validtool","version":"1.0"}]`)
			return
		}
		if r.URL.Path == "/api/v1/project/emptytool" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `[]`)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	tempDir := t.TempDir()
	cache := NewResolutionCache(filepath.Join(tempDir, "cache.json"))
	enricher := NewEnricher(cache)
	enricher.client = server.Client()
	enricher.client.Timeout = 1500 * time.Millisecond
	enricher.repologyBaseURL = server.URL + "/api/v1/project/"

	res := enricher.queryRepology("validtool")
	if !res.verified {
		t.Fatalf("expected validtool to be verified via Repology")
	}

	resEmpty := enricher.queryRepology("emptytool")
	if resEmpty.verified {
		t.Fatalf("expected emptytool not to be verified")
	}
}

func TestEnricherMockTier2DuckDuckGo(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		if q == `\"ddgtool\" CLI OR tool OR software` || r.URL.RawQuery != "" {
			w.WriteHeader(http.StatusOK)
			// Contains >= 2 indicators: github.com and documentation
			fmt.Fprint(w, `<html><body>Visit github.com/user/ddgtool for documentation and releases</body></html>`)
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `<html><body>No matching indicators here</body></html>`)
	}))
	defer server.Close()

	tempDir := t.TempDir()
	cache := NewResolutionCache(filepath.Join(tempDir, "cache.json"))
	enricher := NewEnricher(cache)
	enricher.client = server.Client()
	enricher.client.Timeout = 1500 * time.Millisecond
	enricher.duckduckgoBaseURL = server.URL + "/html/?q="

	res := enricher.queryDuckDuckGo("ddgtool")
	if !res.verified {
		t.Fatalf("expected ddgtool to be verified via DDG indicators")
	}
	if res.evidence != "Verified open-source tool via DuckDuckGo web index" {
		t.Fatalf("unexpected evidence: %s", res.evidence)
	}
}

func TestEnricherFailOpenOn429AndChallenge(t *testing.T) {
	// Server returning 429
	server429 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server429.Close()

	tempDir := t.TempDir()
	cache := NewResolutionCache(filepath.Join(tempDir, "cache.json"))
	enricher := NewEnricher(cache)
	enricher.client = server429.Client()
	enricher.client.Timeout = 1500 * time.Millisecond
	enricher.repologyBaseURL = server429.URL + "/api/v1/project/"
	enricher.duckduckgoBaseURL = server429.URL + "/html/?q="

	res := enricher.resolveCandidate("ratelimitedtool")
	if !res.failOpen {
		t.Fatalf("expected failOpen=true on 429")
	}
	if res.verified {
		t.Fatalf("expected verified=false on 429")
	}

	// Verify nothing was saved to cache
	if _, ok := cache.Get("ratelimitedtool"); ok {
		t.Fatalf("expected no cache entry to be saved on fail-open error")
	}
}

func TestEstimateOnlineETA(t *testing.T) {
	// 0 candidates
	eta0 := EstimateOnlineETA(nil)
	if eta0 != "< 1s" {
		t.Errorf("expected < 1s for 0 candidates, got %s", eta0)
	}

	// 1 candidate
	eta1 := EstimateOnlineETA([]model.Application{
		{Name: "random_unique_uncached_tool_12345"},
	})
	if eta1 == "" {
		t.Errorf("expected non-empty ETA for candidate")
	}
}

