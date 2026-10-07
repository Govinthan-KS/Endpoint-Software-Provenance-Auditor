package classifier

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/example/appaudit/internal/model"
)

// NetworkStats records the lookup and cache hit metrics for terminal telemetry.
type NetworkStats struct {
	Enabled        bool
	Offline        bool
	NetworkLookups int
	CacheHits      int
	RemoteLookups  int
}

// Enricher resolves candidate in-house CLI applications online using Repology and DuckDuckGo.
type Enricher struct {
	client            *http.Client
	cache             *ResolutionCache
	stats             NetworkStats
	mu                sync.Mutex
	isOnline          *bool
	repologyBaseURL   string
	duckduckgoBaseURL string
}

// NewEnricher creates a new Enricher with local caching and strict timeouts.
func NewEnricher(customCache ...*ResolutionCache) *Enricher {
	var c *ResolutionCache
	if len(customCache) > 0 && customCache[0] != nil {
		c = customCache[0]
	} else {
		c = NewResolutionCache()
	}

	return &Enricher{
		client: &http.Client{
			Timeout: 1500 * time.Millisecond,
		},
		cache:             c,
		stats:             NetworkStats{Enabled: true},
		repologyBaseURL:   "https://repology.org/api/v1/project/",
		duckduckgoBaseURL: "https://html.duckduckgo.com/html/?q=",
	}
}

// Stats returns the network and cache telemetry collected during enrichment.
func (e *Enricher) Stats() NetworkStats {
	e.mu.Lock()
	defer e.mu.Unlock()
	s := e.stats
	s.Enabled = true
	return s
}

type lookupOutcome struct {
	verified bool
	evidence string
	failOpen bool
}

// Enrich evaluates candidate in-house apps against local cache and remote resolvers.
// Verified third-party applications skip network resolution entirely.
func (e *Enricher) Enrich(apps []model.Application) {
	// 1. Identify indices of candidate in-house applications
	var candidateIndices []int
	for i := range apps {
		if apps[i].Category == model.CategoryInHouse {
			candidateIndices = append(candidateIndices, i)
		}
	}

	if len(candidateIndices) == 0 {
		return
	}

	// 2. Fast-fail network pre-flight check
	if e.isOnline == nil {
		online := CheckConnectivity()
		e.isOnline = &online
	}
	if !*e.isOnline {
		e.mu.Lock()
		e.stats.Offline = true
		e.mu.Unlock()
		return
	}

	// 3. First pass: Check local persistent cache (0ms overhead)
	type uncachedItem struct {
		key   string
		index int
	}

	var uncached []uncachedItem
	seenUncachedKeys := make(map[string]bool)

	for _, idx := range candidateIndices {
		app := &apps[idx]
		key := NormalizeBinaryKey(app.Name)
		if key == "" {
			key = NormalizeBinaryKey(app.Path)
		}
		if key == "" {
			continue
		}

		if entry, found := e.cache.Get(key); found {
			e.mu.Lock()
			e.stats.NetworkLookups++
			e.stats.CacheHits++
			e.mu.Unlock()

			if entry.IsThirdParty {
				app.Category = model.CategoryThirdParty
				if entry.Evidence != "" {
					app.Evidence = entry.Evidence
				} else {
					app.Evidence = "Verified open-source tool via persistent cache"
				}
				if app.Publisher == "" {
					app.Publisher = "Open Source / Community"
				}
			}
			continue
		}

		if !seenUncachedKeys[key] {
			seenUncachedKeys[key] = true
			uncached = append(uncached, uncachedItem{key: key, index: idx})
		}
	}

	if len(uncached) == 0 {
		return
	}

	// 4. Cap uncached lookups to 10 per execution
	maxLookups := 10
	lookupBatch := uncached
	if len(lookupBatch) > maxLookups {
		lookupBatch = lookupBatch[:maxLookups]
	}

	// 5. Worker pool: Process up to 3 candidate lookups concurrently
	workerSem := make(chan struct{}, 3)
	var wg sync.WaitGroup
	results := make(map[string]lookupOutcome)
	var resultsMu sync.Mutex

	for _, item := range lookupBatch {
		wg.Add(1)
		workerSem <- struct{}{}
		go func(key string) {
			defer func() {
				<-workerSem
				wg.Done()
			}()

			outcome := e.resolveCandidate(key)

			resultsMu.Lock()
			results[key] = outcome
			e.mu.Lock()
			e.stats.NetworkLookups++
			e.stats.RemoteLookups++
			e.mu.Unlock()

			if outcome.verified {
				e.cache.Set(key, CacheEntry{
					IsThirdParty: true,
					Evidence:     outcome.evidence,
				})
			} else if !outcome.failOpen {
				// Clean negative verdict: save negative entry
				e.cache.Set(key, CacheEntry{
					IsThirdParty: false,
				})
			}
			resultsMu.Unlock()
		}(item.key)
	}

	wg.Wait()
	_ = e.cache.Save()

	// 6. Apply resolution outcomes to all matching candidate apps
	for _, idx := range candidateIndices {
		app := &apps[idx]
		if app.Category != model.CategoryInHouse {
			continue
		}
		key := NormalizeBinaryKey(app.Name)
		if key == "" {
			key = NormalizeBinaryKey(app.Path)
		}
		if outcome, ok := results[key]; ok && outcome.verified {
			app.Category = model.CategoryThirdParty
			app.Evidence = outcome.evidence
			if app.Publisher == "" {
				app.Publisher = "Open Source / Community"
			}
		}
	}
}

func (e *Enricher) resolveCandidate(name string) lookupOutcome {
	// Tier 1: Repology API
	repologyOutcome := e.queryRepology(name)
	if repologyOutcome.verified {
		return repologyOutcome
	}

	// If Repology returns 404, empty, or error, inspect Tier 2: DuckDuckGo
	ddgOutcome := e.queryDuckDuckGo(name)
	if ddgOutcome.verified {
		return ddgOutcome
	}

	// If either hit a network timeout / connection error / 429 / challenge, fail open
	if repologyOutcome.failOpen || ddgOutcome.failOpen {
		return lookupOutcome{failOpen: true}
	}

	// Clean negative lookup without errors
	return lookupOutcome{verified: false, failOpen: false}
}

func (e *Enricher) queryRepology(name string) lookupOutcome {
	baseURL := e.repologyBaseURL
	if baseURL == "" {
		baseURL = "https://repology.org/api/v1/project/"
	}
	urlStr := baseURL + url.PathEscape(name)
	req, err := http.NewRequest("GET", urlStr, nil)
	if err != nil {
		return lookupOutcome{failOpen: true}
	}
	req.Header.Set("User-Agent", "appaudit/1.0")

	resp, err := e.client.Do(req)
	if err != nil {
		return lookupOutcome{failOpen: true}
	}
	defer resp.Body.Close()

	if resp.StatusCode == 429 {
		return lookupOutcome{failOpen: true}
	}

	// Repology bot protection: retry with standard browser user-agent if 403 Forbidden
	if resp.StatusCode == 403 {
		req2, err := http.NewRequest("GET", urlStr, nil)
		if err == nil {
			req2.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
			resp2, err := e.client.Do(req2)
			if err == nil {
				defer resp2.Body.Close()
				if resp2.StatusCode == 200 {
					var pkgs []json.RawMessage
					if err := json.NewDecoder(resp2.Body).Decode(&pkgs); err == nil && len(pkgs) > 0 {
						return lookupOutcome{
							verified: true,
							evidence: "Verified open-source tool via Repology",
						}
					}
					return lookupOutcome{verified: false, failOpen: false}
				}
				if resp2.StatusCode == 404 {
					return lookupOutcome{verified: false, failOpen: false}
				}
				if resp2.StatusCode == 429 {
					return lookupOutcome{failOpen: true}
				}
			}
		}
	}

	if resp.StatusCode == 200 {
		var pkgs []json.RawMessage
		if err := json.NewDecoder(resp.Body).Decode(&pkgs); err == nil && len(pkgs) > 0 {
			return lookupOutcome{
				verified: true,
				evidence: "Verified open-source tool via Repology",
			}
		}
		// 200 OK with empty array []
		return lookupOutcome{verified: false, failOpen: false}
	}

	if resp.StatusCode == 404 {
		return lookupOutcome{verified: false, failOpen: false}
	}

	return lookupOutcome{failOpen: true}
}

func (e *Enricher) queryDuckDuckGo(name string) lookupOutcome {
	baseURL := e.duckduckgoBaseURL
	if baseURL == "" {
		baseURL = "https://html.duckduckgo.com/html/?q="
	}
	query := fmt.Sprintf("\"%s\" CLI OR tool OR software", name)
	urlStr := baseURL + url.QueryEscape(query)

	req, err := http.NewRequest("GET", urlStr, nil)
	if err != nil {
		return lookupOutcome{failOpen: true}
	}
	req.Header.Set("User-Agent", "appaudit/1.0")

	resp, err := e.client.Do(req)
	if err != nil {
		return lookupOutcome{failOpen: true}
	}
	defer resp.Body.Close()

	if resp.StatusCode == 429 {
		return lookupOutcome{failOpen: true}
	}

	if resp.StatusCode != 200 {
		return lookupOutcome{failOpen: true}
	}

	// Inspect top 32KB of DDG HTML
	limitReader := io.LimitReader(resp.Body, 32*1024)
	bodyBytes, err := io.ReadAll(limitReader)
	if err != nil {
		return lookupOutcome{failOpen: true}
	}

	lower := strings.ToLower(string(bodyBytes))

	// If DDG returned a bot anomaly challenge, fail open
	if strings.Contains(lower, "anomaly-modal") || strings.Contains(lower, "bots use duckduckgo") {
		return lookupOutcome{failOpen: true}
	}

	indicators := []string{
		"github.com",
		"pypi.org",
		"crates.io",
		"homebrew",
		"documentation",
		"releases",
	}

	matchedCount := 0
	for _, ind := range indicators {
		if strings.Contains(lower, ind) {
			matchedCount++
		}
	}

	if matchedCount >= 2 {
		return lookupOutcome{
			verified: true,
			evidence: "Verified open-source tool via DuckDuckGo web index",
		}
	}

	return lookupOutcome{verified: false, failOpen: false}
}

// EstimateOnlineETA calculates an estimated time duration for resolving the given candidate apps online.
func EstimateOnlineETA(candidates []model.Application) string {
	if len(candidates) == 0 {
		return "< 1s"
	}

	cache := NewResolutionCache()
	uncachedCount := 0
	seen := make(map[string]bool)

	for _, app := range candidates {
		key := NormalizeBinaryKey(app.Name)
		if key == "" {
			key = NormalizeBinaryKey(app.Path)
		}
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true

		if _, found := cache.Get(key); !found {
			uncachedCount++
		}
	}

	if uncachedCount == 0 {
		return "< 1s (cached)"
	}

	if uncachedCount > 10 {
		uncachedCount = 10
	}

	// 3 concurrent workers in worker pool with 1.5s timeout per batch
	batches := (uncachedCount + 2) / 3
	minSec := batches
	maxSec := batches * 2

	if minSec == maxSec {
		return fmt.Sprintf("~%ds", minSec)
	}
	return fmt.Sprintf("~%d-%ds", minSec, maxSec)
}

