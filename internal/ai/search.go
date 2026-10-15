package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/example/appaudit/internal/provenance"
)

// SearchResult represents a single retrieved ground-truth search item.
type SearchResult struct {
	Title   string `json:"title"`
	Snippet string `json:"content"`
	URL     string `json:"url"`
}

// Domain returns the hostname / domain from the search result URL, or the raw URL if unparseable.
func (r SearchResult) Domain() string {
	if r.URL == "" {
		return ""
	}
	u, err := url.Parse(r.URL)
	if err != nil || u.Host == "" {
		return r.URL
	}
	return u.Host
}

// SearchProvider defines the interface for external web search evidence retrieval.
type SearchProvider interface {
	Search(ctx context.Context, query string) ([]SearchResult, error)
}

// SearXNGProvider retrieves search results from a local or self-hosted SearXNG instance.
type SearXNGProvider struct {
	BaseURL    string
	HTTPClient *http.Client
	mu         sync.RWMutex
	lastErr    error
}

// NewSearXNGProvider creates a SearXNG search provider with a generous 30-second timeout.
func NewSearXNGProvider(baseURL string) *SearXNGProvider {
	if baseURL == "" {
		baseURL = "http://localhost:8080"
	}
	baseURL = strings.TrimRight(baseURL, "/")
	return &SearXNGProvider{
		BaseURL: baseURL,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// LastError returns the most recent error encountered during search, if any.
func (s *SearXNGProvider) LastError() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastErr
}

func (s *SearXNGProvider) setLastError(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastErr = err
}

type searxngResponse struct {
	Results []struct {
		Title   string `json:"title"`
		Content string `json:"content"`
		URL     string `json:"url"`
	} `json:"results"`
}

// Search executes a query against SearXNG and returns top 5 results with up to 550-character snippets.
// If SearXNG is offline or returns an error, it falls back gracefully with an empty slice and records LastError.
func (s *SearXNGProvider) Search(ctx context.Context, query string) ([]SearchResult, error) {
	s.setLastError(nil)
	cleanQuery := strings.TrimSpace(query)
	if cleanQuery == "" {
		return []SearchResult{}, nil
	}

	searchURL := fmt.Sprintf("%s/search?q=%s&format=json", s.BaseURL, url.QueryEscape(cleanQuery))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, searchURL, nil)
	if err != nil {
		return []SearchResult{}, nil
	}
	req.Header.Set("Accept", "application/json")

	resp, err := s.HTTPClient.Do(req)
	if err != nil {
		s.setLastError(fmt.Errorf("SearXNG unreachable at %s: %w", s.BaseURL, err))
		return []SearchResult{}, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		s.setLastError(fmt.Errorf("SearXNG returned HTTP %d", resp.StatusCode))
		return []SearchResult{}, nil
	}

	var sr searxngResponse
	if err := json.NewDecoder(resp.Body).Decode(&sr); err != nil {
		s.setLastError(fmt.Errorf("failed to decode SearXNG response: %w", err))
		return []SearchResult{}, nil
	}

	var results []SearchResult
	const maxResults = 5
	const maxSnippetLen = 550

	for i, r := range sr.Results {
		if i >= maxResults {
			break
		}
		snippet := cleanSnippet(r.Content)
		if len(snippet) > maxSnippetLen {
			snippet = snippet[:maxSnippetLen] + "..."
		}
		results = append(results, SearchResult{
			Title:   strings.TrimSpace(r.Title),
			Snippet: snippet,
			URL:     strings.TrimSpace(r.URL),
		})
	}

	return results, nil
}

func cleanSnippet(raw string) string {
	s := strings.ReplaceAll(raw, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	fields := strings.Fields(s)
	return strings.Join(fields, " ")
}

// NoopSearchProvider returns empty results without performing any network lookups.
type NoopSearchProvider struct{}

func (n *NoopSearchProvider) Search(ctx context.Context, query string) ([]SearchResult, error) {
	return []SearchResult{}, nil
}

// BuildSearchQuery constructs an optimized search query biased toward verified software repositories.
func BuildSearchQuery(bundle EvidenceBundle) string {
	cleanName := strings.TrimSpace(bundle.AppName)
	if cleanName == "" && bundle.BinaryName != "" {
		cleanName = strings.TrimSpace(bundle.BinaryName)
	}
	cleanName = strings.TrimSuffix(cleanName, ".exe")

	cleanPub := strings.TrimSpace(bundle.Publisher)
	if cleanPub != "" && provenance.IsWrapperString(cleanPub) {
		cleanPub = ""
	}

	if bundle.IsWrapperStub {
		return fmt.Sprintf("%s windows software github OR cli OR pypi", cleanName)
	}
	if cleanPub != "" {
		return fmt.Sprintf("%s %s software tool", cleanName, cleanPub)
	}
	if len(cleanName) <= 6 {
		return fmt.Sprintf("%s windows software github OR cli OR pypi", cleanName)
	}
	return fmt.Sprintf("%s software executable tool", cleanName)
}
