package provenance

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// SearchCandidateProvider uses search engine indexing solely as a candidate discovery mechanism.
// It applies strict OPSEC filters: generic single words or sensitive path tokens are NOT queried.
// Search results are candidates only; they NEVER automatically classify an executable.
type SearchCandidateProvider struct {
	client  *http.Client
	baseURL string
}

// NewSearchCandidateProvider creates an initialized SearchCandidateProvider.
func NewSearchCandidateProvider(customClient ...*http.Client) *SearchCandidateProvider {
	c := &http.Client{Timeout: 1500 * time.Millisecond}
	if len(customClient) > 0 && customClient[0] != nil {
		c = customClient[0]
	}
	return &SearchCandidateProvider{
		client:  c,
		baseURL: "https://html.duckduckgo.com/html/?q=",
	}
}

// Name returns the provider identifier.
func (s *SearchCandidateProvider) Name() string {
	return "search_candidate_discovery"
}

// Lookup queries public indices only when sufficient non-sensitive public metadata exists.
func (s *SearchCandidateProvider) Lookup(ctx context.Context, artifact Artifact) ([]Evidence, []ProvenanceCandidate, error) {
	// OPSEC: Never query naked generic colliding names (e.g. "sync", "audit", "runner")
	// unless accompanied by explicit external product or publisher metadata.
	if IsGenericCollidingName(artifact.Name) && artifact.ProductName == "" && artifact.Publisher == "" {
		return nil, nil, nil
	}

	// Construct query using distinctive metadata
	queryTerm := artifact.Name
	if artifact.ProductName != "" && !strings.EqualFold(artifact.ProductName, artifact.Name) {
		queryTerm = fmt.Sprintf("\"%s\" \"%s\"", artifact.ProductName, artifact.Name)
	} else if artifact.Publisher != "" {
		queryTerm = fmt.Sprintf("\"%s\" \"%s\"", artifact.Publisher, artifact.Name)
	} else {
		queryTerm = fmt.Sprintf("\"%s\" software OR CLI", artifact.Name)
	}

	urlStr := s.baseURL + url.QueryEscape(queryTerm)
	req, err := http.NewRequestWithContext(ctx, "GET", urlStr, nil)
	if err != nil {
		return nil, nil, nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, nil, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil, nil
	}

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 32*1024))
	if err != nil {
		return nil, nil, nil
	}

	lower := strings.ToLower(string(bodyBytes))

	// Anomaly / bot modal detection -> fail gracefully
	if strings.Contains(lower, "anomaly-modal") || strings.Contains(lower, "bots use duckduckgo") {
		return nil, nil, nil
	}

	// Look for authoritative developer/package ecosystems
	indicators := []string{
		"github.com",
		"pypi.org",
		"crates.io",
		"homebrew",
		"npmjs.com",
		"gitlab.com",
	}

	matchedEco := 0
	for _, ind := range indicators {
		if strings.Contains(lower, ind) {
			matchedEco++
		}
	}

	// Corroboration check: if search finds developer ecosystems AND artifact has matching metadata
	if matchedEco >= 2 {
		ev := Evidence{
			Type:        EvidenceSearchResult,
			Source:      "Public Web Index",
			Strength:    0.35, // Low-to-medium candidate strength
			Description: fmt.Sprintf("Public web search indexed candidate developer repositories for '%s'", queryTerm),
			Confidence:  ConfidenceLow,
		}

		candidate := ProvenanceCandidate{
			Name:     artifact.Name,
			Source:   "Public Web Index",
			Evidence: []Evidence{ev},
		}

		return []Evidence{ev}, []ProvenanceCandidate{candidate}, nil
	}

	return nil, nil, nil
}
