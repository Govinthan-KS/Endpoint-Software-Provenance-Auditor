package provenance

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// PackageProvider queries package repositories (e.g., Repology API) to generate candidates.
// It serves as a candidate generator and supporting evidence source, NOT an identity authority.
type PackageProvider struct {
	client  *http.Client
	baseURL string
}

// NewPackageProvider creates an initialized PackageProvider.
func NewPackageProvider(customClient ...*http.Client) *PackageProvider {
	c := &http.Client{Timeout: 1500 * time.Millisecond}
	if len(customClient) > 0 && customClient[0] != nil {
		c = customClient[0]
	}
	return &PackageProvider{
		client:  c,
		baseURL: "https://repology.org/api/v1/project/",
	}
}

// Name returns the provider identifier.
func (p *PackageProvider) Name() string {
	return "package_repositories"
}

// Lookup queries Repology for the artifact name.
func (p *PackageProvider) Lookup(ctx context.Context, artifact Artifact) ([]Evidence, []ProvenanceCandidate, error) {
	name := strings.TrimSpace(strings.ToLower(artifact.Name))
	if name == "" {
		return nil, nil, nil
	}

	// Protect against generic dictionary collisions: if generic name and no metadata corroboration, skip or lower confidence
	if IsGenericCollidingName(name) && artifact.ProductName == "" && artifact.Publisher == "" && artifact.BuildInfo == nil {
		return nil, nil, nil
	}

	urlStr := p.baseURL + url.PathEscape(name)
	req, err := http.NewRequestWithContext(ctx, "GET", urlStr, nil)
	if err != nil {
		return nil, nil, nil
	}
	req.Header.Set("User-Agent", "appaudit-provenance/1.0")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, nil, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		var pkgs []json.RawMessage
		if err := json.NewDecoder(resp.Body).Decode(&pkgs); err == nil && len(pkgs) > 0 {
			ev := Evidence{
				Type:        EvidencePackageMatch,
				Source:      "Repology Package Index",
				Strength:    0.50, // Candidate supporting evidence, not standalone identity
				Description: fmt.Sprintf("Known public software project '%s' indexed across Linux/BSD/Homebrew package repositories", name),
				URL:         fmt.Sprintf("https://repology.org/project/%s", name),
				Confidence:  ConfidenceMedium,
			}

			candidate := ProvenanceCandidate{
				Name:       name,
				Source:     "Repology",
				ProjectURL: fmt.Sprintf("https://repology.org/project/%s", name),
				Evidence:   []Evidence{ev},
			}

			return []Evidence{ev}, []ProvenanceCandidate{candidate}, nil
		}
	}

	return nil, nil, nil
}

// IsGenericCollidingName returns true if a binary name is a common generic noun that frequently collides with internal names.
func IsGenericCollidingName(name string) bool {
	n := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), ".exe"))
	generic := map[string]bool{
		"sync":     true,
		"update":   true,
		"helper":   true,
		"agent":    true,
		"runner":   true,
		"audit":    true,
		"service":  true,
		"manager":  true,
		"launcher": true,
		"client":   true,
		"daemon":   true,
		"host":     true,
		"proxy":    true,
		"broker":   true,
		"monitor":  true,
		"worker":   true,
		"gateway":  true,
		"backup":   true,
		"tool":     true,
		"test":     true,
		"app":      true,
		"deploy":   true,
		"auth":     true,
		"gatekeeper": true,
	}
	return generic[n]
}
