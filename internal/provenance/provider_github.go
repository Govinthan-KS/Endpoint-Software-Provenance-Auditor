package provenance

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// GitHubReleaseProvider queries public GitHub release metadata to verify artifact SHA-256 digests.
// It uses unauthenticated public access and fails gracefully on rate limits or network issues.
// Binaries are NEVER uploaded or downloaded.
type GitHubReleaseProvider struct {
	client  *http.Client
	baseURL string
}

// NewGitHubReleaseProvider creates an initialized GitHubReleaseProvider.
func NewGitHubReleaseProvider(customClient ...*http.Client) *GitHubReleaseProvider {
	c := &http.Client{Timeout: 2000 * time.Millisecond}
	if len(customClient) > 0 && customClient[0] != nil {
		c = customClient[0]
	}
	return &GitHubReleaseProvider{
		client:  c,
		baseURL: "https://api.github.com/repos",
	}
}

// Name returns the provider identifier.
func (g *GitHubReleaseProvider) Name() string {
	return "github_releases"
}

type ghRelease struct {
	TagName string    `json:"tag_name"`
	Name    string    `json:"name"`
	Body    string    `json:"body"`
	Assets  []ghAsset `json:"assets"`
}

type ghAsset struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
}

// Lookup attempts to match the artifact against public GitHub release metadata.
func (g *GitHubReleaseProvider) Lookup(ctx context.Context, artifact Artifact) ([]Evidence, []ProvenanceCandidate, error) {
	var repoCandidates []string

	// 1. Module path from Go buildinfo (e.g. github.com/owner/repo)
	if artifact.BuildInfo != nil && strings.HasPrefix(artifact.BuildInfo.MainModule, "github.com/") {
		parts := strings.Split(artifact.BuildInfo.MainModule, "/")
		if len(parts) >= 3 {
			repoCandidates = append(repoCandidates, parts[1]+"/"+parts[2])
		}
	}

	// If no candidate repo is known, do not make arbitrary guesses
	if len(repoCandidates) == 0 {
		return nil, nil, nil
	}

	var allEvidence []Evidence
	var allCandidates []ProvenanceCandidate

	for _, repo := range repoCandidates {
		apiURL := fmt.Sprintf("%s/%s/releases/latest", g.baseURL, repo)
		req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "appaudit-provenance/1.0")
		req.Header.Set("Accept", "application/vnd.github.v3+json")

		resp, err := g.client.Do(req)
		if err != nil {
			continue
		}

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			continue
		}

		bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		resp.Body.Close()
		if err != nil {
			continue
		}

		var rel ghRelease
		if err := json.Unmarshal(bodyBytes, &rel); err != nil {
			continue
		}

		// Check if local SHA-256 is cited anywhere in the release notes / checksums table
		localHash := strings.ToLower(artifact.Fingerprint.SHA256)
		relBodyLower := strings.ToLower(rel.Body)

		if localHash != "" && strings.Contains(relBodyLower, localHash) {
			ev := Evidence{
				Type:        EvidenceReleaseAssetMatch,
				Source:      "GitHub Releases (" + repo + ")",
				Strength:    1.0,
				Description: fmt.Sprintf("Local SHA-256 matches published release digest for %s %s", repo, rel.TagName),
				URL:         fmt.Sprintf("https://github.com/%s/releases/tag/%s", repo, rel.TagName),
				Confidence:  ConfidenceVeryHigh,
			}
			allEvidence = append(allEvidence, ev)
			allCandidates = append(allCandidates, ProvenanceCandidate{
				Name:       repo,
				ProjectURL: fmt.Sprintf("https://github.com/%s", repo),
				Source:     "GitHub Releases",
				Evidence:   []Evidence{ev},
			})
			return allEvidence, allCandidates, nil
		}

		// Check if release assets match filename and size
		for _, asset := range rel.Assets {
			if strings.EqualFold(asset.Name, artifact.Name) || strings.EqualFold(asset.Name, artifact.Name+".exe") {
				if artifact.Fingerprint.Size > 0 && asset.Size == artifact.Fingerprint.Size {
					ev := Evidence{
						Type:        EvidenceReleaseAssetMatch,
						Source:      "GitHub Releases (" + repo + ")",
						Strength:    0.85,
						Description: fmt.Sprintf("Release asset '%s' matches executable name and exact byte size (%d bytes) for %s %s", asset.Name, asset.Size, repo, rel.TagName),
						URL:         fmt.Sprintf("https://github.com/%s/releases/tag/%s", repo, rel.TagName),
						Confidence:  ConfidenceHigh,
					}
					allEvidence = append(allEvidence, ev)
					allCandidates = append(allCandidates, ProvenanceCandidate{
						Name:       repo,
						ProjectURL: fmt.Sprintf("https://github.com/%s", repo),
						Source:     "GitHub Releases",
						Evidence:   []Evidence{ev},
					})
				}
			}
		}
	}

	return allEvidence, allCandidates, nil
}
