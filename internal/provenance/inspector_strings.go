package provenance

import (
	"bytes"
	"debug/pe"
	"io"
	"os"
	"regexp"
	"strings"
)

// StringSignatures represents embedded public repository and package registry markers recovered from read-only data.
type StringSignatures struct {
	RepositoryURL string   `json:"repository_url,omitempty"`
	IsCratesIO    bool     `json:"is_crates_io,omitempty"`
	FoundURLs     []string `json:"found_urls,omitempty"`
}

var (
	githubURLRegex = regexp.MustCompile(`https?://github\.com/([a-zA-Z0-9_\-\.]+)/([a-zA-Z0-9_\-\.]+)`)
	gitlabURLRegex = regexp.MustCompile(`https?://gitlab\.com/([a-zA-Z0-9_\-\.]+)/([a-zA-Z0-9_\-\.]+)`)
)

// InspectStringSignatures inspects PE .rdata or read-only binary data for public source code signatures.
func InspectStringSignatures(filePath string) *StringSignatures {
	data := readReadOnlyData(filePath)
	if len(data) == 0 {
		return nil
	}

	sig := &StringSignatures{}

	if bytes.Contains(data, []byte("crates.io-index")) || bytes.Contains(data, []byte("index.crates.io")) {
		sig.IsCratesIO = true
	}

	seen := make(map[string]bool)
	ghMatches := githubURLRegex.FindAll(data, 10)
	for _, m := range ghMatches {
		url := cleanRepoURL(string(m))
		if isValidPublicRepo(url) && !seen[url] {
			seen[url] = true
			sig.FoundURLs = append(sig.FoundURLs, url)
			if sig.RepositoryURL == "" {
				sig.RepositoryURL = url
			}
		}
	}

	// GitLab matches
	glMatches := gitlabURLRegex.FindAll(data, 5)
	for _, m := range glMatches {
		url := cleanRepoURL(string(m))
		if isValidPublicRepo(url) && !seen[url] {
			seen[url] = true
			sig.FoundURLs = append(sig.FoundURLs, url)
			if sig.RepositoryURL == "" {
				sig.RepositoryURL = url
			}
		}
	}

	if sig.RepositoryURL == "" && !sig.IsCratesIO && len(sig.FoundURLs) == 0 {
		return nil
	}

	return sig
}

func readReadOnlyData(filePath string) []byte {
	// Try reading PE .rdata section first
	if peFile, err := pe.Open(filePath); err == nil {
		defer peFile.Close()
		for _, s := range peFile.Sections {
			name := strings.ToLower(strings.TrimRight(s.Name, "\x00"))
			if name == ".rdata" || name == ".rodata" {
				sr := s.Open()
				buf, _ := io.ReadAll(io.LimitReader(sr, 8*1024*1024))
				if len(buf) > 0 {
					return buf
				}
			}
		}
	}

	// Fallback: Read first 4MB of binary
	f, err := os.Open(filePath)
	if err != nil {
		return nil
	}
	defer f.Close()

	buf := make([]byte, 4*1024*1024)
	n, _ := io.ReadFull(f, buf)
	return buf[:n]
}

func cleanRepoURL(raw string) string {
	raw = strings.TrimRight(raw, "/. \t\r\n\x00")
	raw = strings.TrimSuffix(raw, ".git")
	return raw
}

func isValidPublicRepo(url string) bool {
	lower := strings.ToLower(url)
	// Filter out boilerplate registries or generic documentation URLs
	if strings.Contains(lower, "rust-lang/crates.io-index") ||
		strings.Contains(lower, "golang/go") ||
		strings.Contains(lower, "microsoft/windows") {
		return false
	}
	// Require org and repo segments
	parts := strings.Split(strings.TrimPrefix(strings.TrimPrefix(lower, "https://"), "http://"), "/")
	if len(parts) < 3 {
		return false
	}
	org, repo := parts[1], parts[2]
	if len(org) < 2 || len(repo) < 2 {
		return false
	}
	return true
}
