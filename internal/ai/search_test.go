package ai

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSearXNGProvider_Success(t *testing.T) {
	longSnippet := "Line 1\n\nLine 2 with multiple    spaces.\r\n" + strings.Repeat("B", 700)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/search") {
			http.NotFound(w, r)
			return
		}
		q := r.URL.Query().Get("q")
		if q == "" {
			http.Error(w, "missing query", http.StatusBadRequest)
			return
		}

		resp := searxngResponse{
			Results: []struct {
				Title   string `json:"title"`
				Content string `json:"content"`
				URL     string `json:"url"`
			}{
				{
					Title:   "Aider AI Coding Tool",
					Content: longSnippet,
					URL:     "https://github.com/paul-gauthier/aider",
				},
				{
					Title:   "Aider on PyPI",
					Content: "Command line tool for AI programming.",
					URL:     "https://pypi.org/project/aider-chat/",
				},
				{
					Title:   "Aider Documentation",
					Content: "Official documentation and installation guide.",
					URL:     "https://aider.chat",
				},
				{
					Title:   "Aider Benchmarks",
					Content: "SWE-bench leaderboard and evaluations.",
					URL:     "https://aider.chat/docs/benchmarks.html",
				},
				{
					Title:   "Aider Release Notes",
					Content: "Changelog and GitHub releases.",
					URL:     "https://github.com/paul-gauthier/aider/releases",
				},
				{
					Title:   "Aider 6th Result (Should be ignored)",
					Content: "Should exceed maxResults cap of 5.",
					URL:     "https://example.com/extra",
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	provider := NewSearXNGProvider(ts.URL)
	results, err := provider.Search(context.Background(), "aider software")
	if err != nil {
		t.Fatalf("unexpected search error: %v", err)
	}

	// Verify maximum 5 results returned
	if len(results) != 5 {
		t.Fatalf("expected 5 results, got %d", len(results))
	}

	if results[0].Title != "Aider AI Coding Tool" {
		t.Errorf("expected title 'Aider AI Coding Tool', got %q", results[0].Title)
	}

	// Verify snippet truncation to 550 characters (+ "..." = 553)
	if len(results[0].Snippet) > 553 {
		t.Errorf("snippet exceeded maximum 553 chars: %d", len(results[0].Snippet))
	}
	if !strings.HasSuffix(results[0].Snippet, "...") {
		t.Errorf("expected snippet to be truncated with '...', got: %s", results[0].Snippet)
	}
	// Verify newlines were cleaned
	if strings.Contains(results[0].Snippet, "\n") || strings.Contains(results[0].Snippet, "\r") {
		t.Errorf("expected snippet to have newlines removed: %q", results[0].Snippet)
	}

	// Verify Domain helper
	if results[0].Domain() != "github.com" {
		t.Errorf("expected domain 'github.com', got %q", results[0].Domain())
	}
	if results[1].Domain() != "pypi.org" {
		t.Errorf("expected domain 'pypi.org', got %q", results[1].Domain())
	}
}

func TestSearXNGProvider_Offline_Fallback(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "SearXNG backend engine failure", http.StatusInternalServerError)
	}))
	defer ts.Close()

	provider := NewSearXNGProvider(ts.URL)
	results, err := provider.Search(context.Background(), "test query")
	if err != nil {
		t.Fatalf("expected graceful fallback with nil error, got: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("expected 0 results on server error, got %d", len(results))
	}

	// Test completely unreachable port
	offlineProvider := NewSearXNGProvider("http://127.0.0.1:59999")
	resultsOff, errOff := offlineProvider.Search(context.Background(), "test offline")
	if errOff != nil {
		t.Fatalf("expected graceful fallback on connection refused, got: %v", errOff)
	}
	if len(resultsOff) != 0 {
		t.Fatalf("expected 0 results when offline, got %d", len(resultsOff))
	}
}

func TestSearXNGProvider_EmptyQuery(t *testing.T) {
	provider := NewSearXNGProvider("http://localhost:8080")
	results, err := provider.Search(context.Background(), "   ")
	if err != nil {
		t.Fatalf("unexpected error on empty query: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("expected 0 results on empty query, got %d", len(results))
	}
}
