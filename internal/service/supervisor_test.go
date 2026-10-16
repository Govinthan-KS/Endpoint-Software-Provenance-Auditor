package service

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestServiceStatus_Fields(t *testing.T) {
	status := ServiceStatus{
		Name:       "Ollama",
		Endpoint:   "http://localhost:11434",
		Running:    true,
		AutoBooted: false,
	}
	if status.Name != "Ollama" || !status.Running || status.AutoBooted {
		t.Fatalf("unexpected ServiceStatus values: %+v", status)
	}
}

func TestEnsureOllamaRunning_AlreadyHealthy(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/tags" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"models": []map[string]any{
					{"name": "audit-phi:q6k", "model": "audit-phi:q6k"},
				},
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	var buf bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	status, err := EnsureOllamaRunning(ctx, ts.URL, "audit-phi:q6k", &buf)
	if err != nil {
		t.Fatalf("unexpected error for healthy server: %v", err)
	}
	if status == nil || !status.Running || status.AutoBooted {
		t.Fatalf("expected running without auto-boot: %+v", status)
	}
}

func TestEnsureSearXNGRunning_AlreadyHealthy(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/search") {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"results": []any{},
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	var buf bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	status, err := EnsureSearXNGRunning(ctx, ts.URL, &buf)
	if err != nil {
		t.Fatalf("unexpected error for healthy server: %v", err)
	}
	if status == nil || !status.Running || status.AutoBooted {
		t.Fatalf("expected running without auto-boot: %+v", status)
	}
}

func TestEnsureLocalStack_HotStart(t *testing.T) {
	ollamaServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"models": []map[string]any{
				{"name": "audit-phi:q6k", "model": "audit-phi:q6k"},
			},
		})
	}))
	defer ollamaServer.Close()

	searxngServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"results": []any{},
		})
	}))
	defer searxngServer.Close()

	var buf bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	opts := LocalStackOptions{
		OllamaURL:   ollamaServer.URL,
		OllamaModel: "audit-phi:q6k",
		SearXNGURL:  searxngServer.URL,
		Writer:      &buf,
	}

	err := EnsureLocalStackWithOptions(ctx, opts)
	if err != nil {
		t.Fatalf("unexpected error on hot start: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Verifying Ollama") {
		t.Errorf("expected verifying prompt in output, got: %s", output)
	}
	if !strings.Contains(output, "All offline services active") {
		t.Errorf("expected active confirmation in output, got: %s", output)
	}
}

func TestVerifyOllamaModel(t *testing.T) {
	jsonPayload := `{"models":[{"name":"audit-phi:q6k"},{"name":"llama3:latest"}]}`

	var buf bytes.Buffer
	found := verifyOllamaModel(strings.NewReader(jsonPayload), "audit-phi:q6k", &buf)
	if !found {
		t.Errorf("expected audit-phi:q6k to be found")
	}

	buf.Reset()
	foundMissing := verifyOllamaModel(strings.NewReader(jsonPayload), "nonexistent:model", &buf)
	if foundMissing {
		t.Errorf("expected nonexistent model to not be found")
	}
	if !strings.Contains(buf.String(), "Notice: Model \"nonexistent:model\" is not installed") {
		t.Errorf("expected missing model notice, got: %s", buf.String())
	}
}

func TestFindOllamaBinary(t *testing.T) {
	// findOllamaBinary should not panic
	path, err := findOllamaBinary()
	if err == nil && path == "" {
		t.Errorf("expected non-empty path on nil error")
	}
}
