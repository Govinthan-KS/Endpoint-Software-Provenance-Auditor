package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// ServiceStatus represents the health state of an inspected local service.
type ServiceStatus struct {
	Name       string `json:"name"`
	Endpoint   string `json:"endpoint"`
	Running    bool   `json:"running"`
	AutoBooted bool   `json:"auto_booted"`
}

// LocalStackOptions configures the local service connectivity check.
type LocalStackOptions struct {
	OllamaURL   string
	OllamaModel string
	SearXNGURL  string
	Logger      *log.Logger
	Writer      io.Writer
}

// EnsureLocalStack probes both Ollama and SearXNG endpoints.
func EnsureLocalStack(ctx context.Context, logger *log.Logger) error {
	var w io.Writer
	if logger != nil {
		w = logger.Writer()
	} else {
		w = os.Stdout
	}
	return EnsureLocalStackWithOptions(ctx, LocalStackOptions{
		OllamaURL:   "http://127.0.0.1:11434",
		OllamaModel: "audit-phi:q6k",
		SearXNGURL:  "http://127.0.0.1:8080",
		Logger:      logger,
		Writer:      w,
	})
}

// EnsureLocalStackWithOptions checks that Ollama and SearXNG are running without attempting auto-boot.
func EnsureLocalStackWithOptions(ctx context.Context, opts LocalStackOptions) error {
	if opts.OllamaURL == "" {
		opts.OllamaURL = "http://127.0.0.1:11434"
	}
	if opts.SearXNGURL == "" {
		opts.SearXNGURL = "http://127.0.0.1:8080"
	}
	w := opts.Writer
	if w == nil && opts.Logger != nil {
		w = opts.Logger.Writer()
	}
	if w == nil {
		w = os.Stdout
	}

	if w != nil {
		fmt.Fprintln(w, "[Local Stack] Verifying Ollama (11434) and SearXNG (8080)...")
		_ = flushWriter(w)
	}

	ollamaStatus, ollamaErr := EnsureOllamaRunning(ctx, opts.OllamaURL, opts.OllamaModel, w)
	_, searxErr := EnsureSearXNGRunning(ctx, opts.SearXNGURL, w)

	var errs []string
	if ollamaErr != nil {
		errs = append(errs, fmt.Sprintf("Ollama: %v", ollamaErr))
	}
	if searxErr != nil {
		errs = append(errs, fmt.Sprintf("SearXNG: %v", searxErr))
	}

	if len(errs) > 0 {
		return errors.New(strings.Join(errs, " | "))
	}

	if w != nil {
		fmt.Fprintf(w, "[Local Stack] All offline services active (Ollama: %s).\n", ollamaStatus.Endpoint)
		_ = flushWriter(w)
	}
	return nil
}

// ProbeOllamaEndpoint probes Ollama health across prioritized loopback endpoints.
// Returns whether it is healthy, the functional URL, and the active HTTP response body if healthy.
func ProbeOllamaEndpoint(ctx context.Context, baseURL string) (bool, string, *http.Response) {
	if baseURL == "" {
		baseURL = "http://127.0.0.1:11434"
	}
	cleanURL := strings.TrimRight(baseURL, "/")

	candidates := []string{}
	if strings.Contains(cleanURL, "localhost") {
		candidates = append(candidates, strings.Replace(cleanURL, "localhost", "127.0.0.1", 1))
	}
	candidates = append(candidates, cleanURL)
	if !strings.Contains(cleanURL, "127.0.0.1") && !strings.Contains(cleanURL, "localhost") {
		candidates = append(candidates, "http://127.0.0.1:11434")
	}

	client := &http.Client{Timeout: 1200 * time.Millisecond}
	for _, ep := range candidates {
		tagsURL := ep + "/api/tags"
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, tagsURL, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err == nil {
			if resp.StatusCode == http.StatusOK {
				return true, ep, resp
			}
			_ = resp.Body.Close()
		}
	}
	return false, cleanURL, nil
}

// EnsureOllamaRunning checks if Ollama is running and accessible at the specified URL.
// Auto-start logic has been removed; prompts user to start manually if unreachable.
func EnsureOllamaRunning(ctx context.Context, ollamaURL string, targetModel string, w io.Writer) (*ServiceStatus, error) {
	if ollamaURL == "" {
		ollamaURL = "http://127.0.0.1:11434"
	}
	cleanURL := strings.TrimRight(ollamaURL, "/")

	if ok, functionalURL, resp := ProbeOllamaEndpoint(ctx, cleanURL); ok {
		if targetModel != "" && resp != nil {
			verifyOllamaModel(resp.Body, targetModel, w)
		}
		if resp != nil {
			_ = resp.Body.Close()
		}
		return &ServiceStatus{
			Name:       "Ollama",
			Endpoint:   functionalURL,
			Running:    true,
			AutoBooted: false,
		}, nil
	}

	return nil, fmt.Errorf("Ollama is not running at %s. Please start Ollama manually (e.g. run 'ollama serve' in a terminal or launch Ollama from Start Menu)", cleanURL)
}

// EnsureSearXNGRunning checks if SearXNG is running and accessible at the specified URL.
// Auto-start logic has been removed; prompts user to start manually if unreachable.
func EnsureSearXNGRunning(ctx context.Context, searxngURL string, w io.Writer) (*ServiceStatus, error) {
	if searxngURL == "" {
		searxngURL = "http://127.0.0.1:8080"
	}
	cleanURL := strings.TrimRight(searxngURL, "/")

	if ok, _ := probeSearXNGEndpoint(ctx, cleanURL); ok {
		return &ServiceStatus{
			Name:       "SearXNG",
			Endpoint:   cleanURL,
			Running:    true,
			AutoBooted: false,
		}, nil
	}

	return nil, fmt.Errorf("SearXNG is not running at %s. Please start SearXNG manually (e.g. run 'docker start searxng')", cleanURL)
}

func probeSearXNGEndpoint(ctx context.Context, baseURL string) (bool, int) {
	cleanURL := strings.TrimRight(baseURL, "/")
	candidates := []string{}
	if strings.Contains(cleanURL, "localhost") {
		candidates = append(candidates, strings.Replace(cleanURL, "localhost", "127.0.0.1", 1))
	}
	candidates = append(candidates, cleanURL)

	client := &http.Client{Timeout: 1200 * time.Millisecond}
	for _, ep := range candidates {
		hReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, ep+"/healthz", nil)
		if resp, err := client.Do(hReq); err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return true, resp.StatusCode
			}
		}

		sReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, ep+"/search?q=ping&format=json", nil)
		sReq.Header.Set("Accept", "application/json")
		if resp, err := client.Do(sReq); err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return true, resp.StatusCode
			}
		}
	}

	return false, 0
}

func verifyOllamaModel(r io.Reader, targetModel string, w io.Writer) bool {
	var tags struct {
		Models []struct {
			Name  string `json:"name"`
			Model string `json:"model"`
		} `json:"models"`
	}
	if err := json.NewDecoder(r).Decode(&tags); err != nil {
		return false
	}
	for _, m := range tags.Models {
		if strings.EqualFold(m.Name, targetModel) || strings.EqualFold(m.Model, targetModel) ||
			strings.HasPrefix(strings.ToLower(m.Name), strings.ToLower(targetModel)+":") ||
			strings.HasPrefix(strings.ToLower(m.Model), strings.ToLower(targetModel)+":") {
			return true
		}
	}
	if w != nil {
		fmt.Fprintf(w, "  [!] Notice: Model %q is not installed in Ollama. Build or pull via: ollama pull %s\n", targetModel, targetModel)
		_ = flushWriter(w)
	}
	return false
}

func findOllamaBinary() (string, error) {
	if p, err := exec.LookPath("ollama"); err == nil {
		return p, nil
	}
	if runtime.GOOS == "windows" {
		localAppData := os.Getenv("LOCALAPPDATA")
		if localAppData != "" {
			candidate := filepath.Join(localAppData, "Programs", "Ollama", "ollama.exe")
			if fi, err := os.Stat(candidate); err == nil && !fi.IsDir() {
				return candidate, nil
			}
		}
		for _, envKey := range []string{"ProgramFiles", "ProgramFiles(x86)"} {
			if pf := os.Getenv(envKey); pf != "" {
				candidate := filepath.Join(pf, "Ollama", "ollama.exe")
				if fi, err := os.Stat(candidate); err == nil && !fi.IsDir() {
					return candidate, nil
				}
			}
		}
	}
	return "", errors.New("ollama binary not found in PATH or standard installation directory")
}

func flushWriter(w io.Writer) error {
	if f, ok := w.(*os.File); ok {
		return f.Sync()
	}
	return nil
}
