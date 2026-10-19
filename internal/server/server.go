package server

import (
	"context"
	_ "embed"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"sync"
	"time"

	"github.com/example/appaudit/internal/ai"
	"github.com/example/appaudit/internal/provenance"
)

//go:embed web/index.html
var indexHTML []byte

// Config holds configuration for the HTTP server.
type Config struct {
	Port            int
	OllamaURL       string
	SearXNGURL      string
	GeminiKey       string
	DeepSeekKey     string
	SharedCache     *provenance.ProvenanceCache
	Verbose         bool
	AutoOpenBrowser bool
}

// Server encapsulates the embedded web dashboard and HTTP API.
type Server struct {
	cfg                 Config
	httpServer          *http.Server
	cache               *provenance.ProvenanceCache
	mu                  sync.RWMutex
	sessionGeminiKey    string
	sessionDeepSeekKey  string
	activeGeminiModel   string
	activeDeepSeekModel string
	activeOllamaModel   string
	customPrompt        string
}

// NewServer initializes a new Server instance and registers all HTTP endpoints.
func NewServer(cfg Config) *Server {
	if cfg.Port <= 0 {
		cfg.Port = 8085
	}
	if cfg.OllamaURL == "" {
		cfg.OllamaURL = "http://localhost:11434"
	}
	if cfg.SearXNGURL == "" {
		cfg.SearXNGURL = "http://localhost:8080"
	}
	if cfg.SharedCache == nil {
		cfg.SharedCache = provenance.NewProvenanceCache()
	}

	s := &Server{
		cfg:                 cfg,
		cache:               cfg.SharedCache,
		activeGeminiModel:   ai.GetActiveGeminiModel(),
		activeDeepSeekModel: ai.GetActiveDeepSeekModel(),
		activeOllamaModel:   ai.GetActiveOllamaModel(),
		customPrompt:        ai.GetCustomSystemPrompt(),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/api/v1/health", s.handleHealth)

	// Single File Inspection (both routes supported)
	mux.HandleFunc("/api/v1/audit/upload", s.handleAuditSingle)
	mux.HandleFunc("/api/v1/audit", s.handleAuditSingle)

	// Engine Comparison Benchmark
	mux.HandleFunc("/api/v1/audit/compare", s.handleAuditCompare)

	// Host & Directory Scans
	mux.HandleFunc("/api/v1/audit/quick", s.handleAuditQuick)
	mux.HandleFunc("/api/v1/audit/full", s.handleAuditFull)
	mux.HandleFunc("/api/v1/audit/directory", s.handleAuditDirectory)

	// Cache Management
	mux.HandleFunc("/api/v1/cache/clear", s.handleClearCache)
	mux.HandleFunc("/api/v1/cache/stats", s.handleCacheStats)

	// In-House Company Manifest Management
	mux.HandleFunc("/api/v1/company/apps", s.handleCompanyApps)
	mux.HandleFunc("/api/v1/company/register", s.handleCompanyRegister)
	mux.HandleFunc("/api/v1/company/remove", s.handleCompanyRemove)

	// AI Engine, Model & Prompt Management
	mux.HandleFunc("/api/v1/config/ai", s.handleAIConfig)
	mux.HandleFunc("/api/v1/config/key", s.handleConfigKey)
	mux.HandleFunc("/api/v1/config/forget", s.handleConfigForget)
	mux.HandleFunc("/api/v1/config/model", s.handleConfigModel)
	mux.HandleFunc("/api/v1/config/prompt", s.handleConfigPrompt)
	mux.HandleFunc("/api/v1/config/prompt/reset", s.handleConfigPromptReset)
	mux.HandleFunc("/api/v1/models/ollama", s.handleModelsOllama)
	mux.HandleFunc("/api/v1/models/gemini", s.handleModelsGemini)
	mux.HandleFunc("/api/v1/models/deepseek", s.handleModelsDeepSeek)
	mux.HandleFunc("/api/v1/dialog/folder", s.handleDialogFolder)
	mux.HandleFunc("/api/v1/dialog/file", s.handleDialogFile)
	mux.HandleFunc("/api/v1/preflight/stats", s.handlePreflightStats)

	// Chrome DevTools Discovery & Favicon endpoints (silences 404 console errors in Chromium browsers)
	mux.HandleFunc("/.well-known/appspecific/com.chrome.devtools.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{}"))
	})
	mux.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/x-icon")
		w.WriteHeader(http.StatusNoContent)
	})

	s.httpServer = &http.Server{
		Addr:              fmt.Sprintf("127.0.0.1:%d", cfg.Port),
		Handler:           mux,
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	return s
}

// Start launches the HTTP server strictly bound to localhost (127.0.0.1).
func (s *Server) Start() error {
	addr := fmt.Sprintf("127.0.0.1:%d", s.cfg.Port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		originalPort := s.cfg.Port
		for fallbackPort := originalPort + 1; fallbackPort <= originalPort+50; fallbackPort++ {
			if fln, ferr := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", fallbackPort)); ferr == nil {
				fmt.Printf("[ℹ] Port %d is currently occupied. Automatically switched to free port %d.\n", originalPort, fallbackPort)
				s.cfg.Port = fallbackPort
				s.httpServer.Addr = fmt.Sprintf("127.0.0.1:%d", fallbackPort)
				ln = fln
				err = nil
				break
			}
		}
		if err != nil {
			return fmt.Errorf("unable to bind to port %d or any fallback port up to %d: %w", originalPort, originalPort+50, err)
		}
	}

	localURL := fmt.Sprintf("http://127.0.0.1:%d", s.cfg.Port)

	fmt.Println()
	fmt.Println("================================================================================")
	fmt.Printf(" AppAudit Web Dashboard & HTTP Server (Port %d)\n", s.cfg.Port)
	fmt.Println("================================================================================")
	fmt.Printf("[AppAudit Server] Running locally at %s\n", localURL)
	fmt.Println("[INFO] Press Ctrl+C in this terminal window to stop the server.")
	fmt.Println("--------------------------------------------------------------------------------")

	if s.cfg.AutoOpenBrowser {
		go func() {
			time.Sleep(300 * time.Millisecond)
			if err := OpenBrowser(localURL); err != nil {
				fmt.Printf("[!] Could not automatically open browser: %v\n", err)
				fmt.Printf("[INFO] Please open %s manually in your browser.\n", localURL)
			} else {
				fmt.Println("[OK] Web dashboard opened in default browser.")
			}
		}()
	}

	s.logInfo("Server ready locally on %s with dual-tier logging & engine comparisons.", localURL)
	return s.httpServer.Serve(ln)
}

// OpenBrowser opens the specified URL in the user's default web browser.
func OpenBrowser(targetURL string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", targetURL)
		if err := cmd.Start(); err == nil {
			return nil
		}
		cmd = exec.Command("cmd", "/c", "start", targetURL)
		return cmd.Start()
	case "darwin":
		cmd = exec.Command("open", targetURL)
		return cmd.Start()
	default:
		cmd = exec.Command("xdg-open", targetURL)
		return cmd.Start()
	}
}

// Stop gracefully shuts down the server.
func (s *Server) Stop(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}

// Handler returns the underlying http.Handler (useful for unit testing).
func (s *Server) Handler() http.Handler {
	return s.httpServer.Handler
}

// handleIndex serves the embedded dashboard UI.
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		s.logRequest(r.Method, r.URL.Path, r.RemoteAddr, http.StatusNotFound, time.Since(start), "Page not found")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(indexHTML)
	s.logRequest(r.Method, r.URL.Path, r.RemoteAddr, http.StatusOK, time.Since(start), "Served Dashboard UI")
}
