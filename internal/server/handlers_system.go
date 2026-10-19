package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/example/appaudit/internal/ai"
	"github.com/example/appaudit/internal/application"
	"github.com/example/appaudit/internal/provenance"
	"github.com/example/appaudit/internal/service"
)

// handleHealth returns a basic 200 OK health check for the server.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "ok",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
	s.logRequest(r.Method, r.URL.Path, r.RemoteAddr, http.StatusOK, time.Since(start), "Health check")
}

// handleClearCache purges all in-memory and persistent research caches.
func (s *Server) handleClearCache(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	if r.Method != http.MethodPost {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "Method not allowed. Use POST."})
		return
	}

	geminiBefore := ai.CacheEntryCount()
	deepseekBefore := ai.DeepSeekCacheEntryCount()
	ollamaBefore := ai.OllamaCacheEntryCount()
	forensicBefore := s.cache.Count()

	_ = ai.ClearGeminiCache()
	_ = ai.ClearDeepSeekCache()
	_ = ai.ClearOllamaCache()
	_ = s.cache.Clear()

	totalCleared := geminiBefore + deepseekBefore + ollamaBefore + forensicBefore

	s.logDetail("Purged research caches: Gemini=%d, DeepSeek=%d, Ollama=%d, Forensic=%d (Total: %d)",
		geminiBefore, deepseekBefore, ollamaBefore, forensicBefore, totalCleared)
	s.logRequest(r.Method, r.URL.Path, r.RemoteAddr, http.StatusOK, time.Since(start),
		fmt.Sprintf("Cache cleared (%d entries purged)", totalCleared))

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":                   "ok",
		"message":                  "All AI and forensic provenance caches cleared successfully",
		"total_cleared":            totalCleared,
		"gemini_entries_cleared":   geminiBefore,
		"deepseek_entries_cleared": deepseekBefore,
		"ollama_entries_cleared":   ollamaBefore,
		"forensic_entries_cleared": forensicBefore,
	})
}

// handleCacheStats returns the current number of cached entries.
func (s *Server) handleCacheStats(w http.ResponseWriter, r *http.Request) {
	geminiCount := ai.CacheEntryCount()
	deepseekCount := ai.DeepSeekCacheEntryCount()
	ollamaCount := ai.OllamaCacheEntryCount()
	forensicCount := s.cache.Count()
	total := geminiCount + deepseekCount + ollamaCount + forensicCount

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"total":    total,
		"gemini":   geminiCount,
		"deepseek": deepseekCount,
		"ollama":   ollamaCount,
		"forensic": forensicCount,
	})
}

// fileExists checks whether a path exists and is not a directory.
func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
}

// handleCompanyApps returns all applications registered in the enterprise company manifest.
func (s *Server) handleCompanyApps(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	manifest, err := application.LoadCompanyManifest()
	if err != nil {
		s.logError("Failed to load company manifest: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "error",
			"error":  fmt.Sprintf("Failed to load company manifest: %v", err),
		})
		return
	}

	manifestPath, _ := application.CompanyManifestPath()
	apps := manifest.ListApps()
	if apps == nil {
		apps = []application.CompanyAppEntry{}
	}

	s.logRequest(r.Method, r.URL.Path, r.RemoteAddr, http.StatusOK, time.Since(start),
		fmt.Sprintf("Listed %d in-house applications", len(apps)))

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":        "ok",
		"count":         len(apps),
		"manifest_path": manifestPath,
		"apps":          apps,
	})
}

// CompanyRegisterRequest represents parameters to register an in-house company tool.
type CompanyRegisterRequest struct {
	Path        string `json:"path"`
	Name        string `json:"name"`
	SHA256      string `json:"sha256"`
	Description string `json:"description"`
}

// handleCompanyRegister registers a new enterprise in-house binary by path, hash, or upload.
func (s *Server) handleCompanyRegister(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "error",
			"error":  "Method not allowed. Use POST.",
		})
		return
	}

	manifest, err := application.LoadCompanyManifest()
	if err != nil {
		s.logError("Failed to load company manifest: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "error",
			"error":  fmt.Sprintf("Failed to load company manifest: %v", err),
		})
		return
	}

	var entry *application.CompanyAppEntry
	contentType := r.Header.Get("Content-Type")

	if strings.HasPrefix(contentType, "multipart/form-data") {
		if err := r.ParseMultipartForm(MaxUploadBytes); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status": "error",
				"error":  fmt.Sprintf("Failed to parse form: %v", err),
			})
			return
		}

		appName := strings.TrimSpace(r.FormValue("name"))
		appDesc := strings.TrimSpace(r.FormValue("description"))
		pathOverride := strings.TrimSpace(r.FormValue("path"))

		file, header, err := r.FormFile("file")
		if err != nil {
			file, header, err = r.FormFile("binary")
		}

		if err != nil {
			targetPath := strings.Trim(strings.TrimSpace(r.FormValue("path")), "\"'")
			targetSHA := strings.TrimSpace(r.FormValue("sha256"))
			if targetPath == "" && targetSHA == "" {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"status": "error",
					"error":  "Missing file or binary path to register",
				})
				return
			}
			if targetPath != "" && fileExists(targetPath) {
				entry, err = manifest.RegisterAppWithDetails(targetPath, appName, pathOverride, appDesc)
			} else if targetSHA != "" {
				entry, err = manifest.RegisterAppByHash(targetSHA, appName, targetPath, appDesc)
			} else {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"status": "error",
					"error":  fmt.Sprintf("Target file not found at path %q on host", targetPath),
				})
				return
			}
		} else {
			defer file.Close()
			origName := header.Filename
			if appName == "" {
				appName = strings.TrimSuffix(origName, filepath.Ext(origName))
			}
			tempFile, err := os.CreateTemp("", "company-upload-*.exe")
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"status": "error",
					"error":  fmt.Sprintf("Failed to create temporary file: %v", err),
				})
				return
			}
			tempPath := tempFile.Name()
			defer os.Remove(tempPath)

			if _, err := io.Copy(tempFile, file); err != nil {
				tempFile.Close()
				w.WriteHeader(http.StatusInternalServerError)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"status": "error",
					"error":  fmt.Sprintf("Failed to write temporary upload: %v", err),
				})
				return
			}
			tempFile.Close()

			dispPath := origName
			if pathOverride != "" {
				dispPath = pathOverride
			}
			entry, err = manifest.RegisterAppWithDetails(tempPath, appName, dispPath, appDesc)
		}
	} else {
		var req CompanyRegisterRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status": "error",
				"error":  fmt.Sprintf("Invalid JSON body: %v", err),
			})
			return
		}

		cleanPath := strings.Trim(strings.TrimSpace(req.Path), "\"'")
		cleanSHA := strings.TrimSpace(req.SHA256)
		cleanName := strings.TrimSpace(req.Name)
		cleanDesc := strings.TrimSpace(req.Description)

		if cleanPath == "" && cleanSHA == "" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status": "error",
				"error":  "Either 'path' or 'sha256' is required to register an in-house application",
			})
			return
		}

		if cleanPath != "" && fileExists(cleanPath) {
			entry, err = manifest.RegisterAppWithDetails(cleanPath, cleanName, "", cleanDesc)
		} else if cleanSHA != "" {
			entry, err = manifest.RegisterAppByHash(cleanSHA, cleanName, cleanPath, cleanDesc)
		} else {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status": "error",
				"error":  fmt.Sprintf("File not found at specified path %q on the server host. Please ensure the path exists or provide its SHA-256 hash.", cleanPath),
			})
			return
		}
	}

	if err != nil {
		s.logError("Failed to register in-house app: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "error",
			"error":  fmt.Sprintf("Registration failed: %v", err),
		})
		return
	}

	// Invalidate forensic and AI caches for this hash so subsequent scans immediately exit at Stage 1
	if entry != nil && entry.SHA256 != "" {
		s.cache.Delete(entry.SHA256)
		_ = ai.ClearGeminiCache()
		_ = ai.ClearDeepSeekCache()
		_ = ai.ClearOllamaCache()
	}

	manifestPath, _ := application.CompanyManifestPath()
	s.logSuccess("Registered in-house company app: '%s' (SHA-256: %s)", entry.Name, entry.SHA256)
	s.logRequest(r.Method, r.URL.Path, r.RemoteAddr, http.StatusOK, time.Since(start),
		fmt.Sprintf("Registered in-house app '%s'", entry.Name))

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":        "ok",
		"success":       true,
		"message":       fmt.Sprintf("Successfully registered '%s' as in-house company application", entry.Name),
		"manifest_path": manifestPath,
		"entry":         entry,
	})
}

// CompanyRemoveRequest represents parameters to unregister an in-house company tool.
type CompanyRemoveRequest struct {
	Identifier string `json:"identifier"`
}

// handleCompanyRemove deletes an application from the company manifest.
func (s *Server) handleCompanyRemove(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodPost && r.Method != http.MethodDelete {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "error",
			"error":  "Method not allowed. Use POST or DELETE.",
		})
		return
	}

	var req CompanyRemoveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "error",
			"error":  fmt.Sprintf("Invalid JSON body: %v", err),
		})
		return
	}

	id := strings.TrimSpace(req.Identifier)
	if id == "" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "error",
			"error":  "Field 'identifier' is required",
		})
		return
	}

	manifest, err := application.LoadCompanyManifest()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "error",
			"error":  fmt.Sprintf("Failed to load company manifest: %v", err),
		})
		return
	}

	removed, err := manifest.RemoveApp(id)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "error",
			"error":  fmt.Sprintf("Failed to remove app: %v", err),
		})
		return
	}

	if !removed {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"success": false,
			"message": fmt.Sprintf("No application matching %q found in company manifest", id),
		})
		return
	}

	s.cache.Delete(id)
	_ = ai.ClearGeminiCache()
	_ = ai.ClearDeepSeekCache()
	_ = ai.ClearOllamaCache()

	s.logRequest(r.Method, r.URL.Path, r.RemoteAddr, http.StatusOK, time.Since(start),
		fmt.Sprintf("Removed company app %q", id))

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "ok",
		"success": true,
		"message": fmt.Sprintf("Successfully removed %q from company manifest", id),
	})
}

func (s *Server) getGeminiKey() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.sessionGeminiKey != "" {
		return s.sessionGeminiKey
	}
	if s.cfg.GeminiKey != "" {
		return s.cfg.GeminiKey
	}
	return ai.GetGeminiAPIKey("")
}

func (s *Server) getDeepSeekKey() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.sessionDeepSeekKey != "" {
		return s.sessionDeepSeekKey
	}
	if s.cfg.DeepSeekKey != "" {
		return s.cfg.DeepSeekKey
	}
	return ai.GetDeepSeekAPIKey("")
}

func (s *Server) getActiveModel(mode string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	switch strings.ToLower(mode) {
	case "gemini":
		if s.activeGeminiModel != "" {
			return s.activeGeminiModel
		}
		return ai.GetActiveGeminiModel()
	case "deepseek":
		if s.activeDeepSeekModel != "" {
			return s.activeDeepSeekModel
		}
		return ai.GetActiveDeepSeekModel()
	case "ollama":
		if s.activeOllamaModel != "" {
			return s.activeOllamaModel
		}
		return ai.GetActiveOllamaModel()
	default:
		return "none"
	}
}

func (s *Server) getEffectivePrompt() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if strings.TrimSpace(s.customPrompt) != "" {
		return s.customPrompt
	}
	if p := ai.GetCustomSystemPrompt(); p != "" {
		return p
	}
	return ai.UnifiedSystemPrompt
}

func isOllamaTextOnly(name string, families []string) bool {
	lowerName := strings.ToLower(name)
	multimodalKeywords := []string{
		"vision", "llava", "moondream", "minicpm-v", "qwen-vl", "qwen2-vl",
		"clip", "mllama", "paligemma", "cogvlm", "bakllava", "image",
	}
	for _, kw := range multimodalKeywords {
		if strings.Contains(lowerName, kw) {
			return false
		}
		for _, fam := range families {
			if strings.Contains(strings.ToLower(fam), kw) {
				return false
			}
		}
	}
	return true
}

func (s *Server) handleAIConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	gemKey := s.getGeminiKey()
	dsKey := s.getDeepSeekKey()

	resp := map[string]interface{}{
		"gemini": map[string]interface{}{
			"configured":   gemKey != "",
			"masked_key":   ai.MaskAPIKey(gemKey),
			"cached":       ai.HasStoredGeminiAPIKey(),
			"active_model": s.getActiveModel("gemini"),
		},
		"gemini_has_key":      gemKey != "",
		"gemini_key_masked":   ai.MaskAPIKey(gemKey),
		"gemini_cached":       ai.HasStoredGeminiAPIKey(),
		"gemini_active_model": s.getActiveModel("gemini"),

		"deepseek": map[string]interface{}{
			"configured":   dsKey != "",
			"masked_key":   ai.MaskAPIKey(dsKey),
			"cached":       ai.HasStoredDeepSeekAPIKey(),
			"active_model": s.getActiveModel("deepseek"),
		},
		"deepseek_has_key":      dsKey != "",
		"deepseek_key_masked":   ai.MaskAPIKey(dsKey),
		"deepseek_cached":       ai.HasStoredDeepSeekAPIKey(),
		"deepseek_active_model": s.getActiveModel("deepseek"),

		"ollama": map[string]interface{}{
			"active_model": s.getActiveModel("ollama"),
			"url":          s.cfg.OllamaURL,
		},
		"ollama_active_model": s.getActiveModel("ollama"),

		"prompt": map[string]interface{}{
			"custom":  s.customPrompt,
			"default": ai.UnifiedSystemPrompt,
			"active":  s.getEffectivePrompt(),
		},
		"system_prompt":    s.getEffectivePrompt(),
		"is_custom_prompt": s.customPrompt != "" || ai.GetCustomSystemPrompt() != "",
	}
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleConfigKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Provider string `json:"provider"`
		Key      string `json:"key"`
		Cache    bool   `json:"cache"`
		Persist  bool   `json:"persist"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid JSON payload"}`, http.StatusBadRequest)
		return
	}
	key := strings.Trim(strings.TrimSpace(req.Key), "\"'")
	if key == "" {
		http.Error(w, `{"error":"API key cannot be empty"}`, http.StatusBadRequest)
		return
	}

	shouldPersist := req.Cache || req.Persist
	provider := strings.ToLower(strings.TrimSpace(req.Provider))
	s.mu.Lock()
	switch provider {
	case "gemini":
		s.sessionGeminiKey = key
		if shouldPersist {
			_ = ai.SaveGeminiAPIKey(key)
		}
	case "deepseek":
		s.sessionDeepSeekKey = key
		if shouldPersist {
			_ = ai.SaveDeepSeekAPIKey(key)
		}
	default:
		s.mu.Unlock()
		http.Error(w, `{"error":"Unsupported provider. Use 'gemini' or 'deepseek'."}`, http.StatusBadRequest)
		return
	}
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":     "ok",
		"success":    true,
		"provider":   provider,
		"masked_key": ai.MaskAPIKey(key),
		"cached":     shouldPersist,
	})
}

func (s *Server) handleConfigForget(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Provider string `json:"provider"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	provider := strings.ToLower(strings.TrimSpace(req.Provider))

	s.mu.Lock()
	if provider == "gemini" || provider == "all" || provider == "" {
		_ = ai.ClearGeminiAPIKey()
		s.sessionGeminiKey = ""
		_ = ai.ClearGeminiCache()
	}
	if provider == "deepseek" || provider == "all" || provider == "" {
		_ = ai.ClearDeepSeekAPIKey()
		s.sessionDeepSeekKey = ""
		_ = ai.ClearDeepSeekCache()
	}
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "ok",
		"success": true,
		"message": "API key successfully forgotten",
	})
}

func (s *Server) handleConfigModel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Provider string `json:"provider"`
		Model    string `json:"model"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid JSON payload"}`, http.StatusBadRequest)
		return
	}
	model := strings.TrimSpace(req.Model)
	if model == "" {
		http.Error(w, `{"error":"Model name cannot be empty"}`, http.StatusBadRequest)
		return
	}
	provider := strings.ToLower(strings.TrimSpace(req.Provider))

	s.mu.Lock()
	switch provider {
	case "gemini":
		s.activeGeminiModel = model
		_ = ai.SaveActiveGeminiModel(model)
	case "deepseek":
		s.activeDeepSeekModel = model
		_ = ai.SaveActiveDeepSeekModel(model)
	case "ollama":
		s.activeOllamaModel = model
		_ = ai.SaveActiveOllamaModel(model)
	default:
		s.mu.Unlock()
		http.Error(w, `{"error":"Unsupported provider. Use 'gemini', 'deepseek', or 'ollama'."}`, http.StatusBadRequest)
		return
	}
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":       "ok",
		"success":      true,
		"provider":     provider,
		"active_model": model,
	})
}

func (s *Server) handleConfigPrompt(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if r.Method == http.MethodGet {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":         "ok",
			"default_prompt": ai.UnifiedSystemPrompt,
			"custom_prompt":  s.customPrompt,
			"active_prompt":  s.getEffectivePrompt(),
		})
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Prompt string `json:"prompt"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid JSON payload"}`, http.StatusBadRequest)
		return
	}
	newPrompt := strings.TrimSpace(req.Prompt)

	s.mu.Lock()
	s.customPrompt = newPrompt
	_ = ai.SaveCustomSystemPrompt(newPrompt)
	s.mu.Unlock()

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":        "ok",
		"success":       true,
		"active_prompt": s.getEffectivePrompt(),
	})
}

func (s *Server) handleConfigPromptReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	s.mu.Lock()
	s.customPrompt = ""
	_ = ai.ClearCustomSystemPrompt()
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":         "ok",
		"success":        true,
		"default_prompt": ai.UnifiedSystemPrompt,
		"active_prompt":  ai.UnifiedSystemPrompt,
	})
}

func (s *Server) handleModelsOllama(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()

	ok, workingURL, resp := service.ProbeOllamaEndpoint(ctx, s.cfg.OllamaURL)
	if !ok || resp == nil {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "offline",
			"error":  "Ollama service is currently stopped or unreachable. Please launch Ollama manually (e.g. run 'ollama serve' in a terminal or open Ollama from Start Menu) and click 'Refresh Local Models'.",
			"models": []string{},
		})
		return
	}
	defer resp.Body.Close()
	_ = workingURL

	if resp.StatusCode != http.StatusOK {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "error",
			"error":  fmt.Sprintf("Ollama returned HTTP %d", resp.StatusCode),
			"models": []string{},
		})
		return
	}

	var tagsResp struct {
		Models []struct {
			Name    string `json:"name"`
			Model   string `json:"model"`
			Details struct {
				Families []string `json:"families"`
				Family   string   `json:"family"`
			} `json:"details"`
		} `json:"models"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tagsResp); err != nil {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "error",
			"error":  fmt.Sprintf("Failed to parse Ollama model tags: %v", err),
			"models": []string{},
		})
		return
	}

	var textModels []string
	for _, m := range tagsResp.Models {
		name := m.Name
		if name == "" {
			name = m.Model
		}
		if name == "" {
			continue
		}
		if isOllamaTextOnly(name, m.Details.Families) {
			textModels = append(textModels, name)
		}
	}

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "ok",
		"models": textModels,
	})
}

func isGeminiTextOnly(name string) bool {
	clean := strings.TrimPrefix(name, "models/")
	lower := strings.ToLower(clean)

	if !strings.HasPrefix(lower, "gemini-") && !strings.HasPrefix(lower, "gemma-") {
		return false
	}

	excluded := []string{
		"image", "imagen", "tts", "transcribe", "speech", "audio", "lyria",
		"music", "robotics", "robot", "computer-use", "nano-banana", "embedding",
		"embed", "aqa", "customtools", "custom-tools", "omni",
	}
	for _, kw := range excluded {
		if strings.Contains(lower, kw) {
			return false
		}
	}
	return true
}

func hasZeroRequestsPerDay(m map[string]interface{}) bool {
	quotaKeys := []string{
		"requestsPerDay", "requests_per_day", "maxRequestsPerDay", "max_requests_per_day",
		"rpd", "freeTierRequestsPerDay", "free_tier_requests_per_day", "freeTierRequests",
		"free_tier_requests",
	}

	for _, k := range quotaKeys {
		if v, ok := m[k]; ok {
			if isZeroQuotaValue(v) {
				return true
			}
		}
	}

	nestedObjects := []string{"rateLimits", "rate_limits", "quota", "freeTier", "free_tier", "limits"}
	for _, no := range nestedObjects {
		if sub, ok := m[no].(map[string]interface{}); ok {
			for _, k := range quotaKeys {
				if v, ok := sub[k]; ok {
					if isZeroQuotaValue(v) {
						return true
					}
				}
			}
		}
	}

	return false
}

func isZeroQuotaValue(v interface{}) bool {
	switch val := v.(type) {
	case float64:
		return val == 0
	case int:
		return val == 0
	case int64:
		return val == 0
	case string:
		trimmed := strings.TrimSpace(val)
		return trimmed == "0" || strings.EqualFold(trimmed, "none")
	}
	return false
}

func isGeminiModelAvailableFreeTier(cleanName string, m map[string]interface{}) bool {
	if !isGeminiTextOnly(cleanName) {
		return false
	}
	if hasZeroRequestsPerDay(m) {
		return false
	}
	return true
}

func (s *Server) handleModelsGemini(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	key := s.getGeminiKey()
	if key == "" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "error",
			"error":  "No Gemini API key configured. Enter API key to load models.",
			"models": []string{},
		})
		return
	}

	apiURL := fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models?key=%s", url.QueryEscape(key))
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(apiURL)
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "error",
			"error":  fmt.Sprintf("Failed to query Gemini API: %v", err),
			"models": []string{},
		})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		w.WriteHeader(resp.StatusCode)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "error",
			"error":  fmt.Sprintf("Gemini API error (HTTP %d): %s", resp.StatusCode, string(body)),
			"models": []string{},
		})
		return
	}

	var geminiResp struct {
		Models []map[string]interface{} `json:"models"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&geminiResp); err != nil {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "error",
			"error":  "Failed to parse Gemini model catalogue",
			"models": []string{},
		})
		return
	}

	var validModels []string
	for _, m := range geminiResp.Models {
		rawName, _ := m["name"].(string)
		cleanName := strings.TrimPrefix(rawName, "models/")

		supportsGenerate := false
		if methods, ok := m["supportedGenerationMethods"].([]interface{}); ok {
			for _, method := range methods {
				if methodStr, ok := method.(string); ok && methodStr == "generateContent" {
					supportsGenerate = true
					break
				}
			}
		}
		if !supportsGenerate {
			continue
		}

		if !isGeminiModelAvailableFreeTier(cleanName, m) {
			continue
		}
		validModels = append(validModels, cleanName)
	}

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "ok",
		"models": validModels,
	})
}

func (s *Server) handleModelsDeepSeek(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	key := s.getDeepSeekKey()
	if key == "" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "error",
			"error":  "No DeepSeek API key configured. Enter API key to load models.",
			"models": []string{},
		})
		return
	}

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest(http.MethodGet, "https://api.deepseek.com/models", nil)
	if err != nil {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "error",
			"error":  err.Error(),
			"models": []string{},
		})
		return
	}
	req.Header.Set("Authorization", "Bearer "+key)

	resp, err := client.Do(req)
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "error",
			"error":  fmt.Sprintf("Failed to query DeepSeek API: %v", err),
			"models": []string{},
		})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		w.WriteHeader(resp.StatusCode)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "error",
			"error":  fmt.Sprintf("DeepSeek API error (HTTP %d): %s", resp.StatusCode, string(body)),
			"models": []string{},
		})
		return
	}

	var dsResp struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&dsResp); err != nil {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "error",
			"error":  "Failed to parse DeepSeek models",
			"models": []string{},
		})
		return
	}

	var validModels []string
	for _, m := range dsResp.Data {
		if strings.TrimSpace(m.ID) != "" {
			validModels = append(validModels, strings.TrimSpace(m.ID))
		}
	}
	if len(validModels) == 0 {
		validModels = []string{"deepseek-chat", "deepseek-reasoner"}
	}

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "ok",
		"models": validModels,
	})
}

func (s *Server) handleDialogFolder(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	path, err := showNativeFolderDialog("Select Folder to Audit")
	if err != nil {
		s.logWarn("Native folder dialog error: %v", err)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "error",
			"error":  err.Error(),
			"path":   "",
		})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "ok",
		"cancelled": path == "",
		"path":      path,
	})
}

func (s *Server) handleDialogFile(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	path, err := showNativeFileDialog("Select Application Executable", "")
	if err != nil {
		s.logWarn("Native file dialog error: %v", err)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "error",
			"error":  err.Error(),
			"path":   "",
		})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "ok",
		"cancelled": path == "",
		"path":      path,
	})
}

// validateEngineKeys ensures that required API keys are present before starting a scan with an online cloud provider.
func (s *Server) validateEngineKeys(mode string, modes []string) error {
	modesToCheck := []string{}
	if mode != "" {
		modesToCheck = append(modesToCheck, mode)
	}
	modesToCheck = append(modesToCheck, modes...)

	for _, m := range modesToCheck {
		switch strings.ToLower(strings.TrimSpace(m)) {
		case "gemini":
			if s.getGeminiKey() == "" {
				return errors.New("Gemini API key is required but not configured. Please enter your Gemini API key in the AI & Models drawer before running scans with Gemini.")
			}
		case "deepseek":
			if s.getDeepSeekKey() == "" {
				return errors.New("DeepSeek API key is required but not configured. Please enter your DeepSeek API key in the AI & Models drawer before running scans with DeepSeek.")
			}
		}
	}
	return nil
}

func (s *Server) buildEngineForMode(ctx context.Context, mode string, customModel ...string) (*application.Engine, error) {
	var reasoner ai.Reasoner = ai.NewNoopReasoner()
	netMode := provenance.NetworkOff

	activeModel := ""
	if len(customModel) > 0 && strings.TrimSpace(customModel[0]) != "" {
		activeModel = strings.TrimSpace(customModel[0])
	} else {
		activeModel = s.getActiveModel(mode)
	}
	effectivePrompt := s.getEffectivePrompt()

	switch strings.ToLower(mode) {
	case "ollama":
		netMode = provenance.NetworkOn
		if activeModel == "" {
			activeModel = ai.DefaultOllamaModel
		}
		s.logDetail("[Local Stack] Verifying Ollama and SearXNG connectivity...")
		supCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		supErr := service.EnsureLocalStackWithOptions(supCtx, service.LocalStackOptions{
			OllamaURL:   s.cfg.OllamaURL,
			OllamaModel: activeModel,
			SearXNGURL:  s.cfg.SearXNGURL,
			Writer:      os.Stdout,
		})
		cancel()
		if supErr != nil {
			s.logError("Local AI Stack connectivity check failed: %v", supErr)
			return nil, fmt.Errorf("Local AI Stack unavailable: %w. Please ensure your Ollama ('ollama serve') and SearXNG services are started manually", supErr)
		}

		searx := ai.NewSearXNGProvider(s.cfg.SearXNGURL)
		cache := ai.NewOllamaCache()
		ollamaBase := strings.Replace(s.cfg.OllamaURL, "localhost:11434", "127.0.0.1:11434", 1)
		localR := ai.NewLocalReasoner(activeModel, searx, cache, ollamaBase)
		localR.SystemPrompt = effectivePrompt

		if err := localR.PreflightGPUCheck(ctx); err != nil {
			s.logError("Local Ollama GPU preflight error: %v", err)
			return nil, fmt.Errorf("Ollama GPU preflight refused: %w. Ensure model %q is pulled ('ollama pull %s') and fits in GPU VRAM", err, activeModel, activeModel)
		}
		reasoner = localR

	case "gemini":
		netMode = provenance.NetworkOn
		key := s.getGeminiKey()
		if key == "" {
			return nil, errors.New("Gemini API key is not configured. Please enter your Gemini API key in the AI Settings drawer or switch to Deterministic mode")
		}
		if activeModel == "" {
			activeModel = ai.DefaultGeminiModel
		}
		reasoner = ai.NewGeminiReasoner(ai.GeminiConfig{
			APIKey:            key,
			Model:             activeModel,
			AllowAnyModel:     true,
			SystemInstruction: effectivePrompt,
			NetworkMode:       provenance.NetworkOn,
		})

	case "deepseek":
		netMode = provenance.NetworkOn
		key := s.getDeepSeekKey()
		if key == "" {
			return nil, errors.New("DeepSeek API key is not configured. Please enter your DeepSeek API key in the AI Settings drawer or switch to Deterministic mode")
		}
		if activeModel == "" {
			activeModel = ai.DefaultDeepSeekModel
		}
		reasoner = ai.NewDeepSeekReasoner(ai.DeepSeekConfig{
			APIKey:          key,
			Model:           activeModel,
			SystemPrompt:    effectivePrompt,
			NetworkMode:     provenance.NetworkOn,
			EnableWebSearch: true,
		})

	default: // "none"
		netMode = provenance.NetworkOff
		reasoner = ai.NewNoopReasoner()
	}

	return application.NewEngine(application.EngineConfig{
		NetworkMode:             netMode,
		CompanyDomainIndicators: ai.GetCompanyIndicators(),
		Reasoner:                reasoner,
		Cache:                   s.cache,
	}), nil
}
