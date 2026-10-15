package ai

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	// EnvGeminiAPIKey defines the standard environment variable name for Gemini.
	EnvGeminiAPIKey = "GEMINI_API_KEY"

	// EnvDeepSeekAPIKey defines the standard environment variable name for DeepSeek.
	EnvDeepSeekAPIKey = "DEEPSEEK_API_KEY"

	// CredentialFileName is the local credentials storage file.
	CredentialFileName = "credentials.json"
)

type credentialStore struct {
	GeminiAPIKey       string   `json:"gemini_api_key,omitempty"`
	DeepSeekAPIKey     string   `json:"deepseek_api_key,omitempty"`
	CompanyIndicators  []string `json:"company_indicators,omitempty"`
	GeminiModel        string   `json:"gemini_model,omitempty"`
	DeepSeekModel      string   `json:"deepseek_model,omitempty"`
	OllamaModel        string   `json:"ollama_model,omitempty"`
	CustomSystemPrompt string   `json:"custom_system_prompt,omitempty"`
}

// ConfigDir returns the platform-appropriate configuration directory for appaudit.
// Windows: %APPDATA%\appaudit
// Unix/macOS: ~/.config/appaudit (or $XDG_CONFIG_HOME/appaudit)
func ConfigDir() (string, error) {
	if runtime.GOOS == "windows" {
		appData := os.Getenv("APPDATA")
		if appData != "" {
			return filepath.Join(appData, "appaudit"), nil
		}
	} else {
		xdg := os.Getenv("XDG_CONFIG_HOME")
		if xdg != "" {
			return filepath.Join(xdg, "appaudit"), nil
		}
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("unable to determine user home directory: %w", err)
	}

	if runtime.GOOS == "windows" {
		return filepath.Join(home, "AppData", "Roaming", "appaudit"), nil
	}
	return filepath.Join(home, ".config", "appaudit"), nil
}

// CredentialStoragePath returns the absolute path to the local credentials file.
func CredentialStoragePath() (string, error) {
	dir, err := ConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, CredentialFileName), nil
}

// GetGeminiAPIKey resolves the Gemini API key from explicit CLI override,
// the standard GEMINI_API_KEY environment variable, or the local credential store.
func GetGeminiAPIKey(explicitKey string) string {
	if explicit := strings.TrimSpace(explicitKey); explicit != "" {
		return explicit
	}

	if envKey := strings.TrimSpace(os.Getenv(EnvGeminiAPIKey)); envKey != "" {
		return envKey
	}

	dir, err := ConfigDir()
	if err != nil {
		return ""
	}

	credPath := filepath.Join(dir, CredentialFileName)
	data, err := os.ReadFile(credPath)
	if err != nil {
		return ""
	}

	var store credentialStore
	if err := json.Unmarshal(data, &store); err != nil {
		return ""
	}

	return strings.TrimSpace(store.GeminiAPIKey)
}

// SaveGeminiAPIKey persists the API key to the local user configuration directory
// using restricted file permissions (0600 on Unix, user-profile isolated on Windows).
func SaveGeminiAPIKey(key string) error {
	trimmed := strings.TrimSpace(key)
	if trimmed == "" {
		return fmt.Errorf("API key cannot be empty")
	}

	dir, err := ConfigDir()
	if err != nil {
		return err
	}

	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create config directory %s: %w", dir, err)
	}

	credPath := filepath.Join(dir, CredentialFileName)
	var store credentialStore
	if data, err := os.ReadFile(credPath); err == nil {
		_ = json.Unmarshal(data, &store)
	}
	store.GeminiAPIKey = trimmed

	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to encode credentials: %w", err)
	}

	if err := os.WriteFile(credPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write credentials to %s: %w", credPath, err)
	}

	return nil
}

// ClearGeminiAPIKey removes any stored credentials from the local configuration file.
func ClearGeminiAPIKey() error {
	dir, err := ConfigDir()
	if err != nil {
		return err
	}
	credPath := filepath.Join(dir, CredentialFileName)
	var store credentialStore
	if data, err := os.ReadFile(credPath); err == nil {
		_ = json.Unmarshal(data, &store)
	}
	store.GeminiAPIKey = ""
	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to encode credentials: %w", err)
	}
	if err := os.WriteFile(credPath, data, 0600); err != nil {
		return fmt.Errorf("failed to update credential file %s: %w", credPath, err)
	}
	return nil
}

// GetDeepSeekAPIKey resolves the DeepSeek API key from explicit CLI override,
// the DEEPSEEK_API_KEY environment variable, or the local credential store.
func GetDeepSeekAPIKey(explicitKey string) string {
	if explicit := strings.TrimSpace(explicitKey); explicit != "" {
		return explicit
	}

	if envKey := strings.TrimSpace(os.Getenv(EnvDeepSeekAPIKey)); envKey != "" {
		return envKey
	}

	dir, err := ConfigDir()
	if err != nil {
		return ""
	}

	credPath := filepath.Join(dir, CredentialFileName)
	data, err := os.ReadFile(credPath)
	if err != nil {
		return ""
	}

	var store credentialStore
	if err := json.Unmarshal(data, &store); err != nil {
		return ""
	}

	return strings.TrimSpace(store.DeepSeekAPIKey)
}

// SaveDeepSeekAPIKey persists the DeepSeek API key to the local user configuration directory.
func SaveDeepSeekAPIKey(key string) error {
	trimmed := strings.TrimSpace(key)
	if trimmed == "" {
		return fmt.Errorf("API key cannot be empty")
	}

	dir, err := ConfigDir()
	if err != nil {
		return err
	}

	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create config directory %s: %w", dir, err)
	}

	credPath := filepath.Join(dir, CredentialFileName)
	var store credentialStore
	if data, err := os.ReadFile(credPath); err == nil {
		_ = json.Unmarshal(data, &store)
	}
	store.DeepSeekAPIKey = trimmed

	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to encode credentials: %w", err)
	}

	if err := os.WriteFile(credPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write credentials to %s: %w", credPath, err)
	}

	return nil
}

// ClearDeepSeekAPIKey removes the DeepSeek API key from the local configuration file.
func ClearDeepSeekAPIKey() error {
	dir, err := ConfigDir()
	if err != nil {
		return err
	}
	credPath := filepath.Join(dir, CredentialFileName)
	var store credentialStore
	if data, err := os.ReadFile(credPath); err == nil {
		_ = json.Unmarshal(data, &store)
	}
	store.DeepSeekAPIKey = ""
	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to encode credentials: %w", err)
	}
	if err := os.WriteFile(credPath, data, 0600); err != nil {
		return fmt.Errorf("failed to update credential file %s: %w", credPath, err)
	}
	return nil
}

// HasStoredDeepSeekAPIKey reports whether a non-empty DeepSeek API key is saved.
func HasStoredDeepSeekAPIKey() bool {
	dir, err := ConfigDir()
	if err != nil {
		return false
	}
	credPath := filepath.Join(dir, CredentialFileName)
	data, err := os.ReadFile(credPath)
	if err != nil {
		return false
	}
	var store credentialStore
	if err := json.Unmarshal(data, &store); err != nil {
		return false
	}
	return strings.TrimSpace(store.DeepSeekAPIKey) != ""
}

// MaskAPIKey returns a safe, masked representation of an API key for display (e.g. AIza...xyz or sk-...xyz).
func MaskAPIKey(key string) string {
	trimmed := strings.TrimSpace(key)
	if len(trimmed) <= 8 {
		if len(trimmed) == 0 {
			return "(none configured)"
		}
		return "********"
	}
	prefix := trimmed[:4]
	suffix := trimmed[len(trimmed)-4:]
	return fmt.Sprintf("%s...%s", prefix, suffix)
}

// HasStoredGeminiAPIKey checks if a credentials file exists and contains a non-empty key.
func HasStoredGeminiAPIKey() bool {
	dir, err := ConfigDir()
	if err != nil {
		return false
	}
	credPath := filepath.Join(dir, CredentialFileName)
	data, err := os.ReadFile(credPath)
	if err != nil {
		return false
	}
	var store credentialStore
	if err := json.Unmarshal(data, &store); err != nil {
		return false
	}
	return strings.TrimSpace(store.GeminiAPIKey) != ""
}

// GetCompanyIndicators returns the configured company domain or certificate name indicators
// from the APPAUDIT_COMPANY_INDICATORS environment variable or the local configuration file.
func GetCompanyIndicators() []string {
	if env := strings.TrimSpace(os.Getenv("APPAUDIT_COMPANY_INDICATORS")); env != "" {
		parts := strings.Split(env, ",")
		var cleaned []string
		for _, p := range parts {
			if t := strings.TrimSpace(p); t != "" {
				cleaned = append(cleaned, t)
			}
		}
		if len(cleaned) > 0 {
			return cleaned
		}
	}

	dir, err := ConfigDir()
	if err != nil {
		return nil
	}

	credPath := filepath.Join(dir, CredentialFileName)
	data, err := os.ReadFile(credPath)
	if err != nil {
		return nil
	}

	var store credentialStore
	if err := json.Unmarshal(data, &store); err != nil {
		return nil
	}

	return store.CompanyIndicators
}

// SaveCompanyIndicators persists company name / domain indicators to the local configuration file.
func SaveCompanyIndicators(indicators []string) error {
	dir, err := ConfigDir()
	if err != nil {
		return err
	}

	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create config directory %s: %w", dir, err)
	}

	credPath := filepath.Join(dir, CredentialFileName)
	var store credentialStore
	if data, err := os.ReadFile(credPath); err == nil {
		_ = json.Unmarshal(data, &store)
	}

	store.CompanyIndicators = indicators

	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to encode credentials: %w", err)
	}

	if err := os.WriteFile(credPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write credentials to %s: %w", credPath, err)
	}

	return nil
}

// ClearCompanyIndicators removes configured company indicators from the local configuration file.
func ClearCompanyIndicators() error {
	return SaveCompanyIndicators(nil)
}

// GetActiveGeminiModel retrieves the configured active Gemini model from disk or returns default.
func GetActiveGeminiModel() string {
	dir, err := ConfigDir()
	if err != nil {
		return DefaultGeminiModel
	}
	credPath := filepath.Join(dir, CredentialFileName)
	data, err := os.ReadFile(credPath)
	if err != nil {
		return DefaultGeminiModel
	}
	var store credentialStore
	if err := json.Unmarshal(data, &store); err != nil || strings.TrimSpace(store.GeminiModel) == "" {
		return DefaultGeminiModel
	}
	return strings.TrimSpace(store.GeminiModel)
}

// SaveActiveGeminiModel persists the user's chosen Gemini model to credentials.json.
func SaveActiveGeminiModel(model string) error {
	dir, err := ConfigDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	credPath := filepath.Join(dir, CredentialFileName)
	var store credentialStore
	if data, err := os.ReadFile(credPath); err == nil {
		_ = json.Unmarshal(data, &store)
	}
	store.GeminiModel = strings.TrimSpace(model)
	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(credPath, data, 0600)
}

// GetActiveDeepSeekModel retrieves the configured active DeepSeek model or default.
func GetActiveDeepSeekModel() string {
	dir, err := ConfigDir()
	if err != nil {
		return DefaultDeepSeekModel
	}
	credPath := filepath.Join(dir, CredentialFileName)
	data, err := os.ReadFile(credPath)
	if err != nil {
		return DefaultDeepSeekModel
	}
	var store credentialStore
	if err := json.Unmarshal(data, &store); err != nil || strings.TrimSpace(store.DeepSeekModel) == "" {
		return DefaultDeepSeekModel
	}
	return strings.TrimSpace(store.DeepSeekModel)
}

// SaveActiveDeepSeekModel persists the user's chosen DeepSeek model.
func SaveActiveDeepSeekModel(model string) error {
	dir, err := ConfigDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	credPath := filepath.Join(dir, CredentialFileName)
	var store credentialStore
	if data, err := os.ReadFile(credPath); err == nil {
		_ = json.Unmarshal(data, &store)
	}
	store.DeepSeekModel = strings.TrimSpace(model)
	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(credPath, data, 0600)
}

// GetActiveOllamaModel retrieves the configured active Ollama model or default.
func GetActiveOllamaModel() string {
	dir, err := ConfigDir()
	if err != nil {
		return DefaultOllamaModel
	}
	credPath := filepath.Join(dir, CredentialFileName)
	data, err := os.ReadFile(credPath)
	if err != nil {
		return DefaultOllamaModel
	}
	var store credentialStore
	if err := json.Unmarshal(data, &store); err != nil || strings.TrimSpace(store.OllamaModel) == "" {
		return DefaultOllamaModel
	}
	return strings.TrimSpace(store.OllamaModel)
}

// SaveActiveOllamaModel persists the user's chosen Ollama model.
func SaveActiveOllamaModel(model string) error {
	dir, err := ConfigDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	credPath := filepath.Join(dir, CredentialFileName)
	var store credentialStore
	if data, err := os.ReadFile(credPath); err == nil {
		_ = json.Unmarshal(data, &store)
	}
	store.OllamaModel = strings.TrimSpace(model)
	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(credPath, data, 0600)
}

// GetCustomSystemPrompt retrieves any custom system prompt saved by the user, or empty string.
func GetCustomSystemPrompt() string {
	dir, err := ConfigDir()
	if err != nil {
		return ""
	}
	credPath := filepath.Join(dir, CredentialFileName)
	data, err := os.ReadFile(credPath)
	if err != nil {
		return ""
	}
	var store credentialStore
	if err := json.Unmarshal(data, &store); err != nil {
		return ""
	}
	return strings.TrimSpace(store.CustomSystemPrompt)
}

// SaveCustomSystemPrompt persists a custom system prompt to credentials.json.
func SaveCustomSystemPrompt(prompt string) error {
	dir, err := ConfigDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	credPath := filepath.Join(dir, CredentialFileName)
	var store credentialStore
	if data, err := os.ReadFile(credPath); err == nil {
		_ = json.Unmarshal(data, &store)
	}
	store.CustomSystemPrompt = strings.TrimSpace(prompt)
	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(credPath, data, 0600)
}

// ClearCustomSystemPrompt clears any custom system prompt, resetting back to the canonical default.
func ClearCustomSystemPrompt() error {
	return SaveCustomSystemPrompt("")
}

