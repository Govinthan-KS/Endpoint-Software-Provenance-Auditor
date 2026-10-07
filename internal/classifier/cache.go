package classifier

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// CacheEntry represents the cached online verification verdict for a binary.
type CacheEntry struct {
	IsThirdParty bool      `json:"is_third_party"`
	Evidence     string    `json:"evidence,omitempty"`
	CachedAt     time.Time `json:"cached_at,omitempty"`
}

// ResolutionCache provides thread-safe access to persistent resolution results.
type ResolutionCache struct {
	mu       sync.RWMutex
	filePath string
	entries  map[string]CacheEntry
	dirty    bool
}

// GetCacheFilePath returns the platform-specific cache file path:
// - Windows: %LOCALAPPDATA%\audit\resolved_cache.json
// - Linux/macOS/BSD: ~/.cache/audit/resolved_cache.json
func GetCacheFilePath() string {
	if runtime.GOOS == "windows" {
		localAppData := os.Getenv("LOCALAPPDATA")
		if localAppData == "" {
			home, err := os.UserHomeDir()
			if err == nil {
				localAppData = filepath.Join(home, "AppData", "Local")
			}
		}
		if localAppData != "" {
			return filepath.Join(localAppData, "audit", "resolved_cache.json")
		}
	}

	cacheHome := os.Getenv("XDG_CACHE_HOME")
	if cacheHome == "" {
		home, err := os.UserHomeDir()
		if err == nil {
			cacheHome = filepath.Join(home, ".cache")
		}
	}
	if cacheHome != "" {
		return filepath.Join(cacheHome, "audit", "resolved_cache.json")
	}

	return filepath.Join(".", "resolved_cache.json")
}

// NormalizeBinaryKey returns a normalized key from a binary name or path:
// lowercased, trimmed, with .exe extension stripped.
func NormalizeBinaryKey(raw string) string {
	base := filepath.Base(raw)
	base = strings.ToLower(base)
	base = strings.TrimSuffix(base, ".exe")
	return strings.TrimSpace(base)
}

// NewResolutionCache loads or initializes the persistent cache from disk.
func NewResolutionCache(customPath ...string) *ResolutionCache {
	path := GetCacheFilePath()
	if len(customPath) > 0 && customPath[0] != "" {
		path = customPath[0]
	}

	cache := &ResolutionCache{
		filePath: path,
		entries:  make(map[string]CacheEntry),
	}
	cache.load()
	return cache
}

func (c *ResolutionCache) load() {
	if c.filePath == "" {
		return
	}
	data, err := os.ReadFile(c.filePath)
	if err != nil {
		return
	}
	var loaded map[string]CacheEntry
	if err := json.Unmarshal(data, &loaded); err == nil && loaded != nil {
		c.entries = loaded
	}
}

// Get looks up a binary in the cache using its normalized name.
func (c *ResolutionCache) Get(binaryName string) (CacheEntry, bool) {
	key := NormalizeBinaryKey(binaryName)
	if key == "" {
		return CacheEntry{}, false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, ok := c.entries[key]
	return entry, ok
}

// Set stores a resolution result in the cache.
func (c *ResolutionCache) Set(binaryName string, entry CacheEntry) {
	key := NormalizeBinaryKey(binaryName)
	if key == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if entry.CachedAt.IsZero() {
		entry.CachedAt = time.Now()
	}
	c.entries[key] = entry
	c.dirty = true
}

// Save persists any modifications to the cache file on disk.
func (c *ResolutionCache) Save() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.dirty || c.filePath == "" {
		return nil
	}

	dir := filepath.Dir(c.filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(c.entries, "", "  ")
	if err != nil {
		return err
	}

	tmpFile := c.filePath + ".tmp"
	if err := os.WriteFile(tmpFile, data, 0644); err != nil {
		return os.WriteFile(c.filePath, data, 0644)
	}

	// Remove target first so atomic rename succeeds cleanly on Windows
	_ = os.Remove(c.filePath)
	if err := os.Rename(tmpFile, c.filePath); err != nil {
		_ = os.Remove(tmpFile)
		return os.WriteFile(c.filePath, data, 0644)
	}

	c.dirty = false
	return nil
}
