package ai

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

const geminiCacheFileName = "gemini_cache.json"

// GeminiCache caches structured research results from Gemini API calls.
// The cache key is an immutable hash of the application identity, version,
// primary executable SHA-256, and suite binary layout.
type GeminiCache struct {
	mu       sync.RWMutex
	filePath string
	records  map[string]ReasoningResult
	dirty    bool
}

// NewGeminiCache initializes or loads the disk-backed research cache.
func NewGeminiCache(customPath ...string) *GeminiCache {
	path := ""
	if len(customPath) > 0 && customPath[0] != "" {
		path = customPath[0]
	} else {
		dir, err := ConfigDir()
		if err == nil {
			path = filepath.Join(dir, geminiCacheFileName)
		}
	}

	c := &GeminiCache{
		filePath: path,
		records:  make(map[string]ReasoningResult),
	}

	if path != "" {
		c.load()
	}
	return c
}

func (c *GeminiCache) load() {
	if c.filePath == "" {
		return
	}
	data, err := os.ReadFile(c.filePath)
	if err != nil {
		return
	}
	var loaded map[string]ReasoningResult
	if err := json.Unmarshal(data, &loaded); err == nil {
		c.records = loaded
	}
}

// ComputeCacheKey computes a deterministic SHA-256 cache key based on the application's
// identity candidate, version, primary executable SHA-256, and sibling count.
func ComputeCacheKey(appName, version, primarySHA256 string, siblingCount int) string {
	raw := fmt.Sprintf("%s|%s|%s|%d", appName, version, primarySHA256, siblingCount)
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

// Get retrieves a cached reasoning result if present.
func (c *GeminiCache) Get(key string) (ReasoningResult, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	res, ok := c.records[key]
	return res, ok
}

// Set stores a reasoning result in the cache and flushes to disk.
func (c *GeminiCache) Set(key string, res ReasoningResult) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.records[key] = res
	c.dirty = true
	c.saveLocked()
}

func (c *GeminiCache) saveLocked() {
	if c.filePath == "" || !c.dirty {
		return
	}
	dir := filepath.Dir(c.filePath)
	_ = os.MkdirAll(dir, 0700)
	data, err := json.MarshalIndent(c.records, "", "  ")
	if err == nil {
		_ = os.WriteFile(c.filePath, data, 0600)
		c.dirty = false
	}
}

// CacheFilePath returns the absolute path to the local Gemini cache file.
func CacheFilePath() (string, error) {
	dir, err := ConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, geminiCacheFileName), nil
}

// ClearGeminiCache removes the local disk cache file.
func ClearGeminiCache() error {
	path, err := CacheFilePath()
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// CacheExists reports whether the disk cache file exists and has non-zero content.
func CacheExists() bool {
	path, err := CacheFilePath()
	if err != nil {
		return false
	}
	info, err := os.Stat(path)
	return err == nil && info.Size() > 0
}

// CacheEntryCount returns the number of cached entries in the disk cache file.
func CacheEntryCount() int {
	path, err := CacheFilePath()
	if err != nil {
		return 0
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	var records map[string]any
	if err := json.Unmarshal(data, &records); err != nil {
		return 0
	}
	return len(records)
}
