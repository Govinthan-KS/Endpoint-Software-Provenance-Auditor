package ai

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const deepseekCacheFileName = "deepseek_cache.json"

// DeepSeekCache caches structured reasoning results from DeepSeek API calls.
// Results (both positive classifications and inconclusive UNKNOWN verdicts)
// are keyed by the primary binary SHA-256 digest so repeat scans consume 0 tokens.
type DeepSeekCache struct {
	mu       sync.RWMutex
	filePath string
	records  map[string]ReasoningResult
	dirty    bool
}

// NewDeepSeekCache initializes or loads the disk-backed DeepSeek research cache.
func NewDeepSeekCache(customPath ...string) *DeepSeekCache {
	path := ""
	if len(customPath) > 0 && customPath[0] != "" {
		path = customPath[0]
	} else {
		dir, err := ConfigDir()
		if err == nil {
			path = filepath.Join(dir, deepseekCacheFileName)
		}
	}

	c := &DeepSeekCache{
		filePath: path,
		records:  make(map[string]ReasoningResult),
	}

	if path != "" {
		c.load()
	}
	return c
}

func (c *DeepSeekCache) load() {
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

// ComputeDeepSeekKey returns the cache key for an executable.
// Uses a deterministic composite SHA-256 digest of application identity, version, binary hash, and sibling count.
func ComputeDeepSeekKey(sha256Hash, appName, version string, siblingCount int) string {
	cleanHash := strings.ToLower(strings.TrimSpace(sha256Hash))
	cleanApp := strings.ToLower(strings.TrimSpace(appName))
	cleanVer := strings.ToLower(strings.TrimSpace(version))
	raw := fmt.Sprintf("%s|%s|%s|%d", cleanApp, cleanVer, cleanHash, siblingCount)
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

// Get retrieves a cached reasoning result if present.
func (c *DeepSeekCache) Get(key string) (ReasoningResult, bool) {
	if c == nil {
		return ReasoningResult{}, false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	res, ok := c.records[strings.ToLower(key)]
	return res, ok
}

// Set stores a reasoning result in the cache and flushes to disk.
func (c *DeepSeekCache) Set(key string, res ReasoningResult) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.records == nil {
		c.records = make(map[string]ReasoningResult)
	}
	c.records[strings.ToLower(key)] = res
	c.dirty = true
	c.saveLocked()
}

func (c *DeepSeekCache) saveLocked() {
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

// DeepSeekCacheFilePath returns the absolute path to the local DeepSeek cache file.
func DeepSeekCacheFilePath() (string, error) {
	dir, err := ConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, deepseekCacheFileName), nil
}

// ClearDeepSeekCache removes the local disk cache file.
func ClearDeepSeekCache() error {
	path, err := DeepSeekCacheFilePath()
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// DeepSeekCacheExists reports whether the disk cache file exists and has non-zero content.
func DeepSeekCacheExists() bool {
	path, err := DeepSeekCacheFilePath()
	if err != nil {
		return false
	}
	info, err := os.Stat(path)
	return err == nil && info.Size() > 0
}

// DeepSeekCacheEntryCount returns the number of cached entries in the disk cache file.
func DeepSeekCacheEntryCount() int {
	path, err := DeepSeekCacheFilePath()
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
