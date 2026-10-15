package provenance

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// CacheRecord represents a cached provenance evaluation result keyed by cryptographic hash.
type CacheRecord struct {
	SHA256             string                `json:"sha256"`
	Classification     Classification        `json:"classification,omitempty"`
	Confidence         Confidence            `json:"confidence,omitempty"`
	Evidence           []Evidence            `json:"evidence,omitempty"`
	Candidates         []ProvenanceCandidate `json:"candidates,omitempty"`
	Inspection         BinaryMetadata        `json:"inspection,omitempty"`
	HasBinaryForensics bool                  `json:"has_binary_forensics,omitempty"`
	CachedAt           time.Time             `json:"cached_at"`
	ExpiresAt          time.Time             `json:"expires_at"`
}

// ProvenanceCache provides thread-safe persistent caching indexed by artifact SHA-256 digest.
type ProvenanceCache struct {
	mu       sync.RWMutex
	filePath string
	records  map[string]CacheRecord
	dirty    bool
}

// GetDefaultCachePath returns the platform-specific cache file path.
func GetDefaultCachePath() string {
	if runtime.GOOS == "windows" {
		localAppData := os.Getenv("LOCALAPPDATA")
		if localAppData == "" {
			if home, err := os.UserHomeDir(); err == nil {
				localAppData = filepath.Join(home, "AppData", "Local")
			}
		}
		if localAppData != "" {
			return filepath.Join(localAppData, "audit", "provenance_cache.json")
		}
	}

	cacheHome := os.Getenv("XDG_CACHE_HOME")
	if cacheHome == "" {
		if home, err := os.UserHomeDir(); err == nil {
			cacheHome = filepath.Join(home, ".cache")
		}
	}
	if cacheHome != "" {
		return filepath.Join(cacheHome, "audit", "provenance_cache.json")
	}

	return filepath.Join(".", "provenance_cache.json")
}

// NewProvenanceCache initializes or loads the cache from disk.
func NewProvenanceCache(customPath ...string) *ProvenanceCache {
	p := GetDefaultCachePath()
	if len(customPath) > 0 && customPath[0] != "" {
		p = customPath[0]
	}

	c := &ProvenanceCache{
		filePath: p,
		records:  make(map[string]CacheRecord),
	}
	c.load()
	return c
}

func (c *ProvenanceCache) load() {
	if c.filePath == "" {
		return
	}
	data, err := os.ReadFile(c.filePath)
	if err != nil {
		return
	}
	var loaded map[string]CacheRecord
	if err := json.Unmarshal(data, &loaded); err == nil && loaded != nil {
		now := time.Now()
		for k, v := range loaded {
			// Purge expired records
			if v.ExpiresAt.IsZero() || v.ExpiresAt.After(now) {
				c.records[strings.ToLower(k)] = v
			}
		}
	}
}

// Get looks up an artifact in the cache by its SHA-256 digest.
func (c *ProvenanceCache) Get(sha256Hash string) (CacheRecord, bool) {
	key := strings.ToLower(strings.TrimSpace(sha256Hash))
	if key == "" {
		return CacheRecord{}, false
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	rec, found := c.records[key]
	if !found {
		return CacheRecord{}, false
	}

	if !rec.ExpiresAt.IsZero() && time.Now().After(rec.ExpiresAt) {
		return CacheRecord{}, false
	}

	return rec, true
}

// Set stores a provenance result keyed by SHA-256.
// High confidence positive evidence is cached for 30 days.
// Unknown or low confidence outcomes are cached for only 1 hour.
// Never permanently caches "not found -> company".
func (c *ProvenanceCache) Set(sha256Hash string, res ClassificationResult) {
	key := strings.ToLower(strings.TrimSpace(sha256Hash))
	if key == "" {
		return
	}

	now := time.Now()
	var ttl time.Duration
	if res.Classification == ClassificationThirdParty && (res.Confidence == ConfidenceVeryHigh || res.Confidence == ConfidenceHigh) {
		ttl = 30 * 24 * time.Hour // 30 days
	} else {
		ttl = 1 * time.Hour // 1 hour TTL for unknown/candidate results
	}

	rec := CacheRecord{
		SHA256:         key,
		Classification: res.Classification,
		Confidence:     res.Confidence,
		Evidence:       res.Evidence,
		Candidates:     res.Candidates,
		CachedAt:       now,
		ExpiresAt:      now.Add(ttl),
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.records[key] = rec
	c.dirty = true
}

// SetBinaryEvidence stores forensic inspection metadata and binary-level evidence for a binary hash.
func (c *ProvenanceCache) SetBinaryEvidence(sha256Hash string, inspection BinaryMetadata, evidence []Evidence) {
	key := strings.ToLower(strings.TrimSpace(sha256Hash))
	if key == "" {
		return
	}

	now := time.Now()
	rec := CacheRecord{
		SHA256:             key,
		Inspection:         inspection,
		Evidence:           evidence,
		HasBinaryForensics: true,
		CachedAt:           now,
		ExpiresAt:          now.Add(30 * 24 * time.Hour), // 30 days for immutable cryptographic binary evidence
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.records[key] = rec
	c.dirty = true
}

// GetBinaryEvidence retrieves cached forensic inspection metadata and binary-level evidence by SHA-256.
func (c *ProvenanceCache) GetBinaryEvidence(sha256Hash string) (BinaryMetadata, []Evidence, bool) {
	rec, found := c.Get(sha256Hash)
	if !found {
		return BinaryMetadata{}, nil, false
	}
	if rec.HasBinaryForensics {
		return rec.Inspection, rec.Evidence, true
	}
	return BinaryMetadata{}, nil, false
}

// Save flushes modified records to disk atomically.
func (c *ProvenanceCache) Save() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.dirty || c.filePath == "" {
		return nil
	}

	dir := filepath.Dir(c.filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(c.records, "", "  ")
	if err != nil {
		return err
	}

	tmpFile := c.filePath + ".tmp"
	if err := os.WriteFile(tmpFile, data, 0644); err != nil {
		return os.WriteFile(c.filePath, data, 0644)
	}

	_ = os.Remove(c.filePath)
	if err := os.Rename(tmpFile, c.filePath); err != nil {
		_ = os.Remove(tmpFile)
		return os.WriteFile(c.filePath, data, 0644)
	}

	c.dirty = false
	return nil
}

// Delete removes a specific artifact digest from the cache and saves to disk.
func (c *ProvenanceCache) Delete(sha256Hash string) bool {
	c.mu.Lock()
	key := strings.ToLower(strings.TrimSpace(sha256Hash))
	_, exists := c.records[key]
	if exists {
		delete(c.records, key)
		c.dirty = true
	}
	c.mu.Unlock()

	if exists {
		_ = c.Save()
		return true
	}
	return false
}

// Clear purges all in-memory cache records and deletes the on-disk cache file.
func (c *ProvenanceCache) Clear() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.records = make(map[string]CacheRecord)
	c.dirty = false
	if c.filePath != "" {
		_ = os.Remove(c.filePath)
	}
	return nil
}

// Count returns the number of active cached records in the cache.
func (c *ProvenanceCache) Count() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.records)
}

