package classifier

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCachePersistenceAndNormalization(t *testing.T) {
	tempDir := t.TempDir()
	cachePath := filepath.Join(tempDir, "resolved_cache.json")

	// 1. Create cache
	cache := NewResolutionCache(cachePath)

	// Check missing entry
	if _, ok := cache.Get("nonexistent"); ok {
		t.Fatalf("expected nonexistent key to be missing")
	}

	// 2. Set positive entry with varied casing and .exe extension
	cache.Set("Aider.EXE", CacheEntry{
		IsThirdParty: true,
		Evidence:     "Verified open-source tool via Repology",
	})

	// 3. Test normalization retrieval
	entry, ok := cache.Get("aider")
	if !ok || !entry.IsThirdParty {
		t.Fatalf("expected aider to be found and marked third-party")
	}
	if entry.Evidence != "Verified open-source tool via Repology" {
		t.Fatalf("unexpected evidence: %s", entry.Evidence)
	}

	// Also retrieve via path
	entry, ok = cache.Get(`C:\tools\AIDER.exe`)
	if !ok || !entry.IsThirdParty {
		t.Fatalf("expected path lookup to normalize correctly")
	}

	// 4. Save and reload
	if err := cache.Save(); err != nil {
		t.Fatalf("failed to save cache: %v", err)
	}

	// Verify file was written
	if _, err := os.Stat(cachePath); err != nil {
		t.Fatalf("cache file not found on disk: %v", err)
	}

	// Reload in new instance
	cache2 := NewResolutionCache(cachePath)
	entry2, ok := cache2.Get("aider")
	if !ok || !entry2.IsThirdParty {
		t.Fatalf("expected reloaded cache to contain aider")
	}

	// 5. Negative verdict caching
	cache2.Set("mycustomtool", CacheEntry{
		IsThirdParty: false,
	})
	if err := cache2.Save(); err != nil {
		t.Fatalf("failed to save cache: %v", err)
	}

	cache3 := NewResolutionCache(cachePath)
	negEntry, ok := cache3.Get("MYCUSTOMTOOL.exe")
	if !ok {
		t.Fatalf("expected mycustomtool to be present in cache")
	}
	if negEntry.IsThirdParty {
		t.Fatalf("expected mycustomtool to be false for IsThirdParty")
	}
}
