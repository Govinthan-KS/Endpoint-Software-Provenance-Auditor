package application

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/example/appaudit/internal/ai"
	"github.com/example/appaudit/internal/provenance"
)

const companyManifestFileName = "company_manifest.json"

// CompanyAppEntry represents an explicitly registered internal company executable.
type CompanyAppEntry struct {
	Name        string `json:"name"`
	Path        string `json:"path,omitempty"`
	SHA256      string `json:"sha256"`
	AddedAt     string `json:"added_at"`
	Description string `json:"description,omitempty"`
}

// CompanyManifest manages the local enterprise repository of internal company software.
type CompanyManifest struct {
	mu       sync.RWMutex
	filePath string
	Entries  map[string]CompanyAppEntry `json:"entries"` // Keyed by SHA-256
}

// CompanyManifestPath returns the absolute path to the local company manifest file.
func CompanyManifestPath() (string, error) {
	dir, err := ai.ConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, companyManifestFileName), nil
}

// LoadCompanyManifest loads the company manifest from disk.
func LoadCompanyManifest() (*CompanyManifest, error) {
	path, err := CompanyManifestPath()
	if err != nil {
		return nil, err
	}
	m := &CompanyManifest{
		filePath: path,
		Entries:  make(map[string]CompanyAppEntry),
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return m, nil
		}
		return nil, err
	}
	_ = json.Unmarshal(data, &m.Entries)
	if m.Entries == nil {
		m.Entries = make(map[string]CompanyAppEntry)
	}
	return m, nil
}

// saveLocked persists the manifest to disk. Assumes m.mu is already write-locked.
func (m *CompanyManifest) saveLocked() error {
	if m.filePath == "" {
		p, err := CompanyManifestPath()
		if err != nil {
			return err
		}
		m.filePath = p
	}
	dir := filepath.Dir(m.filePath)
	_ = os.MkdirAll(dir, 0700)
	data, err := json.MarshalIndent(m.Entries, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(m.filePath, data, 0600)
}

// Save persists the manifest to disk.
func (m *CompanyManifest) Save() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.saveLocked()
}

// RegisterApp registers an executable file by path as a verified company application.
func (m *CompanyManifest) RegisterApp(filePath string, appName string) (*CompanyAppEntry, error) {
	return m.RegisterAppWithDetails(filePath, appName, "", "")
}

// RegisterAppWithDetails registers an executable file by path with custom name, path, and description.
func (m *CompanyManifest) RegisterAppWithDetails(filePath string, appName string, customPath string, description string) (*CompanyAppEntry, error) {
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		absPath = filePath
	}
	fi, err := os.Stat(absPath)
	if err != nil {
		return nil, fmt.Errorf("target file not found: %w", err)
	}
	if fi.IsDir() {
		return nil, fmt.Errorf("target path is a directory, expected an executable file")
	}

	fp, err := provenance.ComputeFingerprint(absPath)
	if err != nil {
		return nil, fmt.Errorf("failed to compute binary fingerprint: %w", err)
	}

	name := strings.TrimSpace(appName)
	if name == "" && customPath != "" {
		name = strings.TrimSuffix(filepath.Base(customPath), filepath.Ext(customPath))
	}
	if name == "" {
		name = strings.TrimSuffix(filepath.Base(absPath), filepath.Ext(absPath))
	}

	storedPath := absPath
	if customPath != "" {
		storedPath = customPath
	}

	desc := description
	if desc == "" {
		desc = "Explicitly registered internal company executable"
	}

	entry := CompanyAppEntry{
		Name:        name,
		Path:        storedPath,
		SHA256:      strings.ToLower(fp.SHA256),
		AddedAt:     time.Now().Format(time.RFC3339),
		Description: desc,
	}

	m.mu.Lock()
	if m.Entries == nil {
		m.Entries = make(map[string]CompanyAppEntry)
	}
	m.Entries[strings.ToLower(fp.SHA256)] = entry
	saveErr := m.saveLocked()
	m.mu.Unlock()

	if saveErr != nil {
		return nil, fmt.Errorf("failed to save company manifest: %w", saveErr)
	}

	return &entry, nil
}

// RegisterAppByHash registers an application directly using its cryptographic SHA-256 digest.
func (m *CompanyManifest) RegisterAppByHash(sha256Hash string, appName string, filePath string, description string) (*CompanyAppEntry, error) {
	cleanHash := strings.ToLower(strings.TrimSpace(sha256Hash))
	if cleanHash == "" {
		return nil, fmt.Errorf("sha256 hash cannot be empty")
	}
	name := strings.TrimSpace(appName)
	if name == "" && filePath != "" {
		name = strings.TrimSuffix(filepath.Base(filePath), filepath.Ext(filePath))
	}
	if name == "" {
		name = "Custom-In-House-App"
	}
	desc := description
	if desc == "" {
		desc = "Explicitly registered internal company executable"
	}
	entry := CompanyAppEntry{
		Name:        name,
		Path:        filePath,
		SHA256:      cleanHash,
		AddedAt:     time.Now().Format(time.RFC3339),
		Description: desc,
	}

	m.mu.Lock()
	if m.Entries == nil {
		m.Entries = make(map[string]CompanyAppEntry)
	}
	m.Entries[cleanHash] = entry
	saveErr := m.saveLocked()
	m.mu.Unlock()

	if saveErr != nil {
		return nil, fmt.Errorf("failed to save company manifest: %w", saveErr)
	}
	return &entry, nil
}

// RemoveApp removes an entry by SHA-256 hash, executable name, or file path.
func (m *CompanyManifest) RemoveApp(identifier string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	idLower := strings.ToLower(strings.TrimSpace(identifier))
	foundKey := ""
	for k, e := range m.Entries {
		if strings.EqualFold(k, idLower) || strings.EqualFold(e.Name, idLower) || strings.EqualFold(filepath.Base(e.Path), idLower) {
			foundKey = k
			break
		}
	}
	if foundKey == "" {
		return false, nil
	}
	delete(m.Entries, foundKey)
	return true, m.saveLocked()
}

// FindMatch checks if a binary matches any entry in the manifest by cryptographic SHA-256 digest.
func (m *CompanyManifest) FindMatch(sha256Hash, path, name string) (CompanyAppEntry, bool) {
	if m == nil {
		return CompanyAppEntry{}, false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()

	cleanHash := strings.ToLower(strings.TrimSpace(sha256Hash))

	// 1. Exact SHA-256 match (highest fidelity cryptographic binding)
	if cleanHash != "" {
		if entry, ok := m.Entries[cleanHash]; ok {
			return entry, true
		}
	}

	// 2. Path match with cryptographic hash verification
	// If a candidate matches by path, its SHA-256 MUST corroborate the registered entry's SHA-256
	// to prevent binary replacement / trojan hijacking.
	if path != "" {
		cleanPath := filepath.Clean(path)
		for _, entry := range m.Entries {
			if entry.Path != "" && strings.EqualFold(filepath.Clean(entry.Path), cleanPath) {
				// If candidate has a hash, require exact hash equality
				if cleanHash != "" && entry.SHA256 != "" {
					if strings.EqualFold(cleanHash, entry.SHA256) {
						return entry, true
					}
					// Hash mismatch at same path indicates file was modified or replaced -> reject match!
					continue
				}
				// If candidate has no hash computed yet, compute on the fly to verify
				if entry.SHA256 != "" {
					if fp, err := provenance.ComputeFingerprint(cleanPath); err == nil {
						if strings.EqualFold(fp.SHA256, entry.SHA256) {
							return entry, true
						}
					}
					continue
				}
				return entry, true
			}
		}
	}

	return CompanyAppEntry{}, false
}

// ListApps returns a sorted slice of all registered company applications.
func (m *CompanyManifest) ListApps() []CompanyAppEntry {
	if m == nil {
		return nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	res := make([]CompanyAppEntry, 0, len(m.Entries))
	for _, e := range m.Entries {
		res = append(res, e)
	}
	sort.Slice(res, func(i, j int) bool {
		return strings.ToLower(res[i].Name) < strings.ToLower(res[j].Name)
	})
	return res
}

