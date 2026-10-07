//go:build darwin

package scanner

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/example/appaudit/internal/model"
)

type darwinScanner struct{}

func newPlatformScanner() Scanner {
	return &darwinScanner{}
}

// Scan enumerates macOS application bundles, $PATH binaries, and active running processes.
func (s *darwinScanner) Scan() ([]model.Application, error) {
	var discovered []model.Application
	seenPaths := make(map[string]bool)

	// 1. Scan Application Bundles (.app)
	bundleApps := s.scanAppBundles()
	for _, app := range bundleApps {
		key := strings.ToLower(app.Path)
		if !seenPaths[key] {
			seenPaths[key] = true
			discovered = append(discovered, app)
		}
	}

	// 2. Scan $PATH directories at rest
	pathApps := s.scanPathDirectories()
	for _, app := range pathApps {
		key := strings.ToLower(app.Path)
		if !seenPaths[key] {
			seenPaths[key] = true
			discovered = append(discovered, app)
		}
	}

	// 3. Scan Active Running Processes
	procApps := s.scanProcesses()
	for _, app := range procApps {
		key := strings.ToLower(app.Path)
		if key != "" && !seenPaths[key] {
			seenPaths[key] = true
			discovered = append(discovered, app)
		}
	}

	return discovered, nil
}

// scanPathDirectories inspects all directories in PATH to find un-run binaries.
func (s *darwinScanner) scanPathDirectories() []model.Application {
	pathEnv := os.Getenv("PATH")
	if pathEnv == "" {
		return nil
	}

	dirs := filepath.SplitList(pathEnv)
	var apps []model.Application
	seenPaths := make(map[string]bool)

	for _, dir := range dirs {
		dir = strings.TrimSpace(dir)
		if dir == "" {
			continue
		}

		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}

			info, err := entry.Info()
			if err != nil {
				continue
			}

			if info.Mode()&0111 != 0 {
				fullPath := filepath.Clean(filepath.Join(dir, entry.Name()))
				key := strings.ToLower(fullPath)
				if seenPaths[key] {
					continue
				}
				seenPaths[key] = true

				apps = append(apps, model.Application{
					Name:     entry.Name(),
					Path:     fullPath,
					Origin:   "Path",
					Evidence: fmt.Sprintf("Executable discovered in PATH directory (%s)", dir),
				})
			}
		}
	}

	return apps
}

// scanAppBundles discovers .app directories in standard macOS system and user locations.
func (s *darwinScanner) scanAppBundles() []model.Application {
	searchDirs := []string{
		"/Applications",
		"/System/Applications",
		"/System/Applications/Utilities",
	}

	if home, err := os.UserHomeDir(); err == nil && home != "" {
		searchDirs = append(searchDirs, filepath.Join(home, "Applications"))
	}

	var apps []model.Application
	for _, dir := range searchDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			// Skip directories that do not exist or lack read permissions
			continue
		}

		for _, entry := range entries {
			if !entry.IsDir() && entry.Type()&os.ModeSymlink == 0 {
				continue
			}

			if strings.HasSuffix(entry.Name(), ".app") {
				bundlePath := filepath.Join(dir, entry.Name())
				app := s.parseBundle(bundlePath)
				apps = append(apps, app)
			}
		}
	}

	return apps
}

// parseBundle extracts metadata from Contents/Info.plist inside a .app bundle.
func (s *darwinScanner) parseBundle(bundlePath string) model.Application {
	appName := strings.TrimSuffix(filepath.Base(bundlePath), ".app")
	infoPlistPath := filepath.Join(bundlePath, "Contents", "Info.plist")

	data, err := os.ReadFile(infoPlistPath)
	if err != nil {
		// Return bundle with basic metadata if Info.plist cannot be read
		return model.Application{
			Name:     appName,
			Path:     bundlePath,
			Origin:   "AppBundle",
			Evidence: fmt.Sprintf("macOS application bundle at %s", bundlePath),
		}
	}

	meta := parseInfoPlistData(data)
	if meta.DisplayName != "" {
		appName = meta.DisplayName
	} else if meta.BundleName != "" {
		appName = meta.BundleName
	}

	version := meta.ShortVersion
	if version == "" {
		version = meta.Version
	}

	return model.Application{
		Name:      appName,
		Path:      bundlePath,
		Publisher: meta.BundleIdentifier,
		Version:   version,
		Origin:    "AppBundle",
		Evidence:  fmt.Sprintf("macOS application bundle (ID: %s)", meta.BundleIdentifier),
	}
}

type plistMeta struct {
	BundleName       string
	DisplayName      string
	BundleIdentifier string
	ShortVersion     string
	Version          string
}

// parseInfoPlistData parses key-value pairs from XML plist content or performs string extraction.
func parseInfoPlistData(data []byte) plistMeta {
	var meta plistMeta

	// Try standard XML parsing first
	decoder := xml.NewDecoder(bytes.NewReader(data))
	var currentKey string

	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}

		switch elem := token.(type) {
		case xml.StartElement:
			if elem.Name.Local == "key" {
				var keyContent string
				if err := decoder.DecodeElement(&keyContent, &elem); err == nil {
					currentKey = strings.TrimSpace(keyContent)
				}
			} else if elem.Name.Local == "string" {
				var valContent string
				if err := decoder.DecodeElement(&valContent, &elem); err == nil {
					val := strings.TrimSpace(valContent)
					switch currentKey {
					case "CFBundleDisplayName":
						meta.DisplayName = val
					case "CFBundleName":
						meta.BundleName = val
					case "CFBundleIdentifier":
						meta.BundleIdentifier = val
					case "CFBundleShortVersionString":
						meta.ShortVersion = val
					case "CFBundleVersion":
						meta.Version = val
					}
					currentKey = ""
				}
			}
		}
	}

	// Fallback heuristic extraction for binary plists containing ASCII strings
	if meta.BundleIdentifier == "" {
		meta.BundleIdentifier = extractPlistStringKey(data, "CFBundleIdentifier")
	}
	if meta.ShortVersion == "" {
		meta.ShortVersion = extractPlistStringKey(data, "CFBundleShortVersionString")
	}
	if meta.BundleName == "" {
		meta.BundleName = extractPlistStringKey(data, "CFBundleName")
	}

	return meta
}

func extractPlistStringKey(data []byte, key string) string {
	idx := bytes.Index(data, []byte(key))
	if idx == -1 {
		return ""
	}
	sub := data[idx+len(key):]
	// Skip non-printable or tag bytes
	start := -1
	for i, b := range sub {
		if (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '.' || b == '-' || b == '_' {
			start = i
			break
		}
		if i > 32 {
			break
		}
	}
	if start == -1 {
		return ""
	}
	end := start
	for end < len(sub) {
		b := sub[end]
		if (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '.' || b == '-' || b == '_' {
			end++
		} else {
			break
		}
	}
	if end > start {
		return string(sub[start:end])
	}
	return ""
}

// scanProcesses queries running processes via /bin/ps.
func (s *darwinScanner) scanProcesses() []model.Application {
	var apps []model.Application

	cmd := exec.Command("/bin/ps", "-axo", "pid,comm")
	out, err := cmd.Output()
	if err != nil {
		return apps
	}

	lines := strings.Split(string(out), "\n")
	seen := make(map[string]bool)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "PID") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		pidStr := fields[0]
		pid, err := strconv.Atoi(pidStr)
		if err != nil || pid <= 1 {
			continue
		}

		cmdPath := strings.Join(fields[1:], " ")
		cleanPath := filepath.Clean(cmdPath)

		// Filter out system kernel daemons or non-absolute paths
		if !filepath.IsAbs(cleanPath) {
			continue
		}

		if seen[cleanPath] {
			continue
		}
		seen[cleanPath] = true

		base := filepath.Base(cleanPath)
		apps = append(apps, model.Application{
			Name:     base,
			Path:     cleanPath,
			Origin:   "Process",
			Evidence: fmt.Sprintf("Active running process (PID %d)", pid),
		})
	}

	return apps
}
