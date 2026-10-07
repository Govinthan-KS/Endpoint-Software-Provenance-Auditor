//go:build linux

package scanner

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/example/appaudit/internal/model"
)

type linuxScanner struct{}

func newPlatformScanner() Scanner {
	return &linuxScanner{}
}

// Scan enumerates installed desktop entries, $PATH binaries, and active running processes on Linux.
func (s *linuxScanner) Scan() ([]model.Application, error) {
	var discovered []model.Application
	seenPaths := make(map[string]bool)

	// 1. Scan XDG Desktop Entries (.desktop files)
	desktopApps := s.scanDesktopEntries()
	for _, app := range desktopApps {
		key := strings.ToLower(app.Name + "|" + app.Path)
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

	// 3. Scan Running Processes via /proc
	procApps := s.scanProcProcesses()
	for _, app := range procApps {
		key := strings.ToLower(app.Path)
		if key != "" && !seenPaths[key] {
			seenPaths[key] = true
			discovered = append(discovered, app)
		}
	}

	return discovered, nil
}

// scanPathDirectories inspects all directories in PATH to find un-run executables.
func (s *linuxScanner) scanPathDirectories() []model.Application {
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

// scanDesktopEntries discovers standard XDG .desktop files.
func (s *linuxScanner) scanDesktopEntries() []model.Application {
	searchDirs := []string{
		"/usr/share/applications",
		"/usr/local/share/applications",
		"/var/lib/flatpak/exports/share/applications",
		"/var/lib/snapd/desktop/applications",
	}

	if home, err := os.UserHomeDir(); err == nil && home != "" {
		searchDirs = append(searchDirs, filepath.Join(home, ".local", "share", "applications"))
	}

	var apps []model.Application
	seenDesktopFiles := make(map[string]bool)

	for _, dir := range searchDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue // Skip unreadable or missing directories
		}

		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".desktop") {
				continue
			}

			if seenDesktopFiles[entry.Name()] {
				continue
			}
			seenDesktopFiles[entry.Name()] = true

			filePath := filepath.Join(dir, entry.Name())
			app, ok := parseDesktopFile(filePath)
			if ok {
				apps = append(apps, app)
			}
		}
	}

	return apps
}

// parseDesktopFile extracts Name, Exec, Categories, and Version from a .desktop file.
func parseDesktopFile(filePath string) (model.Application, bool) {
	f, err := os.Open(filePath)
	if err != nil {
		return model.Application{}, false
	}
	defer f.Close()

	var (
		name         string
		execCmd      string
		version      string
		categories   string
		inEntry      bool
		isTypeApp    = true // Default assume true unless specified otherwise
		noDisplay    = false
	)

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			inEntry = (line == "[Desktop Entry]")
			continue
		}

		if !inEntry {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])

		switch key {
		case "Name":
			if name == "" {
				name = val
			}
		case "Exec":
			if execCmd == "" {
				execCmd = val
			}
		case "Type":
			if val != "Application" {
				isTypeApp = false
			}
		case "Version":
			if version == "" {
				version = val
			}
		case "Categories":
			categories = val
		case "NoDisplay":
			if strings.EqualFold(val, "true") {
				noDisplay = true
			}
		}
	}

	if !isTypeApp || name == "" || noDisplay {
		return model.Application{}, false
	}

	// Clean up Exec command to get actual executable path
	cleanPath := cleanExecPath(execCmd)
	if cleanPath == "" {
		cleanPath = filePath
	}

	evidence := fmt.Sprintf("Desktop entry %s", filepath.Base(filePath))
	if categories != "" {
		evidence += fmt.Sprintf(" (Categories: %s)", categories)
	}

	return model.Application{
		Name:      name,
		Path:      cleanPath,
		Publisher: deriveLinuxPublisher(filePath, cleanPath),
		Version:   version,
		Origin:    "DesktopEntry",
		Evidence:  evidence,
	}, true
}

func cleanExecPath(execStr string) string {
	if execStr == "" {
		return ""
	}

	// Tokenize exec command, stripping field codes like %u, %F, %k
	parts := strings.Fields(execStr)
	if len(parts) == 0 {
		return ""
	}

	bin := strings.Trim(parts[0], `"`)
	if bin == "" {
		return ""
	}

	if filepath.IsAbs(bin) {
		return filepath.Clean(bin)
	}

	if resolved, err := exec.LookPath(bin); err == nil {
		return filepath.Clean(resolved)
	}

	return bin
}

func deriveLinuxPublisher(desktopPath, binPath string) string {
	base := filepath.Base(desktopPath)
	// Example: org.mozilla.firefox.desktop -> org.mozilla
	if strings.Contains(base, ".") {
		parts := strings.Split(base, ".")
		if len(parts) >= 3 && (parts[0] == "com" || parts[0] == "org" || parts[0] == "io" || parts[0] == "net") {
			return parts[0] + "." + parts[1]
		}
	}

	if strings.HasPrefix(binPath, "/snap/") {
		return "Canonical Snap"
	}
	if strings.Contains(binPath, "flatpak") {
		return "Flatpak Application"
	}

	return ""
}

// scanProcProcesses inspects /proc for running processes.
func (s *linuxScanner) scanProcProcesses() []model.Application {
	var apps []model.Application

	procDir, err := os.Open("/proc")
	if err != nil {
		return apps
	}
	defer procDir.Close()

	entries, err := procDir.ReadDir(-1)
	if err != nil {
		return apps
	}

	seenPaths := make(map[string]bool)

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 1 {
			continue
		}

		exeLink := fmt.Sprintf("/proc/%d/exe", pid)
		target, err := os.Readlink(exeLink)
		if err != nil {
			// PermissionDenied or kernel thread; skip gracefully
			continue
		}

		cleanTarget := filepath.Clean(target)
		if cleanTarget == "" || cleanTarget == "/" || seenPaths[cleanTarget] {
			continue
		}
		seenPaths[cleanTarget] = true

		baseName := filepath.Base(cleanTarget)
		apps = append(apps, model.Application{
			Name:     baseName,
			Path:     cleanTarget,
			Origin:   "Process",
			Evidence: fmt.Sprintf("Active running process (PID %d)", pid),
		})
	}

	return apps
}
