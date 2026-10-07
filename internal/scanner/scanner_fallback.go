//go:build !windows && !darwin && !linux

package scanner

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/example/appaudit/internal/model"
)

type fallbackScanner struct{}

func newPlatformScanner() Scanner {
	return &fallbackScanner{}
}

// Scan enumerates applications from $PATH and running processes on generic/BSD POSIX systems.
func (s *fallbackScanner) Scan() ([]model.Application, error) {
	var discovered []model.Application
	seenPaths := make(map[string]bool)

	// 1. Scan $PATH directories
	pathApps := s.scanPathDirectories()
	for _, app := range pathApps {
		key := strings.ToLower(app.Path)
		if !seenPaths[key] {
			seenPaths[key] = true
			discovered = append(discovered, app)
		}
	}

	// 2. Scan Running Processes
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

func (s *fallbackScanner) scanPathDirectories() []model.Application {
	pathEnv := os.Getenv("PATH")
	if pathEnv == "" {
		return nil
	}

	dirs := filepath.SplitList(pathEnv)
	var apps []model.Application

	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue // Skip unreadable or non-existent directories
		}

		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}

			info, err := entry.Info()
			if err != nil {
				continue
			}

			// Check executable bit
			if info.Mode()&0111 != 0 {
				fullPath := filepath.Join(dir, entry.Name())
				apps = append(apps, model.Application{
					Name:     entry.Name(),
					Path:     fullPath,
					Origin:   "Path",
					Evidence: fmt.Sprintf("Executable found in $PATH directory (%s)", dir),
				})
			}
		}
	}

	return apps
}

func (s *fallbackScanner) scanProcesses() []model.Application {
	var apps []model.Application

	// First try /proc if available
	if fi, err := os.Stat("/proc"); err == nil && fi.IsDir() {
		entries, err := os.ReadDir("/proc")
		if err == nil {
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
				if err == nil && target != "" && target != "/" {
					apps = append(apps, model.Application{
						Name:     filepath.Base(target),
						Path:     filepath.Clean(target),
						Origin:   "Process",
						Evidence: fmt.Sprintf("Active running process (PID %d)", pid),
					})
				}
			}
			if len(apps) > 0 {
				return apps
			}
		}
	}

	// Fallback to ps command
	cmd := exec.Command("ps", "-eo", "pid,comm")
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

		comm := strings.Join(fields[1:], " ")
		cleanPath := filepath.Clean(comm)

		if seen[cleanPath] {
			continue
		}
		seen[cleanPath] = true

		apps = append(apps, model.Application{
			Name:     filepath.Base(cleanPath),
			Path:     cleanPath,
			Origin:   "Process",
			Evidence: fmt.Sprintf("Active running process (PID %d)", pid),
		})
	}

	return apps
}
