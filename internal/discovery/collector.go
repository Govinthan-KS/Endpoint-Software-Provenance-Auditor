package discovery

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// IsSystemRootPath checks if a given directory path is inside the operating system root
// (e.g. C:\Windows, C:\Windows\System32, /proc, /sys) to prevent scanning OS internals.
func IsSystemRootPath(path string) bool {
	if path == "" {
		return false
	}
	clean := filepath.Clean(path)
	cleanSlash := filepath.ToSlash(strings.ToLower(clean))

	if runtime.GOOS == "windows" {
		win := strings.ToLower(filepath.ToSlash(os.Getenv("SystemRoot")))
		if win == "" {
			win = "c:/windows"
		}
		winClean := strings.TrimSuffix(win, "/")
		if cleanSlash == winClean || strings.HasPrefix(cleanSlash, winClean+"/") {
			return true
		}
		// Also check drive root Windows folder if SystemRoot was different
		if cleanSlash == "c:/windows" || strings.HasPrefix(cleanSlash, "c:/windows/") {
			return true
		}
		return false
	}

	// Unix / Linux / Darwin system internal directories
	return cleanSlash == "/proc" || strings.HasPrefix(cleanSlash, "/proc/") ||
		cleanSlash == "/sys" || strings.HasPrefix(cleanSlash, "/sys/") ||
		cleanSlash == "/dev" || strings.HasPrefix(cleanSlash, "/dev/")
}

// CollectTargetedRoots dynamically builds a deduplicated slice of targeted application roots
// organized across three tiers:
//   Tier 1: Machine-Wide Applications (%ProgramFiles%, %ProgramFiles(x86)%, %ProgramData%)
//   Tier 2: User-Space Environments & Toolchains (%LocalAppData%\Programs, %AppData%, toolchains)
//   Tier 3: Environment PATH & Active Roots (excluding OS internals like System32)
func CollectTargetedRoots() []string {
	var roots []string
	seen := make(map[string]bool)

	addRoot := func(p string) {
		if p == "" {
			return
		}
		clean := filepath.Clean(p)
		if IsSystemRootPath(clean) {
			return
		}
		key := strings.ToLower(clean)
		if seen[key] {
			return
		}
		fi, err := os.Stat(clean)
		if err != nil || !fi.IsDir() {
			return
		}
		seen[key] = true
		roots = append(roots, clean)
	}

	// expandImmediateSubdirs checks direct children of large application directories
	// and adds them as individual work items to maximize parallel throughput across workers.
	expandImmediateSubdirs := func(parent string) {
		if parent == "" {
			return
		}
		clean := filepath.Clean(parent)
		if IsSystemRootPath(clean) {
			return
		}
		entries, err := os.ReadDir(clean)
		if err != nil {
			addRoot(clean)
			return
		}
		for _, e := range entries {
			if !e.IsDir() || ShouldPruneDir(e.Name()) {
				continue
			}
			addRoot(filepath.Join(clean, e.Name()))
		}
	}

	if runtime.GOOS == "windows" {
		// Tier 1: Machine-Wide Applications
		expandImmediateSubdirs(os.Getenv("ProgramFiles"))
		expandImmediateSubdirs(os.Getenv("ProgramFiles(x86)"))
		expandImmediateSubdirs(os.Getenv("ProgramData"))

		// Tier 2: User-Space Environments & Toolchains
		localAppData := os.Getenv("LocalAppData")
		if localAppData != "" {
			addRoot(filepath.Join(localAppData, "Programs"))
			expandImmediateSubdirs(localAppData)
		}
		expandImmediateSubdirs(os.Getenv("AppData"))

		if userProf := os.Getenv("USERPROFILE"); userProf != "" {
			addRoot(filepath.Join(userProf, ".local", "bin"))
			addRoot(filepath.Join(userProf, ".cargo", "bin"))
			addRoot(filepath.Join(userProf, "go", "bin"))
			addRoot(filepath.Join(userProf, ".dotnet", "tools"))
			addRoot(filepath.Join(userProf, "scoop", "apps"))
			addRoot(filepath.Join(userProf, "Desktop"))
			addRoot(filepath.Join(userProf, "Downloads"))
		}
		if oneDrive := os.Getenv("OneDrive"); oneDrive != "" {
			addRoot(filepath.Join(oneDrive, "Desktop"))
		}
	} else {
		// Unix / Linux / macOS Tiers
		addRoot("/usr/local")
		addRoot("/opt")
		if runtime.GOOS == "darwin" {
			addRoot("/Applications")
		}
		if home, err := os.UserHomeDir(); err == nil {
			addRoot(filepath.Join(home, ".local", "bin"))
			addRoot(filepath.Join(home, ".cargo", "bin"))
			addRoot(filepath.Join(home, "go", "bin"))
			addRoot(filepath.Join(home, "Desktop"))
			addRoot(filepath.Join(home, "Downloads"))
			if runtime.GOOS == "darwin" {
				addRoot(filepath.Join(home, "Applications"))
			}
		}
	}

	// Tier 3: Environment PATH & Active Roots (excluding OS internals)
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		addRoot(dir)
	}

	return roots
}
