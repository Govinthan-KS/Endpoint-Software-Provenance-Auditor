//go:build windows

package scanner

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/example/appaudit/internal/model"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var ignoredWindowsHelpers = map[string]bool{
	"conhost.exe":                 true,
	"crashpad_handler.exe":        true,
	"runtimebroker.exe":           true,
	"sihost.exe":                  true,
	"taskhostw.exe":               true,
	"backgroundtaskhost.exe":      true,
	"dllhost.exe":                 true,
	"wermgr.exe":                  true,
	"werfault.exe":                true,
	"compattelrunner.exe":         true,
	"smartscreen.exe":             true,
	"securityhealthhost.exe":      true,
	"ctfmon.exe":                  true,
	"fontdrvhost.exe":             true,
	"searchfilterhost.exe":        true,
	"searchprotocolhost.exe":      true,
	"textinputhost.exe":           true,
	"shellexperiencehost.exe":     true,
	"startmenuexperiencehost.exe": true,
	"securityhealthsystray.exe":   true,
	"useroobebroker.exe":          true,
	"unsecapp.exe":                true,
	"widgetboard.exe":                true,
	"widgetservice.exe":              true,
	"explorer.exe":                   true,
	"filecoauth.exe":                 true,
	"microsoftstartfeedprovider.exe": true,
	"hpsystemeventutilityhost.exe":   true,
}

var toolchainNoise = map[string]bool{
	"gofmt.exe":         true,
	"mvndebug.exe":      true,
	"nodevars.bat":      true,
	"corepack.cmd":      true,
	"npm.cmd":           true,
	"npx.cmd":           true,
	"git-receive-pack.exe": true,
	"git-upload-pack.exe":  true,
	"git-shell.exe":        true,
	"git-cvsserver.exe":    true,
}

type windowsScanner struct{}

func newPlatformScanner() Scanner {
	return &windowsScanner{}
}

// Scan enumerates user-facing launchable applications from Start Menu, Registry, $PATH, and active processes.
func (s *windowsScanner) Scan() ([]model.Application, error) {
	var discovered []model.Application
	seenCanonicalPaths := make(map[string]bool)
	seenNames := make(map[string]bool)

	// 1. Scan Start Menu (.lnk) shortcuts (primary launchable user applications)
	startApps := s.scanStartMenu()
	for _, app := range startApps {
		canPath := canonicalPath(app.Path)
		normName := strings.ToLower(strings.TrimSpace(app.Name))

		if canPath != "" && seenCanonicalPaths[canPath] {
			continue
		}
		if seenNames[normName] && canPath == "" {
			continue
		}

		if canPath != "" {
			seenCanonicalPaths[canPath] = true
		}
		seenNames[normName] = true
		discovered = append(discovered, app)
	}

	// 2. Scan Windows Registry (HKLM & HKCU, 64-bit and WOW6432Node)
	regApps, _ := s.scanRegistry()
	for _, app := range regApps {
		canPath := canonicalPath(app.Path)
		normName := strings.ToLower(strings.TrimSpace(app.Name))

		if canPath != "" && seenCanonicalPaths[canPath] {
			continue
		}
		if seenNames[normName] && canPath == "" {
			continue
		}

		if canPath != "" {
			seenCanonicalPaths[canPath] = true
		}
		seenNames[normName] = true
		discovered = append(discovered, app)
	}

	// 3. Scan $PATH directories at rest (strictly standalone .exe, excluding OS system folders)
	pathApps := s.scanPathDirectories()
	for _, app := range pathApps {
		canPath := canonicalPath(app.Path)
		if canPath != "" && !seenCanonicalPaths[canPath] {
			seenCanonicalPaths[canPath] = true
			discovered = append(discovered, app)
		}
	}

	// 4. Scan Active Running Processes (grouped by executable, excluding OS system internals)
	procApps, _ := s.scanProcesses()
	for _, app := range procApps {
		canPath := canonicalPath(app.Path)
		if canPath != "" && !seenCanonicalPaths[canPath] {
			seenCanonicalPaths[canPath] = true
			discovered = append(discovered, app)
		}
	}

	return discovered, nil
}

func canonicalPath(p string) string {
	if p == "" {
		return ""
	}
	clean := filepath.Clean(strings.Trim(p, `"`))
	return filepath.ToSlash(strings.ToLower(clean))
}

func isInternalSystemDir(dirPath string) bool {
	slash := filepath.ToSlash(filepath.Clean(strings.ToLower(dirPath)))
	return strings.HasPrefix(slash, "c:/windows/system32") ||
		strings.HasPrefix(slash, "c:/windows/syswow64") ||
		strings.HasPrefix(slash, "c:/windows/winsxs") ||
		strings.HasPrefix(slash, "c:/windows/systemapps") ||
		strings.HasPrefix(slash, "c:/windows/servicing") ||
		strings.HasPrefix(slash, "c:/windows/uus") ||
		strings.Contains(slash, "/package cache/") ||
		slash == "c:/windows"
}

// scanStartMenu discovers user-facing applications registered in Windows Start Menu.
func (s *windowsScanner) scanStartMenu() []model.Application {
	startDirs := []string{
		`C:\ProgramData\Microsoft\Windows\Start Menu\Programs`,
	}
	if appData := os.Getenv("APPDATA"); appData != "" {
		startDirs = append(startDirs, filepath.Join(appData, `Microsoft\Windows\Start Menu\Programs`))
	}

	var apps []model.Application
	seenPaths := make(map[string]bool)

	for _, dir := range startDirs {
		_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}

			if strings.ToLower(filepath.Ext(path)) != ".lnk" {
				return nil
			}

			// Exclude Chrome Apps, Edge Apps, and browser web shortcuts
			pathLower := filepath.ToSlash(strings.ToLower(path))
			if strings.Contains(pathLower, "chrome apps") || strings.Contains(pathLower, "edge apps") {
				return nil
			}

			name, target, ok := parseLnkShortcut(path)
			if !ok || name == "" || target == "" {
				return nil
			}

			if model.IsIgnoredComponent(name) || model.IsWebStub(target) {
				return nil
			}

			// Filter out OS system tool shortcuts
			if isInternalSystemDir(target) {
				return nil
			}

			// Require verified existing standalone .exe
			canP := canonicalPath(target)
			if canP == "" || seenPaths[canP] {
				return nil
			}
			seenPaths[canP] = true

			apps = append(apps, model.Application{
				Name:     name,
				Path:     target,
				Origin:   "StartMenu",
				Evidence: "User-facing launchable application in Windows Start Menu",
			})
			return nil
		})
	}

	return apps
}

// scanRegistry reads installed applications from HKLM and HKCU uninstall keys.
func (s *windowsScanner) scanRegistry() ([]model.Application, error) {
	var apps []model.Application

	type regTarget struct {
		root     registry.Key
		rootName string
		path     string
		access   uint32
	}

	targets := []regTarget{
		{registry.LOCAL_MACHINE, "HKLM", `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`, registry.READ | registry.WOW64_64KEY},
		{registry.LOCAL_MACHINE, "HKLM", `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`, registry.READ | registry.WOW64_32KEY},
		{registry.CURRENT_USER, "HKCU", `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`, registry.READ | registry.WOW64_64KEY},
		{registry.CURRENT_USER, "HKCU", `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`, registry.READ | registry.WOW64_32KEY},
	}

	seenEntries := make(map[string]bool)

	for _, target := range targets {
		k, err := registry.OpenKey(target.root, target.path, target.access)
		if err != nil {
			if errors.Is(err, registry.ErrNotExist) {
				continue
			}
			continue
		}

		subkeys, err := k.ReadSubKeyNames(-1)
		k.Close()
		if err != nil {
			continue
		}

		for _, subkeyName := range subkeys {
			subPath := target.path + `\` + subkeyName
			sk, err := registry.OpenKey(target.root, subPath, target.access)
			if err != nil {
				if errors.Is(err, registry.ErrNotExist) {
					continue
				}
				continue
			}

			app, valid := readUninstallKey(sk, target.rootName+`\`+subPath)
			sk.Close()

			if !valid {
				continue
			}

			// Filter out internal OS components or web stubs
			if isInternalSystemDir(app.Path) || model.IsWebStub(app.Path) {
				continue
			}

			// Deduplicate across 64-bit and WOW6432Node
			dedupKey := strings.ToLower(app.Name + "|" + app.Publisher + "|" + app.Version)
			if seenEntries[dedupKey] {
				continue
			}
			seenEntries[dedupKey] = true
			apps = append(apps, app)
		}
	}

	return apps, nil
}

func readUninstallKey(k registry.Key, fullKeyPath string) (model.Application, bool) {
	if sysComp, ok := readDwordValue(k, "SystemComponent"); ok && sysComp == 1 {
		return model.Application{}, false
	}
	if parent := readStringValue(k, "ParentKeyName"); parent != "" {
		return model.Application{}, false
	}
	if relType := readStringValue(k, "ReleaseType"); strings.Contains(strings.ToLower(relType), "update") || strings.Contains(strings.ToLower(relType), "hotfix") {
		return model.Application{}, false
	}

	displayName := readStringValue(k, "DisplayName")
	if displayName == "" {
		displayName = readStringValue(k, "QuietDisplayName")
	}
	displayName = strings.TrimSpace(displayName)
	if displayName == "" {
		return model.Application{}, false
	}

	// Purge non-application components & runtimes
	if model.IsIgnoredComponent(displayName) {
		return model.Application{}, false
	}

	publisher := readStringValue(k, "Publisher")
	version := readStringValue(k, "DisplayVersion")
	installLocation := readStringValue(k, "InstallLocation")
	displayIcon := readStringValue(k, "DisplayIcon")

	appPath := resolveAppPath(displayName, installLocation, displayIcon)
	if appPath == "" {
		// Omit records that do not resolve to an actual launchable executable binary
		return model.Application{}, false
	}

	if isInternalSystemDir(appPath) || model.IsWebStub(appPath) {
		return model.Application{}, false
	}

	return model.Application{
		Name:      displayName,
		Path:      appPath,
		Publisher: strings.TrimSpace(publisher),
		Version:   strings.TrimSpace(version),
		Origin:    "Registry",
		Evidence:  fmt.Sprintf("Installed software registration in %s", fullKeyPath),
	}, true
}

func readStringValue(k registry.Key, name string) string {
	val, valtype, err := k.GetStringValue(name)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return ""
		}
		return ""
	}
	if valtype == registry.EXPAND_SZ {
		expanded, err := registry.ExpandString(val)
		if err == nil {
			return strings.TrimSpace(expanded)
		}
	}
	return strings.TrimSpace(val)
}

func readDwordValue(k registry.Key, name string) (uint64, bool) {
	val, _, err := k.GetIntegerValue(name)
	if err != nil {
		return 0, false
	}
	return val, true
}

func resolveAppPath(appName, installLoc, displayIcon string) string {
	if displayIcon != "" {
		iconPath := cleanExePath(displayIcon)
		if iconPath != "" && strings.ToLower(filepath.Ext(iconPath)) == ".exe" {
			baseLower := strings.ToLower(filepath.Base(iconPath))
			if !strings.Contains(baseLower, "unins") && !strings.Contains(baseLower, "uninstall") && !strings.Contains(baseLower, "setup") {
				if fi, err := os.Stat(iconPath); err == nil && !fi.IsDir() {
					return iconPath
				}
			}
		}
	}

	if installLoc != "" {
		clean := filepath.Clean(strings.Trim(installLoc, `"`))
		if fi, err := os.Stat(clean); err == nil {
			if !fi.IsDir() && strings.ToLower(filepath.Ext(clean)) == ".exe" {
				return clean
			}
			if fi.IsDir() {
				exe := findExecutableInDir(clean, appName)
				if exe != "" {
					return exe
				}
			}
		}
	}

	return ""
}

func findExecutableInDir(dir, appName string) string {
	if dir == "" {
		return ""
	}
	cleanDir := filepath.Clean(dir)
	fi, err := os.Stat(cleanDir)
	if err != nil || !fi.IsDir() {
		return ""
	}

	cleanAppName := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			return r
		}
		return -1
	}, appName)

	firstWord := strings.Fields(appName)
	var firstWordName string
	if len(firstWord) > 0 {
		firstWordName = firstWord[0]
	}

	searchDirs := []string{cleanDir, filepath.Join(cleanDir, "bin")}
	for _, sDir := range searchDirs {
		// 1. Direct match: <dir>\<appName>.exe
		candidate := filepath.Join(sDir, appName+".exe")
		if cfi, err := os.Stat(candidate); err == nil && !cfi.IsDir() {
			return candidate
		}

		// 2. First word match: <dir>\<firstWord>.exe
		if firstWordName != "" {
			candidate = filepath.Join(sDir, firstWordName+".exe")
			if cfi, err := os.Stat(candidate); err == nil && !cfi.IsDir() {
				return candidate
			}
		}

		// 3. Stripped name match: <dir>\<cleanAppName>.exe
		if cleanAppName != "" {
			candidate = filepath.Join(sDir, cleanAppName+".exe")
			if cfi, err := os.Stat(candidate); err == nil && !cfi.IsDir() {
				return candidate
			}
		}

		// 4. Scan files in directory for primary executable
		entries, err := os.ReadDir(sDir)
		if err == nil {
			for _, e := range entries {
				if e.IsDir() {
					continue
				}
				if strings.ToLower(filepath.Ext(e.Name())) == ".exe" {
					eLower := strings.ToLower(e.Name())
					if strings.Contains(eLower, "unins") || strings.Contains(eLower, "uninstall") ||
						strings.Contains(eLower, "setup") || strings.Contains(eLower, "update") ||
						strings.Contains(eLower, "helper") || strings.Contains(eLower, "crashpad") {
						continue
					}
					fullPath := filepath.Join(sDir, e.Name())
					return fullPath
				}
			}
		}
	}

	return ""
}

func cleanExePath(raw string) string {
	raw = strings.TrimSpace(raw)
	raw = strings.Trim(raw, `"`)

	if idx := strings.Index(raw, ","); idx != -1 {
		raw = raw[:idx]
	}
	raw = strings.TrimSpace(strings.Trim(raw, `"`))
	if raw == "" {
		return ""
	}
	clean := filepath.Clean(raw)
	if strings.ToLower(filepath.Ext(clean)) != ".exe" {
		return ""
	}
	if fi, err := os.Stat(clean); err == nil && !fi.IsDir() {
		return clean
	}
	return ""
}

// scanPathDirectories inspects user and application directories in PATH for standalone .exe binaries.
// Excludes OS internal system folders (System32, SysWOW64, WinSxS) and package script directories.
func (s *windowsScanner) scanPathDirectories() []model.Application {
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

		// Exclude low-level OS system directories
		if isInternalSystemDir(dir) {
			continue
		}

		dirLower := filepath.ToSlash(strings.ToLower(dir))
		// Purge runtime package script directories (Python scripts, npm wrappers, etc.)
		if strings.Contains(dirLower, "/scripts") ||
			strings.Contains(dirLower, "/site-packages") ||
			strings.Contains(dirLower, "node_modules") ||
			strings.Contains(dirLower, "/windowsapps") ||
			strings.Contains(dirLower, "appdata/roaming/npm") {
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

			// Strict extension filtering: only standalone .exe binaries
			if strings.ToLower(filepath.Ext(entry.Name())) != ".exe" {
				continue
			}

			nameWithoutExt := strings.TrimSuffix(entry.Name(), filepath.Ext(entry.Name()))
			if model.IsIgnoredComponent(nameWithoutExt) || toolchainNoise[strings.ToLower(entry.Name())] || strings.HasPrefix(strings.ToLower(entry.Name()), "ijs") {
				continue
			}

			fullPath := filepath.Clean(filepath.Join(dir, entry.Name()))
			normP := strings.ToLower(fullPath)
			if seenPaths[normP] {
				continue
			}
			seenPaths[normP] = true

			apps = append(apps, model.Application{
				Name:     nameWithoutExt,
				Path:     fullPath,
				Origin:   "Path",
				Evidence: fmt.Sprintf("Standalone executable discovered in PATH directory (%s)", dir),
			})
		}
	}

	return apps
}

// scanProcesses queries active running processes, excluding OS internal system processes.
func (s *windowsScanner) scanProcesses() ([]model.Application, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, fmt.Errorf("create process snapshot: %w", err)
	}
	defer windows.CloseHandle(snapshot)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	var apps []model.Application
	seenPaths := make(map[string]bool)

	for err = windows.Process32First(snapshot, &entry); err == nil; err = windows.Process32Next(snapshot, &entry) {
		pid := entry.ProcessID
		if pid <= 4 {
			continue
		}

		exeName := windows.UTF16ToString(entry.ExeFile[:])
		if exeName == "" {
			continue
		}

		exeLower := strings.ToLower(exeName)
		nameWithoutExt := strings.TrimSuffix(exeName, filepath.Ext(exeName))
		if ignoredWindowsHelpers[exeLower] || toolchainNoise[exeLower] || model.IsIgnoredComponent(nameWithoutExt) || strings.HasPrefix(exeLower, "ijs") {
			continue
		}

		exePath := ""
		hProc, procErr := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
		if procErr == nil {
			var buf [windows.MAX_PATH * 2]uint16
			size := uint32(len(buf))
			if qErr := windows.QueryFullProcessImageName(hProc, 0, &buf[0], &size); qErr == nil {
				exePath = windows.UTF16ToString(buf[:size])
			}
			windows.CloseHandle(hProc)
		}

		if exePath == "" {
			continue
		}

		// Exclude low-level OS internal system binaries or web stubs
		if isInternalSystemDir(exePath) || model.IsWebStub(exePath) {
			continue
		}

		cleanPath := filepath.Clean(exePath)
		pathLower := strings.ToLower(cleanPath)
		if seenPaths[pathLower] {
			continue
		}
		seenPaths[pathLower] = true

		baseName := filepath.Base(cleanPath)
		baseWithoutExt := strings.TrimSuffix(baseName, filepath.Ext(baseName))

		apps = append(apps, model.Application{
			Name:     baseWithoutExt,
			Path:     cleanPath,
			Origin:   "Process",
			Evidence: fmt.Sprintf("Active running application process (PID %d)", pid),
		})
	}

	return apps, nil
}
