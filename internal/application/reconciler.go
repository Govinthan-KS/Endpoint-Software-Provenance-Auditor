package application

import (
	"path/filepath"
	"sort"
	"strings"

	"github.com/example/appaudit/internal/model"
)

// RawInput represents an unclassified discovered application candidate or file path.
type RawInput struct {
	Name      string
	Path      string
	Publisher string
	Version   string
	Origin    string // StartMenu, Registry, PATH, Process, DesktopEntry, AppBundle, CLI
}

// Reconciler handles suite directory grouping, primary binary election,
// and noise suppression across registered and portable applications.
type Reconciler struct{}

// NewReconciler creates a new Reconciler instance.
func NewReconciler() *Reconciler {
	return &Reconciler{}
}

// ReconcileRaw converts raw discovery inputs (from scanners or CLI) into unified Application domain objects.
func (r *Reconciler) ReconcileRaw(inputs []RawInput) []Application {
	var registered []RawInput
	var unmapped []RawInput

	for _, item := range inputs {
		if !model.IsExecutableTarget(item.Path) || model.IsWebStub(item.Path) {
			continue
		}

		ext := strings.ToLower(filepath.Ext(item.Path))
		if ext == ".cmd" || ext == ".bat" || ext == ".ps1" || ext == ".sh" || ext == ".vbs" {
			continue
		}

		if isRegisteredOrigin(item.Origin) {
			if model.IsIgnoredComponent(item.Name) {
				continue
			}
			registered = append(registered, item)
		} else {
			unmapped = append(unmapped, item)
		}
	}

	// 1. Group registered applications by suite directory
	suiteGroups := make(map[string][]RawInput)
	var standaloneRegistered []RawInput

	for _, item := range registered {
		sDir := GetSuiteDir(item.Path)
		if sDir != "" {
			suiteGroups[sDir] = append(suiteGroups[sDir], item)
		} else {
			standaloneRegistered = append(standaloneRegistered, item)
		}
	}

	// Merge nested suite directories (e.g. "c:/tools/suite/sub" into "c:/tools/suite")
	suiteGroups = mergeNestedSuites(suiteGroups)

	var applications []Application
	seenCanonicalPaths := make(map[string]int)
	seenRegisteredNames := make(map[string]int)
	seenAppKeys := make(map[string]bool)
	registeredSuiteDirs := make(map[string]int) // suiteDir -> index in applications

	// Consolidate registered suites
	for sDir, group := range suiteGroups {
		primary := electPrimaryBinary(group, sDir)
		app := buildApplicationFromGroup(primary, group, sDir)

		appKey := strings.ToLower(app.Name) + "|" + strings.ToLower(app.PrimaryBinaryPath)
		if !seenAppKeys[appKey] {
			seenAppKeys[appKey] = true
			appIdx := len(applications)
			registeredSuiteDirs[sDir] = appIdx
			if app.PrimaryBinaryPath != "" {
				normP := normalizePath(app.PrimaryBinaryPath)
				seenCanonicalPaths[normP] = appIdx
			}
			if app.Name != "" {
				seenRegisteredNames[strings.ToLower(strings.TrimSpace(app.Name))] = appIdx
			}
			applications = append(applications, app)
		}
	}

	// Consolidate standalone registered
	for _, item := range standaloneRegistered {
		normP := normalizePath(item.Path)
		normN := strings.ToLower(strings.TrimSpace(item.Name))

		if idx, exists := seenCanonicalPaths[normP]; exists && normP != "" {
			mergeMetadata(&applications[idx], item)
			continue
		}
		if idx, exists := seenRegisteredNames[normN]; exists && normN != "" {
			mergeMetadata(&applications[idx], item)
			continue
		}

		app := buildApplicationFromSingle(item, GetSuiteDir(item.Path))
		appKey := normN + "|" + normP
		if !seenAppKeys[appKey] {
			seenAppKeys[appKey] = true
			appIdx := len(applications)
			if normP != "" {
				seenCanonicalPaths[normP] = appIdx
			}
			if normN != "" {
				seenRegisteredNames[normN] = appIdx
			}
			applications = append(applications, app)
		}
	}

	// 2. Group unmapped / portable binaries
	// Sibling unmapped binaries sharing a suite directory are grouped into an Application suite.
	unmappedSuiteGroups := make(map[string][]RawInput)
	var standaloneUnmapped []RawInput

	for _, item := range unmapped {
		if !model.IsExecutableTarget(item.Path) || model.IsWebStub(item.Path) {
			continue
		}

		normP := normalizePath(item.Path)
		normN := strings.ToLower(strings.TrimSpace(item.Name))

		attached := false
		for regSuiteDir, appIdx := range registeredSuiteDirs {
			if regSuiteDir != "" && (normP == regSuiteDir || strings.HasPrefix(normP, regSuiteDir+"/")) {
				alreadyIn := false
				for _, eb := range applications[appIdx].Binaries {
					if normalizePath(eb.Path) == normP {
						alreadyIn = true
						break
					}
				}
				if !alreadyIn {
					applications[appIdx].Binaries = append(applications[appIdx].Binaries, ApplicationBinary{
						Path:      item.Path,
						Name:      item.Name,
						Origin:    item.Origin,
						Publisher: item.Publisher,
						Version:   item.Version,
					})
				}
				attached = true
				break
			}
		}
		if attached {
			continue
		}

		// Known sub-tool noise (like git-upload-pack by itself without a git suite)
		// should never create an application by itself
		if exactSubToolNoise[normN] {
			continue
		}

		sDir := GetSuiteDir(item.Path)
		if sDir != "" {
			unmappedSuiteGroups[sDir] = append(unmappedSuiteGroups[sDir], item)
		} else {
			if model.IsIgnoredComponent(item.Name) || isStandaloneNoise(item.Name, item.Path) {
				continue
			}
			standaloneUnmapped = append(standaloneUnmapped, item)
		}
	}

	// Merge nested unmapped suites
	unmappedSuiteGroups = mergeNestedSuites(unmappedSuiteGroups)

	// Consolidate unmapped suites (e.g. ffmpeg.exe + ffplay.exe + ffprobe.exe)
	for sDir, group := range unmappedSuiteGroups {
		primary := electPrimaryBinary(group, sDir)
		app := buildApplicationFromGroup(primary, group, sDir)

		appKey := strings.ToLower(app.Name) + "|" + strings.ToLower(app.PrimaryBinaryPath)
		if !seenAppKeys[appKey] {
			seenAppKeys[appKey] = true
			applications = append(applications, app)
		}
	}

	// Consolidate standalone unmapped
	seenUnmappedNames := make(map[string]bool)
	for _, item := range standaloneUnmapped {
		normN := strings.ToLower(strings.TrimSpace(item.Name))
		normP := normalizePath(item.Path)

		if seenUnmappedNames[normN] {
			continue
		}
		seenUnmappedNames[normN] = true

		app := buildApplicationFromSingle(item, GetSuiteDir(item.Path))
		appKey := normN + "|" + normP
		if !seenAppKeys[appKey] {
			seenAppKeys[appKey] = true
			applications = append(applications, app)
		}
	}

	return applications
}

func isRegisteredOrigin(origin string) bool {
	return origin == "StartMenu" || origin == "Registry" || origin == "DesktopEntry" || origin == "AppBundle"
}

func normalizePath(path string) string {
	if path == "" {
		return ""
	}
	return strings.TrimSuffix(filepath.ToSlash(filepath.Clean(strings.ToLower(path))), "/")
}

func mergeNestedSuites(suiteGroups map[string][]RawInput) map[string][]RawInput {
	merged := make(map[string][]RawInput)
	var sortedDirs []string
	for d := range suiteGroups {
		sortedDirs = append(sortedDirs, d)
	}
	sort.Slice(sortedDirs, func(i, j int) bool {
		return len(sortedDirs[i]) < len(sortedDirs[j])
	})

	for _, d := range sortedDirs {
		targetDir := d
		for parentDir := range merged {
			if strings.HasPrefix(d, parentDir+"/") {
				targetDir = parentDir
				break
			}
		}
		merged[targetDir] = append(merged[targetDir], suiteGroups[d]...)
	}
	return merged
}

func electPrimaryBinary(group []RawInput, suiteDir string) RawInput {
	if len(group) == 0 {
		return RawInput{}
	}
	bestIdx := 0
	bestScore := ScoreRawSuitability(group[0], suiteDir)
	for j := 1; j < len(group); j++ {
		sc := ScoreRawSuitability(group[j], suiteDir)
		if sc > bestScore {
			bestScore = sc
			bestIdx = j
		}
	}
	return group[bestIdx]
}

// ScoreRawSuitability evaluates how well an executable represents the suite primary binary.
func ScoreRawSuitability(item RawInput, suiteDir string) int {
	score := 50
	if item.Origin == "Registry" {
		score += 50
	} else if item.Origin == "DesktopEntry" || item.Origin == "AppBundle" {
		score += 40
	} else if item.Origin == "StartMenu" {
		score += 30
	}

	normName := strings.ToLower(strings.TrimSpace(item.Name))
	suiteBase := strings.ToLower(filepath.Base(suiteDir))

	if normName == suiteBase || strings.Contains(normName, suiteBase) {
		score += 40
	}

	exeBase := strings.ToLower(filepath.Base(item.Path))
	exeName := strings.TrimSuffix(exeBase, filepath.Ext(exeBase))
	if exeName == suiteBase || strings.Contains(exeName, suiteBase) {
		score += 30
	}

	if IsAuxiliaryComponent(item.Name) || IsAuxiliaryComponent(exeName) {
		score -= 60
	}

	if item.Publisher != "" {
		score += 15
	}
	if item.Version != "" {
		score += 15
	}

	return score
}

func buildApplicationFromGroup(primary RawInput, group []RawInput, suiteDir string) Application {
	appName := primary.Name
	if appName == "" && suiteDir != "" {
		appName = filepath.Base(suiteDir)
	}

	publisher := primary.Publisher
	version := primary.Version

	binaries := make([]ApplicationBinary, 0, len(group))
	seenBinPaths := make(map[string]bool)
	for _, item := range group {
		normP := normalizePath(item.Path)
		if normP != "" && seenBinPaths[normP] {
			continue
		}
		if normP != "" {
			seenBinPaths[normP] = true
		}
		if publisher == "" && item.Publisher != "" {
			publisher = item.Publisher
		}
		if version == "" && item.Version != "" {
			version = item.Version
		}
		binaries = append(binaries, ApplicationBinary{
			Path:      item.Path,
			Name:      item.Name,
			Origin:    item.Origin,
			Publisher: item.Publisher,
			Version:   item.Version,
		})
	}

	return Application{
		ID:                primary.Name + "@" + primary.Path,
		Name:              appName,
		Publisher:         publisher,
		Version:           version,
		InstallDir:        suiteDir,
		PrimaryBinaryPath: primary.Path,
		Binaries:          binaries,
		Origin:            primary.Origin,
	}
}

func buildApplicationFromSingle(item RawInput, suiteDir string) Application {
	return Application{
		ID:                item.Name + "@" + item.Path,
		Name:              item.Name,
		Publisher:         item.Publisher,
		Version:           item.Version,
		InstallDir:        suiteDir,
		PrimaryBinaryPath: item.Path,
		Binaries: []ApplicationBinary{
			{
				Path:      item.Path,
				Name:      item.Name,
				Origin:    item.Origin,
				Publisher: item.Publisher,
				Version:   item.Version,
			},
		},
		Origin: item.Origin,
	}
}

func mergeMetadata(app *Application, item RawInput) {
	if app.Publisher == "" && item.Publisher != "" {
		app.Publisher = item.Publisher
	}
	if app.Version == "" && item.Version != "" {
		app.Version = item.Version
	}
}

// GetSuiteDir extracts the top-level application root directory for an executable path.
func GetSuiteDir(path string) string {
	if path == "" {
		return ""
	}
	clean := filepath.ToSlash(filepath.Clean(path))
	dir := strings.TrimSuffix(filepath.ToSlash(filepath.Dir(clean)), "/")
	if IsGenericRootDir(dir) {
		return ""
	}

	// Traverse up past sub-folders like /bin, /cmd, /tools, /x64, /x86, /app, /client
	for {
		base := strings.ToLower(filepath.Base(dir))
		if base == "bin" || base == "cmd" || base == "tools" || base == "x64" || base == "x86" ||
			base == "application" || base == "app" || base == "client" {
			parent := strings.TrimSuffix(filepath.ToSlash(filepath.Dir(dir)), "/")
			if !IsGenericRootDir(parent) && parent != dir {
				dir = parent
				continue
			}
		}
		break
	}

	if IsGenericRootDir(dir) {
		return ""
	}
	return strings.ToLower(dir)
}

var exactSubToolNoise = map[string]bool{
	"nodevars":         true,
	"mvndebug":         true,
	"corepack":         true,
	"git-receive-pack": true,
	"git-upload-pack":  true,
	"git-shell":        true,
	"git-cvsserver":    true,
}

// IsSubToolNoise checks if a binary is a subordinate helper, script, or non-primary launcher.
func IsSubToolNoise(name, path string) bool {
	return isStandaloneNoise(name, path)
}

func isStandaloneNoise(name, path string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	if exactSubToolNoise[n] {
		return true
	}
	if strings.HasPrefix(n, "ijs") {
		return true
	}

	ext := strings.ToLower(filepath.Ext(path))
	if ext == ".cmd" || ext == ".bat" || ext == ".ps1" || ext == ".sh" || ext == ".vbs" {
		return true
	}
	return false
}

// IsAuxiliaryComponent checks if a binary or application name indicates a secondary helper.
func IsAuxiliaryComponent(name string) bool {
	n := strings.ToLower(name)
	auxKeywords := []string{
		"launcher", "mak", "config", "setup", "uninstall", "unins",
		"helper", "daemon", "updater", "patcher",
		"reload", "proxy", "broker", "worker", "renderer",
		"crashpad", "reporter", "wizard",
	}
	for _, kw := range auxKeywords {
		if strings.Contains(n, kw) {
			return true
		}
	}
	return false
}

// IsGenericRootDir checks if a directory path is a common OS or filesystem root container.
func IsGenericRootDir(dir string) bool {
	d := strings.ToLower(filepath.ToSlash(filepath.Clean(dir)))
	if d == "" || d == "/" || d == "." {
		return true
	}
	// Check drive root (e.g. "c:", "c:/")
	if (len(d) <= 3 && strings.HasSuffix(d, ":")) || (len(d) == 3 && d[1] == ':' && d[2] == '/') {
		return true
	}

	genericPaths := map[string]bool{
		"c:/temp":                true,
		"c:/tmp":                 true,
		"/tmp":                   true,
		"/var/tmp":               true,
		"c:/program files":       true,
		"c:/program files (x86)": true,
		"c:/windows":             true,
		"c:/windows/system32":    true,
		"c:/windows/syswow64":    true,
		"c:/programdata":         true,
		"c:/users":               true,
		"/usr":                   true,
		"/usr/bin":               true,
		"/usr/sbin":              true,
		"/usr/local":             true,
		"/usr/local/bin":         true,
		"/usr/local/sbin":        true,
		"/opt":                   true,
		"/bin":                   true,
		"/sbin":                  true,
		"/applications":          true,
		"/system/applications":   true,
		"/system":                true,
		"/library":               true,
		"/home":                  true,
	}

	if genericPaths[d] {
		return true
	}

	// Match user profiles and common download/temp containers:
	if strings.HasPrefix(d, "c:/users/") {
		parts := strings.Split(d, "/")
		if len(parts) <= 3 { // "c:/users/<username>"
			return true
		}
		if len(parts) == 4 {
			p4 := strings.ToLower(parts[3])
			if p4 == "appdata" || p4 == "downloads" || p4 == "desktop" || p4 == "documents" || p4 == "temp" {
				return true
			}
		}
		if len(parts) == 5 && parts[3] == "appdata" && (parts[4] == "local" || parts[4] == "roaming") {
			return true
		}
		if len(parts) == 6 && parts[3] == "appdata" && parts[4] == "local" && (parts[5] == "programs" || parts[5] == "temp") {
			return true
		}
	}

	if strings.HasPrefix(d, "/home/") || strings.HasPrefix(d, "/users/") {
		parts := strings.Split(d, "/")
		if len(parts) <= 3 { // "/home/<user>"
			return true
		}
		if len(parts) == 4 {
			p4 := strings.ToLower(parts[3])
			if p4 == "downloads" || p4 == "desktop" || p4 == "documents" || p4 == "temp" {
				return true
			}
		}
	}

	return false
}
