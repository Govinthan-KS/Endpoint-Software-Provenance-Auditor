package classifier

import (
	"context"
	"path/filepath"
	"sort"
	"strings"

	"github.com/example/appaudit/internal/model"
	"github.com/example/appaudit/internal/provenance"
)

// ClassifierConfig specifies operational settings for the application classifier.
type ClassifierConfig struct {
	EnableOnlineLookup      bool
	NetworkMode             string // "off", "on", "hash-only"
	CustomProviders         []provenance.ProvenanceProvider
	CompanyDomainIndicators []string
}

var defaultPublishers = []string{
	"microsoft", "google", "apple", "canonical", "mozilla",
	"adobe", "jetbrains", "valve", "docker", "cisco",
	"oracle", "intel", "amd", "nvidia", "amazon",
	"spotify", "zoom", "slack", "discord", "atlassian",
	"github", "gitlab", "vmware", "broadcom", "realtek",
	"dell", "hp", "lenovo", "asus", "acer", "sony",
	"logitech", "brave", "opera", "notion", "dropbox",
	"autodesk", "electronic arts", "ubisoft", "epic games",
	"telegram", "meta", "facebook", "whatsapp", "apache",
	"nginx", "red hat", "suse", "debian", "ubuntu",
	"canonical snap", "flatpak application", "postman",
	"the git development community", "the openvpn project",
	"wireshark", "simon tatham", "mongodb", "nodejs",
	"openjs foundation", "python software foundation",
	"anaconda", "blender foundation", "videolan", "ffmpeg project",
	"gyan doshi", "curl developers", "sqlite development team",
}

// Classifier evaluates discovered applications and assigns provenance classifications.
type Classifier struct {
	config          ClassifierConfig
	knownPublishers []string
	resolver        *provenance.Resolver
	enricher        *Enricher
}

// New creates a new Classifier. By default, online lookups are disabled (NetworkOff).
func New(cfg ...ClassifierConfig) *Classifier {
	var c ClassifierConfig
	if len(cfg) > 0 {
		c = cfg[0]
	}
	return NewWithConfig(c)
}

// NewWithConfig creates a new Classifier configured with specific options.
func NewWithConfig(cfg ClassifierConfig) *Classifier {
	netMode := provenance.NetworkOff
	if cfg.NetworkMode == "on" || (cfg.NetworkMode == "" && cfg.EnableOnlineLookup) {
		netMode = provenance.NetworkOn
	} else if cfg.NetworkMode == "hash-only" {
		netMode = provenance.NetworkHashOnly
	}

	res := provenance.NewResolver(provenance.ResolverConfig{
		NetworkMode:             netMode,
		CustomProviders:         cfg.CustomProviders,
		CompanyDomainIndicators: cfg.CompanyDomainIndicators,
	})

	cl := &Classifier{
		config:          cfg,
		knownPublishers: defaultPublishers,
		resolver:        res,
	}

	if cfg.EnableOnlineLookup || cfg.NetworkMode == "on" {
		cl.enricher = NewEnricher()
	}

	return cl
}

// NewWithEnricher creates a new Classifier with a specified Enricher (for legacy test compatibility).
func NewWithEnricher(enricher *Enricher) *Classifier {
	cl := NewWithConfig(ClassifierConfig{EnableOnlineLookup: true, NetworkMode: "on"})
	cl.enricher = enricher
	return cl
}

// ClassifyApp applies evidence-backed provenance analysis to classify an application.
func (c *Classifier) ClassifyApp(app *model.Application) {
	art := provenance.Artifact{
		Name:      app.Name,
		Path:      app.Path,
		Publisher: app.Publisher,
		Version:   app.Version,
		Origin:    app.Origin,
	}

	res := c.resolver.Resolve(context.Background(), art)

	app.Classification = string(res.Classification)
	app.Confidence = string(res.Confidence)
	app.SHA256 = res.Fingerprint.SHA256
	app.SizeBytes = res.Fingerprint.Size
	app.Explanation = res.Explanation

	if res.ProductName != "" && app.Name == "" {
		app.Name = res.ProductName
	}
	if res.Publisher != "" && app.Publisher == "" {
		app.Publisher = res.Publisher
	}
	if res.Version != "" && app.Version == "" {
		app.Version = res.Version
	}

	if len(res.Evidence) > 0 {
		app.Evidence = res.Evidence[0].Description
	} else if len(res.Explanation) > 0 {
		app.Evidence = res.Explanation[0]
	}

	// Backward-compatible Category mapping
	switch res.Classification {
	case provenance.ClassificationThirdParty:
		app.Category = model.CategoryThirdParty
	case provenance.ClassificationCompany:
		app.Category = model.CategoryInHouse
	default:
		app.Category = model.CategoryUnknown
	}
}

// ReconcileAndClassify processes a collection of discovered applications,
// grouping multi-executable application suites into a single primary application
// and filtering sub-tool/auxiliary executable noise.
func (c *Classifier) ReconcileAndClassify(apps []model.Application) []model.Application {
	registeredByPath := make(map[string]*model.Application)
	registeredByName := make(map[string]*model.Application)

	var registered []model.Application
	var unmapped []model.Application

	for i := range apps {
		app := apps[i]

		if model.IsIgnoredComponent(app.Name) || model.IsWebStub(app.Path) || isSubToolNoise(app.Name, app.Path) || !model.IsExecutableTarget(app.Path) {
			continue
		}

		if app.Origin == "StartMenu" || app.Origin == "Registry" || app.Origin == "DesktopEntry" || app.Origin == "AppBundle" {
			registered = append(registered, app)
			if app.Path != "" {
				normP := strings.TrimSuffix(filepath.ToSlash(filepath.Clean(strings.ToLower(app.Path))), "/")
				registeredByPath[normP] = &registered[len(registered)-1]
			}
			if app.Name != "" {
				normN := strings.ToLower(strings.TrimSpace(app.Name))
				registeredByName[normN] = &registered[len(registered)-1]
			}
		} else {
			unmapped = append(unmapped, app)
		}
	}

	// First pass: Group registered applications by suite directory
	suiteGroups := make(map[string][]model.Application)
	var standaloneRegistered []model.Application

	for i := range registered {
		sDir := getSuiteDir(registered[i].Path)
		if sDir != "" {
			suiteGroups[sDir] = append(suiteGroups[sDir], registered[i])
		} else {
			standaloneRegistered = append(standaloneRegistered, registered[i])
		}
	}

	// Merge nested suite subdirectories into parent suite directory
	// (e.g. "c:/program files/postgresql/16/pgadmin 4" into "c:/program files/postgresql/16")
	mergedSuiteGroups := make(map[string][]model.Application)
	var sortedDirs []string
	for d := range suiteGroups {
		sortedDirs = append(sortedDirs, d)
	}
	sort.Slice(sortedDirs, func(i, j int) bool {
		return len(sortedDirs[i]) < len(sortedDirs[j])
	})

	for _, d := range sortedDirs {
		targetDir := d
		for parentDir := range mergedSuiteGroups {
			if strings.HasPrefix(d, parentDir+"/") {
				targetDir = parentDir
				break
			}
		}
		mergedSuiteGroups[targetDir] = append(mergedSuiteGroups[targetDir], suiteGroups[d]...)
	}
	suiteGroups = mergedSuiteGroups

	var results []model.Application
	seenCanonicalPaths := make(map[string]int)
	seenRegisteredNames := make(map[string]int)
	seenResultKeys := make(map[string]bool)
	registeredSuiteDirs := make(map[string]bool)

	// Consolidate suites: elect the best primary application for each suite directory
	for sDir, group := range suiteGroups {
		registeredSuiteDirs[sDir] = true

		bestIdx := 0
		bestScore := scoreAppSuitability(group[0], sDir)
		for j := 1; j < len(group); j++ {
			sc := scoreAppSuitability(group[j], sDir)
			if sc > bestScore {
				bestScore = sc
				bestIdx = j
			}
		}

		primary := group[bestIdx]

		// Merge metadata from other suite items (e.g. Publisher, Version)
		for j := range group {
			if j == bestIdx {
				continue
			}
			if primary.Publisher == "" && group[j].Publisher != "" {
				primary.Publisher = group[j].Publisher
			}
			if primary.Version == "" && group[j].Version != "" {
				primary.Version = group[j].Version
			}
		}

		c.ClassifyApp(&primary)
		normPath := strings.TrimSuffix(filepath.ToSlash(filepath.Clean(strings.ToLower(primary.Path))), "/")
		normName := strings.ToLower(strings.TrimSpace(primary.Name))

		key := normName + "|" + normPath
		if !seenResultKeys[key] {
			seenResultKeys[key] = true
			resIdx := len(results)
			if normPath != "" {
				seenCanonicalPaths[normPath] = resIdx
			}
			if normName != "" {
				seenRegisteredNames[normName] = resIdx
			}
			results = append(results, primary)
		}
	}

	// Add standalone registered applications
	for i := range standaloneRegistered {
		c.ClassifyApp(&standaloneRegistered[i])
		normPath := strings.TrimSuffix(filepath.ToSlash(filepath.Clean(strings.ToLower(standaloneRegistered[i].Path))), "/")
		normName := strings.ToLower(strings.TrimSpace(standaloneRegistered[i].Name))

		if idx, exists := seenCanonicalPaths[normPath]; exists && normPath != "" {
			existing := &results[idx]
			if existing.Publisher == "" && standaloneRegistered[i].Publisher != "" {
				existing.Publisher = standaloneRegistered[i].Publisher
			}
			if existing.Version == "" && standaloneRegistered[i].Version != "" {
				existing.Version = standaloneRegistered[i].Version
			}
			continue
		}

		if idx, exists := seenRegisteredNames[normName]; exists && normName != "" {
			existing := &results[idx]
			if existing.Publisher == "" && standaloneRegistered[i].Publisher != "" {
				existing.Publisher = standaloneRegistered[i].Publisher
			}
			if existing.Version == "" && standaloneRegistered[i].Version != "" {
				existing.Version = standaloneRegistered[i].Version
			}
			continue
		}

		key := normName + "|" + normPath
		if !seenResultKeys[key] {
			seenResultKeys[key] = true
			resIdx := len(results)
			if normPath != "" {
				seenCanonicalPaths[normPath] = resIdx
			}
			if normName != "" {
				seenRegisteredNames[normName] = resIdx
			}
			results = append(results, standaloneRegistered[i])
		}
	}

	// Second pass: unmapped binaries (PATH and active processes)
	seenUnmappedNames := make(map[string]bool)
	for i := range unmapped {
		item := unmapped[i]

		if isSubToolNoise(item.Name, item.Path) || isAuxiliaryComponent(item.Name) || model.IsIgnoredComponent(item.Name) || model.IsWebStub(item.Path) || !model.IsExecutableTarget(item.Path) {
			continue
		}

		normItemPath := strings.TrimSuffix(filepath.ToSlash(filepath.Clean(strings.ToLower(item.Path))), "/")
		normItemName := strings.ToLower(strings.TrimSpace(item.Name))

		// Check if binary belongs to an already-registered application suite folder
		isRegisteredMatch := false
		if _, exists := registeredByPath[normItemPath]; exists {
			isRegisteredMatch = true
		} else {
			itemSuite := getSuiteDir(normItemPath)
			if itemSuite != "" && registeredSuiteDirs[itemSuite] {
				isRegisteredMatch = true
			} else {
				for regSuiteDir := range registeredSuiteDirs {
					if regSuiteDir != "" && (strings.HasPrefix(normItemPath, regSuiteDir+"/") || normItemPath == regSuiteDir) {
						isRegisteredMatch = true
						break
					}
				}
			}
		}

		if isRegisteredMatch {
			continue
		}

		// Perform classification
		c.ClassifyApp(&item)

		if item.Category == model.CategoryInHouse || item.Category == model.CategoryUnknown {
			if seenUnmappedNames[normItemName] {
				continue
			}
			seenUnmappedNames[normItemName] = true
		}

		key := normItemName + "|" + normItemPath
		if !seenResultKeys[key] {
			seenResultKeys[key] = true
			results = append(results, item)
		}
	}

	// Legacy online enrichment adapter if active
	if c.config.EnableOnlineLookup && c.enricher != nil {
		c.enricher.Enrich(results)
	}

	return results
}

// NetworkStats returns metrics about online enrichment lookups and cache hits.
func (c *Classifier) NetworkStats() NetworkStats {
	if c.config.EnableOnlineLookup && c.enricher != nil {
		return c.enricher.Stats()
	}
	return NetworkStats{
		Enabled: false,
	}
}

// EnrichCandidates performs online verification on a slice of applications.
func (c *Classifier) EnrichCandidates(apps []model.Application) {
	c.config.EnableOnlineLookup = true
	onlineResolver := provenance.NewResolver(provenance.ResolverConfig{
		NetworkMode:             provenance.NetworkOn,
		CompanyDomainIndicators: c.config.CompanyDomainIndicators,
		CustomProviders:         c.config.CustomProviders,
	})

	for i := range apps {
		if apps[i].Classification == string(provenance.ClassificationUnknown) || apps[i].Category == model.CategoryInHouse {
			art := provenance.Artifact{
				Name:      apps[i].Name,
				Path:      apps[i].Path,
				Publisher: apps[i].Publisher,
				Version:   apps[i].Version,
				Origin:    apps[i].Origin,
			}
			res := onlineResolver.Resolve(context.Background(), art)
			apps[i].Classification = string(res.Classification)
			apps[i].Confidence = string(res.Confidence)
			apps[i].SHA256 = res.Fingerprint.SHA256
			apps[i].SizeBytes = res.Fingerprint.Size
			apps[i].Explanation = res.Explanation
			if len(res.Evidence) > 0 {
				apps[i].Evidence = res.Evidence[0].Description
			}
			switch res.Classification {
			case provenance.ClassificationThirdParty:
				apps[i].Category = model.CategoryThirdParty
			case provenance.ClassificationCompany:
				apps[i].Category = model.CategoryInHouse
			default:
				apps[i].Category = model.CategoryUnknown
			}
		}
	}
}

func isSubToolNoise(name, path string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	exactNoise := map[string]bool{
		"nodevars":         true,
		"mvndebug":         true,
		"corepack":         true,
		"gofmt":            true,
		"git-receive-pack": true,
		"git-upload-pack":  true,
		"git-shell":        true,
		"git-cvsserver":    true,
	}
	if exactNoise[n] {
		return true
	}
	if strings.HasPrefix(n, "ijs") {
		return true
	}

	if strings.HasSuffix(n, "helper") || strings.HasSuffix(n, "monitor") ||
		strings.HasSuffix(n, "background") || strings.HasSuffix(n, "container") ||
		strings.HasSuffix(n, "daemon") || strings.HasSuffix(n, "webview2") {
		return true
	}

	ext := strings.ToLower(filepath.Ext(path))
	if ext == ".cmd" || ext == ".bat" || ext == ".ps1" || ext == ".sh" || ext == ".vbs" {
		return true
	}
	return false
}

func isAuxiliaryComponent(name string) bool {
	n := strings.ToLower(name)
	auxKeywords := []string{
		"launcher", "mak", "config", "setup", "uninstall", "unins",
		"helper", "daemon", "updater", "patcher",
		"reload", "proxy", "broker", "worker",
		"crashpad", "reporter", "wizard",
	}
	for _, kw := range auxKeywords {
		if strings.Contains(n, kw) {
			return true
		}
	}
	return false
}

func getSuiteDir(path string) string {
	if path == "" {
		return ""
	}
	clean := filepath.ToSlash(filepath.Clean(path))
	dir := strings.TrimSuffix(filepath.ToSlash(filepath.Dir(clean)), "/")
	if isGenericRootDir(dir) {
		return ""
	}

	// Traverse up past sub-folders like /bin, /cmd, /tools, /x64, /app, /client
	for {
		base := strings.ToLower(filepath.Base(dir))
		if base == "bin" || base == "cmd" || base == "tools" || base == "x64" || base == "x86" || base == "application" || base == "app" || base == "client" {
			parent := strings.TrimSuffix(filepath.ToSlash(filepath.Dir(dir)), "/")
			if !isGenericRootDir(parent) && parent != dir {
				dir = parent
				continue
			}
		}
		break
	}

	if isGenericRootDir(dir) {
		return ""
	}
	return strings.ToLower(dir)
}

func scoreAppSuitability(app model.Application, suiteDir string) int {
	score := 50
	if app.Origin == "Registry" {
		score += 50
	} else if app.Origin == "DesktopEntry" || app.Origin == "AppBundle" {
		score += 40
	} else if app.Origin == "StartMenu" {
		score += 30
	}

	normName := strings.ToLower(strings.TrimSpace(app.Name))
	suiteBase := strings.ToLower(filepath.Base(suiteDir))

	if normName == suiteBase || strings.Contains(normName, suiteBase) {
		score += 40
	}

	exeBase := strings.ToLower(filepath.Base(app.Path))
	exeName := strings.TrimSuffix(exeBase, filepath.Ext(exeBase))
	if exeName == suiteBase || strings.Contains(exeName, suiteBase) {
		score += 30
	}

	if isAuxiliaryComponent(app.Name) || isAuxiliaryComponent(exeName) {
		score -= 60
	}

	if app.Publisher != "" {
		score += 15
	}
	if app.Version != "" {
		score += 15
	}

	return score
}

func isGenericRootDir(dir string) bool {
	d := strings.ToLower(filepath.ToSlash(filepath.Clean(dir)))
	if d == "" || d == "/" || d == "." {
		return true
	}
	// Check drive root (e.g. "c:", "c:/")
	if (len(d) <= 3 && strings.HasSuffix(d, ":")) || (len(d) == 3 && d[1] == ':' && d[2] == '/') {
		return true
	}

	genericPaths := map[string]bool{
		"c:/program files":        true,
		"c:/program files (x86)":  true,
		"c:/windows":              true,
		"c:/windows/system32":     true,
		"c:/windows/syswow64":     true,
		"c:/programdata":          true,
		"c:/users":                true,
		"/usr":                    true,
		"/usr/bin":                true,
		"/usr/sbin":               true,
		"/usr/local":              true,
		"/usr/local/bin":          true,
		"/usr/local/sbin":         true,
		"/opt":                    true,
		"/bin":                    true,
		"/sbin":                   true,
		"/applications":           true,
		"/system/applications":    true,
		"/system":                 true,
		"/library":                true,
		"/home":                   true,
	}

	if genericPaths[d] {
		return true
	}

	// Match user profiles and AppData base containers:
	if strings.HasPrefix(d, "c:/users/") {
		parts := strings.Split(d, "/")
		if len(parts) <= 3 { // "c:/users/<username>"
			return true
		}
		if len(parts) == 4 && parts[3] == "appdata" {
			return true
		}
		if len(parts) == 5 && parts[3] == "appdata" && (parts[4] == "local" || parts[4] == "roaming") {
			return true
		}
		if len(parts) == 6 && parts[3] == "appdata" && parts[4] == "local" && parts[5] == "programs" {
			return true
		}
	}

	if strings.HasPrefix(d, "/home/") {
		parts := strings.Split(d, "/")
		if len(parts) <= 3 { // "/home/<user>"
			return true
		}
	}

	return false
}
