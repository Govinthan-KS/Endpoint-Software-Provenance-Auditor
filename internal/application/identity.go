package application

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/example/appaudit/internal/provenance"
)

// KnownPublicProject maps known tool signatures to canonical public application identities.
type KnownPublicProject struct {
	CanonicalName   string
	Publisher       string
	PrimaryBinaries []string
	SiblingBinaries []string
	FolderKeywords  []string
	ComponentTokens []string
}

var knownPublicProjects = []KnownPublicProject{
	{
		CanonicalName:   "FFmpeg",
		Publisher:       "FFmpeg Project",
		PrimaryBinaries: []string{"ffmpeg"},
		SiblingBinaries: []string{"ffplay", "ffprobe"},
		FolderKeywords:  []string{"ffmpeg", "ffmpeg-"},
		ComponentTokens: []string{"libavcodec", "libavformat", "libavutil", "ffmpeg developers"},
	},
	{
		CanonicalName:   "Git",
		Publisher:       "The Git Development Community",
		PrimaryBinaries: []string{"git"},
		SiblingBinaries: []string{"git-receive-pack", "git-upload-pack", "git-shell"},
		FolderKeywords:  []string{"git"},
		ComponentTokens: []string{"libgit", "git version"},
	},
	{
		CanonicalName:   "PostgreSQL",
		Publisher:       "PostgreSQL Global Development Group",
		PrimaryBinaries: []string{"postgres"},
		SiblingBinaries: []string{"psql", "pg_dump", "pgadmin4"},
		FolderKeywords:  []string{"postgresql", "postgres"},
		ComponentTokens: []string{"libpq", "postgresql"},
	},
	{
		CanonicalName:   "Python",
		Publisher:       "Python Software Foundation",
		PrimaryBinaries: []string{"python", "python3"},
		SiblingBinaries: []string{"pythonw", "pip"},
		FolderKeywords:  []string{"python", "python3"},
		ComponentTokens: []string{"cpython", "python core"},
	},
	{
		CanonicalName:   "Node.js",
		Publisher:       "OpenJS Foundation",
		PrimaryBinaries: []string{"node"},
		SiblingBinaries: []string{"npm", "npx", "corepack"},
		FolderKeywords:  []string{"nodejs", "node"},
		ComponentTokens: []string{"v8", "nodejs"},
	},
	{
		CanonicalName:   "Go Toolchain",
		Publisher:       "Google LLC / The Go Authors",
		PrimaryBinaries: []string{"go"},
		SiblingBinaries: []string{"gofmt"},
		FolderKeywords:  []string{"go\\bin", "go/bin"},
		ComponentTokens: []string{"go compiler", "runtime/internal"},
	},
	{
		CanonicalName:   "7-Zip",
		Publisher:       "Igor Pavlov",
		PrimaryBinaries: []string{"7z", "7zfm"},
		SiblingBinaries: []string{"7za"},
		FolderKeywords:  []string{"7-zip", "7zip"},
		ComponentTokens: []string{"7-zip", "igor pavlov"},
	},
	{
		CanonicalName:   "ripgrep",
		Publisher:       "Andrew Gallant (BurntSushi)",
		PrimaryBinaries: []string{"rg"},
		FolderKeywords:  []string{"ripgrep"},
		ComponentTokens: []string{"burntsushi", "ripgrep"},
	},
	{
		CanonicalName:   "curl",
		Publisher:       "Daniel Stenberg",
		PrimaryBinaries: []string{"curl"},
		FolderKeywords:  []string{"curl"},
		ComponentTokens: []string{"libcurl", "daniel stenberg"},
	},
	{
		CanonicalName:   "MongoDB",
		Publisher:       "MongoDB, Inc.",
		PrimaryBinaries: []string{"mongod"},
		SiblingBinaries: []string{"mongos", "mongosh", "mongo", "mongoimport", "mongodump", "mongorestore", "mongoexport"},
		FolderKeywords:  []string{"mongodb"},
		ComponentTokens: []string{"mongodb"},
	},
}

// CanonicalBinaryBase returns the normalized lower-case base name of an executable without path or extension.
func CanonicalBinaryBase(name string) string {
	b := strings.ToLower(strings.TrimSpace(name))
	b = filepath.Base(b)
	return strings.TrimSuffix(b, filepath.Ext(b))
}

// ResolveIdentity deduces the logical application identity from multi-signal evidence.
func ResolveIdentity(bundle EvidenceBundle) ApplicationIdentity {
	var signals []string

	// 0. Local Package Manager or Runtime Receipts (Tier 1.5A)
	if bundle.PackageReceipt != nil {
		rec := bundle.PackageReceipt
		pub := rec.Authors
		if pub == "" {
			pub = rec.PackageName
		}
		return ApplicationIdentity{
			Name:       rec.PackageName,
			Publisher:  pub,
			Version:    rec.Version,
			Ecosystem:  rec.Manager,
			Confidence: provenance.ConfidenceVeryHigh,
			Signals:    []string{fmt.Sprintf("Local package receipt (%s): %s v%s", rec.Manager, rec.PackageName, rec.Version)},
		}
	}
	if bundle.RuntimeReceipt != nil {
		rec := bundle.RuntimeReceipt
		pub := rec.Author
		if pub == "" {
			pub = rec.PackageName
		}
		return ApplicationIdentity{
			Name:       rec.PackageName,
			Publisher:  pub,
			Version:    rec.Version,
			Ecosystem:  rec.Ecosystem,
			Confidence: provenance.ConfidenceVeryHigh,
			Signals:    []string{fmt.Sprintf("Local runtime receipt (%s): %s v%s", rec.Ecosystem, rec.PackageName, rec.Version)},
		}
	}

	// 1. Direct Go BuildInfo Identity
	for _, b := range bundle.Binaries {
		if b.Inspection.BuildInfo != nil && b.Inspection.BuildInfo.MainModule != "" {
			mod := b.Inspection.BuildInfo.MainModule
			signals = append(signals, "Go build module: "+mod)
			name := filepath.Base(mod)
			if name != "" && name != "." {
				return ApplicationIdentity{
					Name:       name,
					Publisher:  mod,
					Version:    b.Inspection.BuildInfo.MainVersion,
					Ecosystem:  "go",
					Confidence: provenance.ConfidenceVeryHigh,
					Signals:    signals,
				}
			}
		}
	}

	// 2. Direct PE Product Metadata Identity
	for _, b := range bundle.Binaries {
		if !b.Inspection.IsWrapperStub && b.Inspection.ProductName != "" {
			signals = append(signals, "PE VersionInfo ProductName: "+b.Inspection.ProductName)
			if b.Inspection.CompanyName != "" {
				signals = append(signals, "PE VersionInfo CompanyName: "+b.Inspection.CompanyName)
			}
			return ApplicationIdentity{
				Name:       b.Inspection.ProductName,
				Publisher:  b.Inspection.CompanyName,
				Version:    b.Inspection.ProductVersion,
				Confidence: provenance.ConfidenceHigh,
				Signals:    signals,
			}
		}
	}

	// 3. Known Public Project Corroboration Engine
	for _, proj := range knownPublicProjects {
		score := 0
		var matchedSignals []string

		// Check primary binary match
		hasPrimaryMatch := false
		primaryBase := CanonicalBinaryBase(bundle.PrimaryBinary.Name)
		for _, pb := range proj.PrimaryBinaries {
			if primaryBase == CanonicalBinaryBase(pb) {
				hasPrimaryMatch = true
				score += 40
				matchedSignals = append(matchedSignals, "Primary binary name matches '"+pb+"'")
				break
			}
		}

		// Check sibling binaries - ensure each canonical sibling can match at most once,
		// and each physical binary produces at most one signal!
		hasSiblingMatch := false
		seenSiblings := make(map[string]bool)
		for _, sib := range proj.SiblingBinaries {
			canonicalSib := CanonicalBinaryBase(sib)
			if seenSiblings[canonicalSib] {
				continue
			}
			if bundle.HasSiblingBinary(canonicalSib) {
				seenSiblings[canonicalSib] = true
				hasSiblingMatch = true
				score += 25
				matchedSignals = append(matchedSignals, "Sibling binary matches layout: '"+canonicalSib+"'")
			}
		}

		// Check directory keywords - only corroborates if executable name or sibling already matched!
		if hasPrimaryMatch || hasSiblingMatch {
			dirLower := strings.ToLower(bundle.InstallDir)
			for _, kw := range proj.FolderKeywords {
				if strings.Contains(dirLower, kw) {
					score += 15
					matchedSignals = append(matchedSignals, "Install directory matches keyword: '"+kw+"'")
					break
				}
			}
		}

		// Check embedded component tokens
		// CRITICAL: Embedded component strings (e.g. libavcodec in an internal app)
		// must NEVER classify the containing application. They only provide corroborative
		// context if primary or sibling executables already matched this project!
		var matchedTokens []string
		for _, token := range proj.ComponentTokens {
			if bundle.HasEmbeddedComponent(token) {
				matchedTokens = append(matchedTokens, token)
			}
		}
		if len(matchedTokens) > 0 && (hasPrimaryMatch || hasSiblingMatch) {
			score += 15
			matchedSignals = append(matchedSignals, fmt.Sprintf("Embedded component candidate: %s (%s)", proj.CanonicalName, strings.Join(matchedTokens, ", ")))
		}

		// Project identity requires at least primary executable name OR sibling executable match!
		if (hasPrimaryMatch || hasSiblingMatch) && score >= 50 {
			conf := provenance.ConfidenceHigh
			if score >= 75 {
				conf = provenance.ConfidenceVeryHigh
			}
			return ApplicationIdentity{
				Name:       proj.CanonicalName,
				Publisher:  proj.Publisher,
				Version:    bundle.PrimaryBinary.Version,
				Confidence: conf,
				Signals:    matchedSignals,
			}
		}
	}

	// 4. Host OS Manifest Identity
	if bundle.AppName != "" && (bundle.Origin == "Registry" || bundle.Origin == "DesktopEntry" || bundle.Origin == "AppBundle") {
		signals = append(signals, "Official host manifest entry: "+bundle.AppName)
		return ApplicationIdentity{
			Name:       bundle.AppName,
			Publisher:  bundle.Publisher,
			Version:    bundle.Version,
			Confidence: provenance.ConfidenceHigh,
			Signals:    signals,
		}
	}

	// 5. Default fallback to AppName or primary binary base
	fallbackName := bundle.AppName
	if fallbackName == "" {
		fallbackName = strings.TrimSuffix(bundle.PrimaryBinary.Name, filepath.Ext(bundle.PrimaryBinary.Name))
	}

	return ApplicationIdentity{
		Name:       fallbackName,
		Publisher:  bundle.Publisher,
		Version:    bundle.Version,
		Confidence: provenance.ConfidenceLow,
		Signals:    []string{"Uncorroborated single executable candidate: " + fallbackName},
	}
}

// IsRecognizedThirdPartyProject checks if the resolved identity is an established public project.
func IsRecognizedThirdPartyProject(identity ApplicationIdentity) bool {
	idLower := strings.ToLower(strings.TrimSpace(identity.Name))
	for _, proj := range knownPublicProjects {
		if strings.ToLower(proj.CanonicalName) == idLower {
			return true
		}
	}
	return false
}
