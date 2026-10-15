package provenance

import (
	"encoding/json"
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"
)

// PackageReceipt represents metadata recovered from a local package manager manifest.
type PackageReceipt struct {
	Manager     string     `json:"manager"` // "scoop", "cargo", "chocolatey"
	PackageName string     `json:"package_name"`
	Version     string     `json:"version,omitempty"`
	Homepage    string     `json:"homepage,omitempty"`
	Authors     string     `json:"authors,omitempty"`
	Description string     `json:"description,omitempty"`
	MatchedBin  string     `json:"matched_bin"`
	Confidence  Confidence `json:"confidence"`
}

// InspectPackageManagerReceipts inspects local package manager records for the binary path.
// Executes in order: Scoop -> Cargo -> Chocolatey with zero network overhead.
func InspectPackageManagerReceipts(binaryPath string) *PackageReceipt {
	if binaryPath == "" {
		return nil
	}

	if r := InspectScoopManifest(binaryPath); r != nil {
		return r
	}

	if r := InspectCargoCrates2(binaryPath); r != nil {
		return r
	}

	if r := InspectChocolateyNuspec(binaryPath); r != nil {
		return r
	}

	return nil
}

type scoopManifestJSON struct {
	Version     string `json:"version"`
	Description string `json:"description"`
	Homepage    string `json:"homepage"`
}

// InspectScoopManifest checks if a binary resides inside a Scoop apps installation tree.
// Path pattern: .../scoop/apps/<app>/...
func InspectScoopManifest(binaryPath string) *PackageReceipt {
	normalized := filepath.ToSlash(filepath.Clean(binaryPath))
	lower := strings.ToLower(normalized)

	const scoopAppsMarker = "/scoop/apps/"
	idx := strings.Index(lower, scoopAppsMarker)
	if idx == -1 {
		return nil
	}

	afterApps := normalized[idx+len(scoopAppsMarker):]
	parts := strings.Split(afterApps, "/")
	if len(parts) == 0 || parts[0] == "" {
		return nil
	}
	appName := parts[0]
	appDir := normalized[:idx+len(scoopAppsMarker)] + appName

	// Candidate manifest paths
	candidateManifests := []string{
		filepath.Join(filepath.FromSlash(appDir), "current", "manifest.json"),
	}
	if len(parts) > 1 && parts[1] != "" && parts[1] != "current" {
		candidateManifests = append(candidateManifests, filepath.Join(filepath.FromSlash(appDir), parts[1], "manifest.json"))
	}
	// Also check adjacent to binary
	binDir := filepath.Dir(binaryPath)
	candidateManifests = append(candidateManifests,
		filepath.Join(binDir, "manifest.json"),
		filepath.Join(binDir, "..", "manifest.json"),
	)

	for _, mPath := range candidateManifests {
		data, err := os.ReadFile(mPath)
		if err != nil {
			continue
		}
		var sm scoopManifestJSON
		if err := json.Unmarshal(data, &sm); err == nil && (sm.Version != "" || sm.Homepage != "") {
			return &PackageReceipt{
				Manager:     "scoop",
				PackageName: appName,
				Version:     sm.Version,
				Homepage:    sm.Homepage,
				Description: sm.Description,
				MatchedBin:  filepath.Base(binaryPath),
				Confidence:  ConfidenceVeryHigh,
			}
		}
	}

	return nil
}

type cargoCrates2JSON struct {
	Installs map[string]struct {
		Bins []string `json:"bins"`
	} `json:"installs"`
}

// InspectCargoCrates2 checks if a binary is tracked by Cargo in $CARGO_HOME/.crates2.json or %USERPROFILE%/.cargo/.crates2.json.
func InspectCargoCrates2(binaryPath string, customCratesPath ...string) *PackageReceipt {
	var cratesFile string
	if len(customCratesPath) > 0 && customCratesPath[0] != "" {
		cratesFile = customCratesPath[0]
	} else {
		cargoHome := os.Getenv("CARGO_HOME")
		if cargoHome != "" {
			cratesFile = filepath.Join(cargoHome, ".crates2.json")
		} else {
			userProfile := os.Getenv("USERPROFILE")
			if userProfile == "" {
				userProfile = os.Getenv("HOME")
			}
			if userProfile != "" {
				cratesFile = filepath.Join(userProfile, ".cargo", ".crates2.json")
			}
		}
	}

	if cratesFile == "" {
		return nil
	}

	data, err := os.ReadFile(cratesFile)
	if err != nil {
		return nil
	}

	var c2 cargoCrates2JSON
	if err := json.Unmarshal(data, &c2); err != nil || len(c2.Installs) == 0 {
		return nil
	}

	targetBin := strings.ToLower(filepath.Base(binaryPath))
	targetStem := strings.TrimSuffix(targetBin, ".exe")

	for installKey, details := range c2.Installs {
		for _, b := range details.Bins {
			bLower := strings.ToLower(b)
			bStem := strings.TrimSuffix(bLower, ".exe")
			if bLower == targetBin || bStem == targetStem {
				// Parse key: "<crate_name> <version> (<source>)"
				// e.g.: "ripgrep 14.1.0 (registry+https://github.com/rust-lang/crates.io-index)"
				crateName, version, repoURL := parseCargoInstallKey(installKey)
				return &PackageReceipt{
					Manager:     "cargo",
					PackageName: crateName,
					Version:     version,
					Homepage:    repoURL,
					Description: "Installed Rust binary from crates.io registry",
					MatchedBin:  filepath.Base(binaryPath),
					Confidence:  ConfidenceVeryHigh,
				}
			}
		}
	}

	return nil
}

func parseCargoInstallKey(key string) (name, version, source string) {
	key = strings.TrimSpace(key)
	parts := strings.Split(key, " ")
	if len(parts) >= 1 {
		name = parts[0]
	}
	if len(parts) >= 2 {
		version = parts[1]
	}
	if len(parts) >= 3 {
		source = strings.Join(parts[2:], " ")
		source = strings.TrimPrefix(source, "(")
		source = strings.TrimSuffix(source, ")")
		source = strings.TrimPrefix(source, "registry+")
	}
	return
}

type chocoNuspecXML struct {
	XMLName  xml.Name `xml:"package"`
	Metadata struct {
		ID          string `xml:"id"`
		Version     string `xml:"version"`
		Authors     string `xml:"authors"`
		ProjectURL  string `xml:"projectUrl"`
		Description string `xml:"description"`
	} `xml:"metadata"`
}

// InspectChocolateyNuspec checks if a binary resides inside a Chocolatey lib folder (.../chocolatey/lib/<pkg>/...).
func InspectChocolateyNuspec(binaryPath string) *PackageReceipt {
	normalized := filepath.ToSlash(filepath.Clean(binaryPath))
	lower := strings.ToLower(normalized)

	const chocoMarker = "/chocolatey/lib/"
	idx := strings.Index(lower, chocoMarker)
	if idx == -1 {
		return nil
	}

	afterLib := normalized[idx+len(chocoMarker):]
	parts := strings.Split(afterLib, "/")
	if len(parts) == 0 || parts[0] == "" {
		return nil
	}
	pkgName := parts[0]
	pkgDir := normalized[:idx+len(chocoMarker)] + pkgName

	// Search for *.nuspec in pkgDir
	entries, err := os.ReadDir(filepath.FromSlash(pkgDir))
	if err != nil {
		return nil
	}

	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(strings.ToLower(e.Name()), ".nuspec") {
			nuspecPath := filepath.Join(filepath.FromSlash(pkgDir), e.Name())
			data, err := os.ReadFile(nuspecPath)
			if err != nil {
				continue
			}
			var spec chocoNuspecXML
			if err := xml.Unmarshal(data, &spec); err == nil {
				id := spec.Metadata.ID
				if id == "" {
					id = pkgName
				}
				return &PackageReceipt{
					Manager:     "chocolatey",
					PackageName: id,
					Version:     spec.Metadata.Version,
					Homepage:    spec.Metadata.ProjectURL,
					Authors:     spec.Metadata.Authors,
					Description: spec.Metadata.Description,
					MatchedBin:  filepath.Base(binaryPath),
					Confidence:  ConfidenceVeryHigh,
				}
			}
		}
	}

	return nil
}
