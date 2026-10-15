package provenance

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// RuntimeReceipt represents metadata recovered from a local runtime environment (Python dist-info, Node package.json).
type RuntimeReceipt struct {
	Ecosystem   string     `json:"ecosystem"` // "python", "node"
	PackageName string     `json:"package_name"`
	Version     string     `json:"version,omitempty"`
	Homepage    string     `json:"homepage,omitempty"`
	Author      string     `json:"author,omitempty"`
	Summary     string     `json:"summary,omitempty"`
	DistInfoDir string     `json:"dist_info_dir,omitempty"`
	MatchedBin  string     `json:"matched_bin"`
	Confidence  Confidence `json:"confidence"`
}

// InspectRuntimeReceipts inspects adjacent Python site-packages or Node package.json records.
func InspectRuntimeReceipts(binaryPath string, customSearchDirs ...string) *RuntimeReceipt {
	if binaryPath == "" {
		return nil
	}

	if r := InspectPythonRuntime(binaryPath, customSearchDirs...); r != nil {
		return r
	}

	if r := InspectNodeRuntime(binaryPath); r != nil {
		return r
	}

	return nil
}

// InspectPythonRuntime locates and parses Python dist-info metadata matching the binary.
func InspectPythonRuntime(binaryPath string, customSearchDirs ...string) *RuntimeReceipt {
	binBase := filepath.Base(binaryPath)
	binStem := strings.ToLower(strings.TrimSuffix(binBase, filepath.Ext(binBase)))
	dir := filepath.Dir(binaryPath)
	dirLower := strings.ToLower(dir)

	// Quick check: if customSearchDirs is not provided, only inspect if path indicates Python/CLI context
	if len(customSearchDirs) == 0 {
		isPythonContext := strings.Contains(dirLower, "scripts") ||
			strings.Contains(dirLower, "bin") ||
			strings.Contains(dirLower, "python") ||
			strings.Contains(dirLower, ".local") ||
			strings.Contains(dirLower, "site-packages") ||
			strings.Contains(dirLower, "dist-packages") ||
			strings.Contains(dirLower, "venv") ||
			strings.Contains(dirLower, "env")

		if !isPythonContext {
			adjLib := filepath.Join(dir, "..", "Lib", "site-packages")
			adjLib2 := filepath.Join(dir, "..", "lib", "site-packages")
			if _, err := os.Stat(adjLib); err != nil {
				if _, err2 := os.Stat(adjLib2); err2 != nil {
					return nil
				}
			}
		}
	}

	var candidateSitePackages []string
	if len(customSearchDirs) > 0 {
		candidateSitePackages = append(candidateSitePackages, customSearchDirs...)
	}

	// Windows standard virtualenv layouts:
	// <venv>\Scripts\tool.exe -> <venv>\Lib\site-packages
	candidateSitePackages = append(candidateSitePackages,
		filepath.Join(dir, "..", "Lib", "site-packages"),
		filepath.Join(dir, "..", "lib", "site-packages"),
		filepath.Join(dir, "..", "site-packages"),
		filepath.Join(dir, "site-packages"),
	)

	// User-level Python site-packages (%APPDATA%\Python\Python*\site-packages):
	appData := os.Getenv("APPDATA")
	if appData != "" {
		pyRoot := filepath.Join(appData, "Python")
		if entries, err := os.ReadDir(pyRoot); err == nil {
			for _, e := range entries {
				if e.IsDir() && strings.HasPrefix(strings.ToLower(e.Name()), "python") {
					candidateSitePackages = append(candidateSitePackages, filepath.Join(pyRoot, e.Name(), "site-packages"))
				}
			}
		}
	}

	// pipx virtualenv locations (%USERPROFILE%\.local\pipx\venvs\<tool>\Lib\site-packages)
	userProfile := os.Getenv("USERPROFILE")
	if userProfile == "" {
		userProfile = os.Getenv("HOME")
	}
	if userProfile != "" {
		pipxVenvs := []string{
			filepath.Join(userProfile, ".local", "pipx", "venvs", binStem, "Lib", "site-packages"),
			filepath.Join(userProfile, ".local", "share", "pipx", "venvs", binStem, "Lib", "site-packages"),
		}
		candidateSitePackages = append(candidateSitePackages, pipxVenvs...)
	}

	for _, sitePkg := range candidateSitePackages {
		cleanSitePkg := filepath.Clean(sitePkg)
		entries, err := os.ReadDir(cleanSitePkg)
		if err != nil {
			continue
		}

		// First pass: look for entry_points.txt exact mapping inside *.dist-info
		for _, e := range entries {
			if !e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".dist-info") {
				continue
			}
			distInfoPath := filepath.Join(cleanSitePkg, e.Name())
			epFile := filepath.Join(distInfoPath, "entry_points.txt")
			if matchesEntryPoint(epFile, binStem) {
				if r, err := ParsePythonDistInfo(distInfoPath); err == nil && r != nil {
					r.MatchedBin = binBase
					return r
				}
			}
		}

		// Second pass: directory name prefix match (e.g., aider_chat-0.86.2.dist-info or black-24.3.0.dist-info)
		binStemUnderscore := strings.ReplaceAll(binStem, "-", "_")
		binStemDash := strings.ReplaceAll(binStem, "_", "-")
		for _, e := range entries {
			if !e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".dist-info") {
				continue
			}
			lowerName := strings.ToLower(e.Name())
			if strings.HasPrefix(lowerName, binStem+"-") ||
				strings.HasPrefix(lowerName, binStemUnderscore+"-") ||
				strings.HasPrefix(lowerName, binStemDash+"-") ||
				strings.HasPrefix(lowerName, binStem+"_") {
				distInfoPath := filepath.Join(cleanSitePkg, e.Name())
				if r, err := ParsePythonDistInfo(distInfoPath); err == nil && r != nil {
					r.MatchedBin = binBase
					return r
				}
			}
		}
	}

	return nil
}

// matchesEntryPoint checks if an entry_points.txt defines a console_script matching binStem.
func matchesEntryPoint(epPath, binStem string) bool {
	f, err := os.Open(epPath)
	if err != nil {
		return false
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	inConsoleScripts := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			inConsoleScripts = strings.EqualFold(line, "[console_scripts]")
			continue
		}
		if inConsoleScripts && line != "" {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) >= 1 {
				scriptName := strings.ToLower(strings.TrimSpace(parts[0]))
				if scriptName == binStem {
					return true
				}
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return false
	}
	return false
}

// ParsePythonDistInfo reads a METADATA file from a .dist-info folder and extracts package details.
func ParsePythonDistInfo(distInfoDir string) (*RuntimeReceipt, error) {
	metaFile := filepath.Join(distInfoDir, "METADATA")
	f, err := os.Open(metaFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	r := &RuntimeReceipt{
		Ecosystem:   "python",
		DistInfoDir: distInfoDir,
		Confidence:  ConfidenceVeryHigh,
	}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		// RFC 822 header ends at empty line before description body
		if line == "" {
			break
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(parts[0]))
		val := strings.TrimSpace(parts[1])

		switch key {
		case "name":
			r.PackageName = val
		case "version":
			r.Version = val
		case "author":
			if r.Author == "" {
				r.Author = val
			}
		case "author-email":
			if r.Author == "" {
				// Strip email e.g. "Paul Gauthier <paul@...>" -> "Paul Gauthier"
				emailIdx := strings.Index(val, "<")
				if emailIdx > 0 {
					r.Author = strings.TrimSpace(val[:emailIdx])
				} else {
					r.Author = val
				}
			}
		case "home-page":
			if r.Homepage == "" {
				r.Homepage = val
			}
		case "project-url":
			// Formats: "Homepage, https://github.com/..." or "repository, https://..."
			urlParts := strings.SplitN(val, ",", 2)
			if len(urlParts) == 2 {
				urlLabel := strings.ToLower(strings.TrimSpace(urlParts[0]))
				urlVal := strings.TrimSpace(urlParts[1])
				if r.Homepage == "" || urlLabel == "homepage" || urlLabel == "repository" {
					r.Homepage = urlVal
				}
			}
		case "summary":
			r.Summary = val
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	if r.PackageName == "" {
		return nil, os.ErrNotExist
	}

	return r, nil
}

type nodePackageJSON struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Description string `json:"description"`
	Homepage    string `json:"homepage"`
	Author      any    `json:"author"`
	Repository  any    `json:"repository"`
}

// InspectNodeRuntime checks if a binary resides in a Node node_modules tree.
func InspectNodeRuntime(binaryPath string) *RuntimeReceipt {
	normalized := filepath.ToSlash(filepath.Clean(binaryPath))
	lower := strings.ToLower(normalized)

	if !strings.Contains(lower, "node_modules") {
		return nil
	}

	dir := filepath.Dir(binaryPath)
	// Walk upwards up to 4 levels looking for package.json
	curr := dir
	for i := 0; i < 4; i++ {
		pkgFile := filepath.Join(curr, "package.json")
		if data, err := os.ReadFile(pkgFile); err == nil {
			var np nodePackageJSON
			if err := json.Unmarshal(data, &np); err == nil && np.Name != "" {
				authorStr := ""
				switch a := np.Author.(type) {
				case string:
					authorStr = a
				case map[string]any:
					if name, ok := a["name"].(string); ok {
						authorStr = name
					}
				}

				repoStr := ""
				switch r := np.Repository.(type) {
				case string:
					repoStr = r
				case map[string]any:
					if url, ok := r["url"].(string); ok {
						repoStr = url
					}
				}

				homepage := np.Homepage
				if homepage == "" {
					homepage = repoStr
				}

				return &RuntimeReceipt{
					Ecosystem:   "node",
					PackageName: np.Name,
					Version:     np.Version,
					Homepage:    homepage,
					Author:      authorStr,
					Summary:     np.Description,
					MatchedBin:  filepath.Base(binaryPath),
					Confidence:  ConfidenceVeryHigh,
				}
			}
		}
		parent := filepath.Dir(curr)
		if parent == curr {
			break
		}
		curr = parent
	}

	return nil
}
