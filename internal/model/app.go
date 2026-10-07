package model

import (
	"path/filepath"
	"strings"
)

// Category represents the classification of an application.
type Category string

const (
	// CategoryInHouse identifies internally developed, custom, or ad-hoc applications.
	CategoryInHouse Category = "In-House / Custom"

	// CategoryThirdParty identifies officially registered or vendor-provided applications.
	CategoryThirdParty Category = "Third-Party / Registered"

	// CategoryUnknown identifies applications where provenance cannot be established with sufficient confidence.
	CategoryUnknown Category = "Unknown / Unresolved"
)

// Application represents a unified discovered application record with provenance intelligence.
type Application struct {
	Name           string      `json:"name"`
	Path           string      `json:"path"`
	Publisher      string      `json:"publisher,omitempty"`
	Version        string      `json:"version,omitempty"`
	Category       Category    `json:"category"`
	Origin         string      `json:"origin"`
	Evidence       string      `json:"evidence"`
	Classification string      `json:"classification,omitempty"`
	Confidence     string      `json:"confidence,omitempty"`
	SHA256         string      `json:"sha256,omitempty"`
	SizeBytes      int64       `json:"size_bytes,omitempty"`
	Explanation    []string    `json:"explanation,omitempty"`
}

// IsIgnoredComponent checks if an application name corresponds to a non-application component,
// such as a runtime redistributable, driver package, hardware SDK, update assistant, language pack,
// web shortcut, or documentation/help link.
func IsIgnoredComponent(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		return true
	}

	// 1. Runtime Redistributables
	if strings.Contains(n, "redistributable") || strings.Contains(n, "redist") {
		return true
	}

	// 2. Hardware / Software SDKs
	if strings.Contains(n, "sdk") || strings.Contains(n, "software development kit") {
		return true
	}

	// 3. Drivers, Chipsets, Support Assist
	if strings.Contains(n, "driver") || strings.Contains(n, "chipset") ||
		strings.Contains(n, "supportassist") || strings.Contains(n, "support assist") {
		return true
	}

	// 4. Update Helpers, Setups, Installers
	if strings.Contains(n, "update assistant") || strings.Contains(n, "update helper") ||
		strings.Contains(n, "setup") || strings.Contains(n, "installer") ||
		strings.Contains(n, "uninstaller") || strings.Contains(n, "uninstall") ||
		strings.HasPrefix(n, "unins") || strings.Contains(n, "bootstrapper") {
		return true
	}

	// 5. Language Packs & Package Caches
	if strings.Contains(n, "language pack") || strings.Contains(n, "langpack") ||
		strings.Contains(n, "language experience pack") || strings.Contains(n, "package cache") {
		return true
	}

	// 6. Background Runtimes, Helpers, Monitors & Containers
	if strings.HasSuffix(n, "helper") || strings.HasSuffix(n, "monitor") ||
		strings.HasSuffix(n, "background") || strings.HasSuffix(n, "container") ||
		strings.HasSuffix(n, "daemon") || strings.HasSuffix(n, "webview2") {
		return true
	}

	// 7. Documentation, Manuals, Help, Licenses, Release Notes
	if strings.Contains(n, "documentation") || strings.Contains(n, "manual") ||
		strings.Contains(n, "readme") || strings.Contains(n, "release notes") ||
		strings.Contains(n, "license") || strings.Contains(n, "faq") ||
		strings.Contains(n, "getting started") || strings.Contains(n, "quick start") ||
		strings.Contains(n, "changelog") || strings.Contains(n, "user guide") ||
		n == "help" || strings.HasPrefix(n, "help ") || strings.HasSuffix(n, " help") || strings.Contains(n, " help ") {
		return true
	}

	// 8. Web Shortcuts & URL link stubs (e.g. Amazon.com, *.url)
	if strings.HasSuffix(n, ".com") || strings.HasSuffix(n, ".org") ||
		strings.HasSuffix(n, ".net") || strings.HasSuffix(n, ".io") ||
		strings.HasSuffix(n, ".url") || strings.HasPrefix(n, "http://") ||
		strings.HasPrefix(n, "https://") || strings.HasPrefix(n, "www.") {
		return true
	}

	return false
}

// IsWebStub checks if a path points to a browser web proxy stub or web app container.
func IsWebStub(path string) bool {
	if path == "" {
		return false
	}
	p := strings.ToLower(filepath.ToSlash(path))
	if strings.HasSuffix(p, "chrome_proxy.exe") ||
		strings.HasSuffix(p, "msedge_proxy.exe") ||
		strings.Contains(p, "chrome apps") ||
		strings.Contains(p, "edge apps") {
		return true
	}
	return false
}

// IsExecutableTarget verifies that the path does not have a known non-executable script or document extension.
func IsExecutableTarget(path string) bool {
	if path == "" {
		return false
	}
	clean := filepath.Clean(path)
	ext := strings.ToLower(filepath.Ext(clean))
	switch ext {
	case ".cmd", ".bat", ".ps1", ".sh", ".vbs", ".url", ".lnk",
		".txt", ".md", ".json", ".xml", ".html", ".htm", ".chm",
		".ico", ".dll", ".sys", ".inf", ".cat", ".cpl":
		return false
	}
	return true
}
