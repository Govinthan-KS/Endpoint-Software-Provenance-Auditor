package provenance

import (
	"bytes"
	"debug/buildinfo"
	"io"
	"os"
	"strings"
)

// InspectBuildMetadata extracts embedded compiler and module metadata from an arbitrary binary.
// Uses debug/buildinfo.ReadFile for Go binaries, and checks for markers of other ecosystems.
func InspectBuildMetadata(filePath string) *BuildMetadata {
	if bi, err := buildinfo.ReadFile(filePath); err == nil && bi != nil {
		meta := &BuildMetadata{
			Ecosystem:   "go",
			GoVersion:   bi.GoVersion,
			MainModule:  bi.Main.Path,
			MainVersion: bi.Main.Version,
			MainSum:     bi.Main.Sum,
			Settings:    make(map[string]string),
		}

		for _, s := range bi.Settings {
			meta.Settings[s.Key] = s.Value
		}

		for _, dep := range bi.Deps {
			if dep != nil && dep.Path != "" {
				meta.Deps = append(meta.Deps, dep.Path)
			}
		}

		return meta
	}

	// Ecosystem heuristic inspection via binary headers/strings
	return inspectOtherEcosystems(filePath)
}

func inspectOtherEcosystems(filePath string) *BuildMetadata {
	f, err := os.Open(filePath)
	if err != nil {
		return nil
	}
	defer f.Close()

	// Read first 2MB to search for characteristic ecosystem signatures
	buf := make([]byte, 2*1024*1024)
	n, _ := io.ReadFull(f, buf)
	data := buf[:n]

	// 1. Rust detection
	if bytes.Contains(data, []byte("rustc/")) || bytes.Contains(data, []byte("CARGO_PKG_NAME")) || bytes.Contains(data, []byte(".cargo/registry")) {
		return &BuildMetadata{
			Ecosystem: "rust",
		}
	}

	// 2. .NET CLR detection
	if bytes.Contains(data, []byte("mscoree.dll")) || bytes.Contains(data, []byte("_CorExeMain")) || bytes.Contains(data, []byte("BSJB")) {
		return &BuildMetadata{
			Ecosystem: "dotnet",
		}
	}

	// 3. PyInstaller / Python embedded bundle
	if bytes.Contains(data, []byte("pyi-windows-msvcr")) || bytes.Contains(data, []byte("Py_Initialize")) || bytes.Contains(data, []byte("MEI")) {
		return &BuildMetadata{
			Ecosystem: "python_pyinstaller",
		}
	}

	// 4. Electron / Node
	if bytes.Contains(data, []byte("ELECTRON_RUN_AS_NODE")) || bytes.Contains(data, []byte("atom-shell")) || bytes.Contains(data, []byte("v8::internal")) {
		return &BuildMetadata{
			Ecosystem: "electron_node",
		}
	}

	return nil
}

// DetectEmbeddedComponents searches a binary's content for known third-party library signatures.
// These are recorded strictly as component-level evidence, not whole-app identity.
func DetectEmbeddedComponents(filePath string) []string {
	f, err := os.Open(filePath)
	if err != nil {
		return nil
	}
	defer f.Close()

	// Inspect first 4MB
	buf := make([]byte, 4*1024*1024)
	n, _ := io.ReadFull(f, buf)
	data := strings.ToLower(string(buf[:n]))

	var components []string
	seen := make(map[string]bool)

	checks := map[string][]string{
		"FFmpeg":     {"libavcodec", "ffmpeg developers", "libavformat", "libavutil"},
		"OpenSSL":    {"openssl 1.", "openssl 3.", "openssl library"},
		"SQLite":     {"sqlite format 3", "2023- sqlite.org", "2024- sqlite.org", "sqlite3_open"},
		"libcurl":    {"libcurl/", "curl developers"},
		"zlib":       {"deflate 1.2", "inflate 1.2", "deflate 1.3"},
		"Chromium":   {"chromium authors", "content_shell"},
		"DirectX":    {"direct3dcreate9", "d3d11create"},
		"Tree-sitter": {"tree-sitter"},
	}

	for comp, sigs := range checks {
		for _, sig := range sigs {
			if strings.Contains(data, sig) {
				if !seen[comp] {
					seen[comp] = true
					components = append(components, comp)
				}
				break
			}
		}
	}

	return components
}
