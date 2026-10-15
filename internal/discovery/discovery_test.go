package discovery

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestDirectoryPruning(t *testing.T) {
	tempDir := t.TempDir()

	// Directory layout:
	//   bin/valid.exe                  (MUST be collected)
	//   custom/tool.exe                (MUST be collected)
	//   node_modules/dummy.exe         (MUST be pruned)
	//   .git/git_dummy.exe             (MUST be pruned)
	//   venv/venv_dummy.exe            (MUST be pruned)
	//   target/rust_dummy.exe          (MUST be pruned)
	//   dist/dist_dummy.exe            (MUST be pruned)
	//   __pycache__/py_dummy.exe       (MUST be pruned)
	//   Temp/temp_dummy.exe            (MUST be pruned)
	//   Cache/cache_dummy.exe          (MUST be pruned)
	//   Logs/log_dummy.exe             (MUST be pruned)
	//   Installer/installer_dummy.exe  (MUST be pruned)

	validFiles := []string{
		filepath.Join(tempDir, "bin", "valid.exe"),
		filepath.Join(tempDir, "custom", "tool.exe"),
	}

	prunedFiles := []string{
		filepath.Join(tempDir, "node_modules", "dummy.exe"),
		filepath.Join(tempDir, ".git", "git_dummy.exe"),
		filepath.Join(tempDir, "venv", "venv_dummy.exe"),
		filepath.Join(tempDir, "target", "rust_dummy.exe"),
		filepath.Join(tempDir, "dist", "dist_dummy.exe"),
		filepath.Join(tempDir, "__pycache__", "py_dummy.exe"),
		filepath.Join(tempDir, "Temp", "temp_dummy.exe"),
		filepath.Join(tempDir, "Cache", "cache_dummy.exe"),
		filepath.Join(tempDir, "Logs", "log_dummy.exe"),
		filepath.Join(tempDir, "Installer", "installer_dummy.exe"),
	}

	for _, p := range append(validFiles, prunedFiles...) {
		dir := filepath.Dir(p)
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatalf("failed to create directory %s: %v", dir, err)
		}
		if err := os.WriteFile(p, []byte("fake-binary-content"), 0755); err != nil {
			t.Fatalf("failed to create file %s: %v", p, err)
		}
	}

	res, err := ScanTargeted([]string{tempDir}, nil)
	if err != nil {
		t.Fatalf("ScanTargeted failed: %v", err)
	}

	if res.DirsPruned == 0 {
		t.Errorf("Expected DirsPruned > 0, got %d", res.DirsPruned)
	}

	foundMap := make(map[string]bool)
	for _, p := range res.Executables {
		foundMap[strings.ToLower(filepath.Clean(p))] = true
	}

	// Verify valid files are discovered
	for _, vf := range validFiles {
		clean := strings.ToLower(filepath.Clean(vf))
		if !foundMap[clean] {
			t.Errorf("Expected valid executable to be collected: %s", vf)
		}
	}

	// Verify pruned files are NOT discovered
	for _, pf := range prunedFiles {
		clean := strings.ToLower(filepath.Clean(pf))
		if foundMap[clean] {
			t.Errorf("Pruned executable should NOT have been collected: %s", pf)
		}
	}

	if len(res.Executables) != len(validFiles) {
		t.Errorf("Expected exactly %d executables collected, got %d: %v", len(validFiles), len(res.Executables), res.Executables)
	}
}

func TestPathFiltering(t *testing.T) {
	if runtime.GOOS == "windows" {
		systemPaths := []string{
			`C:\Windows\System32`,
			`C:\Windows\SysWOW64`,
			`C:\Windows`,
			`C:\Windows\System32\drivers`,
			`c:\windows\system32\openssh`,
		}
		for _, sp := range systemPaths {
			if !IsSystemRootPath(sp) {
				t.Errorf("Expected IsSystemRootPath(%s) = true, got false", sp)
			}
		}

		userAppPaths := []string{
			`C:\Program Files\Git\bin`,
			`C:\Program Files\Docker\bin`,
			`C:\Users\govin\.cargo\bin`,
			`C:\Users\govin\go\bin`,
			`C:\Python314\Scripts`,
			`C:\tools\bin`,
		}
		for _, up := range userAppPaths {
			if IsSystemRootPath(up) {
				t.Errorf("Expected IsSystemRootPath(%s) = false, got true", up)
			}
		}
	} else {
		unixSysPaths := []string{"/proc", "/sys", "/dev"}
		for _, sp := range unixSysPaths {
			if !IsSystemRootPath(sp) {
				t.Errorf("Expected IsSystemRootPath(%s) = true, got false", sp)
			}
		}
	}
}

func TestRootCollection(t *testing.T) {
	roots := CollectTargetedRoots()
	if len(roots) == 0 {
		t.Fatalf("Expected non-empty targeted roots, got 0")
	}

	seen := make(map[string]bool)
	for _, r := range roots {
		clean := strings.ToLower(filepath.Clean(r))
		if seen[clean] {
			t.Errorf("Duplicate root found: %s", r)
		}
		seen[clean] = true

		if IsSystemRootPath(r) {
			t.Errorf("SystemRoot path leaked into targeted roots: %s", r)
		}
	}
}
