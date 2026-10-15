package provenance

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestInspectorPkgMgr(t *testing.T) {
	tempDir := t.TempDir()

	// 1. Scoop test
	scoopAppDir := filepath.Join(tempDir, "scoop", "apps", "git-tool", "current")
	if err := os.MkdirAll(scoopAppDir, 0755); err != nil {
		t.Fatalf("failed to create scoop dir: %v", err)
	}
	scoopManifest := `{
		"version": "2.44.0",
		"description": "Fast, scalable, distributed revision control system",
		"homepage": "https://git-scm.com"
	}`
	if err := os.WriteFile(filepath.Join(scoopAppDir, "manifest.json"), []byte(scoopManifest), 0644); err != nil {
		t.Fatalf("failed to write scoop manifest: %v", err)
	}

	scoopBin := filepath.Join(scoopAppDir, "git-tool.exe")
	scoopReceipt := InspectScoopManifest(scoopBin)
	if scoopReceipt == nil {
		t.Fatalf("expected scoop receipt, got nil")
	}
	if scoopReceipt.PackageName != "git-tool" {
		t.Errorf("expected package name 'git-tool', got '%s'", scoopReceipt.PackageName)
	}
	if scoopReceipt.Version != "2.44.0" {
		t.Errorf("expected version '2.44.0', got '%s'", scoopReceipt.Version)
	}
	if scoopReceipt.Homepage != "https://git-scm.com" {
		t.Errorf("expected homepage 'https://git-scm.com', got '%s'", scoopReceipt.Homepage)
	}

	// Also verify InspectPackageManagerReceipts catches scoop
	pkgReceipt := InspectPackageManagerReceipts(scoopBin)
	if pkgReceipt == nil || pkgReceipt.Manager != "scoop" {
		t.Errorf("InspectPackageManagerReceipts failed for scoop, got: %+v", pkgReceipt)
	}

	// 2. Cargo test
	cargoFile := filepath.Join(tempDir, ".crates2.json")
	cargoJSON := `{
		"installs": {
			"ripgrep 14.1.0 (registry+https://github.com/rust-lang/crates.io-index)": {
				"bins": [
					"rg.exe"
				]
			}
		}
	}`
	if err := os.WriteFile(cargoFile, []byte(cargoJSON), 0644); err != nil {
		t.Fatalf("failed to write cargo crates2 file: %v", err)
	}

	cargoReceipt := InspectCargoCrates2("C:\\tools\\rg.exe", cargoFile)
	if cargoReceipt == nil {
		t.Fatalf("expected cargo receipt, got nil")
	}
	if cargoReceipt.PackageName != "ripgrep" {
		t.Errorf("expected package name 'ripgrep', got '%s'", cargoReceipt.PackageName)
	}
	if cargoReceipt.Version != "14.1.0" {
		t.Errorf("expected version '14.1.0', got '%s'", cargoReceipt.Version)
	}
	if cargoReceipt.Homepage != "https://github.com/rust-lang/crates.io-index" {
		t.Errorf("expected repo 'https://github.com/rust-lang/crates.io-index', got '%s'", cargoReceipt.Homepage)
	}

	// 3. Chocolatey test
	chocoDir := filepath.Join(tempDir, "chocolatey", "lib", "mytool")
	if err := os.MkdirAll(chocoDir, 0755); err != nil {
		t.Fatalf("failed to create choco dir: %v", err)
	}
	chocoNuspec := `<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2015/06/nuspec.xsd">
  <metadata>
    <id>mytool</id>
    <version>1.5.0</version>
    <authors>MyTeam</authors>
    <projectUrl>https://example.com/mytool</projectUrl>
    <description>My cool tool</description>
  </metadata>
</package>`
	if err := os.WriteFile(filepath.Join(chocoDir, "mytool.nuspec"), []byte(chocoNuspec), 0644); err != nil {
		t.Fatalf("failed to write choco nuspec: %v", err)
	}

	chocoBin := filepath.Join(chocoDir, "tools", "mytool.exe")
	chocoReceipt := InspectChocolateyNuspec(chocoBin)
	if chocoReceipt == nil {
		t.Fatalf("expected choco receipt, got nil")
	}
	if chocoReceipt.PackageName != "mytool" {
		t.Errorf("expected package name 'mytool', got '%s'", chocoReceipt.PackageName)
	}
	if chocoReceipt.Version != "1.5.0" {
		t.Errorf("expected version '1.5.0', got '%s'", chocoReceipt.Version)
	}
	if chocoReceipt.Homepage != "https://example.com/mytool" {
		t.Errorf("expected homepage 'https://example.com/mytool', got '%s'", chocoReceipt.Homepage)
	}
}

func TestInspectorPython(t *testing.T) {
	tempDir := t.TempDir()

	scriptsDir := filepath.Join(tempDir, "Scripts")
	sitePkgDir := filepath.Join(tempDir, "Lib", "site-packages")
	distInfoDir := filepath.Join(sitePkgDir, "cool_tool-2.3.4.dist-info")

	if err := os.MkdirAll(scriptsDir, 0755); err != nil {
		t.Fatalf("failed to create scripts dir: %v", err)
	}
	if err := os.MkdirAll(distInfoDir, 0755); err != nil {
		t.Fatalf("failed to create dist-info dir: %v", err)
	}

	dummyBin := filepath.Join(scriptsDir, "cool-tool.exe")
	if err := os.WriteFile(dummyBin, []byte("dummy exe"), 0644); err != nil {
		t.Fatalf("failed to write dummy exe: %v", err)
	}

	metadataContent := `Metadata-Version: 2.1
Name: cool-tool
Version: 2.3.4
Summary: Super cool Python CLI
Home-page: https://github.com/org/cool-tool
Author: Developer Team
Author-email: team@example.com
`
	if err := os.WriteFile(filepath.Join(distInfoDir, "METADATA"), []byte(metadataContent), 0644); err != nil {
		t.Fatalf("failed to write METADATA: %v", err)
	}

	entryPointsContent := `[console_scripts]
cool-tool = cool_tool.cli:main
`
	if err := os.WriteFile(filepath.Join(distInfoDir, "entry_points.txt"), []byte(entryPointsContent), 0644); err != nil {
		t.Fatalf("failed to write entry_points.txt: %v", err)
	}

	receipt := InspectPythonRuntime(dummyBin)
	if receipt == nil {
		t.Fatalf("expected Python runtime receipt, got nil")
	}
	if receipt.PackageName != "cool-tool" {
		t.Errorf("expected package name 'cool-tool', got '%s'", receipt.PackageName)
	}
	if receipt.Version != "2.3.4" {
		t.Errorf("expected version '2.3.4', got '%s'", receipt.Version)
	}
	if receipt.Author != "Developer Team" {
		t.Errorf("expected author 'Developer Team', got '%s'", receipt.Author)
	}
	if receipt.Homepage != "https://github.com/org/cool-tool" {
		t.Errorf("expected homepage 'https://github.com/org/cool-tool', got '%s'", receipt.Homepage)
	}
}

func TestHashLookup_Success(t *testing.T) {
	fakeHash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") != DefaultHashlookupUserAgent {
			t.Errorf("unexpected user agent: %s", r.Header.Get("User-Agent"))
		}
		if r.URL.Path != "/lookup/sha256/"+fakeHash {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, `{
			"FileName": "curl.exe",
			"source": "RDS_2024",
			"hashlookup:trust": 100,
			"ProductCode": {
				"ProductName": "curl",
				"ProductVersion": "8.5.0"
			}
		}`)
	}))
	defer server.Close()

	client := NewHashLookupClient(server.URL + "/lookup/sha256/")
	res, matched, err := client.LookupSHA256(context.Background(), fakeHash)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !matched || res == nil {
		t.Fatalf("expected match, got matched=%v, res=%+v", matched, res)
	}
	if res.ProductName != "curl" {
		t.Errorf("expected ProductName 'curl', got '%s'", res.ProductName)
	}
	if res.FileName != "curl.exe" {
		t.Errorf("expected FileName 'curl.exe', got '%s'", res.FileName)
	}
	if res.Source != "RDS_2024" {
		t.Errorf("expected Source 'RDS_2024', got '%s'", res.Source)
	}
}

func TestHashLookup_FallbackOnTimeout(t *testing.T) {
	fakeHash := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Hang until context is cancelled
		<-r.Context().Done()
	}))
	defer server.Close()

	client := NewHashLookupClient(server.URL + "/")
	client.HTTPClient.Timeout = 50 * time.Millisecond
	client.BackoffDelay = 10 * time.Millisecond

	ctx := context.Background()
	res, matched, err := client.LookupSHA256(ctx, fakeHash)
	// Timeout should return err or nil match without panicking
	if matched {
		t.Errorf("expected matched to be false on timeout, got true")
	}
	if res != nil {
		t.Errorf("expected res to be nil on timeout, got %+v", res)
	}
	if err == nil {
		t.Errorf("expected error on timeout, got nil")
	}
	if !client.IsDegraded() {
		t.Errorf("expected circuit breaker to be tripped after 2 failed attempts")
	}

	// Subsequent lookup should short-circuit immediately without error or hanging
	res2, matched2, err2 := client.LookupSHA256(ctx, fakeHash)
	if matched2 || res2 != nil || err2 != nil {
		t.Errorf("expected degraded circuit to return nil, false, nil; got: res=%v matched=%v err=%v", res2, matched2, err2)
	}
}
