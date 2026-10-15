package application

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/example/appaudit/internal/provenance"
)

func TestCompanyManifest_RegisterAndMatch(t *testing.T) {
	tempDir := t.TempDir()
	manifestPath := filepath.Join(tempDir, "company_manifest.json")

	dummyExe := filepath.Join(tempDir, "InternalPayrollTool.exe")
	if err := os.WriteFile(dummyExe, []byte("dummy-internal-binary-bytes-12345"), 0755); err != nil {
		t.Fatalf("failed to write dummy exe: %v", err)
	}

	manifest := &CompanyManifest{
		filePath: manifestPath,
		Entries:  make(map[string]CompanyAppEntry),
	}

	entry, err := manifest.RegisterApp(dummyExe, "InternalPayrollTool")
	if err != nil {
		t.Fatalf("RegisterApp failed: %v", err)
	}

	if entry.Name != "InternalPayrollTool" {
		t.Errorf("expected name InternalPayrollTool, got %s", entry.Name)
	}
	if entry.SHA256 == "" {
		t.Errorf("expected non-empty SHA256")
	}

	// Test Match by SHA-256
	matched, ok := manifest.FindMatch(entry.SHA256, "", "")
	if !ok || matched.Name != "InternalPayrollTool" {
		t.Errorf("expected match by SHA-256, got ok=%v", ok)
	}

	// Test Match by Path
	matchedByPath, ok := manifest.FindMatch("", dummyExe, "")
	if !ok || matchedByPath.Name != "InternalPayrollTool" {
		t.Errorf("expected match by Path, got ok=%v", ok)
	}

	// Test Decision Engine resolution
	de := NewDecisionEngine(nil, nil, nil)
	de.CompanyManifest = manifest

	app := &Application{
		Name:             "InternalPayrollTool",
		PrimaryBinaryPath: dummyExe,
		Binaries: []ApplicationBinary{
			{
				Name:   "InternalPayrollTool.exe",
				Path:   dummyExe,
				SHA256: entry.SHA256,
			},
		},
	}

	bundle := EvidenceBundle{
		AppName:       "InternalPayrollTool",
		PrimaryBinary: app.Binaries[0],
		Binaries:      app.Binaries,
	}

	de.Decide(context.Background(), app, bundle)

	if app.Classification != provenance.ClassificationCompany {
		t.Fatalf("expected COMPANY classification for registered app, got %s", app.Classification)
	}
	if app.ResolutionSource != "deterministic (Company Registry)" {
		t.Errorf("expected resolution source 'deterministic (Company Registry)', got %s", app.ResolutionSource)
	}
	if app.Confidence != provenance.ConfidenceVeryHigh {
		t.Errorf("expected VERY_HIGH confidence, got %s", app.Confidence)
	}

	// Test Removal
	removed, err := manifest.RemoveApp("InternalPayrollTool")
	if err != nil || !removed {
		t.Fatalf("expected successful removal: %v", err)
	}

	_, stillFound := manifest.FindMatch(entry.SHA256, dummyExe, "")
	if stillFound {
		t.Errorf("entry should not be found after removal")
	}
}
