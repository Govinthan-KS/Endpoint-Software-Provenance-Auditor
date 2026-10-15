package application

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/example/appaudit/internal/provenance"
)

type mockCountingInspector struct {
	mu        sync.Mutex
	callCount int
	metadata  provenance.BinaryMetadata
}

func (m *mockCountingInspector) Inspect(filePath string) (provenance.BinaryMetadata, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.callCount++
	return m.metadata, nil
}

func (m *mockCountingInspector) getCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.callCount
}

// TestCache_RepeatedAnalysisReusesForensicEvidence verifies that analyzing the same binary
// multiple times reuses the cached forensic inspection and avoids repeated expensive inspection.
func TestCache_RepeatedAnalysisReusesForensicEvidence(t *testing.T) {
	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "sample_tool.exe")
	if err := os.WriteFile(binPath, []byte("MZ-sample-executable-binary-content-12345"), 0755); err != nil {
		t.Fatalf("failed to write test binary: %v", err)
	}

	cacheFile := filepath.Join(tmpDir, "cache.json")
	cache := provenance.NewProvenanceCache(cacheFile)

	inspector := &mockCountingInspector{
		metadata: provenance.BinaryMetadata{
			IsExecutable:    true,
			Architecture:    "x64",
			FileDescription: "Cached Mock Tool",
		},
	}

	engine := NewEngine(EngineConfig{
		NetworkMode: provenance.NetworkOff,
		Inspector:   inspector,
		Cache:       cache,
	})

	ctx := context.Background()

	// 1. First analysis - should invoke inspector
	apps1, err := engine.AnalyzePaths(ctx, []string{binPath})
	if err != nil {
		t.Fatalf("First analysis failed: %v", err)
	}
	if len(apps1) != 1 {
		t.Fatalf("Expected 1 app, got %d", len(apps1))
	}
	if inspector.getCount() != 1 {
		t.Fatalf("Expected inspector to be called once, got %d", inspector.getCount())
	}
	if apps1[0].Binaries[0].Inspection.Architecture != "x64" {
		t.Fatalf("Expected Architecture x64, got %s", apps1[0].Binaries[0].Inspection.Architecture)
	}

	// 2. Second analysis of same binary - must reuse cache without re-inspecting
	apps2, err := engine.AnalyzePaths(ctx, []string{binPath})
	if err != nil {
		t.Fatalf("Second analysis failed: %v", err)
	}
	if len(apps2) != 1 {
		t.Fatalf("Expected 1 app, got %d", len(apps2))
	}
	if inspector.getCount() != 1 {
		t.Fatalf("Expected inspector call count to remain 1 (cached), but was %d", inspector.getCount())
	}
	if apps2[0].Binaries[0].Inspection.Architecture != "x64" {
		t.Fatalf("Expected cached Architecture x64, got %s", apps2[0].Binaries[0].Inspection.Architecture)
	}
}

// TestCache_MultiBinarySuiteClassificationDoesNotAttachToIsolatedBinary verifies that
// when a binary is part of a multi-binary suite in one context, its suite-level classification
// is NOT permanently attached to the binary hash when analyzed subsequently in isolation.
func TestCache_MultiBinarySuiteClassificationDoesNotAttachToIsolatedBinary(t *testing.T) {
	tmpDir := t.TempDir()
	suiteDir := filepath.Join(tmpDir, "suite_dir")
	isoDir := filepath.Join(tmpDir, "isolated_dir")
	_ = os.MkdirAll(suiteDir, 0755)
	_ = os.MkdirAll(isoDir, 0755)

	ffmpegContent := []byte("MZ-ffmpeg-simulated-binary-bytes")
	ffprobeContent := []byte("MZ-ffprobe-simulated-binary-bytes")

	suiteFfmpeg := filepath.Join(suiteDir, "ffmpeg.exe")
	suiteFfprobe := filepath.Join(suiteDir, "ffprobe.exe")
	_ = os.WriteFile(suiteFfmpeg, ffmpegContent, 0755)
	_ = os.WriteFile(suiteFfprobe, ffprobeContent, 0755)

	isoFfmpeg := filepath.Join(isoDir, "ffmpeg.exe")
	_ = os.WriteFile(isoFfmpeg, ffmpegContent, 0755)

	cacheFile := filepath.Join(tmpDir, "cache.json")
	cache := provenance.NewProvenanceCache(cacheFile)

	inspector := &mockCountingInspector{
		metadata: provenance.BinaryMetadata{IsExecutable: true},
	}

	engine := NewEngine(EngineConfig{
		NetworkMode:     provenance.NetworkOff,
		KnownPublishers: []string{"externalvendor"},
		Inspector:       inspector,
		Cache:           cache,
	})

	ctx := context.Background()

	// 1. Analyze the multi-binary registered suite containing both binaries.
	// As a registered suite with a known external publisher, it classifies as THIRD_PARTY.
	rawSuite := []RawInput{
		{Name: "Suite App", Path: suiteFfmpeg, Origin: "Registry", Publisher: "ExternalVendor", Version: "1.0"},
		{Name: "Suite Tool", Path: suiteFfprobe, Origin: "Registry", Publisher: "ExternalVendor", Version: "1.0"},
	}
	appsSuite := engine.ProcessRaw(ctx, rawSuite)
	if len(appsSuite) != 1 {
		t.Fatalf("Expected 1 reconciled suite app, got %d", len(appsSuite))
	}
	if appsSuite[0].Classification != provenance.ClassificationThirdParty {
		t.Fatalf("Expected suite to be THIRD_PARTY, got %s", appsSuite[0].Classification)
	}
	if len(appsSuite[0].Binaries) != 2 {
		t.Fatalf("Expected 2 binaries in suite, got %d", len(appsSuite[0].Binaries))
	}

	// 2. Now analyze ONLY the isolated primary binary from isoDir (no suite, no registry manifest)
	appsIso, err := engine.AnalyzePaths(ctx, []string{isoFfmpeg})
	if err != nil {
		t.Fatalf("Isolated analysis failed: %v", err)
	}
	if len(appsIso) != 1 {
		t.Fatalf("Expected 1 app, got %d", len(appsIso))
	}
	isoApp := appsIso[0]

	// In isolation, the binary has no sibling, no publisher signature, and no package manager.
	// It must NOT inherit the multi-binary suite classification!
	if len(isoApp.Binaries) != 1 {
		t.Fatalf("Expected 1 binary in isolated app, got %d", len(isoApp.Binaries))
	}
	if isoApp.Classification == provenance.ClassificationThirdParty {
		t.Fatalf("Isolated binary must NOT inherit suite THIRD_PARTY classification without evidence, got %s (reasons: %v)",
			isoApp.Classification, isoApp.Reasons)
	}
	if isoApp.Classification != provenance.ClassificationUnknown {
		t.Fatalf("Expected UNKNOWN for isolated binary lacking external corroboration, got %s", isoApp.Classification)
	}
}

// TestCache_ChangingApplicationContextDoesNotLeakStaleSuiteEvidence verifies that
// forensic binary metadata is reused across contexts without leaking stale manifest
// or suite-level evidence into the new application context.
func TestCache_ChangingApplicationContextDoesNotLeakStaleSuiteEvidence(t *testing.T) {
	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "custom_runner.exe")
	if err := os.WriteFile(binPath, []byte("MZ-custom-runner-payload-data-999"), 0755); err != nil {
		t.Fatalf("failed to write binary: %v", err)
	}

	cacheFile := filepath.Join(tmpDir, "cache.json")
	cache := provenance.NewProvenanceCache(cacheFile)

	inspector := &mockCountingInspector{
		metadata: provenance.BinaryMetadata{
			IsExecutable:    true,
			Architecture:    "x64",
			FileDescription: "Custom Runner Binary",
		},
	}

	engine := NewEngine(EngineConfig{
		NetworkMode:     provenance.NetworkOff,
		KnownPublishers: []string{"externalcorp"},
		Inspector:       inspector,
		Cache:           cache,
	})

	ctx := context.Background()

	// Context 1: Manifest-discovered registered app with external vendor publisher
	rawContext1 := []RawInput{
		{
			Name:      "External Corp Runner",
			Path:      binPath,
			Publisher: "ExternalCorp International",
			Origin:    "Registry",
			Version:   "1.0.0",
		},
	}

	apps1 := engine.ProcessRaw(ctx, rawContext1)
	if len(apps1) != 1 {
		t.Fatalf("Expected 1 app in Context 1, got %d", len(apps1))
	}
	if apps1[0].Classification != provenance.ClassificationThirdParty {
		t.Fatalf("Expected Context 1 to be THIRD_PARTY, got %s", apps1[0].Classification)
	}
	if apps1[0].Origin != "Registry" {
		t.Fatalf("Expected Context 1 origin Registry, got %s", apps1[0].Origin)
	}

	// Context 2: Same binary hash analyzed as standalone CLI input without any registry manifest
	rawContext2 := []RawInput{
		{
			Name:   "custom_runner",
			Path:   binPath,
			Origin: "CLI",
		},
	}

	apps2 := engine.ProcessRaw(ctx, rawContext2)
	if len(apps2) != 1 {
		t.Fatalf("Expected 1 app in Context 2, got %d", len(apps2))
	}
	app2 := apps2[0]

	// Forensic data should be preserved
	if app2.Binaries[0].Inspection.FileDescription != "Custom Runner Binary" {
		t.Fatalf("Expected forensic inspection reused, got %s", app2.Binaries[0].Inspection.FileDescription)
	}

	// But Context 1's manifest origin and publisher must NOT leak into Context 2!
	if app2.Origin == "Registry" {
		t.Fatalf("Context 1 Origin 'Registry' leaked into Context 2!")
	}
	if app2.Publisher == "ExternalCorp International" {
		t.Fatalf("Context 1 Publisher leaked into Context 2!")
	}
	if app2.Classification != provenance.ClassificationUnknown {
		t.Fatalf("Standalone binary without manifest or signatures must evaluate to UNKNOWN, got %s", app2.Classification)
	}
}
