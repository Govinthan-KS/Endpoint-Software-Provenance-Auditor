package main

import (
	"bufio"
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/example/appaudit/internal/application"
	"github.com/example/appaudit/internal/provenance"
	"github.com/example/appaudit/internal/report"
)

func TestPromptCompanyAppRegistration_Interactive(t *testing.T) {
	tempDir := t.TempDir()

	// Override APPDATA for test isolation
	origAppData := os.Getenv("APPDATA")
	defer os.Setenv("APPDATA", origAppData)
	os.Setenv("APPDATA", tempDir)

	dummyExe := filepath.Join(tempDir, "InHouseAccounting.exe")
	if err := os.WriteFile(dummyExe, []byte("in-house-proprietary-binary-data-7788"), 0755); err != nil {
		t.Fatalf("failed to create dummy binary: %v", err)
	}

	fp, err := provenance.ComputeFingerprint(dummyExe)
	if err != nil {
		t.Fatalf("failed to compute fingerprint: %v", err)
	}

	apps := []application.Application{
		{
			Name:              "InHouseAccounting",
			PrimaryBinaryPath: dummyExe,
			Classification:    provenance.ClassificationUnknown,
			Confidence:        provenance.ConfidenceLow,
			Binaries: []application.ApplicationBinary{
				{
					Name:   "InHouseAccounting.exe",
					Path:   dummyExe,
					SHA256: fp.SHA256,
				},
			},
		},
	}

	// Simulate user responding "y" to the prompt, and then "1" to select the first app
	simulatedInput := "y\n1\n"
	reader := bufio.NewReader(strings.NewReader(simulatedInput))

	promptCompanyAppRegistration(reader, apps, nil, report.Telemetry{})

	// Verify that in-memory app was immediately updated to COMPANY
	if apps[0].Classification != provenance.ClassificationCompany {
		t.Errorf("expected app to be updated to COMPANY, got: %s", apps[0].Classification)
	}
	if apps[0].Confidence != provenance.ConfidenceVeryHigh {
		t.Errorf("expected VERY_HIGH confidence, got: %s", apps[0].Confidence)
	}
	if apps[0].ResolutionSource != "deterministic (Company Registry)" {
		t.Errorf("expected resolution source 'deterministic (Company Registry)', got: %s", apps[0].ResolutionSource)
	}

	// Verify that it is persisted in the Company Manifest
	manifest, err := application.LoadCompanyManifest()
	if err != nil {
		t.Fatalf("failed to load company manifest: %v", err)
	}

	entry, ok := manifest.FindMatch(fp.SHA256, dummyExe, "InHouseAccounting")
	if !ok {
		t.Fatalf("expected app to be registered in manifest, but not found")
	}
	if entry.Name != "InHouseAccounting" {
		t.Errorf("expected entry name 'InHouseAccounting', got '%s'", entry.Name)
	}
}

func TestPromptCompanyAppRegistration_RegisterAll(t *testing.T) {
	tempDir := t.TempDir()

	origAppData := os.Getenv("APPDATA")
	defer os.Setenv("APPDATA", origAppData)
	os.Setenv("APPDATA", tempDir)

	exe1 := filepath.Join(tempDir, "ToolOne.exe")
	exe2 := filepath.Join(tempDir, "ToolTwo.exe")
	_ = os.WriteFile(exe1, []byte("binary-one"), 0755)
	_ = os.WriteFile(exe2, []byte("binary-two"), 0755)

	apps := []application.Application{
		{Name: "ToolOne", PrimaryBinaryPath: exe1, Classification: provenance.ClassificationUnknown},
		{Name: "ToolTwo", PrimaryBinaryPath: exe2, Classification: provenance.ClassificationUnknown},
	}

	// Simulate user typing "yes" and then "all"
	simulatedInput := "yes\nall\n"
	reader := bufio.NewReader(strings.NewReader(simulatedInput))

	promptCompanyAppRegistration(reader, apps, nil, report.Telemetry{})

	if apps[0].Classification != provenance.ClassificationCompany || apps[1].Classification != provenance.ClassificationCompany {
		t.Errorf("expected both apps to be COMPANY, got %s and %s", apps[0].Classification, apps[1].Classification)
	}

	manifest, err := application.LoadCompanyManifest()
	if err != nil {
		t.Fatalf("failed to load manifest: %v", err)
	}
	if len(manifest.Entries) != 2 {
		t.Errorf("expected 2 entries in manifest, got %d", len(manifest.Entries))
	}
}

func TestPromptCompanyAppRegistration_ZeroUnknowns_PathInput(t *testing.T) {
	tempDir := t.TempDir()

	origAppData := os.Getenv("APPDATA")
	defer os.Setenv("APPDATA", origAppData)
	os.Setenv("APPDATA", tempDir)

	exePath := filepath.Join(tempDir, "InternalBillingDaemon.exe")
	_ = os.WriteFile(exePath, []byte("internal-billing-binary-bytes"), 0755)

	// All applications are already resolved (0 unknown apps)
	apps := []application.Application{
		{
			Name:              "InternalBillingDaemon",
			PrimaryBinaryPath: exePath,
			Classification:    provenance.ClassificationThirdParty,
		},
	}

	// Simulate user typing "y" and then providing the path
	simulatedInput := "y\n" + exePath + "\n"
	reader := bufio.NewReader(strings.NewReader(simulatedInput))

	promptCompanyAppRegistration(reader, apps, nil, report.Telemetry{})

	// Check that the in-memory app was switched to COMPANY
	if apps[0].Classification != provenance.ClassificationCompany {
		t.Errorf("expected app to be updated to COMPANY, got %s", apps[0].Classification)
	}

	manifest, err := application.LoadCompanyManifest()
	if err != nil {
		t.Fatalf("failed to load manifest: %v", err)
	}
	if len(manifest.Entries) != 1 {
		t.Errorf("expected 1 entry in manifest, got %d", len(manifest.Entries))
	}
}

func TestCheckLocalPreflight_Success(t *testing.T) {
	ollamaServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/api/tags") {
			_, _ = w.Write([]byte(`{"models":[{"name":"audit-phi:q6k","model":"audit-phi:q6k"}]}`))
			return
		}
		if strings.HasSuffix(r.URL.Path, "/api/ps") {
			_, _ = w.Write([]byte(`{"models":[{"name":"audit-phi:q6k","size":3751364525,"size_vram":3751364525}]}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer ollamaServer.Close()

	searxngServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/search") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"results":[{"title":"Test","content":"Test content","url":"https://test.org"}]}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer searxngServer.Close()

	var buf bytes.Buffer
	ok, guidance := checkLocalPreflight(&buf, ollamaServer.URL, searxngServer.URL, "audit-phi:q6k")
	if !ok {
		t.Fatalf("expected preflight to pass, got false with guidance: %s", guidance)
	}
	if !strings.Contains(buf.String(), "All pre-flight checks passed") {
		t.Errorf("expected success output, got: %s", buf.String())
	}
}

func TestCheckLocalPreflight_OllamaDown(t *testing.T) {
	var buf bytes.Buffer
	ok, guidance := checkLocalPreflight(&buf, "http://127.0.0.1:54321", "http://127.0.0.1:54322", "audit-phi:q6k")
	if ok {
		t.Fatalf("expected preflight to fail when Ollama is offline")
	}
	if !strings.Contains(guidance, "ollama serve") {
		t.Errorf("expected guidance to contain 'ollama serve', got: %s", guidance)
	}
}

func TestCheckLocalPreflight_ModelMissing(t *testing.T) {
	ollamaServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/api/tags") {
			_, _ = w.Write([]byte(`{"models":[{"name":"some-other-model:latest"}]}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer ollamaServer.Close()

	var buf bytes.Buffer
	ok, guidance := checkLocalPreflight(&buf, ollamaServer.URL, "http://127.0.0.1:54322", "audit-phi:q6k")
	if ok {
		t.Fatalf("expected preflight to fail when model is missing")
	}
	if !strings.Contains(guidance, "ollama create audit-phi:q6k") {
		t.Errorf("expected guidance to mention 'ollama create audit-phi:q6k', got: %s", guidance)
	}
}

func TestCheckLocalPreflight_CPUOffload(t *testing.T) {
	ollamaServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/api/tags") {
			_, _ = w.Write([]byte(`{"models":[{"name":"audit-phi:q6k"}]}`))
			return
		}
		if strings.HasSuffix(r.URL.Path, "/api/ps") {
			// size_vram < size indicates CPU offload
			_, _ = w.Write([]byte(`{"models":[{"name":"audit-phi:q6k","size":3751364525,"size_vram":2000000000}]}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer ollamaServer.Close()

	var buf bytes.Buffer
	ok, guidance := checkLocalPreflight(&buf, ollamaServer.URL, "http://127.0.0.1:54322", "audit-phi:q6k")
	if ok {
		t.Fatalf("expected preflight to fail on CPU offload")
	}
	if !strings.Contains(guidance, "HARD REFUSAL") {
		t.Errorf("expected guidance to contain 'HARD REFUSAL', got: %s", guidance)
	}
}

func TestCheckLocalPreflight_SearXNGForbidden(t *testing.T) {
	ollamaServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/api/tags") {
			_, _ = w.Write([]byte(`{"models":[{"name":"audit-phi:q6k"}]}`))
			return
		}
		if strings.HasSuffix(r.URL.Path, "/api/ps") {
			_, _ = w.Write([]byte(`{"models":[{"name":"audit-phi:q6k","size":3751364525,"size_vram":3751364525}]}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer ollamaServer.Close()

	searxngServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Forbidden", http.StatusForbidden)
	}))
	defer searxngServer.Close()

	var buf bytes.Buffer
	ok, guidance := checkLocalPreflight(&buf, ollamaServer.URL, searxngServer.URL, "audit-phi:q6k")
	if ok {
		t.Fatalf("expected preflight to fail on SearXNG 403 Forbidden")
	}
	if !strings.Contains(guidance, "HTTP 403 Forbidden") {
		t.Errorf("expected guidance to mention 'HTTP 403 Forbidden', got: %s", guidance)
	}
}

