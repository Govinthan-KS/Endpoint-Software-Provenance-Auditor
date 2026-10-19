package server

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/example/appaudit/internal/application"
	"github.com/example/appaudit/internal/provenance"
)

func TestHandleIndex(t *testing.T) {
	srv := NewServer(Config{Port: 8080})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d", rec.Code)
	}

	contentType := rec.Header().Get("Content-Type")
	if !strings.Contains(contentType, "text/html") {
		t.Errorf("expected text/html content type, got %s", contentType)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "AppAudit") {
		t.Errorf("expected HTML body to contain 'AppAudit'")
	}
	if !strings.Contains(body, "Deterministic Only") {
		t.Errorf("expected HTML body to contain 'Deterministic Only'")
	}
	if !strings.Contains(body, "Ollama (Local AI)") {
		t.Errorf("expected HTML body to contain 'Ollama (Local AI)'")
	}
}

func TestHandleHealth(t *testing.T) {
	srv := NewServer(Config{Port: 8080})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d", rec.Code)
	}

	var data map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &data); err != nil {
		t.Fatalf("failed to decode JSON response: %v", err)
	}

	if data["status"] != "ok" {
		t.Errorf("expected status 'ok', got %v", data["status"])
	}
	if data["timestamp"] == nil {
		t.Errorf("expected non-nil timestamp")
	}
}

func TestHandleAudit_MethodNotAllowed(t *testing.T) {
	srv := NewServer(Config{Port: 8080})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit", nil)
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected HTTP 405, got %d", rec.Code)
	}
}

func TestHandleAudit_MissingFile(t *testing.T) {
	srv := NewServer(Config{Port: 8080})

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	_ = writer.WriteField("mode", "none")
	_ = writer.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/audit", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected HTTP 400 for missing file, got %d", rec.Code)
	}
}

func TestHandleAudit_Success(t *testing.T) {
	srv := NewServer(Config{Port: 8080})

	tempExe, err := os.CreateTemp("", "test-binary-*.exe")
	if err != nil {
		t.Fatalf("failed to create temp exe: %v", err)
	}
	defer os.Remove(tempExe.Name())
	// Write standard MZ header so PE/inspector doesn't fail
	_, _ = tempExe.Write([]byte("MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"))
	_ = tempExe.Close()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	_ = writer.WriteField("mode", "none")

	part, err := writer.CreateFormFile("file", "mock-sample.exe")
	if err != nil {
		t.Fatalf("failed to create form file: %v", err)
	}

	content, _ := os.ReadFile(tempExe.Name())
	_, _ = part.Write(content)
	_ = writer.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/audit", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d (body: %s)", rec.Code, rec.Body.String())
	}

	var resp AuditResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal JSON response: %v", err)
	}

	if resp.Name != "mock-sample.exe" {
		t.Errorf("expected Name 'mock-sample.exe', got %q", resp.Name)
	}
	if resp.SHA256 == "" {
		t.Errorf("expected non-empty SHA256")
	}
	if resp.Classification == "" {
		t.Errorf("expected non-empty Classification")
	}
	if resp.TriageTier == "" {
		t.Errorf("expected non-empty TriageTier")
	}
	if resp.Evidence == "" {
		t.Errorf("expected non-empty Evidence")
	}
	if resp.ModelUsed != "none" {
		t.Errorf("expected ModelUsed 'none', got %q", resp.ModelUsed)
	}
}

func TestHandleAudit_RealBinaryIfAvailable(t *testing.T) {
	srv := NewServer(Config{Port: 8080})

	// Look for a binary in testdata or build directory
	candidates := []string{
		"../../bin/audit.exe",
		"../../audit.exe",
		"../../testdata/corpus/set1/unknown-executables/bat/bat.exe",
	}

	var targetPath string
	for _, c := range candidates {
		clean := filepath.Clean(c)
		if fi, err := os.Stat(clean); err == nil && !fi.IsDir() {
			targetPath = clean
			break
		}
	}

	if targetPath == "" {
		t.Skip("No real binary found for integration test; skipping")
	}

	content, err := os.ReadFile(targetPath)
	if err != nil {
		t.Fatalf("failed to read target %s: %v", targetPath, err)
	}

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	_ = writer.WriteField("mode", "none")

	part, err := writer.CreateFormFile("file", filepath.Base(targetPath))
	if err != nil {
		t.Fatalf("failed to create form file: %v", err)
	}
	_, _ = part.Write(content)
	_ = writer.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/audit", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d (body: %s)", rec.Code, rec.Body.String())
	}

	var resp AuditResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal JSON response: %v", err)
	}

	if resp.SHA256 == "" {
		t.Errorf("expected non-empty SHA256")
	}
	t.Logf("Audited %s: SHA256=%s Classification=%s Tier=%s Latency=%.1fms",
		resp.Name, resp.SHA256[:12]+"...", resp.Classification, resp.TriageTier, resp.LatencyMs)
}

func TestHandleAudit_PayloadTooLarge(t *testing.T) {
	srv := NewServer(Config{Port: 8080})

	pr, pw := io.Pipe()
	writer := multipart.NewWriter(pw)

	go func() {
		defer pw.Close()
		part, err := writer.CreateFormFile("file", "oversized.exe")
		if err != nil {
			return
		}
		// Write 501 MB of zero bytes
		chunk := make([]byte, 1024*1024)
		for i := 0; i < 501; i++ {
			if _, err := part.Write(chunk); err != nil {
				return
			}
		}
		_ = writer.Close()
	}()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/audit", pr)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected HTTP 413, got %d", rec.Code)
	}
}

func TestHandleClearCache(t *testing.T) {
	srv := NewServer(Config{Port: 8080})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/cache/clear", nil)
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d", rec.Code)
	}

	var data map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &data); err != nil {
		t.Fatalf("failed to decode JSON response: %v", err)
	}

	if data["status"] != "ok" {
		t.Errorf("expected status 'ok', got %v", data["status"])
	}
}

func TestHandleCacheStats(t *testing.T) {
	srv := NewServer(Config{Port: 8080})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/cache/stats", nil)
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d", rec.Code)
	}

	var data map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &data); err != nil {
		t.Fatalf("failed to decode JSON response: %v", err)
	}

	if _, ok := data["total"]; !ok {
		t.Errorf("expected 'total' key in stats response")
	}
}

func TestHandleAuditUpload(t *testing.T) {
	srv := NewServer(Config{Port: 8080})

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	_ = writer.WriteField("mode", "none")

	part, err := writer.CreateFormFile("file", "upload-test.exe")
	if err != nil {
		t.Fatalf("failed to create form file: %v", err)
	}
	_, _ = part.Write([]byte("MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"))
	_ = writer.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/audit/upload", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d (body: %s)", rec.Code, rec.Body.String())
	}

	var resp AuditResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal JSON response: %v", err)
	}

	if resp.Name != "upload-test.exe" {
		t.Errorf("expected Name 'upload-test.exe', got %q", resp.Name)
	}
	if resp.VerificationSource == "" {
		t.Errorf("expected non-empty VerificationSource")
	}
	if resp.Classification == "" {
		t.Errorf("expected non-empty Classification")
	}
	if resp.Confidence == "" {
		t.Errorf("expected non-empty Confidence")
	}
	if resp.Summary == "" {
		t.Errorf("expected non-empty Summary")
	}
	if resp.StageNumber < 1 || resp.StageNumber > 4 {
		t.Errorf("expected valid StageNumber (1-4), got %d", resp.StageNumber)
	}
	if resp.StageName == "" {
		t.Errorf("expected non-empty StageName")
	}
	if resp.TokenEconomics.FormattedCost == "" {
		t.Errorf("expected non-empty TokenEconomics.FormattedCost")
	}
}

func TestHandleAuditCompare(t *testing.T) {
	srv := NewServer(Config{Port: 8080})

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	_ = writer.WriteField("modes", `["none", "none"]`)

	part, err := writer.CreateFormFile("file", "compare-test.exe")
	if err != nil {
		t.Fatalf("failed to create form file: %v", err)
	}
	_, _ = part.Write([]byte("MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"))
	_ = writer.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/audit/compare", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d (body: %s)", rec.Code, rec.Body.String())
	}

	var resp CompareResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal JSON comparison response: %v", err)
	}

	if len(resp.Engines) != 2 {
		t.Fatalf("expected 2 engine results, got %d", len(resp.Engines))
	}
	if !resp.Agreement {
		t.Errorf("expected agreement to be true, got %v", resp.Agreement)
	}
	if resp.Takeaway == "" {
		t.Errorf("expected non-empty Takeaway")
	}
	if resp.Engines[0].StageNumber < 1 {
		t.Errorf("expected positive StageNumber on engine comparison")
	}
	if resp.Engines[0].TokenEconomics.FormattedCost == "" {
		t.Errorf("expected non-empty FormattedCost on engine comparison")
	}
}

func TestHandleAuditDirectory(t *testing.T) {
	srv := NewServer(Config{Port: 8080})

	tempDir, err := os.MkdirTemp("", "appaudit-test-dir-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	testExe := filepath.Join(tempDir, "testtool.exe")
	_ = os.WriteFile(testExe, []byte("MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"), 0755)

	payload := `{"path": ` + string(mustJSON(tempDir)) + `, "mode": "none"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/audit/directory", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d (body: %s)", rec.Code, rec.Body.String())
	}

	var resp MultiAppScanResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal JSON response: %v", err)
	}

	if resp.ScanType != "Custom Directory" {
		t.Errorf("expected scan_type 'Custom Directory', got %q", resp.ScanType)
	}
	if resp.TotalScanned < 1 {
		t.Errorf("expected at least 1 scanned app, got %d", resp.TotalScanned)
	}
	if resp.Economics.TotalTokensSaved < 0 {
		t.Errorf("expected non-negative tokens saved")
	}
	if len(resp.Applications) > 0 && resp.Applications[0].StageNumber < 1 {
		t.Errorf("expected positive StageNumber on scanned app")
	}

	// Test non-existent directory error
	badReq := httptest.NewRequest(http.MethodPost, "/api/v1/audit/directory", strings.NewReader(`{"path": "C:\\nonexistent-dir-12345", "mode": "none"}`))
	badReq.Header.Set("Content-Type", "application/json")
	badRec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(badRec, badReq)
	if badRec.Code != http.StatusBadRequest {
		t.Errorf("expected HTTP 400 for non-existent directory, got %d", badRec.Code)
	}
}

func TestHandleAuditQuick(t *testing.T) {
	srv := NewServer(Config{Port: 8080})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/audit/quick", strings.NewReader("mode=none"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d (body: %s)", rec.Code, rec.Body.String())
	}

	var resp MultiAppScanResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal JSON quick scan response: %v", err)
	}

	if resp.ScanType != "Quick Scan" {
		t.Errorf("expected scan_type 'Quick Scan', got %q", resp.ScanType)
	}
}

func TestJargonFormatters(t *testing.T) {
	// 1. Verification Source formatting tests
	testsSource := []struct {
		tier     string
		reasons  []string
		expected string
	}{
		{"Tier 1 Authenticode", []string{"Signed by Microsoft Corporation"}, "Verified Publisher Signature"},
		{"Tier 1 Buildinfo", []string{"Compiler build metadata confirms github.com/cli/cli"}, "Public Open-Source Build Metadata"},
		{"Tier 1.5A Strings / Receipts", []string{"Local Package Manifest Receipt found in package.json"}, "Local Package Manifest Receipt"},
		{"Tier 1.5B CIRCL Hash DB", []string{"Matched public release artifact in CIRCL Hashlookup"}, "Public Registry Hash Match (CIRCL)"},
		{"Company Registry", []string{"Found in internal corporate registry"}, "Registered Internal Enterprise Tool"},
		{"Tier 2 AI Reasoning", []string{"AI Provenance Inspection confirmed source"}, "AI Provenance Inspection"},
		{"Deterministic Static", []string{"Static hash checks completed"}, "Cryptographic Static Analysis"},
		{"Custom", []string{"No known signals"}, "Heuristic Analysis"},
	}

	for _, tt := range testsSource {
		got := FormatVerificationSource(tt.tier, tt.reasons)
		if got != tt.expected {
			t.Errorf("FormatVerificationSource(%q, %v) = %q, expected %q", tt.tier, tt.reasons, got, tt.expected)
		}
	}

	// 2. Classification formatting tests
	if got := FormatClassification(provenance.ClassificationThirdParty); got != "Verified Third-Party" {
		t.Errorf("FormatClassification(ThirdParty) = %q, expected 'Verified Third-Party'", got)
	}
	if got := FormatClassification("THIRD_PARTY"); got != "Verified Third-Party" {
		t.Errorf("FormatClassification('THIRD_PARTY') = %q, expected 'Verified Third-Party'", got)
	}
	if got := FormatClassification(provenance.ClassificationCompany); got != "In-House / Custom Tool" {
		t.Errorf("FormatClassification(Company) = %q, expected 'In-House / Custom Tool'", got)
	}
	if got := FormatClassification("IN_HOUSE"); got != "In-House / Custom Tool" {
		t.Errorf("FormatClassification('IN_HOUSE') = %q, expected 'In-House / Custom Tool'", got)
	}
	if got := FormatClassification("in_house"); got != "In-House / Custom Tool" {
		t.Errorf("FormatClassification('in_house') = %q, expected 'In-House / Custom Tool'", got)
	}
	if got := FormatClassification("COMPANY"); got != "In-House / Custom Tool" {
		t.Errorf("FormatClassification('COMPANY') = %q, expected 'In-House / Custom Tool'", got)
	}
	if got := FormatClassification(provenance.ClassificationUnknown); got != "Unverified / Unknown" {
		t.Errorf("FormatClassification(Unknown) = %q, expected 'Unverified / Unknown'", got)
	}

	// 3. Confidence formatting tests
	if got := FormatConfidence(provenance.ConfidenceVeryHigh); got != "High" {
		t.Errorf("FormatConfidence(VeryHigh) = %q, expected 'High'", got)
	}
	if got := FormatConfidence(provenance.ConfidenceHigh); got != "High" {
		t.Errorf("FormatConfidence(High) = %q, expected 'High'", got)
	}
	if got := FormatConfidence(provenance.ConfidenceMedium); got != "Medium" {
		t.Errorf("FormatConfidence(Medium) = %q, expected 'Medium'", got)
	}
	if got := FormatConfidence(provenance.ConfidenceLow); got != "Low" {
		t.Errorf("FormatConfidence(Low) = %q, expected 'Low'", got)
	}

	// 4. Summary of findings tests
	if got := FormatSummaryOfFindings(nil); got != "No software findings available." {
		t.Errorf("FormatSummaryOfFindings(nil) = %q", got)
	}

	appThirdParty := &application.Application{
		Classification: provenance.ClassificationThirdParty,
		Reasons:        []string{"Signed by Microsoft Corp code-signing authority."},
	}
	if got := FormatSummaryOfFindings(appThirdParty); !strings.Contains(got, "Cryptographically signed by a verified commercial software publisher") {
		t.Errorf("FormatSummaryOfFindings(appThirdParty) = %q", got)
	}

	appCompany := &application.Application{
		Classification: provenance.ClassificationCompany,
	}
	if got := FormatSummaryOfFindings(appCompany); !strings.Contains(got, "Identified as an internal company utility") {
		t.Errorf("FormatSummaryOfFindings(appCompany) = %q", got)
	}

	appUnknown := &application.Application{
		Classification: provenance.ClassificationUnknown,
	}
	if got := FormatSummaryOfFindings(appUnknown); !strings.Contains(got, "No cryptographically verifiable publisher signature") {
		t.Errorf("FormatSummaryOfFindings(appUnknown) = %q", got)
	}

	appExplicit := &application.Application{
		Classification: provenance.ClassificationThirdParty,
		EvidenceSummary: "Tier 1 Hard Evidence: Discovered public repository github.com/foo/bar for user C:\\Users\\jdoe\\app.exe",
	}
	gotExplicit := FormatSummaryOfFindings(appExplicit)
	if strings.Contains(gotExplicit, "Tier 1 Hard Evidence:") {
		t.Errorf("FormatSummaryOfFindings did not strip tier prefix: %s", gotExplicit)
	}
	if strings.Contains(gotExplicit, "jdoe") {
		t.Errorf("FormatSummaryOfFindings did not mask user path: %s", gotExplicit)
	}
}

func mustJSON(v interface{}) []byte {
	b, _ := json.Marshal(v)
	return b
}

func TestHandleAuditDirectory_MultiCompare(t *testing.T) {
	srv := NewServer(Config{Port: 8080})

	tempDir, err := os.MkdirTemp("", "appaudit-compare-dir-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	testExe := filepath.Join(tempDir, "testtool.exe")
	if err := os.WriteFile(testExe, []byte("MZdummycontenthereforcompare"), 0755); err != nil {
		t.Fatalf("failed to write test exe: %v", err)
	}

	reqBody := mustJSON(map[string]interface{}{
		"path":  tempDir,
		"modes": []string{"none", "ollama"},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/audit/directory", strings.NewReader(string(reqBody)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp MultiAppCompareResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal MultiAppCompareResponse: %v", err)
	}

	if resp.TotalScanned != 1 {
		t.Errorf("expected TotalScanned=1, got %d", resp.TotalScanned)
	}
	if len(resp.EngineSummaries) != 2 {
		t.Errorf("expected 2 engine summaries, got %d", len(resp.EngineSummaries))
	}
	if len(resp.Applications) != 1 {
		t.Errorf("expected 1 application in compare list, got %d", len(resp.Applications))
	}
	if resp.Applications[0].Name != "testtool" {
		t.Errorf("expected name 'testtool', got %q", resp.Applications[0].Name)
	}
	if resp.EfficiencyWinner == "" {
		t.Errorf("expected non-empty efficiency winner")
	}
	t.Logf("Directory Multi-Compare: Winner=%s Consensus=%.1f%% Duration=%.1fms",
		resp.EfficiencyWinner, resp.ConsensusRate, resp.DurationMs)
}

func TestCompanyEndpoints(t *testing.T) {
	tempDir := t.TempDir()
	dummyExe := filepath.Join(tempDir, "InternalFinApp.exe")
	if err := os.WriteFile(dummyExe, []byte("internal-fin-app-binary-content-987"), 0755); err != nil {
		t.Fatalf("failed to create dummy exe: %v", err)
	}

	srv := NewServer(Config{Port: 8080})

	// 1. Register via JSON path
	regPayload := map[string]string{
		"path":        dummyExe,
		"name":        "InternalFinApp",
		"description": "Internal Finance System",
	}
	body, _ := json.Marshal(regPayload)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/company/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 on register, got %d: %s", rec.Code, rec.Body.String())
	}

	var regResp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &regResp); err != nil {
		t.Fatalf("failed to parse register response: %v", err)
	}
	if regResp["status"] != "ok" {
		t.Errorf("expected status 'ok', got %v", regResp["status"])
	}

	// 2. List registered apps
	reqList := httptest.NewRequest(http.MethodGet, "/api/v1/company/apps", nil)
	recList := httptest.NewRecorder()
	srv.Handler().ServeHTTP(recList, reqList)

	if recList.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 on list, got %d", recList.Code)
	}

	var listResp struct {
		Status string                       `json:"status"`
		Count  int                          `json:"count"`
		Apps   []application.CompanyAppEntry `json:"apps"`
	}
	if err := json.Unmarshal(recList.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("failed to parse list response: %v", err)
	}
	found := false
	for _, a := range listResp.Apps {
		if a.Name == "InternalFinApp" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected 'InternalFinApp' in listed company apps, found %d apps", listResp.Count)
	}

	// 3. Remove registered app
	remPayload := map[string]string{
		"identifier": "InternalFinApp",
	}
	remBody, _ := json.Marshal(remPayload)
	reqRem := httptest.NewRequest(http.MethodPost, "/api/v1/company/remove", bytes.NewReader(remBody))
	reqRem.Header.Set("Content-Type", "application/json")
	recRem := httptest.NewRecorder()
	srv.Handler().ServeHTTP(recRem, reqRem)

	if recRem.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 on remove, got %d: %s", recRem.Code, recRem.Body.String())
	}
}

func TestOllamaFilterMultimodal(t *testing.T) {
	testCases := []struct {
		name     string
		families []string
		expected bool
	}{
		{"audit-phi:q6k", []string{"phi3"}, true},
		{"llama3:8b", []string{"llama"}, true},
		{"mistral:latest", []string{"llama"}, true},
		{"deepseek-r1:14b", []string{"qwen2"}, true},
		{"llava:latest", []string{"llama", "clip"}, false},
		{"bakllava:latest", []string{"clip"}, false},
		{"moondream:latest", []string{"clip"}, false},
		{"llama3.2-vision:11b", []string{"mllama"}, false},
		{"qwen-vl:latest", []string{"qwen"}, false},
		{"minicpm-v:latest", []string{"minicpm"}, false},
	}

	for _, tc := range testCases {
		res := isOllamaTextOnly(tc.name, tc.families)
		if res != tc.expected {
			t.Errorf("isOllamaTextOnly(%q, %v) = %v; expected %v", tc.name, tc.families, res, tc.expected)
		}
	}
}

func TestAIConfigEndpoints(t *testing.T) {
	srv := NewServer(Config{Port: 8080})

	// 1. GET /api/v1/config/ai
	reqGet := httptest.NewRequest(http.MethodGet, "/api/v1/config/ai", nil)
	recGet := httptest.NewRecorder()
	srv.Handler().ServeHTTP(recGet, reqGet)
	if recGet.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d", recGet.Code)
	}

	// 2. Set key session-only
	keyPayload := map[string]interface{}{
		"provider": "gemini",
		"key":      "AIzaTestMockKeyForVerification999",
		"cache":    false,
	}
	body, _ := json.Marshal(keyPayload)
	reqKey := httptest.NewRequest(http.MethodPost, "/api/v1/config/key", bytes.NewReader(body))
	reqKey.Header.Set("Content-Type", "application/json")
	recKey := httptest.NewRecorder()
	srv.Handler().ServeHTTP(recKey, reqKey)
	if recKey.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 on set key, got %d", recKey.Code)
	}

	// 3. Set active model
	modPayload := map[string]string{
		"provider": "gemini",
		"model":    "gemini-2.5-flash",
	}
	modBody, _ := json.Marshal(modPayload)
	reqMod := httptest.NewRequest(http.MethodPost, "/api/v1/config/model", bytes.NewReader(modBody))
	reqMod.Header.Set("Content-Type", "application/json")
	recMod := httptest.NewRecorder()
	srv.Handler().ServeHTTP(recMod, reqMod)
	if recMod.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 on set model, got %d", recMod.Code)
	}

	// 4. Set custom prompt
	promptPayload := map[string]string{
		"prompt": "Custom prompt testing for enterprise provenance audit",
	}
	promptBody, _ := json.Marshal(promptPayload)
	reqPrompt := httptest.NewRequest(http.MethodPost, "/api/v1/config/prompt", bytes.NewReader(promptBody))
	reqPrompt.Header.Set("Content-Type", "application/json")
	recPrompt := httptest.NewRecorder()
	srv.Handler().ServeHTTP(recPrompt, reqPrompt)
	if recPrompt.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 on set prompt, got %d", recPrompt.Code)
	}

	// 5. Reset prompt
	reqReset := httptest.NewRequest(http.MethodPost, "/api/v1/config/prompt/reset", nil)
	recReset := httptest.NewRecorder()
	srv.Handler().ServeHTTP(recReset, reqReset)
	if recReset.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 on reset prompt, got %d", recReset.Code)
	}

	// 6. Forget key
	forgetPayload := map[string]string{
		"provider": "gemini",
	}
	forgetBody, _ := json.Marshal(forgetPayload)
	reqForget := httptest.NewRequest(http.MethodPost, "/api/v1/config/forget", bytes.NewReader(forgetBody))
	reqForget.Header.Set("Content-Type", "application/json")
	recForget := httptest.NewRecorder()
	srv.Handler().ServeHTTP(recForget, reqForget)
	if recForget.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 on forget key, got %d", recForget.Code)
	}
}

func TestGeminiFilterTextOnly(t *testing.T) {
	tests := []struct {
		model    string
		expected bool
	}{
		// Valid text models
		{"gemini-2.5-flash", true},
		{"gemini-2.5-pro", true},
		{"gemini-2.5-flash-lite", true},
		{"gemini-1.5-flash", true},
		{"gemini-1.5-pro", true},
		{"gemini-3-flash-preview", true},
		{"gemini-3.1-pro-preview", true},
		{"gemini-3.1-flash-lite", true},
		{"gemini-flash-latest", true},
		{"gemini-pro-latest", true},
		{"gemma-4-26b-a4b-it", true},
		{"gemma-4-31b-it", true},

		// Multimodal Image models (must be excluded)
		{"gemini-2.5-flash-image", false},
		{"gemini-3-pro-image-preview", false},
		{"gemini-3-pro-image", false},
		{"imagen-3.0-generate-002", false},

		// Audio / TTS / Transcription models (must be excluded)
		{"gemini-2.5-flash-preview-tts", false},
		{"gemini-2.5-pro-preview-tts", false},
		{"gemini-3.1-flash-tts-preview", false},
		{"gemini-3.8-flash-tts", false},
		{"gemini-3.8-flash-lite-tts", false},
		{"gemini-3.5-transcribe", false},

		// Music / Lyria models (must be excluded)
		{"lyria-3-clip-preview", false},
		{"lyria-3-pro-preview", false},
		{"lyria-3.5", false},

		// Robotics / Computer use / Specialized (must be excluded)
		{"gemini-robotics-er-2-preview", false},
		{"gemini-2.5-computer-use-preview-10-2025", false},
		{"nano-banana-pro-preview", false},
		{"antigravity-preview-05-2026", false},
		{"text-embedding-004", false},
		{"aqa", false},

		// Customtools / Omni models (excluded from free-tier text catalog)
		{"gemini-3.1-pro-preview-customtools", false},
		{"gemini-omni-flash-preview", false},
	}

	for _, tc := range tests {
		actual := isGeminiTextOnly(tc.model)
		if actual != tc.expected {
			t.Errorf("isGeminiTextOnly(%q) = %v, expected %v", tc.model, actual, tc.expected)
		}
	}
}

func TestGeminiFreeTierFiltering(t *testing.T) {
	// 1. Model with requestsPerDay = 0 must be rejected
	mZeroRPD := map[string]interface{}{
		"name":           "models/gemini-2.5-flash",
		"requestsPerDay": float64(0),
	}
	if !hasZeroRequestsPerDay(mZeroRPD) {
		t.Errorf("expected hasZeroRequestsPerDay to return true for requestsPerDay=0")
	}
	if isGeminiModelAvailableFreeTier("gemini-2.5-flash", mZeroRPD) {
		t.Errorf("expected model with 0 RPD to be rejected for free tier")
	}

	// 2. Model with nested rateLimits.requests_per_day = 0
	mNestedZero := map[string]interface{}{
		"name": "models/gemini-2.5-flash",
		"rateLimits": map[string]interface{}{
			"requests_per_day": int64(0),
		},
	}
	if !hasZeroRequestsPerDay(mNestedZero) {
		t.Errorf("expected hasZeroRequestsPerDay to return true for nested zero requests_per_day")
	}

	// 3. Model with positive RPD must be accepted
	mValid := map[string]interface{}{
		"name":           "models/gemini-2.5-flash",
		"requestsPerDay": float64(1500),
	}
	if hasZeroRequestsPerDay(mValid) {
		t.Errorf("expected hasZeroRequestsPerDay to return false for requestsPerDay=1500")
	}
	if !isGeminiModelAvailableFreeTier("gemini-2.5-flash", mValid) {
		t.Errorf("expected valid model with 1500 RPD to be accepted")
	}

	// 4. Model with customtools in name must be rejected
	mCustomTools := map[string]interface{}{
		"name": "models/gemini-3.1-pro-preview-customtools",
	}
	if isGeminiModelAvailableFreeTier("gemini-3.1-pro-preview-customtools", mCustomTools) {
		t.Errorf("expected customtools model to be rejected")
	}
}


func TestDevToolsAndFaviconEndpoints(t *testing.T) {
	srv := NewServer(Config{Port: 8080})

	// 1. Chrome DevTools discovery endpoint
	req1 := httptest.NewRequest(http.MethodGet, "/.well-known/appspecific/com.chrome.devtools.json", nil)
	rec1 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 for chrome devtools endpoint, got %d", rec1.Code)
	}
	if rec1.Body.String() != "{}" {
		t.Errorf("expected '{}', got %q", rec1.Body.String())
	}

	// 2. Favicon endpoint
	req2 := httptest.NewRequest(http.MethodGet, "/favicon.ico", nil)
	rec2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusNoContent {
		t.Fatalf("expected HTTP 204 for favicon, got %d", rec2.Code)
	}
}




