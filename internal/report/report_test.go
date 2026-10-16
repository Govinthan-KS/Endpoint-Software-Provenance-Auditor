package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/example/appaudit/internal/application"
	"github.com/example/appaudit/internal/provenance"
)

func TestJSONReporter(t *testing.T) {
	apps := []application.Application{
		{
			ID:             "app1@/bin/app1",
			Name:           "TestApp",
			Classification: provenance.ClassificationThirdParty,
			Confidence:     provenance.ConfidenceHigh,
			Binaries: []applicationBinaryStub{
				{Name: "app1.exe", Path: "/bin/app1.exe"},
			},
		},
	}

	var buf bytes.Buffer
	jr := NewJSONReporter()
	err := jr.Report(&buf, apps, Telemetry{Duration: 10 * time.Millisecond})
	if err != nil {
		t.Fatalf("JSONReporter failed: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "TestApp") || !strings.Contains(out, "THIRD_PARTY") {
		t.Errorf("Unexpected JSON output: %s", out)
	}
}

type applicationBinaryStub = application.ApplicationBinary

func TestTerminalReporter(t *testing.T) {
	apps := []application.Application{
		{
			Name:           "FFmpeg",
			Classification: provenance.ClassificationThirdParty,
			Confidence:     provenance.ConfidenceHigh,
			Binaries: []application.ApplicationBinary{
				{Name: "ffmpeg.exe", Path: `C:\tools\ffmpeg\bin\ffmpeg.exe`},
				{Name: "ffplay.exe", Path: `C:\tools\ffmpeg\bin\ffplay.exe`},
				{Name: "ffprobe.exe", Path: `C:\tools\ffmpeg\bin\ffprobe.exe`},
			},
			Reasons: []string{"Corroborated multi-binary suite"},
		},
		{
			Name:              "InternalPayroll",
			Classification:    provenance.ClassificationCompany,
			Confidence:        provenance.ConfidenceVeryHigh,
			PrimaryBinaryPath: `C:\tools\payroll.exe`,
			Reasons:           []string{"Company code-signing certificate"},
		},
		{
			Name:              "UnknownTool",
			Classification:    provenance.ClassificationUnknown,
			Confidence:        provenance.ConfidenceNone,
			PrimaryBinaryPath: `C:\tools\unknown.exe`,
			Reasons:           []string{"No evidence available"},
		},
	}

	var buf bytes.Buffer
	tr := NewTerminalReporter()
	err := tr.Report(&buf, apps, Telemetry{
		Duration:    15 * time.Millisecond,
		NetworkMode: "off",
	})
	if err != nil {
		t.Fatalf("TerminalReporter failed: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "Third-Party") || !strings.Contains(out, "Company") || !strings.Contains(out, "Unknown") {
		t.Errorf("Terminal output missing category sections: %s", out)
	}
	if !strings.Contains(out, "FFmpeg") {
		t.Errorf("Terminal output missing FFmpeg: %s", out)
	}
	if !strings.Contains(out, "InternalPayroll") {
		t.Errorf("Terminal output missing InternalPayroll: %s", out)
	}
}

func TestTerminalReporter_AIErrorReporting(t *testing.T) {
	apps := []application.Application{
		{
			Name:              "grex",
			Classification:    provenance.ClassificationUnknown,
			Confidence:        provenance.ConfidenceNone,
			PrimaryBinaryPath: `C:\tools\grex.exe`,
			ResolutionSource:  "deepseek_error",
			AIError:           "HTTP 401 Unauthorized (Invalid API key - run 'appaudit config set-deepseek-key')",
			EvidenceSummary:   "DeepSeek API authentication failed (HTTP 401 Unauthorized). The configured API key was rejected.",
			Conclusion:        "AI reasoning halted due to invalid or unauthorized DeepSeek API key.",
			Reasons: []string{
				"Tier 3 AI Error (deepseek_flash (deepseek-flash)): HTTP 401 Unauthorized (Invalid API key - run 'appaudit config set-deepseek-key')",
				"DeepSeek authentication error (HTTP 401): invalid or unauthorized API key",
			},
		},
	}

	var buf bytes.Buffer
	tr := NewTerminalReporter()
	err := tr.Report(&buf, apps, Telemetry{
		Duration:    20 * time.Millisecond,
		NetworkMode: "on",
	})
	if err != nil {
		t.Fatalf("TerminalReporter failed: %v", err)
	}

	out := buf.String()

	// 1. Table must say "DeepSeek Error" instead of generic "DeepSeek Inconc."
	if !strings.Contains(out, "DeepSeek Error") {
		t.Errorf("expected 'DeepSeek Error' in table resolution column, got:\n%s", out)
	}

	// 2. Primary reason in table must show the API error
	if !strings.Contains(out, "HTTP 401 Unauthorized") {
		t.Errorf("expected 'HTTP 401 Unauthorized' in table primary reason column, got:\n%s", out)
	}

	// 3. AI Reasoning card must indicate API ERROR status
	if !strings.Contains(out, "[grex] -> UNKNOWN (API ERROR)") {
		t.Errorf("expected status 'UNKNOWN (API ERROR)' in AI reasoning card, got:\n%s", out)
	}

	// 4. Telemetry must report 1 API Error instead of 1 Inconclusive
	if !strings.Contains(out, "1 API Errors") {
		t.Errorf("expected '1 API Errors' in telemetry summary, got:\n%s", out)
	}

	// 5. Dedicated Remediation Notice must be rendered with fix command
	if !strings.Contains(out, "[!] AI Provider Failure & Remediation Notice") {
		t.Errorf("expected Remediation Notice banner, got:\n%s", out)
	}
	if !strings.Contains(out, "appaudit config set-deepseek-key") {
		t.Errorf("expected remediation command 'appaudit config set-deepseek-key' in notice, got:\n%s", out)
	}
}
