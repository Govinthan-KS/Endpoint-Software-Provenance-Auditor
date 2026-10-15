package application

import (
	"context"
	"strings"
	"testing"

	"github.com/example/appaudit/internal/ai"
	"github.com/example/appaudit/internal/provenance"
)

// Test A — Fake FFmpeg: files are fake executables in an FFmpeg-like path
// Expected: UNKNOWN (NOT THIRD_PARTY). Identity candidate FFmpeg preserved.
func TestAdversarial_TestA_FakeFFmpegBundle(t *testing.T) {
	de := NewDecisionEngine(nil, nil, nil)
	app := &Application{
		Name:              "ffmpeg",
		InstallDir:        "c:/tools/ffmpeg/bin",
		PrimaryBinaryPath: "c:/tools/ffmpeg/bin/ffmpeg.exe",
		Binaries: []ApplicationBinary{
			{Name: "ffmpeg.exe", Path: "c:/tools/ffmpeg/bin/ffmpeg.exe"},
			{Name: "ffplay.exe", Path: "c:/tools/ffmpeg/bin/ffplay.exe"},
			{Name: "ffprobe.exe", Path: "c:/tools/ffmpeg/bin/ffprobe.exe"},
		},
	}
	bundle := EvidenceBundle{
		AppName:       app.Name,
		InstallDir:    app.InstallDir,
		PrimaryBinary: app.Binaries[0],
		Binaries:      app.Binaries,
	}

	de.Decide(context.Background(), app, bundle)

	if app.Classification != provenance.ClassificationUnknown {
		t.Fatalf("Expected UNKNOWN for fake FFmpeg bundle lacking ownership provenance, got %s", app.Classification)
	}
	if app.Identity.Name != "FFmpeg" {
		t.Fatalf("Expected candidate Identity FFmpeg, got %s", app.Identity.Name)
	}
	t.Logf("Test A Passed: Fake FFmpeg classified as %s (Candidate Identity=%s)",
		app.Classification, app.Identity.Name)
}

// Test B — Fake PostgreSQL: fake executables in PostgreSQL-like path
// Expected: UNKNOWN (NOT THIRD_PARTY).
func TestAdversarial_TestB_FakePostgresBundle(t *testing.T) {
	de := NewDecisionEngine(nil, nil, nil)
	app := &Application{
		Name:              "postgres",
		InstallDir:        "c:/tools/postgresql/bin",
		PrimaryBinaryPath: "c:/tools/postgresql/bin/postgres.exe",
		Binaries: []ApplicationBinary{
			{Name: "postgres.exe", Path: "c:/tools/postgresql/bin/postgres.exe"},
			{Name: "psql.exe", Path: "c:/tools/postgresql/bin/psql.exe"},
			{Name: "pg_dump.exe", Path: "c:/tools/postgresql/bin/pg_dump.exe"},
		},
	}
	bundle := EvidenceBundle{
		AppName:       app.Name,
		InstallDir:    app.InstallDir,
		PrimaryBinary: app.Binaries[0],
		Binaries:      app.Binaries,
	}

	de.Decide(context.Background(), app, bundle)

	if app.Classification != provenance.ClassificationUnknown {
		t.Fatalf("Expected UNKNOWN for fake PostgreSQL bundle lacking ownership provenance, got %s", app.Classification)
	}
	t.Logf("Test B Passed: Fake PostgreSQL classified as %s", app.Classification)
}

// Test C — Fake Git: fake executables in Git-like path
// Expected: UNKNOWN (NOT THIRD_PARTY).
func TestAdversarial_TestC_FakeGitBundle(t *testing.T) {
	de := NewDecisionEngine(nil, nil, nil)
	app := &Application{
		Name:              "git",
		InstallDir:        "c:/tools/git/bin",
		PrimaryBinaryPath: "c:/tools/git/bin/git.exe",
		Binaries: []ApplicationBinary{
			{Name: "git.exe", Path: "c:/tools/git/bin/git.exe"},
			{Name: "git-bash.exe", Path: "c:/tools/git/bin/git-bash.exe"},
			{Name: "git-cmd.exe", Path: "c:/tools/git/bin/git-cmd.exe"},
		},
	}
	bundle := EvidenceBundle{
		AppName:       app.Name,
		InstallDir:    app.InstallDir,
		PrimaryBinary: app.Binaries[0],
		Binaries:      app.Binaries,
	}

	de.Decide(context.Background(), app, bundle)

	if app.Classification != provenance.ClassificationUnknown {
		t.Fatalf("Expected UNKNOWN for fake Git bundle lacking ownership provenance, got %s", app.Classification)
	}
	t.Logf("Test C Passed: Fake Git classified as %s", app.Classification)
}

// Test D — Renamed Genuine Chrome: genuine commercial signature, renamed to company_tool.exe
// Expected: THIRD_PARTY (crypto signature proves ownership independent of filename).
func TestAdversarial_TestD_RenamedGenuineBinary(t *testing.T) {
	de := NewDecisionEngine(nil, []string{"google llc"}, nil)
	app := &Application{
		Name:              "company_tool",
		PrimaryBinaryPath: "c:/temp/company_tool.exe",
		Binaries: []ApplicationBinary{
			{
				Name: "company_tool.exe",
				Path: "c:/temp/company_tool.exe",
				Inspection: provenance.BinaryMetadata{
					IsExecutable:   true,
					IsSigned:       true,
					SignatureValid: true,
					CertSubject:    "Google LLC",
					CertIssuer:     "DigiCert Inc",
				},
			},
		},
	}
	bundle := EvidenceBundle{
		AppName:       app.Name,
		PrimaryBinary: app.Binaries[0],
		Binaries:      app.Binaries,
	}

	de.Decide(context.Background(), app, bundle)

	if app.Classification != provenance.ClassificationThirdParty {
		t.Fatalf("Expected THIRD_PARTY from valid commercial signature, got %s", app.Classification)
	}
	if app.Confidence != provenance.ConfidenceHigh {
		t.Fatalf("Expected HIGH confidence, got %s", app.Confidence)
	}
	t.Logf("Test D Passed: Renamed binary classified as %s (%s)", app.Classification, app.Confidence)
}

// Test E — Company App Embedding FFmpeg: internal-looking tool containing 3rd-party strings
// Expected: UNKNOWN (and NOT THIRD_PARTY; application identity must not become FFmpeg).
func TestAdversarial_TestE_CompanyAppWithThirdPartyStrings(t *testing.T) {
	de := NewDecisionEngine([]string{"acme"}, nil, nil)
	app := &Application{
		Name:              "CompanyVideoTool",
		PrimaryBinaryPath: "c:/tools/CompanyVideoTool.exe",
		Binaries: []ApplicationBinary{
			{
				Name: "CompanyVideoTool.exe",
				Path: "c:/tools/CompanyVideoTool.exe",
				Inspection: provenance.BinaryMetadata{
					IsExecutable: true,
					Components:   []string{"FFmpeg", "libavcodec", "libavformat", "libavutil", "OpenSSL", "SQLite"},
				},
			},
		},
	}
	bundle := EvidenceBundle{
		AppName:       app.Name,
		PrimaryBinary: app.Binaries[0],
		Binaries:      app.Binaries,
	}

	de.Decide(context.Background(), app, bundle)

	if app.Classification != provenance.ClassificationUnknown {
		t.Fatalf("Expected UNKNOWN for internal tool with 3rd-party strings, got %s", app.Classification)
	}
	if app.Identity.Name == "FFmpeg" {
		t.Fatalf("Containing application identity must NOT become FFmpeg merely from embedded strings, got %s", app.Identity.Name)
	}
	t.Logf("Test E Passed: Company app embedding strings classified as %s (Identity=%s)",
		app.Classification, app.Identity.Name)
}

// Test F — Publisher String Spoof: unsigned binary with PE VersionInfo strings
// Expected: UNKNOWN for Google, Microsoft, and FFmpeg strings. Must never claim "cryptographically signed".
func TestAdversarial_TestF_PublisherStringSpoof(t *testing.T) {
	de := NewDecisionEngine(nil, []string{"google llc", "microsoft corporation", "ffmpeg project"}, nil)

	testCases := []struct {
		company string
		product string
	}{
		{"Google LLC", "Chrome"},
		{"Microsoft Corporation", "Edge"},
		{"FFmpeg Project", "FFmpeg"},
	}

	for _, tc := range testCases {
		app := &Application{
			Name:              "spoofed_tool",
			PrimaryBinaryPath: "c:/temp/spoofed_tool.exe",
			Binaries: []ApplicationBinary{
				{
					Name: "spoofed_tool.exe",
					Path: "c:/temp/spoofed_tool.exe",
					Inspection: provenance.BinaryMetadata{
						IsExecutable:    true,
						IsSigned:        false, // NOT cryptographically signed!
						SignatureValid:  false,
						CompanyName:     tc.company,
						ProductName:     tc.product,
						FileDescription: tc.product,
					},
				},
			},
		}
		bundle := EvidenceBundle{
			AppName:       app.Name,
			PrimaryBinary: app.Binaries[0],
			Binaries:      app.Binaries,
		}

		de.Decide(context.Background(), app, bundle)

		if app.Classification != provenance.ClassificationUnknown {
			t.Fatalf("Expected UNKNOWN for unsigned binary with CompanyName '%s', got %s", tc.company, app.Classification)
		}

		for _, r := range app.Reasons {
			if strings.Contains(strings.ToLower(r), "cryptographically signed") {
				t.Fatalf("VIOLATION: Unsigned binary emitted claim of being cryptographically signed: %s", r)
			}
		}
	}
	t.Logf("Test F Passed: Unsigned binaries with spoofed PE publisher strings classified as UNKNOWN")
}

// Test G — Directory Spoof: random unknown binary placed in known third-party directories
// Expected: UNKNOWN. Directory location alone must not establish THIRD_PARTY.
func TestAdversarial_TestG_DirectorySpoof(t *testing.T) {
	de := NewDecisionEngine(nil, nil, nil)

	spoofedDirs := []string{
		`C:\Program Files\Google\Chrome\Application`,
		`C:\Program Files\FFmpeg\bin`,
		`C:\Program Files\PostgreSQL\18\bin`,
		`C:\Program Files\Git\bin`,
	}

	for _, d := range spoofedDirs {
		app := &Application{
			Name:              "unknown_utility",
			InstallDir:        d,
			PrimaryBinaryPath: d + `\unknown_utility.exe`,
			Binaries: []ApplicationBinary{
				{
					Name: "unknown_utility.exe",
					Path: d + `\unknown_utility.exe`,
				},
			},
		}
		bundle := EvidenceBundle{
			AppName:       app.Name,
			InstallDir:    app.InstallDir,
			PrimaryBinary: app.Binaries[0],
			Binaries:      app.Binaries,
		}

		de.Decide(context.Background(), app, bundle)

		if app.Classification != provenance.ClassificationUnknown {
			t.Fatalf("Directory '%s' alone must NOT establish THIRD_PARTY, got %s", d, app.Classification)
		}
	}
	t.Logf("Test G Passed: Random binaries in spoofed directories all classified as UNKNOWN")
}

// Test H — AI Weak-Evidence Attack: mock reasoner returns THIRD_PARTY / VERY_HIGH on weak evidence
// Expected: UNKNOWN (unsupported AI assertion must be rejected).
func TestAdversarial_TestH_AIWeakEvidenceAttack(t *testing.T) {
	mockAI := &mockAdversarialReasoner{
		outcome: ai.ReasoningResult{
			Classification: provenance.ClassificationThirdParty,
			Confidence:     provenance.ConfidenceVeryHigh,
			Reasons:        []string{"This looks like FFmpeg based on general appearance."},
		},
	}
	de := NewDecisionEngine(nil, nil, mockAI)
	app := &Application{
		Name:              "my_custom_tool",
		PrimaryBinaryPath: "c:/temp/my_custom_tool.exe",
		Binaries: []ApplicationBinary{
			{Name: "my_custom_tool.exe", Path: "c:/temp/my_custom_tool.exe"},
		},
	}
	bundle := EvidenceBundle{
		AppName:       app.Name,
		PrimaryBinary: app.Binaries[0],
		Binaries:      app.Binaries,
	}

	de.Decide(context.Background(), app, bundle)

	if app.Classification != provenance.ClassificationUnknown {
		t.Fatalf("Expected UNKNOWN when AI asserts THIRD_PARTY without objective evidence, got %s", app.Classification)
	}
	t.Logf("Test H Passed: Weak-evidence AI attack rejected -> %s", app.Classification)
}

// Test I — AI Invented Evidence: mock AI claims non-existent certificate, hash, repository
// Expected: UNKNOWN (AI's textual claims must not manufacture evidence).
func TestAdversarial_TestI_AIInventedEvidence(t *testing.T) {
	mockAI := &mockAdversarialReasoner{
		outcome: ai.ReasoningResult{
			Classification: provenance.ClassificationThirdParty,
			Confidence:     provenance.ConfidenceVeryHigh,
			Reasons: []string{
				"Verified against public repository https://github.com/invented/repo",
				"Matched invented SHA256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
				"Found valid certificate issued to Invented Inc",
			},
		},
	}
	de := NewDecisionEngine(nil, nil, mockAI)
	app := &Application{
		Name:              "mystery_binary",
		PrimaryBinaryPath: "c:/temp/mystery_binary.exe",
		Binaries: []ApplicationBinary{
			{Name: "mystery_binary.exe", Path: "c:/temp/mystery_binary.exe"},
		},
	}
	bundle := EvidenceBundle{
		AppName:       app.Name,
		PrimaryBinary: app.Binaries[0],
		Binaries:      app.Binaries,
	}

	de.Decide(context.Background(), app, bundle)

	if app.Classification != provenance.ClassificationUnknown {
		t.Fatalf("Expected UNKNOWN when AI invents non-existent evidence, got %s", app.Classification)
	}
	t.Logf("Test I Passed: Invented-evidence AI attack rejected -> %s", app.Classification)
}

// Test J — AI Unsupported COMPANY: mock AI returns COMPANY / VERY_HIGH with no company evidence
// Expected: UNKNOWN.
func TestAdversarial_TestJ_AIUnsupportedCompany(t *testing.T) {
	mockAI := &mockAdversarialReasoner{
		outcome: ai.ReasoningResult{
			Classification: provenance.ClassificationCompany,
			Confidence:     provenance.ConfidenceVeryHigh,
			Reasons:        []string{"Believed to be an internal company utility."},
		},
	}
	de := NewDecisionEngine([]string{"acme"}, nil, mockAI)
	app := &Application{
		Name:              "unknown_blob",
		PrimaryBinaryPath: "c:/temp/unknown_blob.exe",
		Binaries: []ApplicationBinary{
			{Name: "unknown_blob.exe", Path: "c:/temp/unknown_blob.exe"},
		},
	}
	bundle := EvidenceBundle{
		AppName:       app.Name,
		PrimaryBinary: app.Binaries[0],
		Binaries:      app.Binaries,
	}

	de.Decide(context.Background(), app, bundle)

	if app.Classification != provenance.ClassificationUnknown {
		t.Fatalf("Expected UNKNOWN when AI asserts COMPANY without company evidence, got %s", app.Classification)
	}
	t.Logf("Test J Passed: Unsupported COMPANY AI claim rejected -> %s", app.Classification)
}

// Additional regression: Registered manifest with company publisher remains UNKNOWN
func TestAdversarial_CompanyAppWithRegisteredManifest(t *testing.T) {
	de := NewDecisionEngine([]string{"acme corp", "acme"}, nil, nil)
	app := &Application{
		Name:              "Acme Internal Suite",
		Publisher:         "Acme Corp",
		Origin:            "Registry",
		PrimaryBinaryPath: "c:/program files/acme/app.exe",
		Binaries: []ApplicationBinary{
			{
				Name:   "app.exe",
				Path:   "c:/program files/acme/app.exe",
				Origin: "Registry",
			},
		},
	}
	bundle := EvidenceBundle{
		AppName:       app.Name,
		Publisher:     app.Publisher,
		Origin:        app.Origin,
		PrimaryBinary: app.Binaries[0],
		Binaries:      app.Binaries,
	}

	de.Decide(context.Background(), app, bundle)

	if app.Classification != provenance.ClassificationUnknown {
		t.Fatalf("Expected UNKNOWN (not THIRD_PARTY, not COMPANY), got %s", app.Classification)
	}
}

// Additional regression: Network-off invariant
func TestAdversarial_NetworkOffInvariant(t *testing.T) {
	cfg := EngineConfig{
		NetworkMode: provenance.NetworkOff,
	}
	eng := NewEngine(cfg)

	if eng.config.NetworkMode != provenance.NetworkOff {
		t.Fatalf("Expected NetworkMode to be NetworkOff, got %v", eng.config.NetworkMode)
	}
}

type mockAdversarialReasoner struct {
	outcome ai.ReasoningResult
}

func (m *mockAdversarialReasoner) Name() string { return "adversarial_mock" }
func (m *mockAdversarialReasoner) Analyze(ctx context.Context, bundle any) (ai.ReasoningResult, error) {
	return m.outcome, nil
}

// Test: Unsigned binary with spoofed PE publisher and StartMenu shortcut
// Expected: UNKNOWN (StartMenu shortcuts have no manifest publisher and cannot promote unauthenticated PE strings).
func TestAdversarial_StartMenuShortcut_WithSpoofedPublisherMetadata(t *testing.T) {
	de := NewDecisionEngine(nil, []string{"google llc"}, nil)
	app := &Application{
		Name:              "Chrome",
		Origin:            "StartMenu",
		PrimaryBinaryPath: "c:/temp/chrome.exe",
		Binaries: []ApplicationBinary{
			{
				Name: "chrome.exe",
				Path: "c:/temp/chrome.exe",
				Inspection: provenance.BinaryMetadata{
					IsExecutable: true,
					IsSigned:     false,
					CompanyName:  "Google LLC",
					ProductName:  "Google Chrome",
				},
			},
		},
	}
	bundle := EvidenceBundle{
		AppName:       app.Name,
		Origin:        app.Origin, // StartMenu manifest has no publisher
		PrimaryBinary: app.Binaries[0],
		Binaries:      app.Binaries,
	}

	de.Decide(context.Background(), app, bundle)

	if app.Classification != provenance.ClassificationUnknown {
		t.Fatalf("Expected UNKNOWN for unsigned binary in StartMenu with spoofed PE metadata, got %s", app.Classification)
	}
	t.Logf("StartMenu spoofing test passed -> %s", app.Classification)
}

// Test: Unsigned binary in Registry uninstall key where key had no publisher
// Expected: UNKNOWN (unauthenticated PE strings must not satisfy manifest vendor requirement).
func TestAdversarial_RegistryKey_WithoutPublisher_WithSpoofedMetadata(t *testing.T) {
	de := NewDecisionEngine(nil, []string{"google llc"}, nil)
	app := &Application{
		Name:              "Chrome",
		Origin:            "Registry",
		PrimaryBinaryPath: "c:/temp/chrome.exe",
		Binaries: []ApplicationBinary{
			{
				Name: "chrome.exe",
				Path: "c:/temp/chrome.exe",
				Inspection: provenance.BinaryMetadata{
					IsExecutable: true,
					IsSigned:     false,
					CompanyName:  "Google LLC",
					ProductName:  "Google Chrome",
				},
			},
		},
	}
	bundle := EvidenceBundle{
		AppName:       app.Name,
		Origin:        app.Origin,
		Publisher:     "", // Manifest key had no Publisher string
		PrimaryBinary: app.Binaries[0],
		Binaries:      app.Binaries,
	}

	de.Decide(context.Background(), app, bundle)

	if app.Classification != provenance.ClassificationUnknown {
		t.Fatalf("Expected UNKNOWN when Registry key lacks publisher even if PE has spoofed CompanyName, got %s", app.Classification)
	}
	t.Logf("Registry without publisher test passed -> %s", app.Classification)
}

// Test: Fake package-name and path (e.g. c:/packages/google-chrome/chrome.exe analyzed via CLI)
// Expected: UNKNOWN (path heuristics and package names cannot authorize THIRD_PARTY).
func TestAdversarial_FakePackageNameAndPath(t *testing.T) {
	de := NewDecisionEngine(nil, []string{"google"}, nil)
	app := &Application{
		Name:              "chrome",
		InstallDir:        "c:/packages/google-chrome",
		PrimaryBinaryPath: "c:/packages/google-chrome/chrome.exe",
		Origin:            "CLI",
		Binaries: []ApplicationBinary{
			{Name: "chrome.exe", Path: "c:/packages/google-chrome/chrome.exe"},
		},
	}
	bundle := EvidenceBundle{
		AppName:       app.Name,
		InstallDir:    app.InstallDir,
		Origin:        app.Origin,
		PrimaryBinary: app.Binaries[0],
		Binaries:      app.Binaries,
	}

	de.Decide(context.Background(), app, bundle)

	if app.Classification != provenance.ClassificationUnknown {
		t.Fatalf("Expected UNKNOWN for fake package path analyzed via CLI, got %s", app.Classification)
	}
	t.Logf("Fake package path test passed -> %s", app.Classification)
}

// Test: Random binary whose filename matches a known release artifact (e.g. rg.exe with non-matching hash)
// Expected: UNKNOWN (artifact name alone must not become an exact hash match or claim ownership).
func TestAdversarial_FakeReleaseArtifactMatch(t *testing.T) {
	de := NewDecisionEngine(nil, nil, nil)
	app := &Application{
		Name:              "rg",
		InstallDir:        "c:/bin",
		PrimaryBinaryPath: "c:/bin/rg.exe",
		Origin:            "CLI",
		Binaries: []ApplicationBinary{
			{
				Name:   "rg.exe",
				Path:   "c:/bin/rg.exe",
				SHA256: "0000000000000000000000000000000000000000000000000000000000000000",
			},
		},
	}
	bundle := EvidenceBundle{
		AppName:       app.Name,
		InstallDir:    app.InstallDir,
		Origin:        app.Origin,
		PrimaryBinary: app.Binaries[0],
		Binaries:      app.Binaries,
	}

	de.Decide(context.Background(), app, bundle)

	if app.Classification != provenance.ClassificationUnknown {
		t.Fatalf("Expected UNKNOWN for binary named rg.exe with dummy hash, got %s", app.Classification)
	}
	t.Logf("Fake release artifact match test passed -> %s", app.Classification)
}

// Test: Genuine verified hash match (e.g. NSRL exact hash match)
// Expected: THIRD_PARTY with VERY_HIGH confidence.
func TestAdversarial_GenuineVerifiedHash(t *testing.T) {
	de := NewDecisionEngine(nil, nil, nil)
	app := &Application{
		Name:              "verified_tool",
		PrimaryBinaryPath: "c:/bin/verified_tool.exe",
		Binaries: []ApplicationBinary{
			{Name: "verified_tool.exe", Path: "c:/bin/verified_tool.exe"},
		},
	}
	bundle := EvidenceBundle{
		AppName:       app.Name,
		PrimaryBinary: app.Binaries[0],
		Binaries:      app.Binaries,
		Evidence: []provenance.Evidence{
			{
				Type:        provenance.EvidenceExactHashMatch,
				Source:      "NIST NSRL",
				Strength:    1.0,
				Description: "Exact SHA-256 match in NIST NSRL verified baseline",
				Confidence:  provenance.ConfidenceVeryHigh,
			},
		},
	}

	de.Decide(context.Background(), app, bundle)

	if app.Classification != provenance.ClassificationThirdParty || app.Confidence != provenance.ConfidenceVeryHigh {
		t.Fatalf("Expected THIRD_PARTY / VERY_HIGH for verified hash match, got %s / %s", app.Classification, app.Confidence)
	}
	t.Logf("Verified hash match test passed -> %s (%s)", app.Classification, app.Confidence)
}

// Test: Genuine company signature (Authenticode certificate)
// Expected: COMPANY with VERY_HIGH confidence.
func TestAdversarial_GenuineCompanySignature(t *testing.T) {
	de := NewDecisionEngine([]string{"acme enterprise"}, nil, nil)
	app := &Application{
		Name:              "internal_tool",
		PrimaryBinaryPath: "c:/bin/internal_tool.exe",
		Binaries: []ApplicationBinary{
			{
				Name: "internal_tool.exe",
				Path: "c:/bin/internal_tool.exe",
				Inspection: provenance.BinaryMetadata{
					IsExecutable:   true,
					IsSigned:       true,
					SignatureValid: true,
					CertSubject:    "Acme Enterprise Systems, Inc.",
				},
			},
		},
	}
	bundle := EvidenceBundle{
		AppName:       app.Name,
		PrimaryBinary: app.Binaries[0],
		Binaries:      app.Binaries,
	}

	de.Decide(context.Background(), app, bundle)

	if app.Classification != provenance.ClassificationCompany {
		t.Fatalf("Expected COMPANY for genuine company-signed binary, got %s", app.Classification)
	}
	t.Logf("Genuine company signature test passed -> %s (%s)", app.Classification, app.Confidence)
}
