package application

import (
	"context"
	"strings"
	"testing"

	"github.com/example/appaudit/internal/ai"
	"github.com/example/appaudit/internal/ai/aitest"
	"github.com/example/appaudit/internal/provenance"
)

func TestDecision_ExactHashMatch(t *testing.T) {
	de := NewDecisionEngine(nil, nil, nil)
	app := &Application{Name: "hashapp"}
	bundle := EvidenceBundle{
		PrimaryBinary: ApplicationBinary{Name: "hashapp.exe", SHA256: "abcd"},
		Evidence: []provenance.Evidence{
			{
				Type:        provenance.EvidenceExactHashMatch,
				Source:      "NSRL",
				Strength:    1.0,
				Description: "Exact SHA-256 match in NSRL",
				Confidence:  provenance.ConfidenceVeryHigh,
			},
		},
	}

	de.Decide(context.Background(), app, bundle)

	if app.Classification != provenance.ClassificationThirdParty {
		t.Fatalf("Expected THIRD_PARTY, got %s", app.Classification)
	}
	if app.Confidence != provenance.ConfidenceVeryHigh {
		t.Fatalf("Expected VERY_HIGH confidence, got %s", app.Confidence)
	}
}

func TestDecision_CompanySignature(t *testing.T) {
	de := NewDecisionEngine([]string{"acme.corp", "acme"}, nil, nil)
	app := &Application{Name: "internaltool"}
	bundle := EvidenceBundle{
		Binaries: []ApplicationBinary{
			{
				Name: "internaltool.exe",
				Inspection: provenance.BinaryMetadata{
					IsSigned:       true,
					SignatureValid: true,
					CertSubject:    "Acme Corp Internal Signing Authority",
				},
			},
		},
	}

	de.Decide(context.Background(), app, bundle)

	if app.Classification != provenance.ClassificationCompany {
		t.Fatalf("Expected COMPANY, got %s", app.Classification)
	}
	if app.Confidence != provenance.ConfidenceVeryHigh {
		t.Fatalf("Expected VERY_HIGH confidence, got %s", app.Confidence)
	}
}

func TestDecision_CompanyTrumpsEmbeddedThirdPartyComponent(t *testing.T) {
	// An internal company tool that links FFmpeg libraries and SQLite
	de := NewDecisionEngine([]string{"mycompany"}, nil, nil)
	app := &Application{Name: "InternalVideoEncoder"}
	bundle := EvidenceBundle{
		Binaries: []ApplicationBinary{
			{
				Name: "InternalVideoEncoder.exe",
				Inspection: provenance.BinaryMetadata{
					IsSigned:       true,
					SignatureValid: true,
					CertSubject:    "MyCompany Internal Tools",
					Components:     []string{"libavcodec", "sqlite3"},
				},
			},
		},
	}

	de.Decide(context.Background(), app, bundle)

	if app.Classification != provenance.ClassificationCompany {
		t.Fatalf("Expected COMPANY despite embedded third-party components, got %s", app.Classification)
	}
}

func TestDecision_InternalVideoTool_WithoutCompanySig_DoesNotBecomeThirdParty(t *testing.T) {
	// A proprietary tool that embeds libavcodec but is NOT signed and NOT FFmpeg.
	// Must NOT become THIRD_PARTY merely because libavcodec string is present!
	de := NewDecisionEngine(nil, nil, nil)
	app := &Application{Name: "InternalVideoTool"}
	bundle := EvidenceBundle{
		PrimaryBinary: ApplicationBinary{
			Name: "InternalVideoTool.exe",
			Inspection: provenance.BinaryMetadata{
				Components: []string{"libavcodec"},
			},
		},
		Binaries: []ApplicationBinary{
			{
				Name: "InternalVideoTool.exe",
				Inspection: provenance.BinaryMetadata{
					Components: []string{"libavcodec"},
				},
			},
		},
	}

	de.Decide(context.Background(), app, bundle)

	if app.Classification != provenance.ClassificationUnknown {
		t.Fatalf("Expected UNKNOWN for InternalVideoTool embedding libavcodec, got %s", app.Classification)
	}
}

func TestDecision_FFmpegSuite_CorroboratesThirdParty(t *testing.T) {
	// Real-world FFmpeg Essentials: unsigned, not in NSRL, but has:
	// - primary: ffmpeg.exe
	// - siblings: ffplay.exe, ffprobe.exe
	// - folder: ffmpeg-7.1.1-essentials_build
	// - components: libavcodec, ffmpeg developers
	de := NewDecisionEngine(nil, nil, nil)
	app := &Application{
		Name:       "ffmpeg",
		InstallDir: `C:\Program Files\ffmpeg-7.1.1-essentials_build\bin`,
	}
	bundle := EvidenceBundle{
		AppName:    "ffmpeg",
		InstallDir: `C:\Program Files\ffmpeg-7.1.1-essentials_build\bin`,
		PrimaryBinary: ApplicationBinary{
			Name: "ffmpeg.exe",
			Path: `C:\Program Files\ffmpeg-7.1.1-essentials_build\bin\ffmpeg.exe`,
			Inspection: provenance.BinaryMetadata{
				Components: []string{"libavcodec", "libavformat", "ffmpeg developers"},
			},
		},
		Binaries: []ApplicationBinary{
			{
				Name: "ffmpeg.exe",
				Path: `C:\Program Files\ffmpeg-7.1.1-essentials_build\bin\ffmpeg.exe`,
				Inspection: provenance.BinaryMetadata{
					Components: []string{"libavcodec", "libavformat", "ffmpeg developers"},
				},
			},
			{
				Name: "ffplay.exe",
				Path: `C:\Program Files\ffmpeg-7.1.1-essentials_build\bin\ffplay.exe`,
			},
			{
				Name: "ffprobe.exe",
				Path: `C:\Program Files\ffmpeg-7.1.1-essentials_build\bin\ffprobe.exe`,
			},
		},
	}

	de.Decide(context.Background(), app, bundle)

	// Invariant: Identity candidate != ownership proof.
	// Without genuine cryptographic signature, NSRL hash match, or registered package manifest,
	// an unsigned portable layout establishes identity (FFmpeg), but classification remains UNKNOWN.
	if app.Classification != provenance.ClassificationUnknown {
		t.Fatalf("Expected UNKNOWN for unsigned portable FFmpeg suite lacking ownership provenance, got %s", app.Classification)
	}
	if app.Identity.Name != "FFmpeg" {
		t.Fatalf("Expected Identity name FFmpeg, got %s", app.Identity.Name)
	}
	if len(app.Reasons) == 0 {
		t.Fatalf("Expected explanation reasons for decision")
	}
}

func TestDecision_FFmpegSuite_WithRegisteredOrigin_IsThirdParty(t *testing.T) {
	de := NewDecisionEngine(nil, []string{"ffmpeg project"}, nil)
	app := &Application{
		Name:       "ffmpeg",
		Publisher:  "FFmpeg Project",
		Origin:     "Registry",
		InstallDir: `C:\Program Files\ffmpeg-7.1.1-essentials_build\bin`,
	}
	bundle := EvidenceBundle{
		AppName:    "ffmpeg",
		Publisher:  "FFmpeg Project",
		Origin:     "Registry",
		InstallDir: `C:\Program Files\ffmpeg-7.1.1-essentials_build\bin`,
		PrimaryBinary: ApplicationBinary{
			Name: "ffmpeg.exe",
			Path: `C:\Program Files\ffmpeg-7.1.1-essentials_build\bin\ffmpeg.exe`,
		},
	}

	de.Decide(context.Background(), app, bundle)

	if app.Classification != provenance.ClassificationThirdParty {
		t.Fatalf("Expected THIRD_PARTY for registered FFmpeg package, got %s", app.Classification)
	}
	if app.Confidence != provenance.ConfidenceHigh {
		t.Fatalf("Expected HIGH confidence, got %s", app.Confidence)
	}
}

func TestDecision_GenericBinary_IsUnknown(t *testing.T) {
	de := NewDecisionEngine(nil, nil, nil)
	app := &Application{Name: "updater"}
	bundle := EvidenceBundle{
		PrimaryBinary: ApplicationBinary{Name: "updater.exe"},
		Binaries:      []ApplicationBinary{{Name: "updater.exe"}},
	}

	de.Decide(context.Background(), app, bundle)

	if app.Classification != provenance.ClassificationUnknown {
		t.Fatalf("Expected UNKNOWN for generic binary, got %s", app.Classification)
	}
	if app.Confidence != provenance.ConfidenceNone {
		t.Fatalf("Expected NONE confidence, got %s", app.Confidence)
	}
}

func TestDecision_AIReasoner_FallbackAndSynthesis(t *testing.T) {
	ctx := context.Background()

	// 1. AI synthesizes THIRD_PARTY for ambiguous bundle with objective external manifest
	mockThirdParty := &aitest.MockReasoner{
		Result: ai.ReasoningResult{
			Classification: provenance.ClassificationThirdParty,
			Identity:       "CustomOpenTool",
			Confidence:     provenance.ConfidenceMedium,
			Reasons:        []string{"Ambiguous signals consistent with public project"},
		},
	}
	deAI := NewDecisionEngine(nil, []string{"external foundation"}, mockThirdParty)
	appAI := &Application{
		Name:      "ambiguous",
		Publisher: "External Foundation",
		Origin:    "Registry",
	}
	deAI.Decide(ctx, appAI, EvidenceBundle{
		Origin:        "Registry",
		Publisher:     "External Foundation",
		PrimaryBinary: ApplicationBinary{Name: "ambiguous.exe"},
	})

	if appAI.Classification != provenance.ClassificationThirdParty {
		t.Fatalf("Expected THIRD_PARTY from grounded AI reasoner, got %s", appAI.Classification)
	}

	// 2. AI errors -> falls back safely to deterministic UNKNOWN
	mockErr := &aitest.MockReasoner{
		Err: context.DeadlineExceeded,
	}
	deErr := NewDecisionEngine(nil, nil, mockErr)
	appErr := &Application{Name: "ambiguous"}
	deErr.Decide(ctx, appErr, EvidenceBundle{PrimaryBinary: ApplicationBinary{Name: "ambiguous.exe"}})

	if appErr.Classification != provenance.ClassificationUnknown {
		t.Fatalf("Expected fallback to UNKNOWN on AI error, got %s", appErr.Classification)
	}

	// 3. AI returns APIError (e.g. DeepSeek HTTP 401 Unauthorized) -> preserves error details, sets deepseek_error, no Rule F generic text
	mockDeepSeekError := &aitest.MockReasoner{
		MockName: "deepseek_flash (deepseek-flash)",
		Result: ai.ReasoningResult{
			Classification:  provenance.ClassificationUnknown,
			Confidence:      provenance.ConfidenceNone,
			APIError:        "HTTP 401 Unauthorized (Invalid API key - run 'appaudit config set-deepseek-key')",
			EvidenceSummary: "DeepSeek API authentication failed (HTTP 401 Unauthorized).",
			Conclusion:      "AI reasoning halted due to invalid API key.",
			Reasons:         []string{"DeepSeek authentication error (HTTP 401): invalid or unauthorized API key"},
		},
	}
	deDeepSeek := NewDecisionEngine(nil, nil, mockDeepSeekError)
	appDeepSeek := &Application{Name: "grex"}
	deDeepSeek.Decide(ctx, appDeepSeek, EvidenceBundle{PrimaryBinary: ApplicationBinary{Name: "grex.exe"}})

	if appDeepSeek.Classification != provenance.ClassificationUnknown {
		t.Fatalf("Expected UNKNOWN, got %s", appDeepSeek.Classification)
	}
	if appDeepSeek.ResolutionSource != "deepseek_error" {
		t.Errorf("Expected resolution source 'deepseek_error', got %s", appDeepSeek.ResolutionSource)
	}
	if appDeepSeek.AIError != "HTTP 401 Unauthorized (Invalid API key - run 'appaudit config set-deepseek-key')" {
		t.Errorf("Expected app.AIError to be populated, got: %s", appDeepSeek.AIError)
	}
	for _, r := range appDeepSeek.Reasons {
		if strings.Contains(r, "Rule F Fallback") {
			t.Errorf("Generic Rule F fallback should not be appended on APIError, found: %s", r)
		}
	}
}

func TestDecision_RegisteredManifest_CompanyPublisherWithoutSignature_IsUnknown(t *testing.T) {
	// Scenario A: Internal application registered in Windows Add/Remove Programs (Registry),
	// Publisher matches company indicator ("Acme Corp"), but binary has no code-signing certificate
	// and no internal Go module. Must NOT become THIRD_PARTY!
	de := NewDecisionEngine([]string{"acme.corp", "acme"}, nil, nil)
	app := &Application{
		Name:      "Acme Internal Billing System",
		Publisher: "Acme Corporation",
		Origin:    "Registry",
	}
	bundle := EvidenceBundle{
		AppName:       "Acme Internal Billing System",
		Publisher:     "Acme Corporation",
		Origin:        "Registry",
		PrimaryBinary: ApplicationBinary{Name: "billing.exe"},
		Binaries:      []ApplicationBinary{{Name: "billing.exe"}},
	}

	de.Decide(context.Background(), app, bundle)

	if app.Classification == provenance.ClassificationThirdParty {
		t.Fatalf("VIOLATION: Internal registered company app classified as THIRD_PARTY!")
	}
	if app.Classification != provenance.ClassificationUnknown {
		t.Fatalf("Expected UNKNOWN for unsigned internal registered app, got %s", app.Classification)
	}
	if app.Confidence != provenance.ConfidenceNone {
		t.Fatalf("Expected NONE confidence, got %s", app.Confidence)
	}
}

func TestDecision_RegisteredManifest_KnownExternalPublisher_IsThirdParty(t *testing.T) {
	// Scenario B: External application registered in OS manifest with verified external publisher
	// (e.g. "Microsoft Corporation")
	de := NewDecisionEngine(nil, []string{"microsoft", "google"}, nil)
	app := &Application{
		Name:      "Visual Studio Code",
		Publisher: "Microsoft Corporation",
		Origin:    "Registry",
	}
	bundle := EvidenceBundle{
		AppName:       "Visual Studio Code",
		Publisher:     "Microsoft Corporation",
		Origin:        "Registry",
		PrimaryBinary: ApplicationBinary{Name: "Code.exe"},
		Binaries:      []ApplicationBinary{{Name: "Code.exe"}},
	}

	de.Decide(context.Background(), app, bundle)

	if app.Classification != provenance.ClassificationThirdParty {
		t.Fatalf("Expected THIRD_PARTY for recognized external publisher in Registry, got %s", app.Classification)
	}
	if app.Confidence != provenance.ConfidenceHigh {
		t.Fatalf("Expected HIGH confidence, got %s", app.Confidence)
	}
}

func TestDecision_RegisteredManifest_GenericUnverifiedPublisher_IsUnknown(t *testing.T) {
	// Scenario C: Registry entry with generic/unrecognized publisher and name.
	// Must NOT automatically become THIRD_PARTY!
	de := NewDecisionEngine(nil, []string{"microsoft", "google"}, nil)
	app := &Application{
		Name:      "RandomUtility",
		Publisher: "Unknown Software LLC",
		Origin:    "Registry",
	}
	bundle := EvidenceBundle{
		AppName:       "RandomUtility",
		Publisher:     "Unknown Software LLC",
		Origin:        "Registry",
		PrimaryBinary: ApplicationBinary{Name: "util.exe"},
		Binaries:      []ApplicationBinary{{Name: "util.exe"}},
	}

	de.Decide(context.Background(), app, bundle)

	if app.Classification == provenance.ClassificationThirdParty {
		t.Fatalf("VIOLATION: Generic unverified registry entry falsely classified as THIRD_PARTY!")
	}
	if app.Classification != provenance.ClassificationUnknown {
		t.Fatalf("Expected UNKNOWN for unverified registry entry, got %s", app.Classification)
	}
}

func TestDecision_SiblingDeduplication_NoInflatedSignals(t *testing.T) {
	// P0 #2: Ensure one physical ffplay.exe produces exactly one sibling signal,
	// one ffprobe.exe produces exactly one sibling signal, and signals are not duplicated by extensions.
	bundle := EvidenceBundle{
		AppName:    "ffmpeg",
		InstallDir: `C:\Tools\ffmpeg\bin`,
		PrimaryBinary: ApplicationBinary{
			Name: "ffmpeg.exe",
			Path: `C:\Tools\ffmpeg\bin\ffmpeg.exe`,
		},
		Binaries: []ApplicationBinary{
			{Name: "ffmpeg.exe", Path: `C:\Tools\ffmpeg\bin\ffmpeg.exe`},
			{Name: "ffplay.exe", Path: `C:\Tools\ffmpeg\bin\ffplay.exe`},
			{Name: "ffprobe.exe", Path: `C:\Tools\ffmpeg\bin\ffprobe.exe`},
		},
	}

	identity := ResolveIdentity(bundle)

	ffplayCount := 0
	ffprobeCount := 0
	for _, sig := range identity.Signals {
		if sig == "Sibling binary matches layout: 'ffplay'" {
			ffplayCount++
		}
		if sig == "Sibling binary matches layout: 'ffprobe'" {
			ffprobeCount++
		}
		if sig == "Sibling binary matches layout: 'ffplay.exe'" || sig == "Sibling binary matches layout: 'ffprobe.exe'" {
			t.Fatalf("VIOLATION: Found duplicate extension sibling signal: %s", sig)
		}
	}

	if ffplayCount != 1 {
		t.Fatalf("Expected exactly 1 ffplay sibling signal, got %d", ffplayCount)
	}
	if ffprobeCount != 1 {
		t.Fatalf("Expected exactly 1 ffprobe sibling signal, got %d", ffprobeCount)
	}
}

type testTrackingReasoner struct {
	name   string
	calls  int
	result ai.ReasoningResult
	onCall func(bundle any)
}

func (t *testTrackingReasoner) Name() string {
	if t.name != "" {
		return t.name
	}
	return "gemini"
}

func (t *testTrackingReasoner) Analyze(ctx context.Context, bundle any) (ai.ReasoningResult, error) {
	t.calls++
	if t.onCall != nil {
		t.onCall(bundle)
	}
	return t.result, nil
}

func TestDecision_MultiEXE_RecognizedApplication_BypassesGemini(t *testing.T) {
	mock := &testTrackingReasoner{
		name:   "gemini",
		result: ai.ReasoningResult{Classification: provenance.ClassificationThirdParty},
	}

	de := NewDecisionEngine(nil, nil, mock)

	app := &Application{
		Name:              "MyRecognizedSuite",
		InstallDir:        `C:\Program Files\MyRecognizedSuite`,
		PrimaryBinaryPath: `C:\Program Files\MyRecognizedSuite\app.exe`,
		Binaries: []ApplicationBinary{
			{Name: "app.exe", Path: `C:\Program Files\MyRecognizedSuite\app.exe`},
			{Name: "app_helper.exe", Path: `C:\Program Files\MyRecognizedSuite\app_helper.exe`},
			{Name: "app_updater.exe", Path: `C:\Program Files\MyRecognizedSuite\app_updater.exe`},
		},
	}

	bundle := EvidenceBundle{
		AppName:           app.Name,
		InstallDir:        app.InstallDir,
		PrimaryBinary:     app.Binaries[0],
		Binaries:          app.Binaries,
		Evidence: []provenance.Evidence{
			{
				Type:        provenance.EvidencePublisherSignature,
				Source:      "Authenticode Certificate",
				Strength:    0.95,
				Description: "Binary cryptographically signed by: External Vendor LLC",
				Confidence:  provenance.ConfidenceHigh,
			},
		},
	}

	de.Decide(context.Background(), app, bundle)

	if app.Classification != provenance.ClassificationThirdParty {
		t.Fatalf("Expected THIRD_PARTY, got %s", app.Classification)
	}
	if app.ResolutionSource != "deterministic" {
		t.Fatalf("Expected resolution source 'deterministic', got %s", app.ResolutionSource)
	}
	if mock.calls != 0 {
		t.Fatalf("Expected 0 Gemini calls for deterministically recognized application, got %d", mock.calls)
	}
}

func TestDecision_MultiEXE_UnresolvedApplication_InvokesGeminiExactlyOnce(t *testing.T) {
	var receivedBinariesCount int

	mock := &testTrackingReasoner{
		name: "gemini",
		result: ai.ReasoningResult{
			Classification:    provenance.ClassificationThirdParty,
			Confidence:        provenance.ConfidenceHigh,
			Identity:          "Awesome MultiTool Suite",
			Sources:           []string{"https://github.com/example/multitool"},
			Reasons:           []string{"Digital research identified official open source multi-tool"},
			ResearchPerformed: true,
		},
		onCall: func(b any) {
			if bundle, ok := b.(EvidenceBundle); ok {
				receivedBinariesCount = len(bundle.Binaries)
			}
		},
	}

	de := NewDecisionEngine(nil, nil, mock)

	app := &Application{
		Name:              "multitool",
		InstallDir:        `C:\tools\multitool`,
		PrimaryBinaryPath: `C:\tools\multitool\tool1.exe`,
		Binaries: []ApplicationBinary{
			{Name: "tool1.exe", Path: `C:\tools\multitool\tool1.exe`},
			{Name: "tool2.exe", Path: `C:\tools\multitool\tool2.exe`},
			{Name: "tool3.exe", Path: `C:\tools\multitool\tool3.exe`},
			{Name: "tool4.exe", Path: `C:\tools\multitool\tool4.exe`},
		},
	}

	bundle := EvidenceBundle{
		AppName:       app.Name,
		InstallDir:    app.InstallDir,
		PrimaryBinary: app.Binaries[0],
		Binaries:      app.Binaries,
	}

	de.Decide(context.Background(), app, bundle)

	if mock.calls != 1 {
		t.Fatalf("Expected Gemini to be invoked EXACTLY ONCE for unresolved application suite, got %d calls", mock.calls)
	}
	if receivedBinariesCount != 4 {
		t.Fatalf("Expected Gemini to receive all 4 binaries in the application bundle, got %d", receivedBinariesCount)
	}
	if app.Classification != provenance.ClassificationThirdParty {
		t.Fatalf("Expected THIRD_PARTY, got %s", app.Classification)
	}
	if app.ResolutionSource != "gemini_search" {
		t.Fatalf("Expected resolution source 'gemini_search', got %s", app.ResolutionSource)
	}
}
