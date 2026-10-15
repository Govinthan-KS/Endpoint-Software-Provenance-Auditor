package application

import (
	"context"
	"testing"

	"github.com/example/appaudit/internal/ai"
	"github.com/example/appaudit/internal/provenance"
)

// TestRealCorpus_GeminiBenchmark evaluates real-world corpus applications against
// deterministic analysis and Gemini search-grounded research + Grounding Gate verification.
func TestRealCorpus_GeminiBenchmark(t *testing.T) {
	ctx := context.Background()

	// 1. Setup Mock Gemini Search Grounded Reasoner simulating real Google Search findings
	mockReasoner := &corpusBenchmarkReasoner{}

	// 2. Setup Decision Engines
	deterministicEngine := NewDecisionEngine([]string{"company", "internal", "acme"}, []string{
		"google llc",
		"microsoft corporation",
		"docker inc.",
		"jetbrains s.r.o.",
		"oracle and/or its affiliates",
		"oracle corporation",
	}, ai.NewNoopReasoner())

	geminiEngine := NewDecisionEngine([]string{"company", "internal", "acme"}, []string{
		"google llc",
		"microsoft corporation",
		"docker inc.",
		"jetbrains s.r.o.",
		"oracle and/or its affiliates",
		"oracle corporation",
	}, mockReasoner)

	// Corpus representative samples from host scan
	type testAppCase struct {
		CaseNumber           int
		Name                 string
		Description          string
		Binaries             []ApplicationBinary
		ExpectedBefore       provenance.Classification
		ExpectedAfter        provenance.Classification
		ExpectedGate         string // "accepted" | "rejected" | "bypassed"
		ExpectedRes          string // "deterministic" | "gemini_search" | "gemini_inconclusive"
		ExpectedArtifactProv string // "MATCHED" | "NOT_ESTABLISHED" | ""
		AuthoritativeEv      string
	}

	cases := []testAppCase{
		{
			CaseNumber:  1,
			Name:        "Google Chrome",
			Description: "Genuine third-party application already detected deterministically via Authenticode",
			Binaries: []ApplicationBinary{
				{
					Name: "chrome.exe",
					Path: `C:\Program Files\Google\Chrome\Application\chrome.exe`,
					Inspection: provenance.BinaryMetadata{
						IsExecutable:   true,
						IsSigned:       true,
						SignatureValid: true,
						CertSubject:    "Google LLC",
						CertIssuer:     "DigiCert Trusted G4 Code Signing",
					},
				},
			},
			ExpectedBefore:       provenance.ClassificationThirdParty,
			ExpectedAfter:        provenance.ClassificationThirdParty,
			ExpectedGate:         "bypassed",
			ExpectedRes:          "deterministic",
			ExpectedArtifactProv: "MATCHED",
			AuthoritativeEv:      "Verified external commercial Authenticode certificate (Google LLC)",
		},
		{
			CaseNumber:  2,
			Name:        "ffmpeg",
			Description: "Unsigned portable open-source application identified via official project documentation",
			Binaries: []ApplicationBinary{
				{
					Name:   "ffmpeg.exe",
					Path:   `C:\Program Files\ffmpeg-7.1.1-essentials_build\bin\ffmpeg.exe`,
					SHA256: "b90225987bdd042cca09a1efb5e34e9848f2d1dbf5fbcd388753a44145522997",
					Inspection: provenance.BinaryMetadata{
						IsExecutable: true,
						IsSigned:     false,
						Components:   []string{"FFmpeg", "libavcodec"},
					},
				},
			},
			ExpectedBefore:       provenance.ClassificationUnknown,
			ExpectedAfter:        provenance.ClassificationThirdParty,
			ExpectedGate:         "accepted",
			ExpectedRes:          "gemini_search",
			ExpectedArtifactProv: "NOT_ESTABLISHED",
			AuthoritativeEv:      "Official project documentation and releases from ffmpeg.org (ArtifactProvenance: NOT_ESTABLISHED)",
		},
		{
			CaseNumber:  3,
			Name:        "mongosh",
			Description: "Application identified as MongoDB Shell via authoritative sources without exact release hash",
			Binaries: []ApplicationBinary{
				{
					Name:   "mongosh.exe",
					Path:   `C:\Users\govin\Downloads\mongosh-2.5.1-win32-x64\bin\mongosh.exe`,
					SHA256: "64c2ab0a55ac09117dfa213e8c8d54c13430b9d58c36c3b4ae0fbeba516725be",
					Inspection: provenance.BinaryMetadata{
						IsExecutable: true,
						IsSigned:     false,
					},
				},
			},
			ExpectedBefore:       provenance.ClassificationUnknown,
			ExpectedAfter:        provenance.ClassificationThirdParty,
			ExpectedGate:         "accepted",
			ExpectedRes:          "gemini_search",
			ExpectedArtifactProv: "NOT_ESTABLISHED",
			AuthoritativeEv:      "Official project documentation from mongodb.com (ArtifactProvenance: NOT_ESTABLISHED)",
		},
		{
			CaseNumber:  4,
			Name:        "OfficialGithubTool",
			Description: "Application with official GitHub release checksum matching local SHA-256",
			Binaries: []ApplicationBinary{
				{
					Name:   "gh-tool.exe",
					Path:   `C:\Tools\gh-tool.exe`,
					SHA256: "4a2b9f1c7d8e3b5a6c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b",
					Inspection: provenance.BinaryMetadata{
						IsExecutable: true,
						IsSigned:     false,
					},
				},
			},
			ExpectedBefore:       provenance.ClassificationUnknown,
			ExpectedAfter:        provenance.ClassificationThirdParty,
			ExpectedGate:         "accepted",
			ExpectedRes:          "gemini_search",
			ExpectedArtifactProv: "MATCHED",
			AuthoritativeEv:      "Exact match against official GitHub release asset SHA-256 published by upstream project",
		},
		{
			CaseNumber:  5,
			Name:        "choco",
			Description: "Signed application filtered deterministically via valid external Authenticode certificate",
			Binaries: []ApplicationBinary{
				{
					Name:   "choco.exe",
					Path:   `C:\ProgramData\chocolatey\bin\choco.exe`,
					SHA256: "e3f1fe0728a8623fcb9e8003c4c8bf65d958045efac4714701b7f0501cfdbb13",
					Inspection: provenance.BinaryMetadata{
						IsExecutable:   true,
						IsSigned:       true,
						SignatureValid: true,
						CertSubject:    "Chocolatey Software, Inc",
						CertIssuer:     "DigiCert, Inc.",
					},
				},
			},
			ExpectedBefore:       provenance.ClassificationThirdParty, // Recognized deterministically via valid Authenticode!
			ExpectedAfter:        provenance.ClassificationThirdParty,
			ExpectedGate:         "bypassed",
			ExpectedRes:          "deterministic",
			ExpectedArtifactProv: "MATCHED",
			AuthoritativeEv:      "Cryptographic Authenticode certificate (Chocolatey Software, Inc)",
		},
		{
			CaseNumber:  6,
			Name:        "webm_encoder",
			Description: "Application with only weak search results",
			Binaries: []ApplicationBinary{
				{
					Name: "webm_encoder.exe",
					Path: `C:\Users\govin\.gemini\antigravity-ide\bin\webm_encoder.exe`,
					Inspection: provenance.BinaryMetadata{
						IsExecutable: true,
						IsSigned:     false,
					},
				},
			},
			ExpectedBefore:  provenance.ClassificationUnknown,
			ExpectedAfter:   provenance.ClassificationUnknown,
			ExpectedGate:    "rejected",
			ExpectedRes:     "gemini_inconclusive",
			AuthoritativeEv: "None (Search queries yield no authoritative vendor, release, or cryptographic evidence)",
		},
		{
			CaseNumber:  7,
			Name:        "ForumClaimedTool",
			Description: "Application with forum/blog/community claims",
			Binaries: []ApplicationBinary{
				{
					Name: "forum_tool.exe",
					Path: `C:\temp\forum_tool.exe`,
					Inspection: provenance.BinaryMetadata{
						IsExecutable: true,
						IsSigned:     false,
					},
				},
			},
			ExpectedBefore:  provenance.ClassificationUnknown,
			ExpectedAfter:   provenance.ClassificationUnknown,
			ExpectedGate:    "rejected",
			ExpectedRes:     "gemini_inconclusive",
			AuthoritativeEv: "None (Forum/community post claims rejected by Grounding Gate; lacks cryptographic/checksum proof)",
		},
		{
			CaseNumber:  8,
			Name:        "CompanyVideoTool",
			Description: "Company application containing third-party/open-source components",
			Binaries: []ApplicationBinary{
				{
					Name: "CompanyVideoTool.exe",
					Path: `C:\internal\CompanyVideoTool.exe`,
					Inspection: provenance.BinaryMetadata{
						IsExecutable: true,
						IsSigned:     false,
						Components:   []string{"FFmpeg", "OpenSSL", "libcurl"},
					},
				},
			},
			ExpectedBefore:  provenance.ClassificationUnknown,
			ExpectedAfter:   provenance.ClassificationUnknown,
			ExpectedGate:    "rejected",
			ExpectedRes:     "gemini_inconclusive",
			AuthoritativeEv: "None (Component identity cannot be equated with application ownership; unverified)",
		},
		{
			CaseNumber:  9,
			Name:        "SpoofedInternalApp",
			Description: "Company application with spoofed publisher/product strings",
			Binaries: []ApplicationBinary{
				{
					Name: "InternalApp.exe",
					Path: `C:\temp\InternalApp.exe`,
					Inspection: provenance.BinaryMetadata{
						IsExecutable: true,
						IsSigned:     false,
						CompanyName:  "Acme Enterprise",
						ProductName:  "Acme Core Tool",
					},
				},
			},
			ExpectedBefore:  provenance.ClassificationUnknown,
			ExpectedAfter:   provenance.ClassificationUnknown,
			ExpectedGate:    "rejected",
			ExpectedRes:     "gemini_inconclusive",
			AuthoritativeEv: "None (Unauthenticated PE VersionInfo metadata rejected as ownership proof)",
		},
		{
			CaseNumber:  10,
			Name:        "builder",
			Description: "Ambiguous executable where Gemini cannot establish provenance",
			Binaries: []ApplicationBinary{
				{
					Name: "builder.exe",
					Path: `C:\tools\builder.exe`,
					Inspection: provenance.BinaryMetadata{
						IsExecutable: true,
						IsSigned:     false,
					},
				},
			},
			ExpectedBefore:  provenance.ClassificationUnknown,
			ExpectedAfter:   provenance.ClassificationUnknown,
			ExpectedGate:    "rejected",
			ExpectedRes:     "gemini_inconclusive",
			AuthoritativeEv: "None (Name matches multiple disparate projects; release provenance cannot be established)",
		},
	}

	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			// Phase 1: Deterministic
			appBefore := &Application{
				Name:              tc.Name,
				PrimaryBinaryPath: tc.Binaries[0].Path,
				Binaries:          tc.Binaries,
			}
			bundleBefore := EvidenceBundle{
				AppName:       appBefore.Name,
				PrimaryBinary: tc.Binaries[0],
				Binaries:      tc.Binaries,
			}
			deterministicEngine.Decide(ctx, appBefore, bundleBefore)

			if appBefore.Classification != tc.ExpectedBefore {
				t.Fatalf("[%s Before] Expected %s, got %s", tc.Name, tc.ExpectedBefore, appBefore.Classification)
			}

			// Phase 2: Gemini Search Grounding
			appAfter := &Application{
				Name:              tc.Name,
				PrimaryBinaryPath: tc.Binaries[0].Path,
				Binaries:          tc.Binaries,
			}
			bundleAfter := EvidenceBundle{
				AppName:       appAfter.Name,
				PrimaryBinary: tc.Binaries[0],
				Binaries:      tc.Binaries,
			}
			geminiEngine.Decide(ctx, appAfter, bundleAfter)

			if appAfter.Classification != tc.ExpectedAfter {
				t.Fatalf("[%s After] Expected %s, got %s", tc.Name, tc.ExpectedAfter, appAfter.Classification)
			}
			if appAfter.ResolutionSource != tc.ExpectedRes {
				t.Fatalf("[%s ResolutionSource] Expected %s, got %s", tc.Name, tc.ExpectedRes, appAfter.ResolutionSource)
			}
			if tc.ExpectedArtifactProv != "" && appAfter.ArtifactProvenance != tc.ExpectedArtifactProv {
				t.Fatalf("[%s ArtifactProvenance] Expected %s, got %s", tc.Name, tc.ExpectedArtifactProv, appAfter.ArtifactProvenance)
			}

			t.Logf("Case %d (%s): Before=%s -> After=%s [Res=%s, Gate=%s, ArtifactProv=%s]",
				tc.CaseNumber, tc.Name, appBefore.Classification, appAfter.Classification, appAfter.ResolutionSource, tc.ExpectedGate, appAfter.ArtifactProvenance)
		})
	}
}

// corpusBenchmarkReasoner simulates Gemini with Google Search tool grounding on the benchmark cases.
type corpusBenchmarkReasoner struct{}

func (c *corpusBenchmarkReasoner) Name() string {
	return "gemini-3.5-flash-lite (search grounded)"
}

func (c *corpusBenchmarkReasoner) Analyze(ctx context.Context, bundle any) (ai.ReasoningResult, error) {
	eb, ok := bundle.(EvidenceBundle)
	if !ok {
		return ai.ReasoningResult{Classification: provenance.ClassificationUnknown}, nil
	}

	switch eb.AppName {
	case "Google Chrome":
		// Should never be reached in reality because deterministic Tier 1 early exits
		return ai.ReasoningResult{
			Classification:    provenance.ClassificationThirdParty,
			Publisher:         "Google LLC",
			ResearchPerformed: true,
		}, nil

	case "ffmpeg":
		return ai.ReasoningResult{
			Classification:    provenance.ClassificationThirdParty,
			Identity:          "FFmpeg",
			Publisher:         "FFmpeg Project",
			ResearchPerformed: true,
			Reasons:           []string{"Software identified as FFmpeg; authoritative documentation and project release corroborates third-party application"},
			EvidenceClaims: []ai.EvidenceClaim{
				{
					Claim:            "FFmpeg is an open source multimedia framework",
					Source:           "https://ffmpeg.org",
					SourceType:       "official",
					EvidenceStrength: "authoritative",
					Supports:         "identity",
				},
			},
			Sources: []string{
				"https://ffmpeg.org",
			},
		}, nil

	case "mongosh":
		return ai.ReasoningResult{
			Classification:    provenance.ClassificationThirdParty,
			Identity:          "mongosh",
			Publisher:         "MongoDB Inc.",
			ResearchPerformed: true,
			Reasons:           []string{"Identified as MongoDB Shell via official documentation and distribution"},
			EvidenceClaims: []ai.EvidenceClaim{
				{
					Claim:            "MongoDB Shell is developed by MongoDB Inc.",
					Source:           "https://www.mongodb.com/docs/mongodb-shell/",
					SourceType:       "official",
					EvidenceStrength: "authoritative",
					Supports:         "identity",
				},
			},
			Sources: []string{
				"https://www.mongodb.com/docs/mongodb-shell/",
			},
		}, nil

	case "OfficialGithubTool":
		hash := "4a2b9f1c7d8e3b5a6c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b"
		return ai.ReasoningResult{
			Classification:    provenance.ClassificationThirdParty,
			Identity:          "OfficialGithubTool",
			Publisher:         "GitHub Project",
			ResearchPerformed: true,
			Reasons:           []string{"Official GitHub release asset checksum matches on-disk binary SHA-256"},
			EvidenceClaims: []ai.EvidenceClaim{
				{
					Claim:            "Official release checksum matches sha256: " + hash,
					Source:           "https://github.com/project/tool/releases/v1.0.0/checksums.txt",
					SourceType:       "official",
					EvidenceStrength: "authoritative",
					Supports:         "provenance",
				},
			},
			Sources: []string{
				"https://github.com/project/tool/releases/v1.0.0/checksums.txt",
			},
		}, nil

	case "choco":
		return ai.ReasoningResult{
			Classification:    provenance.ClassificationThirdParty,
			Identity:          "Chocolatey",
			Publisher:         "Chocolatey Software, Inc",
			ResearchPerformed: true,
			Reasons:           []string{"Official vendor website and repository confirm Chocolatey Software, Inc is publisher"},
			EvidenceClaims: []ai.EvidenceClaim{
				{
					Claim:            "Chocolatey is officially published and signed by Chocolatey Software, Inc",
					Source:           "https://chocolatey.org",
					SourceType:       "official",
					EvidenceStrength: "authoritative",
					Supports:         "ownership",
				},
			},
			Sources: []string{
				"https://chocolatey.org",
				"https://github.com/chocolatey/choco",
			},
		}, nil

	case "webm_encoder":
		return ai.ReasoningResult{
			Classification:    provenance.ClassificationUnknown,
			ResearchPerformed: true,
			Reasons:           []string{"Web search yielded no authoritative project, publisher, or release checksums"},
		}, nil

	case "ForumClaimedTool":
		return ai.ReasoningResult{
			Classification:    provenance.ClassificationThirdParty,
			ResearchPerformed: true,
			Reasons:           []string{"Forum comment claimed this tool was made by vendor"},
			EvidenceClaims: []ai.EvidenceClaim{
				{
					Claim:            "Forum user stated this tool is commercial software",
					Source:           "https://forum.example.com/topic/456",
					SourceType:       "secondary",
					EvidenceStrength: "clue",
					Supports:         "identity",
				},
			},
		}, nil

	case "CompanyVideoTool":
		return ai.ReasoningResult{
			Classification:    provenance.ClassificationThirdParty,
			ResearchPerformed: true,
			Reasons:           []string{"Embedded strings match FFmpeg, OpenSSL, and libcurl"},
			EvidenceClaims: []ai.EvidenceClaim{
				{
					Claim:            "Binary contains FFmpeg and OpenSSL strings",
					Source:           "https://ffmpeg.org",
					SourceType:       "official",
					EvidenceStrength: "clue",
					Supports:         "identity",
				},
			},
		}, nil

	case "SpoofedInternalApp":
		return ai.ReasoningResult{
			Classification:    provenance.ClassificationUnknown,
			ResearchPerformed: true,
			Reasons:           []string{"Unauthenticated PE strings cannot establish company ownership without cryptographic cert"},
		}, nil

	case "builder":
		return ai.ReasoningResult{
			Classification:    provenance.ClassificationUnknown,
			ResearchPerformed: true,
			Reasons:           []string{"Executable name maps to multiple distinct public tools; provenance ambiguous"},
		}, nil

	default:
		return ai.ReasoningResult{
			Classification: provenance.ClassificationUnknown,
			Reasons:        []string{"Unresolved provenance"},
		}, nil
	}
}
