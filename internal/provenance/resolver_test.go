package provenance

import (
	"context"
	"path/filepath"
	"testing"
)

// mockInspector allows injecting mock binary metadata for testing.
type mockInspector struct {
	meta BinaryMetadata
}

func (m *mockInspector) Inspect(path string) (BinaryMetadata, error) {
	return m.meta, nil
}

func TestResolver_RuleA_ExactHashMatch(t *testing.T) {
	hashProvider := NewHashProvider()
	hashProvider.Register("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", KnownHashRecord{
		Product:   "OpenSourceTool",
		Version:   "1.0.0",
		Publisher: "Community",
		Source:    "NIST NSRL",
	})

	r := NewResolver(ResolverConfig{
		NetworkMode:     NetworkOff,
		CustomProviders: []ProvenanceProvider{hashProvider},
	})

	art := Artifact{
		Name: "testtool.exe",
		Fingerprint: Fingerprint{
			SHA256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			Size:   1024,
		},
	}

	res := r.Resolve(context.Background(), art)

	if res.Classification != ClassificationThirdParty {
		t.Fatalf("Expected THIRD_PARTY, got %s", res.Classification)
	}
	if res.Confidence != ConfidenceVeryHigh {
		t.Fatalf("Expected VERY_HIGH confidence, got %s", res.Confidence)
	}
	if len(res.Evidence) == 0 || res.Evidence[0].Type != EvidenceExactHashMatch {
		t.Fatalf("Expected EvidenceExactHashMatch as primary evidence")
	}
}

func TestResolver_FFmpegEssentials_Benchmark(t *testing.T) {
	// Verifies that FFmpeg Essentials with product metadata and known public release hash
	// resolves to THIRD_PARTY with high confidence and complete evidence chain.
	hashProvider := NewHashProvider()
	r := NewResolver(ResolverConfig{
		NetworkMode:     NetworkOff,
		Cache:           NewProvenanceCache(filepath.Join(t.TempDir(), "cache.json")),
		CustomProviders: []ProvenanceProvider{hashProvider},
		Inspector: &mockInspector{
			meta: BinaryMetadata{
				ProductName:     "FFmpeg",
				CompanyName:     "Gyan Doshi",
				FileDescription: "FFmpeg command line tool",
				ProductVersion:  "7.0",
			},
		},
	})

	art := Artifact{
		Name: "ffmpeg.exe",
		Path: `C:\Tools\ffmpeg\bin\ffmpeg.exe`,
		Fingerprint: Fingerprint{
			SHA256: "372132174c804b3dae27da1d598e096238b975e533ca6ee6b683ef0e4c62d085",
			Size:   125000000,
		},
	}

	res := r.Resolve(context.Background(), art)

	if res.Classification != ClassificationThirdParty {
		t.Fatalf("Expected THIRD_PARTY for FFmpeg, got %s", res.Classification)
	}
	if res.Confidence != ConfidenceVeryHigh {
		t.Fatalf("Expected VERY_HIGH confidence for exact hash match, got %s", res.Confidence)
	}
	if res.ProductName != "FFmpeg" {
		t.Fatalf("Expected ProductName FFmpeg, got %s", res.ProductName)
	}

	hasHashEvidence := false
	for _, ev := range res.Evidence {
		if ev.Type == EvidenceExactHashMatch {
			hasHashEvidence = true
			break
		}
	}
	if !hasHashEvidence {
		t.Fatalf("Expected EvidenceExactHashMatch in evidence chain")
	}
}

func TestResolver_GenericFilenameCollisions(t *testing.T) {
	// Generic names must NEVER be classified as third-party solely from filename.
	genericNames := []string{
		"sync.exe",
		"update.exe",
		"helper.exe",
		"agent.exe",
		"runner.exe",
		"audit.exe",
		"service.exe",
		"manager.exe",
	}

	r := NewResolver(ResolverConfig{
		NetworkMode: NetworkOff,
	})

	for _, name := range genericNames {
		t.Run(name, func(t *testing.T) {
			art := Artifact{
				Name: name,
				Path: filepath.Join(`C:\Tools`, name),
			}

			res := r.Resolve(context.Background(), art)

			if res.Classification != ClassificationUnknown {
				t.Fatalf("Expected UNKNOWN for generic name %q without corroboration, got %s", name, res.Classification)
			}
			if res.Confidence != ConfidenceNone {
				t.Fatalf("Expected NONE confidence for %q, got %s", name, res.Confidence)
			}
		})
	}
}

func TestResolver_RuleB_StrongPublisher(t *testing.T) {
	r := NewResolver(ResolverConfig{
		NetworkMode: NetworkOff,
		Inspector: &mockInspector{
			meta: BinaryMetadata{
				IsSigned:       true,
				SignatureValid: true,
				CertSubject:    "Microsoft Corporation",
				CertIssuer:     "Microsoft Code Signing PCA",
				ProductName:    "Sysinternals Suite",
				CompanyName:    "Microsoft Corporation",
			},
		},
	})

	art := Artifact{
		Name: "procexp.exe",
		Path: `C:\Tools\procexp.exe`,
	}

	res := r.Resolve(context.Background(), art)

	if res.Classification != ClassificationThirdParty {
		t.Fatalf("Expected THIRD_PARTY, got %s", res.Classification)
	}
	if res.Confidence != ConfidenceHigh {
		t.Fatalf("Expected HIGH confidence, got %s", res.Confidence)
	}
	if res.Publisher != "Microsoft Corporation" {
		t.Fatalf("Expected publisher Microsoft Corporation, got %s", res.Publisher)
	}
}

func TestResolver_RuleC_GoBuildMetadata(t *testing.T) {
	r := NewResolver(ResolverConfig{
		NetworkMode: NetworkOff,
		Inspector: &mockInspector{
			meta: BinaryMetadata{
				BuildInfo: &BuildMetadata{
					Ecosystem:   "go",
					GoVersion:   "go1.22.0",
					MainModule:  "github.com/junegunn/fzf",
					MainVersion: "v0.48.0",
				},
			},
		},
	})

	art := Artifact{
		Name: "fzf.exe",
		Path: `C:\Tools\fzf.exe`,
	}

	res := r.Resolve(context.Background(), art)

	if res.Classification != ClassificationThirdParty {
		t.Fatalf("Expected THIRD_PARTY, got %s", res.Classification)
	}
	if res.Confidence != ConfidenceHigh {
		t.Fatalf("Expected HIGH confidence for public Go module, got %s", res.Confidence)
	}
}

func TestResolver_RuleG_CompanyProvenance(t *testing.T) {
	r := NewResolver(ResolverConfig{
		NetworkMode:             NetworkOff,
		CompanyDomainIndicators: []string{"mycorp.internal", "mycorp.com"},
		Inspector: &mockInspector{
			meta: BinaryMetadata{
				BuildInfo: &BuildMetadata{
					Ecosystem:  "go",
					MainModule: "github.com/mycorp.internal/platform/deploy-agent",
				},
			},
		},
	})

	art := Artifact{
		Name: "deploy-agent.exe",
		Path: `C:\Internal\deploy-agent.exe`,
	}

	res := r.Resolve(context.Background(), art)

	if res.Classification != ClassificationCompany {
		t.Fatalf("Expected COMPANY, got %s", res.Classification)
	}
	if res.Confidence != ConfidenceHigh {
		t.Fatalf("Expected HIGH confidence for company module, got %s", res.Confidence)
	}
}

func TestResolver_RuleF_NoEvidenceIsUnknown(t *testing.T) {
	// Critical rule: Absence of public match NEVER proves COMPANY.
	r := NewResolver(ResolverConfig{
		NetworkMode: NetworkOff,
	})

	art := Artifact{
		Name: "proprietary_mystery.exe",
		Path: `C:\Custom\proprietary_mystery.exe`,
	}

	res := r.Resolve(context.Background(), art)

	if res.Classification != ClassificationUnknown {
		t.Fatalf("Expected UNKNOWN when no evidence exists, got %s", res.Classification)
	}
	if res.Confidence != ConfidenceNone {
		t.Fatalf("Expected NONE confidence, got %s", res.Confidence)
	}
}

func TestResolver_ProgramFilesPathOnlyIsUnknown(t *testing.T) {
	// Program Files alone is WEAK evidence and does NOT establish classification.
	r := NewResolver(ResolverConfig{
		NetworkMode: NetworkOff,
	})

	art := Artifact{
		Name: "unregistered.exe",
		Path: `C:\Program Files\UnknownVendor\unregistered.exe`,
	}

	res := r.Resolve(context.Background(), art)

	if res.Classification != ClassificationUnknown {
		t.Fatalf("Expected UNKNOWN for path-only heuristic, got %s", res.Classification)
	}
}

func TestResolver_UnregisteredBinaryWithoutEvidenceIsUnknown(t *testing.T) {
	// An unmapped binary on disk without manifest registration, publisher, or signature is UNKNOWN.
	r := NewResolver(ResolverConfig{
		NetworkMode: NetworkOff,
	})

	art := Artifact{
		Name:   "InternalSuite.exe",
		Path:   `C:\Tools\InternalSuite.exe`,
		Origin: "Path",
	}

	res := r.Resolve(context.Background(), art)

	if res.Classification != ClassificationUnknown {
		t.Fatalf("Expected UNKNOWN for unregistered binary without evidence, got %s", res.Classification)
	}
}

func TestResolver_RegisteredManifestResolvesThirdParty(t *testing.T) {
	r := NewResolver(ResolverConfig{
		NetworkMode: NetworkOff,
	})

	art := Artifact{
		Name:   "RegisteredApp.exe",
		Path:   `C:\Program Files\Vendor\RegisteredApp.exe`,
		Origin: "StartMenu",
	}

	res := r.Resolve(context.Background(), art)

	if res.Classification != ClassificationThirdParty {
		t.Fatalf("Expected THIRD_PARTY for registered application, got %s", res.Classification)
	}
	if res.Confidence != ConfidenceHigh {
		t.Fatalf("Expected HIGH confidence for registered application, got %s", res.Confidence)
	}
}

func TestResolver_CacheHitBySHA256(t *testing.T) {
	tempDir := t.TempDir()
	cache := NewProvenanceCache(filepath.Join(tempDir, "cache.json"))

	testHash := "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
	cache.Set(testHash, ClassificationResult{
		Classification: ClassificationThirdParty,
		Confidence:     ConfidenceHigh,
		Evidence: []Evidence{
			{
				Type:        EvidenceReleaseAssetMatch,
				Source:      "Cached GitHub Release",
				Strength:    0.90,
				Description: "Verified release asset in cache",
				Confidence:  ConfidenceHigh,
			},
		},
	})

	r := NewResolver(ResolverConfig{
		NetworkMode: NetworkOff,
		Cache:       cache,
	})

	art := Artifact{
		Name: "tool.exe",
		Fingerprint: Fingerprint{
			SHA256: testHash,
		},
	}

	res := r.Resolve(context.Background(), art)

	if res.Classification != ClassificationThirdParty {
		t.Fatalf("Expected THIRD_PARTY from cache, got %s", res.Classification)
	}
	if res.Confidence != ConfidenceHigh {
		t.Fatalf("Expected HIGH confidence from cache, got %s", res.Confidence)
	}
}
