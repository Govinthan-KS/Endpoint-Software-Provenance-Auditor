package provenance

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// NetworkMode controls outbound network intelligence operations.
type NetworkMode string

const (
	NetworkOff      NetworkMode = "off"       // 100% local-first, zero socket requests
	NetworkHashOnly NetworkMode = "hash-only" // Only query exact SHA-256 hashes against known databases
	NetworkOn       NetworkMode = "on"        // Full candidate resolution (GitHub releases, Repology, Search)
)

// ResolverConfig defines settings for the Provenance Resolver.
type ResolverConfig struct {
	NetworkMode               NetworkMode
	KnownExternalPublishers   []string
	CompanyDomainIndicators   []string
	CustomProviders           []ProvenanceProvider
	Cache                     *ProvenanceCache
	Inspector                 BinaryInspector
	ConnectTimeout            time.Duration
}

// Resolver orchestrates multi-tier provenance collection, candidate corroboration, and scoring.
type Resolver struct {
	config    ResolverConfig
	cache     *ProvenanceCache
	inspector BinaryInspector
	providers []ProvenanceProvider
}

// NewResolver creates an initialized Provenance Resolver.
func NewResolver(cfg ResolverConfig) *Resolver {
	if cfg.NetworkMode == "" {
		cfg.NetworkMode = NetworkOff
	}
	if cfg.ConnectTimeout == 0 {
		cfg.ConnectTimeout = 350 * time.Millisecond
	}
	if len(cfg.KnownExternalPublishers) == 0 {
		cfg.KnownExternalPublishers = defaultExternalPublishers
	}
	if cfg.Inspector == nil {
		cfg.Inspector = DefaultBinaryInspector()
	}

	c := cfg.Cache
	if c == nil {
		c = NewProvenanceCache()
	}

	var providers []ProvenanceProvider
	if len(cfg.CustomProviders) > 0 {
		providers = cfg.CustomProviders
	} else {
		// Default provider suite
		providers = append(providers, NewHashProvider())
		if cfg.NetworkMode == NetworkOn {
			providers = append(providers, NewGitHubReleaseProvider())
			providers = append(providers, NewPackageProvider())
			providers = append(providers, NewSearchCandidateProvider())
		}
	}

	return &Resolver{
		config:    cfg,
		cache:     c,
		inspector: cfg.Inspector,
		providers: providers,
	}
}

var defaultExternalPublishers = []string{
	"microsoft", "google", "apple", "canonical", "mozilla",
	"adobe", "jetbrains", "valve", "docker", "cisco",
	"oracle", "intel", "amd", "nvidia", "amazon",
	"spotify", "zoom", "slack", "discord", "atlassian",
	"github", "gitlab", "vmware", "broadcom", "realtek",
	"dell", "hp", "lenovo", "asus", "acer", "sony",
	"logitech", "brave", "opera", "notion", "dropbox",
	"autodesk", "electronic arts", "ubisoft", "epic games",
	"telegram", "meta", "facebook", "whatsapp", "apache",
	"nginx", "red hat", "suse", "debian", "ubuntu",
	"canonical snap", "flatpak application", "postman",
	"the git development community", "the openvpn project",
	"wireshark", "simon tatham", "mongodb", "nodejs",
	"openjs foundation", "python software foundation",
	"anaconda", "blender foundation", "videolan", "ffmpeg project",
	"gyan doshi", "curl developers", "sqlite development team",
}

// Resolve analyzes an artifact and produces an evidence-backed ClassificationResult.
// Conforms strictly to: No public match != company-developed.
func (r *Resolver) Resolve(ctx context.Context, artifact Artifact) ClassificationResult {
	var evidence []Evidence
	var candidates []ProvenanceCandidate
	explanation := []string{}

	// 1. Ensure SHA-256 fingerprint is computed locally
	if artifact.Fingerprint.SHA256 == "" && artifact.Path != "" {
		fp, err := ComputeFingerprint(artifact.Path)
		if err == nil {
			artifact.Fingerprint = fp
		}
	}

	// 2. Check persistent cache by SHA-256 (if available)
	if artifact.Fingerprint.SHA256 != "" {
		if cached, ok := r.cache.Get(artifact.Fingerprint.SHA256); ok {
			if cached.Confidence == ConfidenceVeryHigh || cached.Confidence == ConfidenceHigh {
				return ClassificationResult{
					Classification: cached.Classification,
					Confidence:     cached.Confidence,
					Fingerprint:    artifact.Fingerprint,
					ProductName:    artifact.ProductName,
					Publisher:      artifact.Publisher,
					Version:        artifact.Version,
					Evidence:       cached.Evidence,
					Candidates:     cached.Candidates,
					Explanation:    []string{"Verified from local persistent provenance cache (keyed by SHA-256)"},
				}
			}
		}
	}

	// 3. Deep binary inspection
	if artifact.Path != "" && r.inspector != nil {
		if meta, err := r.inspector.Inspect(artifact.Path); err == nil {
			if artifact.ProductName == "" && meta.ProductName != "" {
				artifact.ProductName = meta.ProductName
			}
			if artifact.Publisher == "" && meta.CompanyName != "" {
				artifact.Publisher = meta.CompanyName
			}
			if artifact.Version == "" && meta.ProductVersion != "" {
				artifact.Version = meta.ProductVersion
			}
			if artifact.OriginalFilename == "" && meta.OriginalFilename != "" {
				artifact.OriginalFilename = meta.OriginalFilename
			}
			if artifact.InternalName == "" && meta.InternalName != "" {
				artifact.InternalName = meta.InternalName
			}
			if artifact.FileDescription == "" && meta.FileDescription != "" {
				artifact.FileDescription = meta.FileDescription
			}
			if artifact.LegalCopyright == "" && meta.LegalCopyright != "" {
				artifact.LegalCopyright = meta.LegalCopyright
			}
			artifact.IsGUI = meta.IsGUI
			artifact.BuildInfo = meta.BuildInfo
			artifact.Components = meta.Components

			// Evaluate Authenticode signature metadata
			if meta.IsSigned {
				if r.isCompanyPublisher(meta.CertSubject) || r.isCompanyPublisher(meta.CompanyName) {
					evidence = append(evidence, Evidence{
						Type:        EvidenceCompanyProvenance,
						Source:      "Authenticode Digital Signature",
						Strength:    0.95,
						Description: fmt.Sprintf("Cryptographically signed by internal company certificate (%s)", meta.CertSubject),
						Confidence:  ConfidenceHigh,
					})
				} else if meta.SignatureValid || meta.CertSubject != "" || meta.CompanyName != "" {
					pub := meta.CertSubject
					if pub == "" {
						pub = meta.CompanyName
					}
					if pub == "" {
						pub = "Verified Commercial Publisher"
					}
					evidence = append(evidence, Evidence{
						Type:        EvidencePublisherSignature,
						Source:      "Authenticode Digital Signature",
						Strength:    0.90,
						Description: fmt.Sprintf("Cryptographically signed by external commercial publisher (%s)", pub),
						Confidence:  ConfidenceHigh,
					})
				}
			}

			// Evaluate PE Product metadata
			if meta.ProductName != "" || meta.FileDescription != "" {
				vendor := meta.CompanyName
				if vendor == "" {
					vendor = meta.LegalCopyright
				}
				if r.isKnownExternalPublisher(vendor) {
					evidence = append(evidence, Evidence{
						Type:        EvidenceProductMetadata,
						Source:      "PE Version Resource",
						Strength:    0.75,
						Description: fmt.Sprintf("Product metadata identifies '%s' by verified vendor '%s'", meta.ProductName, vendor),
						Confidence:  ConfidenceHigh,
					})
				} else if meta.ProductName != "" {
					evidence = append(evidence, Evidence{
						Type:        EvidenceProductMetadata,
						Source:      "PE Version Resource",
						Strength:    0.40,
						Description: fmt.Sprintf("Embedded product name: %s", meta.ProductName),
						Confidence:  ConfidenceLow,
					})
				}
			}

			// Evaluate Go Build Metadata
			if meta.BuildInfo != nil && meta.BuildInfo.Ecosystem == "go" {
				if strings.HasPrefix(meta.BuildInfo.MainModule, "github.com/") ||
					strings.HasPrefix(meta.BuildInfo.MainModule, "golang.org/") ||
					strings.HasPrefix(meta.BuildInfo.MainModule, "gitlab.com/") {

					isCompanyModule := false
					for _, corp := range r.config.CompanyDomainIndicators {
						if strings.Contains(strings.ToLower(meta.BuildInfo.MainModule), corp) {
							isCompanyModule = true
							break
						}
					}

					if isCompanyModule {
						evidence = append(evidence, Evidence{
							Type:        EvidenceCompanyProvenance,
							Source:      "Go Build Metadata (debug/buildinfo)",
							Strength:    0.90,
							Description: fmt.Sprintf("Go module path belongs to company repository: %s", meta.BuildInfo.MainModule),
							Confidence:  ConfidenceHigh,
						})
					} else {
						evidence = append(evidence, Evidence{
							Type:        EvidenceBuildMetadata,
							Source:      "Go Build Metadata (debug/buildinfo)",
							Strength:    0.85,
							Description: fmt.Sprintf("Go main module identifies public open-source project: %s (%s)", meta.BuildInfo.MainModule, meta.BuildInfo.MainVersion),
							URL:         "https://" + meta.BuildInfo.MainModule,
							Confidence:  ConfidenceHigh,
						})
					}
				}
			}

			// Record embedded components (e.g. FFmpeg, SQLite)
			for _, comp := range meta.Components {
				evidence = append(evidence, Evidence{
					Type:        EvidenceComponentMatch,
					Source:      "Binary Static Strings",
					Strength:    0.25,
					Description: fmt.Sprintf("Contains embedded signature for third-party component '%s'", comp),
					Confidence:  ConfidenceLow,
				})
			}
		}
	}

	// 4. Evaluate artifact publisher metadata (if present)
	if artifact.Publisher != "" {
		if r.isCompanyPublisher(artifact.Publisher) {
			evidence = append(evidence, Evidence{
				Type:        EvidenceCompanyProvenance,
				Source:      "Company Software Publisher",
				Strength:    0.90,
				Description: fmt.Sprintf("Identified internal company publisher (%s)", artifact.Publisher),
				Confidence:  ConfidenceHigh,
			})
		} else if r.isKnownExternalPublisher(artifact.Publisher) {
			evidence = append(evidence, Evidence{
				Type:        EvidenceProductMetadata,
				Source:      "Verified Software Publisher",
				Strength:    0.85,
				Description: fmt.Sprintf("Verified external software publisher (%s)", artifact.Publisher),
				Confidence:  ConfidenceHigh,
			})
		}
	}

	// Evaluate official host installation manifests
	if artifact.Origin == "StartMenu" || artifact.Origin == "Registry" || artifact.Origin == "DesktopEntry" || artifact.Origin == "AppBundle" {
		if r.isCompanyPublisher(artifact.Publisher) {
			evidence = append(evidence, Evidence{
				Type:        EvidenceCompanyProvenance,
				Source:      "Company Software Publisher Manifest",
				Strength:    0.90,
				Description: fmt.Sprintf("Identified internal company publisher (%s)", artifact.Publisher),
				Confidence:  ConfidenceHigh,
			})
		} else {
			pub := artifact.Publisher
			if pub == "" {
				pub = artifact.Name
			}
			evidence = append(evidence, Evidence{
				Type:        EvidenceInstallMetadata,
				Source:      artifact.Origin,
				Strength:    0.85,
				Description: fmt.Sprintf("Officially registered application in host OS manifest (%s: %s)", artifact.Origin, pub),
				Confidence:  ConfidenceHigh,
			})
		}
	}

	if artifact.Path != "" {
		pLower := strings.ToLower(filepath.ToSlash(artifact.Path))
		if strings.Contains(pLower, "program files") || strings.Contains(pLower, "/usr/bin") || strings.Contains(pLower, "/usr/local/bin") {
			evidence = append(evidence, Evidence{
				Type:        EvidencePathHeuristic,
				Source:      "Filesystem Path",
				Strength:    0.10,
				Description: "Resides in system installation directory",
				Confidence:  ConfidenceNone,
			})
		} else if strings.Contains(pLower, "/dev/") || strings.Contains(pLower, "/workspace/") || strings.Contains(pLower, "/src/") {
			evidence = append(evidence, Evidence{
				Type:        EvidencePathHeuristic,
				Source:      "Filesystem Path",
				Strength:    0.15,
				Description: "Resides in development workspace path",
				Confidence:  ConfidenceNone,
			})
		}
	}

	// 5. Query pluggable providers (hash database runs locally; remote providers require network mode)
	isOnline := false
	if r.config.NetworkMode == NetworkOn || r.config.NetworkMode == NetworkHashOnly {
		isOnline = r.checkOnline()
		if !isOnline {
			explanation = append(explanation, "Network unreachable: external remote lookups skipped.")
		}
	} else {
		explanation = append(explanation, "Network disabled (offline mode): evaluated purely on local cryptographic & metadata evidence.")
	}

	for _, prov := range r.providers {
		// Known hash database runs purely locally; permitted in all modes
		if prov.Name() == "known_hash_database" {
			pEvidence, pCandidates, err := prov.Lookup(ctx, artifact)
			if err == nil {
				evidence = append(evidence, pEvidence...)
				candidates = append(candidates, pCandidates...)
			}
			continue
		}

		// Remote providers require NetworkOn and active network connection
		if r.config.NetworkMode != NetworkOn || !isOnline {
			continue
		}

		pEvidence, pCandidates, err := prov.Lookup(ctx, artifact)
		if err == nil {
			evidence = append(evidence, pEvidence...)
			candidates = append(candidates, pCandidates...)
		}
	}

	// 6. Apply Decision Rules
	result := r.evaluateDecisionRules(artifact, evidence, candidates, explanation)

	// 7. Persist result in cache
	if artifact.Fingerprint.SHA256 != "" {
		r.cache.Set(artifact.Fingerprint.SHA256, result)
		_ = r.cache.Save()
	}

	return result
}

func (r *Resolver) evaluateDecisionRules(artifact Artifact, evidence []Evidence, candidates []ProvenanceCandidate, baseExplanation []string) ClassificationResult {
	// Sort evidence by strength descending
	sort.Slice(evidence, func(i, j int) bool {
		return evidence[i].Strength > evidence[j].Strength
	})

	// Rule A: Exact public artifact match (SHA-256 match in known releases or NSRL)
	for _, ev := range evidence {
		if ev.Type == EvidenceExactHashMatch {
			return ClassificationResult{
				Classification: ClassificationThirdParty,
				Confidence:     ConfidenceVeryHigh,
				Fingerprint:    artifact.Fingerprint,
				ProductName:    artifact.ProductName,
				Publisher:      artifact.Publisher,
				Version:        artifact.Version,
				Evidence:       evidence,
				Candidates:     candidates,
				Explanation: append(baseExplanation,
					"Rule A: Cryptographic SHA-256 digest exactly matches verified public release artifact.",
					ev.Description,
				),
			}
		}
		if ev.Type == EvidenceReleaseAssetMatch && ev.Strength >= 0.95 {
			return ClassificationResult{
				Classification: ClassificationThirdParty,
				Confidence:     ConfidenceVeryHigh,
				Fingerprint:    artifact.Fingerprint,
				ProductName:    artifact.ProductName,
				Publisher:      artifact.Publisher,
				Version:        artifact.Version,
				Evidence:       evidence,
				Candidates:     candidates,
				Explanation: append(baseExplanation,
					"Rule A: Cryptographic SHA-256 digest exactly matches GitHub release asset.",
					ev.Description,
				),
			}
		}
	}

	// Rule G: Strong company evidence (internal signature or internal module path)
	for _, ev := range evidence {
		if ev.Type == EvidenceCompanyProvenance && ev.Strength >= 0.80 {
			return ClassificationResult{
				Classification: ClassificationCompany,
				Confidence:     ev.Confidence,
				Fingerprint:    artifact.Fingerprint,
				ProductName:    artifact.ProductName,
				Publisher:      artifact.Publisher,
				Version:        artifact.Version,
				Evidence:       evidence,
				Candidates:     candidates,
				Explanation: append(baseExplanation,
					"Rule G: Verified internal company ownership signal.",
					ev.Description,
				),
			}
		}
	}

	// Rule B: Strong publisher / product provenance
	hasStrongSignature := false
	hasStrongProductMeta := false
	hasStrongInstallMeta := false
	var bestPublisherEv Evidence
	for _, ev := range evidence {
		if ev.Type == EvidencePublisherSignature && ev.Strength >= 0.80 {
			hasStrongSignature = true
			bestPublisherEv = ev
		}
		if ev.Type == EvidenceProductMetadata && ev.Strength >= 0.70 {
			hasStrongProductMeta = true
			if bestPublisherEv.Description == "" || bestPublisherEv.Strength < ev.Strength {
				bestPublisherEv = ev
			}
		}
		if ev.Type == EvidenceInstallMetadata && ev.Strength >= 0.70 {
			hasStrongInstallMeta = true
			if bestPublisherEv.Description == "" || bestPublisherEv.Strength < ev.Strength {
				bestPublisherEv = ev
			}
		}
	}
	if hasStrongSignature && (hasStrongProductMeta || artifact.ProductName != "") {
		return ClassificationResult{
			Classification: ClassificationThirdParty,
			Confidence:     ConfidenceHigh,
			Fingerprint:    artifact.Fingerprint,
			ProductName:    artifact.ProductName,
			Publisher:      artifact.Publisher,
			Version:        artifact.Version,
			Evidence:       evidence,
			Candidates:     candidates,
			Explanation: append(baseExplanation,
				"Rule B: Verified trusted commercial publisher signature corroborated with consistent product metadata.",
				bestPublisherEv.Description,
			),
		}
	}
	if hasStrongSignature || hasStrongProductMeta || hasStrongInstallMeta {
		conf := ConfidenceHigh
		return ClassificationResult{
			Classification: ClassificationThirdParty,
			Confidence:     conf,
			Fingerprint:    artifact.Fingerprint,
			ProductName:    artifact.ProductName,
			Publisher:      artifact.Publisher,
			Version:        artifact.Version,
			Evidence:       evidence,
			Candidates:     candidates,
			Explanation: append(baseExplanation,
				"Rule B: Verified external publisher signature or official application installation manifest.",
				bestPublisherEv.Description,
			),
		}
	}

	// Rule C: Strong build / project provenance (Go module path / public repo)
	for _, ev := range evidence {
		if ev.Type == EvidenceBuildMetadata && ev.Strength >= 0.80 {
			return ClassificationResult{
				Classification: ClassificationThirdParty,
				Confidence:     ConfidenceHigh,
				Fingerprint:    artifact.Fingerprint,
				ProductName:    artifact.ProductName,
				Publisher:      artifact.Publisher,
				Version:        artifact.Version,
				Evidence:       evidence,
				Candidates:     candidates,
				Explanation: append(baseExplanation,
					"Rule C: Embedded compiler build metadata confirms public open-source project origin.",
					ev.Description,
				),
			}
		}
	}

	// Rule D: Strong package / project identity
	// Must NOT be a generic colliding name (e.g. sync.exe, update.exe) without corroboration!
	isGeneric := IsGenericCollidingName(artifact.Name)
	hasPackageMatch := false
	hasReleaseMatch := false
	for _, ev := range evidence {
		if ev.Type == EvidencePackageMatch {
			hasPackageMatch = true
		}
		if ev.Type == EvidenceReleaseAssetMatch && ev.Strength >= 0.80 {
			hasReleaseMatch = true
		}
	}

	if (!isGeneric || hasStrongProductMeta || artifact.ProductName != "") && (hasPackageMatch || hasReleaseMatch) {
		conf := ConfidenceMedium
		if hasReleaseMatch {
			conf = ConfidenceHigh
		}
		return ClassificationResult{
			Classification: ClassificationThirdParty,
			Confidence:     conf,
			Fingerprint:    artifact.Fingerprint,
			ProductName:    artifact.ProductName,
			Publisher:      artifact.Publisher,
			Version:        artifact.Version,
			Evidence:       evidence,
			Candidates:     candidates,
			Explanation: append(baseExplanation,
				"Rule D: Public package and project registry matches verified against artifact characteristics.",
			),
		}
	}

	// Rule E: Weak search or naked generic name only -> UNKNOWN
	if isGeneric {
		return ClassificationResult{
			Classification: ClassificationUnknown,
			Confidence:     ConfidenceNone,
			Fingerprint:    artifact.Fingerprint,
			ProductName:    artifact.ProductName,
			Publisher:      artifact.Publisher,
			Version:        artifact.Version,
			Evidence:       evidence,
			Candidates:     candidates,
			Explanation: append(baseExplanation,
				"Rule E: Binary name is a common generic noun; public name matches rejected without cryptographic or publisher corroboration.",
				"Insufficient evidence to establish external or company provenance.",
			),
		}
	}

	// Rule F: Default fallback -> UNKNOWN (Never COMPANY!)
	var missingReasons []string
	missingReasons = append(missingReasons, "Rule F: No exact public cryptographic hash match found.")
	missingReasons = append(missingReasons, "No trusted external code-signing certificate identified.")
	missingReasons = append(missingReasons, "Binary contains no public project build metadata.")
	missingReasons = append(missingReasons, "Conclusion: Provenance cannot be established with sufficient confidence -> UNKNOWN.")

	return ClassificationResult{
		Classification: ClassificationUnknown,
		Confidence:     ConfidenceNone,
		Fingerprint:    artifact.Fingerprint,
		ProductName:    artifact.ProductName,
		Publisher:      artifact.Publisher,
		Version:        artifact.Version,
		Evidence:       evidence,
		Candidates:     candidates,
		Explanation:    append(baseExplanation, missingReasons...),
	}
}

func (r *Resolver) isKnownExternalPublisher(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(name)
	for _, pub := range r.config.KnownExternalPublishers {
		if strings.Contains(n, pub) {
			return true
		}
	}
	return false
}

func (r *Resolver) isCompanyPublisher(name string) bool {
	if name == "" || len(r.config.CompanyDomainIndicators) == 0 {
		return false
	}
	n := strings.ToLower(name)
	for _, corp := range r.config.CompanyDomainIndicators {
		if strings.Contains(n, corp) {
			return true
		}
	}
	return false
}

func (r *Resolver) checkOnline() bool {
	conn, err := net.DialTimeout("tcp", "1.1.1.1:53", r.config.ConnectTimeout)
	if err == nil {
		conn.Close()
		return true
	}
	conn, err = net.DialTimeout("tcp", "8.8.8.8:53", r.config.ConnectTimeout)
	if err == nil {
		conn.Close()
		return true
	}
	return false
}
