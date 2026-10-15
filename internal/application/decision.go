package application

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"sync"

	"github.com/example/appaudit/internal/ai"
	"github.com/example/appaudit/internal/provenance"
)

// DecisionEngine performs multi-tier evidence fusion, identity attribution, and ownership classification.
type DecisionEngine struct {
	CompanyIndicators []string
	KnownPublishers   []string
	CompanyManifest   *CompanyManifest
	Reasoner          ai.Reasoner
	HashLookupClient  *provenance.HashLookupClient
	NetworkMode       provenance.NetworkMode
	tier1Hits         int
	tier15AHits       int
	tier15BHits       int
	tier2Hits         int
	statsMu           sync.Mutex
}

// NewDecisionEngine creates an initialized decision engine.
func NewDecisionEngine(companyIndicators []string, knownPublishers []string, reasoner ai.Reasoner, hashLookup ...*provenance.HashLookupClient) *DecisionEngine {
	if reasoner == nil {
		reasoner = ai.NewNoopReasoner()
	}
	manifest, _ := LoadCompanyManifest()
	var hlClient *provenance.HashLookupClient
	if len(hashLookup) > 0 && hashLookup[0] != nil {
		hlClient = hashLookup[0]
	} else {
		hlClient = provenance.NewHashLookupClient()
	}
	return &DecisionEngine{
		CompanyIndicators: companyIndicators,
		KnownPublishers:   knownPublishers,
		CompanyManifest:   manifest,
		Reasoner:          reasoner,
		HashLookupClient:  hlClient,
	}
}

func (de *DecisionEngine) RecordTier1Hit() {
	de.statsMu.Lock()
	defer de.statsMu.Unlock()
	de.tier1Hits++
}

func (de *DecisionEngine) RecordTier15AHit() {
	de.statsMu.Lock()
	defer de.statsMu.Unlock()
	de.tier15AHits++
}

func (de *DecisionEngine) RecordTier15BHit() {
	de.statsMu.Lock()
	defer de.statsMu.Unlock()
	de.tier15BHits++
}

func (de *DecisionEngine) RecordTier2Hit() {
	de.statsMu.Lock()
	defer de.statsMu.Unlock()
	de.tier2Hits++
}

func (de *DecisionEngine) GetTriageStats() (tier1, tier15A, tier15B, tier2 int) {
	de.statsMu.Lock()
	defer de.statsMu.Unlock()
	return de.tier1Hits, de.tier15AHits, de.tier15BHits, de.tier2Hits
}

// Decide evaluates an Application and its aggregated EvidenceBundle to determine final ownership.
func (de *DecisionEngine) Decide(ctx context.Context, app *Application, bundle EvidenceBundle) {
	if app.ReadError != "" || bundle.ReadError != "" {
		errStr := app.ReadError
		if errStr == "" {
			errStr = bundle.ReadError
		}
		app.Classification = provenance.ClassificationUnknown
		app.Confidence = provenance.ConfidenceNone
		app.ResolutionSource = "File Inspection Failed"
		app.Reasons = []string{"Inspection halted: " + errStr}
		app.EvidenceSummary = errStr
		app.Conclusion = "Binary could not be read or parsed safely; withheld from AI and CIRCL lookup."
		return
	}

	identity := ResolveIdentity(bundle)
	app.Identity = identity
	if app.Name == "" || app.Name == app.PrimaryBinaryPath {
		app.Name = identity.Name
	}
	if app.Publisher == "" && identity.Publisher != "" {
		app.Publisher = identity.Publisher
	}
	if app.Version == "" && identity.Version != "" {
		app.Version = identity.Version
	}

	var ownershipEvidence []provenance.Evidence
	var identityEvidence []provenance.Evidence
	var reasons []string

	// TIER 1: Hard Deterministic Evidence

	// 1.0 Explicitly Registered Internal Company Manifest
	if compEv, ok := bundle.HasCompanyManifestMatch(de.CompanyManifest); ok {
		app.Classification = provenance.ClassificationCompany
		app.Confidence = provenance.ConfidenceVeryHigh
		app.ResolutionSource = "deterministic (Company Registry)"
		app.ArtifactProvenance = "MATCHED"
		ownershipEvidence = append(ownershipEvidence, compEv)
		reasons = append(reasons, "Tier 1 Hard Evidence: Explicitly registered internal company application.", compEv.Description)
		de.RecordTier1Hit()
		finalizeApp(app, identityEvidence, ownershipEvidence, reasons)
		return
	}

	// 1.1 Internal Company Code-Signing or Internal Go Module
	if compEv, ok := bundle.HasCompanySignature(de.CompanyIndicators); ok {
		app.Classification = provenance.ClassificationCompany
		app.Confidence = compEv.Confidence
		app.ResolutionSource = "deterministic"
		app.ArtifactProvenance = "MATCHED"
		ownershipEvidence = append(ownershipEvidence, compEv)
		reasons = append(reasons, "Tier 1 Hard Evidence: Verified internal company ownership signal.", compEv.Description)
		de.RecordTier1Hit()
		finalizeApp(app, identityEvidence, ownershipEvidence, reasons)
		return
	}

	// 1.2 Exact Cryptographic Hash Match (NSRL / Known Releases)
	if hashEv, ok := bundle.HasExactHashMatch(); ok {
		app.Classification = provenance.ClassificationThirdParty
		app.Confidence = provenance.ConfidenceVeryHigh
		app.ResolutionSource = "deterministic"
		app.ArtifactProvenance = "MATCHED"
		ownershipEvidence = append(ownershipEvidence, hashEv)
		reasons = append(reasons, "Tier 1 Hard Evidence: Cryptographic SHA-256 digest exactly matches verified public release artifact.", hashEv.Description)
		de.RecordTier1Hit()
		finalizeApp(app, identityEvidence, ownershipEvidence, reasons)
		return
	}

	// 1.3 Strong Verified External Code-Signing Signature
	if sigEv, ok := bundle.HasExternalSignature(de.CompanyIndicators); ok {
		app.Classification = provenance.ClassificationThirdParty
		app.Confidence = provenance.ConfidenceHigh
		app.ResolutionSource = "deterministic"
		app.ArtifactProvenance = "MATCHED"
		ownershipEvidence = append(ownershipEvidence, sigEv)
		reasons = append(reasons, "Tier 1 Hard Evidence: Verified external code-signing certificate.", sigEv.Description)
		de.RecordTier1Hit()
		finalizeApp(app, identityEvidence, ownershipEvidence, reasons)
		return
	}

	// 1.4 Verified External Go Toolchain or Public Module
	for _, b := range bundle.Binaries {
		if b.Inspection.BuildInfo != nil {
			if b.Inspection.BuildInfo.GoVersion != "" && (strings.EqualFold(b.Name, "go") || strings.EqualFold(b.Name, "gofmt") || strings.Contains(strings.ToLower(b.Path), "go/bin") || strings.Contains(strings.ToLower(b.Path), "go\\bin")) {
				ev := provenance.Evidence{
					Type:        provenance.EvidenceBuildMetadata,
					Source:      "Go Toolchain",
					Strength:    0.85,
					Description: "Official Go programming language toolchain distribution (" + b.Inspection.BuildInfo.GoVersion + ")",
					Confidence:  provenance.ConfidenceHigh,
				}
				app.Classification = provenance.ClassificationThirdParty
				app.Confidence = provenance.ConfidenceHigh
				app.ResolutionSource = "deterministic"
				app.ArtifactProvenance = "MATCHED"
				ownershipEvidence = append(ownershipEvidence, ev)
				reasons = append(reasons, "Tier 1 Hard Evidence: Official Go programming language toolchain distribution.", ev.Description)
				de.RecordTier1Hit()
				finalizeApp(app, identityEvidence, ownershipEvidence, reasons)
				return
			}
			if b.Inspection.BuildInfo.MainModule != "" {
				mod := b.Inspection.BuildInfo.MainModule
				if strings.HasPrefix(mod, "github.com/") || strings.HasPrefix(mod, "golang.org/") ||
					strings.HasPrefix(mod, "gopkg.in/") || strings.HasPrefix(mod, "gitlab.com/") {
					ev := provenance.Evidence{
						Type:        provenance.EvidenceBuildMetadata,
						Source:      "Go BuildInfo",
						Strength:    0.85,
						Description: "Compiler build metadata confirms public open-source project origin: " + mod,
						Confidence:  provenance.ConfidenceHigh,
					}
					app.Classification = provenance.ClassificationThirdParty
					app.Confidence = provenance.ConfidenceHigh
					app.ResolutionSource = "deterministic"
					app.ArtifactProvenance = "MATCHED"
					ownershipEvidence = append(ownershipEvidence, ev)
					reasons = append(reasons, "Tier 1 Hard Evidence: Compiler build metadata confirms public open-source project repository.", ev.Description)
					de.RecordTier1Hit()
					finalizeApp(app, identityEvidence, ownershipEvidence, reasons)
					return
				}
			}
		}
	}

	// 1.5 Verified External Product Metadata (PE Version Resource from recognized vendor in standard install directory)
	if prodEv, ok := bundle.HasExternalProductMetadata(); ok {
		if isStandardInstallDir(app.PrimaryBinaryPath) || isStandardInstallDir(app.InstallDir) {
			app.Classification = provenance.ClassificationThirdParty
			app.Confidence = provenance.ConfidenceHigh
			app.ResolutionSource = "deterministic"
			app.ArtifactProvenance = "MATCHED"
			ownershipEvidence = append(ownershipEvidence, prodEv)
			reasons = append(reasons, "Tier 1 Hard Evidence: Verified external product metadata.", prodEv.Description)
			de.RecordTier1Hit()
			finalizeApp(app, identityEvidence, ownershipEvidence, reasons)
			return
		}
	}

	// 1.6 Windows Store / WindowsApps Package
	if strings.Contains(strings.ToLower(app.PrimaryBinaryPath), "windowsapps") {
		for _, pub := range de.KnownPublishers {
			if strings.Contains(strings.ToLower(app.PrimaryBinaryPath), pub) || strings.Contains(strings.ToLower(app.Name), pub) {
				ev := provenance.Evidence{
					Type:        provenance.EvidenceInstallMetadata,
					Source:      "WindowsApps Store Package",
					Strength:    0.80,
					Description: fmt.Sprintf("Windows Store application package for recognized vendor (%s)", pub),
					Confidence:  provenance.ConfidenceHigh,
				}
				app.Classification = provenance.ClassificationThirdParty
				app.Confidence = provenance.ConfidenceHigh
				app.ResolutionSource = "deterministic"
				app.ArtifactProvenance = "MATCHED"
				ownershipEvidence = append(ownershipEvidence, ev)
				reasons = append(reasons, "Tier 1 Hard Evidence: Windows Store application package for recognized vendor.", ev.Description)
				de.RecordTier1Hit()
				finalizeApp(app, identityEvidence, ownershipEvidence, reasons)
				return
			}
		}
	}

	// TIER 1.5A: Local Package, Runtime Receipts & String Mining (Zero Network)
	if bundle.PackageReceipt != nil {
		rec := bundle.PackageReceipt
		if app.Name == "" || app.Name == app.PrimaryBinaryPath || provenance.IsWrapperString(app.Name) {
			app.Name = rec.PackageName
		}
		if app.Publisher == "" || provenance.IsWrapperString(app.Publisher) {
			if rec.Authors != "" {
				app.Publisher = rec.Authors
			} else {
				app.Publisher = rec.PackageName
			}
		}
		if app.Version == "" && rec.Version != "" {
			app.Version = rec.Version
		}
		app.Classification = provenance.ClassificationThirdParty
		app.Confidence = provenance.ConfidenceVeryHigh
		app.ResolutionSource = fmt.Sprintf("deterministic (%s receipt)", rec.Manager)
		app.ArtifactProvenance = "MATCHED"
		if rec.Homepage != "" {
			app.Sources = []string{rec.Homepage}
		}
		desc := fmt.Sprintf("Local %s receipt confirms public package '%s' (v%s)", rec.Manager, rec.PackageName, rec.Version)
		ev := provenance.Evidence{
			Type:        provenance.EvidenceLocalReceipt,
			Source:      fmt.Sprintf("%s Manifest", strings.Title(rec.Manager)),
			Strength:    0.95,
			Description: desc,
			Confidence:  provenance.ConfidenceVeryHigh,
			URL:         rec.Homepage,
		}
		ownershipEvidence = append(ownershipEvidence, ev)
		reasons = append(reasons, "Tier 1.5A Local Receipt: "+desc)
		de.RecordTier15AHit()
		finalizeApp(app, identityEvidence, ownershipEvidence, reasons)
		return
	}

	if bundle.RuntimeReceipt != nil {
		rec := bundle.RuntimeReceipt
		if app.Name == "" || app.Name == app.PrimaryBinaryPath || provenance.IsWrapperString(app.Name) {
			app.Name = rec.PackageName
		}
		if app.Publisher == "" || provenance.IsWrapperString(app.Publisher) {
			if rec.Author != "" {
				app.Publisher = rec.Author
			} else {
				app.Publisher = rec.PackageName
			}
		}
		if app.Version == "" && rec.Version != "" {
			app.Version = rec.Version
		}
		app.Classification = provenance.ClassificationThirdParty
		app.Confidence = provenance.ConfidenceVeryHigh
		app.ResolutionSource = fmt.Sprintf("deterministic (%s receipt)", rec.Ecosystem)
		app.ArtifactProvenance = "MATCHED"
		if rec.Homepage != "" {
			app.Sources = []string{rec.Homepage}
		}
		desc := fmt.Sprintf("Local %s runtime receipt confirms package '%s' (v%s)", rec.Ecosystem, rec.PackageName, rec.Version)
		ev := provenance.Evidence{
			Type:        provenance.EvidenceLocalReceipt,
			Source:      fmt.Sprintf("%s dist-info", rec.Ecosystem),
			Strength:    0.95,
			Description: desc,
			Confidence:  provenance.ConfidenceVeryHigh,
			URL:         rec.Homepage,
		}
		ownershipEvidence = append(ownershipEvidence, ev)
		reasons = append(reasons, "Tier 1.5A Local Receipt: "+desc)
		de.RecordTier15AHit()
		finalizeApp(app, identityEvidence, ownershipEvidence, reasons)
		return
	}

	if bundle.StringSignatures != nil && bundle.StringSignatures.RepositoryURL != "" {
		repoURL := bundle.StringSignatures.RepositoryURL
		app.Classification = provenance.ClassificationThirdParty
		app.Confidence = provenance.ConfidenceHigh
		app.ResolutionSource = "deterministic (embedded repository)"
		app.ArtifactProvenance = "MATCHED"
		app.Sources = []string{repoURL}
		desc := "Discovered public repository in binary read-only data: " + repoURL
		ev := provenance.Evidence{
			Type:        provenance.EvidenceBuildMetadata,
			Source:      "Binary Embedded Strings (.rdata)",
			Strength:    0.80,
			Description: desc,
			Confidence:  provenance.ConfidenceHigh,
			URL:         repoURL,
		}
		ownershipEvidence = append(ownershipEvidence, ev)
		reasons = append(reasons, "Tier 1.5A String Mining: "+desc)
		de.RecordTier15AHit()
		finalizeApp(app, identityEvidence, ownershipEvidence, reasons)
		return
	}

	// TIER 1.5B: Public Hash API (CIRCL Hashlookup)
	primaryHash := bundle.PrimaryBinary.SHA256
	if primaryHash != "" && de.HashLookupClient != nil && !de.HashLookupClient.IsDegraded() && de.NetworkMode != provenance.NetworkOff {
		res, matched, err := de.HashLookupClient.LookupSHA256(ctx, primaryHash)
		if err == nil && matched && res != nil {
			app.Classification = provenance.ClassificationThirdParty
			app.Confidence = provenance.ConfidenceDeterministic
			app.ResolutionSource = "deterministic (CIRCL Hashlookup)"
			app.ArtifactProvenance = "MATCHED"
			if app.Name == "" || app.Name == app.PrimaryBinaryPath || provenance.IsWrapperString(app.Name) {
				if res.ProductName != "" {
					app.Name = res.ProductName
				} else if res.FileName != "" {
					app.Name = res.FileName
				}
			}
			desc := fmt.Sprintf("CIRCL Public Database Match: %s (%s) [source: %s]", res.ProductName, res.FileName, res.Source)
			ev := provenance.Evidence{
				Type:        provenance.EvidenceExactHashMatch,
				Source:      "CIRCL Hashlookup (NSRL/RDS)",
				Strength:    1.0,
				Description: desc,
				Confidence:  provenance.ConfidenceDeterministic,
			}
			ownershipEvidence = append(ownershipEvidence, ev)
			reasons = append(reasons, "Tier 1.5B Public Hash DB: "+desc)
			de.RecordTier15BHit()
			finalizeApp(app, identityEvidence, ownershipEvidence, reasons)
			return
		}
	}

	// TIER 2: Corroborative Evidence Fusion

	// 2.1 Project Identity Corroboration (Candidate Identity Recording)
	// Structural signals match project pattern for candidate identity
	if IsRecognizedThirdPartyProject(identity) {
		for _, sig := range identity.Signals {
			ev := provenance.Evidence{
				Type:        provenance.EvidenceProjectMatch,
				Source:      "Identity Heuristic",
				Strength:    0.50,
				Description: sig,
				Confidence:  identity.Confidence,
			}
			identityEvidence = append(identityEvidence, ev)
		}

		reasons = append(reasons,
			fmt.Sprintf("Identity Heuristics: Structural signals match project pattern for '%s' (%s).", identity.Name, identity.Publisher),
		)
		reasons = append(reasons, identity.Signals...)
	}

	// 2.2 Official Host OS Installation Manifest / Registered Application
	inStandardDir := isStandardInstallDir(app.PrimaryBinaryPath) || isStandardInstallDir(app.InstallDir)
	if isRegisteredOrigin(app.Origin) || inStandardDir {
		manifestPub := bundle.Publisher
		if manifestPub == "" && inStandardDir && identity.Publisher != "" {
			manifestPub = identity.Publisher
		}

		// A. Check for company ownership association
		if de.isCompanyIndicator(manifestPub) || (manifestPub != "" && de.isCompanyIndicator(app.Name)) {
			reasons = append(reasons,
				fmt.Sprintf("Manifest entry indicates company association (%s), but lacks verified internal code-signing certificate or build provenance.", manifestPub),
				"Conclusion: Unverified company application candidate -> UNKNOWN.",
			)
			app.Classification = provenance.ClassificationUnknown
			app.Confidence = provenance.ConfidenceNone
			finalizeApp(app, identityEvidence, ownershipEvidence, reasons)
			return
		}

		// B. External vendor verification
		if manifestPub != "" && de.isKnownExternalPublisher(manifestPub) {
			ev := provenance.Evidence{
				Type:        provenance.EvidenceInstallMetadata,
				Source:      app.Origin,
				Strength:    0.75,
				Description: fmt.Sprintf("Officially registered application from recognized external vendor (%s: %s)", app.Origin, manifestPub),
				Confidence:  provenance.ConfidenceHigh,
			}
			app.Classification = provenance.ClassificationThirdParty
			app.Confidence = provenance.ConfidenceHigh
			app.ResolutionSource = "deterministic"
			app.ArtifactProvenance = "MATCHED"
			ownershipEvidence = append(ownershipEvidence, ev)
			reasons = append(reasons, "Tier 2 Corroboration: Officially registered application from recognized external publisher.", ev.Description)
			finalizeApp(app, identityEvidence, ownershipEvidence, reasons)
			return
		}

		// C. Generic, unverified, or missing publisher in manifest:
		// Records contextual installation evidence only. Must NOT independently establish THIRD_PARTY!
		pub := manifestPub
		if pub == "" {
			pub = app.Name
		}
		ev := provenance.Evidence{
			Type:        provenance.EvidenceInstallMetadata,
			Source:      app.Origin,
			Strength:    0.30,
			Description: fmt.Sprintf("Host OS manifest registration exists (%s: %s)", app.Origin, pub),
			Confidence:  provenance.ConfidenceLow,
		}
		ownershipEvidence = append(ownershipEvidence, ev)
	}

	// TIER 2 / TIER 3: Optional AI Reasoning Synthesis Layer
	if de.Reasoner != nil && de.Reasoner.Name() != "none" {
		finalizeApp(app, identityEvidence, ownershipEvidence, reasons)
		de.RecordTier2Hit()
		aiResult, err := de.Reasoner.Analyze(ctx, bundle)
		de.ApplyAIResult(app, bundle, aiResult, err)
		return
	}

	// FALLBACK: UNKNOWN (Never COMPANY!)
	app.Classification = provenance.ClassificationUnknown
	app.Confidence = provenance.ConfidenceNone
	if app.ResolutionSource == "" {
		app.ResolutionSource = "deterministic"
	}
	reasons = append(reasons,
		"Rule F Fallback: No exact public cryptographic hash match found.",
		"No trusted external or internal code-signing certificate identified.",
		"No verified internal company ownership evidence.",
		"Available identity signals insufficient to establish provenance.",
		"Conclusion: Provenance cannot be established with sufficient confidence -> UNKNOWN.",
	)
	finalizeApp(app, identityEvidence, ownershipEvidence, reasons)
}

func finalizeApp(app *Application, identityEv, ownershipEv []provenance.Evidence, reasons []string) {
	app.IdentityEvidence = identityEv
	app.OwnershipEvidence = ownershipEv
	app.Reasons = reasons
}

// ApplyAIResult synthesizes the AI reasoning outcome onto an Application candidate.
func (de *DecisionEngine) ApplyAIResult(app *Application, bundle EvidenceBundle, aiResult ai.ReasoningResult, err error) {
	reasonerName := "ai"
	if de.Reasoner != nil {
		reasonerName = de.Reasoner.Name()
	}
	isDeepSeek := strings.Contains(strings.ToLower(reasonerName), "deepseek")
	isLocal := strings.Contains(strings.ToLower(reasonerName), "local") || strings.Contains(strings.ToLower(reasonerName), "ollama")
	reasons := app.Reasons
	identityEvidence := app.IdentityEvidence
	ownershipEvidence := app.OwnershipEvidence

	if err == nil {
		app.EvidenceSummary = aiResult.EvidenceSummary
		app.Conclusion = aiResult.Conclusion
		app.PromptTokens = aiResult.TokenUsage.PromptTokens
		app.CompletionTokens = aiResult.TokenUsage.CompletionTokens
		app.TotalTokens = aiResult.TokenUsage.TotalTokens
		app.AIError = aiResult.APIError
		app.SearchGrounded = aiResult.SearchGrounded
		app.DegradationWarning = aiResult.DegradationWarning
		app.SearchWarning = aiResult.SearchWarning

		// If an API-level error occurred (e.g. HTTP 401, 402, 403, 429, network error),
		// preserve the error details and do not overwrite with generic Rule F fallback!
		if aiResult.APIError != "" {
			app.Classification = provenance.ClassificationUnknown
			app.Confidence = provenance.ConfidenceNone
			if isDeepSeek {
				app.ResolutionSource = "deepseek_error"
			} else if isLocal {
				app.ResolutionSource = "ollama_error"
			} else {
				app.ResolutionSource = "gemini_error"
			}
			reasons = append(reasons, fmt.Sprintf("Tier 3 AI Error (%s): %s", reasonerName, aiResult.APIError))
			reasons = append(reasons, aiResult.Reasons...)
			finalizeApp(app, identityEvidence, ownershipEvidence, reasons)
			return
		}

		ok, reasonMsg, artifactProv := de.verifyAIOwnershipGrounding(bundle, aiResult)
		if ok && aiResult.Classification != provenance.ClassificationUnknown {
			app.Classification = aiResult.Classification
			isGrounded := aiResult.SearchGrounded || len(aiResult.Sources) > 0
			app.SearchGrounded = isGrounded
			if !isGrounded {
				app.Confidence = provenance.ConfidenceLow
			} else {
				app.Confidence = aiResult.Confidence
			}
			if isDeepSeek {
				app.ResolutionSource = "deepseek_reasoning"
			} else if isLocal {
				app.ResolutionSource = "ollama_reasoning"
			} else {
				app.ResolutionSource = "gemini_search"
			}
			app.ArtifactProvenance = artifactProv
			app.ResearchCacheHit = aiResult.CacheHit
			app.Sources = aiResult.Sources
			if aiResult.Identity != "" {
				if app.Name == "" {
					app.Name = aiResult.Identity
				}
				if app.Identity.Name == "" || provenance.IsWrapperString(app.Identity.Name) {
					app.Identity.Name = aiResult.Identity
				}
			}
			if aiResult.Publisher != "" && (app.Publisher == "" || provenance.IsWrapperString(app.Publisher)) && !provenance.IsWrapperString(aiResult.Publisher) {
				app.Publisher = aiResult.Publisher
				app.Identity.Publisher = aiResult.Publisher
			}
			reasons = append(reasons, fmt.Sprintf("Tier 3 AI Synthesis (%s): %s", reasonerName, reasonMsg))
			if !aiResult.SearchGrounded && aiResult.DegradationWarning != "" {
				reasons = append(reasons, "Disclaimer: "+aiResult.DegradationWarning)
			}
			reasons = append(reasons, aiResult.Reasons...)
			finalizeApp(app, identityEvidence, ownershipEvidence, reasons)
			return
		}

		// Inconclusive or ungrounded AI assertion
		app.Classification = provenance.ClassificationUnknown
		app.Confidence = provenance.ConfidenceNone
		if isDeepSeek {
			app.ResolutionSource = "deepseek_inconclusive"
		} else if isLocal {
			app.ResolutionSource = "ollama_inconclusive"
		} else {
			app.ResolutionSource = "gemini_inconclusive"
		}
		app.ResearchCacheHit = aiResult.CacheHit
		app.Sources = aiResult.Sources
		if !ok {
			reasons = append(reasons, fmt.Sprintf("Tier 3 AI Grounding Gate: %s", reasonMsg))
		} else {
			reasons = append(reasons, fmt.Sprintf("Tier 3 AI Research (%s): Research concluded UNKNOWN provenance.", reasonerName))
			reasons = append(reasons, aiResult.Reasons...)
		}
		reasons = append(reasons,
			"Rule F Fallback: No exact public cryptographic hash match found.",
			"No trusted external or internal code-signing certificate identified.",
			"No verified internal company ownership evidence.",
			"Available identity signals insufficient to establish provenance.",
			"Conclusion: Provenance cannot be established with sufficient confidence -> UNKNOWN.",
		)
		finalizeApp(app, identityEvidence, ownershipEvidence, reasons)
	} else {
		app.AIError = fmt.Sprintf("Reasoner execution error: %v", err)
		app.Classification = provenance.ClassificationUnknown
		app.Confidence = provenance.ConfidenceNone
		if isDeepSeek {
			app.ResolutionSource = "deepseek_error"
		} else {
			app.ResolutionSource = "gemini_error"
		}
		reasons = append(reasons, fmt.Sprintf("Tier 3 AI Reasoner (%s) unavailable: %v", reasonerName, err))
		finalizeApp(app, identityEvidence, ownershipEvidence, reasons)
	}
}

func (de *DecisionEngine) isCompanyIndicator(val string) bool {
	if val == "" || len(de.CompanyIndicators) == 0 {
		return false
	}
	valLower := strings.ToLower(val)
	for _, ind := range de.CompanyIndicators {
		if strings.Contains(valLower, strings.ToLower(ind)) {
			return true
		}
	}
	return false
}

func (de *DecisionEngine) isKnownExternalPublisher(val string) bool {
	if val == "" || len(de.KnownPublishers) == 0 {
		return false
	}
	valLower := strings.ToLower(val)
	for _, pub := range de.KnownPublishers {
		if strings.Contains(valLower, strings.ToLower(pub)) {
			return true
		}
	}
	return false
}

// verifyAIOwnershipGrounding checks that an AI recommendation is credible and supported by digital source research.
// Under the product model:
// 1. Local application has reasonably identifiable application identity/name/context.
// 2. Research finds credible digital sources supporting that identity.
// 3. Sources are authoritative or sufficiently credible (official project/package documentation, not forums/blogs).
// 4. No known internal company classification conflict.
// If exact release hash matches primary SHA (or local signature or NSRL), ArtifactProvenance is "MATCHED".
// Otherwise, credible identification results in ArtifactProvenance "NOT_ESTABLISHED".
func (de *DecisionEngine) verifyAIOwnershipGrounding(bundle EvidenceBundle, aiResult ai.ReasoningResult) (bool, string, string) {
	target := aiResult.Classification

	if target == provenance.ClassificationCompany {
		if compEv, ok := bundle.HasCompanyManifestMatch(de.CompanyManifest); ok {
			return true, "Corroborated by internal company registry: " + compEv.Description, "MATCHED"
		}
		if compEv, ok := bundle.HasCompanySignature(de.CompanyIndicators); ok {
			return true, "Corroborated by verified internal company code-signing: " + compEv.Description, "MATCHED"
		}
		for _, b := range bundle.Binaries {
			if b.Inspection.BuildInfo != nil && b.Inspection.BuildInfo.MainModule != "" {
				modLower := strings.ToLower(b.Inspection.BuildInfo.MainModule)
				for _, ind := range de.CompanyIndicators {
					if strings.Contains(modLower, strings.ToLower(ind)) {
						return true, "Corroborated by internal Go buildinfo module matching company domain: " + b.Inspection.BuildInfo.MainModule, "MATCHED"
					}
				}
			}
		}
		return false, "AI recommended COMPANY, but rejected because the objective evidence lacks verified internal code-signing certificate or company build provenance.", ""
	}

	if target != provenance.ClassificationThirdParty {
		return true, "", ""
	}

	// 1. Reject if there is a known internal company classification conflict
	if de.isCompanyIndicator(bundle.AppName) || de.isCompanyIndicator(bundle.Publisher) {
		return false, fmt.Sprintf("AI recommended THIRD_PARTY, but rejected due to classification conflict: application or publisher matches internal company indicator (%s / %s)", bundle.AppName, bundle.Publisher), ""
	}
	for _, b := range bundle.Binaries {
		if b.Inspection.BuildInfo != nil && b.Inspection.BuildInfo.MainModule != "" {
			if de.isCompanyIndicator(b.Inspection.BuildInfo.MainModule) {
				return false, "AI recommended THIRD_PARTY, but rejected due to classification conflict: Go buildinfo matches internal company module", ""
			}
		}
	}

	// 2. Ensure application has identifiable identity/name/context
	appName := strings.TrimSpace(bundle.AppName)
	if appName == "" && bundle.PrimaryBinary.Name != "" {
		appName = bundle.PrimaryBinary.Name
	}
	aiIdentity := strings.TrimSpace(aiResult.Identity)
	if aiIdentity == "" {
		aiIdentity = strings.TrimSpace(aiResult.Publisher)
	}
	if appName == "" && aiIdentity == "" {
		return false, "AI recommended THIRD_PARTY, but rejected because application lacks identifiable name or identity context.", ""
	}

	// 3. Hallucination safeguard: Must have digital sources or evidence claims
	if len(aiResult.Sources) == 0 && len(aiResult.EvidenceClaims) == 0 {
		return false, "AI recommended THIRD_PARTY, but rejected by Grounding Gate: ungrounded assertion lacking digital sources or evidence claims.", ""
	}

	// 4. Fabricated checksum safeguard:
	// If the AI claimed an exact release hash that contradicts the local binary hash, reject as fabricated
	primaryHash := strings.ToLower(bundle.PrimaryBinary.SHA256)
	hasExactHashClaim := false
	hasInventedHashClaim := false

	for _, claim := range aiResult.EvidenceClaims {
		claimLower := strings.ToLower(claim.Claim)
		if strings.Contains(claimLower, "sha256") || strings.Contains(claimLower, "sha-256") || strings.Contains(claimLower, "checksum") {
			for _, word := range strings.Fields(claimLower) {
				cleanWord := strings.Trim(word, ":=,;\"'()")
				if len(cleanWord) == 64 && isHex(cleanWord) {
					if primaryHash != "" && cleanWord == primaryHash {
						hasExactHashClaim = true
					} else if primaryHash != "" && cleanWord != primaryHash {
						hasInventedHashClaim = true
					}
				}
			}
		}
	}
	if hasInventedHashClaim && !hasExactHashClaim {
		return false, "AI recommended THIRD_PARTY, but rejected by Grounding Gate: fabricated or mismatching release checksum in AI evidence claims.", ""
	}

	// 5. Source quality safeguard:
	// Reject forum/blog/secondary claims when no authoritative or official sources are available
	hasAuthoritativeOrOfficialSource := false
	var officialSourceNames []string

	for _, claim := range aiResult.EvidenceClaims {
		if (claim.SourceType == "official" || claim.SourceType == "package") &&
			(claim.EvidenceStrength == "authoritative" || claim.EvidenceStrength == "supporting") {
			hasAuthoritativeOrOfficialSource = true
			if claim.Source != "" {
				officialSourceNames = append(officialSourceNames, claim.Source)
			}
		}
	}

	for _, src := range aiResult.Sources {
		srcLower := strings.ToLower(src)
		if !strings.Contains(srcLower, "forum") && !strings.Contains(srcLower, "blog") &&
			!strings.Contains(srcLower, "reddit") && !strings.Contains(srcLower, "stackoverflow") {
			hasAuthoritativeOrOfficialSource = true
			officialSourceNames = append(officialSourceNames, src)
		}
	}

	if !hasAuthoritativeOrOfficialSource {
		return false, "AI recommended THIRD_PARTY, but rejected by Grounding Gate: digital research relies on low-quality forum/secondary sources without authoritative project documentation.", ""
	}

	// 6. Determine ArtifactProvenance: MATCHED vs NOT_ESTABLISHED
	artifactProv := "NOT_ESTABLISHED"
	if _, ok := bundle.HasExactHashMatch(); ok || hasExactHashClaim {
		artifactProv = "MATCHED"
	} else if _, ok := bundle.HasExternalSignature(de.CompanyIndicators); ok {
		artifactProv = "MATCHED"
	} else {
		for _, b := range bundle.Binaries {
			if b.Inspection.BuildInfo != nil && b.Inspection.BuildInfo.MainModule != "" {
				mod := b.Inspection.BuildInfo.MainModule
				if strings.HasPrefix(mod, "github.com/") || strings.HasPrefix(mod, "golang.org/") ||
					strings.HasPrefix(mod, "gopkg.in/") || strings.HasPrefix(mod, "gitlab.com/") {
					artifactProv = "MATCHED"
					break
				}
			}
		}
	}

	srcSummary := ""
	if len(officialSourceNames) > 0 {
		srcSummary = officialSourceNames[0]
	} else if len(aiResult.Sources) > 0 {
		srcSummary = aiResult.Sources[0]
	}

	if artifactProv == "MATCHED" {
		return true, fmt.Sprintf("Corroborated by digital research with verified artifact release evidence (%s)", srcSummary), artifactProv
	}

	return true, fmt.Sprintf("Corroborated by digital research identifying legitimate third-party application (%s)", srcSummary), artifactProv
}

func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func isStandardInstallDir(path string) bool {
	if path == "" {
		return false
	}
	p := strings.ToLower(filepath.ToSlash(path))
	return strings.Contains(p, "program files") ||
		strings.Contains(p, "program files (x86)") ||
		strings.Contains(p, "programdata") ||
		strings.Contains(p, "appdata/local/programs") ||
		strings.Contains(p, "appdata/local/chromium") ||
		strings.Contains(p, "appdata/local/mongodbcompass") ||
		strings.Contains(p, "windowsapps") ||
		strings.Contains(p, "turboc") ||
		strings.Contains(p, "/windows") ||
		strings.Contains(p, "c:/windows") ||
		strings.Contains(p, "system32") ||
		strings.Contains(p, "syswow64") ||
		strings.Contains(p, "/usr/") ||
		strings.Contains(p, "/opt/") ||
		strings.Contains(p, "/bin/") ||
		strings.Contains(p, "/sbin/") ||
		strings.Contains(p, "/applications")
}

