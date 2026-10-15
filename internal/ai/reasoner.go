package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/example/appaudit/internal/provenance"
)

// EvidenceClaim represents a fine-grained assertion from research.
type EvidenceClaim struct {
	Claim            string `json:"claim"`
	Source           string `json:"source"`
	SourceType       string `json:"source_type"`       // official | package | secondary | local
	EvidenceStrength string `json:"evidence_strength"` // authoritative | supporting | clue
	Supports         string `json:"supports"`          // identity | ownership | provenance
}

// TokenUsage tracks prompt, completion, and total tokens consumed during an AI reasoning call.
type TokenUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// ReasoningResult contains the structured decision emitted by an AI reasoner.
type ReasoningResult struct {
	Classification    provenance.Classification `json:"classification"`
	Identity          string                    `json:"identity,omitempty"`
	Confidence        provenance.Confidence     `json:"confidence"`
	Publisher         string                    `json:"publisher,omitempty"`
	Reasons           []string                  `json:"reasons"`
	Sources           []string                  `json:"sources,omitempty"`
	ResearchPerformed bool                      `json:"research_performed,omitempty"`
	EvidenceClaims    []EvidenceClaim           `json:"evidence_claims,omitempty"`
	CacheHit          bool                      `json:"cache_hit,omitempty"`
	EvidenceSummary   string                    `json:"evidence_summary,omitempty"`
	Conclusion        string                    `json:"conclusion,omitempty"`
	TokenUsage        TokenUsage                `json:"token_usage,omitempty"`
	APIError          string                    `json:"api_error,omitempty"`
	SearchGrounded    bool                      `json:"search_grounded"`
	DegradationWarning string                   `json:"degradation_warning,omitempty"`
	SearchWarning      string                   `json:"search_warning,omitempty"`
}

// EvidenceBundle holds the serializable evidence for an application candidate in AI reasoning.
type EvidenceBundle struct {
	SHA256          string `json:"sha256,omitempty"`
	AppName         string `json:"app_name"`
	Publisher       string `json:"publisher,omitempty"`
	Version         string `json:"version,omitempty"`
	BinaryName      string `json:"binary_name,omitempty"`
	Path            string `json:"path,omitempty"`
	InstallDir      string `json:"install_dir,omitempty"`
	Origin          string `json:"origin,omitempty"`
	SiblingCount    int    `json:"sibling_count,omitempty"`
	EvidenceSummary string `json:"evidence_summary,omitempty"`
	IsWrapperStub   bool   `json:"is_wrapper_stub,omitempty"`
	Raw             any    `json:"raw,omitempty"`
}

// ToAIEvidenceBundle converts an arbitrary bundle into a normalized EvidenceBundle.
func ToAIEvidenceBundle(bundle any) EvidenceBundle {
	if eb, ok := bundle.(EvidenceBundle); ok {
		return eb
	}
	if bundle == nil {
		return EvidenceBundle{AppName: "unknown"}
	}
	data, err := json.Marshal(bundle)
	if err != nil {
		return EvidenceBundle{AppName: "unknown", Raw: bundle}
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return EvidenceBundle{AppName: "unknown", Raw: bundle}
	}
	eb := EvidenceBundle{Raw: bundle}
	if v, ok := m["app_name"].(string); ok {
		eb.AppName = v
	}
	if v, ok := m["publisher"].(string); ok {
		eb.Publisher = v
	}
	if v, ok := m["version"].(string); ok {
		eb.Version = v
	}
	if v, ok := m["origin"].(string); ok {
		eb.Origin = v
	}
	if v, ok := m["install_dir"].(string); ok {
		eb.InstallDir = v
	}
	if v, ok := m["sha256"].(string); ok {
		eb.SHA256 = v
	}
	if v, ok := m["is_wrapper_stub"].(bool); ok {
		eb.IsWrapperStub = v
	}
	if pb, ok := m["primary_binary"].(map[string]any); ok {
		if sha, ok := pb["sha256"].(string); ok && eb.SHA256 == "" {
			eb.SHA256 = sha
		}
		if name, ok := pb["name"].(string); ok && eb.BinaryName == "" {
			eb.BinaryName = name
		}
		if p, ok := pb["path"].(string); ok && eb.Path == "" {
			eb.Path = p
		}
		if insp, ok := pb["inspection"].(map[string]any); ok {
			if ws, ok := insp["is_wrapper_stub"].(bool); ok && ws {
				eb.IsWrapperStub = true
			}
		}
	}
	if bins, ok := m["binaries"].([]any); ok {
		eb.SiblingCount = len(bins)
	}
	if eb.AppName == "" && eb.BinaryName != "" {
		eb.AppName = eb.BinaryName
	}
	return eb
}

// Reasoner defines the contract for optional evidence synthesis layers.
type Reasoner interface {
	Name() string
	Analyze(ctx context.Context, bundle any) (ReasoningResult, error)
}

// BatchReasoner defines the contract for AI reasoners capable of multi-item batch processing.
type BatchReasoner interface {
	ReasonBatch(ctx context.Context, bundles []EvidenceBundle) ([]ReasoningResult, error)
}

// UnifiedSystemPrompt is the single canonical system prompt used across all AI reasoning providers
// (DeepSeek, Google Gemini, Ollama/Local). It enforces consistent provenance reasoning with pragmatic
// developer-tooling and package-manager awareness.
const UnifiedSystemPrompt = `You are a software provenance evidence classifier and researcher.
Analyze the provided application evidence bundle and classify the software as THIRD_PARTY, COMPANY, or UNKNOWN.

REASONING PROCEDURE & PROVENANCE GUIDELINES:
1. Examine the binary name, architecture, embedded strings, compiler metadata, and component markers.
2. Cross-reference against web search results and your knowledge of legitimate, public open-source and commercial software projects (e.g., GitHub, GitLab, official vendor websites, package registries, standard developer CLI tools).
3. Recognize standard package manager launchers and CLI shims:
   - Developer tools on Windows are frequently installed via package managers (Python pip/pipx, Node npm/npx, Rust cargo, Go install, Scoop, Chocolatey, Winget).
   - Python pip creates entrypoint executables using standard generic C launcher shims (e.g. 't64.exe', 't32.exe', or PE metadata 'Simple Launcher') wrapping the Python script.
   - Node/npm creates '.cmd' or small wrapper executables; Scoop/Choco create 'shim.exe'.
   - If a binary is a standard launcher shim or wrapper for a recognized public open-source or commercial tool (e.g., aider, black, pipenv, mongosh, bat, ripgrep, jq, ninja), classify the application as "THIRD_PARTY". Do NOT mark it UNKNOWN simply because it is an unsigned launcher stub or wrapper.
   - Do NOT adopt boilerplate wrapper/stub metadata (e.g., 'Simple Launcher User', 'Simple Launcher', 'distlib') as the application publisher; identify the actual underlying software project and author/organization.
4. Recognize portable & developer tools:
   - Many legitimate CLI tools and developer utilities are distributed as portable zip archives or unsigned executables without commercial EV code-signing certificates.
   - If the executable name, version, and context match an established legitimate public project, classify as "THIRD_PARTY" with "HIGH" or "VERY_HIGH" confidence.
5. Internal company software:
   - If there is affirmative evidence of internal company ownership (matching company names, proprietary internal Go modules, corporate internal paths, internal domains, or private corporate copyright), classify as "COMPANY".
6. When to return UNKNOWN:
   - Classify as "UNKNOWN" only if the application is truly ambiguous, unidentifiable, appears to be an unrecognized proprietary in-house tool without company registration, or lacks sufficient corroborating digital evidence.
   - Absence of public evidence does NOT mean COMPANY.

Keep responses strictly concise to conserve tokens. Do NOT include Markdown code blocks or any conversational text.

You must respond ONLY with a valid JSON object matching this schema:
{
  "classification": "THIRD_PARTY" | "COMPANY" | "UNKNOWN",
  "identity": "Brief application or project name and role (max 40 chars)",
  "publisher": "Author, organization, or vendor (max 35 chars)",
  "confidence": "VERY_HIGH" | "HIGH" | "MEDIUM" | "LOW" | "NONE",
  "sources": ["https://..."],
  "evidence": "Single concise sentence summarizing key digital evidence",
  "conclusion": "Single concise sentence stating final provenance verdict"
}`

// SystemPrompt maintains backwards compatibility with legacy callers.
const SystemPrompt = UnifiedSystemPrompt

// BuildUserPrompt constructs a standardized, token-efficient prompt for an application evidence bundle.
func BuildUserPrompt(appName string, bundleJSON []byte) string {
	return fmt.Sprintf("Classify the provenance of application '%s':\n\nLocal evidence bundle:\n%s\n\nRespond ONLY with a valid JSON object matching the required schema. Do NOT include Markdown code blocks or conversational text.", appName, string(bundleJSON))
}

// AIOutputSchema matches the standardized JSON schema emitted by all reasoners.
type AIOutputSchema struct {
	Classification string   `json:"classification"`
	Identity       string   `json:"identity"`
	Publisher      string   `json:"publisher"`
	Confidence     string   `json:"confidence"`
	Sources        []string `json:"sources"`
	Evidence       string   `json:"evidence"`
	Conclusion     string   `json:"conclusion"`
	Reasons        []string `json:"reasons,omitempty"`
}

// ConvertAIOutputToResult converts an AIOutputSchema into a domain ReasoningResult.
func ConvertAIOutputToResult(output AIOutputSchema, extraSources []string, usage TokenUsage, appName string) ReasoningResult {
	var class provenance.Classification
	switch strings.ToUpper(strings.TrimSpace(output.Classification)) {
	case "THIRD_PARTY", "THIRDPARTY":
		class = provenance.ClassificationThirdParty
	case "COMPANY", "INTERNAL", "FIRST_PARTY", "FIRSTPARTY":
		class = provenance.ClassificationCompany
	default:
		class = provenance.ClassificationUnknown
	}

	var conf provenance.Confidence
	switch strings.ToUpper(strings.TrimSpace(output.Confidence)) {
	case "VERY_HIGH", "VERYHIGH":
		conf = provenance.ConfidenceVeryHigh
	case "HIGH":
		conf = provenance.ConfidenceHigh
	case "MEDIUM":
		conf = provenance.ConfidenceMedium
	case "LOW":
		conf = provenance.ConfidenceLow
	default:
		if class == provenance.ClassificationThirdParty || class == provenance.ClassificationCompany {
			conf = provenance.ConfidenceMedium
		} else {
			conf = provenance.ConfidenceNone
		}
	}

	reasons := output.Reasons
	if len(reasons) == 0 {
		if output.Evidence != "" {
			reasons = append(reasons, output.Evidence)
		}
		if output.Conclusion != "" {
			reasons = append(reasons, output.Conclusion)
		}
		if len(reasons) == 0 {
			reasons = []string{fmt.Sprintf("AI Reasoner classified application as %s", class)}
		}
	}

	allSources := append(output.Sources, extraSources...)
	sourceMap := make(map[string]bool)
	var dedupedSources []string
	for _, s := range allSources {
		sClean := strings.TrimSpace(s)
		if sClean != "" && !sourceMap[sClean] {
			sourceMap[sClean] = true
			dedupedSources = append(dedupedSources, sClean)
		}
	}

	var claims []EvidenceClaim
	for _, s := range dedupedSources {
		claims = append(claims, EvidenceClaim{
			Claim:            fmt.Sprintf("Recognized open-source / third-party project %s", output.Identity),
			Source:           s,
			SourceType:       "secondary",
			EvidenceStrength: "supporting",
			Supports:         "provenance",
		})
	}
	if len(claims) == 0 && class == provenance.ClassificationThirdParty && len(reasons) > 0 {
		claims = append(claims, EvidenceClaim{
			Claim:            reasons[0],
			Source:           "Pre-trained Software Knowledge",
			SourceType:       "secondary",
			EvidenceStrength: "supporting",
			Supports:         "provenance",
		})
	}

	evidenceSummary := strings.TrimSpace(output.Evidence)
	if evidenceSummary == "" && len(reasons) > 0 {
		evidenceSummary = reasons[0]
	}
	if evidenceSummary == "" {
		if class == provenance.ClassificationThirdParty {
			evidenceSummary = "Matches recognized public open-source software project."
		} else if class == provenance.ClassificationCompany {
			evidenceSummary = "Matches verified company ownership markers."
		} else {
			evidenceSummary = "Insufficient public evidence to verify provenance."
		}
	}

	conclusion := strings.TrimSpace(output.Conclusion)
	if conclusion == "" && len(reasons) > 1 {
		conclusion = reasons[1]
	}
	if conclusion == "" {
		if class == provenance.ClassificationThirdParty {
			conclusion = fmt.Sprintf("Verified authentic third-party software (%s).", output.Identity)
		} else if class == provenance.ClassificationCompany {
			conclusion = "Verified company-owned software."
		} else {
			conclusion = "Provenance cannot be attributed to a legitimate public project or company; kept UNKNOWN."
		}
	}

	identity := strings.TrimSpace(output.Identity)
	if identity == "" {
		identity = appName
	}

	return ReasoningResult{
		Classification:    class,
		Identity:          identity,
		Confidence:        conf,
		Publisher:         strings.TrimSpace(output.Publisher),
		Reasons:           reasons,
		Sources:           dedupedSources,
		ResearchPerformed: true,
		SearchGrounded:    len(dedupedSources) > 0,
		EvidenceClaims:    claims,
		EvidenceSummary:   evidenceSummary,
		Conclusion:        conclusion,
		TokenUsage:        usage,
	}
}
