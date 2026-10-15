package application

import (
	"github.com/example/appaudit/internal/provenance"
)

// Application represents a first-class logical software product represented by one or more binaries.
type Application struct {
	ID                string                    `json:"id"`
	Name              string                    `json:"name"`
	Publisher         string                    `json:"publisher,omitempty"`
	Version           string                    `json:"version,omitempty"`
	InstallDir        string                    `json:"install_dir,omitempty"`
	PrimaryBinaryPath string                    `json:"primary_binary_path,omitempty"`
	Binaries          []ApplicationBinary       `json:"binaries"`
	Identity          ApplicationIdentity       `json:"identity"`
	IdentityEvidence  []provenance.Evidence     `json:"identity_evidence,omitempty"`
	OwnershipEvidence []provenance.Evidence     `json:"ownership_evidence,omitempty"`
	Classification    provenance.Classification `json:"classification"`
	Confidence        provenance.Confidence     `json:"confidence"`
	Origin            string                    `json:"origin,omitempty"`
	Reasons           []string                  `json:"reasons,omitempty"`
	ResolutionSource  string                    `json:"resolution_source,omitempty"`
	Sources           []string                  `json:"sources,omitempty"`
	ArtifactProvenance string                   `json:"artifact_provenance,omitempty"`
	ResearchCacheHit   bool                     `json:"research_cache_hit,omitempty"`
	EvidenceSummary    string                   `json:"evidence_summary,omitempty"`
	Conclusion         string                   `json:"conclusion,omitempty"`
	PromptTokens       int                      `json:"prompt_tokens,omitempty"`
	CompletionTokens   int                      `json:"completion_tokens,omitempty"`
	TotalTokens        int                      `json:"total_tokens,omitempty"`
	AIError            string                   `json:"ai_error,omitempty"`
	SearchGrounded     bool                     `json:"search_grounded"`
	DegradationWarning string                   `json:"degradation_warning,omitempty"`
	SearchWarning      string                   `json:"search_warning,omitempty"`
	ReadError          string                   `json:"read_error,omitempty"`
}

// ApplicationBinary represents one on-disk executable belonging to an application.
type ApplicationBinary struct {
	Path       string                   `json:"path"`
	Name       string                   `json:"name"`
	SHA256     string                   `json:"sha256,omitempty"`
	SizeBytes  int64                    `json:"size_bytes,omitempty"`
	Origin     string                   `json:"origin,omitempty"`
	Publisher  string                   `json:"publisher,omitempty"`
	Version    string                   `json:"version,omitempty"`
	Inspection provenance.BinaryMetadata `json:"inspection,omitempty"`
	Evidence   []provenance.Evidence    `json:"evidence,omitempty"`
	ReadError  string                   `json:"read_error,omitempty"`
}

// ApplicationIdentity captures the identified software product, independent of ownership.
type ApplicationIdentity struct {
	Name       string                `json:"name"`
	Publisher  string                `json:"publisher,omitempty"`
	Version    string                `json:"version,omitempty"`
	Ecosystem  string                `json:"ecosystem,omitempty"`
	Confidence provenance.Confidence `json:"confidence"`
	Signals    []string              `json:"signals,omitempty"`
}

// BinaryNames returns a list of executable names belonging to this application.
func (a *Application) BinaryNames() []string {
	names := make([]string, len(a.Binaries))
	for i, b := range a.Binaries {
		names[i] = b.Name
	}
	return names
}

// PrimarySHA256 returns the SHA-256 hash of the primary executable if available.
func (a *Application) PrimarySHA256() string {
	if len(a.Binaries) == 0 {
		return ""
	}
	for _, b := range a.Binaries {
		if b.Path == a.PrimaryBinaryPath && b.SHA256 != "" {
			return b.SHA256
		}
	}
	return a.Binaries[0].SHA256
}
