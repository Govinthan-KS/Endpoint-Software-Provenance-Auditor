package provenance

// Classification represents the provenance classification of an executable.
type Classification string

const (
	// ClassificationThirdParty indicates sufficiently strong evidence that the executable originated externally.
	ClassificationThirdParty Classification = "THIRD_PARTY"

	// ClassificationCompany indicates sufficiently strong evidence that the executable is company-developed or company-owned.
	ClassificationCompany Classification = "COMPANY"

	// ClassificationUnknown indicates provenance cannot be established with sufficient confidence.
	// Absence of public evidence NEVER proves company provenance; it results in UNKNOWN.
	ClassificationUnknown Classification = "UNKNOWN"
)

// Confidence represents the level of certainty supporting a classification.
type Confidence string

const (
	ConfidenceVeryHigh Confidence = "VERY_HIGH"
	ConfidenceHigh     Confidence = "HIGH"
	ConfidenceMedium   Confidence = "MEDIUM"
	ConfidenceLow      Confidence = "LOW"
	ConfidenceNone     Confidence = "NONE"
)

// EvidenceType categorizes the specific kind of evidence collected.
type EvidenceType string

const (
	EvidenceExactHashMatch     EvidenceType = "exact_hash_match"
	EvidenceReleaseAssetMatch  EvidenceType = "release_asset_match"
	EvidencePublisherSignature EvidenceType = "publisher_signature"
	EvidenceProductMetadata    EvidenceType = "product_metadata"
	EvidenceBuildMetadata      EvidenceType = "build_metadata"
	EvidenceProjectMatch       EvidenceType = "project_match"
	EvidenceComponentMatch     EvidenceType = "component_match"
	EvidencePackageMatch       EvidenceType = "package_match"
	EvidenceSearchResult       EvidenceType = "search_result"
	EvidenceInstallMetadata    EvidenceType = "install_metadata"
	EvidencePathHeuristic      EvidenceType = "path_heuristic"
	EvidenceCompanyProvenance  EvidenceType = "company_provenance"
)

// Evidence holds structured information describing an observation about an artifact.
type Evidence struct {
	Type        EvidenceType `json:"type"`
	Source      string       `json:"source"`
	Strength    float64      `json:"strength"` // 0.0 (weakest) to 1.0 (definitive)
	Description string       `json:"description"`
	URL         string       `json:"url,omitempty"`
	Confidence  Confidence   `json:"confidence"`
}

// ProvenanceCandidate represents a candidate external project or package discovered during research.
type ProvenanceCandidate struct {
	Name       string     `json:"name"`
	Publisher  string     `json:"publisher,omitempty"`
	ProjectURL string     `json:"project_url,omitempty"`
	Source     string     `json:"source"`
	Evidence   []Evidence `json:"evidence,omitempty"`
}

// BuildMetadata captures compiler and build environment information (e.g., from debug/buildinfo).
type BuildMetadata struct {
	Ecosystem   string            `json:"ecosystem"` // "go", "rust", "dotnet", "c_cpp", etc.
	GoVersion   string            `json:"go_version,omitempty"`
	MainModule  string            `json:"main_module,omitempty"`
	MainVersion string            `json:"main_version,omitempty"`
	MainSum     string            `json:"main_sum,omitempty"`
	Deps        []string          `json:"deps,omitempty"`
	Settings    map[string]string `json:"settings,omitempty"`
}

// Artifact represents an on-disk executable undergoing provenance analysis.
type Artifact struct {
	Name             string         `json:"name"`
	Path             string         `json:"path"`
	Fingerprint      Fingerprint    `json:"fingerprint"`
	Publisher        string         `json:"publisher,omitempty"`
	ProductName      string         `json:"product_name,omitempty"`
	Version          string         `json:"version,omitempty"`
	OriginalFilename string         `json:"original_filename,omitempty"`
	InternalName     string         `json:"internal_name,omitempty"`
	FileDescription  string         `json:"file_description,omitempty"`
	LegalCopyright   string         `json:"legal_copyright,omitempty"`
	Origin           string         `json:"origin"` // StartMenu, Registry, PATH, Process, DesktopEntry, AppBundle
	IsGUI            bool           `json:"is_gui"`
	BuildInfo        *BuildMetadata `json:"build_info,omitempty"`
	Components       []string       `json:"components,omitempty"`
}

// ClassificationResult represents the final, fully explainable provenance verdict for an artifact.
type ClassificationResult struct {
	Classification Classification        `json:"classification"`
	Confidence     Confidence            `json:"confidence"`
	Fingerprint    Fingerprint           `json:"fingerprint"`
	ProductName    string                `json:"product_name,omitempty"`
	Publisher      string                `json:"publisher,omitempty"`
	Version        string                `json:"version,omitempty"`
	Evidence       []Evidence            `json:"evidence"`
	Candidates     []ProvenanceCandidate `json:"candidates,omitempty"`
	Explanation    []string              `json:"explanation"`
}
