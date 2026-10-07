package provenance

// BinaryMetadata represents normalized metadata extracted from an executable binary across platforms.
type BinaryMetadata struct {
	IsExecutable     bool              `json:"is_executable"`
	IsGUI            bool              `json:"is_gui"`
	Architecture     string            `json:"architecture"`
	Subsystem        uint16            `json:"subsystem"`
	CompanyName      string            `json:"company_name,omitempty"`
	ProductName      string            `json:"product_name,omitempty"`
	FileDescription  string            `json:"file_description,omitempty"`
	OriginalFilename string            `json:"original_filename,omitempty"`
	InternalName     string            `json:"internal_name,omitempty"`
	ProductVersion   string            `json:"product_version,omitempty"`
	FileVersion      string            `json:"file_version,omitempty"`
	LegalCopyright   string            `json:"legal_copyright,omitempty"`
	Comments         string            `json:"comments,omitempty"`
	IsSigned         bool              `json:"is_signed"`
	SignatureValid   bool              `json:"signature_valid"`
	CertSubject      string            `json:"cert_subject,omitempty"`
	CertIssuer       string            `json:"cert_issuer,omitempty"`
	BuildInfo        *BuildMetadata    `json:"build_info,omitempty"`
	Components       []string          `json:"components,omitempty"`
	ExtraStrings     map[string]string `json:"extra_strings,omitempty"`
}

// BinaryInspector defines the contract for platform-specific binary format analysis.
type BinaryInspector interface {
	Inspect(filePath string) (BinaryMetadata, error)
}
