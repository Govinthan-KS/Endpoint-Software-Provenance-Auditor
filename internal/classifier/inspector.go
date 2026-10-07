package classifier

// BinaryInspectionResult represents the outcome of deep binary inspection.
type BinaryInspectionResult struct {
	IsCommercial bool   // True if verified via Authenticode, Developer ID, or package manager
	IsGUI        bool   // True if windowed GUI application (IMAGE_SUBSYSTEM_WINDOWS_GUI)
	Subsystem    uint16 // PE Subsystem code (2 = GUI, 3 = CUI/Console)
	Publisher    string // Extracted vendor/publisher name (e.g. from PE CompanyName or signing authority)
	Description  string // Extracted description or package name
	Evidence     string // Specific verification evidence
}
