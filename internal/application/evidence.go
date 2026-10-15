package application

import (
	"fmt"
	"strings"

	"github.com/example/appaudit/internal/provenance"
)

// EvidenceBundle aggregates forensic binary facts and structural application context
// for consumption by the decision engine and optional AI reasoners.
type EvidenceBundle struct {
	AppName          string                `json:"app_name"`
	Publisher        string                `json:"publisher,omitempty"`
	Version          string                `json:"version,omitempty"`
	Origin           string                `json:"origin,omitempty"`
	InstallDir       string                `json:"install_dir,omitempty"`
	PrimaryBinary    ApplicationBinary     `json:"primary_binary"`
	Binaries         []ApplicationBinary   `json:"binaries"`
	IdentityEvidence []provenance.Evidence `json:"identity_evidence,omitempty"`
	Evidence         []provenance.Evidence `json:"evidence"`
	Candidates       []string              `json:"candidates,omitempty"`
	Reasons          []string                     `json:"reasons,omitempty"`
	IsWrapperStub    bool                         `json:"is_wrapper_stub,omitempty"`
	PackageReceipt   *provenance.PackageReceipt   `json:"package_receipt,omitempty"`
	RuntimeReceipt   *provenance.RuntimeReceipt   `json:"runtime_receipt,omitempty"`
	StringSignatures *provenance.StringSignatures `json:"string_signatures,omitempty"`
	HashLookupResult *provenance.HashLookupResult `json:"hash_lookup_result,omitempty"`
	ReadError        string                       `json:"read_error,omitempty"`
}

// HasExactHashMatch checks if any binary has an exact public release SHA-256 match.
func (eb *EvidenceBundle) HasExactHashMatch() (provenance.Evidence, bool) {
	for _, ev := range eb.Evidence {
		if ev.Type == provenance.EvidenceExactHashMatch || (ev.Type == provenance.EvidenceReleaseAssetMatch && ev.Strength >= 0.95) {
			return ev, true
		}
	}
	return provenance.Evidence{}, false
}

// HasCompanyManifestMatch checks if any binary in the application bundle matches an explicitly registered company application.
func (eb *EvidenceBundle) HasCompanyManifestMatch(manifest *CompanyManifest) (provenance.Evidence, bool) {
	if manifest == nil || len(manifest.Entries) == 0 {
		return provenance.Evidence{}, false
	}
	for _, b := range eb.Binaries {
		if entry, ok := manifest.FindMatch(b.SHA256, b.Path, b.Name); ok {
			shortHash := entry.SHA256
			if len(shortHash) > 12 {
				shortHash = shortHash[:12] + "..."
			}
			return provenance.Evidence{
				Type:        provenance.EvidenceCompanyProvenance,
				Source:      "Company Registry",
				Strength:    1.0,
				Description: fmt.Sprintf("Explicitly registered internal company application '%s' (SHA-256: %s)", entry.Name, shortHash),
				Confidence:  provenance.ConfidenceVeryHigh,
			}, true
		}
	}
	return provenance.Evidence{}, false
}

// HasCompanySignature checks if any binary has a verified internal company code-signing certificate or module.
func (eb *EvidenceBundle) HasCompanySignature(indicators []string) (provenance.Evidence, bool) {
	for _, ev := range eb.Evidence {
		if ev.Type == provenance.EvidenceCompanyProvenance && ev.Strength >= 0.80 {
			return ev, true
		}
	}

	// Check binary inspection metadata directly
	for _, b := range eb.Binaries {
		if b.Inspection.IsSigned && b.Inspection.SignatureValid && b.Inspection.CertSubject != "" {
			signer := b.Inspection.CertSubject
			signerLower := strings.ToLower(signer)
			for _, ind := range indicators {
				if strings.Contains(signerLower, strings.ToLower(ind)) {
					return provenance.Evidence{
						Type:        provenance.EvidenceCompanyProvenance,
						Source:      "Authenticode Certificate",
						Strength:    0.95,
						Description: "Binary Authenticode certificate matches internal company identity: " + signer,
						Confidence:  provenance.ConfidenceVeryHigh,
					}, true
				}
			}
		}
		if b.Inspection.BuildInfo != nil && b.Inspection.BuildInfo.MainModule != "" {
			modLower := strings.ToLower(b.Inspection.BuildInfo.MainModule)
			for _, ind := range indicators {
				if strings.Contains(modLower, strings.ToLower(ind)) {
					return provenance.Evidence{
						Type:        provenance.EvidenceCompanyProvenance,
						Source:      "Go BuildInfo",
						Strength:    0.90,
						Description: "Compiler buildinfo main module matches internal company domain: " + b.Inspection.BuildInfo.MainModule,
						Confidence:  provenance.ConfidenceHigh,
					}, true
				}
			}
		}
	}

	return provenance.Evidence{}, false
}

// HasExternalSignature checks if any binary has a genuinely valid Authenticode signature from a non-company signer.
// Deployment assumption: A genuinely valid Authenticode signature from a signer that is not an identified internal/company
// signer is sufficient to recognize the application as third-party.
// Whitelists of hardcoded vendors are not required; unauthenticated PE strings are never treated as signatures.
func (eb *EvidenceBundle) HasExternalSignature(companyIndicators []string) (provenance.Evidence, bool) {
	for _, b := range eb.Binaries {
		if !b.Inspection.IsSigned || !b.Inspection.SignatureValid || b.Inspection.CertSubject == "" {
			continue
		}
		signer := b.Inspection.CertSubject
		signerLower := strings.ToLower(signer)

		isCompany := false
		for _, ind := range companyIndicators {
			if ind != "" && strings.Contains(signerLower, strings.ToLower(ind)) {
				isCompany = true
				break
			}
		}
		if isCompany {
			continue
		}

		return provenance.Evidence{
			Type:        provenance.EvidencePublisherSignature,
			Source:      "Authenticode Certificate",
			Strength:    0.95,
			Description: "Binary cryptographically signed by external publisher: " + signer,
			Confidence:  provenance.ConfidenceHigh,
		}, true
	}

	for _, ev := range eb.Evidence {
		if ev.Type == provenance.EvidencePublisherSignature && ev.Strength >= 0.80 {
			descLower := strings.ToLower(ev.Description)
			isCompany := false
			for _, ind := range companyIndicators {
				if ind != "" && strings.Contains(descLower, strings.ToLower(ind)) {
					isCompany = true
					break
				}
			}
			if !isCompany {
				return ev, true
			}
		}
	}

	return provenance.Evidence{}, false
}

// HasExternalProductMetadata checks if any binary has strong verified external product metadata.
func (eb *EvidenceBundle) HasExternalProductMetadata() (provenance.Evidence, bool) {
	for _, ev := range eb.Evidence {
		if ev.Type == provenance.EvidenceProductMetadata && ev.Strength >= 0.70 {
			return ev, true
		}
	}
	return provenance.Evidence{}, false
}

// HasEmbeddedComponent checks if any binary contains embedded string signatures for a given component.
func (eb *EvidenceBundle) HasEmbeddedComponent(compName string) bool {
	target := strings.ToLower(compName)
	for _, b := range eb.Binaries {
		for _, comp := range b.Inspection.Components {
			if strings.Contains(strings.ToLower(comp), target) {
				return true
			}
		}
	}
	return false
}

// HasSiblingBinary checks if the application suite contains an executable matching the given base name.
func (eb *EvidenceBundle) HasSiblingBinary(baseName string) bool {
	target := CanonicalBinaryBase(baseName)
	for _, b := range eb.Binaries {
		if CanonicalBinaryBase(b.Name) == target {
			return true
		}
	}
	return false
}

// SiblingCount returns the number of executables in this application.
func (eb *EvidenceBundle) SiblingCount() int {
	return len(eb.Binaries)
}
