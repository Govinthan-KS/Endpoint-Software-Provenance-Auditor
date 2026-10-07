package provenance

import "context"

// ProvenanceProvider defines the contract for external and local intelligence sources.
type ProvenanceProvider interface {
	// Name returns the identifier of the provider.
	Name() string

	// Lookup evaluates an artifact and returns any discovered evidence and/or candidate identities.
	// Providers MUST never upload binary contents.
	// If a provider cannot establish provenance, it returns an empty evidence slice (never an error that implies company ownership).
	Lookup(ctx context.Context, artifact Artifact) ([]Evidence, []ProvenanceCandidate, error)
}
