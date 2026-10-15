package ai

import (
	"context"

	"github.com/example/appaudit/internal/provenance"
)

// NoopReasoner is the default reasoner when AI evaluation is disabled (--model none).
type NoopReasoner struct{}

// NewNoopReasoner returns a disabled reasoner.
func NewNoopReasoner() *NoopReasoner {
	return &NoopReasoner{}
}

func (n *NoopReasoner) Name() string {
	return "none"
}

func (n *NoopReasoner) Analyze(ctx context.Context, bundle any) (ReasoningResult, error) {
	return ReasoningResult{
		Classification: provenance.ClassificationUnknown,
		Confidence:     provenance.ConfidenceNone,
		Reasons:        []string{"AI reasoning layer disabled (--model none)."},
	}, nil
}

// ReasonBatch returns disabled provenance results for all bundles in the batch.
func (n *NoopReasoner) ReasonBatch(ctx context.Context, bundles []EvidenceBundle) ([]ReasoningResult, error) {
	results := make([]ReasoningResult, len(bundles))
	for i := range bundles {
		results[i], _ = n.Analyze(ctx, bundles[i])
	}
	return results, nil
}

