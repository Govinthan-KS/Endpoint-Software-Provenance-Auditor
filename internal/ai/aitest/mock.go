package aitest

import (
	"context"
	"errors"
	"time"

	"github.com/example/appaudit/internal/ai"
	"github.com/example/appaudit/internal/provenance"
)

// MockReasoner allows tests to simulate various AI outcomes and edge cases.
type MockReasoner struct {
	MockName      string
	Result        ai.ReasoningResult
	Err           error
	Delay         time.Duration
	MalformedJSON bool
}

func (m *MockReasoner) Name() string {
	if m.MockName != "" {
		return m.MockName
	}
	return "mock"
}

func (m *MockReasoner) Analyze(ctx context.Context, bundle any) (ai.ReasoningResult, error) {
	if m.Delay > 0 {
		select {
		case <-time.After(m.Delay):
		case <-ctx.Done():
			return ai.ReasoningResult{
				Classification: provenance.ClassificationUnknown,
				Confidence:     provenance.ConfidenceNone,
				Reasons:        []string{"AI reasoner timed out or was cancelled."},
			}, ctx.Err()
		}
	}

	if m.Err != nil {
		return ai.ReasoningResult{
			Classification: provenance.ClassificationUnknown,
			Confidence:     provenance.ConfidenceNone,
			Reasons:        []string{"AI reasoner encountered error: " + m.Err.Error()},
		}, m.Err
	}

	if m.MalformedJSON {
		return ai.ReasoningResult{
			Classification: provenance.ClassificationUnknown,
			Confidence:     provenance.ConfidenceNone,
			Reasons:        []string{"AI response validation failed: invalid schema."},
		}, errors.New("malformed JSON from model")
	}

	return m.Result, nil
}
