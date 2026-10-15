package ai_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/example/appaudit/internal/ai"
	"github.com/example/appaudit/internal/ai/aitest"
	"github.com/example/appaudit/internal/provenance"
)

func TestNoopReasoner(t *testing.T) {
	r := ai.NewNoopReasoner()
	res, err := r.Analyze(context.Background(), nil)
	if err != nil {
		t.Fatalf("Expected nil error from NoopReasoner, got %v", err)
	}
	if res.Classification != provenance.ClassificationUnknown {
		t.Errorf("Expected UNKNOWN, got %s", res.Classification)
	}
}

func TestMockReasoner_Outcomes(t *testing.T) {
	ctx := context.Background()

	// 1. Success Third-Party
	m1 := &aitest.MockReasoner{
		Result: ai.ReasoningResult{
			Classification: provenance.ClassificationThirdParty,
			Confidence:     provenance.ConfidenceHigh,
			Reasons:        []string{"Verified public project"},
		},
	}
	r1, err := m1.Analyze(ctx, nil)
	if err != nil || r1.Classification != provenance.ClassificationThirdParty {
		t.Errorf("Expected THIRD_PARTY, got %s (%v)", r1.Classification, err)
	}

	// 2. Success Company
	m2 := &aitest.MockReasoner{
		Result: ai.ReasoningResult{
			Classification: provenance.ClassificationCompany,
			Confidence:     provenance.ConfidenceHigh,
			Reasons:        []string{"Company internal tool"},
		},
	}
	r2, err := m2.Analyze(ctx, nil)
	if err != nil || r2.Classification != provenance.ClassificationCompany {
		t.Errorf("Expected COMPANY, got %s (%v)", r2.Classification, err)
	}

	// 3. Error
	m3 := &aitest.MockReasoner{
		Err: errors.New("backend failed"),
	}
	r3, err := m3.Analyze(ctx, nil)
	if err == nil || r3.Classification != provenance.ClassificationUnknown {
		t.Errorf("Expected error and UNKNOWN fallback, got %v and %s", err, r3.Classification)
	}

	// 4. Timeout
	timeoutCtx, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
	defer cancel()
	m4 := &aitest.MockReasoner{
		Delay: 100 * time.Millisecond,
	}
	r4, err := m4.Analyze(timeoutCtx, nil)
	if err == nil || r4.Classification != provenance.ClassificationUnknown {
		t.Errorf("Expected timeout error and UNKNOWN fallback, got %v and %s", err, r4.Classification)
	}

	// 5. Malformed JSON
	m5 := &aitest.MockReasoner{
		MalformedJSON: true,
	}
	r5, err := m5.Analyze(ctx, nil)
	if err == nil || r5.Classification != provenance.ClassificationUnknown {
		t.Errorf("Expected malformed error and UNKNOWN fallback, got %v and %s", err, r5.Classification)
	}
}
