//go:build windows

package scanner

import (
	"testing"
)

func TestWindowsScanner(t *testing.T) {
	s := newPlatformScanner()
	apps, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	t.Logf("Discovered %d applications on Windows host", len(apps))
	if len(apps) == 0 {
		t.Errorf("Expected to discover applications, got 0")
	}
}

func BenchmarkWindowsScanner(b *testing.B) {
	s := newPlatformScanner()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = s.Scan()
	}
}

