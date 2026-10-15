//go:build windows

package scanner_test

import (
	"testing"

	"github.com/example/appaudit/internal/scanner"
)

func TestWindowsScanner(t *testing.T) {
	s := scanner.New()
	apps, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	t.Logf("Discovered %d applications on Windows host", len(apps))
	if len(apps) == 0 {
		t.Errorf("Expected to discover applications, got 0")
	}
}

func TestWindowsScanner_FullScan(t *testing.T) {
	s := scanner.New()
	var progressReports int
	apps, err := s.FullScan(func(discoveredCount int, currentPath string) {
		progressReports++
	})
	if err != nil {
		t.Fatalf("FullScan failed: %v", err)
	}
	t.Logf("FullScan discovered %d applications (%d progress callbacks)", len(apps), progressReports)
	if len(apps) == 0 {
		t.Errorf("Expected to discover applications during FullScan, got 0")
	}
}

func BenchmarkWindowsScanner(b *testing.B) {
	s := scanner.New()
	b.ResetTimer()
	for b.Loop() {
		_, _ = s.Scan()
	}
}
