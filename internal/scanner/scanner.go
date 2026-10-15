package scanner

import "github.com/example/appaudit/internal/model"

// ProgressFunc reports real-time scan metrics during deep filesystem discovery.
type ProgressFunc func(discoveredCount int, currentDirectory string)

// Scanner defines the interface for platform-specific system discovery.
type Scanner interface {
	Scan() ([]model.Application, error)
	FullScan(progress ProgressFunc) ([]model.Application, error)
}

// New returns the platform-specific Scanner implementation.
func New() Scanner {
	return newPlatformScanner()
}
