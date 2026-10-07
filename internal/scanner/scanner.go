package scanner

import "github.com/example/appaudit/internal/model"

// Scanner defines the interface for platform-specific system discovery.
type Scanner interface {
	Scan() ([]model.Application, error)
}

// New returns the platform-specific Scanner implementation.
func New() Scanner {
	return newPlatformScanner()
}
