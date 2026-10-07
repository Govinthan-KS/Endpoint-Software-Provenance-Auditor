//go:build !windows && !darwin && !linux

package classifier

// inspectPlatformBinary provides a fallback implementation for unsupported/generic POSIX systems.
func inspectPlatformBinary(filePath string, knownPublishers []string) BinaryInspectionResult {
	return BinaryInspectionResult{
		IsCommercial: false,
		Evidence:     "Platform binary inspection not supported",
	}
}
