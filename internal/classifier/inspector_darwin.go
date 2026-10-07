//go:build darwin

package classifier

import (
	"os/exec"
	"strings"
)

// inspectPlatformBinary verifies macOS code signatures using /usr/bin/codesign.
func inspectPlatformBinary(filePath string, knownPublishers []string) BinaryInspectionResult {
	cmd := exec.Command("/usr/bin/codesign", "-dv", filePath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return BinaryInspectionResult{
			IsCommercial: false,
			Evidence:     "Unsigned or ad-hoc binary (codesign check failed)",
		}
	}

	outStr := string(out)
	outLower := strings.ToLower(outStr)

	// Check for official Apple Root / Software Signing or Developer ID
	if strings.Contains(outStr, "Authority=Apple Root CA") ||
		strings.Contains(outStr, "Authority=Software Signing") ||
		strings.Contains(outStr, "Authority=Developer ID Application:") {
		
		pub := "Apple Developer ID"
		// Try extracting developer name
		if idx := strings.Index(outStr, "Authority=Developer ID Application: "); idx != -1 {
			sub := outStr[idx+len("Authority=Developer ID Application: "):]
			if endIdx := strings.Index(sub, "\n"); endIdx != -1 {
				pub = strings.TrimSpace(sub[:endIdx])
			}
		}

		return BinaryInspectionResult{
			IsCommercial: true,
			Publisher:    pub,
			Evidence:     "Verified Apple Developer ID code signature",
		}
	}

	for _, kp := range knownPublishers {
		if strings.Contains(outLower, kp) {
			return BinaryInspectionResult{
				IsCommercial: true,
				Publisher:    kp,
				Evidence:     "Verified established vendor signature identifier (" + kp + ")",
			}
		}
	}

	return BinaryInspectionResult{
		IsCommercial: false,
		Evidence:     "Lacks official Apple or Developer ID signature",
	}
}
