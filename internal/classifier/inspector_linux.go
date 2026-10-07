//go:build linux

package classifier

import (
	"os/exec"
	"strings"
)

// inspectPlatformBinary checks if a binary is owned by an official Linux package manager.
func inspectPlatformBinary(filePath string, knownPublishers []string) BinaryInspectionResult {
	// 1. Try Debian / Ubuntu dpkg
	if dpkgPath, err := exec.LookPath("dpkg"); err == nil && dpkgPath != "" {
		cmd := exec.Command(dpkgPath, "-S", filePath)
		out, err := cmd.Output()
		if err == nil && len(out) > 0 {
			pkg := strings.TrimSpace(string(out))
			if idx := strings.Index(pkg, ":"); idx != -1 {
				pkg = pkg[:idx]
			}
			return BinaryInspectionResult{
				IsCommercial: true,
				Publisher:    "Debian/Ubuntu Package",
				Description:  pkg,
				Evidence:     "Managed by system package manager (dpkg: " + pkg + ")",
			}
		}
	}

	// 2. Try RPM (RHEL, Fedora, CentOS, openSUSE)
	if rpmPath, err := exec.LookPath("rpm"); err == nil && rpmPath != "" {
		cmd := exec.Command(rpmPath, "-qf", filePath)
		out, err := cmd.Output()
		if err == nil && len(out) > 0 && !strings.Contains(string(out), "is not owned") {
			pkg := strings.TrimSpace(string(out))
			return BinaryInspectionResult{
				IsCommercial: true,
				Publisher:    "RPM Package",
				Description:  pkg,
				Evidence:     "Managed by system package manager (rpm: " + pkg + ")",
			}
		}
	}

	// 3. Try Pacman (Arch Linux)
	if pacmanPath, err := exec.LookPath("pacman"); err == nil && pacmanPath != "" {
		cmd := exec.Command(pacmanPath, "-Qo", filePath)
		out, err := cmd.Output()
		if err == nil && len(out) > 0 {
			pkg := strings.TrimSpace(string(out))
			return BinaryInspectionResult{
				IsCommercial: true,
				Publisher:    "Pacman Package",
				Description:  pkg,
				Evidence:     "Managed by system package manager (pacman: " + pkg + ")",
			}
		}
	}

	return BinaryInspectionResult{
		IsCommercial: false,
		Evidence:     "Not registered in system package manager",
	}
}
