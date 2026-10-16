//go:build !windows

package service

import (
	"os/exec"
)

// SetDetachedProcess is a no-op on non-Windows platforms.
func SetDetachedProcess(cmd *exec.Cmd) {
	// Background detached process handled by default on Unix
}
