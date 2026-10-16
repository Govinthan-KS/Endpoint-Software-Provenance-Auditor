//go:build windows

package service

import (
	"os/exec"
	"syscall"
)

// SetDetachedProcess sets Windows-specific creation flags to run background services
// without opening console windows. CREATE_NO_WINDOW (0x08000000) runs without a console
// window, while CREATE_NEW_PROCESS_GROUP (0x00000200) isolates it into its own process group.
// Note: CREATE_NO_WINDOW and DETACHED_PROCESS cannot be combined per Win32 CreateProcess spec.
func SetDetachedProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: 0x08000000 | 0x00000200, // CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP
	}
}
