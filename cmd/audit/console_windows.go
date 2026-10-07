//go:build windows

package main

import (
	"bufio"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

var (
	kernel32Dll               = syscall.NewLazyDLL("kernel32.dll")
	procGetConsoleProcessList = kernel32Dll.NewProc("GetConsoleProcessList")
)

// pauseIfStandalone checks if the process was launched by double-clicking in Windows Explorer
// (meaning Windows created a temporary console window exclusively for this process).
// If so, it pauses execution before exit so the user can inspect the output.
func pauseIfStandalone() {
	// If stdout is redirected or piped (e.g., CI/CD, JSON pipe, script), never pause
	if fi, err := os.Stdout.Stat(); err == nil {
		if (fi.Mode() & os.ModeCharDevice) == 0 {
			return
		}
	}

	if procGetConsoleProcessList.Find() != nil {
		return
	}

	var pids [2]uint32
	r, _, _ := procGetConsoleProcessList.Call(uintptr(unsafe.Pointer(&pids[0])), uintptr(len(pids)))
	// If process count is <= 1, this process is the sole client attached to the console (Explorer double-click)
	if r <= 1 {
		fmt.Print("\nPress Enter to exit...")
		_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
	}
}
