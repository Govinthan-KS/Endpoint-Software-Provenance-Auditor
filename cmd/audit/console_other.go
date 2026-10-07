//go:build !windows

package main

// pauseIfStandalone is a no-op on non-Windows platforms.
func pauseIfStandalone() {
}
