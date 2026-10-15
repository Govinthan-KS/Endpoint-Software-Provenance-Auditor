//go:build !windows

package provenance

func verifyWinTrust(_ string) bool {
	return false
}
