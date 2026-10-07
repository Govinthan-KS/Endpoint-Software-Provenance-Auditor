//go:build !windows

package scanner

func parseLnkShortcut(lnkPath string) (name, targetPath string, ok bool) {
	return "", "", false
}
