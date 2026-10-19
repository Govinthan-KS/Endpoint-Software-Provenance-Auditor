//go:build !windows

package server

func showNativeFolderDialog(title string) (string, error) {
	return "", nil
}

func showNativeFileDialog(title string, filter string) (string, error) {
	return "", nil
}
