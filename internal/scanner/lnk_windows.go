//go:build windows

package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"unicode/utf16"

	"github.com/example/appaudit/internal/model"
)

// parseLnkShortcut extracts the display name and target executable path from a .lnk shell link file.
func parseLnkShortcut(lnkPath string) (name, targetPath string, ok bool) {
	base := filepath.Base(lnkPath)
	name = strings.TrimSuffix(base, filepath.Ext(base))

	if model.IsIgnoredComponent(name) {
		return "", "", false
	}

	data, err := os.ReadFile(lnkPath)
	if err != nil || len(data) < 76 {
		return "", "", false
	}

	// Verify HeaderSize (must be 0x0000004C)
	if data[0] != 0x4C || data[1] != 0x00 || data[2] != 0x00 || data[3] != 0x00 {
		return "", "", false
	}

	targetPath = extractExeFromLnkBytes(data)
	if targetPath == "" || model.IsWebStub(targetPath) {
		return "", "", false
	}

	return name, targetPath, true
}

func extractExeFromLnkBytes(data []byte) string {
	// Look for drive letter pattern, e.g. "C:\" followed by ".exe" (ASCII or UTF-16LE)
	// Try ASCII first
	for i := 0; i+3 < len(data); i++ {
		b := data[i]
		if ((b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')) && data[i+1] == ':' && data[i+2] == '\\' {
			// Found drive root, extract until null terminator or non-printable
			end := i + 3
			for end < len(data) && data[end] != 0 && data[end] >= 32 {
				end++
			}
			candidate := string(data[i:end])
			if exe := extractExeCandidate(candidate); exe != "" {
				return exe
			}
		}
	}

	// Try UTF-16LE
	for i := 0; i+6 < len(data); i += 2 {
		b := data[i]
		if ((b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')) && data[i+1] == 0 &&
			data[i+2] == ':' && data[i+3] == 0 &&
			data[i+4] == '\\' && data[i+5] == 0 {

			var u16 []uint16
			pos := i
			for pos+1 < len(data) {
				char := uint16(data[pos]) | (uint16(data[pos+1]) << 8)
				pos += 2
				if char == 0 || char < 32 {
					break
				}
				u16 = append(u16, char)
				if len(u16) > 260 {
					break
				}
			}
			if len(u16) > 0 {
				candidate := string(utf16.Decode(u16))
				if exe := extractExeCandidate(candidate); exe != "" {
					return exe
				}
			}
		}
	}

	return ""
}

func extractExeCandidate(raw string) string {
	lower := strings.ToLower(raw)
	idx := strings.Index(lower, ".exe")
	if idx == -1 {
		return ""
	}
	clean := filepath.Clean(strings.Trim(raw[:idx+4], `"`))
	if strings.ToLower(filepath.Ext(clean)) != ".exe" {
		return ""
	}
	if fi, err := os.Stat(clean); err == nil && !fi.IsDir() {
		return clean
	}
	return ""
}
