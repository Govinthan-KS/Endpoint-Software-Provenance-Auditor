package server

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"
)

var (
	// Windows user directory regex: C:\Users\<username>\...
	winUserRegex = regexp.MustCompile(`(?i)([a-zA-Z]:\\Users\\)[^\\]+`)

	// Unix / Mac home directory regex: /home/<username>/... or /Users/<username>/...
	unixUserRegex = regexp.MustCompile(`(/(?:home|Users)/)[^/]+`)

	// Google API key regex: AIzaSy...
	geminiKeyRegex = regexp.MustCompile(`(AIza[0-9A-Za-z-_]{2})[0-9A-Za-z-_]+`)

	// DeepSeek / OpenAI style API key: sk-...
	deepseekKeyRegex = regexp.MustCompile(`(sk-[0-9A-Za-z-_]{4})[0-9A-Za-z-_]+`)

	// Bearer token regex
	bearerRegex = regexp.MustCompile(`(?i)(Bearer\s+[0-9A-Za-z-_]{4})[0-9A-Za-z-_]+`)

	// URL embedded credentials regex: https://user:pass@host
	urlCredsRegex = regexp.MustCompile(`://([^:]+):([^@]+)@`)

	// Temporary upload path pattern: appaudit-upload-*.exe
	tempUploadRegex = regexp.MustCompile(`(?i)appaudit-upload-[0-9a-zA-Z_-]+\.exe`)
)

// MaskPII replaces sensitive paths, usernames, and credentials with masked placeholders.
func MaskPII(input string) string {
	if input == "" {
		return ""
	}

	res := input

	if home, err := os.UserHomeDir(); err == nil && len(home) > 3 {
		cleanHome := strings.TrimRight(home, "\\/")
		parts := strings.Split(cleanHome, string(os.PathSeparator))
		if len(parts) >= 2 {
			maskedHome := strings.Join(parts[:len(parts)-1], string(os.PathSeparator)) + string(os.PathSeparator) + "***"
			res = strings.ReplaceAll(res, cleanHome, maskedHome)
		}
	}

	res = winUserRegex.ReplaceAllString(res, "${1}***")
	res = unixUserRegex.ReplaceAllString(res, "${1}***")
	res = geminiKeyRegex.ReplaceAllString(res, "${1}***")
	res = deepseekKeyRegex.ReplaceAllString(res, "${1}***")
	res = bearerRegex.ReplaceAllString(res, "${1}***")
	res = urlCredsRegex.ReplaceAllString(res, "://${1}:***@")

	return res
}

// SanitizeClientLog produces friendly, sanitized messages for the frontend browser log.
// It removes technical noise like temporary upload filenames, stack frames, and sensitive paths.
func SanitizeClientLog(msg string) string {
	if msg == "" {
		return ""
	}

	clean := MaskPII(msg)
	clean = tempUploadRegex.ReplaceAllString(clean, "[uploaded-binary]")
	clean = strings.TrimSpace(clean)

	return clean
}

func (s *Server) logInfo(format string, args ...interface{}) {
	ts := time.Now().Format("15:04:05")
	fmt.Printf("[%s] [INFO]  %s\n", ts, MaskPII(fmt.Sprintf(format, args...)))
}

func (s *Server) logDetail(format string, args ...interface{}) {
	ts := time.Now().Format("15:04:05")
	fmt.Printf("   [%s] -> %s\n", ts, MaskPII(fmt.Sprintf(format, args...)))
}

func (s *Server) logWarn(format string, args ...interface{}) {
	ts := time.Now().Format("15:04:05")
	fmt.Printf("   [%s] [WARN]  %s\n", ts, MaskPII(fmt.Sprintf(format, args...)))
}

func (s *Server) logError(format string, args ...interface{}) {
	ts := time.Now().Format("15:04:05")
	fmt.Fprintf(os.Stderr, "   [%s] [ERROR] %s\n", ts, MaskPII(fmt.Sprintf(format, args...)))
}

func (s *Server) logSuccess(format string, args ...interface{}) {
	ts := time.Now().Format("15:04:05")
	fmt.Printf("   [%s] [OK]    %s\n", ts, MaskPII(fmt.Sprintf(format, args...)))
}

func (s *Server) logRequest(method, path, clientIP string, status int, duration time.Duration, extra string) {
	ts := time.Now().Format("15:04:05")
	statusTag := "OK"
	if status >= 400 && status < 500 {
		statusTag = "WARN"
	} else if status >= 500 {
		statusTag = "ERR"
	}
	durStr := fmt.Sprintf("%.1fms", float64(duration.Microseconds())/1000.0)
	maskedExtra := MaskPII(extra)
	if maskedExtra != "" {
		fmt.Printf("[%s] [%-4s] %-4s %-22s %3d | %-7s | %s (%s)\n", ts, statusTag, method, path, status, durStr, maskedExtra, clientIP)
	} else {
		fmt.Printf("[%s] [%-4s] %-4s %-22s %3d | %-7s | (%s)\n", ts, statusTag, method, path, status, durStr, clientIP)
	}
}
