package server

import (
	"strings"
	"testing"
)

func TestMaskPII(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Windows user path",
			input:    `Error processing C:\Users\alice\AppData\Local\tool.exe`,
			expected: `Error processing C:\Users\***\AppData\Local\tool.exe`,
		},
		{
			name:     "Unix user path",
			input:    `Error reading /home/bob/projects/app.bin`,
			expected: `Error reading /home/***/projects/app.bin`,
		},
		{
			name:     "Gemini API key",
			input:    `Using key AIzaSyA1B2C3D4E5F6G7H8I9J0 for reasoning`,
			expected: `Using key AIzaSy*** for reasoning`,
		},
		{
			name:     "DeepSeek API key",
			input:    `Token sk-1234567890abcdef1234567890abcdef authenticated`,
			expected: `Token sk-1234*** authenticated`,
		},
		{
			name:     "Embedded URL credentials",
			input:    `Connecting to http://admin:secretPass123@192.168.1.1:8080`,
			expected: `Connecting to http://admin:***@192.168.1.1:8080`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MaskPII(tt.input)
			if got != tt.expected {
				t.Errorf("MaskPII() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestSanitizeClientLog(t *testing.T) {
	input := `Inspecting temporary file C:\Users\govin\AppData\Local\Temp\appaudit-upload-98124.exe`
	cleaned := SanitizeClientLog(input)
	if strings.Contains(cleaned, "govin") {
		t.Errorf("SanitizeClientLog leaked username: %s", cleaned)
	}
	if strings.Contains(cleaned, "appaudit-upload-98124.exe") {
		t.Errorf("SanitizeClientLog leaked raw temp file: %s", cleaned)
	}
}
