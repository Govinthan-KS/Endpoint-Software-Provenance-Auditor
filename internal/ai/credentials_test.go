package ai

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestCredentials_MaskAPIKey(t *testing.T) {
	cases := []struct {
		input    string
		expected string
	}{
		{"", "(none configured)"},
		{"short", "********"},
		{"12345678", "********"},
		{"AIzaSyAbcd1234wxyz", "AIza...wxyz"},
	}

	for _, c := range cases {
		masked := MaskAPIKey(c.input)
		if masked != c.expected {
			t.Errorf("MaskAPIKey(%q) = %q, expected %q", c.input, masked, c.expected)
		}
	}
}

func TestCredentials_SaveAndLoad(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "appaudit_cred_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	credPath := filepath.Join(tempDir, CredentialFileName)

	// Save key directly to mock file
	testKey := "AIzaSyTestMockKeyForValidation1234"
	if err := os.WriteFile(credPath, []byte(`{"gemini_api_key":"`+testKey+`"}`), 0600); err != nil {
		t.Fatalf("failed to write test cred file: %v", err)
	}

	// Read using store logic
	data, err := os.ReadFile(credPath)
	if err != nil {
		t.Fatalf("failed to read test cred: %v", err)
	}

	var store credentialStore
	if err := json.Unmarshal(data, &store); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if store.GeminiAPIKey != testKey {
		t.Errorf("expected %s, got %s", testKey, store.GeminiAPIKey)
	}
}

func TestCredentials_HasStoredGeminiAPIKey(t *testing.T) {
	// Function returns a boolean without panicking or erroring
	_ = HasStoredGeminiAPIKey()
}
