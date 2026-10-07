package provenance

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

// Fingerprint holds cryptographic and physical properties of a local binary.
type Fingerprint struct {
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// ComputeFingerprint calculates the SHA-256 digest and file size for a local executable.
// It streams the file content without loading the entire binary into memory.
// Crucially, this operation is strictly local; the binary is never uploaded.
func ComputeFingerprint(filePath string) (Fingerprint, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return Fingerprint{}, fmt.Errorf("open file for fingerprinting: %w", err)
	}
	defer f.Close()

	h := sha256.New()
	written, err := io.Copy(h, f)
	if err != nil {
		return Fingerprint{}, fmt.Errorf("hash file stream: %w", err)
	}

	return Fingerprint{
		SHA256: hex.EncodeToString(h.Sum(nil)),
		Size:   written,
	}, nil
}
