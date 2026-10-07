//go:build windows

package classifier

import (
	"bytes"
	"debug/pe"
	"io"
	"strings"
	"unicode/utf16"
)

// inspectPlatformBinary reads Windows PE headers and resource tables to verify publisher metadata.
func inspectPlatformBinary(filePath string, knownPublishers []string) BinaryInspectionResult {
	peFile, err := pe.Open(filePath)
	if err != nil {
		return BinaryInspectionResult{}
	}
	defer peFile.Close()

	var hasCert bool
	var subsystem uint16
	switch opt := peFile.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		subsystem = opt.Subsystem
		if len(opt.DataDirectory) > 4 && opt.DataDirectory[4].Size > 0 {
			hasCert = true
		}
	case *pe.OptionalHeader64:
		subsystem = opt.Subsystem
		if len(opt.DataDirectory) > 4 && opt.DataDirectory[4].Size > 0 {
			hasCert = true
		}
	}
	isGUI := (subsystem == 2) // IMAGE_SUBSYSTEM_WINDOWS_GUI

	var companyName, fileDesc, legalCopyright string
	rsrc := peFile.Section(".rsrc")
	if rsrc != nil {
		sr := rsrc.Open()
		data, err := io.ReadAll(io.LimitReader(sr, 2*1024*1024))
		if err == nil && len(data) > 0 {
			companyName = extractPEString(data, "CompanyName")
			fileDesc = extractPEString(data, "FileDescription")
			legalCopyright = extractPEString(data, "LegalCopyright")
		}
	}

	// 1. Authenticode Certificate Table is present
	if hasCert {
		pub := companyName
		if pub == "" {
			pub = "Authenticode Signed Binary"
		}
		return BinaryInspectionResult{
			IsCommercial: true,
			IsGUI:        isGUI,
			Subsystem:    subsystem,
			Publisher:    pub,
			Description:  fileDesc,
			Evidence:     "Verified Authenticode digital signature table in PE header",
		}
	}

	// 2. Verified Commercial Publisher in PE Metadata
	if companyName != "" {
		compLower := strings.ToLower(companyName)
		for _, kp := range knownPublishers {
			if strings.Contains(compLower, kp) {
				return BinaryInspectionResult{
					IsCommercial: true,
					IsGUI:        isGUI,
					Subsystem:    subsystem,
					Publisher:    companyName,
					Description:  fileDesc,
					Evidence:     "Verified commercial publisher (" + companyName + ") in PE version resource",
				}
			}
		}

		// Also check copyright notice
		if legalCopyright != "" {
			copyLower := strings.ToLower(legalCopyright)
			for _, kp := range knownPublishers {
				if strings.Contains(copyLower, kp) {
					return BinaryInspectionResult{
						IsCommercial: true,
						IsGUI:        isGUI,
						Subsystem:    subsystem,
						Publisher:    companyName,
						Description:  fileDesc,
						Evidence:     "Verified commercial copyright in PE version resource (" + legalCopyright + ")",
					}
				}
			}
		}
	}

	// Unsigned and lacks commercial metadata
	return BinaryInspectionResult{
		IsCommercial: false,
		IsGUI:        isGUI,
		Subsystem:    subsystem,
		Publisher:    companyName,
		Description:  fileDesc,
		Evidence:     "Unsigned binary lacking commercial vendor metadata",
	}
}

// extractPEString finds a UTF-16LE null-terminated string value following a key in resource data.
func extractPEString(data []byte, key string) string {
	runes := []rune(key)
	u16 := utf16.Encode(runes)
	keyBytes := make([]byte, len(u16)*2)
	for i, r := range u16 {
		keyBytes[i*2] = byte(r)
		keyBytes[i*2+1] = byte(r >> 8)
	}

	idx := bytes.Index(data, keyBytes)
	if idx == -1 {
		return ""
	}

	pos := idx + len(keyBytes)

	// Skip trailing null word and 32-bit padding zeros
	for pos+1 < len(data) && data[pos] == 0 && data[pos+1] == 0 {
		pos += 2
	}

	if pos >= len(data) {
		return ""
	}

	var u16Chars []uint16
	for pos+1 < len(data) {
		val := uint16(data[pos]) | (uint16(data[pos+1]) << 8)
		pos += 2
		if val == 0 {
			break
		}
		if val < 32 && val != '\t' && val != '\n' && val != '\r' {
			break
		}
		u16Chars = append(u16Chars, val)
		if len(u16Chars) > 256 {
			break
		}
	}

	if len(u16Chars) == 0 {
		return ""
	}

	return strings.TrimSpace(string(utf16.Decode(u16Chars)))
}
