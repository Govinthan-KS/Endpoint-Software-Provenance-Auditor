package provenance

import (
	"bytes"
	"crypto/x509"
	"debug/pe"
	"encoding/binary"
	"io"
	"os"
	"strings"
	"unicode/utf16"
)

// PEInspector analyzes Portable Executable (PE) files for detailed metadata and digital signatures.
type PEInspector struct{}

// NewPEInspector returns an initialized PEInspector.
func NewPEInspector() *PEInspector {
	return &PEInspector{}
}

// Inspect reads PE headers, version resources, Authenticode certificates, and build metadata.
func (p *PEInspector) Inspect(filePath string) (BinaryMetadata, error) {
	meta := BinaryMetadata{
		IsExecutable: true,
	}

	peFile, err := pe.Open(filePath)
	if err != nil {
		return meta, err
	}
	defer peFile.Close()

	// Machine architecture
	switch peFile.FileHeader.Machine {
	case pe.IMAGE_FILE_MACHINE_AMD64:
		meta.Architecture = "amd64"
	case pe.IMAGE_FILE_MACHINE_I386:
		meta.Architecture = "386"
	case pe.IMAGE_FILE_MACHINE_ARM64:
		meta.Architecture = "arm64"
	default:
		meta.Architecture = "unknown"
	}

	var securityDir pe.DataDirectory
	switch opt := peFile.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		meta.Subsystem = opt.Subsystem
		meta.IsGUI = (opt.Subsystem == 2)
		if len(opt.DataDirectory) > 4 {
			securityDir = opt.DataDirectory[4]
		}
	case *pe.OptionalHeader64:
		meta.Subsystem = opt.Subsystem
		meta.IsGUI = (opt.Subsystem == 2)
		if len(opt.DataDirectory) > 4 {
			securityDir = opt.DataDirectory[4]
		}
	}

	// 1. Version Resource Extraction (.rsrc)
	rsrc := peFile.Section(".rsrc")
	if rsrc != nil {
		sr := rsrc.Open()
		data, err := io.ReadAll(io.LimitReader(sr, 4*1024*1024))
		if err == nil && len(data) > 0 {
			meta.CompanyName = extractPEString(data, "CompanyName")
			meta.ProductName = extractPEString(data, "ProductName")
			meta.FileDescription = extractPEString(data, "FileDescription")
			meta.OriginalFilename = extractPEString(data, "OriginalFilename")
			meta.InternalName = extractPEString(data, "InternalName")
			meta.ProductVersion = extractPEString(data, "ProductVersion")
			meta.FileVersion = extractPEString(data, "FileVersion")
			meta.LegalCopyright = extractPEString(data, "LegalCopyright")
			meta.Comments = extractPEString(data, "Comments")
		}
	}

	// 2. Authenticode Certificate Extraction
	if securityDir.Size > 0 && securityDir.VirtualAddress > 0 {
		meta.IsSigned = true
		subject, issuer, valid := parseAuthenticodeCert(filePath, int64(securityDir.VirtualAddress), int64(securityDir.Size))
		if subject != "" {
			meta.CertSubject = subject
			meta.CertIssuer = issuer
			meta.SignatureValid = valid
			if meta.CompanyName == "" {
				meta.CompanyName = subject
			}
		}
	}

	// 3. Go & Ecosystem Build Metadata
	meta.BuildInfo = InspectBuildMetadata(filePath)

	// 4. Embedded Component Signatures
	meta.Components = DetectEmbeddedComponents(filePath)

	return meta, nil
}

// parseAuthenticodeCert extracts the X.509 signing certificate subject and issuer from the PE certificate directory.
func parseAuthenticodeCert(filePath string, offset, size int64) (subject, issuer string, valid bool) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", "", false
	}
	defer f.Close()

	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return "", "", false
	}

	// Read WIN_CERTIFICATE header (dwLength: 4B, wRevision: 2B, wCertificateType: 2B)
	var header struct {
		Length          uint32
		Revision        uint16
		CertificateType uint16
	}
	if err := binary.Read(f, binary.LittleEndian, &header); err != nil {
		return "", "", false
	}

	// wCertificateType == 0x0002 indicates WIN_CERT_TYPE_PKCS_SIGNED_DATA
	if header.CertificateType != 2 || header.Length <= 8 {
		return "", "", false
	}

	certData := make([]byte, header.Length-8)
	if _, err := io.ReadFull(f, certData); err != nil {
		return "", "", false
	}

	// Parse embedded X.509 certificates from the PKCS#7 signed data
	certs := extractX509Certs(certData)
	if len(certs) == 0 {
		return "Authenticode Signed Binary", "", true
	}

	// Leaf certificate is typically the code-signing certificate
	leaf := certs[0]
	sub := leaf.Subject.CommonName
	if len(leaf.Subject.Organization) > 0 {
		sub = leaf.Subject.Organization[0]
	}
	iss := leaf.Issuer.CommonName
	if len(leaf.Issuer.Organization) > 0 {
		iss = leaf.Issuer.Organization[0]
	}

	return sub, iss, true
}

func extractX509Certs(data []byte) []*x509.Certificate {
	var results []*x509.Certificate

	// Scan through raw data for DER sequence patterns of X.509 certificates
	// A certificate begins with ASN.1 SEQUENCE (0x30, 0x82, len1, len2) followed by 0x30, 0x82 (TBSCertificate)
	for i := 0; i+4 < len(data); i++ {
		if data[i] == 0x30 && data[i+1] == 0x82 {
			certLen := int(binary.BigEndian.Uint16(data[i+2:i+4])) + 4
			if i+certLen <= len(data) && certLen > 200 {
				candidate := data[i : i+certLen]
				if cert, err := x509.ParseCertificate(candidate); err == nil && cert != nil {
					results = append(results, cert)
					i += certLen - 1
				}
			}
		}
	}

	return results
}

// extractPEString extracts a UTF-16LE string associated with a key from PE resource tables.
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

	// Skip trailing null word and padding
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
