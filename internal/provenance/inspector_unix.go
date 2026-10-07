package provenance

import (
	"debug/elf"
	"debug/macho"
	"runtime"
)

// DefaultBinaryInspector returns a platform-appropriate BinaryInspector.
func DefaultBinaryInspector() BinaryInspector {
	switch runtime.GOOS {
	case "windows":
		return NewPEInspector()
	case "darwin":
		return NewMachOInspector()
	default:
		return NewELFInspector()
	}
}

// MachOInspector analyzes macOS Mach-O binaries.
type MachOInspector struct{}

func NewMachOInspector() *MachOInspector {
	return &MachOInspector{}
}

func (m *MachOInspector) Inspect(filePath string) (BinaryMetadata, error) {
	meta := BinaryMetadata{
		IsExecutable: true,
	}

	mf, err := macho.Open(filePath)
	if err == nil {
		defer mf.Close()
		switch mf.Cpu {
		case macho.CpuArm64:
			meta.Architecture = "arm64"
		case macho.CpuAmd64:
			meta.Architecture = "amd64"
		default:
			meta.Architecture = "unknown"
		}
	}

	meta.BuildInfo = InspectBuildMetadata(filePath)
	meta.Components = DetectEmbeddedComponents(filePath)
	return meta, nil
}

// ELFInspector analyzes Linux/FreeBSD ELF binaries.
type ELFInspector struct{}

func NewELFInspector() *ELFInspector {
	return &ELFInspector{}
}

func (e *ELFInspector) Inspect(filePath string) (BinaryMetadata, error) {
	meta := BinaryMetadata{
		IsExecutable: true,
	}

	ef, err := elf.Open(filePath)
	if err == nil {
		defer ef.Close()
		switch ef.Machine {
		case elf.EM_X86_64:
			meta.Architecture = "amd64"
		case elf.EM_AARCH64:
			meta.Architecture = "arm64"
		case elf.EM_386:
			meta.Architecture = "386"
		default:
			meta.Architecture = "unknown"
		}
	}

	meta.BuildInfo = InspectBuildMetadata(filePath)
	meta.Components = DetectEmbeddedComponents(filePath)
	return meta, nil
}
