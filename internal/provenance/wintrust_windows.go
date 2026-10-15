//go:build windows

package provenance

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	wintrust = windows.NewLazySystemDLL("wintrust.dll")
	procWinVerifyTrust = wintrust.NewProc("WinVerifyTrust")
)

const (
	WTD_UI_NONE             = 2
	WTD_REVOKE_NONE         = 0
	WTD_CHOICE_FILE         = 1
	WTD_STATEACTION_IGNORE  = 0
	WTD_SAFER_FLAG          = 0x00000100
)

type WINTRUST_FILE_INFO struct {
	cbStruct      uint32
	pcwszFilePath *uint16
	hFile         windows.Handle
	pgKnownSubject unsafe.Pointer
}

type WINTRUST_DATA struct {
	cbStruct            uint32
	pPolicyCallbackData unsafe.Pointer
	pSIPClientData      unsafe.Pointer
	dwUIChoice          uint32
	fdwRevocationChecks uint32
	dwUnionChoice       uint32
	pFile               unsafe.Pointer
	dwStateAction       uint32
	hWVTStateData       windows.Handle
	pwszURLReference    unsafe.Pointer
	dwProvFlags         uint32
	dwUIContext         uint32
	pSignatureSettings  unsafe.Pointer
}

// verifyWinTrust performs native Windows cryptographic Authenticode validation
// checking whether the file signature is cryptographically valid and signed by a trusted root.
func verifyWinTrust(filePath string) bool {
	if filePath == "" {
		return false
	}
	pathPtr, err := syscall.UTF16PtrFromString(filePath)
	if err != nil {
		return false
	}

	fileInfo := WINTRUST_FILE_INFO{
		cbStruct:      uint32(unsafe.Sizeof(WINTRUST_FILE_INFO{})),
		pcwszFilePath: pathPtr,
	}

	// WINTRUST_ACTION_GENERIC_VERIFY_V2: {00AAC56B-CD44-11d0-8CC2-00C04FC295EE}
	actionVerify := windows.GUID{
		Data1: 0x00aac56b,
		Data2: 0xcd44,
		Data3: 0x11d0,
		Data4: [8]byte{0x8c, 0xc2, 0x00, 0xc0, 0x4f, 0xc2, 0x95, 0xee},
	}

	wvtData := WINTRUST_DATA{
		cbStruct:            uint32(unsafe.Sizeof(WINTRUST_DATA{})),
		dwUIChoice:          WTD_UI_NONE,
		fdwRevocationChecks: WTD_REVOKE_NONE,
		dwUnionChoice:       WTD_CHOICE_FILE,
		pFile:               unsafe.Pointer(&fileInfo),
		dwStateAction:       WTD_STATEACTION_IGNORE,
		dwProvFlags:         WTD_SAFER_FLAG,
	}

	r1, _, _ := procWinVerifyTrust.Call(
		uintptr(windows.InvalidHandle),
		uintptr(unsafe.Pointer(&actionVerify)),
		uintptr(unsafe.Pointer(&wvtData)),
	)

	// Return code 0 (ERROR_SUCCESS) means signature is valid and trusted
	return int32(r1) == 0
}
