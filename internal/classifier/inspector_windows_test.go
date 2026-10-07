//go:build windows

package classifier

import (
	"os/exec"
	"testing"
)

func TestInspectPlatformBinary(t *testing.T) {
	c := New()

	// 1. Test signed/commercial Windows binary
	cmdPath, err := exec.LookPath("cmd.exe")
	if err == nil {
		res := inspectPlatformBinary(cmdPath, c.knownPublishers)
		t.Logf("cmd.exe inspection: Commercial=%v, Publisher=%q, Evidence=%q",
			res.IsCommercial, res.Publisher, res.Evidence)
		if !res.IsCommercial {
			t.Errorf("Expected cmd.exe to be identified as commercial, got %v", res.IsCommercial)
		}
	}

	// 2. Test powershell.exe
	psPath, err := exec.LookPath("powershell.exe")
	if err == nil {
		res := inspectPlatformBinary(psPath, c.knownPublishers)
		t.Logf("powershell.exe inspection: Commercial=%v, Publisher=%q, Evidence=%q",
			res.IsCommercial, res.Publisher, res.Evidence)
		if !res.IsCommercial {
			t.Errorf("Expected powershell.exe to be commercial, got %v", res.IsCommercial)
		}
	}

	// 3. Test bfscfg.exe
	bfscfgPath := `C:\windows\system32\bfscfg.exe`
	resBfs := inspectPlatformBinary(bfscfgPath, c.knownPublishers)
	t.Logf("bfscfg.exe inspection: Commercial=%v, Publisher=%q, Desc=%q, Evidence=%q",
		resBfs.IsCommercial, resBfs.Publisher, resBfs.Description, resBfs.Evidence)
}
