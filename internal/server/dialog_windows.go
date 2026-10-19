//go:build windows

package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"os/exec"
	"strings"
	"time"
	"unicode/utf16"
)

// showNativeFolderDialog launches a native Windows FolderBrowserDialog on the user's desktop
// and returns the selected folder path, or empty string if cancelled.
func showNativeFolderDialog(title string) (string, error) {
	if title == "" {
		title = "Select Folder to Audit (AppAudit)"
	}
	// Escape single quotes in title
	escapedTitle := strings.ReplaceAll(title, "'", "''")
	psScript := `$ProgressPreference = 'SilentlyContinue';
Add-Type -AssemblyName System.Windows.Forms;
Add-Type -AssemblyName System.Drawing;
$f = New-Object System.Windows.Forms.Form;
$f.TopMost = $true;
$f.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen;
$f.Size = New-Object System.Drawing.Size(1, 1);
$f.Opacity = 0.0;
$f.ShowInTaskbar = $false;
$null = $f.Show();
$null = $f.Focus();
$null = $f.Activate();
$null = $f.BringToFront();
$d = New-Object System.Windows.Forms.FolderBrowserDialog;
$d.Description = '` + escapedTitle + `';
$d.ShowNewFolderButton = $true;
$d.AutoUpgradeEnabled = $true;
$res = $d.ShowDialog($f);
if ($res -eq [System.Windows.Forms.DialogResult]::OK -and $d.SelectedPath) {
    [Console]::Out.Write($d.SelectedPath);
}
$null = $f.Close();
$null = $f.Dispose();
`
	return runPowerShellDialog(psScript)
}

// showNativeFileDialog launches a native Windows OpenFileDialog on the user's desktop
// for executable files (.exe, .dll) and returns the chosen absolute path.
func showNativeFileDialog(title string, filter string) (string, error) {
	if title == "" {
		title = "Select Application Binary (AppAudit)"
	}
	if filter == "" {
		filter = "Windows Executables (*.exe;*.dll)|*.exe;*.dll|All Files (*.*)|*.*"
	}
	escapedTitle := strings.ReplaceAll(title, "'", "''")
	escapedFilter := strings.ReplaceAll(filter, "'", "''")
	psScript := `$ProgressPreference = 'SilentlyContinue';
Add-Type -AssemblyName System.Windows.Forms;
Add-Type -AssemblyName System.Drawing;
$f = New-Object System.Windows.Forms.Form;
$f.TopMost = $true;
$f.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen;
$f.Size = New-Object System.Drawing.Size(1, 1);
$f.Opacity = 0.0;
$f.ShowInTaskbar = $false;
$null = $f.Show();
$null = $f.Focus();
$null = $f.Activate();
$null = $f.BringToFront();
$d = New-Object System.Windows.Forms.OpenFileDialog;
$d.Title = '` + escapedTitle + `';
$d.Filter = '` + escapedFilter + `';
$d.CheckFileExists = $true;
$d.Multiselect = $false;
$d.AutoUpgradeEnabled = $true;
$res = $d.ShowDialog($f);
if ($res -eq [System.Windows.Forms.DialogResult]::OK -and $d.FileName) {
    [Console]::Out.Write($d.FileName);
}
$null = $f.Close();
$null = $f.Dispose();
`
	return runPowerShellDialog(psScript)
}

func runPowerShellDialog(script string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// Encode script to UTF-16LE Base64 so PowerShell receives it safely without stdin or escaping issues
	utf16Bytes := utf16LEEncode(script)
	b64Script := base64.StdEncoding.EncodeToString(utf16Bytes)

	cmd := exec.CommandContext(ctx, "powershell", "-Sta", "-NoProfile", "-ExecutionPolicy", "Bypass", "-EncodedCommand", b64Script)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		errMsg := strings.TrimSpace(stderr.String())
		if errMsg != "" {
			return "", fmt.Errorf("%w: %s", err, errMsg)
		}
		return "", err
	}
	clean := strings.TrimSpace(string(out))
	if strings.EqualFold(clean, "true") || strings.EqualFold(clean, "false") {
		return "", nil
	}
	clean = strings.TrimPrefix(clean, "True")
	clean = strings.TrimPrefix(clean, "False")
	clean = strings.TrimSpace(clean)
	return clean, nil
}

func utf16LEEncode(s string) []byte {
	u16 := utf16.Encode([]rune(s))
	b := make([]byte, len(u16)*2)
	for i, v := range u16 {
		b[i*2] = byte(v)
		b[i*2+1] = byte(v >> 8)
	}
	return b
}


