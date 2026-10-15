package application

import (
	"testing"
)

func TestReconciler_PortableFFmpegGrouping(t *testing.T) {
	reconciler := NewReconciler()

	inputs := []RawInput{
		{
			Name:   "ffmpeg",
			Path:   `C:\Program Files\ffmpeg-7.1.1-essentials_build\bin\ffmpeg.exe`,
			Origin: "PATH",
		},
		{
			Name:   "ffplay",
			Path:   `C:\Program Files\ffmpeg-7.1.1-essentials_build\bin\ffplay.exe`,
			Origin: "PATH",
		},
		{
			Name:   "ffprobe",
			Path:   `C:\Program Files\ffmpeg-7.1.1-essentials_build\bin\ffprobe.exe`,
			Origin: "PATH",
		},
	}

	apps := reconciler.ReconcileRaw(inputs)

	if len(apps) != 1 {
		t.Fatalf("Expected 1 consolidated Application suite for portable FFmpeg, got %d", len(apps))
	}

	app := apps[0]
	if len(app.Binaries) != 3 {
		t.Fatalf("Expected 3 binaries in FFmpeg application suite, got %d", len(app.Binaries))
	}

	// Verify primary binary is ffmpeg.exe
	if app.Name != "ffmpeg" && app.Name != "ffmpeg-7.1.1-essentials_build" {
		t.Errorf("Unexpected app name: %s", app.Name)
	}
}

func TestReconciler_RegisteredSuiteMerging(t *testing.T) {
	reconciler := NewReconciler()

	inputs := []RawInput{
		{
			Name:      "PostgreSQL 16",
			Path:      `C:\Program Files\PostgreSQL\16\bin\postgres.exe`,
			Publisher: "PostgreSQL Global Development Group",
			Version:   "16.1",
			Origin:    "Registry",
		},
		{
			Name:      "pgAdmin 4",
			Path:      `C:\Program Files\PostgreSQL\16\pgAdmin 4\bin\pgAdmin4.exe`,
			Publisher: "PostgreSQL Global Development Group",
			Version:   "16.1",
			Origin:    "StartMenu",
		},
	}

	apps := reconciler.ReconcileRaw(inputs)

	if len(apps) != 1 {
		t.Fatalf("Expected 1 merged PostgreSQL application suite, got %d", len(apps))
	}

	if apps[0].Publisher != "PostgreSQL Global Development Group" {
		t.Errorf("Expected publisher PostgreSQL Global Development Group, got %s", apps[0].Publisher)
	}
}

func TestReconciler_NoiseFiltering(t *testing.T) {
	reconciler := NewReconciler()

	inputs := []RawInput{
		{
			Name:   "Microsoft Visual C++ 2015-2022 Redistributable",
			Path:   `C:\Windows\System32\vcruntime140.dll`,
			Origin: "Registry",
		},
		{
			Name:   "nodevars.bat",
			Path:   `C:\Program Files\nodejs\nodevars.bat`,
			Origin: "PATH",
		},
		{
			Name:   "git-upload-pack",
			Path:   `C:\Program Files\Git\bin\git-upload-pack.exe`,
			Origin: "PATH",
		},
	}

	apps := reconciler.ReconcileRaw(inputs)

	if len(apps) != 0 {
		t.Fatalf("Expected all noise/redistributable items to be filtered out, got %d", len(apps))
	}
}

func TestReconciler_MongoDBSuiteGrouping(t *testing.T) {
	reconciler := NewReconciler()

	inputs := []RawInput{
		{
			Name:   "mongod",
			Path:   `C:\Program Files\MongoDB\Server\8.0\bin\mongod.exe`,
			Origin: "Registry",
		},
		{
			Name:   "mongos",
			Path:   `C:\Program Files\MongoDB\Server\8.0\bin\mongos.exe`,
			Origin: "PATH",
		},
		{
			Name:   "mongosh",
			Path:   `C:\Program Files\MongoDB\Server\8.0\bin\mongosh.exe`,
			Origin: "PATH",
		},
	}

	apps := reconciler.ReconcileRaw(inputs)

	if len(apps) != 1 {
		t.Fatalf("Expected exactly 1 consolidated MongoDB application, got %d", len(apps))
	}

	app := apps[0]
	if len(app.Binaries) != 3 {
		t.Fatalf("Expected 3 binaries in MongoDB suite, got %d", len(app.Binaries))
	}

	if app.PrimaryBinaryPath != `C:\Program Files\MongoDB\Server\8.0\bin\mongod.exe` {
		t.Errorf("Expected primary binary to be mongod.exe, got %s", app.PrimaryBinaryPath)
	}
}

func TestReconciler_GoToolchainGrouping(t *testing.T) {
	reconciler := NewReconciler()

	inputs := []RawInput{
		{
			Name:   "go",
			Path:   `C:\Program Files\Go\bin\go.exe`,
			Origin: "PATH",
		},
		{
			Name:   "gofmt",
			Path:   `C:\Program Files\Go\bin\gofmt.exe`,
			Origin: "PATH",
		},
	}

	apps := reconciler.ReconcileRaw(inputs)

	if len(apps) != 1 {
		t.Fatalf("Expected exactly 1 consolidated Go toolchain application, got %d", len(apps))
	}

	app := apps[0]
	if len(app.Binaries) != 2 {
		t.Fatalf("Expected 2 binaries (go and gofmt) in Go toolchain, got %d", len(app.Binaries))
	}

	if app.PrimaryBinaryPath != `C:\Program Files\Go\bin\go.exe` {
		t.Errorf("Expected primary binary to be go.exe, got %s", app.PrimaryBinaryPath)
	}
}

func TestReconciler_AppWithHelperUpdaterRenderer(t *testing.T) {
	reconciler := NewReconciler()

	inputs := []RawInput{
		{
			Name:   "MyApp",
			Path:   `C:\Program Files\MyApp\myapp.exe`,
			Origin: "Registry",
		},
		{
			Name:   "myapp_helper",
			Path:   `C:\Program Files\MyApp\myapp_helper.exe`,
			Origin: "PATH",
		},
		{
			Name:   "myapp_updater",
			Path:   `C:\Program Files\MyApp\myapp_updater.exe`,
			Origin: "PATH",
		},
		{
			Name:   "renderer",
			Path:   `C:\Program Files\MyApp\renderer.exe`,
			Origin: "PATH",
		},
	}

	apps := reconciler.ReconcileRaw(inputs)

	if len(apps) != 1 {
		t.Fatalf("Expected 1 consolidated application suite for MyApp, got %d", len(apps))
	}

	app := apps[0]
	if len(app.Binaries) != 4 {
		t.Fatalf("Expected 4 binaries in MyApp suite, got %d", len(app.Binaries))
	}

	if app.PrimaryBinaryPath != `C:\Program Files\MyApp\myapp.exe` {
		t.Errorf("Expected primary binary to be myapp.exe, got %s", app.PrimaryBinaryPath)
	}
}

func TestReconciler_UnrelatedDownloadsDoNotMerge(t *testing.T) {
	reconciler := NewReconciler()

	inputs := []RawInput{
		{
			Name:   "aider",
			Path:   `C:\Users\testuser\Downloads\aider.exe`,
			Origin: "PATH",
		},
		{
			Name:   "ffmpeg",
			Path:   `C:\Users\testuser\Downloads\ffmpeg.exe`,
			Origin: "PATH",
		},
		{
			Name:   "standalone_tool",
			Path:   `C:\temp\standalone_tool.exe`,
			Origin: "PATH",
		},
	}

	apps := reconciler.ReconcileRaw(inputs)

	if len(apps) != 3 {
		t.Fatalf("Expected 3 independent applications for unrelated downloads/temp tools, got %d", len(apps))
	}

	names := make(map[string]bool)
	for _, a := range apps {
		names[a.Name] = true
		if len(a.Binaries) != 1 {
			t.Errorf("Expected standalone app %s to have exactly 1 binary, got %d", a.Name, len(a.Binaries))
		}
	}

	if !names["aider"] || !names["ffmpeg"] || !names["standalone_tool"] {
		t.Errorf("Expected apps aider, ffmpeg, and standalone_tool to be preserved independently, got: %+v", apps)
	}
}
