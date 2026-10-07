package classifier

import (
	"path/filepath"
	"testing"

	"github.com/example/appaudit/internal/model"
	"github.com/example/appaudit/internal/provenance"
)

func TestClassifierRules(t *testing.T) {
	c := New()

	tests := []struct {
		name          string
		app           model.Application
		expectedClass string
		expectedCat   model.Category
	}{
		{
			name: "Third-Party Registry entry with Microsoft publisher",
			app: model.Application{
				Name:      "Visual Studio Code",
				Path:      `C:\Program Files\Microsoft VS Code\Code.exe`,
				Publisher: "Microsoft Corporation",
				Origin:    "Registry",
			},
			expectedClass: "THIRD_PARTY",
			expectedCat:   model.CategoryThirdParty,
		},
		{
			name: "Third-Party macOS AppBundle with verified vendor",
			app: model.Application{
				Name:      "Slack",
				Path:      "/Applications/Slack.app",
				Publisher: "Slack Technologies",
				Origin:    "AppBundle",
			},
			expectedClass: "THIRD_PARTY",
			expectedCat:   model.CategoryThirdParty,
		},
		{
			name: "Third-Party Linux Desktop Entry with Mozilla publisher",
			app: model.Application{
				Name:      "Firefox",
				Path:      "/usr/bin/firefox",
				Publisher: "org.mozilla",
				Origin:    "DesktopEntry",
			},
			expectedClass: "THIRD_PARTY",
			expectedCat:   model.CategoryThirdParty,
		},
		{
			name: "Unverified binary in system folder lacking corroboration",
			app: model.Application{
				Name:   "rogue_service",
				Path:   `C:\Program Files\rogue_service.exe`,
				Origin: "Process",
			},
			expectedClass: "UNKNOWN",
			expectedCat:   model.CategoryUnknown,
		},
		{
			name: "Unmanaged custom process in user directory without external evidence",
			app: model.Application{
				Name:   "custom_agent",
				Path:   `C:\CustomTools\custom_agent.exe`,
				Origin: "Process",
			},
			expectedClass: "UNKNOWN",
			expectedCat:   model.CategoryUnknown,
		},
		{
			name: "Generic colliding name without corroboration",
			app: model.Application{
				Name:   "sync.exe",
				Path:   `C:\Tools\sync.exe`,
				Origin: "Path",
			},
			expectedClass: "UNKNOWN",
			expectedCat:   model.CategoryUnknown,
		},
		{
			name: "Portable tool with known commercial publisher",
			app: model.Application{
				Name:      "Putty",
				Path:      `C:\Users\User\Desktop\putty.exe`,
				Publisher: "Simon Tatham",
				Origin:    "Path",
			},
			expectedClass: "THIRD_PARTY",
			expectedCat:   model.CategoryThirdParty,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c.ClassifyApp(&tc.app)
			if tc.app.Classification != tc.expectedClass {
				t.Errorf("Expected classification %q, got %q", tc.expectedClass, tc.app.Classification)
			}
			if tc.app.Category != tc.expectedCat {
				t.Errorf("Expected category %q, got %q", tc.expectedCat, tc.app.Category)
			}
		})
	}
}

func TestReconcileAndClassify(t *testing.T) {
	c := New()

	apps := []model.Application{
		{
			Name:      "Google Chrome",
			Path:      `C:\Program Files\Google\Chrome\Application`,
			Publisher: "Google LLC",
			Origin:    "Registry",
		},
		{
			Name:   "chrome",
			Path:   `C:\Program Files\Google\Chrome\Application\chrome.exe`,
			Origin: "Process",
		},
		{
			Name:   "unmapped-tool",
			Path:   `C:\Users\User\go\bin\unmapped-tool.exe`,
			Origin: "Process",
		},
	}

	results := c.ReconcileAndClassify(apps)

	// chrome.exe process should be merged into registered Google Chrome
	var unknownCount, thirdPartyCount int
	for _, app := range results {
		if app.Category == model.CategoryUnknown {
			unknownCount++
			if app.Name != "unmapped-tool" {
				t.Errorf("Unexpected unknown app: %s", app.Name)
			}
		} else if app.Category == model.CategoryThirdParty {
			thirdPartyCount++
			if app.Name != "Google Chrome" {
				t.Errorf("Unexpected third-party app: %s", app.Name)
			}
		}
	}

	if unknownCount != 1 {
		t.Errorf("Expected 1 unknown app, got %d", unknownCount)
	}
	if thirdPartyCount != 1 {
		t.Errorf("Expected 1 third-party app, got %d", thirdPartyCount)
	}
}

func TestReconcileAndClassify_MultiExecutableSuiteConsolidation(t *testing.T) {
	c := New()

	apps := []model.Application{
		// CodeBlocks suite: 5 shortcuts + 1 registry + 2 PATH/process binaries
		{
			Name:   "Addr2LineUI",
			Path:   `C:\Program Files\CodeBlocks\Addr2LineUI.exe`,
			Origin: "StartMenu",
		},
		{
			Name:   "cb_share_config",
			Path:   `C:\Program Files\CodeBlocks\cb_share_config.exe`,
			Origin: "StartMenu",
		},
		{
			Name:   "cbp2make",
			Path:   `C:\Program Files\CodeBlocks\cbp2make.exe`,
			Origin: "StartMenu",
		},
		{
			Name:      "CodeBlocks",
			Path:      `C:\Program Files\CodeBlocks\codeblocks.exe`,
			Publisher: "The Code::Blocks Team",
			Version:   "20.03",
			Origin:    "Registry",
		},
		{
			Name:   "CodeBlocks",
			Path:   `C:\Program Files\CodeBlocks\codeblocks.exe`,
			Origin: "StartMenu",
		},
		{
			Name:   "CodeBlocks Launcher",
			Path:   `C:\Program Files\CodeBlocks\CbLauncher.exe`,
			Origin: "StartMenu",
		},
		{
			Name:   "cbp2make",
			Path:   `C:\Program Files\CodeBlocks\bin\cbp2make.exe`,
			Origin: "Path",
		},
		{
			Name:   "codeblocks",
			Path:   `C:\Program Files\CodeBlocks\codeblocks.exe`,
			Origin: "Process",
		},
		// PostgreSQL suite: 3 shortcuts + 1 registry + 1 process
		{
			Name:      "PostgreSQL 16",
			Path:      `C:\Program Files\PostgreSQL\16\bin\postgres.exe`,
			Publisher: "PostgreSQL Global Development Group",
			Version:   "16.1",
			Origin:    "Registry",
		},
		{
			Name:   "Reload Configuration",
			Path:   `C:\Program Files\PostgreSQL\16\bin\pg_ctl.exe`,
			Origin: "StartMenu",
		},
		{
			Name:   "SQL Shell (psql)",
			Path:   `C:\Program Files\PostgreSQL\16\bin\psql.exe`,
			Origin: "StartMenu",
		},
		{
			Name:   "pgAdmin 4",
			Path:   `C:\Program Files\PostgreSQL\16\pgAdmin 4\bin\pgAdmin4.exe`,
			Origin: "StartMenu",
		},
		{
			Name:   "postgres",
			Path:   `C:\Program Files\PostgreSQL\16\bin\postgres.exe`,
			Origin: "Process",
		},
	}

	results := c.ReconcileAndClassify(apps)

	// We expect exactly 2 applications in total: CodeBlocks and PostgreSQL 16
	// All auxiliary exes (CbLauncher, cbp2make, cb_share_config, Addr2LineUI, Reload Configuration, SQL Shell, pgAdmin)
	// MUST be collapsed into their parent suite and NOT listed as separate third-party apps!
	if len(results) != 2 {
		t.Fatalf("Expected exactly 2 consolidated suite applications, got %d: %+v", len(results), results)
	}

	for _, app := range results {
		if app.Category != model.CategoryThirdParty {
			t.Errorf("Expected app %s to be Third-Party, got %s", app.Name, app.Category)
		}
		if app.Name != "CodeBlocks" && app.Name != "PostgreSQL 16" {
			t.Errorf("Unexpected app in consolidated results: %s (%s)", app.Name, app.Path)
		}
	}
}

func TestClassifierDefaultOfflineLookup(t *testing.T) {
	c := New() // Default: offline
	if c.config.EnableOnlineLookup {
		t.Fatalf("expected EnableOnlineLookup to be false by default")
	}

	apps := []model.Application{
		{
			Name:   "custom-tool",
			Path:   `C:\Tools\custom-tool.exe`,
			Origin: "Path",
		},
	}

	results := c.ReconcileAndClassify(apps)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	// In offline mode without public evidence, unmapped tool is UNKNOWN
	if results[0].Classification != string(provenance.ClassificationUnknown) {
		t.Fatalf("expected custom-tool to be UNKNOWN when online lookup is disabled, got %s", results[0].Classification)
	}
}

func TestClassifierOptInOnlineLookup(t *testing.T) {
	tempDir := t.TempDir()
	cache := NewResolutionCache(filepath.Join(tempDir, "cache.json"))
	cache.Set("ripgrep", CacheEntry{
		IsThirdParty: true,
		Evidence:     "Verified open-source tool via persistent cache",
	})

	enricher := NewEnricher(cache)
	online := true
	enricher.isOnline = &online

	c := NewWithEnricher(enricher)
	if !c.config.EnableOnlineLookup {
		t.Fatalf("expected EnableOnlineLookup to be true")
	}

	apps := []model.Application{
		{
			Name:      "ripgrep",
			Path:      `C:\Tools\ripgrep.exe`,
			Origin:    "Path",
			Publisher: "BurntSushi",
		},
		{
			Name:      "VS Code",
			Path:      `C:\Program Files\Microsoft VS Code\Code.exe`,
			Origin:    "Registry",
			Publisher: "Microsoft Corporation",
		},
	}

	results := c.ReconcileAndClassify(apps)

	for _, app := range results {
		if app.Name == "ripgrep" || app.Name == "VS Code" {
			if app.Category != model.CategoryThirdParty {
				t.Fatalf("expected %s to be third-party, got %s", app.Name, app.Category)
			}
		}
	}
}

func BenchmarkReconcileAndClassify(b *testing.B) {
	c := New()
	apps := make([]model.Application, 200)
	for i := 0; i < 100; i++ {
		apps[i] = model.Application{
			Name:      "Official App",
			Path:      `C:\Program Files\Vendor\app.exe`,
			Publisher: "Microsoft Corporation",
			Origin:    "Registry",
		}
	}
	for i := 100; i < 200; i++ {
		apps[i] = model.Application{
			Name:   "dev-tool",
			Path:   `C:\Users\User\go\bin\dev-tool.exe`,
			Origin: "Process",
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = c.ReconcileAndClassify(apps)
	}
}
