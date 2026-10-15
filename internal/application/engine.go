package application

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/example/appaudit/internal/ai"
	"github.com/example/appaudit/internal/discovery"
	"github.com/example/appaudit/internal/model"
	"github.com/example/appaudit/internal/provenance"
	"github.com/example/appaudit/internal/scanner"
	"github.com/example/appaudit/internal/service"
)

// EngineConfig configures the Application Engine.
type EngineConfig struct {
	NetworkMode             provenance.NetworkMode
	CompanyDomainIndicators []string
	KnownPublishers         []string
	Reasoner                ai.Reasoner
	Inspector               provenance.BinaryInspector
	Cache                   *provenance.ProvenanceCache
}

// Engine coordinates application discovery reconciliation, forensic inspection, and classification.
type Engine struct {
	config     EngineConfig
	reconciler *Reconciler
	decision   *DecisionEngine
	inspector  provenance.BinaryInspector
	cache      *provenance.ProvenanceCache
}

// NewEngine creates an initialized Application Engine.
func NewEngine(cfg EngineConfig) *Engine {
	if cfg.NetworkMode == "" {
		cfg.NetworkMode = provenance.NetworkOff
	}
	if len(cfg.KnownPublishers) == 0 {
		cfg.KnownPublishers = defaultPublishers
	}
	if cfg.Reasoner == nil {
		cfg.Reasoner = ai.NewNoopReasoner()
	}
	if cfg.Inspector == nil {
		cfg.Inspector = provenance.DefaultBinaryInspector()
	}
	if cfg.Cache == nil {
		cfg.Cache = provenance.NewProvenanceCache()
	}

	reconciler := NewReconciler()
	decision := NewDecisionEngine(cfg.CompanyDomainIndicators, cfg.KnownPublishers, cfg.Reasoner)
	decision.NetworkMode = cfg.NetworkMode

	return &Engine{
		config:     cfg,
		reconciler: reconciler,
		decision:   decision,
		inspector:  cfg.Inspector,
		cache:      cfg.Cache,
	}
}

var defaultPublishers = []string{
	"microsoft", "google", "apple", "canonical", "mozilla",
	"adobe", "jetbrains", "valve", "docker", "cisco",
	"oracle", "intel", "amd", "nvidia", "amazon",
	"spotify", "zoom", "slack", "discord", "atlassian",
	"github", "gitlab", "vmware", "broadcom", "realtek",
	"dell", "hp", "lenovo", "asus", "acer", "sony",
	"logitech", "brave", "opera", "notion", "dropbox",
	"autodesk", "electronic arts", "ubisoft", "epic games",
	"telegram", "meta", "facebook", "whatsapp", "apache",
	"nginx", "red hat", "suse", "debian", "ubuntu",
	"canonical snap", "flatpak application", "postman",
	"the git development community", "the openvpn project",
	"wireshark", "simon tatham", "mongodb", "nodejs",
	"openjs foundation", "python software foundation",
	"anaconda", "blender foundation", "videolan", "ffmpeg project",
	"gyan doshi", "curl developers", "sqlite development team",
	"chromium", "the chromium authors", "code::blocks", "the code::blocks team",
	"go authors", "borland", "embarcadero", "turbo c++",
}

// ProcessDiscovered reconciles raw discovered models from system scanners and classifies them.
func (e *Engine) ProcessDiscovered(ctx context.Context, discovered []model.Application) []Application {
	rawInputs := make([]RawInput, len(discovered))
	for i, d := range discovered {
		rawInputs[i] = RawInput{
			Name:      d.Name,
			Path:      d.Path,
			Publisher: d.Publisher,
			Version:   d.Version,
			Origin:    d.Origin,
		}
	}
	return e.ProcessRaw(ctx, rawInputs)
}

// ProcessRaw reconciles raw candidate inputs and classifies the resulting applications.
func (e *Engine) ProcessRaw(ctx context.Context, rawInputs []RawInput) []Application {
	apps := e.reconciler.ReconcileRaw(rawInputs)

	// Parallelize deep forensic binary inspection and classification across 16 workers
	workerCount := 16
	if len(apps) < workerCount {
		workerCount = len(apps)
	}
	isTerm := false
	if fi, err := os.Stdout.Stat(); err == nil && (fi.Mode()&os.ModeCharDevice) != 0 {
		isTerm = true
	}

	_, isBatch := e.decision.Reasoner.(ai.BatchReasoner)
	if isBatch && e.decision.Reasoner.Name() != "none" {
		// 1. Parallel deterministic inspection & classification
		savedReasoner := e.decision.Reasoner
		e.decision.Reasoner = ai.NewNoopReasoner()
		if workerCount > 0 {
			sem := make(chan struct{}, workerCount)
			var wg sync.WaitGroup
			var completed int32
			total := len(apps)
			for i := range apps {
				wg.Add(1)
				go func(app *Application) {
					defer wg.Done()
					sem <- struct{}{}
					defer func() { <-sem }()
					e.inspectAndClassifyApp(ctx, app)
					if isTerm && total > 0 {
						done := atomic.AddInt32(&completed, 1)
						fmt.Printf("\r[Forensic Triage] Inspecting applications: %d/%d (%d%%)...", done, total, done*100/int32(total))
						_ = os.Stdout.Sync()
					}
				}(&apps[i])
			}
			wg.Wait()
			if isTerm {
				fmt.Printf("\r[OK] Forensic triage complete: %d applications inspected.            \n", len(apps))
				_ = os.Stdout.Sync()
			}
			_ = e.cache.Save()
		}
		e.decision.Reasoner = savedReasoner

		// 2. Batch classify remaining unresolved applications
		var unknownApps []*Application
		for i := range apps {
			if apps[i].Classification == provenance.ClassificationUnknown {
				unknownApps = append(unknownApps, &apps[i])
			}
		}
		if len(unknownApps) > 0 {
			e.ClassifyBatch(ctx, unknownApps)
		}
	} else {
		if workerCount > 0 {
			sem := make(chan struct{}, workerCount)
			var wg sync.WaitGroup
			var completed int32
			total := len(apps)
			for i := range apps {
				wg.Add(1)
				go func(app *Application) {
					defer wg.Done()
					sem <- struct{}{}
					defer func() { <-sem }()
					e.inspectAndClassifyApp(ctx, app)
					if isTerm && total > 0 {
						done := atomic.AddInt32(&completed, 1)
						fmt.Printf("\r[Forensic Triage] Inspecting applications: %d/%d (%d%%)...", done, total, done*100/int32(total))
						_ = os.Stdout.Sync()
					}
				}(&apps[i])
			}
			wg.Wait()
			if isTerm {
				fmt.Printf("\r[OK] Forensic triage complete: %d applications inspected.            \n", len(apps))
				_ = os.Stdout.Sync()
			}
			_ = e.cache.Save()
		}
	}

	// Sort alphabetically by classification, then name
	sort.Slice(apps, func(i, j int) bool {
		if apps[i].Classification != apps[j].Classification {
			return apps[i].Classification < apps[j].Classification
		}
		return strings.ToLower(apps[i].Name) < strings.ToLower(apps[j].Name)
	})

	return apps
}

// AnalyzePaths analyzes one or more file or directory paths provided by the user.
func (e *Engine) AnalyzePaths(ctx context.Context, paths []string) ([]Application, error) {
	var rawInputs []RawInput

	for _, p := range paths {
		cleanP := filepath.Clean(p)
		fi, err := os.Stat(cleanP)
		if err != nil {
			continue
		}

		if fi.IsDir() {
			// Walk directory to find binaries
			_ = filepath.Walk(cleanP, func(subPath string, info os.FileInfo, walkErr error) error {
				if walkErr != nil || info == nil || info.IsDir() {
					return nil
				}
				if model.IsExecutableTarget(subPath) && !IsSubToolNoise(info.Name(), subPath) {
					rawInputs = append(rawInputs, RawInput{
						Name:   strings.TrimSuffix(info.Name(), filepath.Ext(info.Name())),
						Path:   subPath,
						Origin: "CLI",
					})
				}
				return nil
			})
		} else {
			if model.IsExecutableTarget(cleanP) {
				rawInputs = append(rawInputs, RawInput{
					Name:   strings.TrimSuffix(fi.Name(), filepath.Ext(fi.Name())),
					Path:   cleanP,
					Origin: "CLI",
				})
			}
		}
	}

	return e.ProcessRaw(ctx, rawInputs), nil
}

// InspectSingleBinary inspects and classifies a single executable binary at the given path.
// An optional originalName can be provided to preserve the original filename if the file was uploaded as a temporary file.
func (e *Engine) InspectSingleBinary(path string, originalName ...string) (*Application, error) {
	return e.InspectSingleBinaryWithContext(context.Background(), path, originalName...)
}

// InspectSingleBinaryWithContext inspects and classifies a single executable binary with a custom context.
func (e *Engine) InspectSingleBinaryWithContext(ctx context.Context, path string, originalName ...string) (*Application, error) {
	cleanP := filepath.Clean(path)
	fi, err := os.Stat(cleanP)
	if err != nil {
		return nil, fmt.Errorf("failed to access binary %q: %w", path, err)
	}

	name := strings.TrimSuffix(fi.Name(), filepath.Ext(fi.Name()))
	if len(originalName) > 0 && originalName[0] != "" {
		base := filepath.Base(originalName[0])
		name = strings.TrimSuffix(base, filepath.Ext(base))
	}

	app := buildApplicationFromSingle(RawInput{
		Name:   name,
		Path:   cleanP,
		Origin: "UPLOAD",
	}, filepath.Dir(cleanP))

	e.inspectAndClassifyApp(ctx, &app)
	_ = e.cache.Save()
	return &app, nil
}

// DiscoverQuickScan performs fast inventory discovery on host shortcuts and registry, returning candidate raw inputs.
func DiscoverQuickScan() ([]RawInput, error) {
	sysScanner := scanner.New()
	raw, err := sysScanner.Scan()
	if err != nil {
		return nil, err
	}
	rawInputs := make([]RawInput, len(raw))
	for i, d := range raw {
		rawInputs[i] = RawInput{
			Name:      d.Name,
			Path:      d.Path,
			Publisher: d.Publisher,
			Version:   d.Version,
			Origin:    d.Origin,
		}
	}
	return rawInputs, nil
}

// DiscoverFullScan performs deep discovery across machine and user targets (excluding system files), returning candidate raw inputs.
func DiscoverFullScan() ([]RawInput, error) {
	sysScanner := scanner.New()
	var raw []model.Application
	discRes, _ := discovery.ScanTargeted(nil, nil)
	if discRes != nil {
		raw = append(raw, discRes.Applications...)
	}
	quickApps, err := sysScanner.Scan()
	if err == nil {
		raw = append(raw, quickApps...)
	}
	rawInputs := make([]RawInput, len(raw))
	for i, d := range raw {
		rawInputs[i] = RawInput{
			Name:      d.Name,
			Path:      d.Path,
			Publisher: d.Publisher,
			Version:   d.Version,
			Origin:    d.Origin,
		}
	}
	return rawInputs, nil
}

// DiscoverDirectory collects executable candidate binaries recursively from a given folder path.
func DiscoverDirectory(dirPath string) ([]RawInput, error) {
	cleanP := filepath.Clean(dirPath)
	var rawInputs []RawInput
	err := filepath.Walk(cleanP, func(subPath string, info os.FileInfo, walkErr error) error {
		if walkErr != nil || info == nil || info.IsDir() {
			return nil
		}
		if model.IsExecutableTarget(subPath) && !IsSubToolNoise(info.Name(), subPath) {
			rawInputs = append(rawInputs, RawInput{
				Name:   strings.TrimSuffix(info.Name(), filepath.Ext(info.Name())),
				Path:   subPath,
				Origin: "CLI",
			})
		}
		return nil
	})
	return rawInputs, err
}

// RunQuickScan performs fast inventory discovery on host shortcuts and registry, then classifies all discovered software.
func (e *Engine) RunQuickScan(ctx context.Context) ([]Application, error) {
	raw, err := DiscoverQuickScan()
	if err != nil {
		return nil, err
	}
	return e.ProcessRaw(ctx, raw), nil
}

// RunFullScan performs deep discovery across machine and user targets (excluding system files) and classifies all discovered software.
func (e *Engine) RunFullScan(ctx context.Context) ([]Application, error) {
	raw, err := DiscoverFullScan()
	if err != nil {
		return nil, err
	}
	return e.ProcessRaw(ctx, raw), nil
}

// ClassifyApp performs forensic inspection, evidence gathering, and classification on an application.
func (e *Engine) ClassifyApp(ctx context.Context, app *Application) {
	e.inspectAndClassifyApp(ctx, app)
}

func (e *Engine) inspectAndClassifyApp(ctx context.Context, app *Application) {
	bundle := e.prepareBundle(app)
	e.decision.Decide(ctx, app, bundle)
}

// ClassifyBatch performs batched classification on multiple unresolved application candidates.
// If the configured reasoner implements ai.BatchReasoner, it chunk-batches them to prevent 429 rate limits.
func (e *Engine) ClassifyBatch(ctx context.Context, apps []*Application) {
	if len(apps) == 0 {
		return
	}

	var unresolvedApps []*Application
	var unresolvedBundles []EvidenceBundle

	for _, app := range apps {
		if app.Classification == "" || app.Classification == provenance.ClassificationUnknown {
			bundle := e.prepareBundle(app)
			if bundle.ReadError != "" || app.ReadError != "" {
				errStr := app.ReadError
				if errStr == "" {
					errStr = bundle.ReadError
				}
				app.Classification = provenance.ClassificationUnknown
				app.Confidence = provenance.ConfidenceNone
				app.ResolutionSource = "File Inspection Failed"
				app.Reasons = []string{"Inspection halted: " + errStr}
				app.EvidenceSummary = errStr
				app.Conclusion = "Binary could not be read or parsed safely; withheld from AI and CIRCL lookup."
				continue
			}
			unresolvedApps = append(unresolvedApps, app)
			unresolvedBundles = append(unresolvedBundles, bundle)
		}
	}

	if len(unresolvedApps) == 0 {
		_ = e.cache.Save()
		return
	}

	batchReasoner, isBatch := e.decision.Reasoner.(ai.BatchReasoner)
	if isBatch && len(unresolvedApps) >= 1 {
		aiBundles := make([]ai.EvidenceBundle, len(unresolvedApps))
		for i, app := range unresolvedApps {
			primaryHash := unresolvedBundles[i].PrimaryBinary.SHA256
			isWrapper := unresolvedBundles[i].IsWrapperStub || unresolvedBundles[i].PrimaryBinary.Inspection.IsWrapperStub
			pub := app.Publisher
			if isWrapper && provenance.IsWrapperString(pub) {
				pub = ""
			}
			aiBundles[i] = ai.EvidenceBundle{
				SHA256:        primaryHash,
				AppName:       app.Name,
				Publisher:     pub,
				Version:       app.Version,
				BinaryName:    unresolvedBundles[i].PrimaryBinary.Name,
				Path:          unresolvedBundles[i].PrimaryBinary.Path,
				InstallDir:    app.InstallDir,
				Origin:        app.Origin,
				SiblingCount:  len(unresolvedBundles[i].Binaries),
				IsWrapperStub: isWrapper,
				Raw:           unresolvedBundles[i],
			}
		}

		results, err := batchReasoner.ReasonBatch(ctx, aiBundles)
		if len(results) == len(unresolvedApps) {
			for i, app := range unresolvedApps {
				e.decision.RecordTier2Hit()
				e.decision.ApplyAIResult(app, unresolvedBundles[i], results[i], err)
			}
			_ = e.cache.Save()
			return
		}

		// If a batch reasoner encountered a fatal error (e.g. Ollama daemon offline) and returned no results,
		// record the infrastructure error on all candidate applications immediately rather than repeating
		// failing network round-trips individually for every single application.
		if err != nil {
			for i, app := range unresolvedApps {
				e.decision.ApplyAIResult(app, unresolvedBundles[i], ai.ReasoningResult{
					Classification:  provenance.ClassificationUnknown,
					Confidence:      provenance.ConfidenceNone,
					APIError:        err.Error(),
					EvidenceSummary: "Batch AI reasoning halted: " + err.Error(),
					Conclusion:      "AI reasoning refused due to service unavailability.",
					Reasons:         []string{fmt.Sprintf("Batch reasoning error: %v", err)},
				}, err)
			}
			_ = e.cache.Save()
			return
		}
	}

	// Fallback to individual classification if not a batch reasoner
	for i, app := range unresolvedApps {
		e.decision.Decide(ctx, app, unresolvedBundles[i])
	}
	_ = e.cache.Save()
}

func (e *Engine) prepareBundle(app *Application) EvidenceBundle {
	if provenance.IsWrapperString(app.Publisher) {
		app.Publisher = ""
	}
	bundle := EvidenceBundle{
		AppName:    app.Name,
		Publisher:  app.Publisher,
		Version:    app.Version,
		Origin:     app.Origin,
		InstallDir: app.InstallDir,
	}

	// Inspect each binary in the application
	for i := range app.Binaries {
		b := &app.Binaries[i]

		// 1. Check file accessibility and compute SHA-256 fingerprint if path exists
		if b.Path != "" {
			info, statErr := os.Stat(b.Path)
			if statErr != nil {
				errMsg := statErr.Error()
				if strings.Contains(strings.ToLower(errMsg), "sharing violation") || strings.Contains(strings.ToLower(errMsg), "used by another process") {
					b.ReadError = "File locked by active Windows process (sharing violation)"
				} else if os.IsPermission(statErr) || strings.Contains(strings.ToLower(errMsg), "access is denied") {
					b.ReadError = "Access denied (Administrator privileges required)"
				} else {
					b.ReadError = fmt.Sprintf("Failed to access file: %v", statErr)
				}
			} else if info.Size() == 0 {
				b.ReadError = "Zero-byte file (empty executable)"
			} else if b.SHA256 == "" {
				fp, err := provenance.ComputeFingerprint(b.Path)
				if err != nil {
					errMsg := err.Error()
					if strings.Contains(strings.ToLower(errMsg), "sharing violation") || strings.Contains(strings.ToLower(errMsg), "used by another process") {
						b.ReadError = "File locked by active Windows process (sharing violation)"
					} else if os.IsPermission(err) || strings.Contains(strings.ToLower(errMsg), "access is denied") {
						b.ReadError = "Access denied (Administrator privileges required)"
					} else {
						b.ReadError = fmt.Sprintf("Failed to read binary: %v", err)
					}
				} else {
					b.SHA256 = fp.SHA256
					b.SizeBytes = fp.Size
				}
			}
		}

		if b.ReadError != "" {
			if bundle.ReadError == "" || b.Path == app.PrimaryBinaryPath {
				bundle.ReadError = b.ReadError
				app.ReadError = b.ReadError
			}
			if b.Path == app.PrimaryBinaryPath || bundle.PrimaryBinary.Path == "" {
				bundle.PrimaryBinary = *b
			}
			continue
		}

		// 2. Check binary forensic cache first
		cacheHit := false
		if b.SHA256 != "" {
			if cachedMeta, cachedEv, ok := e.cache.GetBinaryEvidence(b.SHA256); ok {
				cacheHit = true
				if !cachedMeta.IsWrapperStub && (provenance.IsWrapperString(cachedMeta.CompanyName) || provenance.IsWrapperString(cachedMeta.FileDescription) || provenance.IsWrapperString(cachedMeta.ProductName)) {
					cachedMeta.IsWrapperStub = true
					if provenance.IsWrapperString(cachedMeta.CompanyName) {
						cachedMeta.CompanyName = ""
					}
					if provenance.IsWrapperString(cachedMeta.FileDescription) {
						cachedMeta.FileDescription = ""
					}
					if provenance.IsWrapperString(cachedMeta.ProductName) {
						cachedMeta.ProductName = ""
					}
				}
				b.Inspection = cachedMeta
				b.Evidence = cachedEv
				if cachedMeta.IsWrapperStub {
					bundle.IsWrapperStub = true
				}
				if b.Publisher == "" && cachedMeta.CompanyName != "" && !cachedMeta.IsWrapperStub {
					b.Publisher = cachedMeta.CompanyName
				}
				if b.Version == "" && cachedMeta.ProductVersion != "" && !cachedMeta.IsWrapperStub {
					b.Version = cachedMeta.ProductVersion
				}
				bundle.Evidence = append(bundle.Evidence, cachedEv...)
				if b.Path == app.PrimaryBinaryPath || bundle.PrimaryBinary.Path == "" {
					bundle.PrimaryBinary = *b
				}
			}
		}

		// 3. Cache miss: perform deep forensic binary inspection
		if !cacheHit && b.Path != "" {
			meta, err := e.inspector.Inspect(b.Path)
			if err == nil {
				b.Inspection = meta
				if meta.IsWrapperStub {
					bundle.IsWrapperStub = true
				}
				if b.Publisher == "" && meta.CompanyName != "" && !meta.IsWrapperStub {
					b.Publisher = meta.CompanyName
				}
				if b.Version == "" && meta.ProductVersion != "" && !meta.IsWrapperStub {
					b.Version = meta.ProductVersion
				}
			} else {
				b.ReadError = fmt.Sprintf("Corrupted or invalid PE executable: %v", err)
				if bundle.ReadError == "" || b.Path == app.PrimaryBinaryPath {
					bundle.ReadError = b.ReadError
					app.ReadError = b.ReadError
				}
			}
		}

		// Tier 1.5A Inspection: Local package manifests, runtime environments, and embedded strings (Zero Network)
		// Only perform expensive string mining and runtime inspection on unsigned binaries
		if b.Path != "" && (!b.Inspection.IsSigned || b.Inspection.CertSubject == "") {
			if bundle.PackageReceipt == nil {
				if pkgRec := provenance.InspectPackageManagerReceipts(b.Path); pkgRec != nil {
					bundle.PackageReceipt = pkgRec
				}
			}
			if bundle.RuntimeReceipt == nil {
				if rtRec := provenance.InspectRuntimeReceipts(b.Path); rtRec != nil {
					bundle.RuntimeReceipt = rtRec
					b.Inspection.IsWrapperStub = true
					bundle.IsWrapperStub = true
				}
			}
			if bundle.StringSignatures == nil {
				if strSigs := provenance.InspectStringSignatures(b.Path); strSigs != nil {
					bundle.StringSignatures = strSigs
				}
			}
		}

		if cacheHit {
			continue
		}

		// 4. Collect binary-level evidence
		var binEvidence []provenance.Evidence

		// Authenticode signature evidence (requires verified signature)
		if b.Inspection.IsSigned && b.Inspection.CertSubject != "" {
			binEvidence = append(binEvidence, provenance.Evidence{
				Type:        provenance.EvidencePublisherSignature,
				Source:      "Authenticode Certificate",
				Strength:    0.90,
				Description: "Binary cryptographically signed by: " + b.Inspection.CertSubject,
				Confidence:  provenance.ConfidenceHigh,
			})
		}

		// VersionInfo product metadata evidence (suppressed if binary is a wrapper stub)
		if !b.Inspection.IsWrapperStub && (b.Inspection.ProductName != "" || b.Inspection.CompanyName != "") {
			vendor := b.Inspection.CompanyName
			if vendor == "" {
				vendor = b.Inspection.LegalCopyright
			}
			prod := b.Inspection.ProductName
			if prod == "" {
				prod = b.Inspection.FileDescription
			}
			if prod == "" {
				prod = b.Name
			}
			if vendor != "" && e.decision.isKnownExternalPublisher(vendor) && !e.decision.isCompanyIndicator(vendor) {
				binEvidence = append(binEvidence, provenance.Evidence{
					Type:        provenance.EvidenceProductMetadata,
					Source:      "PE Version Resource",
					Strength:    0.75,
					Description: fmt.Sprintf("Product metadata identifies '%s' by verified vendor '%s'", prod, vendor),
					Confidence:  provenance.ConfidenceHigh,
				})
			} else if prod != "" {
				binEvidence = append(binEvidence, provenance.Evidence{
					Type:        provenance.EvidenceProductMetadata,
					Source:      "PE Version Resource",
					Strength:    0.30,
					Description: "PE Product String: " + prod,
					Confidence:  provenance.ConfidenceLow,
				})
			}
		}

		// Go compiler build info
		if b.Inspection.BuildInfo != nil {
			if b.Inspection.BuildInfo.MainModule != "" {
				binEvidence = append(binEvidence, provenance.Evidence{
					Type:        provenance.EvidenceBuildMetadata,
					Source:      "Go BuildInfo",
					Strength:    0.85,
					Description: "Go main module: " + b.Inspection.BuildInfo.MainModule,
					Confidence:  provenance.ConfidenceHigh,
				})
			} else if b.Inspection.BuildInfo.GoVersion != "" && (strings.EqualFold(b.Name, "go") || strings.EqualFold(b.Name, "gofmt")) {
				binEvidence = append(binEvidence, provenance.Evidence{
					Type:        provenance.EvidenceBuildMetadata,
					Source:      "Go Toolchain",
					Strength:    0.85,
					Description: "Official Go programming language toolchain distribution (" + b.Inspection.BuildInfo.GoVersion + ")",
					Confidence:  provenance.ConfidenceHigh,
				})
			}
		}

		// Embedded component strings
		for _, comp := range b.Inspection.Components {
			binEvidence = append(binEvidence, provenance.Evidence{
				Type:        provenance.EvidenceComponentMatch,
				Source:      "Binary Static Strings",
				Strength:    0.30,
				Description: "Contains embedded signature for component '" + comp + "'",
				Confidence:  provenance.ConfidenceLow,
			})
		}

		b.Evidence = binEvidence
		bundle.Evidence = append(bundle.Evidence, binEvidence...)

		// 5. Cache binary forensic evidence keyed by immutable SHA-256
		if b.SHA256 != "" {
			e.cache.SetBinaryEvidence(b.SHA256, b.Inspection, binEvidence)
		}

		if b.Path == app.PrimaryBinaryPath || bundle.PrimaryBinary.Path == "" {
			bundle.PrimaryBinary = *b
		}
	}

	if bundle.IsWrapperStub {
		if provenance.IsWrapperString(bundle.Publisher) {
			bundle.Publisher = ""
		}
		if provenance.IsWrapperString(app.Publisher) {
			app.Publisher = ""
		}
	}
	bundle.Binaries = app.Binaries
	return bundle
}

// GetTriageStats returns the hit counts for Tier 1, Tier 1.5A, Tier 1.5B, and Tier 2 AI reasoning.
func (e *Engine) GetTriageStats() (tier1, tier15A, tier15B, tier2 int) {
	return e.decision.GetTriageStats()
}

// EnsureLocalServices verifies and auto-starts local services (Ollama and SearXNG)
// if the engine is configured with a LocalReasoner.
func (e *Engine) EnsureLocalServices(ctx context.Context) error {
	if _, isLocal := e.decision.Reasoner.(*ai.LocalReasoner); isLocal {
		return service.EnsureLocalStack(ctx, nil)
	}
	return nil
}

// DecisionEngine returns the underlying DecisionEngine instance.
func (e *Engine) DecisionEngine() *DecisionEngine {
	return e.decision
}


