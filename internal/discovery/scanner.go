package discovery

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/example/appaudit/internal/model"
)

// PruneDirNames defines the O(1) directory exclusion set for fast subtree termination.
var PruneDirNames = map[string]bool{
	// Developer trees & build outputs
	"node_modules": true,
	".git":         true,
	".svn":         true,
	".hg":          true,
	"venv":         true,
	".venv":        true,
	"env":          true,
	"target":       true, // Rust build artifacts
	"dist":         true,
	"build":        true,
	"__pycache__":  true,

	// Temporary, caches, and crash logs
	"temp":         true,
	"cache":        true,
	"caches":       true,
	"crashdumps":   true,
	"logs":         true,

	// Windows bloat & package stores
	"packages":                  true, // AppX / WindowsApps
	"installer":                 true, // Windows\Installer rollbacks
	"winsxs":                    true,
	"package cache":             true,
	"user data":                 true,
	"inetcache":                 true,
	"$recycle.bin":              true,
	"system volume information": true,
	"recovery":                  true,
	"$winreagent":               true,
}

// ShouldPruneDir returns true if a directory name matches the exclusion set.
func ShouldPruneDir(name string) bool {
	return PruneDirNames[strings.ToLower(name)]
}

// ProgressFunc reports real-time discovery count and current scanning location.
type ProgressFunc func(discoveredCount int, currentPath string)

// DiscoveryResult encapsulates discovered executables, applications, and performance telemetry.
type DiscoveryResult struct {
	Executables      []string
	Applications     []model.Application
	DirsVisited      int64
	DirsPruned       int64
	FilesScanned     int64
	ExecutablesFound int64
	Duration         time.Duration
	DurationMs       float64
}

// ScanTargeted executes high-throughput concurrent scanning over targeted directory roots
// with aggressive subtree pruning.
func ScanTargeted(roots []string, progress ProgressFunc) (*DiscoveryResult, error) {
	startTime := time.Now()
	res := &DiscoveryResult{}

	if len(roots) == 0 {
		roots = CollectTargetedRoots()
	}

	seenPaths := &sync.Map{}
	ch := make(chan string, 2048)

	var lastProgressTime time.Time
	var progressMu sync.Mutex

	// Collector goroutine: receives candidate paths, deduplicates them, and builds application models
	done := make(chan struct{})
	go func() {
		defer close(done)
		for path := range ch {
			key := strings.ToLower(filepath.Clean(path))
			if _, loaded := seenPaths.LoadOrStore(key, true); loaded {
				continue
			}

			atomic.AddInt64(&res.ExecutablesFound, 1)
			count := int(atomic.LoadInt64(&res.ExecutablesFound))
			res.Executables = append(res.Executables, path)

			baseName := filepath.Base(path)
			nameWithoutExt := strings.TrimSuffix(baseName, filepath.Ext(baseName))

			res.Applications = append(res.Applications, model.Application{
				Name:     nameWithoutExt,
				Path:     path,
				Origin:   "TargetedScan",
				Evidence: fmt.Sprintf("Executable discovered in targeted tier: %s", filepath.Dir(path)),
			})

			if progress != nil {
				progressMu.Lock()
				now := time.Now()
				if now.Sub(lastProgressTime) >= 80*time.Millisecond || count%25 == 0 {
					lastProgressTime = now
					progressMu.Unlock()
					progress(count, path)
				} else {
					progressMu.Unlock()
				}
			}
		}
	}()

	// Worker pool concurrency
	workerCount := 24
	if workerCount > len(roots) && len(roots) > 0 {
		workerCount = len(roots)
	}
	sem := make(chan struct{}, workerCount)
	var wg sync.WaitGroup

	for _, root := range roots {
		wg.Add(1)
		go func(r string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			_ = filepath.WalkDir(r, func(path string, d fs.DirEntry, err error) error {
				if err != nil {
					// Permission resilience: skip directory immediately without breaking traversal
					if d != nil && d.IsDir() {
						return filepath.SkipDir
					}
					return nil
				}

				if d.IsDir() {
					atomic.AddInt64(&res.DirsVisited, 1)

					// Circular junction and symlink protection
					if d.Type()&fs.ModeSymlink != 0 || d.Type()&fs.ModeIrregular != 0 {
						atomic.AddInt64(&res.DirsPruned, 1)
						return filepath.SkipDir
					}

					// Aggressive subtree pruning
					if ShouldPruneDir(d.Name()) {
						atomic.AddInt64(&res.DirsPruned, 1)
						return filepath.SkipDir
					}
					return nil
				}

				atomic.AddInt64(&res.FilesScanned, 1)

				// Fast executable filtering
				if isExecutableEntry(d) {
					ch <- path
				}
				return nil
			})
		}(root)
	}

	wg.Wait()
	close(ch)
	<-done

	elapsed := time.Since(startTime)
	res.Duration = elapsed
	res.DurationMs = float64(elapsed.Microseconds()) / 1000.0

	return res, nil
}

func isExecutableEntry(d fs.DirEntry) bool {
	ext := filepath.Ext(d.Name())
	if runtime.GOOS == "windows" {
		return strings.EqualFold(ext, ".exe")
	}
	// For Unix/macOS, check if extension is executable or mode has execute bit
	if strings.EqualFold(ext, ".app") || strings.EqualFold(ext, ".bin") || strings.EqualFold(ext, ".sh") {
		return true
	}
	info, err := d.Info()
	if err == nil && info.Mode()&0111 != 0 {
		return true
	}
	return false
}
