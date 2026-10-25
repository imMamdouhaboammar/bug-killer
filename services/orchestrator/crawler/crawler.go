package crawler

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/aegis/orchestrator/ledger"
	"github.com/spf13/afero"
)

type CrawlStatus = ledger.CrawlStatus

const (
	CrawlStatusComplete = ledger.CrawlStatusComplete
	CrawlStatusPartial  = ledger.CrawlStatusPartial
	CrawlStatusError    = ledger.CrawlStatusError
)

type CrawlResult struct {
	Assets          []ledger.RuntimeAsset `json:"assets"`
	SkippedDirs     []string              `json:"skipped_dirs"`
	TraversalErrors []string              `json:"traversal_errors"`
	Status          CrawlStatus           `json:"status"`
}

type CrawlerConfig struct {
	RootPaths      []string
	MaxWorkers     int
	ExcludeDirs    []string
	CollectBinary  bool
	Fs             afero.Fs
	MaxDepth       int             // Maximum directory depth relative to root (0 = unlimited)
	MaxFiles       int             // Maximum total files to inspect (0 = unlimited)
	FollowSymlinks bool            // Whether to traverse symlinks
	Context        context.Context // Optional context for cancellation/timeout
}

type FileCrawler struct {
	config          CrawlerConfig
	fs              afero.Fs
	workers         chan struct{}
	results         chan ledger.RuntimeAsset
	mu              sync.Mutex
	traversalErrors []string
	skippedDirs     []string
	fileCount       int64
	fileLimitHit    atomic.Bool
	depthLimitHit   atomic.Bool
	canceled        atomic.Bool
}

func NewFileCrawler(cfg CrawlerConfig) *FileCrawler {
	if cfg.MaxWorkers <= 0 {
		cfg.MaxWorkers = 16
	}
	if len(cfg.ExcludeDirs) == 0 {
		cfg.ExcludeDirs = []string{".git", "node_modules", "vendor", "cache", "proc", "sys", "dev"}
	}
	fileSystem := cfg.Fs
	if fileSystem == nil {
		fileSystem = afero.NewOsFs()
	}
	return &FileCrawler{
		config:          cfg,
		fs:              fileSystem,
		workers:         make(chan struct{}, cfg.MaxWorkers),
		results:         make(chan ledger.RuntimeAsset, 1024),
		traversalErrors: make([]string, 0),
		skippedDirs:     make([]string, 0),
	}
}

func (fc *FileCrawler) recordTraversalError(errStr string) {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	fc.traversalErrors = append(fc.traversalErrors, errStr)
}

func (fc *FileCrawler) recordSkippedDir(dirPath string) {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	fc.skippedDirs = append(fc.skippedDirs, dirPath)
}

func (fc *FileCrawler) Crawl() CrawlResult {
	ctx := fc.config.Context
	if ctx == nil {
		ctx = context.Background()
	}
	return fc.CrawlWithContext(ctx)
}

func (fc *FileCrawler) CrawlWithContext(ctx context.Context) CrawlResult {
	var collected []ledger.RuntimeAsset
	var wg sync.WaitGroup
	doneCollecting := make(chan struct{})

	go func() {
		for asset := range fc.results {
			collected = append(collected, asset)
		}
		close(doneCollecting)
	}()

	for _, root := range fc.config.RootPaths {
		wg.Add(1)
		go func(r string) {
			defer wg.Done()
			fc.walkRoot(ctx, r, &wg)
		}(root)
	}

	wg.Wait()
	close(fc.results)
	<-doneCollecting

	fc.mu.Lock()
	defer fc.mu.Unlock()

	if collected == nil {
		collected = make([]ledger.RuntimeAsset, 0)
	}
	if fc.skippedDirs == nil {
		fc.skippedDirs = make([]string, 0)
	}
	if fc.traversalErrors == nil {
		fc.traversalErrors = make([]string, 0)
	}

	status := CrawlStatusComplete
	if fc.canceled.Load() || (ctx != nil && ctx.Err() != nil) {
		if len(collected) > 0 {
			status = CrawlStatusPartial
		} else {
			status = CrawlStatusError
		}
	} else if fc.fileLimitHit.Load() || fc.depthLimitHit.Load() {
		status = CrawlStatusPartial
	} else if len(fc.traversalErrors) > 0 {
		if len(collected) > 0 {
			status = CrawlStatusPartial
		} else {
			status = CrawlStatusError
		}
	} else if len(fc.config.RootPaths) == 0 {
		status = CrawlStatusComplete
	}

	return CrawlResult{
		Assets:          collected,
		SkippedDirs:     fc.skippedDirs,
		TraversalErrors: fc.traversalErrors,
		Status:          status,
	}
}

func (fc *FileCrawler) walkRoot(ctx context.Context, root string, wg *sync.WaitGroup) {
	cleanRoot := filepath.Clean(root)

	// Verify root path accessibility
	if _, err := fc.fs.Stat(cleanRoot); err != nil {
		fc.recordTraversalError(fmt.Sprintf("%s: %v", cleanRoot, err))
		return
	}

	walkErr := afero.Walk(fc.fs, cleanRoot, func(path string, info os.FileInfo, err error) error {
		// 1. Cancellation check
		if ctx != nil && ctx.Err() != nil {
			fc.canceled.Store(true)
			return ctx.Err()
		}

		// 2. Limit check
		if fc.fileLimitHit.Load() {
			return filepath.SkipDir
		}

		// 3. Strict error checking: capture errors instead of silently swallowing them
		if err != nil {
			fc.recordTraversalError(fmt.Sprintf("%s: %v", path, err))
			if info != nil && info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		if info == nil {
			fc.recordTraversalError(fmt.Sprintf("%s: file info is nil", path))
			return nil
		}

		// 4. Directory filtering and depth limits
		if info.IsDir() {
			name := info.Name()
			for _, excl := range fc.config.ExcludeDirs {
				if name == excl {
					fc.recordSkippedDir(path)
					return filepath.SkipDir
				}
			}

			if fc.config.MaxDepth > 0 && path != cleanRoot {
				rel, relErr := filepath.Rel(cleanRoot, path)
				if relErr == nil && rel != "." {
					depth := len(strings.Split(filepath.ToSlash(rel), "/"))
					if depth > fc.config.MaxDepth {
						fc.recordSkippedDir(fmt.Sprintf("%s (exceeded max depth %d)", path, fc.config.MaxDepth))
						fc.depthLimitHit.Store(true)
						return filepath.SkipDir
					}
				}
			}

			return nil
		}

		// 5. File depth limit
		if fc.config.MaxDepth > 0 && path != cleanRoot {
			rel, relErr := filepath.Rel(cleanRoot, path)
			if relErr == nil && rel != "." {
				parts := strings.Split(filepath.ToSlash(rel), "/")
				if len(parts)-1 > fc.config.MaxDepth {
					return nil
				}
			}
		}

		// 6. Max files limit
		if fc.config.MaxFiles > 0 {
			count := atomic.AddInt64(&fc.fileCount, 1)
			if count > int64(fc.config.MaxFiles) {
				fc.fileLimitHit.Store(true)
				return filepath.SkipDir
			}
		}

		// 7. Symlink check
		if info.Mode()&os.ModeSymlink != 0 && !fc.config.FollowSymlinks {
			fc.recordSkippedDir(fmt.Sprintf("%s (symlink skipped)", path))
			return nil
		}

		fileName := info.Name()
		fullPath := path

		// 8. Classify target
		if fileName == "composer.json" {
			fc.results <- ledger.RuntimeAsset{
				Type:   "php",
				Path:   fullPath,
				Source: "manifest",
				Metadata: map[string]string{
					"manifest_type": "composer",
				},
			}
		} else if fileName == "package.json" {
			fc.results <- ledger.RuntimeAsset{
				Type:   "node",
				Path:   fullPath,
				Source: "manifest",
				Metadata: map[string]string{
					"manifest_type": "npm",
				},
			}
		} else if strings.HasPrefix(fileName, "Dockerfile") {
			fc.results <- ledger.RuntimeAsset{
				Type:   "container",
				Path:   fullPath,
				Source: "dockerfile",
			}
		} else if fileName == "nginx.conf" || (strings.HasSuffix(fileName, ".conf") && strings.Contains(fullPath, "nginx")) {
			fc.results <- ledger.RuntimeAsset{
				Type:   "webserver",
				Path:   fullPath,
				Source: "config",
				Metadata: map[string]string{
					"server": "nginx",
				},
			}
		} else if fileName == "httpd.conf" || fileName == "apache2.conf" || fileName == ".htaccess" {
			fc.results <- ledger.RuntimeAsset{
				Type:   "webserver",
				Path:   fullPath,
				Source: "config",
				Metadata: map[string]string{
					"server": "apache",
				},
			}
		} else if fileName == "haproxy.cfg" {
			fc.results <- ledger.RuntimeAsset{
				Type:   "webserver",
				Path:   fullPath,
				Source: "config",
				Metadata: map[string]string{
					"server": "haproxy",
				},
			}
		} else if fc.config.CollectBinary && (info.Mode()&0111 != 0) {
			// Executable binaries
			if fileName == "php" || strings.HasPrefix(fileName, "php8.") || fileName == "php-fpm" {
				fc.results <- ledger.RuntimeAsset{
					Type:   "php",
					Path:   fullPath,
					Source: "binary",
				}
			} else if fileName == "node" || fileName == "nodejs" {
				fc.results <- ledger.RuntimeAsset{
					Type:   "node",
					Path:   fullPath,
					Source: "binary",
				}
			} else if fileName == "bun" {
				fc.results <- ledger.RuntimeAsset{
					Type:   "bun",
					Path:   fullPath,
					Source: "binary",
				}
			} else if strings.HasPrefix(fileName, "libphp") && strings.HasSuffix(fileName, ".so") {
				fc.results <- ledger.RuntimeAsset{
					Type:   "php",
					Path:   fullPath,
					Source: "shared_object",
				}
			}
		}

		return nil
	})

	if walkErr != nil && !errors.Is(walkErr, context.Canceled) {
		fc.recordTraversalError(fmt.Sprintf("%s: walk error: %v", cleanRoot, walkErr))
	}
}
