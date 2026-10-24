package crawler

import (
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/aegis/orchestrator/ledger"
)

type CrawlerConfig struct {
	RootPaths     []string
	MaxWorkers    int
	ExcludeDirs   []string
	CollectBinary bool
}

type FileCrawler struct {
	config  CrawlerConfig
	workers chan struct{}
	results chan ledger.RuntimeAsset
}

func NewFileCrawler(cfg CrawlerConfig) *FileCrawler {
	if cfg.MaxWorkers <= 0 {
		cfg.MaxWorkers = 16
	}
	if len(cfg.ExcludeDirs) == 0 {
		cfg.ExcludeDirs = []string{".git", "node_modules", "vendor", "cache", "proc", "sys", "dev"}
	}
	return &FileCrawler{
		config:  cfg,
		workers: make(chan struct{}, cfg.MaxWorkers),
		results: make(chan ledger.RuntimeAsset, 1024),
	}
}

func (fc *FileCrawler) Crawl() []ledger.RuntimeAsset {
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
			fc.walkRoot(r, &wg)
		}(root)
	}

	wg.Wait()
	close(fc.results)
	<-doneCollecting

	return collected
}

func (fc *FileCrawler) walkRoot(root string, wg *sync.WaitGroup) {
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		if info.IsDir() {
			name := info.Name()
			for _, excl := range fc.config.ExcludeDirs {
				if name == excl {
					return filepath.SkipDir
				}
			}
			return nil
		}

		fileName := info.Name()
		fullPath := path

		// Classify target
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
		} else if fileName == "nginx.conf" || strings.HasSuffix(fileName, ".conf") && strings.Contains(fullPath, "nginx") {
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
}
