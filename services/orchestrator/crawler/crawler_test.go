package crawler

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aegis/orchestrator/ledger"
	"github.com/spf13/afero"
)

func TestFileCrawlerDiscovery(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "aegis-crawler-test")
	if err != nil {
		t.Fatalf("Failed to create tempdir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create test files
	_ = os.WriteFile(filepath.Join(tempDir, "package.json"), []byte(`{"name":"test"}`), 0644)
	_ = os.WriteFile(filepath.Join(tempDir, "composer.json"), []byte(`{"require":{"php":"^8.2"}}`), 0644)
	_ = os.WriteFile(filepath.Join(tempDir, "nginx.conf"), []byte(`server { listen 80; }`), 0644)
	_ = os.WriteFile(filepath.Join(tempDir, "Dockerfile"), []byte(`FROM node:22`), 0644)

	fc := NewFileCrawler(CrawlerConfig{
		RootPaths:     []string{tempDir},
		MaxWorkers:    4,
		CollectBinary: false,
	})

	res := fc.Crawl()
	if res.Status != CrawlStatusComplete {
		t.Fatalf("Expected CrawlStatusComplete, got %s", res.Status)
	}
	if len(res.TraversalErrors) != 0 {
		t.Errorf("Expected 0 traversal errors, got: %v", res.TraversalErrors)
	}
	if len(res.Assets) < 4 {
		t.Fatalf("Expected at least 4 assets, discovered %d", len(res.Assets))
	}

	foundPackageJson := false
	foundComposerJson := false
	foundNginx := false
	foundDockerfile := false

	for _, a := range res.Assets {
		switch filepath.Base(a.Path) {
		case "package.json":
			foundPackageJson = true
		case "composer.json":
			foundComposerJson = true
		case "nginx.conf":
			foundNginx = true
		case "Dockerfile":
			foundDockerfile = true
		}
	}

	if !foundPackageJson || !foundComposerJson || !foundNginx || !foundDockerfile {
		t.Errorf("Discovery incomplete: pkg=%v, comp=%v, nginx=%v, docker=%v",
			foundPackageJson, foundComposerJson, foundNginx, foundDockerfile)
	}
}

func TestFileCrawlerAferoMemoryFs(t *testing.T) {
	memFs := afero.NewMemMapFs()
	_ = memFs.MkdirAll("/isolated/app", 0755)
	_ = afero.WriteFile(memFs, "/isolated/app/package.json", []byte(`{"name":"sandbox"}`), 0644)
	_ = afero.WriteFile(memFs, "/isolated/app/Dockerfile", []byte(`FROM node:20`), 0644)

	fc := NewFileCrawler(CrawlerConfig{
		RootPaths:     []string{"/isolated/app"},
		MaxWorkers:    2,
		CollectBinary: false,
		Fs:            memFs,
	})

	res := fc.Crawl()
	if res.Status != CrawlStatusComplete {
		t.Fatalf("Expected CrawlStatusComplete, got %s", res.Status)
	}
	if len(res.Assets) != 2 {
		t.Fatalf("Expected 2 assets from memory fs, got %d", len(res.Assets))
	}
}

func TestFileCrawlerCapturesTraversalErrorOnInaccessibleRoot(t *testing.T) {
	nonExistentRoot := "/non/existent/path/for/aegis/crawler/test"
	fc := NewFileCrawler(CrawlerConfig{
		RootPaths: []string{nonExistentRoot},
	})

	res := fc.Crawl()
	if res.Status != CrawlStatusError {
		t.Errorf("Expected CrawlStatusError for non-existent root, got %s", res.Status)
	}
	if len(res.TraversalErrors) == 0 {
		t.Fatal("Expected traversal errors to capture non-existent root, got 0 errors")
	}
	if !strings.Contains(res.TraversalErrors[0], nonExistentRoot) {
		t.Errorf("Expected error to mention %s, got: %s", nonExistentRoot, res.TraversalErrors[0])
	}
}

func TestFileCrawlerCapturesTraversalErrorOnUnreadableSubdir(t *testing.T) {
	tempDir := t.TempDir()

	// Create a valid readable file
	_ = os.WriteFile(filepath.Join(tempDir, "package.json"), []byte(`{"name":"valid"}`), 0644)

	// Create an unreadable subdirectory
	unreadableDir := filepath.Join(tempDir, "unreadable_sub")
	if err := os.Mkdir(unreadableDir, 0700); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(unreadableDir, "composer.json"), []byte(`{}`), 0644)

	// Revoke read/exec permissions so Walk fails on unreadableDir
	if err := os.Chmod(unreadableDir, 0000); err != nil {
		t.Skipf("cannot chmod 0000 on this platform: %v", err)
	}
	defer os.Chmod(unreadableDir, 0755) // restore for cleanup

	fc := NewFileCrawler(CrawlerConfig{
		RootPaths: []string{tempDir},
	})

	res := fc.Crawl()

	// Should not silently swallow the error!
	if len(res.TraversalErrors) == 0 {
		t.Fatal("Expected traversal error for unreadable subdirectory, but none was recorded!")
	}
	// Since 1 asset was found and 1 directory failed, status should be PARTIAL
	if res.Status != CrawlStatusPartial {
		t.Errorf("Expected status PARTIAL when unreadable subdirectory encountered, got: %s", res.Status)
	}
	if len(res.Assets) != 1 {
		t.Errorf("Expected 1 discovered asset from accessible portion, got %d", len(res.Assets))
	}
}

func TestFileCrawlerCapturesSkippedDirs(t *testing.T) {
	memFs := afero.NewMemMapFs()
	_ = memFs.MkdirAll("/app/.git", 0755)
	_ = afero.WriteFile(memFs, "/app/.git/package.json", []byte(`{"name":"git-internal"}`), 0644)
	_ = memFs.MkdirAll("/app/node_modules/lib", 0755)
	_ = afero.WriteFile(memFs, "/app/node_modules/lib/package.json", []byte(`{"name":"lib"}`), 0644)
	_ = memFs.MkdirAll("/app/src", 0755)
	_ = afero.WriteFile(memFs, "/app/src/package.json", []byte(`{"name":"app"}`), 0644)

	fc := NewFileCrawler(CrawlerConfig{
		RootPaths:   []string{"/app"},
		ExcludeDirs: []string{".git", "node_modules"},
		Fs:          memFs,
	})

	res := fc.Crawl()
	if res.Status != CrawlStatusComplete {
		t.Errorf("Expected CrawlStatusComplete, got %s", res.Status)
	}
	if len(res.Assets) != 1 {
		t.Errorf("Expected only 1 asset (outside excluded dirs), got %d", len(res.Assets))
	}

	foundGitSkipped := false
	foundNodeModulesSkipped := false
	for _, skipped := range res.SkippedDirs {
		if strings.Contains(skipped, ".git") {
			foundGitSkipped = true
		}
		if strings.Contains(skipped, "node_modules") {
			foundNodeModulesSkipped = true
		}
	}
	if !foundGitSkipped || !foundNodeModulesSkipped {
		t.Errorf("Expected .git and node_modules in SkippedDirs, got: %v", res.SkippedDirs)
	}
}

func TestFileCrawlerDepthLimit(t *testing.T) {
	memFs := afero.NewMemMapFs()
	_ = memFs.MkdirAll("/app/l1/l2/l3", 0755)
	_ = afero.WriteFile(memFs, "/app/l1/package.json", []byte(`{"name":"level1"}`), 0644)
	_ = afero.WriteFile(memFs, "/app/l1/l2/l3/package.json", []byte(`{"name":"level3"}`), 0644)

	fc := NewFileCrawler(CrawlerConfig{
		RootPaths: []string{"/app"},
		MaxDepth:  2,
		Fs:        memFs,
	})

	res := fc.Crawl()
	if res.Status != CrawlStatusPartial {
		t.Errorf("Expected CrawlStatusPartial when depth limit is hit, got %s", res.Status)
	}
	if len(res.Assets) != 1 {
		t.Errorf("Expected 1 asset within depth limit, got %d", len(res.Assets))
	}
	if len(res.SkippedDirs) == 0 {
		t.Error("Expected SkippedDirs to record depth limit cutoff")
	}
}

func TestFileCrawlerMaxFilesLimit(t *testing.T) {
	memFs := afero.NewMemMapFs()
	_ = memFs.MkdirAll("/app", 0755)
	_ = afero.WriteFile(memFs, "/app/package.json", []byte(`{"name":"app"}`), 0644)
	_ = afero.WriteFile(memFs, "/app/composer.json", []byte(`{}`), 0644)
	_ = afero.WriteFile(memFs, "/app/nginx.conf", []byte(`server { listen 80; }`), 0644)
	_ = afero.WriteFile(memFs, "/app/Dockerfile", []byte(`FROM node:20`), 0644)

	fc := NewFileCrawler(CrawlerConfig{
		RootPaths: []string{"/app"},
		MaxFiles:  2,
		Fs:        memFs,
	})

	res := fc.Crawl()
	if res.Status != CrawlStatusPartial {
		t.Errorf("Expected CrawlStatusPartial when file count limit hit, got %s", res.Status)
	}
}

func TestFileCrawlerContextCancellation(t *testing.T) {
	memFs := afero.NewMemMapFs()
	_ = memFs.MkdirAll("/app", 0755)
	_ = afero.WriteFile(memFs, "/app/package.json", []byte(`{"name":"app"}`), 0644)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	fc := NewFileCrawler(CrawlerConfig{
		RootPaths: []string{"/app"},
		Context:   ctx,
		Fs:        memFs,
	})

	res := fc.Crawl()
	if res.Status == CrawlStatusComplete {
		t.Errorf("Expected non-complete status on context cancellation, got %s", res.Status)
	}
}

func TestCoverageLedgerTruthfulPropagation(t *testing.T) {
	covLedger := ledger.NewCoverageLedger("test-host")
	skipped := []string{"/var/log", "/proc"}
	errors := []string{"/root/secret: permission denied"}

	covLedger.RecordCrawlSummary(ledger.CrawlStatusPartial, skipped, errors)
	covLedger.AddAsset(ledger.RuntimeAsset{
		Type:   "php",
		Path:   "/var/www/composer.json",
		Source: "manifest",
	})

	if covLedger.CrawlStatus != ledger.CrawlStatusPartial {
		t.Errorf("Expected CrawlStatusPartial, got %s", covLedger.CrawlStatus)
	}
	if len(covLedger.SkippedDirs) != 2 {
		t.Errorf("Expected 2 skipped dirs, got %d", len(covLedger.SkippedDirs))
	}
	if len(covLedger.TraversalErrors) != 1 {
		t.Errorf("Expected 1 traversal error, got %d", len(covLedger.TraversalErrors))
	}
	if covLedger.TotalAssets != 1 {
		t.Errorf("Expected 1 total asset, got %d", covLedger.TotalAssets)
	}

	tempDir := t.TempDir()
	outPath := filepath.Join(tempDir, "ledger.json")
	if err := covLedger.WriteToFile(outPath); err != nil {
		t.Fatalf("Failed to write ledger: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("Failed to read ledger: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, `"crawl_status": "PARTIAL"`) {
		t.Errorf("Ledger JSON missing crawl_status: %s", content)
	}
	if !strings.Contains(content, `permission denied`) {
		t.Errorf("Ledger JSON missing traversal error: %s", content)
	}
}
