package crawler

import (
	"os"
	"path/filepath"
	"testing"

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

	assets := fc.Crawl()
	if len(assets) < 4 {
		t.Fatalf("Expected at least 4 assets, discovered %d", len(assets))
	}

	foundPackageJson := false
	foundComposerJson := false
	foundNginx := false
	foundDockerfile := false

	for _, a := range assets {
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

	assets := fc.Crawl()
	if len(assets) != 2 {
		t.Fatalf("Expected 2 assets from memory fs, got %d", len(assets))
	}
}
