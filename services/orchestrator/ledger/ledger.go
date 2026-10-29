package ledger

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type CrawlStatus string

const (
	CrawlStatusComplete CrawlStatus = "COMPLETE"
	CrawlStatusPartial  CrawlStatus = "PARTIAL"
	CrawlStatusError    CrawlStatus = "ERROR"
)

type RuntimeAsset struct {
	Type          string            `json:"type"` // "php", "node", "bun", "webserver", "container"
	Path          string            `json:"path"`
	Version       string            `json:"version,omitempty"`
	Source        string            `json:"source"` // "binary", "manifest", "docker", "process"
	Metadata      map[string]string `json:"metadata,omitempty"`
	AssociatedPID int               `json:"associated_pid,omitempty"`
}

type CoverageLedger struct {
	HostID          string         `json:"host_id"`
	GeneratedAt     string         `json:"generated_at"`
	ScanDuration    string         `json:"scan_duration"`
	TotalAssets     int            `json:"total_assets"`
	Assets          []RuntimeAsset `json:"assets"`
	CrawlStatus     CrawlStatus    `json:"crawl_status,omitempty"`
	SkippedDirs     []string       `json:"skipped_dirs,omitempty"`
	TraversalErrors []string       `json:"traversal_errors,omitempty"`
}

func NewCoverageLedger(hostID string) *CoverageLedger {
	return &CoverageLedger{
		HostID:          hostID,
		GeneratedAt:     time.Now().UTC().Format(time.RFC3339),
		Assets:          make([]RuntimeAsset, 0),
		CrawlStatus:     CrawlStatusComplete,
		SkippedDirs:     make([]string, 0),
		TraversalErrors: make([]string, 0),
	}
}

func (l *CoverageLedger) AddAsset(asset RuntimeAsset) {
	l.Assets = append(l.Assets, asset)
	l.TotalAssets = len(l.Assets)
}

func (l *CoverageLedger) RecordCrawlSummary(status CrawlStatus, skippedDirs []string, traversalErrors []string) {
	l.CrawlStatus = status
	if skippedDirs != nil {
		l.SkippedDirs = skippedDirs
	}
	if traversalErrors != nil {
		l.TraversalErrors = traversalErrors
	}
}

func (l *CoverageLedger) WriteToFile(filePath string) error {
	data, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory for coverage ledger: %w", err)
	}

	tmpFile, err := os.CreateTemp(dir, ".coverage-ledger-*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create temporary file for coverage ledger: %w", err)
	}
	tmpName := tmpFile.Name()
	defer func() {
		_ = os.Remove(tmpName)
	}()

	if _, err := tmpFile.Write(data); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("failed to write coverage ledger data: %w", err)
	}
	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("failed to sync coverage ledger data: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("failed to close temporary coverage ledger file: %w", err)
	}
	if err := os.Rename(tmpName, filePath); err != nil {
		return fmt.Errorf("failed to atomically rename coverage ledger: %w", err)
	}
	return nil
}
