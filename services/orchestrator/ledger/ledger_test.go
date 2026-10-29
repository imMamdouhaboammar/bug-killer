package ledger

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestCoverageLedger_WriteToFile_AtomicCreationAndReplace(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "ledger-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	targetFile := filepath.Join(tempDir, "nested", "sub", "coverage-ledger.json")

	ledger := NewCoverageLedger("test-host-01")
	ledger.AddAsset(RuntimeAsset{
		Type:          "php",
		Path:          "/usr/bin/php8.2",
		Source:        "binary",
		AssociatedPID: 1234,
	})

	if err := ledger.WriteToFile(targetFile); err != nil {
		t.Fatalf("unexpected error writing ledger: %v", err)
	}

	// Verify file exists and is valid JSON
	data, err := os.ReadFile(targetFile)
	if err != nil {
		t.Fatalf("failed to read written ledger file: %v", err)
	}

	var parsed CoverageLedger
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to parse written ledger: %v", err)
	}

	if parsed.HostID != "test-host-01" {
		t.Errorf("expected host_id 'test-host-01', got '%s'", parsed.HostID)
	}
	if parsed.TotalAssets != 1 {
		t.Errorf("expected total_assets 1, got %d", parsed.TotalAssets)
	}

	// Atomic replace test: update ledger and write again
	ledger.AddAsset(RuntimeAsset{
		Type:   "node",
		Path:   "/usr/bin/node",
		Source: "binary",
	})
	if err := ledger.WriteToFile(targetFile); err != nil {
		t.Fatalf("unexpected error overwriting ledger: %v", err)
	}

	data2, err := os.ReadFile(targetFile)
	if err != nil {
		t.Fatalf("failed to read overwritten ledger file: %v", err)
	}
	var parsed2 CoverageLedger
	if err := json.Unmarshal(data2, &parsed2); err != nil {
		t.Fatalf("failed to parse overwritten ledger: %v", err)
	}
	if parsed2.TotalAssets != 2 {
		t.Errorf("expected total_assets 2 after update, got %d", parsed2.TotalAssets)
	}

	// Verify no temporary files remain in directory
	dirEntries, err := os.ReadDir(filepath.Dir(targetFile))
	if err != nil {
		t.Fatalf("failed to read target directory: %v", err)
	}
	for _, entry := range dirEntries {
		if filepath.Ext(entry.Name()) == ".tmp" {
			t.Errorf("found leftover temp file: %s", entry.Name())
		}
	}
}
