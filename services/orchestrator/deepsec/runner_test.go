package deepsec

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/spf13/afero"
)

func TestDeepSecRunnerScanAndProcess(t *testing.T) {
	memFs := afero.NewMemMapFs()
	runner := NewRunner(memFs)
	projectID := "test-orch-project"
	rootPath := "/workspace/test-repo"

	// 1. Scaffold files in in-memory filesystem
	_ = memFs.MkdirAll(filepath.Join(rootPath, "src"), 0755)
	_ = memFs.MkdirAll(filepath.Join(rootPath, "node_modules", "pkg"), 0755)

	sqlFile := filepath.Join(rootPath, "src", "db.js")
	_ = afero.WriteFile(memFs, sqlFile, []byte("const q = \"SELECT * FROM users WHERE id = \" + req.query.id;\n"), 0644)

	rceFile := filepath.Join(rootPath, "src", "eval.py")
	_ = afero.WriteFile(memFs, rceFile, []byte("import os\nexec(user_input)\n"), 0644)

	ignoredFile := filepath.Join(rootPath, "node_modules", "pkg", "index.js")
	_ = afero.WriteFile(memFs, ignoredFile, []byte("eval(danger)\n"), 0644)

	ctx := context.Background()

	// 2. Scan
	scanStats, err := runner.Scan(ctx, rootPath, projectID)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if scanStats.FilesScanned != 2 {
		t.Errorf("Expected 2 files scanned (ignoring node_modules), got %d", scanStats.FilesScanned)
	}
	if scanStats.CandidatesFound != 2 {
		t.Errorf("Expected 2 candidate matches, got %d", scanStats.CandidatesFound)
	}

	pending, err := runner.LoadPendingFiles(projectID)
	if err != nil {
		t.Fatalf("LoadPendingFiles failed: %v", err)
	}
	if len(pending) != 2 {
		t.Errorf("Expected 2 pending file records, got %d", len(pending))
	}

	// 3. Process
	procStats, err := runner.Process(ctx, rootPath, projectID, 2, 1)
	if err != nil {
		t.Fatalf("Process failed: %v", err)
	}

	if procStats.FilesProcessed != 2 {
		t.Errorf("Expected 2 files processed, got %d", procStats.FilesProcessed)
	}
	if procStats.FindingsCount != 2 {
		t.Errorf("Expected 2 findings, got %d", procStats.FindingsCount)
	}

	// 4. Verify no more pending files
	remainingPending, err := runner.LoadPendingFiles(projectID)
	if err != nil {
		t.Fatalf("LoadPendingFiles post-process failed: %v", err)
	}
	if len(remainingPending) != 0 {
		t.Errorf("Expected 0 remaining pending files, got %d", len(remainingPending))
	}
}
