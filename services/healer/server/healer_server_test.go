package server

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	omniv1 "github.com/aegis/healer/omniv1"
)

func TestStatefulHealerExecutionAndRollback(t *testing.T) {
	tmpDir := t.TempDir()
	confPath := filepath.Join(tmpDir, "nginx.conf")
	initialContent := "server {\n    listen 80;\n    location / {\n        proxy_pass http://localhost:8080;\n    }\n}\n"
	if err := os.WriteFile(confPath, []byte(initialContent), 0644); err != nil {
		t.Fatalf("failed to write test nginx conf: %v", err)
	}

	server, err := NewStatefulHealerServer(filepath.Join(tmpDir, "backups"))
	if err != nil {
		t.Fatalf("failed to initialize StatefulHealerServer: %v", err)
	}

	// 1. Execute Remediation (WAF Virtual Patch)
	dir := &omniv1.HealingDirective{
		DirectiveId:     "dir-waf-001",
		RemediationType: omniv1.RemediationType_REMEDIATION_VIRTUAL_PATCH_WAF,
		TargetFilePath:  confPath,
		DryRun:          false,
	}

	res, err := server.ExecuteRemediation(context.Background(), dir)
	if err != nil {
		t.Fatalf("ExecuteRemediation failed: %v", err)
	}
	if !res.Success {
		t.Fatalf("expected Success=true, error: %s", res.ErrorMessage)
	}
	if res.Ed25519AgentSignature == "" {
		t.Errorf("expected non-empty Ed25519 signature")
	}

	// Verify file was patched
	patchedData, _ := os.ReadFile(confPath)
	if !strings.Contains(string(patchedData), "415") {
		t.Errorf("expected patched nginx conf to contain 415 Brotli drop rule")
	}

	// 2. Rollback
	rollbackDir := &omniv1.HealingDirective{
		DirectiveId:    res.BackupManifestId,
		TargetFilePath: confPath,
		DryRun:         false,
	}

	rollRes, err := server.RollbackRemediation(context.Background(), rollbackDir)
	if err != nil {
		t.Fatalf("RollbackRemediation failed: %v", err)
	}
	if !rollRes.Success {
		t.Fatalf("expected Rollback Success=true, error: %s", rollRes.ErrorMessage)
	}

	// Verify restored content matches original
	restoredData, _ := os.ReadFile(confPath)
	if string(restoredData) != initialContent {
		t.Errorf("restored content does not match initial content:\nGot: %s\nWant: %s", string(restoredData), initialContent)
	}
}

func TestStatefulHealerTamperedRollbackFailsClosed(t *testing.T) {
	tmpDir := t.TempDir()
	confPath := filepath.Join(tmpDir, "nginx.conf")
	_ = os.WriteFile(confPath, []byte("server { listen 80; }"), 0644)

	backupDir := filepath.Join(tmpDir, "backups")
	server, _ := NewStatefulHealerServer(backupDir)

	res, _ := server.ExecuteRemediation(context.Background(), &omniv1.HealingDirective{
		DirectiveId:     "tamper-test",
		RemediationType: omniv1.RemediationType_REMEDIATION_VIRTUAL_PATCH_WAF,
		TargetFilePath:  confPath,
	})

	// Tamper with the backup file
	backupFile := filepath.Join(backupDir, res.BackupManifestId+".bak")
	_ = os.WriteFile(backupFile, []byte("tampered_malicious_content"), 0600)

	// Attempt rollback
	rollRes, err := server.RollbackRemediation(context.Background(), &omniv1.HealingDirective{
		DirectiveId:    res.BackupManifestId,
		TargetFilePath: confPath,
	})
	if err != nil {
		t.Fatalf("unexpected gRPC error: %v", err)
	}
	if rollRes.Success {
		t.Errorf("expected rollback of tampered file to fail closed, but it reported success")
	}
	if !strings.Contains(rollRes.ErrorMessage, "SIGNATURE MISMATCH") {
		t.Errorf("expected SIGNATURE MISMATCH error, got: %s", rollRes.ErrorMessage)
	}
}
