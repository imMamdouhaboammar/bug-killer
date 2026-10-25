package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"

	omniv1 "github.com/aegis/healer/omniv1"
)

func TestStatefulHealerDoesNotReplaceCorruptSigningKey(t *testing.T) {
	backupDir := filepath.Join(t.TempDir(), "backups")
	if err := os.MkdirAll(backupDir, 0700); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(backupDir, "agent_identity.key")
	if err := os.WriteFile(keyPath, []byte("corrupt-key"), 0600); err != nil {
		t.Fatal(err)
	}

	if _, err := NewStatefulHealerServer(backupDir); err == nil {
		t.Fatal("Must fail closed when a persisted signing identity is corrupted")
	}
	data, err := os.ReadFile(keyPath)
	if err != nil || !bytes.Equal(data, []byte("corrupt-key")) {
		t.Fatal("Corrupted identity must be preserved for operator recovery, never replaced")
	}
}

func TestStatefulHealerUsesStableSigningKeyOnRestart(t *testing.T) {
	backupDir := filepath.Join(t.TempDir(), "backups")
	first, err := NewStatefulHealerServer(backupDir)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewStatefulHealerServer(backupDir)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.pubKey, second.pubKey) {
		t.Fatal("Backup signatures must remain verifiable after process restart")
	}
}

func TestDefaultHealerBackupsAndIdentityUsePersistentHomeDirectory(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	server, err := NewStatefulHealerServer("")
	if err != nil {
		t.Fatal(err)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	if server.backupDir != filepath.Join(home, ".bug-killer", "backups") {
		t.Fatalf("Default backup location must be persistent, got: %s", server.backupDir)
	}
	identityPath := filepath.Join(home, ".bug-killer", "identity", "agent.key")
	if info, err := os.Stat(identityPath); err != nil || info.Size() != ed25519.SeedSize {
		t.Fatalf("Default Ed25519 identity must use persistent trust path: %v", err)
	}
	restarted, err := NewStatefulHealerServer("")
	if err != nil || !bytes.Equal(restarted.pubKey, server.pubKey) {
		t.Fatalf("Default signing key must survive restarts: %v", err)
	}
}

func TestStatefulHealerRejectsTamperedPublicHalfOfLegacyIdentity(t *testing.T) {
	backupDir := filepath.Join(t.TempDir(), "backups")
	if err := os.MkdirAll(backupDir, 0700); err != nil {
		t.Fatal(err)
	}
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	key[ed25519.SeedSize] ^= 0xff
	if err := os.WriteFile(filepath.Join(backupDir, "agent_identity.key"), key, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewStatefulHealerServer(backupDir); err == nil {
		t.Fatal("An inconsistent Ed25519 private/public keypair must not become the rollback trust root")
	}
}

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

func TestRollbackRejectsDifferentTargetThanSignedBackup(t *testing.T) {
	tmp := t.TempDir()
	original := filepath.Join(tmp, "nginx.conf")
	other := filepath.Join(tmp, "unrelated.conf")
	if err := os.WriteFile(original, []byte("server { listen 80; }"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(other, []byte("untouched"), 0600); err != nil {
		t.Fatal(err)
	}
	srv, err := NewStatefulHealerServer(filepath.Join(tmp, "backups"))
	if err != nil {
		t.Fatal(err)
	}
	created, err := srv.ExecuteRemediation(context.Background(), &omniv1.HealingDirective{
		DirectiveId: "binding-test", RemediationType: omniv1.RemediationType_REMEDIATION_VIRTUAL_PATCH_WAF, TargetFilePath: original,
	})
	if err != nil || !created.Success {
		t.Fatalf("failed to make backup: %v, %+v", err, created)
	}
	result, err := srv.RollbackRemediation(context.Background(), &omniv1.HealingDirective{
		DirectiveId: created.BackupManifestId, TargetFilePath: other,
	})
	if err != nil || result.Success {
		t.Fatalf("Rollback must reject replacing an unrelated file: %v, %+v", err, result)
	}
	data, err := os.ReadFile(other)
	if err != nil || string(data) != "untouched" {
		t.Fatal("Rollback must not modify an unrelated destination")
	}
}

func TestRollbackRejectsTraversalBackupIdentifier(t *testing.T) {
	srv, err := NewStatefulHealerServer(filepath.Join(t.TempDir(), "backups"))
	if err != nil {
		t.Fatal(err)
	}
	result, err := srv.RollbackRemediation(context.Background(), &omniv1.HealingDirective{
		DirectiveId: "../../some-other-file", TargetFilePath: filepath.Join(t.TempDir(), "destination"),
	})
	if err != nil || result.Success || !strings.Contains(result.ErrorMessage, "Invalid backup") {
		t.Fatalf("Must reject path traversal identifier before file I/O: %v, %+v", err, result)
	}
}

func TestWafDryRunDoesNotWriteBackupOrSignature(t *testing.T) {
	tmp := t.TempDir()
	conf := filepath.Join(tmp, "nginx.conf")
	if err := os.WriteFile(conf, []byte("server { listen 80; }"), 0600); err != nil {
		t.Fatal(err)
	}
	backupDir := filepath.Join(tmp, "backups")
	srv, err := NewStatefulHealerServer(backupDir)
	if err != nil {
		t.Fatal(err)
	}
	result, err := srv.ExecuteRemediation(context.Background(), &omniv1.HealingDirective{
		DirectiveId: "preview", RemediationType: omniv1.RemediationType_REMEDIATION_VIRTUAL_PATCH_WAF,
		TargetFilePath: conf, DryRun: true,
	})
	if err != nil || !result.Success {
		t.Fatalf("Dry-run preview should work: %v, %+v", err, result)
	}
	if result.BackupManifestId != "" {
		t.Fatal("Dry-run must not claim to have created a backup")
	}
	entries, err := os.ReadDir(backupDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".bak") || strings.HasSuffix(entry.Name(), ".meta") {
			t.Fatalf("Dry-run unexpectedly wrote a backup artifact: %s", entry.Name())
		}
	}
}
