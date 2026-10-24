package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"

	omniv1 "github.com/aegis/healer/omniv1"
	"github.com/aegis/healer/pkgmgr"
	"github.com/aegis/healer/supervisor"
	"github.com/aegis/healer/waf"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// StatefulHealerServer implements the omniv1.OmniStatefulHealerServer gRPC service.
type StatefulHealerServer struct {
	omniv1.UnimplementedOmniStatefulHealerServer
	wafInjector *waf.WafInjector
	upgrader    *pkgmgr.PackageUpgrader
	supervisor  *supervisor.ProcessSupervisor
	backupDir   string
	pubKey      ed25519.PublicKey
	privKey     ed25519.PrivateKey
}

// BackupManifest stores the cryptographic metadata for non-repudiation rollbacks.
type BackupManifest struct {
	DirectiveID string `json:"directive_id"`
	OriginalPath string `json:"original_path"`
	BackupPath   string `json:"backup_path"`
	SHA256Hash   string `json:"sha256_hash"`
	Signature    string `json:"signature"`
	Timestamp    int64  `json:"timestamp"`
}

// NewStatefulHealerServer creates a new remediation gRPC server with Ed25519 keypair.
func NewStatefulHealerServer(backupDir string) (*StatefulHealerServer, error) {
	if backupDir == "" {
		backupDir = "/tmp/.omni_backups"
	}
	if err := os.MkdirAll(backupDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to initialize backup directory %s: %w", backupDir, err)
	}

	keyPath := filepath.Join(backupDir, "agent_identity.key")
	var pub ed25519.PublicKey
	var priv ed25519.PrivateKey
	if data, err := os.ReadFile(keyPath); err == nil && len(data) == ed25519.PrivateKeySize {
		priv = ed25519.PrivateKey(data)
		pub = priv.Public().(ed25519.PublicKey)
	} else {
		var err error
		pub, priv, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate ed25519 agent identity key: %w", err)
		}
		if err := os.WriteFile(keyPath, priv, 0600); err != nil {
			return nil, fmt.Errorf("failed to persist agent identity key: %w", err)
		}
	}

	return &StatefulHealerServer{
		wafInjector: waf.NewWafInjector(),
		upgrader:    pkgmgr.NewPackageUpgrader(),
		supervisor:  supervisor.NewProcessSupervisor(),
		backupDir:   backupDir,
		pubKey:      pub,
		privKey:     priv,
	}, nil
}

// ExecuteRemediation applies the remediation directive, records a signed backup, and returns the cryptographic receipt.
func (s *StatefulHealerServer) ExecuteRemediation(ctx context.Context, dir *omniv1.HealingDirective) (*omniv1.HealingResult, error) {
	if dir == nil {
		return nil, status.Error(codes.InvalidArgument, "healing directive must not be nil")
	}

	res := &omniv1.HealingResult{
		DirectiveId:          dir.DirectiveId,
		AppliedTimestampUnix: time.Now().Unix(),
	}

	switch dir.RemediationType {
	case omniv1.RemediationType_REMEDIATION_VIRTUAL_PATCH_WAF:
		if dir.TargetFilePath == "" {
			res.Success = false
			res.ErrorMessage = "TargetFilePath required for WAF virtual patch"
			return res, nil
		}

		// 1. Create cryptographic backup before modifying file
		manifestID, sig, err := s.createBackup(dir.DirectiveId, dir.TargetFilePath)
		if err != nil && !dir.DryRun {
			res.Success = false
			res.ErrorMessage = fmt.Sprintf("backup failed: %v", err)
			return res, nil
		}
		res.BackupManifestId = manifestID
		res.Ed25519AgentSignature = sig

		if dir.DryRun {
			res.Success = true
			res.AppliedDiff = "[DRY-RUN] Would inject HTTP 415 Brotli drop rule into " + dir.TargetFilePath
			return res, nil
		}

		// 2. Apply patch
		applied, err := s.wafInjector.InjectNginx(dir.TargetFilePath)
		if err != nil {
			res.Success = false
			res.ErrorMessage = fmt.Sprintf("WAF injection error: %v", err)
			return res, nil
		}

		res.Success = true
		if applied {
			res.AppliedDiff = "Injected HTTP 415 Brotli drop rule and FastCGI buffer limits"
		} else {
			res.AppliedDiff = "Idempotent: configuration already patched"
		}

	case omniv1.RemediationType_REMEDIATION_PACKAGE_UPGRADE:
		pkgName := dir.PackageName
		if pkgName == "" {
			pkgName = dir.TargetIdentifier
		}
		out, err := s.upgrader.ExecuteUpgrade(pkgName, dir.DryRun)
		if err != nil {
			res.Success = false
			res.ErrorMessage = fmt.Sprintf("Package upgrade error: %v", err)
			return res, nil
		}
		res.Success = true
		res.AppliedDiff = out

	case omniv1.RemediationType_REMEDIATION_PROCESS_RELOAD:
		out, err := s.supervisor.ReloadService(dir.TargetIdentifier, dir.DryRun)
		if err != nil {
			res.Success = false
			res.ErrorMessage = fmt.Sprintf("Service reload error: %v", err)
			return res, nil
		}
		res.Success = true
		res.AppliedDiff = out

	default:
		res.Success = false
		res.ErrorMessage = fmt.Sprintf("Unsupported remediation type: %v", dir.RemediationType)
	}

	return res, nil
}

// RollbackRemediation verifies the Ed25519 signature before restoring the file state.
func (s *StatefulHealerServer) RollbackRemediation(ctx context.Context, dir *omniv1.HealingDirective) (*omniv1.HealingResult, error) {
	manifestID := dir.DirectiveId
	backupFile := filepath.Join(s.backupDir, manifestID+".bak")
	manifestFile := filepath.Join(s.backupDir, manifestID+".meta")

	if _, err := os.Stat(backupFile); os.IsNotExist(err) {
		return &omniv1.HealingResult{
			DirectiveId:  dir.DirectiveId,
			Success:      false,
			ErrorMessage: fmt.Sprintf("Backup file not found for directive %s", dir.DirectiveId),
		}, nil
	}

	backupData, err := os.ReadFile(backupFile)
	if err != nil {
		return &omniv1.HealingResult{
			DirectiveId:  dir.DirectiveId,
			Success:      false,
			ErrorMessage: fmt.Sprintf("Failed to read backup: %v", err),
		}, nil
	}

	// Verify SHA-256 hash
	h := sha256.Sum256(backupData)
	hashHex := hex.EncodeToString(h[:])

	// Read and verify Ed25519 signature
	sigBytes, err := os.ReadFile(manifestFile)
	if err != nil {
		return &omniv1.HealingResult{
			DirectiveId:  dir.DirectiveId,
			Success:      false,
			ErrorMessage: "Missing backup signature metadata",
		}, nil
	}

	sig, err := hex.DecodeString(string(sigBytes))
	if err != nil || !ed25519.Verify(s.pubKey, []byte(hashHex), sig) {
		return &omniv1.HealingResult{
			DirectiveId:  dir.DirectiveId,
			Success:      false,
			ErrorMessage: "ED25519 SIGNATURE MISMATCH: Backup payload compromised or corrupted",
		}, nil
	}

	if dir.DryRun {
		return &omniv1.HealingResult{
			DirectiveId: dir.DirectiveId,
			Success:     true,
			AppliedDiff: fmt.Sprintf("[DRY-RUN] Signature verified. Would restore %s", dir.TargetFilePath),
		}, nil
	}

	// Restore original file
	if err := os.WriteFile(dir.TargetFilePath, backupData, 0644); err != nil {
		return &omniv1.HealingResult{
			DirectiveId:  dir.DirectiveId,
			Success:      false,
			ErrorMessage: fmt.Sprintf("Failed to restore target file: %v", err),
		}, nil
	}

	return &omniv1.HealingResult{
		DirectiveId:          dir.DirectiveId,
		Success:              true,
		AppliedDiff:          fmt.Sprintf("Restored %s from verified backup %s", dir.TargetFilePath, manifestID),
		AppliedTimestampUnix: time.Now().Unix(),
	}, nil
}

func (s *StatefulHealerServer) createBackup(directiveID, targetPath string) (string, string, error) {
	orig, err := os.ReadFile(targetPath)
	if err != nil {
		return "", "", fmt.Errorf("cannot read target file %s: %w", targetPath, err)
	}

	h := sha256.Sum256(orig)
	hashHex := hex.EncodeToString(h[:])

	// Sign SHA-256 with Ed25519 agent private key
	sig := ed25519.Sign(s.privKey, []byte(hashHex))
	sigHex := hex.EncodeToString(sig)

	manifestID := fmt.Sprintf("manifest-%s-%d", directiveID, time.Now().UnixNano())
	backupFile := filepath.Join(s.backupDir, manifestID+".bak")
	manifestFile := filepath.Join(s.backupDir, manifestID+".meta")

	if err := os.WriteFile(backupFile, orig, 0600); err != nil {
		return "", "", fmt.Errorf("failed to write backup payload: %w", err)
	}
	if err := os.WriteFile(manifestFile, []byte(sigHex), 0600); err != nil {
		return "", "", fmt.Errorf("failed to write manifest signature: %w", err)
	}

	return manifestID, sigHex, nil
}
