package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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
	ManifestID   string `json:"manifest_id"`
	DirectiveID  string `json:"directive_id"`
	OriginalPath string `json:"original_path"`
	BackupPath   string `json:"backup_path"`
	SHA256Hash   string `json:"sha256_hash"`
	Signature    string `json:"signature"`
	Timestamp    int64  `json:"timestamp"`
}

func signedManifestPayload(manifest BackupManifest) ([]byte, error) {
	manifest.Signature = ""
	return json.Marshal(manifest)
}

func validManifestID(id string) bool {
	if !strings.HasPrefix(id, "manifest-") || len(id) != len("manifest-")+32 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(id, "manifest-"))
	return err == nil
}

func canonicalTargetPath(target string) (string, error) {
	absolute, err := filepath.Abs(target)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err == nil {
		return resolved, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(absolute))
	if err != nil {
		return "", err
	}
	return filepath.Join(parent, filepath.Base(absolute)), nil
}

// NewStatefulHealerServer creates a new remediation gRPC server with Ed25519 keypair.
func NewStatefulHealerServer(backupDir string) (*StatefulHealerServer, error) {
	keyPath := filepath.Join(backupDir, "agent_identity.key")
	if backupDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("cannot determine persistent signing identity location: %w", err)
		}
		backupDir = filepath.Join(home, ".bug-killer", "backups")
		keyPath = filepath.Join(home, ".bug-killer", "identity", "agent.key")
	}
	if err := os.MkdirAll(backupDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to initialize backup directory %s: %w", backupDir, err)
	}
	keyDir := filepath.Dir(keyPath)
	if err := os.MkdirAll(keyDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to initialize signing identity directory %s: %w", keyDir, err)
	}
	if info, err := os.Lstat(keyDir); err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("signing identity directory must be a private 0700 directory: %s", keyDir)
	}
	if info, err := os.Lstat(backupDir); err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("backup directory must be a private 0700 directory: %s", backupDir)
	}
	var pub ed25519.PublicKey
	var priv ed25519.PrivateKey
	data, err := os.ReadFile(keyPath)
	switch {
	case err == nil:
		info, statErr := os.Lstat(keyPath)
		if statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || (len(data) != ed25519.PrivateKeySize && len(data) != ed25519.SeedSize) {
			return nil, fmt.Errorf("invalid existing Ed25519 signing identity; refusing key rotation")
		}
		priv = ed25519.NewKeyFromSeed(data[:ed25519.SeedSize])
		if len(data) == ed25519.PrivateKeySize && !bytes.Equal(priv, data) {
			return nil, fmt.Errorf("invalid Ed25519 keypair: public key disagrees with private seed; refusing key rotation")
		}
		pub = priv.Public().(ed25519.PublicKey)
	case !errors.Is(err, os.ErrNotExist):
		return nil, fmt.Errorf("failed to read existing agent identity key: %w", err)
	default:
		pub, priv, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate ed25519 agent identity key: %w", err)
		}
		// Write completely before atomically publishing the identity without clobbering.
		temp, createErr := os.CreateTemp(keyDir, ".agent-identity-*")
		if createErr != nil {
			return nil, fmt.Errorf("failed to prepare identity key: %w", createErr)
		}
		defer os.Remove(temp.Name())
		if err = temp.Chmod(0600); err == nil {
			_, err = temp.Write(priv.Seed())
		}
		if err == nil {
			err = temp.Sync()
		}
		closeErr := temp.Close()
		if err != nil {
			return nil, fmt.Errorf("failed to write identity key: %w", err)
		}
		if closeErr != nil {
			return nil, fmt.Errorf("failed to close identity key: %w", closeErr)
		}
		if err := os.Link(temp.Name(), keyPath); err != nil {
			return nil, fmt.Errorf("failed to atomically publish identity key (possible concurrent creation): %w", err)
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
		if dir.DryRun {
			res.Success = true
			res.AppliedDiff = "[DRY-RUN] Would inject HTTP 415 Brotli drop rule into " + dir.TargetFilePath
			return res, nil
		}

		// 1. Create cryptographic backup before modifying file
		manifestID, sig, err := s.createBackup(dir.DirectiveId, dir.TargetFilePath)
		if err != nil {
			res.Success = false
			res.ErrorMessage = fmt.Sprintf("backup failed: %v", err)
			return res, nil
		}
		res.BackupManifestId = manifestID
		res.Ed25519AgentSignature = sig

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
	if dir == nil {
		return nil, status.Error(codes.InvalidArgument, "rollback directive must not be nil")
	}
	manifestID := dir.DirectiveId
	if !validManifestID(manifestID) {
		return &omniv1.HealingResult{
			DirectiveId: manifestID, Success: false, ErrorMessage: "Invalid backup manifest identifier",
		}, nil
	}
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

	// Independently verify both the payload digest and its bound destination.
	h := sha256.Sum256(backupData)
	hashHex := hex.EncodeToString(h[:])

	metadata, err := os.ReadFile(manifestFile)
	if err != nil {
		return &omniv1.HealingResult{
			DirectiveId:  dir.DirectiveId,
			Success:      false,
			ErrorMessage: "Missing backup signature metadata",
		}, nil
	}
	var manifest BackupManifest
	if err := json.Unmarshal(metadata, &manifest); err != nil {
		return &omniv1.HealingResult{DirectiveId: manifestID, Success: false,
			ErrorMessage: "ED25519 SIGNATURE MISMATCH: invalid or legacy unbound backup metadata"}, nil
	}
	targetPath, err := canonicalTargetPath(dir.TargetFilePath)
	if err != nil || targetPath != manifest.OriginalPath || manifest.ManifestID != manifestID || manifest.BackupPath != backupFile || manifest.SHA256Hash != hashHex {
		return &omniv1.HealingResult{DirectiveId: manifestID, Success: false,
			ErrorMessage: "ED25519 SIGNATURE MISMATCH: target path, backup identity or digest differs from signed manifest"}, nil
	}
	message, err := signedManifestPayload(manifest)
	if err != nil {
		return &omniv1.HealingResult{DirectiveId: manifestID, Success: false, ErrorMessage: "Cannot reconstruct signed manifest"}, nil
	}
	sig, err := hex.DecodeString(manifest.Signature)
	if err != nil || !ed25519.Verify(s.pubKey, message, sig) {
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

	// Restore by atomic replacement in the canonical, signed destination directory.
	// This avoids partial writes and does not follow a retargeted final symlink.
	temp, err := os.CreateTemp(filepath.Dir(targetPath), ".bug-killer-restore-*")
	if err != nil {
		return &omniv1.HealingResult{DirectiveId: manifestID, Success: false, ErrorMessage: fmt.Sprintf("Failed to prepare rollback: %v", err)}, nil
	}
	defer os.Remove(temp.Name())
	mode := os.FileMode(0600)
	if info, statErr := os.Stat(targetPath); statErr == nil {
		mode = info.Mode().Perm()
	}
	writeErr := temp.Chmod(mode)
	if writeErr == nil {
		_, writeErr = temp.Write(backupData)
	}
	if writeErr == nil {
		writeErr = temp.Sync()
	}
	closeErr := temp.Close()
	if writeErr == nil {
		writeErr = closeErr
	}
	if writeErr == nil {
		writeErr = os.Rename(temp.Name(), targetPath)
	}
	if writeErr != nil {
		return &omniv1.HealingResult{
			DirectiveId:  dir.DirectiveId,
			Success:      false,
			ErrorMessage: fmt.Sprintf("Failed to restore target file atomically: %v", writeErr),
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
	canonical, err := canonicalTargetPath(targetPath)
	if err != nil {
		return "", "", fmt.Errorf("cannot resolve target path %s: %w", targetPath, err)
	}
	orig, err := os.ReadFile(canonical)
	if err != nil {
		return "", "", fmt.Errorf("cannot read target file %s: %w", targetPath, err)
	}

	h := sha256.Sum256(orig)
	hashHex := hex.EncodeToString(h[:])

	// The identifier is independent of untrusted directive text and cannot
	// contain directory separators or traverse outside the backup directory.
	randomID := make([]byte, 16)
	if _, err := rand.Read(randomID); err != nil {
		return "", "", fmt.Errorf("failed to create random backup identifier: %w", err)
	}
	manifestID := "manifest-" + hex.EncodeToString(randomID)
	backupFile := filepath.Join(s.backupDir, manifestID+".bak")
	manifestFile := filepath.Join(s.backupDir, manifestID+".meta")
	manifest := BackupManifest{
		ManifestID:   manifestID,
		DirectiveID:  directiveID,
		OriginalPath: canonical,
		BackupPath:   backupFile,
		SHA256Hash:   hashHex,
		Timestamp:    time.Now().Unix(),
	}
	message, err := signedManifestPayload(manifest)
	if err != nil {
		return "", "", fmt.Errorf("failed to encode backup manifest: %w", err)
	}
	sigHex := hex.EncodeToString(ed25519.Sign(s.privKey, message))
	manifest.Signature = sigHex
	meta, err := json.Marshal(manifest)
	if err != nil {
		return "", "", fmt.Errorf("failed to encode signed backup manifest: %w", err)
	}

	backup, err := os.OpenFile(backupFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", "", fmt.Errorf("failed to create exclusive backup payload: %w", err)
	}
	var writeErr error
	_, writeErr = backup.Write(orig)
	if writeErr == nil {
		writeErr = backup.Sync()
	}
	closeErr := backup.Close()
	if writeErr == nil {
		writeErr = closeErr
	}
	if writeErr != nil {
		_ = os.Remove(backupFile)
		return "", "", fmt.Errorf("failed to write backup payload: %w", writeErr)
	}
	metaFile, err := os.OpenFile(manifestFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", "", fmt.Errorf("failed to create signed backup manifest: %w", err)
	}
	_, writeErr = metaFile.Write(meta)
	if writeErr == nil {
		writeErr = metaFile.Sync()
	}
	closeErr = metaFile.Close()
	if writeErr == nil {
		writeErr = closeErr
	}
	if writeErr != nil {
		_ = os.Remove(manifestFile)
		return "", "", fmt.Errorf("failed to write signed backup manifest: %w", writeErr)
	}

	return manifestID, sigHex, nil
}
