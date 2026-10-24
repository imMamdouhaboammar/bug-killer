use std::fs;
use std::path::Path;
use crate::types::*;
use crate::healer::backup::BackupManager;

pub struct RollbackManager;

impl RollbackManager {
    /// Reverts all changes recorded in a specified backup ID after cryptographic verification.
    pub fn rollback(root: &Path, backup_id: &str) -> Result<usize, String> {
        let backup_dir = root.join(".aegis").join("backups").join(backup_id);
        if !backup_dir.exists() {
            return Err(format!("Backup ID '{}' not found at {:?}", backup_id, backup_dir));
        }

        let manifest_path = backup_dir.join("manifest.json");
        let content = fs::read_to_string(&manifest_path)
            .map_err(|e| format!("Failed to read backup manifest: {}", e))?;

        let manifest: BackupManifest = serde_json::from_str(&content)
            .map_err(|e| format!("Invalid backup manifest JSON: {}", e))?;

        // Cryptographic identity trust verification (fail-closed if tampered)
        if manifest.signature.is_some() {
            crate::identity::AgentIdentity::verify_manifest(&manifest)
                .map_err(|e| format!("Cryptographic trust verification failed: {}", e))?;
        }

        let mut restored_count = 0;

        for record in &manifest.records {
            let backup_file = backup_dir.join(&record.backup_file_name);
            if !backup_file.exists() {
                return Err(format!("Backup archive file {:?} is missing", backup_file));
            }

            // Verify checksum of backup copy
            let backup_sha256 = BackupManager::compute_sha256(&backup_file)
                .map_err(|e| format!("Failed to compute backup checksum: {}", e))?;

            if backup_sha256 != record.original_sha256 {
                return Err(format!(
                    "Integrity check failed for {}: expected {}, got {}",
                    record.backup_file_name, record.original_sha256, backup_sha256
                ));
            }

            let target_file = root.join(&record.relative_target_path);
            if let Some(parent) = target_file.parent() {
                let _ = fs::create_dir_all(parent);
            }

            // Restore original file
            fs::copy(&backup_file, &target_file)
                .map_err(|e| format!("Failed to restore {:?}: {}", target_file, e))?;

            restored_count += 1;
        }

        Ok(restored_count)
    }
}
