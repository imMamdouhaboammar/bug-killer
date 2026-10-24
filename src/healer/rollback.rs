use crate::healer::backup::BackupManager;
use crate::types::*;
use std::fs;
use std::path::Path;

pub struct RollbackManager;

impl RollbackManager {
    /// Reverts all changes recorded in a specified backup ID after cryptographic verification.
    pub fn rollback(root: &Path, backup_id: &str) -> Result<usize, String> {
        let backup_dir = root.join(".aegis").join("backups").join(backup_id);
        if !backup_dir.exists() {
            return Err(format!(
                "Backup ID '{}' not found at {:?}",
                backup_id, backup_dir
            ));
        }

        let manifest_path = backup_dir.join("manifest.json");
        let content = fs::read_to_string(&manifest_path)
            .map_err(|e| format!("Failed to read backup manifest: {}", e))?;

        let manifest: BackupManifest = serde_json::from_str(&content)
            .map_err(|e| format!("Invalid backup manifest JSON: {}", e))?;

        // Cryptographic identity trust verification (mandatory, fail-closed against local agent trust root)
        crate::identity::AgentIdentity::verify_manifest_with_root(root, &manifest)
            .map_err(|e| format!("Cryptographic trust verification failed: {}", e))?;

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

            // Security: Path traversal & boundary containment guard
            let rel_path = Path::new(&record.relative_target_path);
            if rel_path.is_absolute()
                || rel_path.components().any(|c| {
                    matches!(
                        c,
                        std::path::Component::ParentDir
                            | std::path::Component::RootDir
                            | std::path::Component::Prefix(_)
                    )
                })
            {
                return Err(format!(
                    "Path traversal attempt rejected in backup record: '{}'",
                    record.relative_target_path
                ));
            }

            let target_file = root.join(rel_path);

            let parent = target_file.parent().unwrap_or(root);
            let _ = fs::create_dir_all(parent);

            // Atomically restore original file via tempfile + atomic rename to prevent partial restores
            let backup_content = fs::read(&backup_file)
                .map_err(|e| format!("Failed to read backup payload {:?}: {}", backup_file, e))?;

            let mut temp = tempfile::NamedTempFile::new_in(parent)
                .map_err(|e| format!("Failed to create temporary file in {:?}: {}", parent, e))?;

            use std::io::Write;
            temp.write_all(&backup_content)
                .map_err(|e| format!("Failed to write restoration payload: {}", e))?;

            temp.persist(&target_file)
                .map_err(|e| format!("Failed to atomically restore {:?}: {}", target_file, e))?;

            restored_count += 1;
        }

        Ok(restored_count)
    }
}
