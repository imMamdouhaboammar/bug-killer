use std::fs;
use std::path::{Path, PathBuf};
use sha2::{Sha256, Digest};
use chrono::Utc;
use crate::types::*;

pub struct BackupManager;

impl BackupManager {
    /// Computes the SHA256 checksum of a file.
    pub fn compute_sha256(path: &Path) -> std::io::Result<String> {
        let bytes = fs::read(path)?;
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        Ok(format!("{:x}", hasher.finalize()))
    }

    /// Creates an atomic backup of target files before modifying them.
    pub fn create_backup(root: &Path, files: &[PathBuf]) -> std::io::Result<BackupManifest> {
        let backup_id = Utc::now().format("%Y%m%d_%H%M%S").to_string();
        let backup_dir = root.join(".aegis").join("backups").join(&backup_id);
        fs::create_dir_all(&backup_dir)?;

        let mut records = Vec::new();

        for (idx, file) in files.iter().enumerate() {
            if !file.exists() {
                continue;
            }

            let sha256 = Self::compute_sha256(file)?;
            let backup_file_name = format!("{}_{}", idx, file.file_name().unwrap_or_default().to_string_lossy());
            let backup_path = backup_dir.join(&backup_file_name);

            fs::copy(file, backup_path)?;

            let relative_target_path = file
                .strip_prefix(root)
                .unwrap_or(file)
                .to_string_lossy()
                .to_string();

            records.push(BackupRecord {
                relative_target_path,
                original_sha256: sha256,
                backup_file_name,
            });
        }

        let manifest = BackupManifest {
            backup_id,
            created_at: Utc::now().to_rfc3339(),
            root_dir: root.to_string_lossy().to_string(),
            records,
        };

        let manifest_path = backup_dir.join("manifest.json");
        let manifest_json = serde_json::to_string_pretty(&manifest)?;
        fs::write(manifest_path, manifest_json)?;

        Ok(manifest)
    }

    /// Lists all backup manifests available in `.aegis/backups/`.
    pub fn list_backups(root: &Path) -> Vec<BackupManifest> {
        let mut list = Vec::new();
        let backups_dir = root.join(".aegis").join("backups");
        if !backups_dir.exists() {
            return list;
        }

        if let Ok(entries) = fs::read_dir(&backups_dir) {
            for entry in entries.flatten() {
                let manifest_path = entry.path().join("manifest.json");
                if manifest_path.exists() {
                    if let Ok(content) = fs::read_to_string(&manifest_path) {
                        if let Ok(manifest) = serde_json::from_str::<BackupManifest>(&content) {
                            list.push(manifest);
                        }
                    }
                }
            }
        }

        list.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        list
    }
}
