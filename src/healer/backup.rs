use crate::types::*;
use chrono::Utc;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

pub struct BackupManager;

impl BackupManager {
    /// Computes the SHA256 checksum of a file.
    pub fn compute_sha256(path: &Path) -> std::io::Result<String> {
        let bytes = fs::read(path)?;
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        Ok(crate::to_hex(hasher.finalize()))
    }

    /// Generates a collision-proof unique backup ID.
    pub fn generate_backup_id() -> String {
        let mut nonce = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut nonce);
        let nonce_hex: String = nonce.iter().map(|b| format!("{:02x}", b)).collect();
        format!("{}_{}", Utc::now().format("%Y%m%d_%H%M%S"), nonce_hex)
    }

    /// Creates an atomic backup of target files before modifying them.
    #[allow(dead_code)] // Retained for consumers restoring pre-existing snapshots in integration tests.
    pub fn create_backup(root: &Path, files: &[PathBuf]) -> std::io::Result<BackupManifest> {
        Self::create_backup_with_post_heals(root, files, &[])
    }

    /// Creates an atomic backup for a patch action list with expected post-heal content hashes.
    pub fn create_backup_for_actions(
        root: &Path,
        actions: &[PatchAction],
    ) -> std::io::Result<BackupManifest> {
        let files: Vec<PathBuf> = actions.iter().map(|a| a.target_file.clone()).collect();
        let post_heals: Vec<(PathBuf, String)> = actions
            .iter()
            .map(|a| {
                let mut hasher = Sha256::new();
                hasher.update(a.replacement_content.as_bytes());
                (a.target_file.clone(), crate::to_hex(hasher.finalize()))
            })
            .collect();
        Self::create_backup_with_post_heals(root, &files, &post_heals)
    }

    fn create_backup_with_post_heals(
        root: &Path,
        files: &[PathBuf],
        post_heals: &[(PathBuf, String)],
    ) -> std::io::Result<BackupManifest> {
        let backup_id = Self::generate_backup_id();
        let backups_dir = root.join(".aegis").join("backups");
        fs::create_dir_all(&backups_dir)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&backups_dir, fs::Permissions::from_mode(0o700));
        }

        // Private temporary staging directory (0700)
        let staging_dir = tempfile::Builder::new()
            .prefix(".staging_")
            .tempdir_in(&backups_dir)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(staging_dir.path(), fs::Permissions::from_mode(0o700));
        }

        let mut records = Vec::new();

        for (idx, file) in files.iter().enumerate() {
            if !file.exists() {
                continue;
            }

            let sha256 = Self::compute_sha256(file)?;

            #[cfg(unix)]
            let mode = {
                use std::os::unix::fs::PermissionsExt;
                fs::metadata(file).map(|m| m.permissions().mode()).ok()
            };
            #[cfg(not(unix))]
            let mode = None;

            let post_heal_sha256 = post_heals
                .iter()
                .find(|(p, _)| p == file)
                .map(|(_, s)| s.clone());

            let backup_file_name = format!(
                "{}_{}",
                idx,
                file.file_name().unwrap_or_default().to_string_lossy()
            );
            let staging_file_path = staging_dir.path().join(&backup_file_name);

            fs::copy(file, &staging_file_path)?;

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&staging_file_path, fs::Permissions::from_mode(0o600));
            }

            let relative_target_path = file
                .strip_prefix(root)
                .unwrap_or(file)
                .to_string_lossy()
                .to_string();

            records.push(BackupRecord {
                relative_target_path,
                original_sha256: sha256,
                backup_file_name,
                mode,
                post_heal_sha256,
            });
        }

        let mut manifest = BackupManifest {
            backup_id: backup_id.clone(),
            created_at: Utc::now().to_rfc3339(),
            root_dir: root.to_string_lossy().to_string(),
            records,
            signer_public_key: None,
            signature: None,
        };

        // Cryptographically sign the manifest via AgentIdentity (fail-closed)
        let identity = crate::identity::AgentIdentity::get_or_create(root).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("Failed to initialize agent identity for signing: {}", e),
            )
        })?;
        identity.sign_manifest(&mut manifest);

        let manifest_path = staging_dir.path().join("manifest.json");
        let manifest_json = serde_json::to_string_pretty(&manifest)?;
        fs::write(&manifest_path, manifest_json)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&manifest_path, fs::Permissions::from_mode(0o600));
        }

        // Atomically publish staging directory to .aegis/backups/<backup_id>
        let final_backup_dir = backups_dir.join(&backup_id);
        let staging_path = staging_dir.path().to_path_buf();

        if final_backup_dir.exists() {
            let _ = staging_dir.close();
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!(
                    "Backup snapshot directory {:?} already exists; refusing to overwrite",
                    final_backup_dir
                ),
            ));
        }

        if let Err(e) = fs::rename(&staging_path, &final_backup_dir) {
            let _ = staging_dir.close();
            return Err(e);
        }

        let _ = staging_dir.keep();

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
                if entry.file_name().to_string_lossy().starts_with('.') {
                    continue;
                }
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
