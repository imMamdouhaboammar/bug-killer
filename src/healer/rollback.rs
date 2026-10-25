use crate::types::*;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

pub struct RollbackManager;

impl RollbackManager {
    /// Reverts all changes recorded in a specified backup ID after cryptographic verification.
    pub fn rollback(root: &Path, backup_id: &str) -> Result<usize, String> {
        Self::rollback_with_force(root, backup_id, false)
    }

    /// Reverts all changes with an option to bypass post-heal drift detection.
    #[allow(dead_code)]
    pub fn rollback_force(root: &Path, backup_id: &str) -> Result<usize, String> {
        Self::rollback_with_force(root, backup_id, true)
    }

    /// Reverts all changes recorded in a specified backup ID after cryptographic verification,
    /// with file permission preservation, drift detection, and honest partial failure reporting.
    pub fn rollback_with_force(root: &Path, backup_id: &str, force: bool) -> Result<usize, String> {
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

        let canonical_root = root
            .canonicalize()
            .map_err(|e| format!("Failed to resolve workspace root: {e}"))?;

        // Verified record tuple: (target_path, backup_content, original_mode)
        let mut verified_records: Vec<(PathBuf, Vec<u8>, Option<u32>)> =
            Vec::with_capacity(manifest.records.len());

        // Preflight every signed record before mutating any target.
        for record in &manifest.records {
            let backup_name = Path::new(&record.backup_file_name);
            if backup_name.components().count() != 1
                || !matches!(
                    backup_name.components().next(),
                    Some(std::path::Component::Normal(_))
                )
            {
                return Err("Invalid backup archive filename".to_string());
            }
            let backup_file = backup_dir.join(&record.backup_file_name);
            if !backup_file.exists() {
                return Err(format!("Backup archive file {:?} is missing", backup_file));
            }

            let backup_content = fs::read(&backup_file)
                .map_err(|e| format!("Failed to read backup payload {:?}: {}", backup_file, e))?;
            let backup_sha256 = format!("{:x}", Sha256::digest(&backup_content));

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

            let target_file = canonical_root.join(rel_path);

            // Verify no symlink traversal in components
            let mut curr = canonical_root.clone();
            for comp in rel_path.components() {
                if let std::path::Component::Normal(part) = comp {
                    curr.push(part);
                    if let Ok(meta) = fs::symlink_metadata(&curr) {
                        if meta.file_type().is_symlink() {
                            return Err(format!(
                                "Restore target path contains symlink: {:?}",
                                curr
                            ));
                        }
                    }
                }
            }

            let parent = target_file.parent().unwrap_or(&canonical_root);
            let canonical_parent = parent
                .canonicalize()
                .map_err(|e| format!("Restore target parent is unavailable: {e}"))?;
            if !canonical_parent.starts_with(&canonical_root)
                || fs::symlink_metadata(&target_file)
                    .is_ok_and(|metadata| metadata.file_type().is_symlink())
            {
                return Err(format!(
                    "Restore target escapes workspace or is a symlink: {:?}",
                    target_file
                ));
            }

            // Detect drift: if a file has been modified since the heal action
            // (i.e. current content doesn't match expected post-heal content or original backup),
            // reject overwriting without explicit force.
            if !force && target_file.exists() {
                let current_content = fs::read(&target_file).map_err(|e| {
                    format!(
                        "Failed to read target file {:?} for drift detection: {}",
                        target_file, e
                    )
                })?;
                let current_sha256 = format!("{:x}", Sha256::digest(&current_content));

                // If it already matches original_sha256, no drift conflict
                if current_sha256 != record.original_sha256 {
                    if let Some(ref expected_post) = record.post_heal_sha256 {
                        if &current_sha256 != expected_post {
                            return Err(format!(
                                "Post-heal drift detected in {:?}: current hash {} matches neither expected post-heal hash {} nor original backup {}. Refusing to overwrite without explicit force.",
                                target_file, current_sha256, expected_post, record.original_sha256
                            ));
                        }
                    }
                }
            }

            verified_records.push((target_file, backup_content, record.mode));
        }

        let all_targets: Vec<PathBuf> =
            verified_records.iter().map(|(t, _, _)| t.clone()).collect();
        let mut restored_files: Vec<PathBuf> = Vec::new();

        for (idx, (target_file, backup_content, original_mode)) in
            verified_records.into_iter().enumerate()
        {
            let parent = target_file.parent().unwrap_or(root);
            let restore_res = (|| -> Result<(), String> {
                let mut temp = tempfile::NamedTempFile::new_in(parent).map_err(|e| {
                    format!("Failed to create temporary file in {:?}: {}", parent, e)
                })?;

                use std::io::Write;
                temp.write_all(&backup_content)
                    .map_err(|e| format!("Failed to write restoration payload: {}", e))?;

                #[cfg(unix)]
                if let Some(mode) = original_mode {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = temp
                        .as_file_mut()
                        .set_permissions(fs::Permissions::from_mode(mode));
                }

                temp.persist(&target_file).map_err(|e| {
                    format!("Failed to atomically restore {:?}: {}", target_file, e)
                })?;

                #[cfg(unix)]
                if let Some(mode) = original_mode {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = fs::set_permissions(&target_file, fs::Permissions::from_mode(mode));
                }

                Ok(())
            })();

            match restore_res {
                Ok(()) => {
                    restored_files.push(target_file);
                }
                Err(err) => {
                    let mut unrestored_files = vec![target_file];
                    for remaining in &all_targets[idx + 1..] {
                        unrestored_files.push(remaining.clone());
                    }

                    if restored_files.is_empty() {
                        return Err(format!(
                            "ROLLBACK_FAILED: failed to restore {:?}: {}. Restored files: []; Un-restored files: {:?}",
                            unrestored_files[0], err, unrestored_files
                        ));
                    } else {
                        return Err(format!(
                            "PARTIALLY_RESTORED: failed to restore {:?}: {}. Restored files: {:?}; Un-restored files: {:?}",
                            unrestored_files[0], err, restored_files, unrestored_files
                        ));
                    }
                }
            }
        }

        Ok(restored_files.len())
    }
}
