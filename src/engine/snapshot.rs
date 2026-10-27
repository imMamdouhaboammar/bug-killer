use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;
use walkdir::WalkDir;

use crate::engine::scope::{ResearchScope, ScopeError};
use crate::identity::to_hex;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InventoryStatus {
    Complete,
    Partial,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotFileEntry {
    pub relative_path: String,
    pub size_bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotInventory {
    pub total_files: usize,
    pub hashed_files: usize,
    pub unreadable_files: Vec<String>,
    pub skipped_files: Vec<String>,
    pub status: InventoryStatus,
}

/// Represents an immutable, content-pinned snapshot of an authorized research target directory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetSnapshot {
    pub target_root: PathBuf,
    pub snapshot_sha256: String,
    pub tool_binary_sha256: String,
    pub tool_version: String,
    pub inventory: SnapshotInventory,
    pub files: Vec<SnapshotFileEntry>,
    pub created_at: String,
}

impl TargetSnapshot {
    /// Captures a target snapshot requiring 100% complete file inventory; fails closed on any unreadable file.
    pub fn create(scope: &ResearchScope) -> Result<Self, ScopeError> {
        Self::create_internal(scope, false)
    }

    /// Captures a target snapshot allowing partial inventory when unreadable files are encountered,
    /// marking the inventory status explicitly as `InventoryStatus::Partial`.
    pub fn create_allow_partial(scope: &ResearchScope) -> Result<Self, ScopeError> {
        Self::create_internal(scope, true)
    }

    fn create_internal(scope: &ResearchScope, allow_partial: bool) -> Result<Self, ScopeError> {
        scope.validate()?;

        let mut files = Vec::new();
        let mut unreadable_files = Vec::new();
        let mut skipped_files = Vec::new();
        let mut total_files = 0;

        for entry in WalkDir::new(&scope.target_root)
            .follow_links(false)
            .into_iter()
            .filter_entry(|e| {
                let path = e.path();
                // Exclude dot-git and excluded paths early from traversal
                !scope.excluded_subpaths.iter().any(|ex| path == ex)
            })
        {
            let dir_entry = match entry {
                Ok(e) => e,
                Err(err) => {
                    let err_path = err
                        .path()
                        .unwrap_or(&scope.target_root)
                        .to_string_lossy()
                        .to_string();
                    if allow_partial {
                        unreadable_files.push(err_path);
                        continue;
                    } else {
                        return Err(ScopeError::IoError {
                            path: err.path().unwrap_or(&scope.target_root).to_path_buf(),
                            message: err.to_string(),
                        });
                    }
                }
            };

            let path = dir_entry.path();
            if path == scope.target_root {
                continue;
            }

            // Check symlinks for outside-root escape
            if dir_entry.path_is_symlink() {
                match scope.is_path_in_scope(path) {
                    Ok(_) => {}
                    Err(err @ ScopeError::SymlinkEscape { .. }) => {
                        return Err(err);
                    }
                    Err(err) => {
                        if allow_partial {
                            unreadable_files.push(path.to_string_lossy().to_string());
                            continue;
                        } else {
                            return Err(err);
                        }
                    }
                }
            }

            if !path.is_file() {
                continue;
            }

            total_files += 1;

            // Check if within allowed subpaths if configured
            if !scope.allowed_subpaths.is_empty() {
                let canonical = match fs::canonicalize(path) {
                    Ok(c) => c,
                    Err(e) => {
                        if allow_partial {
                            unreadable_files.push(path.to_string_lossy().to_string());
                            continue;
                        } else {
                            return Err(ScopeError::IoError {
                                path: path.to_path_buf(),
                                message: e.to_string(),
                            });
                        }
                    }
                };

                let within_allowed = scope
                    .allowed_subpaths
                    .iter()
                    .any(|allowed| canonical.starts_with(allowed));
                if !within_allowed {
                    skipped_files.push(path.to_string_lossy().to_string());
                    continue;
                }
            }

            // Read file bytes
            match fs::read(path) {
                Ok(bytes) => {
                    let mut file_hasher = Sha256::new();
                    file_hasher.update(&bytes);
                    let file_sha256 = to_hex(file_hasher.finalize());

                    let relative_path = path
                        .strip_prefix(&scope.target_root)
                        .map(|p| p.to_string_lossy().to_string())
                        .unwrap_or_else(|_| path.to_string_lossy().to_string());

                    files.push(SnapshotFileEntry {
                        relative_path,
                        size_bytes: bytes.len() as u64,
                        sha256: file_sha256,
                    });
                }
                Err(err) => {
                    let path_str = path.to_string_lossy().to_string();
                    if allow_partial {
                        unreadable_files.push(path_str);
                    } else {
                        return Err(ScopeError::IoError {
                            path: path.to_path_buf(),
                            message: err.to_string(),
                        });
                    }
                }
            }
        }

        // Deterministic lexicographical ordering by relative_path
        files.sort_by(|a, b| a.relative_path.cmp(&b.relative_path));

        // Compute composite snapshot SHA-256
        let mut composite_hasher = Sha256::new();
        for f in &files {
            composite_hasher.update(f.relative_path.as_bytes());
            composite_hasher.update(b":");
            composite_hasher.update(f.size_bytes.to_be_bytes());
            composite_hasher.update(b":");
            composite_hasher.update(f.sha256.as_bytes());
            composite_hasher.update(b"\n");
        }
        let snapshot_sha256 = to_hex(composite_hasher.finalize());

        // Measure and pin current tool binary SHA-256
        let tool_binary_sha256 = Self::measure_tool_binary_sha256();
        let tool_version = env!("CARGO_PKG_VERSION").to_string();

        let status = if unreadable_files.is_empty() {
            InventoryStatus::Complete
        } else {
            InventoryStatus::Partial
        };

        let inventory = SnapshotInventory {
            total_files,
            hashed_files: files.len(),
            unreadable_files,
            skipped_files,
            status,
        };

        Ok(Self {
            target_root: scope.target_root.clone(),
            snapshot_sha256,
            tool_binary_sha256,
            tool_version,
            inventory,
            files,
            created_at: Utc::now().to_rfc3339(),
        })
    }

    fn measure_tool_binary_sha256() -> String {
        if let Ok(exe_path) = std::env::current_exe() {
            if let Ok(bytes) = fs::read(exe_path) {
                let mut hasher = Sha256::new();
                hasher.update(&bytes);
                return to_hex(hasher.finalize());
            }
        }

        // Fallback deterministic digest based on package metadata
        let mut hasher = Sha256::new();
        hasher.update(env!("CARGO_PKG_NAME").as_bytes());
        hasher.update(env!("CARGO_PKG_VERSION").as_bytes());
        to_hex(hasher.finalize())
    }
}
