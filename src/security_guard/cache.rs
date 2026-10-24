#![allow(dead_code)]

use crate::types::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedFileEntry {
    pub sha256: String,
    pub findings: Vec<Finding>,
    pub checked_at: String,
    pub rules_version: String,
    pub detector_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardCache {
    pub version: String,
    pub entries: HashMap<String, CachedFileEntry>,
}

impl Default for GuardCache {
    fn default() -> Self {
        Self {
            version: "1.0".to_string(),
            entries: HashMap::new(),
        }
    }
}

pub struct CacheEngine;

impl CacheEngine {
    pub fn cache_path(root: &Path) -> PathBuf {
        root.join(".bugkiller").join("cache.json")
    }

    /// Computes SHA-256 of string content.
    pub fn compute_sha256(content: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    /// Loads cache from `.bugkiller/cache.json`, returning empty cache if missing or invalid.
    pub fn load_cache(root: &Path) -> GuardCache {
        let path = Self::cache_path(root);
        if let Ok(data) = fs::read_to_string(&path) {
            if let Ok(cache) = serde_json::from_str(&data) {
                return cache;
            }
        }
        GuardCache::default()
    }

    /// Saves cache to `.bugkiller/cache.json`.
    pub fn save_cache(root: &Path, cache: &GuardCache) -> Result<(), String> {
        let path = Self::cache_path(root);
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let data = serde_json::to_string_pretty(cache)
            .map_err(|e| format!("Failed to serialize cache: {}", e))?;
        fs::write(&path, data).map_err(|e| format!("Failed to write cache.json: {}", e))?;
        Ok(())
    }

    /// Checks if a file has a valid, non-stale cache entry matching current content hash.
    pub fn get_cached(
        cache: &GuardCache,
        rel_path: &str,
        content: &str,
        current_rules_version: &str,
    ) -> Option<Vec<Finding>> {
        let entry = cache.entries.get(rel_path)?;
        let current_hash = Self::compute_sha256(content);
        if entry.sha256 == current_hash && entry.rules_version == current_rules_version {
            Some(entry.findings.clone())
        } else {
            None
        }
    }

    /// Updates cache entry for a file.
    pub fn update_entry(
        cache: &mut GuardCache,
        rel_path: &str,
        content: &str,
        findings: &[Finding],
        rules_version: &str,
    ) {
        let sha256 = Self::compute_sha256(content);
        let entry = CachedFileEntry {
            sha256,
            findings: findings.to_vec(),
            checked_at: chrono::Utc::now().to_rfc3339(),
            rules_version: rules_version.to_string(),
            detector_version: env!("CARGO_PKG_VERSION").to_string(),
        };
        cache.entries.insert(rel_path.to_string(), entry);
    }
}
