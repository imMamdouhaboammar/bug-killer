use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use serde::{Deserialize, Serialize};

use crate::engine::protocol::{CoverageReceiptV1, DiagnosticV1, FindingV1};

/// Unique cache key for structural analysis results.
/// Combines file source content SHA-256, tree-sitter grammar ID/version, and active rule pack hash.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StructuralCacheKey {
    pub source_sha256: String,
    pub grammar_id: String,
    pub rule_pack_hash: String,
}

impl StructuralCacheKey {
    pub fn new(
        source_sha256: impl Into<String>,
        grammar_id: impl Into<String>,
        rule_pack_hash: impl Into<String>,
    ) -> Self {
        Self {
            source_sha256: source_sha256.into(),
            grammar_id: grammar_id.into(),
            rule_pack_hash: rule_pack_hash.into(),
        }
    }
}

/// Cached result of a structural analysis run for a specific file version.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedAnalysis {
    pub findings: Vec<FindingV1>,
    pub receipts: Vec<CoverageReceiptV1>,
    pub diagnostics: Vec<DiagnosticV1>,
    pub cached_at: String,
}

/// Thread-safe in-memory cache for structural AST scans.
/// Enables instantaneous re-scans of unchanged files and clean invalidation upon mutation.
#[derive(Debug, Clone, Default)]
pub struct StructuralCache {
    entries: Arc<RwLock<HashMap<StructuralCacheKey, CachedAnalysis>>>,
    source_to_keys: Arc<RwLock<HashMap<String, Vec<StructuralCacheKey>>>>,
    hits: Arc<AtomicU64>,
    misses: Arc<AtomicU64>,
}

impl StructuralCache {
    pub fn new() -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
            source_to_keys: Arc::new(RwLock::new(HashMap::new())),
            hits: Arc::new(AtomicU64::new(0)),
            misses: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Retrieves cached findings and receipts if present for the exact key.
    pub fn get(&self, key: &StructuralCacheKey) -> Option<CachedAnalysis> {
        let entries = self.entries.read().ok()?;
        if let Some(cached) = entries.get(key) {
            self.hits.fetch_add(1, Ordering::Relaxed);
            Some(cached.clone())
        } else {
            self.misses.fetch_add(1, Ordering::Relaxed);
            None
        }
    }

    /// Inserts or replaces cached analysis results.
    pub fn insert(&self, key: StructuralCacheKey, result: CachedAnalysis) {
        let source_sha = key.source_sha256.clone();
        if let Ok(mut entries) = self.entries.write() {
            entries.insert(key.clone(), result);
        }
        if let Ok(mut source_map) = self.source_to_keys.write() {
            source_map.entry(source_sha).or_default().push(key);
        }
    }

    /// Invalidates all cached analysis results associated with the given source content SHA-256.
    pub fn invalidate_source(&self, source_sha256: &str) -> usize {
        let keys_to_remove = if let Ok(mut source_map) = self.source_to_keys.write() {
            source_map.remove(source_sha256).unwrap_or_default()
        } else {
            Vec::new()
        };

        let count = keys_to_remove.len();
        if let Ok(mut entries) = self.entries.write() {
            for key in &keys_to_remove {
                entries.remove(key);
            }
        }
        count
    }

    /// Clears all entries and resets metrics.
    pub fn clear(&self) {
        if let Ok(mut entries) = self.entries.write() {
            entries.clear();
        }
        if let Ok(mut source_map) = self.source_to_keys.write() {
            source_map.clear();
        }
        self.hits.store(0, Ordering::Relaxed);
        self.misses.store(0, Ordering::Relaxed);
    }

    pub fn hit_count(&self) -> u64 {
        self.hits.load(Ordering::Relaxed)
    }

    pub fn miss_count(&self) -> u64 {
        self.misses.load(Ordering::Relaxed)
    }

    pub fn len(&self) -> usize {
        self.entries.read().map(|m| m.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_structural_cache_roundtrip_and_invalidation() {
        let cache = StructuralCache::new();
        let key = StructuralCacheKey::new(
            "sha256_file1_v1",
            "tree-sitter-python@0.25.0",
            "rules_hash_abc",
        );

        assert!(cache.get(&key).is_none());
        assert_eq!(cache.miss_count(), 1);
        assert_eq!(cache.hit_count(), 0);

        let cached = CachedAnalysis {
            findings: Vec::new(),
            receipts: Vec::new(),
            diagnostics: Vec::new(),
            cached_at: "2026-10-25T00:00:00Z".to_string(),
        };

        cache.insert(key.clone(), cached);
        assert_eq!(cache.len(), 1);

        let retrieved = cache.get(&key).expect("cache hit");
        assert_eq!(retrieved.cached_at, "2026-10-25T00:00:00Z");
        assert_eq!(cache.hit_count(), 1);

        // Source mutation invalidation
        let removed = cache.invalidate_source("sha256_file1_v1");
        assert_eq!(removed, 1);
        assert_eq!(cache.len(), 0);
        assert!(cache.get(&key).is_none());
        assert_eq!(cache.miss_count(), 2);
    }
}
