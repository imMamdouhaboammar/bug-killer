use crate::advisory::provider::AdvisoryRecord;
use crate::engine::protocol::{
    CoverageReceiptStatus, CoverageReceiptV1, ReceiptCounts, ReceiptReasonCode,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvisorySnapshot {
    pub snapshot_sha256: String,
    pub retrieved_at: String,
    pub records: Vec<AdvisoryRecord>,
}

#[derive(Debug, Clone)]
pub struct AdvisoryCache {
    pub snapshot: AdvisorySnapshot,
}

impl AdvisoryCache {
    pub fn new(snapshot: AdvisorySnapshot) -> Self {
        Self { snapshot }
    }

    pub fn from_records(records: Vec<AdvisoryRecord>, retrieved_at: String) -> Self {
        let serialized = serde_json::to_vec(&records).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(&serialized);
        let digest = format!("{:x}", hasher.finalize());

        Self {
            snapshot: AdvisorySnapshot {
                snapshot_sha256: digest,
                retrieved_at,
                records,
            },
        }
    }

    pub fn snapshot(&self) -> &AdvisorySnapshot {
        &self.snapshot
    }

    pub fn is_stale(&self, ttl_seconds: u64) -> bool {
        self.is_stale_at(ttl_seconds, Utc::now())
    }

    pub fn is_stale_at(&self, ttl_seconds: u64, now: DateTime<Utc>) -> bool {
        let Ok(retrieved) = DateTime::parse_from_rfc3339(&self.snapshot.retrieved_at) else {
            // Cannot parse timestamp safely; surface stale condition without crashing
            return true;
        };

        let elapsed = now.signed_duration_since(retrieved.with_timezone(&Utc));
        if elapsed.num_seconds() < 0 {
            return false;
        }

        elapsed.num_seconds() > ttl_seconds as i64
    }

    pub fn generate_receipt(
        &self,
        run_id: &str,
        check_id: &str,
        target_id: &str,
        ttl_seconds: u64,
    ) -> CoverageReceiptV1 {
        let stale = self.is_stale(ttl_seconds);
        let now_str = Utc::now().to_rfc3339();

        let (status, reason_codes, details) = if stale {
            (
                CoverageReceiptStatus::Partial,
                vec![ReceiptReasonCode::Other],
                vec![format!(
                    "Advisory feed snapshot age exceeds TTL ({}s)",
                    ttl_seconds
                )],
            )
        } else {
            (
                CoverageReceiptStatus::Evaluated,
                vec![],
                vec!["Advisory feed snapshot is fresh and valid".to_string()],
            )
        };

        CoverageReceiptV1 {
            schema_version: "1.0".to_string(),
            receipt_id: format!(
                "receipt-advisory-cache-{}",
                &self.snapshot.snapshot_sha256[..12]
            ),
            run_id: run_id.to_string(),
            engine_id: "advisory-cache".to_string(),
            engine_version: "1.0.0".to_string(),
            check_id: check_id.to_string(),
            target_id: target_id.to_string(),
            snapshot_sha256: self.snapshot.snapshot_sha256.clone(),
            status,
            counts: ReceiptCounts {
                items_discovered: self.snapshot.records.len() as u64,
                items_examined: self.snapshot.records.len() as u64,
                items_excluded: 0,
                items_skipped: 0,
            },
            reason_codes,
            details,
            started_at: self.snapshot.retrieved_at.clone(),
            completed_at: now_str,
            required_by_policy: Some(true),
            artifact_digests: vec![self.snapshot.snapshot_sha256.clone()],
            previous_receipt_id: None,
        }
    }
}
