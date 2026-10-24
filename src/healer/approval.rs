use crate::healer::AutopilotHealer;
use crate::healer::rollback::RollbackManager;
use crate::identity::AgentIdentity;
use crate::scanner::FleetScanner;
use crate::types::*;
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalReceipt {
    pub plan_id: String,
    pub plan_checksum: String,
    pub approver: String,
    pub timestamp: String,
    pub valid_until: String,
    pub signature: String,
}

pub struct ApprovalManager;

impl ApprovalManager {
    /// Computes a deterministic SHA-256 checksum over the proposed patch actions.
    pub fn compute_plan_checksum(actions: &[PatchAction]) -> String {
        let mut hasher = Sha256::new();
        for action in actions {
            hasher.update(action.target_file.to_string_lossy().as_bytes());
            hasher.update(action.original_checksum.as_bytes());
            hasher.update(action.replacement_content.as_bytes());
        }
        format!("{:x}", hasher.finalize())
    }

    /// Issues an operator approval receipt cryptographically signed with the root identity key.
    pub fn create_approval_receipt(
        root: &Path,
        plan_id: &str,
        plan_checksum: &str,
        approver: &str,
        validity_mins: i64,
    ) -> Result<ApprovalReceipt, String> {
        let identity = AgentIdentity::get_or_create(root)
            .map_err(|e| format!("Failed to access agent identity key: {}", e))?;

        let now = Utc::now();
        let expiry = now + Duration::minutes(validity_mins);
        let timestamp = now.to_rfc3339();
        let valid_until = expiry.to_rfc3339();

        let payload = format!("{}:{}:{}:{}", plan_id, plan_checksum, approver, valid_until);
        let signature = identity.sign_bytes(payload.as_bytes());

        Ok(ApprovalReceipt {
            plan_id: plan_id.to_string(),
            plan_checksum: plan_checksum.to_string(),
            approver: approver.to_string(),
            timestamp,
            valid_until,
            signature,
        })
    }

    /// Verifies that an approval receipt is structurally and cryptographically valid.
    pub fn verify_approval_receipt(
        root: &Path,
        receipt: &ApprovalReceipt,
        current_plan_checksum: &str,
    ) -> Result<(), String> {
        // 1. Check plan integrity
        if receipt.plan_checksum != current_plan_checksum {
            return Err(format!(
                "Integrity Mismatch: Approved plan checksum ({}) does not match current plan checksum ({})",
                receipt.plan_checksum, current_plan_checksum
            ));
        }

        // 2. Check expiration
        let expiry = chrono::DateTime::parse_from_rfc3339(&receipt.valid_until)
            .map_err(|e| format!("Invalid receipt timestamp format: {}", e))?;
        if Utc::now() > expiry {
            return Err(format!(
                "Approval Expired: Receipt expired at {} (current time: {})",
                receipt.valid_until,
                Utc::now().to_rfc3339()
            ));
        }

        // 3. Cryptographically verify signature using agent identity
        let identity = AgentIdentity::get_or_create(root)
            .map_err(|e| format!("Failed to access agent identity key: {}", e))?;

        let payload = format!(
            "{}:{}:{}:{}",
            receipt.plan_id, receipt.plan_checksum, receipt.approver, receipt.valid_until
        );

        identity
            .verify_bytes(payload.as_bytes(), &receipt.signature)
            .map_err(|e| format!("Cryptographic Verification Failed: {}", e))?;

        Ok(())
    }

    /// Executes graduated L4 healing gated by operator approval receipt, with automatic post-execution verification.
    pub fn execute_supervised_healing(
        root: &Path,
        receipt: &ApprovalReceipt,
        actions: &[PatchAction],
    ) -> Result<(BackupManifest, usize), String> {
        let current_checksum = Self::compute_plan_checksum(actions);
        Self::verify_approval_receipt(root, receipt, &current_checksum)?;

        // 1. Execute atomic multi-file healing
        let (manifest, applied_count) = AutopilotHealer::execute_healing(root, actions)?;

        // 2. Post-execution verification pass
        let post_scan = FleetScanner::scan_directory(root, false);
        let unresolved_risks = post_scan
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Critical || f.severity == Severity::High)
            .count();

        // If post-verification reveals failure or unreadable files, automatically rollback
        if unresolved_risks > 0 || !post_scan.coverage.parser_failures.is_empty() {
            let rollback_res = RollbackManager::rollback(root, &manifest.backup_id);
            return Err(format!(
                "Post-execution validation failed: {} unresolved critical/high findings or parser failures detected. Automatic rollback triggered (result: {:?}).",
                unresolved_risks, rollback_res
            ));
        }

        Ok((manifest, applied_count))
    }

    /// Saves receipt to standard approval directory (.bug-killer/approvals/<plan_id>.receipt.json)
    pub fn save_receipt(root: &Path, receipt: &ApprovalReceipt) -> Result<PathBuf, String> {
        let approval_dir = root.join(".bug-killer").join("approvals");
        fs::create_dir_all(&approval_dir)
            .map_err(|e| format!("Failed to create approval directory: {}", e))?;

        let receipt_path = approval_dir.join(format!("{}.receipt.json", receipt.plan_id));
        let serialized = serde_json::to_string_pretty(receipt)
            .map_err(|e| format!("Failed to serialize approval receipt: {}", e))?;

        fs::write(&receipt_path, serialized)
            .map_err(|e| format!("Failed to save approval receipt: {}", e))?;

        Ok(receipt_path)
    }

    /// Loads receipt from file
    pub fn load_receipt(path: &Path) -> Result<ApprovalReceipt, String> {
        let content = fs::read_to_string(path)
            .map_err(|e| format!("Failed to read approval receipt from {:?}: {}", path, e))?;
        serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse approval receipt JSON: {}", e))
    }
}
