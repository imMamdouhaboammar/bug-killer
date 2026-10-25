use crate::healer::AutopilotHealer;
use crate::healer::rollback::RollbackManager;
use crate::identity::{AgentIdentity, OperatorIdentity};
use crate::scanner::FleetScanner;
use crate::types::*;
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalReceipt {
    pub plan_id: String,
    pub plan_checksum: String,
    #[serde(default)]
    pub canonical_root: String,
    pub approver: String,
    #[serde(default)]
    pub action_risk: String,
    pub timestamp: String,
    pub valid_until: String,
    #[serde(default)]
    pub nonce: String,
    #[serde(default)]
    pub operator_public_key: Option<String>,
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

    /// Computes canonical workspace root path string.
    pub fn canonical_root(root: &Path) -> String {
        root.canonicalize()
            .unwrap_or_else(|_| root.to_path_buf())
            .to_string_lossy()
            .to_string()
    }

    /// Generates a cryptographically secure 16-byte random hex nonce.
    pub fn generate_nonce() -> String {
        use rand::RngCore;
        let mut bytes = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// Formats canonical signature payload binding plan, workspace root, action risk, expiry, and nonce.
    pub fn compute_receipt_payload(
        plan_id: &str,
        plan_checksum: &str,
        canonical_root: &str,
        approver: &str,
        action_risk: &str,
        valid_until: &str,
        nonce: &str,
    ) -> String {
        format!(
            "{}:{}:{}:{}:{}:{}:{}",
            plan_id, plan_checksum, canonical_root, approver, action_risk, valid_until, nonce
        )
    }

    fn used_nonces_path(root: &Path) -> PathBuf {
        root.join(".bug-killer")
            .join("approvals")
            .join("used_nonces.json")
    }

    /// Checks if a nonce has already been consumed in this workspace.
    pub fn is_nonce_used(root: &Path, nonce: &str) -> Result<bool, String> {
        let path = Self::used_nonces_path(root);
        // Preserve previously consumed receipts from the legacy ledger. A damaged
        // ledger is not evidence that a receipt is fresh.
        if path.exists() {
            let content = fs::read_to_string(&path)
                .map_err(|e| format!("Failed to read nonce ledger: {e}"))?;
            let nonces: std::collections::HashSet<String> =
                serde_json::from_str(&content).map_err(|e| format!("Corrupt nonce ledger: {e}"))?;
            if nonces.contains(nonce) {
                return Ok(true);
            }
        }
        let marker = Self::nonce_marker_path(root, nonce);
        match fs::metadata(marker) {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(format!("Cannot inspect nonce state: {e}")),
        }
    }

    fn nonce_marker_path(root: &Path, nonce: &str) -> PathBuf {
        let digest = format!("{:x}", Sha256::digest(nonce.as_bytes()));
        root.join(".bug-killer")
            .join("approvals")
            .join("used_nonces")
            .join(digest)
    }

    /// Records a consumed nonce to prevent replay attacks.
    pub fn record_used_nonce(root: &Path, nonce: &str) -> Result<(), String> {
        if nonce.is_empty() {
            return Err("Approval nonce is required".into());
        }
        if Self::is_nonce_used(root, nonce)? {
            return Err("Receipt Replay Detected: nonce already consumed".into());
        }
        let marker = Self::nonce_marker_path(root, nonce);
        let parent = marker.parent().expect("nonce marker always has parent");
        fs::create_dir_all(parent).map_err(|e| format!("Cannot create nonce store: {e}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
                .map_err(|e| format!("Cannot protect nonce store: {e}"))?;
        }
        // O_EXCL-style publication is the consumption point. Only one of two
        // concurrent executions may create the marker.
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(marker)
            .map_err(|e| format!("Cannot atomically consume approval nonce: {e}"))?;
        file.write_all(b"consumed\n")
            .and_then(|_| file.sync_all())
            .map_err(|e| format!("Cannot durably consume approval nonce: {e}"))?;
        Ok(())
    }

    /// Issues an operator approval receipt cryptographically signed with distinct operator authority.
    pub fn create_approval_receipt(
        root: &Path,
        plan_id: &str,
        plan_checksum: &str,
        approver: &str,
        validity_mins: i64,
    ) -> Result<ApprovalReceipt, String> {
        let operator = OperatorIdentity::get_or_create(root)
            .map_err(|e| format!("Failed to access operator identity key: {}", e))?;
        Self::create_approval_receipt_with_operator(
            &operator,
            root,
            plan_id,
            plan_checksum,
            approver,
            validity_mins,
            "PrivilegedRemediation",
        )
    }

    /// Issues an operator approval receipt using explicit OperatorIdentity.
    pub fn create_approval_receipt_with_operator(
        operator: &OperatorIdentity,
        root: &Path,
        plan_id: &str,
        plan_checksum: &str,
        approver: &str,
        validity_mins: i64,
        action_risk: &str,
    ) -> Result<ApprovalReceipt, String> {
        let now = Utc::now();
        let expiry = now + Duration::minutes(validity_mins);
        let timestamp = now.to_rfc3339();
        let valid_until = expiry.to_rfc3339();
        let canonical_root = Self::canonical_root(root);
        let nonce = Self::generate_nonce();

        let payload = Self::compute_receipt_payload(
            plan_id,
            plan_checksum,
            &canonical_root,
            approver,
            action_risk,
            &valid_until,
            &nonce,
        );
        let signature = operator.sign_bytes(payload.as_bytes());

        Ok(ApprovalReceipt {
            plan_id: plan_id.to_string(),
            plan_checksum: plan_checksum.to_string(),
            canonical_root,
            approver: approver.to_string(),
            action_risk: action_risk.to_string(),
            timestamp,
            valid_until,
            nonce,
            operator_public_key: Some(operator.public_key_hex()),
            signature,
        })
    }

    /// Verifies that an approval receipt is structurally and cryptographically valid under operator authority.
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

        // 3. Workspace root binding check
        let expected_canonical_root = Self::canonical_root(root);
        if !receipt.canonical_root.is_empty() && receipt.canonical_root != expected_canonical_root {
            return Err(format!(
                "Workspace Root Mismatch: Receipt bound to root '{}', but verifying in '{}'",
                receipt.canonical_root, expected_canonical_root
            ));
        }

        // 4. Replay prevention check
        if receipt.nonce.is_empty() {
            return Err("Approval receipt is missing mandatory replay nonce".into());
        }
        if Self::is_nonce_used(root, &receipt.nonce)? {
            return Err(format!(
                "Receipt Replay Detected: nonce '{}' has already been used",
                receipt.nonce
            ));
        }

        // 5. Reject privilege escalation: signature minted by scanner agent identity without operator authority
        if let Ok(agent_id) = AgentIdentity::get_or_create(root) {
            if let Some(ref op_pub) = receipt.operator_public_key {
                if op_pub == &agent_id.public_key_hex() {
                    return Err(
                        "Privilege Escalation Rejected: Approval receipt was signed with scanner agent identity, not operator authority".to_string()
                    );
                }
            }
        }

        // 6. Cryptographically verify signature using operator authority
        let operator = OperatorIdentity::get_or_create(root)
            .map_err(|e| format!("Failed to access operator identity key: {}", e))?;

        let bound_payload = Self::compute_receipt_payload(
            &receipt.plan_id,
            &receipt.plan_checksum,
            &receipt.canonical_root,
            &receipt.approver,
            &receipt.action_risk,
            &receipt.valid_until,
            &receipt.nonce,
        );

        let verify_result = operator.verify_bytes(bound_payload.as_bytes(), &receipt.signature);
        if let Err(err) = verify_result {
            // Check legacy 4-tuple format for backwards compatibility if operator signed it
            let legacy_payload = format!(
                "{}:{}:{}:{}",
                receipt.plan_id, receipt.plan_checksum, receipt.approver, receipt.valid_until
            );
            if operator
                .verify_bytes(legacy_payload.as_bytes(), &receipt.signature)
                .is_err()
            {
                return Err(format!("Cryptographic Verification Failed: {}", err));
            }
        }

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

        // Record nonce to prevent replay
        Self::record_used_nonce(root, &receipt.nonce)?;

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
