use crate::identity::{AgentIdentity, OperatorIdentity};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

/// Cryptographically signed operator approval receipt binding a specific disclosure draft,
/// recipient, workspace root, expiration, and replay-prevention nonce.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisclosureApprovalReceipt {
    pub draft_id: String,
    pub draft_checksum: String,
    pub recipient: String,
    pub canonical_root: String,
    pub approver: String,
    pub timestamp: String,
    pub valid_until: String,
    pub nonce: String,
    pub operator_public_key: String,
    pub signature: String,
}

/// Gatekeeper managing cryptographic authorization receipts for vulnerability disclosure (ADR-008 & ADR-010).
pub struct DisclosureApprovalManager;

impl DisclosureApprovalManager {
    /// Computes deterministic SHA-256 checksum over canonical disclosure draft JSON.
    pub fn compute_draft_checksum(draft_json: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(draft_json.as_bytes());
        crate::to_hex(hasher.finalize())
    }

    /// Resolves canonical path string for workspace root binding.
    pub fn canonical_root(root: &Path) -> String {
        root.canonicalize()
            .unwrap_or_else(|_| root.to_path_buf())
            .to_string_lossy()
            .to_string()
    }

    /// Generates a cryptographically secure 16-byte random hex nonce.
    pub fn generate_nonce() -> String {
        let mut bytes = [0u8; 16];
        rand::fill(&mut bytes);
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// Canonical payload encoding for Ed25519 signature binding all disclosure parameters.
    pub fn compute_receipt_payload(
        draft_id: &str,
        draft_checksum: &str,
        recipient: &str,
        canonical_root: &str,
        approver: &str,
        valid_until: &str,
        nonce: &str,
    ) -> String {
        serde_json::to_string(&(
            draft_id,
            draft_checksum,
            recipient,
            canonical_root,
            approver,
            valid_until,
            nonce,
        ))
        .expect("serializing string tuple cannot fail")
    }

    /// Returns path to consumed disclosure nonces ledger.
    pub fn nonces_path(root: &Path) -> PathBuf {
        root.join(".bug-killer")
            .join("approvals")
            .join("disclosure_nonces.json")
    }

    /// Checks if a nonce has already been consumed in the target workspace.
    pub fn is_nonce_consumed(root: &Path, nonce: &str) -> Result<bool, String> {
        let path = Self::nonces_path(root);
        if !path.exists() {
            return Ok(false);
        }
        let content = fs::read_to_string(&path)
            .map_err(|e| format!("Failed to read disclosure nonces ledger: {e}"))?;
        let nonces: HashSet<String> = serde_json::from_str(&content)
            .map_err(|e| format!("Corrupt disclosure nonces ledger: {e}"))?;
        Ok(nonces.contains(nonce))
    }

    /// Durably marks an approval nonce as consumed to prevent replay attacks.
    pub fn consume_nonce(root: &Path, nonce: &str) -> Result<(), String> {
        if nonce.is_empty() {
            return Err("Approval nonce cannot be empty".into());
        }
        if Self::is_nonce_consumed(root, nonce)? {
            return Err(format!(
                "Nonce replay detected: nonce '{}' already consumed",
                nonce
            ));
        }

        let path = Self::nonces_path(root);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Cannot create approvals directory: {e}"))?;
        }

        let mut nonces: HashSet<String> = if path.exists() {
            let content = fs::read_to_string(&path)
                .map_err(|e| format!("Failed to read disclosure nonces ledger: {e}"))?;
            serde_json::from_str(&content)
                .map_err(|e| format!("Corrupt disclosure nonces ledger: {e}"))?
        } else {
            HashSet::new()
        };

        nonces.insert(nonce.to_string());

        let serialized = serde_json::to_string_pretty(&nonces)
            .map_err(|e| format!("Failed to serialize disclosure nonces: {e}"))?;

        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .map_err(|e| format!("Failed to open disclosure nonces ledger: {e}"))?;

        file.write_all(serialized.as_bytes())
            .and_then(|_| file.sync_all())
            .map_err(|e| format!("Failed to write disclosure nonces ledger: {e}"))?;

        Ok(())
    }

    /// Issues an operator approval receipt cryptographically signed with distinct operator authority.
    pub fn sign_approval(
        operator: &OperatorIdentity,
        draft_id: &str,
        draft_json: &str,
        recipient: &str,
        canonical_root: &Path,
        duration_hours: i64,
    ) -> Result<DisclosureApprovalReceipt, String> {
        let approver = format!("operator:{}", &operator.public_key_hex()[..16]);
        Self::sign_approval_with_approver(
            operator,
            draft_id,
            draft_json,
            recipient,
            canonical_root,
            &approver,
            duration_hours,
        )
    }

    /// Issues an operator approval receipt with an explicitly designated approver identity.
    pub fn sign_approval_with_approver(
        operator: &OperatorIdentity,
        draft_id: &str,
        draft_json: &str,
        recipient: &str,
        canonical_root: &Path,
        approver: &str,
        duration_hours: i64,
    ) -> Result<DisclosureApprovalReceipt, String> {
        let draft_checksum = Self::compute_draft_checksum(draft_json);
        let canonical_root_str = Self::canonical_root(canonical_root);
        let now = Utc::now();
        let timestamp = now.to_rfc3339();
        let valid_until = (now + Duration::hours(duration_hours)).to_rfc3339();
        let nonce = Self::generate_nonce();

        let payload = Self::compute_receipt_payload(
            draft_id,
            &draft_checksum,
            recipient,
            &canonical_root_str,
            approver,
            &valid_until,
            &nonce,
        );
        let signature = operator.sign_bytes(payload.as_bytes());

        Ok(DisclosureApprovalReceipt {
            draft_id: draft_id.to_string(),
            draft_checksum,
            recipient: recipient.to_string(),
            canonical_root: canonical_root_str,
            approver: approver.to_string(),
            timestamp,
            valid_until,
            nonce,
            operator_public_key: operator.public_key_hex(),
            signature,
        })
    }

    /// Verifies that an approval receipt is structurally and cryptographically valid under operator authority.
    /// Fails closed if content, recipient, workspace root, or expiration have changed,
    /// if the nonce was replayed, or if signed with an agent key (ADR-008).
    pub fn verify_approval(
        receipt: &DisclosureApprovalReceipt,
        draft_id: &str,
        draft_json: &str,
        recipient: &str,
        canonical_root: &Path,
    ) -> Result<(), String> {
        // 1. Check Draft ID
        if receipt.draft_id != draft_id {
            return Err(format!(
                "Draft ID Mismatch: Approved draft ID '{}' does not match target draft ID '{}'",
                receipt.draft_id, draft_id
            ));
        }

        // 2. Check Draft checksum
        let current_checksum = Self::compute_draft_checksum(draft_json);
        if receipt.draft_checksum != current_checksum {
            return Err(format!(
                "Draft Checksum Mismatch: Approved draft checksum '{}' does not match current content checksum '{}'",
                receipt.draft_checksum, current_checksum
            ));
        }

        // 3. Check Recipient
        if receipt.recipient != recipient {
            return Err(format!(
                "Recipient Mismatch: Approved recipient '{}' does not match target recipient '{}'",
                receipt.recipient, recipient
            ));
        }

        // 4. Canonical workspace root check
        let expected_canonical_root = Self::canonical_root(canonical_root);
        if !receipt.canonical_root.is_empty() && receipt.canonical_root != expected_canonical_root {
            return Err(format!(
                "Workspace Root Mismatch: Receipt bound to root '{}', but verifying in '{}'",
                receipt.canonical_root, expected_canonical_root
            ));
        }

        // 5. Expiration check
        let expiry = chrono::DateTime::parse_from_rfc3339(&receipt.valid_until)
            .map_err(|e| format!("Invalid receipt valid_until timestamp: {e}"))?;
        if Utc::now() > expiry {
            return Err(format!(
                "Approval Expired: Receipt expired at {} (current time: {})",
                receipt.valid_until,
                Utc::now().to_rfc3339()
            ));
        }

        // 6. Nonce replay check
        if receipt.nonce.is_empty() {
            return Err("Approval receipt is missing mandatory replay nonce".into());
        }
        if Self::is_nonce_consumed(canonical_root, &receipt.nonce)? {
            return Err(format!(
                "Receipt Replay Detected: nonce '{}' already consumed",
                receipt.nonce
            ));
        }

        // 7. ADR-008: Agent signing key cannot forge operator approval
        let agent_key_path = canonical_root.join(".aegis").join("agent_identity.key");
        if agent_key_path.exists() {
            if let Ok(agent) = AgentIdentity::load_existing(canonical_root) {
                if receipt.operator_public_key == agent.public_key_hex() {
                    return Err(
                        "Privilege Escalation Rejected: agent identity key cannot approve disclosure (ADR-008)".into(),
                    );
                }
            }
        }

        // Cryptographic signature verification over canonical payload
        let payload = Self::compute_receipt_payload(
            &receipt.draft_id,
            &receipt.draft_checksum,
            &receipt.recipient,
            &receipt.canonical_root,
            &receipt.approver,
            &receipt.valid_until,
            &receipt.nonce,
        );

        OperatorIdentity::verify_signature(
            &receipt.operator_public_key,
            payload.as_bytes(),
            &receipt.signature,
        )
        .map_err(|e| format!("Cryptographic signature verification failed: {e}"))?;

        Ok(())
    }

    /// Saves approval receipt to disk at `<canonical_root>/.bug-killer/approvals/<draft_id>.disclosure_receipt.json`.
    pub fn save_receipt(
        root: &Path,
        receipt: &DisclosureApprovalReceipt,
    ) -> Result<PathBuf, String> {
        let approvals_dir = root.join(".bug-killer").join("approvals");
        fs::create_dir_all(&approvals_dir)
            .map_err(|e| format!("Failed to create approvals directory: {e}"))?;

        let receipt_path =
            approvals_dir.join(format!("{}.disclosure_receipt.json", receipt.draft_id));
        let serialized = serde_json::to_string_pretty(receipt)
            .map_err(|e| format!("Failed to serialize approval receipt: {e}"))?;

        fs::write(&receipt_path, serialized).map_err(|e| {
            format!(
                "Failed to write approval receipt to {}: {e}",
                receipt_path.display()
            )
        })?;

        Ok(receipt_path)
    }

    /// Loads approval receipt from a JSON file.
    pub fn load_receipt(path: &Path) -> Result<DisclosureApprovalReceipt, String> {
        let content = fs::read_to_string(path).map_err(|e| {
            format!(
                "Failed to read approval receipt from {}: {e}",
                path.display()
            )
        })?;
        serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse approval receipt JSON: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_sign_and_verify_approval() {
        let temp = tempdir().unwrap();
        let root = temp.path();

        let operator = OperatorIdentity::get_or_create(root).unwrap();
        let draft_id = "draft-101";
        let draft_json = r#"{"draft_id":"draft-101","title":"Synthetic issue"}"#;
        let recipient = "security@example.com";

        let receipt = DisclosureApprovalManager::sign_approval(
            &operator, draft_id, draft_json, recipient, root, 24,
        )
        .unwrap();

        assert_eq!(receipt.draft_id, draft_id);
        assert_eq!(receipt.recipient, recipient);

        // Verification should succeed
        let verify_res = DisclosureApprovalManager::verify_approval(
            &receipt, draft_id, draft_json, recipient, root,
        );
        assert!(verify_res.is_ok());
    }

    #[test]
    fn test_tampered_draft_fails_verification() {
        let temp = tempdir().unwrap();
        let root = temp.path();

        let operator = OperatorIdentity::get_or_create(root).unwrap();
        let draft_id = "draft-102";
        let draft_json = r#"{"draft_id":"draft-102","title":"Original"}"#;
        let recipient = "security@example.com";

        let receipt = DisclosureApprovalManager::sign_approval(
            &operator, draft_id, draft_json, recipient, root, 24,
        )
        .unwrap();

        // Tamper with the draft content
        let tampered_json = r#"{"draft_id":"draft-102","title":"Tampered Content"}"#;
        let verify_res = DisclosureApprovalManager::verify_approval(
            &receipt,
            draft_id,
            tampered_json,
            recipient,
            root,
        );
        assert!(verify_res.is_err());
        assert!(verify_res.unwrap_err().contains("Draft Checksum Mismatch"));
    }

    #[test]
    fn test_tampered_recipient_fails_verification() {
        let temp = tempdir().unwrap();
        let root = temp.path();

        let operator = OperatorIdentity::get_or_create(root).unwrap();
        let draft_id = "draft-103";
        let draft_json = r#"{"draft_id":"draft-103"}"#;
        let recipient = "security@example.com";

        let receipt = DisclosureApprovalManager::sign_approval(
            &operator, draft_id, draft_json, recipient, root, 24,
        )
        .unwrap();

        // Recipient changed to an attacker address
        let verify_res = DisclosureApprovalManager::verify_approval(
            &receipt,
            draft_id,
            draft_json,
            "attacker@unauthorized.com",
            root,
        );
        assert!(verify_res.is_err());
        assert!(verify_res.unwrap_err().contains("Recipient Mismatch"));
    }

    #[test]
    fn test_nonce_replay_prevention() {
        let temp = tempdir().unwrap();
        let root = temp.path();

        let operator = OperatorIdentity::get_or_create(root).unwrap();
        let draft_id = "draft-104";
        let draft_json = r#"{"draft_id":"draft-104"}"#;
        let recipient = "security@example.com";

        let receipt = DisclosureApprovalManager::sign_approval(
            &operator, draft_id, draft_json, recipient, root, 24,
        )
        .unwrap();

        // Consume the nonce
        DisclosureApprovalManager::consume_nonce(root, &receipt.nonce).unwrap();

        // Second verification should fail due to replayed nonce
        let verify_res = DisclosureApprovalManager::verify_approval(
            &receipt, draft_id, draft_json, recipient, root,
        );
        assert!(verify_res.is_err());
        assert!(verify_res.unwrap_err().contains("Receipt Replay Detected"));
    }

    #[test]
    fn test_adr008_agent_key_cannot_forge_operator_approval() {
        let temp = tempdir().unwrap();
        let root = temp.path();

        // Create an agent identity key in the workspace
        let agent = AgentIdentity::get_or_create(root).unwrap();

        let draft_id = "draft-105";
        let draft_json = r#"{"draft_id":"draft-105"}"#;
        let recipient = "security@example.com";
        let canonical_root_str = DisclosureApprovalManager::canonical_root(root);
        let now = Utc::now();
        let valid_until = (now + Duration::hours(24)).to_rfc3339();
        let nonce = DisclosureApprovalManager::generate_nonce();
        let approver = "forged-agent";

        let payload = DisclosureApprovalManager::compute_receipt_payload(
            draft_id,
            &DisclosureApprovalManager::compute_draft_checksum(draft_json),
            recipient,
            &canonical_root_str,
            approver,
            &valid_until,
            &nonce,
        );

        // Sign with AGENT key instead of operator key
        let signature = agent.sign_bytes(payload.as_bytes());

        let forged_receipt = DisclosureApprovalReceipt {
            draft_id: draft_id.to_string(),
            draft_checksum: DisclosureApprovalManager::compute_draft_checksum(draft_json),
            recipient: recipient.to_string(),
            canonical_root: canonical_root_str,
            approver: approver.to_string(),
            timestamp: now.to_rfc3339(),
            valid_until,
            nonce,
            operator_public_key: agent.public_key_hex(),
            signature,
        };

        let verify_res = DisclosureApprovalManager::verify_approval(
            &forged_receipt,
            draft_id,
            draft_json,
            recipient,
            root,
        );

        assert!(verify_res.is_err());
        assert!(
            verify_res
                .unwrap_err()
                .contains("Privilege Escalation Rejected")
        );
    }
}
