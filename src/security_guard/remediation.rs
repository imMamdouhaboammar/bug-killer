#![allow(dead_code)]

use crate::detectors::DetectorRegistry;
use crate::healer::approval::ApprovalManager;
use crate::healer::backup::BackupManager;
use crate::healer::rollback::RollbackManager;
use crate::security_guard::config::RemediationLevel;
use crate::types::*;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixProposal {
    pub finding_id: String,
    pub rule_id: String,
    pub target_file: PathBuf,
    pub original_sha256: String,
    pub replacement_content: String,
    pub diff_preview: String,
    pub explanation: String,
    pub required_level: RemediationLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationOutcome {
    pub success: bool,
    pub finding_id: String,
    pub backup_id: Option<String>,
    pub verification_status: String,
    pub message: String,
}

pub struct RemediationEngine;

impl RemediationEngine {
    /// Generates a bounded, non-mutating repair proposal for a detected security finding.
    pub fn propose_fix(root: &Path, finding: &Finding) -> Result<FixProposal, String> {
        let file_path = finding
            .file_path
            .as_ref()
            .ok_or_else(|| "Finding does not have an associated file path".to_string())?;

        let full_path = if file_path.is_absolute() || file_path.starts_with(root) {
            file_path.clone()
        } else {
            root.join(file_path)
        };

        if !full_path.exists() {
            return Err(format!(
                "Target file does not exist: {}",
                full_path.display()
            ));
        }

        let content = fs::read_to_string(&full_path)
            .map_err(|e| format!("Failed to read target file: {}", e))?;
        let original_sha256 = BackupManager::compute_sha256(&full_path)
            .map_err(|e| format!("Failed to compute file checksum: {}", e))?;

        let rule_id = finding.cve.as_str();

        let manual_fix = || {
            (
                String::new(),
                "No safe automatic patch for this target; manual remediation required.".to_string(),
                finding.suggested_remediation.clone(),
                RemediationLevel::Propose,
            )
        };
        let (replacement_content, diff_preview, explanation, required_level) = match rule_id {
            "BK-AI-INF-003" => {
                let last_image = content
                    .lines()
                    .filter_map(|line| {
                        let mut words = line.split_whitespace();
                        if words.next()?.eq_ignore_ascii_case("FROM") {
                            words.next()
                        } else {
                            None
                        }
                    })
                    .next_back()
                    .unwrap_or("");
                if last_image != "node" && !last_image.starts_with("node:") {
                    manual_fix()
                } else {
                    let mut lines: Vec<&str> = content.lines().collect();
                    let last_from = lines
                        .iter()
                        .rposition(|line| {
                            line.trim_start().to_ascii_uppercase().starts_with("FROM ")
                        })
                        .unwrap_or(0);
                    if let Some(idx) = (last_from..lines.len())
                        .rev()
                        .find(|idx| matches!(lines[*idx].trim(), "USER root" | "USER 0"))
                    {
                        lines[idx] = "USER node";
                    } else {
                        lines.push("USER node");
                    }
                    (
                        format!("{}\n", lines.join("\n")),
                        "Switch the final official Node image stage to USER node".to_string(),
                        "Use the non-root node user provided by the official Node image"
                            .to_string(),
                        RemediationLevel::GuardedLocalFix,
                    )
                }
            }
            _ => manual_fix(),
        };

        Ok(FixProposal {
            finding_id: finding.id.clone(),
            rule_id: rule_id.to_string(),
            target_file: full_path,
            original_sha256,
            replacement_content,
            diff_preview,
            explanation,
            required_level,
        })
    }

    /// Applies an authorized fix proposal with atomic Ed25519 backup and independent post-change verification.
    pub fn apply_guarded_fix(
        root: &Path,
        proposal: &FixProposal,
        allowed_level: RemediationLevel,
        approval_receipt: Option<&str>,
    ) -> Result<RemediationOutcome, String> {
        // 1. Permission level check
        match proposal.required_level {
            RemediationLevel::ReportOnly | RemediationLevel::Propose => {
                return Err("Proposal is advisory only and cannot modify files.".to_string());
            }
            RemediationLevel::GuardedLocalFix => {
                if allowed_level == RemediationLevel::ReportOnly
                    || allowed_level == RemediationLevel::Propose
                {
                    return Err(format!(
                        "Unauthorized mutation: Current policy level is {:?}, but fix requires GuardedLocalFix.",
                        allowed_level
                    ));
                }
            }
            RemediationLevel::PrivilegedRemediation => {
                if allowed_level != RemediationLevel::PrivilegedRemediation {
                    return Err(
                        "Operation requires Level 3 PrivilegedRemediation authorization."
                            .to_string(),
                    );
                }
                let receipt_token = approval_receipt.ok_or_else(|| {
                    "Level 3 PrivilegedRemediation requires an operator approval receipt."
                        .to_string()
                })?;
                // Verify receipt token
                let receipt: crate::healer::approval::ApprovalReceipt =
                    serde_json::from_str(receipt_token)
                        .map_err(|e| format!("Invalid operator approval receipt JSON: {}", e))?;
                ApprovalManager::verify_approval_receipt(
                    root,
                    &receipt,
                    &proposal.original_sha256,
                )?;
            }
        }

        // 2. Path confinement check
        let canonical_root = root
            .canonicalize()
            .map_err(|e| format!("Invalid workspace root: {e}"))?;
        let canonical_target = proposal
            .target_file
            .canonicalize()
            .map_err(|e| format!("Invalid target path: {e}"))?;
        if !canonical_target.starts_with(&canonical_root)
            || !canonical_target.is_file()
            || fs::symlink_metadata(&proposal.target_file)
                .is_ok_and(|metadata| metadata.file_type().is_symlink())
        {
            return Err(format!(
                "Security Boundary Violation: Target file {} escapes workspace root {}",
                proposal.target_file.display(),
                root.display()
            ));
        }

        // 3. Precondition: check current file hash matches original_sha256
        let current_sha256 = BackupManager::compute_sha256(&proposal.target_file)
            .map_err(|e| format!("Failed to read target file: {}", e))?;
        if current_sha256 != proposal.original_sha256 {
            return Err(format!(
                "Precondition check failed: File was modified since proposal (expected {}, found {})",
                proposal.original_sha256, current_sha256
            ));
        }

        // 4. Create atomic signed backup
        let manifest =
            BackupManager::create_backup(root, std::slice::from_ref(&proposal.target_file))
                .map_err(|e| format!("Backup creation failed: {}", e))?;
        let backup_id = manifest.backup_id.clone();

        // 5. Apply patch
        let parent = proposal.target_file.parent().unwrap_or(root);
        let original_permissions = fs::metadata(&proposal.target_file)
            .map_err(|e| format!("Failed to inspect target permissions: {e}"))?
            .permissions();
        let mut temp = tempfile::NamedTempFile::new_in(parent)
            .map_err(|e| format!("Failed to stage replacement: {e}"))?;
        temp.write_all(proposal.replacement_content.as_bytes())
            .map_err(|e| format!("Failed to write staged replacement: {e}"))?;
        temp.as_file()
            .set_permissions(original_permissions)
            .map_err(|e| format!("Failed to preserve target permissions: {e}"))?;
        temp.persist(&proposal.target_file)
            .map_err(|e| format!("Failed to atomically apply patch: {e}"))?;

        // 6. Independent verification
        let post_scan =
            DetectorRegistry::default().execute_guard_scan(root, ScanProfile::Project, None, false);
        let finding_still_exists = post_scan.findings.iter().any(|f| {
            (f.cve.as_str() == proposal.rule_id
                || f.advisory_ids.iter().any(|a| a == &proposal.rule_id))
                && f.file_path
                    .as_ref()
                    .map(|p| p.ends_with(&proposal.target_file))
                    .unwrap_or(false)
        });

        if finding_still_exists || post_scan.status != ScanStatus::Completed {
            // Independent verification failed! Automatic rollback.
            if let Err(error) = RollbackManager::rollback(root, &backup_id) {
                return Err(format!(
                    "Verification failed and rollback failed (backup {backup_id}): {error}"
                ));
            }
            Ok(RemediationOutcome {
                success: false,
                finding_id: proposal.finding_id.clone(),
                backup_id: Some(backup_id),
                verification_status: "VERIFICATION_FAILED".to_string(),
                message: "Post-remediation verification failed: Vulnerability invariant not restored. Automatically rolled back to snapshot.".to_string(),
            })
        } else {
            Ok(RemediationOutcome {
                success: true,
                finding_id: proposal.finding_id.clone(),
                backup_id: Some(backup_id),
                verification_status: "VERIFIED_CLEAN".to_string(),
                message: "Patch applied successfully and independently verified clean.".to_string(),
            })
        }
    }
}
