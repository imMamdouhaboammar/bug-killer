#![allow(dead_code)]

use crate::healer::approval::ApprovalManager;
use crate::healer::backup::BackupManager;
use crate::healer::rollback::RollbackManager;
use crate::scanner::FleetScanner;
use crate::security_guard::config::RemediationLevel;
use crate::types::*;
use serde::{Deserialize, Serialize};
use std::fs;
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

        let full_path = if file_path.is_absolute() {
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

        let (replacement_content, diff_preview, explanation, required_level) = match rule_id {
            "BK-AI-INF-001" => {
                // Docker root user -> add USER appuser or USER node
                let patched = if content.contains("USER ") {
                    content.replace("USER root", "USER node")
                } else {
                    format!("{}\nUSER node\n", content.trim_end())
                };
                let diff =
                    "+ USER node (switch container runtime from root to non-privileged user)"
                        .to_string();
                let exp =
                    "Enforce least privilege by running the container as non-root user 'node'."
                        .to_string();
                (patched, diff, exp, RemediationLevel::GuardedLocalFix)
            }
            "BK-AI-CIC-001" => {
                // Untrusted GitHub Actions context interpolation in run:
                let patched = content
                    .replace("${{ github.event.comment.body }}", "\"$COMMENT_BODY\"")
                    .replace("${{ github.event.issue.title }}", "\"$ISSUE_TITLE\"");
                let diff = "- ${{ github.event... }}\n+ \"$ENV_VAR\" (pass via step environment variables)".to_string();
                let exp = "Isolate untrusted user-controlled strings into shell environment variables to prevent command injection.".to_string();
                (patched, diff, exp, RemediationLevel::GuardedLocalFix)
            }
            "BK-AI-SEC-001" => {
                // Hardcoded secret -> replace with process.env lookup
                let lines: Vec<String> = content
                    .lines()
                    .enumerate()
                    .map(|(idx, l)| {
                        if Some(idx + 1) == finding.line_number {
                            if l.contains("AKIA") {
                                return l.replace(
                                    &l.trim().to_string(),
                                    "const apiKey = process.env.AWS_ACCESS_KEY_ID;",
                                );
                            }
                            if l.contains("sk-") {
                                return l.replace(
                                    &l.trim().to_string(),
                                    "const apiKey = process.env.OPENAI_API_KEY;",
                                );
                            }
                        }
                        l.to_string()
                    })
                    .collect();
                let patched = lines.join("\n");
                let diff = "- <hardcoded_secret>\n+ process.env.<SECRET_KEY>".to_string();
                let exp = "Replace hardcoded API key with runtime environment variable access."
                    .to_string();
                (patched, diff, exp, RemediationLevel::GuardedLocalFix)
            }
            _ => {
                // Generic remediation guidance proposal
                let exp = format!("Remediation guidance: {}", finding.suggested_remediation);
                (
                    content.clone(),
                    "No automatic syntax patch available; manual remediation required.".to_string(),
                    exp,
                    RemediationLevel::Propose,
                )
            }
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
        if !proposal.target_file.starts_with(root) {
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
        fs::write(&proposal.target_file, &proposal.replacement_content)
            .map_err(|e| format!("Failed to apply patch to file: {}", e))?;

        // 6. Independent verification
        let post_scan = FleetScanner::scan_directory(root, false);
        let finding_still_exists = post_scan.findings.iter().any(|f| {
            (f.cve.as_str() == proposal.rule_id
                || f.advisory_ids.iter().any(|a| a == &proposal.rule_id))
                && f.file_path
                    .as_ref()
                    .map(|p| p.ends_with(&proposal.target_file))
                    .unwrap_or(false)
        });

        if finding_still_exists {
            // Independent verification failed! Automatic rollback.
            let _ = RollbackManager::rollback(root, &backup_id);
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
