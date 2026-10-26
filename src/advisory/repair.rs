use crate::advisory::correlator::{Affectedness, AffectednessCorrelator};
use crate::advisory::provider::AdvisoryRecord;
use crate::advisory::sbom::PackageIdentity;
use crate::engine::protocol::*;
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RepairVerificationStatus {
    FixedVerified,
    IncompleteRepair {
        reason: String,
        retained_vulnerabilities: Vec<String>,
    },
    Failed {
        reason: String,
    },
}

#[derive(Debug, Clone, Default)]
pub struct PackageRepairPlanner {
    correlator: AffectednessCorrelator,
}

impl PackageRepairPlanner {
    pub fn new() -> Self {
        Self {
            correlator: AffectednessCorrelator::new(),
        }
    }

    /// Plans a targeted, bounded version bump for a package.
    #[allow(clippy::too_many_arguments)]
    pub fn plan_package_upgrade(
        &self,
        run_id: &str,
        workspace_root_digest: &str,
        package: &PackageIdentity,
        target_version: &str,
        manifest_rel_path: &str,
        manifest_content: &str,
        finding_ids: Vec<String>,
        risk_level: RepairRiskLevel,
    ) -> Result<RepairPlanV1, String> {
        if finding_ids.is_empty() {
            return Err("finding_ids must not be empty".to_string());
        }

        let preimage_sha256 = compute_sha256(manifest_content.as_bytes());

        // Perform minimal replacement of old version with target version
        let old_version = package.resolved_version.as_deref().unwrap_or("");
        let updated_content = if !old_version.is_empty() && manifest_content.contains(old_version) {
            manifest_content.replacen(old_version, target_version, 1)
        } else {
            // Append or format replacement
            format!(
                "{}\n# Updated {} to {}\n",
                manifest_content, package.name, target_version
            )
        };

        let expected_postimage_sha256 = compute_sha256(updated_content.as_bytes());

        let diff_text = format!(
            "--- a/{path}\n+++ b/{path}\n@@ -1 +1 @@\n- {pkg} {old_ver}\n+ {pkg} {new_ver}\n",
            path = manifest_rel_path,
            pkg = package.name,
            old_ver = old_version,
            new_ver = target_version
        );
        let diff_artifact_sha256 = compute_sha256(diff_text.as_bytes());

        let action = ProposedActionV1 {
            action_id: format!("action-bump-{}-to-{}", package.name, target_version),
            kind: ProposedActionKind::LockfileUpdate,
            target_relative_path: manifest_rel_path.to_string(),
            preimage_sha256,
            expected_postimage_sha256,
            diff_artifact_sha256: Some(diff_artifact_sha256),
        };

        let verifications = vec![
            RequiredVerificationV1 {
                verification_id: "verify-requery".to_string(),
                kind: VerificationKind::DependencyRequery,
                required: true,
            },
            RequiredVerificationV1 {
                verification_id: "verify-rescan".to_string(),
                kind: VerificationKind::SecurityRescan,
                required: true,
            },
            RequiredVerificationV1 {
                verification_id: "verify-build".to_string(),
                kind: VerificationKind::Build,
                required: true,
            },
            RequiredVerificationV1 {
                verification_id: "verify-test".to_string(),
                kind: VerificationKind::Test,
                required: true,
            },
        ];

        let now = Utc::now();
        let expires = now + Duration::days(7);

        let plan = RepairPlanV1 {
            schema_version: "1.0".to_string(),
            plan_id: format!("repair-plan-{}", package.name),
            run_id: run_id.to_string(),
            finding_ids,
            workspace_root_digest: workspace_root_digest.to_string(),
            risk_level,
            proposed_actions: vec![action],
            required_verifications: verifications,
            approval: None,
            status: RepairPlanStatus::Proposed,
            backup_manifest_ref: None,
            created_at: now.to_rfc3339(),
            expires_at: expires.to_rfc3339(),
            idempotency_key: Some(format!("repair-{}-{}", package.name, target_version)),
        };

        plan.validate()?;
        Ok(plan)
    }

    /// Critical Invariant Check: Transitive vulnerability retention check.
    /// If upgrading a direct dependency leaves an indirect/transitive vulnerable copy in the lockfile,
    /// it CANNOT claim FixedVerified; it reports INCOMPLETE_REPAIR / PARTIAL.
    pub fn verify_repair_outcome(
        &self,
        _plan: &RepairPlanV1,
        post_repair_inventory: &[PackageIdentity],
        advisories: &[AdvisoryRecord],
    ) -> RepairVerificationStatus {
        let mut retained_vulnerabilities = Vec::new();

        for pkg in post_repair_inventory {
            for adv in advisories {
                let aff = self.correlator.evaluate_affectedness(pkg, adv);
                if aff == Affectedness::VersionAffected {
                    let desc = format!(
                        "{}@{} ({}) affected by {}",
                        pkg.name,
                        pkg.resolved_version.as_deref().unwrap_or("?"),
                        if pkg.direct { "direct" } else { "transitive" },
                        adv.advisory_id
                    );
                    retained_vulnerabilities.push(desc);
                }
            }
        }

        if !retained_vulnerabilities.is_empty() {
            RepairVerificationStatus::IncompleteRepair {
                reason: format!(
                    "Transitive vulnerable package retained in lockfile inventory: {} lingering vulnerability item(s)",
                    retained_vulnerabilities.len()
                ),
                retained_vulnerabilities,
            }
        } else {
            RepairVerificationStatus::FixedVerified
        }
    }

    /// Emits a CoverageReceiptV1 reflecting the repair verification status.
    pub fn generate_coverage_receipt(
        &self,
        run_id: &str,
        outcome: &RepairVerificationStatus,
    ) -> CoverageReceiptV1 {
        let now = Utc::now().to_rfc3339();
        let dummy_digest =
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string();

        match outcome {
            RepairVerificationStatus::FixedVerified => CoverageReceiptV1 {
                schema_version: "1.0".to_string(),
                receipt_id: format!("receipt-repair-fixed-{}", &run_id[..run_id.len().min(8)]),
                run_id: run_id.to_string(),
                engine_id: "package-repair-planner".to_string(),
                engine_version: "1.0.0".to_string(),
                check_id: "check-package-repair".to_string(),
                target_id: "target-lockfile".to_string(),
                snapshot_sha256: dummy_digest.clone(),
                status: CoverageReceiptStatus::Evaluated,
                counts: ReceiptCounts {
                    items_discovered: 1,
                    items_examined: 1,
                    items_excluded: 0,
                    items_skipped: 0,
                },
                reason_codes: vec![],
                details: vec![
                    "Repair verification successful: zero vulnerable packages remaining"
                        .to_string(),
                ],
                started_at: now.clone(),
                completed_at: now,
                required_by_policy: Some(true),
                artifact_digests: vec![dummy_digest],
                previous_receipt_id: None,
            },
            RepairVerificationStatus::IncompleteRepair {
                reason,
                retained_vulnerabilities,
            } => {
                let mut details = vec![reason.clone()];
                details.extend(retained_vulnerabilities.clone());
                CoverageReceiptV1 {
                    schema_version: "1.0".to_string(),
                    receipt_id: format!(
                        "receipt-repair-partial-{}",
                        &run_id[..run_id.len().min(8)]
                    ),
                    run_id: run_id.to_string(),
                    engine_id: "package-repair-planner".to_string(),
                    engine_version: "1.0.0".to_string(),
                    check_id: "check-package-repair".to_string(),
                    target_id: "target-lockfile".to_string(),
                    snapshot_sha256: dummy_digest.clone(),
                    status: CoverageReceiptStatus::Partial,
                    counts: ReceiptCounts {
                        items_discovered: 1,
                        items_examined: 1,
                        items_excluded: 0,
                        items_skipped: 0,
                    },
                    reason_codes: vec![ReceiptReasonCode::Other],
                    details,
                    started_at: now.clone(),
                    completed_at: now,
                    required_by_policy: Some(true),
                    artifact_digests: vec![dummy_digest],
                    previous_receipt_id: None,
                }
            }
            RepairVerificationStatus::Failed { reason } => CoverageReceiptV1 {
                schema_version: "1.0".to_string(),
                receipt_id: format!("receipt-repair-failed-{}", &run_id[..run_id.len().min(8)]),
                run_id: run_id.to_string(),
                engine_id: "package-repair-planner".to_string(),
                engine_version: "1.0.0".to_string(),
                check_id: "check-package-repair".to_string(),
                target_id: "target-lockfile".to_string(),
                snapshot_sha256: dummy_digest.clone(),
                status: CoverageReceiptStatus::Error,
                counts: ReceiptCounts {
                    items_discovered: 1,
                    items_examined: 1,
                    items_excluded: 0,
                    items_skipped: 0,
                },
                reason_codes: vec![ReceiptReasonCode::Other],
                details: vec![reason.clone()],
                started_at: now.clone(),
                completed_at: now,
                required_by_policy: Some(true),
                artifact_digests: vec![dummy_digest],
                previous_receipt_id: None,
            },
        }
    }
}

fn compute_sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    crate::to_hex(hasher.finalize())
}
