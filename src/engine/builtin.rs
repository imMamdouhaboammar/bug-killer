use std::path::PathBuf;
use std::time::Instant;

use crate::detectors::DetectorRegistry;
use crate::engine::adapter::{AdapterCapabilities, AnalyzerAdapter};
use crate::engine::converter::{to_normalized_finding, to_normalized_receipt};
use crate::engine::protocol::{
    AnalysisRequest, AnalysisResponse, DiagnosticV1, EngineStatus, ResourceUsage,
};
use crate::engine::runner::{AnalysisError, CancellationToken};
use crate::types::{CoverageStatus, ScanProfile, ScanStatus, TargetKind};

/// Builtin scanner adapter wrapping the core Bug Killer detector scanning engine (`DetectorRegistry`).
#[derive(Default, Clone)]
pub struct BuiltinScannerAdapter {
    registry: DetectorRegistry,
}

impl BuiltinScannerAdapter {
    pub fn new() -> Self {
        Self {
            registry: DetectorRegistry::default(),
        }
    }
}

impl AnalyzerAdapter for BuiltinScannerAdapter {
    fn engine_id(&self) -> &str {
        "builtin-scanner"
    }

    fn engine_version(&self) -> &str {
        "1.0.0"
    }

    fn supported_profiles(&self) -> &[ScanProfile] {
        &[
            ScanProfile::Quick,
            ScanProfile::Project,
            ScanProfile::Ci,
            ScanProfile::Deep,
            ScanProfile::Research,
        ]
    }

    fn supported_languages(&self) -> &[&str] {
        &[
            "javascript",
            "typescript",
            "python",
            "php",
            "go",
            "rust",
            "dockerfile",
            "yaml",
            "markdown",
            "generic",
        ]
    }

    fn supported_target_kinds(&self) -> &[TargetKind] {
        &[
            TargetKind::GenericSourceFile,
            TargetKind::NodeSourceFile,
            TargetKind::ComposerManifest,
            TargetKind::ComposerLockfile,
            TargetKind::NodePackageManifest,
            TargetKind::NodeLockfile,
            TargetKind::Dockerfile,
            TargetKind::GenericConfigFile,
            TargetKind::EnvironmentFile,
            TargetKind::McpServerConfig,
            TargetKind::AgentSkillManifest,
            TargetKind::BinaryExecutable,
        ]
    }

    fn capabilities(&self) -> AdapterCapabilities {
        AdapterCapabilities {
            requires_network: false,
            requires_mutation: false,
            is_isolated: true,
            supports_cancellation: true,
        }
    }

    fn analyze(
        &self,
        request: &AnalysisRequest,
        cancel_token: &CancellationToken,
    ) -> Result<AnalysisResponse, AnalysisError> {
        let start = Instant::now();

        if cancel_token.is_cancelled() {
            return Err(AnalysisError::Cancelled);
        }

        let root = PathBuf::from(&request.snapshot_ref);
        if !root.exists() {
            return Err(AnalysisError::ExecutionFailed(format!(
                "Target snapshot path does not exist: {}",
                request.snapshot_ref
            )));
        }

        // Execute scan using the encapsulated DetectorRegistry
        let guard_report = self.registry.execute_guard_scan(
            &root,
            request.profile,
            None,
            request.permissions.allow_network,
        );

        if cancel_token.is_cancelled() {
            return Err(AnalysisError::Cancelled);
        }

        // Convert receipts
        let mut receipts = Vec::new();
        for r in &guard_report.receipts {
            let mut norm_r = to_normalized_receipt(r, &request.run_id, &request.snapshot_sha256);
            norm_r.run_id = request.run_id.clone();
            norm_r.snapshot_sha256 = request.snapshot_sha256.clone();
            receipts.push(norm_r);
        }

        // If no receipts were produced by detectors, generate receipt from base scan coverage
        if receipts.is_empty() {
            let base_status = match guard_report.coverage.coverage_status {
                CoverageStatus::Complete => {
                    crate::engine::protocol::CoverageReceiptStatus::Evaluated
                }
                CoverageStatus::Partial | CoverageStatus::ScanIncomplete => {
                    crate::engine::protocol::CoverageReceiptStatus::Partial
                }
                CoverageStatus::Unsupported => {
                    crate::engine::protocol::CoverageReceiptStatus::Unsupported
                }
                CoverageStatus::NotRun => crate::engine::protocol::CoverageReceiptStatus::NotRun,
                CoverageStatus::Error => crate::engine::protocol::CoverageReceiptStatus::Error,
            };

            let reason_codes =
                if base_status != crate::engine::protocol::CoverageReceiptStatus::Evaluated {
                    vec![crate::engine::protocol::ReceiptReasonCode::Other]
                } else {
                    Vec::new()
                };

            let now = chrono::Utc::now().to_rfc3339();
            receipts.push(crate::engine::protocol::CoverageReceiptV1 {
                schema_version: "1.0".to_string(),
                receipt_id: format!("receipt-{}-root", request.run_id),
                run_id: request.run_id.clone(),
                engine_id: self.engine_id().to_string(),
                engine_version: self.engine_version().to_string(),
                check_id: "ALL_ACTIVE".to_string(),
                target_id: request.snapshot_ref.clone(),
                snapshot_sha256: request.snapshot_sha256.clone(),
                status: base_status,
                counts: crate::engine::protocol::ReceiptCounts {
                    items_discovered: guard_report.files_assessed as u64,
                    items_examined: guard_report.coverage.files_scanned as u64,
                    items_excluded: guard_report.coverage.files_excluded as u64,
                    items_skipped: guard_report.coverage.unsupported_targets.len() as u64,
                },
                reason_codes,
                details: guard_report.unexamined_reasons.clone(),
                started_at: guard_report.scan_time.clone(),
                completed_at: now.clone(),
                required_by_policy: Some(false),
                artifact_digests: Vec::new(),
                previous_receipt_id: None,
            });
        }

        let receipt_ids: Vec<String> = receipts.iter().map(|r| r.receipt_id.clone()).collect();

        // Convert findings
        let mut findings = Vec::new();
        for f in &guard_report.findings {
            let mut norm_f = to_normalized_finding(f, &request.run_id, &request.snapshot_sha256);
            norm_f.run_id = request.run_id.clone();
            norm_f.source_snapshot_sha256 = request.snapshot_sha256.clone();
            norm_f.coverage_receipt_ids = receipt_ids.clone();
            findings.push(norm_f);
        }

        let status = match guard_report.status {
            ScanStatus::Completed => EngineStatus::Completed,
            ScanStatus::Partial => EngineStatus::Partial,
            ScanStatus::Failed => EngineStatus::Error,
            ScanStatus::Blocked => EngineStatus::Blocked,
            ScanStatus::NotRun | ScanStatus::Unsupported | ScanStatus::Running => {
                EngineStatus::Partial
            }
        };

        let diagnostics = guard_report
            .unexamined_reasons
            .iter()
            .map(|reason| DiagnosticV1 {
                code: "SCAN_UNEXAMINED_REASON".to_string(),
                message: reason.clone(),
                target_id: None,
            })
            .collect();

        let duration_ms = start.elapsed().as_millis() as u64;

        Ok(AnalysisResponse {
            schema_version: "1.0".to_string(),
            run_id: request.run_id.clone(),
            engine_id: self.engine_id().to_string(),
            engine_version: self.engine_version().to_string(),
            snapshot_sha256: request.snapshot_sha256.clone(),
            status,
            findings,
            receipts,
            diagnostics,
            resources: ResourceUsage {
                duration_ms,
                peak_memory_bytes: 1024 * 1024,
            },
            completed_at: chrono::Utc::now().to_rfc3339(),
        })
    }
}
