use super::{DetectorResult, ScanContext, SecurityDetector};
use crate::types::*;
use chrono::Utc;

pub struct OpsQaDetector;

impl SecurityDetector for OpsQaDetector {
    fn id(&self) -> &'static str {
        "ops-qa"
    }

    fn name(&self) -> &'static str {
        "Errors, Observability & Test Integrity Security Detector"
    }

    fn supported_rule_ids(&self) -> &[&'static str] {
        &[
            "BK-AI-OPS-001",
            "BK-AI-OPS-002",
            "BK-AI-OPS-003",
            "BK-AI-OPS-004",
            "BK-AI-OPS-005",
            "BK-AI-OPS-006",
            "BK-AI-OPS-007",
            "BK-AI-OPS-008",
            "BK-AI-OPS-009",
            "BK-AI-OPS-010",
            "BK-AI-OPS-011",
            "BK-AI-OPS-012",
            "BK-AI-QAT-001",
            "BK-AI-QAT-002",
            "BK-AI-QAT-003",
            "BK-AI-QAT-004",
            "BK-AI-QAT-005",
            "BK-AI-QAT-006",
            "BK-AI-QAT-007",
            "BK-AI-QAT-008",
            "BK-AI-QAT-009",
            "BK-AI-QAT-010",
            "BK-AI-QAT-011",
            "BK-AI-QAT-012",
        ]
    }

    fn supported_languages(&self) -> &[&'static str] {
        &[
            "javascript",
            "typescript",
            "python",
            "go",
            "rust",
            "generic",
        ]
    }

    fn supported_targets(&self) -> &[TargetKind] {
        &[
            TargetKind::GenericSourceFile,
            TargetKind::NodeSourceFile,
            TargetKind::GenericConfigFile,
        ]
    }

    fn run(&self, ctx: &ScanContext) -> DetectorResult {
        let report = ctx.get_report();
        let findings: Vec<Finding> = report
            .findings
            .iter()
            .filter(|f| f.detector_id == "ops-qa")
            .cloned()
            .collect();

        let rules_run = self
            .supported_rule_ids()
            .iter()
            .map(|s| s.to_string())
            .collect();
        let receipt = CoverageReceipt {
            scanner_id: self.id().to_string(),
            scanner_version: env!("CARGO_PKG_VERSION").to_string(),
            target_id: ctx.root.display().to_string(),
            status: CoverageStatus::Complete,
            items_examined: report.total_files_scanned as u64,
            skipped_reasons: Vec::new(),
            errors: Vec::new(),
            completed_at: Utc::now().to_rfc3339(),
        };

        DetectorResult {
            findings,
            receipt,
            rules_run,
        }
    }
}

pub struct BkhSafetyDetector;

impl SecurityDetector for BkhSafetyDetector {
    fn id(&self) -> &'static str {
        "bkh-safety"
    }

    fn name(&self) -> &'static str {
        "Bug Killer Healer & Scanner Safety Detector"
    }

    fn supported_rule_ids(&self) -> &[&'static str] {
        &[
            "BK-AI-BKH-001",
            "BK-AI-BKH-002",
            "BK-AI-BKH-003",
            "BK-AI-BKH-004",
            "BK-AI-BKH-005",
            "BK-AI-BKH-006",
            "BK-AI-BKH-007",
            "BK-AI-BKH-008",
            "BK-AI-BKH-009",
            "BK-AI-BKH-010",
            "BK-AI-BKH-011",
            "BK-AI-BKH-012",
            "BK-AI-BKH-013",
            "BK-AI-BKH-014",
            "BK-AI-BKH-015",
            "BK-AI-BKH-016",
            "BK-AI-BKH-017",
            "BK-AI-BKH-018",
        ]
    }

    fn supported_languages(&self) -> &[&'static str] {
        &[
            "javascript",
            "typescript",
            "python",
            "go",
            "rust",
            "generic",
        ]
    }

    fn supported_targets(&self) -> &[TargetKind] {
        &[
            TargetKind::GenericSourceFile,
            TargetKind::NodeSourceFile,
            TargetKind::GenericConfigFile,
        ]
    }

    fn run(&self, ctx: &ScanContext) -> DetectorResult {
        let report = ctx.get_report();
        let findings: Vec<Finding> = report
            .findings
            .iter()
            .filter(|f| f.detector_id == "bkh-safety")
            .cloned()
            .collect();

        let rules_run = self
            .supported_rule_ids()
            .iter()
            .map(|s| s.to_string())
            .collect();
        let receipt = CoverageReceipt {
            scanner_id: self.id().to_string(),
            scanner_version: env!("CARGO_PKG_VERSION").to_string(),
            target_id: ctx.root.display().to_string(),
            status: CoverageStatus::Complete,
            items_examined: report.total_files_scanned as u64,
            skipped_reasons: Vec::new(),
            errors: Vec::new(),
            completed_at: Utc::now().to_rfc3339(),
        };

        DetectorResult {
            findings,
            receipt,
            rules_run,
        }
    }
}
