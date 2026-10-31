use super::{DetectorResult, ScanContext, SecurityDetector};
use crate::types::*;
use chrono::Utc;

pub struct AuthSecurityDetector;

impl SecurityDetector for AuthSecurityDetector {
    fn id(&self) -> &'static str {
        "auth-security"
    }

    fn name(&self) -> &'static str {
        "Authentication & Session Security Detector"
    }

    fn supported_rule_ids(&self) -> &[&'static str] {
        &[
            "BK-AI-AUT-001",
            "BK-AI-AUT-002",
            "BK-AI-AUT-003",
            "BK-AI-AUT-004",
            "BK-AI-AUT-005",
            "BK-AI-AUT-006",
            "BK-AI-AUT-007",
            "BK-AI-AUT-008",
            "BK-AI-AUT-009",
            "BK-AI-AUT-010",
            "BK-AI-AUT-011",
            "BK-AI-AUT-012",
            "BK-AI-SES-001",
            "BK-AI-SES-002",
            "BK-AI-SES-003",
            "BK-AI-SES-004",
            "BK-AI-SES-005",
            "BK-AI-SES-006",
            "BK-AI-SES-007",
            "BK-AI-SES-008",
            "BK-AI-SES-009",
            "BK-AI-SES-010",
            "BK-AI-SES-011",
            "BK-AI-SES-012",
        ]
    }

    fn supported_languages(&self) -> &[&'static str] {
        &["javascript", "typescript", "python", "php", "go"]
    }

    fn supported_targets(&self) -> &[TargetKind] {
        &[TargetKind::GenericSourceFile, TargetKind::NodeSourceFile]
    }

    fn run(&self, ctx: &ScanContext) -> DetectorResult {
        let report = ctx.get_report();
        let auth_findings: Vec<Finding> = report
            .findings
            .iter()
            .filter(|f| f.detector_id == "auth-security")
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
            findings: auth_findings,
            receipt,
            rules_run,
        }
    }
}

pub struct AuthzSecurityDetector;

impl SecurityDetector for AuthzSecurityDetector {
    fn id(&self) -> &'static str {
        "authz-security"
    }

    fn name(&self) -> &'static str {
        "Authorization & Tenant Isolation Security Detector"
    }

    fn supported_rule_ids(&self) -> &[&'static str] {
        &[
            "BK-AI-AZ-001",
            "BK-AI-AZ-002",
            "BK-AI-AZ-003",
            "BK-AI-AZ-004",
            "BK-AI-AZ-005",
            "BK-AI-AZ-006",
            "BK-AI-AZ-007",
            "BK-AI-AZ-008",
            "BK-AI-AZ-009",
            "BK-AI-AZ-010",
            "BK-AI-AZ-011",
            "BK-AI-AZ-012",
            "BK-AI-AZ-013",
            "BK-AI-AZ-014",
        ]
    }

    fn supported_languages(&self) -> &[&'static str] {
        &["javascript", "typescript", "python", "php", "go"]
    }

    fn supported_targets(&self) -> &[TargetKind] {
        &[TargetKind::GenericSourceFile, TargetKind::NodeSourceFile]
    }

    fn run(&self, ctx: &ScanContext) -> DetectorResult {
        let report = ctx.get_report();
        let authz_findings: Vec<Finding> = report
            .findings
            .iter()
            .filter(|f| f.detector_id == "authz-security")
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
            findings: authz_findings,
            receipt,
            rules_run,
        }
    }
}

pub struct FilesystemExtDetector;

impl SecurityDetector for FilesystemExtDetector {
    fn id(&self) -> &'static str {
        "filesystem-ext"
    }

    fn name(&self) -> &'static str {
        "Filesystem, Archive & Injection Security Detector"
    }

    fn supported_rule_ids(&self) -> &[&'static str] {
        &[
            "BK-AI-FIL-003",
            "BK-AI-FIL-004",
            "BK-AI-FIL-005",
            "BK-AI-FIL-006",
            "BK-AI-FIL-007",
            "BK-AI-FIL-009",
            "BK-AI-FIL-010",
            "BK-AI-FIL-011",
            "BK-AI-FIL-012",
            "BK-AI-FIL-013",
            "BK-AI-FIL-014",
            "BK-AI-INJ-002",
            "BK-AI-INJ-004",
            "BK-AI-INJ-005",
            "BK-AI-INJ-008",
            "BK-AI-INJ-009",
            "BK-AI-INJ-010",
            "BK-AI-INJ-011",
            "BK-AI-INJ-012",
            "BK-AI-INJ-013",
            "BK-AI-INJ-016",
        ]
    }

    fn supported_languages(&self) -> &[&'static str] {
        &["javascript", "typescript", "python", "php", "go", "generic"]
    }

    fn supported_targets(&self) -> &[TargetKind] {
        &[TargetKind::GenericSourceFile, TargetKind::NodeSourceFile]
    }

    fn run(&self, ctx: &ScanContext) -> DetectorResult {
        let report = ctx.get_report();
        let fs_findings: Vec<Finding> = report
            .findings
            .iter()
            .filter(|f| f.detector_id == "filesystem-ext")
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
            findings: fs_findings,
            receipt,
            rules_run,
        }
    }
}

pub struct BizConcurrencyDetector;

impl SecurityDetector for BizConcurrencyDetector {
    fn id(&self) -> &'static str {
        "biz-concurrency"
    }

    fn name(&self) -> &'static str {
        "Concurrency, Workflow State & Business Logic Security Detector"
    }

    fn supported_rule_ids(&self) -> &[&'static str] {
        &[
            "BK-AI-RAC-001",
            "BK-AI-RAC-002",
            "BK-AI-RAC-003",
            "BK-AI-RAC-004",
            "BK-AI-RAC-005",
            "BK-AI-RAC-006",
            "BK-AI-RAC-007",
            "BK-AI-RAC-008",
            "BK-AI-RAC-009",
            "BK-AI-RAC-010",
            "BK-AI-BIZ-001",
            "BK-AI-BIZ-002",
            "BK-AI-BIZ-003",
            "BK-AI-BIZ-004",
            "BK-AI-BIZ-005",
            "BK-AI-BIZ-006",
            "BK-AI-BIZ-007",
            "BK-AI-BIZ-008",
            "BK-AI-BIZ-009",
            "BK-AI-BIZ-010",
            "BK-AI-BIZ-011",
            "BK-AI-BIZ-012",
        ]
    }

    fn supported_languages(&self) -> &[&'static str] {
        &[
            "javascript",
            "typescript",
            "python",
            "go",
            "rust",
            "php",
            "generic",
        ]
    }

    fn supported_targets(&self) -> &[TargetKind] {
        &[TargetKind::GenericSourceFile, TargetKind::NodeSourceFile]
    }

    fn run(&self, ctx: &ScanContext) -> DetectorResult {
        let report = ctx.get_report();
        let biz_findings: Vec<Finding> = report
            .findings
            .iter()
            .filter(|f| f.detector_id == "biz-concurrency")
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
            findings: biz_findings,
            receipt,
            rules_run,
        }
    }
}
