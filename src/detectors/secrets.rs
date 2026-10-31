use super::{DetectorResult, ScanContext, SecurityDetector};
use crate::types::*;
use chrono::Utc;

pub struct SecretDetector;

impl SecurityDetector for SecretDetector {
    fn id(&self) -> &'static str {
        "secret-detector"
    }

    fn name(&self) -> &'static str {
        "Hardcoded Secrets & Credential Leakage Detector"
    }

    fn supported_rule_ids(&self) -> &[&'static str] {
        &[
            "BK-AI-SEC-001",
            "BK-AI-SEC-002",
            "BK-AI-SEC-003",
            "BK-AI-SEC-004",
            "BK-AI-SEC-010",
        ]
    }

    fn supported_languages(&self) -> &[&'static str] {
        &["generic", "dockerfile"]
    }

    fn supported_targets(&self) -> &[TargetKind] {
        &[
            TargetKind::GenericSourceFile,
            TargetKind::GenericConfigFile,
            TargetKind::Dockerfile,
            TargetKind::EnvironmentFile,
        ]
    }

    fn run(&self, ctx: &ScanContext) -> DetectorResult {
        let report = ctx.get_report();
        let secret_findings: Vec<Finding> = report
            .findings
            .iter()
            .filter(|f| f.detector_id == "secret-detector")
            .cloned()
            .collect();

        let rules_run = self
            .supported_rule_ids()
            .iter()
            .map(|s| s.to_string())
            .collect();
        let errors: Vec<String> = report
            .coverage
            .parser_failures
            .iter()
            .map(|failure| format!("{}: {}", failure.path.display(), failure.reason))
            .collect();
        let complete = report.coverage.is_complete();
        let receipt = CoverageReceipt {
            scanner_id: self.id().to_string(),
            scanner_version: env!("CARGO_PKG_VERSION").to_string(),
            target_id: ctx.root.display().to_string(),
            status: if complete {
                CoverageStatus::Complete
            } else {
                CoverageStatus::Partial
            },
            items_examined: report.total_files_scanned as u64,
            skipped_reasons: if report.coverage.files_excluded > 0 {
                vec![format!(
                    "{} files excluded from scan",
                    report.coverage.files_excluded
                )]
            } else {
                Vec::new()
            },
            errors: if !complete && errors.is_empty() {
                vec![format!(
                    "Underlying scan coverage is {:?}",
                    report.coverage.coverage_status
                )]
            } else {
                errors
            },
            completed_at: Utc::now().to_rfc3339(),
        };

        DetectorResult {
            findings: secret_findings,
            receipt,
            rules_run,
        }
    }
}

pub struct CryptoWeaknessDetector;

impl SecurityDetector for CryptoWeaknessDetector {
    fn id(&self) -> &'static str {
        "crypto-weakness"
    }

    fn name(&self) -> &'static str {
        "Cryptographic Weakness (Hash/Cipher/IV) Security Detector"
    }

    fn supported_rule_ids(&self) -> &[&'static str] {
        &["BK-AI-CRY-001", "BK-AI-CRY-002", "BK-AI-CRY-003"]
    }

    fn supported_languages(&self) -> &[&'static str] {
        &["javascript", "typescript", "python", "go", "rust"]
    }

    fn supported_targets(&self) -> &[TargetKind] {
        &[TargetKind::GenericSourceFile, TargetKind::NodeSourceFile]
    }

    fn run(&self, ctx: &ScanContext) -> DetectorResult {
        let report = ctx.get_report();
        let crypto_findings: Vec<Finding> = report
            .findings
            .iter()
            .filter(|f| f.detector_id == "crypto-weakness")
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
            findings: crypto_findings,
            receipt,
            rules_run,
        }
    }
}

pub struct DataPrivacyDetector;

impl SecurityDetector for DataPrivacyDetector {
    fn id(&self) -> &'static str {
        "data-privacy"
    }

    fn name(&self) -> &'static str {
        "Data Privacy, Storage & Database Security Detector"
    }

    fn supported_rule_ids(&self) -> &[&'static str] {
        &[
            "BK-AI-SEC-005",
            "BK-AI-SEC-006",
            "BK-AI-SEC-007",
            "BK-AI-SEC-008",
            "BK-AI-SEC-009",
            "BK-AI-SEC-011",
            "BK-AI-SEC-012",
            "BK-AI-DAT-001",
            "BK-AI-DAT-002",
            "BK-AI-DAT-003",
            "BK-AI-DAT-004",
            "BK-AI-DAT-005",
            "BK-AI-DAT-006",
            "BK-AI-DAT-007",
            "BK-AI-DAT-008",
            "BK-AI-DAT-009",
            "BK-AI-DAT-010",
            "BK-AI-DAT-011",
            "BK-AI-DAT-012",
        ]
    }

    fn supported_languages(&self) -> &[&'static str] {
        &["javascript", "typescript", "python", "go", "generic"]
    }

    fn supported_targets(&self) -> &[TargetKind] {
        &[TargetKind::GenericSourceFile, TargetKind::NodeSourceFile]
    }

    fn run(&self, ctx: &ScanContext) -> DetectorResult {
        let report = ctx.get_report();
        let privacy_findings: Vec<Finding> = report
            .findings
            .iter()
            .filter(|f| f.detector_id == "data-privacy")
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
            findings: privacy_findings,
            receipt,
            rules_run,
        }
    }
}
