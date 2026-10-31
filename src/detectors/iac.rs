use super::{DetectorResult, ScanContext, SecurityDetector};
use crate::types::*;
use chrono::Utc;

pub struct CicdSecurityDetector;

impl SecurityDetector for CicdSecurityDetector {
    fn id(&self) -> &'static str {
        "cicd-security"
    }

    fn name(&self) -> &'static str {
        "CI/CD Pipeline & GitHub Actions Security Detector"
    }

    fn supported_rule_ids(&self) -> &[&'static str] {
        &[
            "BK-AI-CIC-001",
            "BK-AI-CIC-002",
            "BK-AI-CIC-003",
            "BK-AI-CIC-004",
            "BK-AI-CIC-006",
        ]
    }

    fn supported_languages(&self) -> &[&'static str] {
        &["yaml"]
    }

    fn supported_targets(&self) -> &[TargetKind] {
        &[TargetKind::GenericConfigFile]
    }

    fn run(&self, ctx: &ScanContext) -> DetectorResult {
        let report = ctx.get_report();
        let cicd_findings: Vec<Finding> = report
            .findings
            .iter()
            .filter(|f| f.detector_id == "cicd-security")
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
            findings: cicd_findings,
            receipt,
            rules_run,
        }
    }
}

pub struct ContainerIacDetector;

impl SecurityDetector for ContainerIacDetector {
    fn id(&self) -> &'static str {
        "container-iac"
    }

    fn name(&self) -> &'static str {
        "Containerfile & Infrastructure-as-Code Security Detector"
    }

    fn supported_rule_ids(&self) -> &[&'static str] {
        &[
            "BK-AI-INF-001",
            "BK-AI-INF-003",
            "BK-AI-INF-004",
            "BK-AI-INF-007",
            "BK-AI-INF-008",
            "BK-AI-INF-010",
        ]
    }

    fn supported_languages(&self) -> &[&'static str] {
        &["dockerfile"]
    }

    fn supported_targets(&self) -> &[TargetKind] {
        &[TargetKind::Dockerfile]
    }

    fn run(&self, ctx: &ScanContext) -> DetectorResult {
        let report = ctx.get_report();
        let container_findings: Vec<Finding> = report
            .findings
            .iter()
            .filter(|f| f.target_kind == TargetKind::Dockerfile)
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
            findings: container_findings,
            receipt,
            rules_run,
        }
    }
}

pub struct IacSecurityDetector;

impl SecurityDetector for IacSecurityDetector {
    fn id(&self) -> &'static str {
        "iac-security"
    }

    fn name(&self) -> &'static str {
        "Infrastructure, Cloud & CI/CD Security Detector"
    }

    fn supported_rule_ids(&self) -> &[&'static str] {
        &[
            "BK-AI-INF-002",
            "BK-AI-INF-005",
            "BK-AI-INF-006",
            "BK-AI-INF-009",
            "BK-AI-INF-011",
            "BK-AI-INF-012",
            "BK-AI-INF-013",
            "BK-AI-INF-014",
            "BK-AI-INF-015",
            "BK-AI-INF-016",
            "BK-AI-CIC-005",
            "BK-AI-CIC-007",
            "BK-AI-CIC-008",
            "BK-AI-CIC-009",
            "BK-AI-CIC-010",
            "BK-AI-CIC-011",
            "BK-AI-CIC-012",
            "BK-AI-CIC-013",
            "BK-AI-CIC-014",
        ]
    }

    fn supported_languages(&self) -> &[&'static str] {
        &["yaml", "dockerfile", "generic"]
    }

    fn supported_targets(&self) -> &[TargetKind] {
        &[
            TargetKind::Dockerfile,
            TargetKind::GenericConfigFile,
            TargetKind::GenericSourceFile,
        ]
    }

    fn run(&self, ctx: &ScanContext) -> DetectorResult {
        let report = ctx.get_report();
        let iac_findings: Vec<Finding> = report
            .findings
            .iter()
            .filter(|f| f.detector_id == "iac-security")
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
            findings: iac_findings,
            receipt,
            rules_run,
        }
    }
}

pub struct NativeDesktopDetector;

impl SecurityDetector for NativeDesktopDetector {
    fn id(&self) -> &'static str {
        "native-desktop"
    }

    fn name(&self) -> &'static str {
        "Native Memory Safety & Mobile/Desktop Security Detector"
    }

    fn supported_rule_ids(&self) -> &[&'static str] {
        &[
            "BK-AI-MEM-004",
            "BK-AI-MEM-005",
            "BK-AI-MEM-006",
            "BK-AI-MEM-007",
            "BK-AI-MEM-008",
            "BK-AI-MEM-009",
            "BK-AI-MEM-010",
            "BK-AI-MEM-011",
            "BK-AI-MEM-012",
            "BK-AI-MOB-001",
            "BK-AI-MOB-002",
            "BK-AI-MOB-003",
            "BK-AI-MOB-004",
            "BK-AI-MOB-005",
            "BK-AI-MOB-006",
            "BK-AI-MOB-007",
            "BK-AI-MOB-008",
            "BK-AI-MOB-009",
            "BK-AI-MOB-010",
            "BK-AI-AIC-004",
            "BK-AI-LLM-019",
            "BK-AI-LLM-021",
        ]
    }

    fn supported_languages(&self) -> &[&'static str] {
        &[
            "c",
            "cpp",
            "rust",
            "zig",
            "swift",
            "kotlin",
            "java",
            "javascript",
            "typescript",
            "python",
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
            .filter(|f| f.detector_id == "native-desktop")
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
