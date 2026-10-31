use super::{DetectorResult, ScanContext, SecurityDetector};
use crate::types::*;
use chrono::Utc;

pub struct WebSecurityDetector;

impl SecurityDetector for WebSecurityDetector {
    fn id(&self) -> &'static str {
        "web-security"
    }

    fn name(&self) -> &'static str {
        "Web & Frontend Security Detector"
    }

    fn supported_rule_ids(&self) -> &[&'static str] {
        &[
            "BK-AI-WEB-001",
            "BK-AI-WEB-002",
            "BK-AI-WEB-003",
            "BK-AI-WEB-004",
            "BK-AI-WEB-005",
            "BK-AI-WEB-006",
            "BK-AI-WEB-007",
            "BK-AI-WEB-008",
            "BK-AI-WEB-009",
            "BK-AI-WEB-010",
            "BK-AI-WEB-011",
            "BK-AI-WEB-012",
            "BK-AI-WEB-013",
            "BK-AI-WEB-014",
            "BK-AI-WEB-015",
        ]
    }

    fn supported_languages(&self) -> &[&'static str] {
        &["javascript", "typescript", "html", "python", "php"]
    }

    fn supported_targets(&self) -> &[TargetKind] {
        &[TargetKind::GenericSourceFile, TargetKind::NodeSourceFile]
    }

    fn run(&self, ctx: &ScanContext) -> DetectorResult {
        let report = ctx.get_report();
        let web_findings: Vec<Finding> = report
            .findings
            .iter()
            .filter(|f| f.detector_id == "web-security")
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
            findings: web_findings,
            receipt,
            rules_run,
        }
    }
}

pub struct ApiSecurityDetector;

impl SecurityDetector for ApiSecurityDetector {
    fn id(&self) -> &'static str {
        "api-security"
    }

    fn name(&self) -> &'static str {
        "HTTP API, GraphQL & Realtime Security Detector"
    }

    fn supported_rule_ids(&self) -> &[&'static str] {
        &[
            "BK-AI-API-001",
            "BK-AI-API-002",
            "BK-AI-API-003",
            "BK-AI-API-004",
            "BK-AI-API-005",
            "BK-AI-API-006",
            "BK-AI-API-007",
            "BK-AI-API-008",
            "BK-AI-API-009",
            "BK-AI-API-010",
            "BK-AI-API-011",
            "BK-AI-API-012",
            "BK-AI-API-013",
            "BK-AI-API-014",
        ]
    }

    fn supported_languages(&self) -> &[&'static str] {
        &["javascript", "typescript", "python", "go"]
    }

    fn supported_targets(&self) -> &[TargetKind] {
        &[TargetKind::GenericSourceFile, TargetKind::NodeSourceFile]
    }

    fn run(&self, ctx: &ScanContext) -> DetectorResult {
        let report = ctx.get_report();
        let api_findings: Vec<Finding> = report
            .findings
            .iter()
            .filter(|f| f.detector_id == "api-security")
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
            findings: api_findings,
            receipt,
            rules_run,
        }
    }
}

pub struct NetworkDosDetector;

impl SecurityDetector for NetworkDosDetector {
    fn id(&self) -> &'static str {
        "network-dos"
    }

    fn name(&self) -> &'static str {
        "Network, SSRF & Denial of Service Security Detector"
    }

    fn supported_rule_ids(&self) -> &[&'static str] {
        &[
            "BK-AI-NET-001",
            "BK-AI-NET-002",
            "BK-AI-NET-003",
            "BK-AI-NET-004",
            "BK-AI-NET-005",
            "BK-AI-NET-006",
            "BK-AI-NET-007",
            "BK-AI-NET-008",
            "BK-AI-NET-009",
            "BK-AI-NET-010",
            "BK-AI-DOS-001",
            "BK-AI-DOS-002",
            "BK-AI-DOS-003",
            "BK-AI-DOS-004",
            "BK-AI-DOS-005",
            "BK-AI-DOS-006",
            "BK-AI-DOS-007",
            "BK-AI-DOS-008",
            "BK-AI-DOS-009",
            "BK-AI-DOS-010",
            "BK-AI-DOS-011",
            "BK-AI-DOS-012",
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
        let net_findings: Vec<Finding> = report
            .findings
            .iter()
            .filter(|f| f.detector_id == "network-dos")
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
            findings: net_findings,
            receipt,
            rules_run,
        }
    }
}
