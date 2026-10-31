use super::{DetectorResult, ScanContext, SecurityDetector};
use crate::types::*;
use chrono::Utc;

pub struct TaintSastDetector;

impl SecurityDetector for TaintSastDetector {
    fn id(&self) -> &'static str {
        "taint-sast"
    }

    fn name(&self) -> &'static str {
        "AST Dataflow & Taint SAST Detector"
    }

    fn supported_rule_ids(&self) -> &[&'static str] {
        &[
            "BK-AI-INJ-001",
            "BK-AI-INJ-003",
            "BK-AI-INJ-006",
            "BK-AI-INJ-007",
            "BK-AI-FIL-001",
            "BK-AI-FIL-002",
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
        let mut rules_run = Vec::new();
        for id in self.supported_rule_ids() {
            rules_run.push(id.to_string());
        }

        let receipt = CoverageReceipt {
            scanner_id: self.id().to_string(),
            scanner_version: env!("CARGO_PKG_VERSION").to_string(),
            target_id: ctx.root.display().to_string(),
            status: report.coverage.coverage_status,
            items_examined: report.total_files_scanned as u64,
            skipped_reasons: Vec::new(),
            errors: report
                .coverage
                .parser_failures
                .iter()
                .map(|f| format!("{}: {}", f.path.display(), f.reason))
                .collect(),
            completed_at: Utc::now().to_rfc3339(),
        };

        DetectorResult {
            findings: report.findings.clone(),
            receipt,
            rules_run,
        }
    }
}

pub struct InjectionSecurityDetector;

impl SecurityDetector for InjectionSecurityDetector {
    fn id(&self) -> &'static str {
        "injection-security"
    }

    fn name(&self) -> &'static str {
        "YAML Expression Injection & ReDoS Security Detector"
    }

    fn supported_rule_ids(&self) -> &[&'static str] {
        &["BK-AI-INJ-014", "BK-AI-INJ-015"]
    }

    fn supported_languages(&self) -> &[&'static str] {
        &["yaml", "javascript", "typescript", "python"]
    }

    fn supported_targets(&self) -> &[TargetKind] {
        &[
            TargetKind::GenericConfigFile,
            TargetKind::GenericSourceFile,
            TargetKind::NodeSourceFile,
        ]
    }

    fn run(&self, ctx: &ScanContext) -> DetectorResult {
        let report = ctx.get_report();
        let injection_findings: Vec<Finding> = report
            .findings
            .iter()
            .filter(|f| f.detector_id == "injection-security")
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
            findings: injection_findings,
            receipt,
            rules_run,
        }
    }
}

pub struct ParserSecurityDetector;

impl SecurityDetector for ParserSecurityDetector {
    fn id(&self) -> &'static str {
        "parser-security"
    }

    fn name(&self) -> &'static str {
        "Parsers, Deserialization & Cryptography Security Detector"
    }

    fn supported_rule_ids(&self) -> &[&'static str] {
        &[
            "BK-AI-PAR-001",
            "BK-AI-PAR-002",
            "BK-AI-PAR-003",
            "BK-AI-PAR-004",
            "BK-AI-PAR-005",
            "BK-AI-PAR-006",
            "BK-AI-PAR-007",
            "BK-AI-PAR-008",
            "BK-AI-PAR-009",
            "BK-AI-PAR-010",
            "BK-AI-PAR-011",
            "BK-AI-PAR-012",
            "BK-AI-CRY-004",
            "BK-AI-CRY-005",
            "BK-AI-CRY-006",
            "BK-AI-CRY-007",
            "BK-AI-CRY-008",
            "BK-AI-CRY-009",
            "BK-AI-CRY-010",
            "BK-AI-CRY-011",
            "BK-AI-CRY-012",
        ]
    }

    fn supported_languages(&self) -> &[&'static str] {
        &["javascript", "typescript", "python", "php", "generic"]
    }

    fn supported_targets(&self) -> &[TargetKind] {
        &[TargetKind::GenericSourceFile, TargetKind::NodeSourceFile]
    }

    fn run(&self, ctx: &ScanContext) -> DetectorResult {
        let report = ctx.get_report();
        let parser_findings: Vec<Finding> = report
            .findings
            .iter()
            .filter(|f| f.detector_id == "parser-security")
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
            findings: parser_findings,
            receipt,
            rules_run,
        }
    }
}

pub struct LanguagePitfallsDetector;

impl SecurityDetector for LanguagePitfallsDetector {
    fn id(&self) -> &'static str {
        "language-pitfalls"
    }

    fn name(&self) -> &'static str {
        "Language & Runtime Specific Red Flags Security Detector"
    }

    fn supported_rule_ids(&self) -> &[&'static str] {
        &[
            "BK-AI-LNG-001",
            "BK-AI-LNG-002",
            "BK-AI-LNG-003",
            "BK-AI-LNG-004",
            "BK-AI-LNG-005",
            "BK-AI-LNG-006",
            "BK-AI-LNG-007",
            "BK-AI-LNG-008",
            "BK-AI-LNG-009",
            "BK-AI-LNG-010",
            "BK-AI-LNG-011",
            "BK-AI-LNG-012",
            "BK-AI-LNG-013",
            "BK-AI-LNG-014",
            "BK-AI-LNG-015",
            "BK-AI-LNG-016",
            "BK-AI-LNG-017",
            "BK-AI-LNG-018",
            "BK-AI-LNG-019",
            "BK-AI-LNG-020",
            "BK-AI-LNG-021",
            "BK-AI-LNG-022",
            "BK-AI-LNG-023",
            "BK-AI-LNG-024",
            "BK-AI-LNG-025",
            "BK-AI-LNG-026",
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
            "java",
            "c",
            "cpp",
            "ruby",
            "dotnet",
            "generic",
        ]
    }

    fn supported_targets(&self) -> &[TargetKind] {
        &[TargetKind::GenericSourceFile, TargetKind::NodeSourceFile]
    }

    fn run(&self, ctx: &ScanContext) -> DetectorResult {
        let report = ctx.get_report();
        let findings: Vec<Finding> = report
            .findings
            .iter()
            .filter(|f| f.detector_id == "language-pitfalls")
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

pub struct MemTempDetector;

impl SecurityDetector for MemTempDetector {
    fn id(&self) -> &'static str {
        "mem-temp"
    }

    fn name(&self) -> &'static str {
        "Memory Safety & Insecure Temp File Detector"
    }

    fn supported_rule_ids(&self) -> &[&'static str] {
        &[
            "BK-AI-MEM-001",
            "BK-AI-MEM-002",
            "BK-AI-MEM-003",
            "BK-AI-FIL-008",
        ]
    }

    fn supported_languages(&self) -> &[&'static str] {
        &[
            "c",
            "cpp",
            "rust",
            "zig",
            "javascript",
            "typescript",
            "python",
            "generic",
        ]
    }

    fn supported_targets(&self) -> &[TargetKind] {
        &[TargetKind::GenericSourceFile, TargetKind::NodeSourceFile]
    }

    fn run(&self, ctx: &ScanContext) -> DetectorResult {
        let report = ctx.get_report();
        let findings: Vec<Finding> = report
            .findings
            .iter()
            .filter(|f| f.detector_id == "mem-temp")
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
