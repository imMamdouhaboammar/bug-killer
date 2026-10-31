use super::{DetectorResult, ScanContext, SecurityDetector};
use crate::osv::OsvClient;
use crate::types::*;
use chrono::Utc;

pub struct OsvScaDetector;

impl SecurityDetector for OsvScaDetector {
    fn id(&self) -> &'static str {
        "osv-sca"
    }

    fn name(&self) -> &'static str {
        "Multi-Ecosystem Software Composition Analysis (OSV) Detector"
    }

    fn supported_rule_ids(&self) -> &[&'static str] {
        &["BK-AI-SCA-001", "BK-AI-SCA-002", "BK-AI-SCA-005"]
    }

    fn supported_languages(&self) -> &[&'static str] {
        &[
            "javascript",
            "typescript",
            "php",
            "python",
            "rust",
            "go",
            "java",
            "csharp",
            "ruby",
        ]
    }

    fn supported_targets(&self) -> &[TargetKind] {
        &[
            TargetKind::NodePackageManifest,
            TargetKind::NodeLockfile,
            TargetKind::ComposerManifest,
            TargetKind::ComposerLockfile,
            TargetKind::CargoLockManifest,
            TargetKind::GoModManifest,
            TargetKind::JavaPomManifest,
            TargetKind::DotnetCsprojManifest,
            TargetKind::RubyGemfileManifest,
            TargetKind::PythonPoetryManifest,
            TargetKind::CycloneDxSbom,
            TargetKind::SpdxSbom,
        ]
    }

    fn run(&self, ctx: &ScanContext) -> DetectorResult {
        let (findings, receipt) = if ctx.enable_network_osv {
            let osv_client = OsvClient::new();
            osv_client.scan_workspace_with_receipt(&ctx.root)
        } else {
            let receipt = CoverageReceipt {
                scanner_id: self.id().to_string(),
                scanner_version: env!("CARGO_PKG_VERSION").to_string(),
                target_id: ctx.root.display().to_string(),
                status: CoverageStatus::NotRun,
                items_examined: 0,
                skipped_reasons: vec![
                    "Network OSV lookup disabled for offline profile".to_string(),
                ],
                errors: Vec::new(),
                completed_at: Utc::now().to_rfc3339(),
            };
            (Vec::new(), receipt)
        };

        let rules_run = self
            .supported_rule_ids()
            .iter()
            .map(|s| s.to_string())
            .collect();
        DetectorResult {
            findings,
            receipt,
            rules_run,
        }
    }
}

pub struct SupplyChainDetector;

impl SecurityDetector for SupplyChainDetector {
    fn id(&self) -> &'static str {
        "supply-chain-security"
    }

    fn name(&self) -> &'static str {
        "Supply Chain, Dependency Resolution & Agent Supply Security Detector"
    }

    fn supported_rule_ids(&self) -> &[&'static str] {
        &[
            "BK-AI-SCA-003",
            "BK-AI-SCA-004",
            "BK-AI-SCA-006",
            "BK-AI-SCA-007",
            "BK-AI-SCA-008",
            "BK-AI-SCA-009",
            "BK-AI-SCA-010",
            "BK-AI-SCA-011",
            "BK-AI-SCA-012",
            "BK-AI-SCA-013",
            "BK-AI-SCA-014",
            "BK-AI-AGS-001",
            "BK-AI-AGS-002",
            "BK-AI-AGS-003",
            "BK-AI-AGS-004",
            "BK-AI-AGS-005",
            "BK-AI-AGS-006",
            "BK-AI-AGS-007",
            "BK-AI-AGS-008",
            "BK-AI-AGS-009",
            "BK-AI-AGS-010",
            "BK-AI-AGS-011",
            "BK-AI-AGS-012",
        ]
    }

    fn supported_languages(&self) -> &[&'static str] {
        &[
            "javascript",
            "typescript",
            "python",
            "rust",
            "go",
            "generic",
        ]
    }

    fn supported_targets(&self) -> &[TargetKind] {
        &[
            TargetKind::NodePackageManifest,
            TargetKind::GenericConfigFile,
            TargetKind::GenericSourceFile,
        ]
    }

    fn run(&self, ctx: &ScanContext) -> DetectorResult {
        let report = ctx.get_report();
        let sca_findings: Vec<Finding> = report
            .findings
            .iter()
            .filter(|f| f.detector_id == "supply-chain-security")
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
            findings: sca_findings,
            receipt,
            rules_run,
        }
    }
}
