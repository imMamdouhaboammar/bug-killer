#![allow(dead_code)]

use crate::catalog::SecurityCatalog;
use crate::osv::OsvClient;
use crate::scanner::FleetScanner;
use crate::types::*;
use chrono::Utc;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Context provided to a detector during execution.
#[derive(Clone)]
pub struct ScanContext {
    pub root: PathBuf,
    pub profile: ScanProfile,
    pub changed_files: Option<Vec<PathBuf>>,
    pub enable_network_osv: bool,
    pub cached_report: Option<Arc<ScanReport>>,
}

impl ScanContext {
    pub fn get_report(&self) -> Arc<ScanReport> {
        if let Some(ref r) = self.cached_report {
            r.clone()
        } else {
            Arc::new(FleetScanner::scan_directory(&self.root, false))
        }
    }
}

/// Output result produced by an individual detector execution.
#[derive(Debug, Clone)]
pub struct DetectorResult {
    pub findings: Vec<Finding>,
    pub receipt: CoverageReceipt,
    pub rules_run: Vec<String>,
}

/// Common interface that all security detectors must implement.
pub trait SecurityDetector: Send + Sync {
    /// Machine-readable identifier for the detector (e.g. "taint-sast").
    fn id(&self) -> &'static str;

    /// Human-readable display name for the detector.
    fn name(&self) -> &'static str;

    /// List of catalog rule IDs evaluated by this detector.
    fn supported_rule_ids(&self) -> &[&'static str];

    /// List of programming languages or frameworks supported by this detector.
    fn supported_languages(&self) -> &[&'static str];

    /// Target kinds analyzed by this detector.
    fn supported_targets(&self) -> &[TargetKind];

    /// Filesystem and network permissions required by this detector.
    fn required_permissions(&self) -> &'static str {
        "READ_ONLY_WORKSPACE"
    }

    /// Executes the detector against the provided scan context.
    fn run(&self, ctx: &ScanContext) -> DetectorResult;
}

// ---------------- Concrete Detector Implementations ----------------

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
            findings: secret_findings,
            receipt,
            rules_run,
        }
    }
}

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

pub struct AgentSkillDetector;

impl SecurityDetector for AgentSkillDetector {
    fn id(&self) -> &'static str {
        "agent-skill"
    }

    fn name(&self) -> &'static str {
        "AI Agent Skill & MCP Configuration Security Detector"
    }

    fn supported_rule_ids(&self) -> &[&'static str] {
        &[
            "BK-AI-LLM-001",
            "BK-AI-LLM-003",
            "BK-AI-LLM-004",
            "BK-AI-LLM-008",
            "BK-AI-LLM-014",
            "BK-AI-LLM-017",
        ]
    }

    fn supported_languages(&self) -> &[&'static str] {
        &["markdown", "json", "python", "javascript", "typescript"]
    }

    fn supported_targets(&self) -> &[TargetKind] {
        &[
            TargetKind::AgentSkillManifest,
            TargetKind::McpServerConfig,
            TargetKind::GenericConfigFile,
            TargetKind::GenericSourceFile,
            TargetKind::NodeSourceFile,
        ]
    }

    fn run(&self, ctx: &ScanContext) -> DetectorResult {
        let report = ctx.get_report();
        let agent_findings: Vec<Finding> = report
            .findings
            .iter()
            .filter(|f| {
                f.detector_id == "agent-security-scanner"
                    || f.detector_id == "agent-skill-scanner"
                    || f.detector_id == "agent-mcp-scanner"
                    || f.target_kind == TargetKind::AgentSkillManifest
                    || f.target_kind == TargetKind::McpServerConfig
            })
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
            findings: agent_findings,
            receipt,
            rules_run,
        }
    }
}

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

pub struct DynamicRulesDetector;

impl SecurityDetector for DynamicRulesDetector {
    fn id(&self) -> &'static str {
        "dynamic-rules"
    }

    fn name(&self) -> &'static str {
        "Pluggable Dynamic Vulnerability Rules Engine"
    }

    fn supported_rule_ids(&self) -> &[&'static str] {
        &[
            "CVE-2024-5480",
            "CVE-2023-44487",
            "SEC-001-EXPOSED-ENV-SECRETS",
            "SEC-002-PYTHON-UNSAFE-EVAL",
        ]
    }

    fn supported_languages(&self) -> &[&'static str] {
        &[
            "generic",
            "python",
            "nginx",
            "javascript",
            "typescript",
            "go",
            "php",
        ]
    }

    fn supported_targets(&self) -> &[TargetKind] {
        &[TargetKind::GenericSourceFile, TargetKind::NginxConfig]
    }

    fn run(&self, ctx: &ScanContext) -> DetectorResult {
        let rules = crate::rules::RuleEngine::load_rules(None, &ctx.root);
        let mut rules_run: Vec<String> = self
            .supported_rule_ids()
            .iter()
            .map(|s| s.to_string())
            .collect();
        for r in &rules {
            if !rules_run.contains(&r.id) {
                rules_run.push(r.id.clone());
            }
        }

        let report = FleetScanner::scan_directory_with_rules(&ctx.root, false, &rules);
        let dynamic_findings: Vec<Finding> = report
            .findings
            .into_iter()
            .filter(|f| f.detector_id == "dynamic-rules")
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
            findings: dynamic_findings,
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

pub struct AiAgentExtDetector;

impl SecurityDetector for AiAgentExtDetector {
    fn id(&self) -> &'static str {
        "ai-agent-ext"
    }

    fn name(&self) -> &'static str {
        "LLM, Autonomous Agent & AI Assistant Flaws Security Detector"
    }

    fn supported_rule_ids(&self) -> &[&'static str] {
        &[
            "BK-AI-LLM-002",
            "BK-AI-LLM-005",
            "BK-AI-LLM-006",
            "BK-AI-LLM-007",
            "BK-AI-LLM-008",
            "BK-AI-LLM-009",
            "BK-AI-LLM-010",
            "BK-AI-LLM-011",
            "BK-AI-LLM-012",
            "BK-AI-LLM-013",
            "BK-AI-LLM-014",
            "BK-AI-LLM-015",
            "BK-AI-LLM-016",
            "BK-AI-LLM-018",
            "BK-AI-LLM-020",
            "BK-AI-LLM-022",
            "BK-AI-AIC-001",
            "BK-AI-AIC-002",
            "BK-AI-AIC-003",
            "BK-AI-AIC-005",
            "BK-AI-AIC-006",
            "BK-AI-AIC-007",
            "BK-AI-AIC-008",
            "BK-AI-AIC-009",
            "BK-AI-AIC-010",
            "BK-AI-AIC-011",
            "BK-AI-AIC-012",
            "BK-AI-AIC-013",
            "BK-AI-AIC-014",
            "BK-AI-AIC-015",
            "BK-AI-AIC-016",
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
            TargetKind::AgentSkillManifest,
        ]
    }

    fn run(&self, ctx: &ScanContext) -> DetectorResult {
        let report = ctx.get_report();
        let agent_findings: Vec<Finding> = report
            .findings
            .iter()
            .filter(|f| f.detector_id == "ai-agent-ext")
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
            findings: agent_findings,
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

// ---------------- Detector Registry ----------------

pub struct DetectorRegistry {
    detectors: Vec<Arc<dyn SecurityDetector>>,
}

impl Default for DetectorRegistry {
    fn default() -> Self {
        let mut reg = Self {
            detectors: Vec::new(),
        };
        reg.register(Arc::new(TaintSastDetector));
        reg.register(Arc::new(SecretDetector));
        reg.register(Arc::new(CicdSecurityDetector));
        reg.register(Arc::new(ContainerIacDetector));
        reg.register(Arc::new(AgentSkillDetector));
        reg.register(Arc::new(OsvScaDetector));
        reg.register(Arc::new(DynamicRulesDetector));
        reg.register(Arc::new(InjectionSecurityDetector));
        reg.register(Arc::new(CryptoWeaknessDetector));
        reg.register(Arc::new(WebSecurityDetector));
        reg.register(Arc::new(ApiSecurityDetector));
        reg.register(Arc::new(AuthSecurityDetector));
        reg.register(Arc::new(AuthzSecurityDetector));
        reg.register(Arc::new(FilesystemExtDetector));
        reg.register(Arc::new(DataPrivacyDetector));
        reg.register(Arc::new(ParserSecurityDetector));
        reg.register(Arc::new(NetworkDosDetector));
        reg.register(Arc::new(IacSecurityDetector));
        reg.register(Arc::new(SupplyChainDetector));
        reg.register(Arc::new(BizConcurrencyDetector));
        reg.register(Arc::new(AiAgentExtDetector));
        reg.register(Arc::new(LanguagePitfallsDetector));
        reg.register(Arc::new(OpsQaDetector));
        reg.register(Arc::new(NativeDesktopDetector));
        reg.register(Arc::new(MemTempDetector));
        reg
    }
}

impl DetectorRegistry {
    pub fn new() -> Self {
        Self {
            detectors: Vec::new(),
        }
    }

    pub fn register(&mut self, detector: Arc<dyn SecurityDetector>) {
        self.detectors.push(detector);
    }

    pub fn all_detectors(&self) -> &[Arc<dyn SecurityDetector>] {
        &self.detectors
    }

    pub fn supported_rule_ids(&self) -> HashSet<String> {
        let mut ids = HashSet::new();
        for d in &self.detectors {
            for id in d.supported_rule_ids() {
                ids.insert(id.to_string());
            }
        }
        ids
    }

    /// Discovers active languages and target kinds in the workspace root.
    pub fn discover_workspace_languages(&self, root: &Path) -> HashSet<String> {
        let mut langs = HashSet::new();
        langs.insert("generic".to_string());

        let entries = walkdir::WalkDir::new(root)
            .max_depth(5)
            .into_iter()
            .filter_entry(|entry| {
                entry.depth() == 0
                    || !matches!(
                        entry.file_name().to_str(),
                        Some(
                            ".git" | "node_modules" | "vendor" | "target" | ".aegis" | ".bugkiller"
                        )
                    )
            })
            .filter_map(Result::ok);
        {
            for entry in entries {
                if !entry.file_type().is_file() {
                    continue;
                }
                let name = entry.file_name().to_string_lossy();
                if name.ends_with(".js") || name.ends_with(".mjs") || name == "package.json" {
                    langs.insert("javascript".to_string());
                }
                if name.ends_with(".ts") || name.ends_with(".tsx") {
                    langs.insert("typescript".to_string());
                }
                if name.ends_with(".py") || name == "requirements.txt" || name == "pyproject.toml" {
                    langs.insert("python".to_string());
                }
                if name.ends_with(".php") || name == "composer.json" {
                    langs.insert("php".to_string());
                }
                if name.ends_with(".go") || name == "go.mod" {
                    langs.insert("go".to_string());
                }
                if name.ends_with(".rs") || name == "Cargo.toml" {
                    langs.insert("rust".to_string());
                }
                if name == "Dockerfile"
                    || name.starts_with("Dockerfile.")
                    || name == "Containerfile"
                {
                    langs.insert("dockerfile".to_string());
                }
                if entry.path().to_string_lossy().contains(".github")
                    && (name.ends_with(".yml") || name.ends_with(".yaml"))
                {
                    langs.insert("yaml".to_string());
                }
                if name == "SKILL.md" || name.ends_with(".skill") {
                    langs.insert("markdown".to_string());
                }
            }
        }

        langs
    }

    /// Executes complete security guard scan producing an honest, typed `SecurityGuardReport`.
    pub fn execute_guard_scan(
        &self,
        root: &Path,
        profile: ScanProfile,
        changed_files: Option<Vec<PathBuf>>,
        enable_network_osv: bool,
    ) -> SecurityGuardReport {
        let scan_start = Utc::now();
        let catalog = SecurityCatalog::global();
        let detected_languages = self.discover_workspace_languages(root);
        let supported_rule_set = self.supported_rule_ids();

        // 1. Classify applicable rules from catalog vs unsupported rules
        let mut applicable_rules = Vec::new();
        let mut unsupported_rules = Vec::new();

        for rule in catalog.all_rules() {
            let is_applicable = rule
                .applicable_languages
                .iter()
                .any(|l| detected_languages.contains(l));

            if is_applicable {
                applicable_rules.push(rule.rule_id.clone());
                if !supported_rule_set.contains(&rule.rule_id) {
                    unsupported_rules.push(rule.rule_id.clone());
                }
            }
        }

        // 2. Execute detectors
        let base_report = Arc::new(FleetScanner::scan_directory_with_rules_and_taint(
            root,
            false,
            &[],
            true,
        ));
        let ctx = ScanContext {
            root: root.to_path_buf(),
            profile,
            changed_files,
            enable_network_osv,
            cached_report: Some(base_report.clone()),
        };

        let mut all_findings = Vec::new();
        let mut rules_evaluated = HashSet::new();
        let mut receipts = Vec::new();
        let mut unexamined_reasons = Vec::new();

        all_findings.extend(base_report.findings.clone());

        for detector in &self.detectors {
            let result = detector.run(&ctx);
            for r in result.rules_run {
                rules_evaluated.insert(r);
            }
            all_findings.extend(result.findings);
            receipts.push(result.receipt);
        }

        // Deduplicate findings
        all_findings.sort_by(|a, b| {
            (&a.id, &a.file_path, a.line_number).cmp(&(&b.id, &b.file_path, b.line_number))
        });
        all_findings.dedup_by(|a, b| {
            a.id == b.id && a.file_path == b.file_path && a.line_number == b.line_number
        });

        if let Some(changed) = &ctx.changed_files {
            let changed_paths: HashSet<PathBuf> = changed
                .iter()
                .map(|path| {
                    if path.is_absolute() {
                        path.clone()
                    } else {
                        root.join(path)
                    }
                })
                .collect();
            all_findings.retain(|finding| {
                finding.file_path.as_ref().is_some_and(|path| {
                    let full_path = if path.is_absolute() {
                        path.clone()
                    } else {
                        root.join(path)
                    };
                    changed_paths.contains(&full_path)
                })
            });
        }

        // 3. Compute status and classification
        let has_parser_failures = !base_report.coverage.parser_failures.is_empty();
        let has_receipt_errors = receipts.iter().any(|r| !r.errors.is_empty());

        let status = if has_receipt_errors || has_parser_failures {
            ScanStatus::Partial
        } else {
            ScanStatus::Completed
        };

        if !unsupported_rules.is_empty() {
            unexamined_reasons.push(format!(
                "{} applicable catalog rules remain unsupported by active automated detectors",
                unsupported_rules.len()
            ));
        }

        let has_confirmed = all_findings.iter().any(|f| {
            f.severity == Severity::Critical
                || f.severity == Severity::High
                || f.affectedness == Affectedness::ConfirmedAffected
        });

        let result_classification = if has_confirmed {
            ResultClassification::Confirmed
        } else if !all_findings.is_empty() {
            ResultClassification::Suspected
        } else if status == ScanStatus::Completed && base_report.coverage.is_complete() {
            ResultClassification::NoFindingInCoverage
        } else {
            ResultClassification::NotAssessed
        };

        let mut rules_eval_vec: Vec<String> = rules_evaluated.into_iter().collect();
        rules_eval_vec.sort();

        applicable_rules.sort();
        unsupported_rules.sort();

        SecurityGuardReport {
            workspace_root: root.to_path_buf(),
            scan_time: scan_start.to_rfc3339(),
            scan_profile: profile,
            status,
            result_classification,
            files_assessed: base_report.total_files_scanned,
            findings: all_findings,
            rules_evaluated: rules_eval_vec,
            applicable_rules,
            unsupported_rules,
            coverage: base_report.coverage.clone(),
            receipts,
            unexamined_reasons,
        }
    }
}
