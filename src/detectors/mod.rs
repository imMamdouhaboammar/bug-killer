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
#[derive(Debug, Clone)]
pub struct ScanContext {
    pub root: PathBuf,
    pub profile: ScanProfile,
    pub changed_files: Option<Vec<PathBuf>>,
    pub enable_network_osv: bool,
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
        let report = FleetScanner::scan_directory_with_rules_and_taint(&ctx.root, false, &[], true);
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
            findings: report.findings,
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
        &["BK-AI-SEC-001", "BK-AI-SEC-002", "BK-AI-SEC-004"]
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
        let report = FleetScanner::scan_directory(&ctx.root, false);
        let secret_findings: Vec<Finding> = report
            .findings
            .into_iter()
            .filter(|f| f.detector_id == "secret-detector")
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
        &["BK-AI-CIC-001", "BK-AI-CIC-002"]
    }

    fn supported_languages(&self) -> &[&'static str] {
        &["yaml"]
    }

    fn supported_targets(&self) -> &[TargetKind] {
        &[TargetKind::GenericConfigFile]
    }

    fn run(&self, ctx: &ScanContext) -> DetectorResult {
        let report = FleetScanner::scan_directory(&ctx.root, false);
        let cicd_findings: Vec<Finding> = report
            .findings
            .into_iter()
            .filter(|f| f.detector_id == "cicd-security")
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
        &["BK-AI-INF-003", "BK-AI-INF-004"]
    }

    fn supported_languages(&self) -> &[&'static str] {
        &["dockerfile"]
    }

    fn supported_targets(&self) -> &[TargetKind] {
        &[TargetKind::Dockerfile]
    }

    fn run(&self, ctx: &ScanContext) -> DetectorResult {
        let report = FleetScanner::scan_directory(&ctx.root, false);
        let container_findings: Vec<Finding> = report
            .findings
            .into_iter()
            .filter(|f| f.target_kind == TargetKind::Dockerfile)
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
        &["BK-AI-LLM-001", "BK-AI-LLM-008", "BK-AI-LLM-014"]
    }

    fn supported_languages(&self) -> &[&'static str] {
        &["markdown", "json"]
    }

    fn supported_targets(&self) -> &[TargetKind] {
        &[TargetKind::AgentSkillManifest, TargetKind::McpServerConfig]
    }

    fn run(&self, ctx: &ScanContext) -> DetectorResult {
        let report = FleetScanner::scan_directory(&ctx.root, false);
        let agent_findings: Vec<Finding> = report
            .findings
            .into_iter()
            .filter(|f| {
                f.target_kind == TargetKind::AgentSkillManifest
                    || f.target_kind == TargetKind::McpServerConfig
            })
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
        let ctx = ScanContext {
            root: root.to_path_buf(),
            profile,
            changed_files,
            enable_network_osv,
        };

        let mut all_findings = Vec::new();
        let mut rules_evaluated = HashSet::new();
        let mut receipts = Vec::new();
        let mut unexamined_reasons = Vec::new();

        let base_report = FleetScanner::scan_directory_with_rules_and_taint(root, false, &[], true);
        all_findings.extend(base_report.findings);

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
            coverage: base_report.coverage,
            receipts,
            unexamined_reasons,
        }
    }
}
