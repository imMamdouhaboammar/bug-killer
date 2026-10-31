#![allow(dead_code)]

pub mod agent;
pub mod auth;
pub mod iac;
pub mod quality;
pub mod sast;
pub mod secrets;
pub mod supply_chain;
pub mod web;

pub use agent::{AgentSkillDetector, AiAgentExtDetector, DynamicRulesDetector};
pub use auth::{
    AuthSecurityDetector, AuthzSecurityDetector, BizConcurrencyDetector, FilesystemExtDetector,
};
pub use iac::{
    CicdSecurityDetector, ContainerIacDetector, IacSecurityDetector, NativeDesktopDetector,
};
pub use quality::{BkhSafetyDetector, OpsQaDetector};
pub use sast::{
    InjectionSecurityDetector, LanguagePitfallsDetector, MemTempDetector, ParserSecurityDetector,
    TaintSastDetector,
};
pub use secrets::{CryptoWeaknessDetector, DataPrivacyDetector, SecretDetector};
pub use supply_chain::{OsvScaDetector, SupplyChainDetector};
pub use web::{ApiSecurityDetector, NetworkDosDetector, WebSecurityDetector};

use crate::catalog::SecurityCatalog;
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

// ---------------- Detector Registry ----------------

#[derive(Clone)]
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
        reg.register(Arc::new(BkhSafetyDetector));
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

    /// Discovers if workspace contains dependency manifests or lockfiles.
    /// An inaccessible subtree must not be mistaken for the absence of a manifest.
    pub fn workspace_has_package_manifests(&self, root: &Path) -> bool {
        self.try_workspace_has_package_manifests(root)
            .unwrap_or(true)
    }

    pub fn try_workspace_has_package_manifests(&self, root: &Path) -> Result<bool, String> {
        let manifest_names = [
            "package.json",
            "package-lock.json",
            "yarn.lock",
            "pnpm-lock.yaml",
            "composer.json",
            "composer.lock",
            "Cargo.toml",
            "Cargo.lock",
            "go.mod",
            "go.sum",
            "pom.xml",
            "requirements.txt",
            "pyproject.toml",
            "Pipfile",
            "Gemfile",
            "Gemfile.lock",
        ];

        for entry in walkdir::WalkDir::new(root)
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
        {
            let entry =
                entry.map_err(|e| format!("Dependency manifest traversal incomplete: {e}"))?;
            if entry.file_type().is_file() {
                let name = entry.file_name().to_string_lossy();
                if manifest_names.iter().any(|m| name == *m) || name.ends_with(".csproj") {
                    return Ok(true);
                }
            }
        }
        Ok(false)
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
        let manifest_discovery = self.try_workspace_has_package_manifests(root);
        // On discovery error we cannot prove an SCA rule is inapplicable.
        let has_manifests = manifest_discovery.as_ref().copied().unwrap_or(true);

        // 1. Classify applicable rules from catalog vs unsupported rules
        let mut applicable_rules = Vec::new();
        let mut unsupported_rules = Vec::new();

        for rule in catalog.all_rules() {
            let is_lang_applicable = rule
                .applicable_languages
                .iter()
                .any(|l| detected_languages.contains(l));

            let is_sca = rule
                .required_evidence
                .contains(&crate::catalog::EvidenceKind::Sca)
                || rule.rule_id.contains("-SCA-");

            let is_applicable = is_lang_applicable && (!is_sca || has_manifests);

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
        let mut rule_coverage: std::collections::BTreeMap<String, RuleCoverageStatus> =
            std::collections::BTreeMap::new();

        all_findings.extend(base_report.findings.clone());

        for detector in &self.detectors {
            let result = detector.run(&ctx);
            let has_errors =
                !result.receipt.errors.is_empty() || result.receipt.status == CoverageStatus::Error;
            let is_not_run = result.receipt.status == CoverageStatus::NotRun;

            for r in &result.rules_run {
                if has_errors {
                    rule_coverage.insert(r.clone(), RuleCoverageStatus::Error);
                } else if is_not_run {
                    rule_coverage.insert(r.clone(), RuleCoverageStatus::NotRun);
                } else if result.receipt.status == CoverageStatus::Complete {
                    rule_coverage.insert(r.clone(), RuleCoverageStatus::SupportedAndEvaluated);
                    rules_evaluated.insert(r.clone());
                } else {
                    rule_coverage.insert(r.clone(), RuleCoverageStatus::NotRun);
                }
            }

            all_findings.extend(result.findings);
            receipts.push(result.receipt);
        }

        // Truthful catalog coverage: map every catalog rule to its concrete evaluation status
        for rule in catalog.all_rules() {
            let is_lang_applicable = rule
                .applicable_languages
                .iter()
                .any(|l| detected_languages.contains(l));

            let is_sca = rule
                .required_evidence
                .contains(&crate::catalog::EvidenceKind::Sca)
                || rule.rule_id.contains("-SCA-");

            let is_applicable = is_lang_applicable && (!is_sca || has_manifests);

            if manifest_discovery.is_err() && is_sca && is_lang_applicable {
                rule_coverage.insert(rule.rule_id.clone(), RuleCoverageStatus::Error);
                rules_evaluated.remove(&rule.rule_id);
            } else if !is_applicable {
                rule_coverage.insert(rule.rule_id.clone(), RuleCoverageStatus::NotApplicable);
                rules_evaluated.remove(&rule.rule_id);
            } else if !supported_rule_set.contains(&rule.rule_id) {
                rule_coverage.insert(rule.rule_id.clone(), RuleCoverageStatus::Unsupported);
                rules_evaluated.remove(&rule.rule_id);
            } else {
                rule_coverage
                    .entry(rule.rule_id.clone())
                    .or_insert(RuleCoverageStatus::NotRun);
            }
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
        let has_receipt_errors = receipts
            .iter()
            .any(|r| !r.errors.is_empty() || r.status == CoverageStatus::Error);
        let has_errored_rules = rule_coverage
            .values()
            .any(|s| *s == RuleCoverageStatus::Error);

        let has_skipped_applicable = rule_coverage.iter().any(|(id, r_status)| {
            applicable_rules.contains(id)
                && (*r_status == RuleCoverageStatus::NotRun
                    || *r_status == RuleCoverageStatus::Error)
        });

        let status = if !unsupported_rules.is_empty()
            || manifest_discovery.is_err()
            || has_receipt_errors
            || has_parser_failures
            || has_errored_rules
            || has_skipped_applicable
        {
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
        if let Err(reason) = &manifest_discovery {
            unexamined_reasons.push(reason.clone());
        }

        // Severity is impact, not proof. A critical lexical match remains suspected.
        let has_confirmed = all_findings.iter().any(|f| {
            f.affectedness == Affectedness::ConfirmedAffected
                && f.evidence_certainty == EvidenceCertainty::Confirmed
        });

        let result_classification = if has_confirmed {
            ResultClassification::Confirmed
        } else if !all_findings.is_empty() {
            ResultClassification::Suspected
        } else if status == ScanStatus::Completed
            && base_report.coverage.is_complete()
            && !has_skipped_applicable
            && unsupported_rules.is_empty()
        {
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
            rule_coverage,
        }
    }
}
