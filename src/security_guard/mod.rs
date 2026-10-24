#![allow(dead_code)]

pub mod cache;
pub mod config;
pub mod guidance;
pub mod remediation;

use self::config::{ConfigManager, ProjectConfig, ProjectPolicy, RemediationLevel};
use self::guidance::{GuidanceEngine, TaskSecurityGuidance};
use self::remediation::{FixProposal, RemediationEngine, RemediationOutcome};
use crate::catalog::SecurityCatalog;
use crate::detectors::DetectorRegistry;
use crate::identity::AgentIdentity;
use crate::scanner::FleetScanner;
use crate::types::*;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitReceipt {
    pub project_name: String,
    pub initialized: bool,
    pub config_path: PathBuf,
    pub policy_path: PathBuf,
    pub baseline_path: PathBuf,
    pub detected_languages: Vec<String>,
    pub package_managers: Vec<String>,
    pub git_hook_installed: bool,
    pub baseline_findings_count: usize,
    pub baseline_clean: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityStatusReport {
    pub is_initialized: bool,
    pub project_name: String,
    pub languages: Vec<String>,
    pub remediation_level: RemediationLevel,
    pub pre_commit_gate_enabled: bool,
    pub last_baseline_time: Option<String>,
    pub baseline_findings_count: usize,
    pub baseline_status: Option<ScanStatus>,
    pub agent_identity_configured: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingExplanation {
    pub finding_id: String,
    pub rule_id: String,
    pub cwe: Option<String>,
    pub severity: Severity,
    pub category: String,
    pub description: String,
    pub target_file: Option<PathBuf>,
    pub line_number: Option<usize>,
    pub detection_method: String,
    pub proof_target: String,
    pub remediation_guidance: String,
    pub verification_requirements: String,
}

pub struct SecurityGuard;

impl SecurityGuard {
    /// Detects package managers present in workspace root.
    pub fn discover_package_managers(root: &Path) -> Vec<String> {
        let mut pms = Vec::new();
        if root.join("package-lock.json").exists() {
            pms.push("npm".to_string());
        }
        if root.join("pnpm-lock.yaml").exists() {
            pms.push("pnpm".to_string());
        }
        if root.join("yarn.lock").exists() {
            pms.push("yarn".to_string());
        }
        if root.join("bun.lockb").exists() || root.join("bun.lock").exists() {
            pms.push("bun".to_string());
        }
        if root.join("composer.lock").exists() || root.join("composer.json").exists() {
            pms.push("composer".to_string());
        }
        if root.join("Cargo.lock").exists() || root.join("Cargo.toml").exists() {
            pms.push("cargo".to_string());
        }
        if root.join("go.mod").exists() {
            pms.push("go mod".to_string());
        }
        if root.join("requirements.txt").exists() || root.join("Pipfile").exists() {
            pms.push("pip".to_string());
        }
        if root.join("poetry.lock").exists() {
            pms.push("poetry".to_string());
        }
        pms
    }

    /// Initializes Bug Killer inside a project workspace idempotently.
    pub fn init(root: &Path, install_hooks: bool) -> Result<InitReceipt, String> {
        let registry = DetectorRegistry::default();
        let detected_langs_set = registry.discover_workspace_languages(root);
        let mut detected_languages: Vec<String> = detected_langs_set.into_iter().collect();
        detected_languages.sort();

        let package_managers = Self::discover_package_managers(root);
        let project_name = root
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();

        let already_init = ConfigManager::is_initialized(root);

        // Idempotency: preserve existing configuration if already initialized
        let mut config = if already_init {
            ConfigManager::load_config(root)
        } else {
            let cfg = ProjectConfig {
                name: project_name.clone(),
                languages: detected_languages.clone(),
                package_managers: package_managers.clone(),
                ..Default::default()
            };
            ConfigManager::save_config(root, &cfg)?;
            cfg
        };

        if !ConfigManager::policy_path(root).exists() {
            ConfigManager::save_policy(root, &ProjectPolicy::default())?;
        }

        // Initialize agent cryptographic trust anchor
        let _ = AgentIdentity::get_or_create(root);

        // Run baseline security assessment
        let baseline_report = registry.execute_guard_scan(root, config.scan_profile, None, false);
        let baseline_clean = baseline_report.is_clean();
        let baseline_count = baseline_report.findings.len();

        // Write baseline report
        let baseline_json = serde_json::to_string_pretty(&baseline_report)
            .map_err(|e| format!("Failed to serialize baseline report: {}", e))?;
        fs::write(ConfigManager::baseline_path(root), baseline_json)
            .map_err(|e| format!("Failed to write baseline.json: {}", e))?;

        // Idempotent Git hook installation
        let mut hook_installed = false;
        if install_hooks {
            hook_installed = Self::install_pre_commit_hook(root)?;
            config.pre_commit_gate = true;
            let _ = ConfigManager::save_config(root, &config);
        }

        Ok(InitReceipt {
            project_name: config.name,
            initialized: true,
            config_path: ConfigManager::config_path(root),
            policy_path: ConfigManager::policy_path(root),
            baseline_path: ConfigManager::baseline_path(root),
            detected_languages,
            package_managers,
            git_hook_installed: hook_installed,
            baseline_findings_count: baseline_count,
            baseline_clean,
        })
    }

    /// Installs or updates a non-destructive Git pre-commit hook idempotently.
    pub fn install_pre_commit_hook(root: &Path) -> Result<bool, String> {
        let hooks_dir = root.join(".git").join("hooks");
        if !hooks_dir.exists() {
            return Ok(false);
        }

        let hook_file = hooks_dir.join("pre-commit");
        let marker = "# BUG_KILLER_SECURITY_GATE_START";
        let hook_content = r#"# BUG_KILLER_SECURITY_GATE_START
# Run Bug Killer quick security scan on staged/changed files
if command -v bug-killer >/dev/null 2>&1; then
    bug-killer security scan --profile quick || {
        echo "❌ [Bug Killer] Security Gate Failed. Fix critical findings or update policy before committing."
        exit 1
    }
fi
# BUG_KILLER_SECURITY_GATE_END
"#;

        if hook_file.exists() {
            let existing = fs::read_to_string(&hook_file).unwrap_or_default();
            if existing.contains(marker) {
                return Ok(true); // already installed idempotently
            }
            // Append hook
            let combined = format!("{}\n\n{}", existing.trim_end(), hook_content);
            fs::write(&hook_file, combined)
                .map_err(|e| format!("Failed to update pre-commit hook: {}", e))?;
        } else {
            let full_script = format!("#!/bin/sh\n\n{}", hook_content);
            fs::write(&hook_file, full_script)
                .map_err(|e| format!("Failed to create pre-commit hook: {}", e))?;
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&hook_file, fs::Permissions::from_mode(0o755));
        }

        Ok(true)
    }

    /// Returns high-level security status of a workspace.
    pub fn status(root: &Path) -> SecurityStatusReport {
        let is_init = ConfigManager::is_initialized(root);
        let config = ConfigManager::load_config(root);

        let (last_baseline_time, baseline_findings_count, baseline_status) =
            if let Ok(data) = fs::read_to_string(ConfigManager::baseline_path(root)) {
                if let Ok(report) = serde_json::from_str::<SecurityGuardReport>(&data) {
                    (
                        Some(report.scan_time),
                        report.findings.len(),
                        Some(report.status),
                    )
                } else {
                    (None, 0, None)
                }
            } else {
                (None, 0, None)
            };

        let identity_configured = AgentIdentity::get_or_create(root).is_ok();

        SecurityStatusReport {
            is_initialized: is_init,
            project_name: config.name,
            languages: config.languages,
            remediation_level: config.remediation_level,
            pre_commit_gate_enabled: config.pre_commit_gate,
            last_baseline_time,
            baseline_findings_count,
            baseline_status,
            agent_identity_configured: identity_configured,
        }
    }

    /// Executes security scan with configurable scan profile and optional incremental caching.
    pub fn scan(
        root: &Path,
        profile: ScanProfile,
        changed_files_only: bool,
        enable_network_osv: bool,
    ) -> SecurityGuardReport {
        let registry = DetectorRegistry::default();
        let changed_files = if changed_files_only {
            Self::discover_changed_files(root)
        } else {
            None
        };

        registry.execute_guard_scan(root, profile, changed_files, enable_network_osv)
    }

    /// Discovers changed files in git repository if git is present.
    pub fn discover_changed_files(root: &Path) -> Option<Vec<PathBuf>> {
        let output = std::process::Command::new("git")
            .arg("-C")
            .arg(root)
            .args(["status", "--porcelain"])
            .output()
            .ok()?;

        if !output.status.success() {
            return None;
        }

        let mut files = Vec::new();
        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines() {
            let line = line.trim();
            if line.len() > 3 {
                let file_part = &line[3..].trim();
                let p = root.join(file_part);
                if p.is_file() {
                    files.push(p);
                }
            }
        }
        Some(files)
    }

    /// Provides deep technical explanation and catalog grounding for a finding ID.
    pub fn explain(finding_id: &str, root: &Path) -> Option<FindingExplanation> {
        let catalog = SecurityCatalog::global();
        let report = FleetScanner::scan_directory(root, false);
        let finding = report.findings.iter().find(|f| {
            f.id == finding_id
                || f.id.starts_with(finding_id)
                || f.dedupe_fingerprint.starts_with(finding_id)
        })?;

        let rule_id = finding.cve.as_str();
        let catalog_rule = catalog.get_rule(rule_id);

        Some(FindingExplanation {
            finding_id: finding.id.clone(),
            rule_id: rule_id.to_string(),
            cwe: catalog_rule.and_then(|r| r.cwe.clone()),
            severity: finding.severity,
            category: catalog_rule
                .map(|r| r.category.clone())
                .unwrap_or_else(|| finding.category.clone()),
            description: finding.description.clone(),
            target_file: finding.file_path.clone(),
            line_number: finding.line_number,
            detection_method: catalog_rule
                .map(|r| r.detection_method.clone())
                .unwrap_or_else(|| "AUTOMATED_SCANNER".to_string()),
            proof_target: catalog_rule
                .map(|r| r.remediation_guidance.clone())
                .unwrap_or_default(),
            remediation_guidance: finding.suggested_remediation.clone(),
            verification_requirements: catalog_rule
                .map(|r| r.verification_requirements.clone())
                .unwrap_or_default(),
        })
    }

    /// Prepares a non-mutating prospective repair plan for a finding.
    pub fn plan_fix(finding_id: &str, root: &Path) -> Result<FixProposal, String> {
        let report = FleetScanner::scan_directory(root, false);
        let finding = report
            .findings
            .iter()
            .find(|f| {
                f.id == finding_id
                    || f.id.starts_with(finding_id)
                    || f.dedupe_fingerprint.starts_with(finding_id)
            })
            .ok_or_else(|| format!("Finding '{}' not found in current scan", finding_id))?;

        RemediationEngine::propose_fix(root, finding)
    }

    /// Applies an authorized fix plan with verification and automatic rollback.
    pub fn apply_fix(
        proposal: &FixProposal,
        root: &Path,
        receipt: Option<&str>,
    ) -> Result<RemediationOutcome, String> {
        let config = ConfigManager::load_config(root);
        RemediationEngine::apply_guarded_fix(root, proposal, config.remediation_level, receipt)
    }

    /// Provides task-scoped security guidance before coding.
    pub fn guidance(task: &str, language: &str) -> TaskSecurityGuidance {
        GuidanceEngine::generate_guidance(task, language)
    }
}
