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
use crate::types::*;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

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
        AgentIdentity::get_or_create(root)
            .map_err(|e| format!("Failed to initialize signing identity: {e}"))?;

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
            config.pre_commit_gate = hook_installed;
            ConfigManager::save_config(root, &config)?;
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
# Scan the staged Git index, not the potentially different working tree.
if ! command -v bug-killer >/dev/null 2>&1; then
    echo "[Bug Killer] Security gate unavailable: install bug-killer before committing." >&2
    exit 1
fi
bug-killer security scan --profile quick --staged --fail-on high || {
    echo "[Bug Killer] Staged security gate failed. Review the findings before committing." >&2
    exit 1
}
# BUG_KILLER_SECURITY_GATE_END
"#;

        if hook_file.exists() {
            let existing = fs::read_to_string(&hook_file).unwrap_or_default();
            // Keep the shebang first, then run our guard before any prior hook
            // can exit early. Replace older Bug Killer blocks in-place.
            let without_old = if let Some(start) = existing.find(marker) {
                let end_marker = "# BUG_KILLER_SECURITY_GATE_END";
                if let Some(end) = existing[start..].find(end_marker) {
                    format!(
                        "{}{}",
                        &existing[..start],
                        &existing[start + end + end_marker.len()..]
                    )
                } else {
                    return Err(
                        "Existing Bug Killer hook marker is incomplete; manual repair needed"
                            .into(),
                    );
                }
            } else {
                existing
            };
            let combined = if let Some(rest) = without_old.strip_prefix("#!/bin/sh") {
                format!(
                    "#!/bin/sh\n{}\n{}",
                    hook_content,
                    rest.trim_start_matches('\n')
                )
            } else if without_old.starts_with("#!") {
                return Err(
                    "Existing Git hook uses a non-shell interpreter; refusing to rewrite it".into(),
                );
            } else {
                format!("#!/bin/sh\n{}\n{}", hook_content, without_old)
            };
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

        let identity_configured = root.join(".aegis/agent_identity.key").is_file();

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

    /// Scan the exact Git index snapshot that the next commit would contain.
    /// This must not use working-tree contents: staged code may differ from disk.
    pub fn scan_staged(root: &Path, profile: ScanProfile) -> Result<SecurityGuardReport, String> {
        fn git_output(root: &Path, args: &[&str]) -> Result<Vec<u8>, String> {
            let output = Command::new("git")
                .arg("-C")
                .arg(root)
                .args(args)
                .output()
                .map_err(|e| format!("Git index inspection unavailable: {e}"))?;
            if !output.status.success() {
                return Err(format!(
                    "Git index inspection failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                ));
            }
            Ok(output.stdout)
        }

        let names = git_output(
            root,
            &[
                "diff",
                "--cached",
                "--name-only",
                "--diff-filter=ACMR",
                "-z",
            ],
        )?;
        let changed: Vec<&str> = names
            .split(|byte| *byte == 0)
            .filter(|bytes| !bytes.is_empty())
            .map(|bytes| {
                std::str::from_utf8(bytes)
                    .map_err(|_| "Non-UTF8 staged paths cannot be safely inspected".to_string())
            })
            .collect::<Result<_, _>>()?;
        let snapshot =
            tempfile::tempdir().map_err(|e| format!("Cannot create index snapshot: {e}"))?;
        let listed = git_output(root, &["ls-files", "--cached", "--stage", "-z"])?;
        for record in listed
            .split(|byte| *byte == 0)
            .filter(|bytes| !bytes.is_empty())
        {
            let separator = record
                .iter()
                .position(|byte| *byte == b'\t')
                .ok_or_else(|| "Unexpected Git index entry".to_string())?;
            let (metadata, with_tab) = record.split_at(separator);
            let name = &with_tab[1..];
            let mode = metadata
                .split(|byte| *byte == b' ')
                .next()
                .unwrap_or_default();
            let relative = std::str::from_utf8(name)
                .map_err(|_| "Non-UTF8 tracked paths cannot be safely inspected".to_string())?;
            let path = Path::new(relative);
            if path.is_absolute()
                || path
                    .components()
                    .any(|part| !matches!(part, std::path::Component::Normal(_)))
            {
                return Err(format!("Unsafe staged path: {relative}"));
            }
            if mode != b"100644" && mode != b"100755" {
                if changed.contains(&relative) {
                    return Err(format!(
                        "Changed non-regular Git index entry requires review: {relative}"
                    ));
                }
                continue;
            }
            let output = git_output(root, &["show", &format!(":{relative}")])?;
            let destination = snapshot.path().join(path);
            if let Some(parent) = destination.parent() {
                fs::create_dir_all(parent)
                    .map_err(|e| format!("Cannot create snapshot directory: {e}"))?;
            }
            fs::write(destination, output)
                .map_err(|e| format!("Cannot materialize staged blob {relative}: {e}"))?;
        }
        let selected: Vec<PathBuf> = changed
            .iter()
            .map(|name| snapshot.path().join(name))
            .collect();
        let mut report = DetectorRegistry::default().execute_guard_scan(
            snapshot.path(),
            profile,
            Some(selected),
            false,
        );
        report.workspace_root = root.to_path_buf();
        for finding in &mut report.findings {
            if let Some(path) = finding.file_path.as_mut() {
                if let Ok(relative) = path.strip_prefix(snapshot.path()) {
                    *path = root.join(relative);
                }
            }
        }
        Ok(report)
    }

    /// Discovers changed files in git repository if git is present.
    pub fn discover_changed_files(root: &Path) -> Option<Vec<PathBuf>> {
        let output = std::process::Command::new("git")
            .arg("-C")
            .arg(root)
            .args(["status", "--porcelain=v1", "-z"])
            .output()
            .ok()?;

        if !output.status.success() {
            return None;
        }

        let mut files = Vec::new();
        let mut entries = output
            .stdout
            .split(|byte| *byte == 0)
            .filter(|e| !e.is_empty());
        while let Some(entry) = entries.next() {
            if entry.len() >= 4 {
                let status = &entry[..2];
                // -z puts the destination path first and the former path second for renames.
                if status.contains(&b'R') || status.contains(&b'C') {
                    entries.next();
                }
                let p = root.join(String::from_utf8_lossy(&entry[3..]).as_ref());
                if p.is_file() {
                    files.push(p);
                }
            }
        }
        Some(files)
    }

    fn resolve_finding(finding_id: &str, root: &Path) -> Result<Finding, String> {
        if finding_id.is_empty() {
            return Err("Finding ID cannot be empty".to_string());
        }
        let report = Self::scan(root, ScanProfile::Project, false, false);
        let exact: Vec<&Finding> = report
            .findings
            .iter()
            .filter(|f| f.id == finding_id || f.dedupe_fingerprint == finding_id)
            .collect();
        let matches: Vec<&Finding> = if exact.is_empty() {
            report
                .findings
                .iter()
                .filter(|f| {
                    f.id.starts_with(finding_id) || f.dedupe_fingerprint.starts_with(finding_id)
                })
                .collect()
        } else {
            exact
        };
        match matches.as_slice() {
            [finding] => Ok((*finding).clone()),
            [] => Err(format!(
                "Finding '{}' not found in current scan",
                finding_id
            )),
            _ => Err(format!(
                "Finding prefix '{}' is ambiguous; use an exact ID or longer fingerprint",
                finding_id
            )),
        }
    }

    /// Provides deep technical explanation and catalog grounding for a finding ID.
    pub fn explain(finding_id: &str, root: &Path) -> Option<FindingExplanation> {
        let catalog = SecurityCatalog::global();
        let finding = Self::resolve_finding(finding_id, root).ok()?;

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
        let finding = Self::resolve_finding(finding_id, root)?;

        RemediationEngine::propose_fix(root, &finding)
    }

    /// Applies an authorized fix plan with verification and automatic rollback.
    pub fn apply_fix(
        proposal: &FixProposal,
        root: &Path,
        receipt: Option<&str>,
    ) -> Result<RemediationOutcome, String> {
        let config = ConfigManager::load_config(root);
        let policy = ConfigManager::load_policy(root);
        if !policy.allow_guarded_local_fix {
            return Err("Project policy denies guarded local file mutation".to_string());
        }
        RemediationEngine::apply_guarded_fix(root, proposal, config.remediation_level, receipt)
    }

    /// Provides task-scoped security guidance before coding.
    pub fn guidance(task: &str, language: &str) -> TaskSecurityGuidance {
        GuidanceEngine::generate_guidance(task, language)
    }
}
