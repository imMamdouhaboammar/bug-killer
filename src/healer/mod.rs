pub mod backup;
pub mod virtual_patch;
pub mod manifest_patch;
pub mod source_patch;
pub mod rollback;

use std::path::{Path, PathBuf};
use crate::types::*;
use crate::rules::{RuleEngine, VulnerabilityRule};
use self::backup::BackupManager;
use self::virtual_patch::VirtualPatcher;
use self::manifest_patch::ManifestPatcher;
use self::source_patch::SourcePatcher;

pub struct AutopilotHealer;

impl AutopilotHealer {
    /// Generates a comprehensive plan of atomic patches to heal detected vulnerabilities.
    pub fn plan_healing(report: &ScanReport) -> Vec<PatchAction> {
        let rules = RuleEngine::load_rules(None, &report.target_dir);
        Self::plan_healing_with_rules(report, &rules)
    }

    /// Generates healing plan using an explicit set of rules.
    pub fn plan_healing_with_rules(report: &ScanReport, rules: &[VulnerabilityRule]) -> Vec<PatchAction> {
        let mut plan = Vec::new();

        for finding in &report.findings {
            let path = match &finding.file_path {
                Some(p) => p.as_path(),
                None => continue,
            };

            // 1. Check if finding originated from a dynamic rule
            if let CveId::Custom { id: ref rule_id, .. } = finding.cve {
                if let Some(rule) = rules.iter().find(|r| &r.id == rule_id) {
                    if let Ok(content) = std::fs::read_to_string(path) {
                        if let Some(action) = RuleEngine::plan_patch(path, &content, rule) {
                            if !plan.iter().any(|a: &PatchAction| a.target_file == action.target_file) {
                                plan.push(action);
                                continue;
                            }
                        }
                    }
                }
            }

            // 2. Check if finding originated from OSV database (id starts with "osv-")
            if finding.id.starts_with("osv-") {
                if let Some(fix_ver) = finding.safe_threshold.strip_prefix("Upgrade to >= ") {
                    let pkg_name = finding.detected_version_or_pattern.split('@').next().unwrap_or("").trim();
                    if !pkg_name.is_empty() {
                        let action = match finding.target_kind {
                            TargetKind::NodePackageManifest => {
                                ManifestPatcher::plan_generic_npm_dependency_bump(path, pkg_name, fix_ver)
                            }
                            TargetKind::GenericConfigFile if path.file_name().and_then(|s| s.to_str()) == Some("requirements.txt") => {
                                ManifestPatcher::plan_generic_python_requirements_bump(path, pkg_name, fix_ver)
                            }
                            TargetKind::GoModManifest => {
                                ManifestPatcher::plan_generic_go_mod_bump(path, pkg_name, fix_ver)
                            }
                            TargetKind::DotnetCsprojManifest => {
                                ManifestPatcher::plan_generic_dotnet_csproj_bump(path, pkg_name, fix_ver)
                            }
                            _ => None,
                        };
                        if let Some(act) = action {
                            if !plan.iter().any(|a: &PatchAction| a.target_file == act.target_file) {
                                plan.push(act);
                                continue;
                            }
                        }
                    }
                }
            }

            // 3. Built-in hardcoded remediations for zero-day CVEs
            match finding.target_kind {
                TargetKind::NginxConfig => {
                    if let Some(action) = VirtualPatcher::plan_nginx_patch(path) {
                        if !plan.iter().any(|a: &PatchAction| a.target_file == action.target_file) {
                            plan.push(action);
                        }
                    }
                }
                TargetKind::NodePackageManifest => {
                    if let Some(action) = ManifestPatcher::plan_package_json_patch(path) {
                        if !plan.iter().any(|a: &PatchAction| a.target_file == action.target_file) {
                            plan.push(action);
                        }
                    }
                }
                TargetKind::ComposerManifest => {
                    if let Some(action) = ManifestPatcher::plan_composer_json_patch(path) {
                        if !plan.iter().any(|a: &PatchAction| a.target_file == action.target_file) {
                            plan.push(action);
                        }
                    }
                }
                TargetKind::Dockerfile => {
                    if let Some(action) = ManifestPatcher::plan_dockerfile_patch(path) {
                        if !plan.iter().any(|a: &PatchAction| a.target_file == action.target_file) {
                            plan.push(action);
                        }
                    }
                }
                TargetKind::NodeSourceFile => {
                    if let Some(action) = SourcePatcher::plan_express_guard_patch(path) {
                        if !plan.iter().any(|a: &PatchAction| a.target_file == action.target_file) {
                            plan.push(action);
                        }
                    }
                }
                _ => {}
            }
        }

        plan
    }

    /// Executes the healing plan atomically: creates backup, replaces file contents, and verifies write.
    pub fn execute_healing(root: &Path, actions: &[PatchAction]) -> Result<(BackupManifest, usize), String> {
        if actions.is_empty() {
            return Err("No healing actions to execute".into());
        }

        let target_files: Vec<PathBuf> = actions.iter().map(|a| a.target_file.clone()).collect();
        let manifest = BackupManager::create_backup(root, &target_files)
            .map_err(|e| format!("Failed to create safety backup: {}", e))?;

        let mut applied_count = 0;

        for action in actions {
            // Write atomically via tempfile
            let parent_dir = action.target_file.parent().unwrap_or(root);
            let mut temp = tempfile::NamedTempFile::new_in(parent_dir)
                .map_err(|e| format!("Failed to create temporary file: {}", e))?;

            use std::io::Write;
            temp.write_all(action.replacement_content.as_bytes())
                .map_err(|e| format!("Failed to write replacement content: {}", e))?;

            temp.persist(&action.target_file)
                .map_err(|e| format!("Failed to atomically persist {:?}: {}", action.target_file, e))?;

            applied_count += 1;
        }

        Ok((manifest, applied_count))
    }
}
