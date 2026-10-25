pub mod approval;
pub mod backup;
pub mod manifest_patch;
pub mod rollback;
pub mod source_patch;
pub mod virtual_patch;

#[allow(unused_imports)]
pub use approval::{ApprovalManager, ApprovalReceipt};

use self::backup::BackupManager;
use self::manifest_patch::ManifestPatcher;
use self::source_patch::SourcePatcher;
use self::virtual_patch::VirtualPatcher;
use crate::rules::{RuleEngine, VulnerabilityRule};
use crate::types::*;
use std::path::{Path, PathBuf};

pub struct AutopilotHealer;

impl AutopilotHealer {
    /// Generates a comprehensive plan of atomic patches to heal detected vulnerabilities.
    pub fn plan_healing(report: &ScanReport) -> Vec<PatchAction> {
        let rules = RuleEngine::load_rules(None, &report.target_dir);
        Self::plan_healing_with_rules(report, &rules)
    }

    /// Generates healing plan using an explicit set of rules.
    /// Skips untrusted workspace dynamic rules unless verified or approved.
    pub fn plan_healing_with_rules(
        report: &ScanReport,
        rules: &[VulnerabilityRule],
    ) -> Vec<PatchAction> {
        Self::plan_healing_with_rules_and_approval(report, rules, false)
    }

    /// Generates healing plan using an explicit set of rules, with optional operator consent for untrusted rules.
    pub fn plan_healing_with_rules_and_approval(
        report: &ScanReport,
        rules: &[VulnerabilityRule],
        allow_untrusted_rules: bool,
    ) -> Vec<PatchAction> {
        let mut plan = Vec::new();

        for finding in &report.findings {
            let path = match &finding.file_path {
                Some(p) => p.as_path(),
                None => continue,
            };

            // 1. Check if finding originated from a dynamic rule
            if let CveId::Custom {
                id: ref rule_id, ..
            } = finding.cve
            {
                if let Some(rule) = rules.iter().find(|r| &r.id == rule_id) {
                    // Issue #23: Project-bundled rules must be treated as untrusted data by default:
                    // they may generate scan findings, but MUST NOT be auto-applied without
                    // explicit provenance verification or operator consent.
                    if !rule.is_trusted() && !allow_untrusted_rules {
                        continue;
                    }
                    if let Ok(content) = std::fs::read_to_string(path) {
                        if let Some(action) = RuleEngine::plan_patch(path, &content, rule) {
                            if !plan
                                .iter()
                                .any(|a: &PatchAction| a.target_file == action.target_file)
                            {
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
                    let pkg_name = finding
                        .detected_version_or_pattern
                        .split('@')
                        .next()
                        .unwrap_or("")
                        .trim();
                    if !pkg_name.is_empty() {
                        let action = match finding.target_kind {
                            TargetKind::NodePackageManifest => {
                                ManifestPatcher::plan_generic_npm_dependency_bump(
                                    path, pkg_name, fix_ver,
                                )
                            }
                            TargetKind::GenericConfigFile
                                if path.file_name().and_then(|s| s.to_str())
                                    == Some("requirements.txt") =>
                            {
                                ManifestPatcher::plan_generic_python_requirements_bump(
                                    path, pkg_name, fix_ver,
                                )
                            }
                            TargetKind::GoModManifest => {
                                ManifestPatcher::plan_generic_go_mod_bump(path, pkg_name, fix_ver)
                            }
                            TargetKind::DotnetCsprojManifest => {
                                ManifestPatcher::plan_generic_dotnet_csproj_bump(
                                    path, pkg_name, fix_ver,
                                )
                            }
                            _ => None,
                        };
                        if let Some(act) = action {
                            if !plan
                                .iter()
                                .any(|a: &PatchAction| a.target_file == act.target_file)
                            {
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
                        if !plan
                            .iter()
                            .any(|a: &PatchAction| a.target_file == action.target_file)
                        {
                            plan.push(action);
                        }
                    }
                }
                TargetKind::NodePackageManifest => {
                    if let Some(action) = ManifestPatcher::plan_package_json_patch(path) {
                        if !plan
                            .iter()
                            .any(|a: &PatchAction| a.target_file == action.target_file)
                        {
                            plan.push(action);
                        }
                    }
                }
                TargetKind::ComposerManifest => {
                    if let Some(action) = ManifestPatcher::plan_composer_json_patch(path) {
                        if !plan
                            .iter()
                            .any(|a: &PatchAction| a.target_file == action.target_file)
                        {
                            plan.push(action);
                        }
                    }
                }
                TargetKind::Dockerfile => {
                    if let Some(action) = ManifestPatcher::plan_dockerfile_patch(path) {
                        if !plan
                            .iter()
                            .any(|a: &PatchAction| a.target_file == action.target_file)
                        {
                            plan.push(action);
                        }
                    }
                }
                TargetKind::NodeSourceFile => {
                    if let Some(action) = SourcePatcher::plan_express_guard_patch(path) {
                        if !plan
                            .iter()
                            .any(|a: &PatchAction| a.target_file == action.target_file)
                        {
                            plan.push(action);
                        }
                    }
                }
                _ => {}
            }
        }

        plan
    }

    /// Performs preflight validation of the entire plan before touching a single byte on disk:
    /// a) Canonicalize `root`.
    /// b) Verify all target paths are strictly within `canonical_root` (reject path traversal `..`, symlinks in target file, symlinks in parent directories, absolute paths escaping root).
    /// c) Verify all target files are regular files that exist.
    /// d) Verify that for each action, the current file's SHA-256 hash matches `action.original_checksum`.
    /// e) Reject duplicate targets in the same plan.
    pub fn preflight_plan(root: &Path, actions: &[PatchAction]) -> Result<Vec<PathBuf>, String> {
        if actions.is_empty() {
            return Err("Healing plan is empty".to_string());
        }

        // a) Canonicalize root
        let canonical_root = root
            .canonicalize()
            .map_err(|e| format!("Failed to canonicalize workspace root {:?}: {}", root, e))?;

        let mut seen_targets = std::collections::HashSet::new();
        let mut canonical_targets = Vec::with_capacity(actions.len());

        for action in actions {
            // b) Reject path traversal components
            if action
                .target_file
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
            {
                return Err(format!(
                    "Path traversal attempt rejected in target: {:?}",
                    action.target_file
                ));
            }

            // Determine path relative to root
            let rel_path = if let Ok(rel) = action.target_file.strip_prefix(&canonical_root) {
                rel.to_path_buf()
            } else if let Ok(rel) = action.target_file.strip_prefix(root) {
                rel.to_path_buf()
            } else if action.target_file.is_relative() {
                action.target_file.clone()
            } else {
                return Err(format!(
                    "Target file escapes workspace root: {:?}",
                    action.target_file
                ));
            };

            if rel_path.is_absolute()
                || rel_path.components().any(|c| {
                    matches!(
                        c,
                        std::path::Component::ParentDir
                            | std::path::Component::RootDir
                            | std::path::Component::Prefix(_)
                    )
                })
            {
                return Err(format!(
                    "Path traversal attempt rejected in relative target: {:?}",
                    rel_path
                ));
            }

            let components: Vec<_> = rel_path.components().collect();
            if components.is_empty() {
                return Err("Target file path cannot be empty or root".to_string());
            }

            // Verify no symlinks in parent directories or in the target file
            let mut curr = canonical_root.clone();
            for (i, comp) in components.iter().enumerate() {
                match comp {
                    std::path::Component::Normal(part) => {
                        curr.push(part);
                        let meta = match std::fs::symlink_metadata(&curr) {
                            Ok(m) => m,
                            Err(e) => {
                                return Err(format!(
                                    "Target file does not exist or cannot be inspected {:?}: {}",
                                    curr, e
                                ));
                            }
                        };

                        if meta.file_type().is_symlink() {
                            if i + 1 == components.len() {
                                return Err(format!("Target file is a symlink: {:?}", curr));
                            } else {
                                return Err(format!("Parent directory is a symlink: {:?}", curr));
                            }
                        }

                        if i + 1 == components.len() {
                            // c) Verify target file is a regular file that exists
                            if !meta.file_type().is_file() {
                                return Err(format!("Target is not a regular file: {:?}", curr));
                            }
                        } else if !meta.file_type().is_dir() {
                            return Err(format!("Parent component is not a directory: {:?}", curr));
                        }
                    }
                    _ => {
                        return Err(format!("Invalid path component in target: {:?}", comp));
                    }
                }
            }

            let canonical_target = curr
                .canonicalize()
                .map_err(|e| format!("Failed to canonicalize target {:?}: {}", curr, e))?;

            if !canonical_target.starts_with(&canonical_root) {
                return Err(format!("Target escapes workspace: {:?}", canonical_target));
            }

            // e) Reject duplicate targets in the same plan
            if !seen_targets.insert(canonical_target.clone()) {
                return Err(format!(
                    "Duplicate target file in healing plan: {:?}",
                    canonical_target
                ));
            }

            // d) Verify actual file's SHA-256 hash matches action.original_checksum
            let actual_checksum =
                BackupManager::compute_sha256(&canonical_target).map_err(|e| {
                    format!(
                        "Failed to compute checksum for {:?}: {}",
                        canonical_target, e
                    )
                })?;

            if actual_checksum != action.original_checksum {
                return Err(format!(
                    "Preimage verification failed for {:?}: expected checksum {}, got actual {}",
                    canonical_target, action.original_checksum, actual_checksum
                ));
            }

            canonical_targets.push(canonical_target);
        }

        Ok(canonical_targets)
    }

    /// Executes the healing plan atomically: validates plan preflight, creates backup, replaces file contents, and verifies write.
    pub fn execute_healing(
        root: &Path,
        actions: &[PatchAction],
    ) -> Result<(BackupManifest, usize), String> {
        if actions.is_empty() {
            return Err("No healing actions to execute".into());
        }

        // 1. Strict preflight validation before touching a single byte on disk
        let canonical_targets = Self::preflight_plan(root, actions)?;

        // 2. Collision-proof backup with atomic staging
        let manifest = BackupManager::create_backup_for_actions(root, actions)
            .map_err(|e| format!("Failed to create safety backup: {}", e))?;

        let mut applied_count = 0;
        let mut apply_error = None;

        for (action, target_path) in actions.iter().zip(canonical_targets.iter()) {
            // Write atomically via tempfile
            let parent_dir = target_path.parent().unwrap_or(root);
            let write_res = (|| -> Result<(), String> {
                let mut temp = tempfile::NamedTempFile::new_in(parent_dir)
                    .map_err(|e| format!("Failed to create temporary file: {}", e))?;

                use std::io::Write;
                temp.write_all(action.replacement_content.as_bytes())
                    .map_err(|e| format!("Failed to write replacement content: {}", e))?;

                #[cfg(unix)]
                {
                    if let Ok(meta) = std::fs::metadata(target_path) {
                        let _ = temp.as_file_mut().set_permissions(meta.permissions());
                    }
                }

                temp.persist(target_path).map_err(|e| {
                    format!("Failed to atomically persist {:?}: {}", target_path, e)
                })?;
                Ok(())
            })();

            match write_res {
                Ok(()) => {
                    applied_count += 1;
                }
                Err(e) => {
                    apply_error = Some(e);
                    break;
                }
            }
        }

        if let Some(err) = apply_error {
            // Multi-file Transaction Safety: Rollback any partially applied changes
            if applied_count > 0 {
                return match crate::healer::rollback::RollbackManager::rollback(
                    root,
                    &manifest.backup_id,
                ) {
                    Ok(restored) if restored >= applied_count => Err(format!(
                        "Multi-file healing transaction aborted: {}. Restored {} changed files from backup {}.",
                        err, restored, manifest.backup_id
                    )),
                    Ok(restored) => Err(format!(
                        "Multi-file healing transaction aborted: {}. PARTIAL ROLLBACK: restored {} of {} applied files. Manual recovery required; backup ID: {}.",
                        err, restored, applied_count, manifest.backup_id
                    )),
                    Err(rollback_error) => Err(format!(
                        "Multi-file healing transaction aborted: {}. ROLLBACK FAILED: {}. {} files may remain modified. Manual recovery required; backup ID: {}.",
                        err, rollback_error, applied_count, manifest.backup_id
                    )),
                };
            }
            return Err(format!(
                "Multi-file healing transaction aborted before any changes were applied: {}.",
                err
            ));
        }

        Ok((manifest, applied_count))
    }
}
