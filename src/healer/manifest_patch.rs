use std::fs;
use std::path::Path;
use regex::Regex;
use crate::types::*;
use crate::healer::backup::BackupManager;

pub struct ManifestPatcher;

impl ManifestPatcher {
    /// Bumps `package.json` engines to safe Node.js release (>=22.23.4).
    pub fn plan_package_json_patch(path: &Path) -> Option<PatchAction> {
        let content = fs::read_to_string(path).ok()?;
        let mut json: serde_json::Value = serde_json::from_str(&content).ok()?;
        let sha256 = BackupManager::compute_sha256(path).ok()?;

        let mut changed = false;

        if let Some(obj) = json.as_object_mut() {
            if let Some(engines) = obj.get_mut("engines").and_then(|e| e.as_object_mut()) {
                if let Some(curr) = engines.get("node").and_then(|n| n.as_str()) {
                    if curr == ">=22.23.4" {
                        return None;
                    }
                }
                engines.insert("node".to_string(), serde_json::Value::String(">=22.23.4".to_string()));
                changed = true;
            } else {
                let mut engines = serde_json::Map::new();
                engines.insert("node".to_string(), serde_json::Value::String(">=22.23.4".to_string()));
                obj.insert("engines".to_string(), serde_json::Value::Object(engines));
                changed = true;
            }
        }

        if !changed {
            return None;
        }

        let new_content = serde_json::to_string_pretty(&json).ok()? + "\n";

        Some(PatchAction {
            action_type: PatchActionType::PackageManifestVersionBump,
            target_file: path.to_path_buf(),
            original_checksum: sha256,
            diff_description: "Pin engines.node to safe release >=22.23.4 in package.json".into(),
            replacement_content: new_content,
        })
    }

    /// Bumps `composer.json` to safe PHP release (>=8.2.35).
    pub fn plan_composer_json_patch(path: &Path) -> Option<PatchAction> {
        let content = fs::read_to_string(path).ok()?;
        let mut json: serde_json::Value = serde_json::from_str(&content).ok()?;
        let sha256 = BackupManager::compute_sha256(path).ok()?;

        let mut changed = false;

        if let Some(obj) = json.as_object_mut() {
            if let Some(require) = obj.get_mut("require").and_then(|r| r.as_object_mut()) {
                if let Some(curr) = require.get("php").and_then(|p| p.as_str()) {
                    if curr == ">=8.2.35" {
                        return None;
                    }
                }
                require.insert("php".to_string(), serde_json::Value::String(">=8.2.35".to_string()));
                changed = true;
            }
        }

        if !changed {
            return None;
        }

        let new_content = serde_json::to_string_pretty(&json).ok()? + "\n";

        Some(PatchAction {
            action_type: PatchActionType::ComposerVersionBump,
            target_file: path.to_path_buf(),
            original_checksum: sha256,
            diff_description: "Pin require.php to safe release >=8.2.35 in composer.json".into(),
            replacement_content: new_content,
        })
    }

    /// Bumps Dockerfile base images to safe patched versions.
    pub fn plan_dockerfile_patch(path: &Path) -> Option<PatchAction> {
        let content = fs::read_to_string(path).ok()?;
        let sha256 = BackupManager::compute_sha256(path).ok()?;

        let mut modified = String::new();
        let mut changed = false;

        // PHP replacements
        let re_php = Regex::new(r"(?i)^FROM\s+php:(8\.[2-5])(?:\.\d+)?(-[a-z0-9\-]+)?").unwrap();
        // Node replacements
        let re_node = Regex::new(r"(?i)^FROM\s+node:(22|24|26)(?:\.\d+)?(?:\.\d+)?(-[a-z0-9\-]+)?").unwrap();

        for line in content.lines() {
            if let Some(caps) = re_php.captures(line) {
                let branch = &caps[1];
                let suffix = caps.get(2).map(|m| m.as_str()).unwrap_or("");
                let safe_ver = match branch {
                    "8.2" => "8.2.35",
                    "8.3" => "8.3.36",
                    "8.4" => "8.4.27",
                    "8.5" => "8.5.12",
                    _ => branch,
                };
                let new_line = format!("FROM php:{}{}", safe_ver, suffix);
                if new_line != line {
                    modified.push_str(&new_line);
                    modified.push('\n');
                    changed = true;
                    continue;
                }
            } else if let Some(caps) = re_node.captures(line) {
                let major = &caps[1];
                let suffix = caps.get(2).map(|m| m.as_str()).unwrap_or("");
                let safe_ver = match major {
                    "22" => "22.23.4",
                    "24" => "24.22.1",
                    "26" => "26.12.1",
                    _ => major,
                };
                let new_line = format!("FROM node:{}{}", safe_ver, suffix);
                if new_line != line {
                    modified.push_str(&new_line);
                    modified.push('\n');
                    changed = true;
                    continue;
                }
            }

            modified.push_str(line);
            modified.push('\n');
        }

        if !changed {
            return None;
        }

        Some(PatchAction {
            action_type: PatchActionType::DockerfileBaseImageBump,
            target_file: path.to_path_buf(),
            original_checksum: sha256,
            diff_description: "Upgrade Dockerfile base images to safe patched releases".into(),
            replacement_content: modified,
        })
    }

    /// Bumps an arbitrary package dependency in `package.json` to a safe version.
    pub fn plan_generic_npm_dependency_bump(path: &Path, package_name: &str, safe_version: &str) -> Option<PatchAction> {
        let content = fs::read_to_string(path).ok()?;
        let mut json: serde_json::Value = serde_json::from_str(&content).ok()?;
        let sha256 = BackupManager::compute_sha256(path).ok()?;

        let mut changed = false;
        let sections = ["dependencies", "devDependencies"];

        if let Some(obj) = json.as_object_mut() {
            for sec in sections {
                if let Some(deps) = obj.get_mut(sec).and_then(|d| d.as_object_mut()) {
                    if let Some(curr) = deps.get(package_name).and_then(|v| v.as_str()) {
                        let clean_curr = curr.trim_start_matches('^').trim_start_matches('~').trim();
                        if clean_curr == safe_version {
                            return None;
                        }
                        deps.insert(package_name.to_string(), serde_json::Value::String(format!("^{}", safe_version)));
                        changed = true;
                    }
                }
            }
        }

        if !changed {
            return None;
        }

        let new_content = serde_json::to_string_pretty(&json).ok()? + "\n";
        Some(PatchAction {
            action_type: PatchActionType::PackageManifestVersionBump,
            target_file: path.to_path_buf(),
            original_checksum: sha256,
            diff_description: format!("Upgrade {} to safe release ^{} in package.json", package_name, safe_version),
            replacement_content: new_content,
        })
    }

    /// Bumps an arbitrary package dependency in `requirements.txt` to a safe version.
    pub fn plan_generic_python_requirements_bump(path: &Path, package_name: &str, safe_version: &str) -> Option<PatchAction> {
        let content = fs::read_to_string(path).ok()?;
        let sha256 = BackupManager::compute_sha256(path).ok()?;

        let mut lines = Vec::new();
        let mut changed = false;

        for line in content.lines() {
            let trimmed = line.trim();
            if let Some((pkg, _)) = trimmed.split_once("==") {
                if pkg.trim() == package_name {
                    lines.push(format!("{}=={}", package_name, safe_version));
                    changed = true;
                    continue;
                }
            }
            lines.push(line.to_string());
        }

        if !changed {
            return None;
        }

        let new_content = lines.join("\n") + "\n";
        Some(PatchAction {
            action_type: PatchActionType::GenericReplace,
            target_file: path.to_path_buf(),
            original_checksum: sha256,
            diff_description: format!("Upgrade {} to safe release =={} in requirements.txt", package_name, safe_version),
            replacement_content: new_content,
        })
    }
}
