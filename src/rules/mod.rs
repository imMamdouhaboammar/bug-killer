use std::fs;
use std::path::Path;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use crate::types::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityRule {
    pub id: String,
    pub title: String,
    pub severity: Severity,
    #[serde(default)]
    pub description: String,
    pub target_kind: TargetKind,
    #[serde(default)]
    pub file_patterns: Vec<String>,
    pub detection: DetectionMatcher,
    #[serde(default)]
    pub remediation: Option<RemediationStrategy>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum DetectionMatcher {
    #[serde(rename = "regex")]
    RegexMatch {
        pattern: String,
        #[serde(default)]
        not_matching: Option<String>,
    },
    #[serde(rename = "string_contains")]
    StringContains {
        search: String,
        #[serde(default)]
        except_if_contains: Option<String>,
    },
    #[serde(rename = "missing_pattern")]
    MissingPattern {
        required_pattern: String,
    },
    #[serde(rename = "semver_dependency")]
    SemVerDependency {
        package_name: String,
        vulnerable_range: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum RemediationStrategy {
    #[serde(rename = "string_replace")]
    StringReplace {
        search: String,
        replace: String,
        description: String,
    },
    #[serde(rename = "regex_replace")]
    RegexReplace {
        search: String,
        replace: String,
        description: String,
    },
    #[serde(rename = "append_block")]
    AppendBlock {
        snippet: String,
        description: String,
    },
    #[serde(rename = "bump_dependency")]
    BumpDependency {
        package_name: String,
        safe_version: String,
        description: String,
    },
}

pub struct RuleEngine;

impl RuleEngine {
    /// Loads vulnerability rules from an optional explicit directory or file,
    /// as well as scanning `root/rules/` and `~/.bug-killer/rules/`.
    pub fn load_rules(custom_path: Option<&Path>, root: &Path) -> Vec<VulnerabilityRule> {
        let mut rules = Vec::new();

        // 1. If explicit path specified
        if let Some(path) = custom_path {
            Self::collect_rules_from_path(path, &mut rules);
        }

        // 2. Discover in workspace root `rules/`
        let local_rules = root.join("rules");
        if local_rules.exists() {
            Self::collect_rules_from_path(&local_rules, &mut rules);
        }

        // 3. Discover in `.bug-killer/rules/`
        let dot_rules = root.join(".bug-killer").join("rules");
        if dot_rules.exists() {
            Self::collect_rules_from_path(&dot_rules, &mut rules);
        }

        // Deduplicate rules by ID
        rules.sort_by(|a, b| a.id.cmp(&b.id));
        rules.dedup_by(|a, b| a.id == b.id);

        rules
    }

    fn collect_rules_from_path(path: &Path, rules: &mut Vec<VulnerabilityRule>) {
        if path.is_file() {
            if let Some(loaded) = Self::parse_rule_file(path) {
                rules.extend(loaded);
            }
        } else if path.is_dir() {
            if let Ok(entries) = fs::read_dir(path) {
                for entry in entries.flatten() {
                    let entry_path = entry.path();
                    if entry_path.is_file() && entry_path.extension().and_then(|s| s.to_str()) == Some("json") {
                        if let Some(loaded) = Self::parse_rule_file(&entry_path) {
                            rules.extend(loaded);
                        }
                    }
                }
            }
        }
    }

    fn parse_rule_file(path: &Path) -> Option<Vec<VulnerabilityRule>> {
        let content = fs::read_to_string(path).ok()?;
        // Try parsing as array of rules first
        if let Ok(list) = serde_json::from_str::<Vec<VulnerabilityRule>>(&content) {
            return Some(list);
        }
        // Try parsing as a single rule
        if let Ok(single) = serde_json::from_str::<VulnerabilityRule>(&content) {
            return Some(vec![single]);
        }
        None
    }

    /// Tests if a file path matches any pattern defined in the rule.
    pub fn matches_file_pattern(path: &Path, patterns: &[String]) -> bool {
        if patterns.is_empty() {
            return true;
        }

        let file_name = path.file_name().unwrap_or_default().to_string_lossy();
        let path_str = path.to_string_lossy();

        for pat in patterns {
            if pat == "*" {
                return true;
            }
            if let Some(ext) = pat.strip_prefix("*.") {
                if let Some(file_ext) = path.extension().and_then(|s| s.to_str()) {
                    if file_ext == ext {
                        return true;
                    }
                }
            } else if pat.contains('/') {
                if path_str.ends_with(pat) || path_str.contains(pat) {
                    return true;
                }
            } else if file_name == pat.as_str() {
                return true;
            }
        }

        false
    }

    /// Evaluates a single rule against a file's content.
    pub fn scan_file(path: &Path, content: &str, rule: &VulnerabilityRule) -> Option<Finding> {
        if !Self::matches_file_pattern(path, &rule.file_patterns) {
            return None;
        }

        match &rule.detection {
            DetectionMatcher::RegexMatch { pattern, not_matching } => {
                let re = Regex::new(pattern).ok()?;
                if let Some(mat) = re.find(content) {
                    // Check exclusion filter if present
                    if let Some(not_pat) = not_matching {
                        if let Ok(not_re) = Regex::new(not_pat) {
                            if not_re.is_match(content) {
                                return None;
                            }
                        }
                    }

                    // Compute line number
                    let line_number = content[..mat.start()].lines().count() + 1;
                    let detected_snippet = mat.as_str().trim().to_string();

                    Some(Finding {
                        id: format!("dynamic-{}-{}", rule.id, path.display()),
                        cve: CveId::Custom {
                            id: rule.id.clone(),
                            title: rule.title.clone(),
                        },
                        severity: rule.severity,
                        target_kind: rule.target_kind.clone(),
                        file_path: Some(path.to_path_buf()),
                        line_number: Some(line_number),
                        detected_version_or_pattern: detected_snippet,
                        safe_threshold: "Refer to remediation blueprint".into(),
                        description: rule.description.clone(),
                        suggested_remediation: rule
                            .remediation
                            .as_ref()
                            .map(|r| match r {
                                RemediationStrategy::StringReplace { description, .. } => description.clone(),
                                RemediationStrategy::RegexReplace { description, .. } => description.clone(),
                                RemediationStrategy::AppendBlock { description, .. } => description.clone(),
                                RemediationStrategy::BumpDependency { description, .. } => description.clone(),
                            })
                            .unwrap_or_else(|| "Manual inspection required".into()),
                    })
                } else {
                    None
                }
            }
            DetectionMatcher::StringContains { search, except_if_contains } => {
                if let Some(pos) = content.find(search) {
                    if let Some(except) = except_if_contains {
                        if content.contains(except) {
                            return None;
                        }
                    }

                    let line_number = content[..pos].lines().count() + 1;
                    Some(Finding {
                        id: format!("dynamic-{}-{}", rule.id, path.display()),
                        cve: CveId::Custom {
                            id: rule.id.clone(),
                            title: rule.title.clone(),
                        },
                        severity: rule.severity,
                        target_kind: rule.target_kind.clone(),
                        file_path: Some(path.to_path_buf()),
                        line_number: Some(line_number),
                        detected_version_or_pattern: search.clone(),
                        safe_threshold: "Remediation rule available".into(),
                        description: rule.description.clone(),
                        suggested_remediation: rule
                            .remediation
                            .as_ref()
                            .map(|r| match r {
                                RemediationStrategy::StringReplace { description, .. } => description.clone(),
                                RemediationStrategy::RegexReplace { description, .. } => description.clone(),
                                RemediationStrategy::AppendBlock { description, .. } => description.clone(),
                                RemediationStrategy::BumpDependency { description, .. } => description.clone(),
                            })
                            .unwrap_or_else(|| "Manual inspection required".into()),
                    })
                } else {
                    None
                }
            }
            DetectionMatcher::MissingPattern { required_pattern } => {
                if !content.contains(required_pattern) {
                    Some(Finding {
                        id: format!("dynamic-{}-{}", rule.id, path.display()),
                        cve: CveId::Custom {
                            id: rule.id.clone(),
                            title: rule.title.clone(),
                        },
                        severity: rule.severity,
                        target_kind: rule.target_kind.clone(),
                        file_path: Some(path.to_path_buf()),
                        line_number: Some(1),
                        detected_version_or_pattern: format!("Missing required configuration: '{}'", required_pattern),
                        safe_threshold: format!("Configuration must include: '{}'", required_pattern),
                        description: rule.description.clone(),
                        suggested_remediation: rule
                            .remediation
                            .as_ref()
                            .map(|r| match r {
                                RemediationStrategy::StringReplace { description, .. } => description.clone(),
                                RemediationStrategy::RegexReplace { description, .. } => description.clone(),
                                RemediationStrategy::AppendBlock { description, .. } => description.clone(),
                                RemediationStrategy::BumpDependency { description, .. } => description.clone(),
                            })
                            .unwrap_or_else(|| "Manual configuration required".into()),
                    })
                } else {
                    None
                }
            }
            DetectionMatcher::SemVerDependency { package_name, vulnerable_range } => {
                // Parse package.json or composer.json
                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(content) {
                    let mut found_ver = None;
                    if let Some(deps) = parsed.get("dependencies").and_then(|d| d.as_object()) {
                        if let Some(v) = deps.get(package_name).and_then(|v| v.as_str()) {
                            found_ver = Some(v);
                        }
                    }
                    if found_ver.is_none() {
                        if let Some(dev_deps) = parsed.get("devDependencies").and_then(|d| d.as_object()) {
                            if let Some(v) = dev_deps.get(package_name).and_then(|v| v.as_str()) {
                                found_ver = Some(v);
                            }
                        }
                    }

                    if let Some(ver_str) = found_ver {
                        let clean_ver = ver_str.trim_start_matches('^').trim_start_matches('~').trim();
                        if let Ok(req) = semver::VersionReq::parse(vulnerable_range) {
                            if let Ok(sem) = semver::Version::parse(clean_ver) {
                                if req.matches(&sem) {
                                    return Some(Finding {
                                        id: format!("dynamic-{}-{}", rule.id, path.display()),
                                        cve: CveId::Custom {
                                            id: rule.id.clone(),
                                            title: rule.title.clone(),
                                        },
                                        severity: rule.severity,
                                        target_kind: rule.target_kind.clone(),
                                        file_path: Some(path.to_path_buf()),
                                        line_number: None,
                                        detected_version_or_pattern: format!("{} @ {}", package_name, ver_str),
                                        safe_threshold: format!("Must not match {}", vulnerable_range),
                                        description: rule.description.clone(),
                                        suggested_remediation: format!("Upgrade {} out of vulnerable range {}", package_name, vulnerable_range),
                                    });
                                }
                            }
                        }
                    }
                }
                None
            }
        }
    }

    /// Plans a patch action using the rule's defined remediation strategy.
    pub fn plan_patch(path: &Path, content: &str, rule: &VulnerabilityRule) -> Option<PatchAction> {
        let remediation = rule.remediation.as_ref()?;
        let original_checksum = {
            let mut hasher = Sha256::new();
            hasher.update(content.as_bytes());
            format!("{:x}", hasher.finalize())
        };

        match remediation {
            RemediationStrategy::StringReplace { search, replace, description } => {
                if !content.contains(search) {
                    return None;
                }
                let replacement_content = content.replace(search, replace);
                Some(PatchAction {
                    action_type: PatchActionType::GenericReplace,
                    target_file: path.to_path_buf(),
                    original_checksum,
                    diff_description: description.clone(),
                    replacement_content,
                })
            }
            RemediationStrategy::RegexReplace { search, replace, description } => {
                let re = Regex::new(search).ok()?;
                if !re.is_match(content) {
                    return None;
                }
                let replacement_content = re.replace_all(content, replace.as_str()).to_string();
                Some(PatchAction {
                    action_type: PatchActionType::GenericReplace,
                    target_file: path.to_path_buf(),
                    original_checksum,
                    diff_description: description.clone(),
                    replacement_content,
                })
            }
            RemediationStrategy::AppendBlock { snippet, description } => {
                if content.contains(snippet.trim()) {
                    return None;
                }
                let mut replacement_content = content.to_string();
                if !replacement_content.ends_with('\n') {
                    replacement_content.push('\n');
                }
                replacement_content.push_str(snippet);
                if !replacement_content.ends_with('\n') {
                    replacement_content.push('\n');
                }
                Some(PatchAction {
                    action_type: PatchActionType::GenericAppend,
                    target_file: path.to_path_buf(),
                    original_checksum,
                    diff_description: description.clone(),
                    replacement_content,
                })
            }
            RemediationStrategy::BumpDependency { package_name, safe_version, description } => {
                if let Ok(mut parsed) = serde_json::from_str::<serde_json::Value>(content) {
                    let mut modified = false;
                    if let Some(deps) = parsed.get_mut("dependencies").and_then(|d| d.as_object_mut()) {
                        if let Some(val) = deps.get_mut(package_name) {
                            *val = serde_json::Value::String(safe_version.clone());
                            modified = true;
                        }
                    }
                    if !modified {
                        if let Some(dev_deps) = parsed.get_mut("devDependencies").and_then(|d| d.as_object_mut()) {
                            if let Some(val) = dev_deps.get_mut(package_name) {
                                *val = serde_json::Value::String(safe_version.clone());
                                modified = true;
                            }
                        }
                    }

                    if modified {
                        let replacement_content = serde_json::to_string_pretty(&parsed).ok()?;
                        return Some(PatchAction {
                            action_type: PatchActionType::PackageManifestVersionBump,
                            target_file: path.to_path_buf(),
                            original_checksum,
                            diff_description: description.clone(),
                            replacement_content,
                        });
                    }
                }
                None
            }
        }
    }
}
