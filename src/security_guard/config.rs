#![allow(dead_code)]

use crate::types::*;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RemediationLevel {
    ReportOnly,
    #[default]
    Propose,
    GuardedLocalFix,
    PrivilegedRemediation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectConfig {
    pub name: String,
    pub initialized_at: String,
    pub languages: Vec<String>,
    pub package_managers: Vec<String>,
    pub scan_profile: ScanProfile,
    pub pre_commit_gate: bool,
    pub remediation_level: RemediationLevel,
    pub enabled_detectors: Vec<String>,
}

impl Default for ProjectConfig {
    fn default() -> Self {
        Self {
            name: "unnamed-project".to_string(),
            initialized_at: chrono::Utc::now().to_rfc3339(),
            languages: vec!["generic".to_string()],
            package_managers: Vec::new(),
            scan_profile: ScanProfile::Quick,
            pre_commit_gate: true,
            remediation_level: RemediationLevel::Propose,
            enabled_detectors: vec![
                "taint-sast".to_string(),
                "secret-detector".to_string(),
                "cicd-security".to_string(),
                "container-iac".to_string(),
                "agent-skill".to_string(),
                "osv-sca".to_string(),
            ],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySuppression {
    pub rule_id: String,
    pub reason: String,
    pub valid_until: Option<String>,
    pub path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectPolicy {
    pub version: String,
    pub min_confidence: Confidence,
    pub block_on_confirmed_critical: bool,
    pub block_on_failed_required_check: bool,
    pub allow_guarded_local_fix: bool,
    #[serde(default)]
    pub suppressions: Vec<PolicySuppression>,
}

impl Default for ProjectPolicy {
    fn default() -> Self {
        Self {
            version: "1.0".to_string(),
            min_confidence: Confidence::Medium,
            block_on_confirmed_critical: true,
            block_on_failed_required_check: true,
            allow_guarded_local_fix: false,
            suppressions: Vec::new(),
        }
    }
}

pub struct ConfigManager;

impl ConfigManager {
    pub fn config_dir(root: &Path) -> PathBuf {
        root.join(".bugkiller")
    }

    pub fn config_path(root: &Path) -> PathBuf {
        Self::config_dir(root).join("config.json")
    }

    pub fn policy_path(root: &Path) -> PathBuf {
        Self::config_dir(root).join("policy.json")
    }

    pub fn baseline_path(root: &Path) -> PathBuf {
        Self::config_dir(root).join("baseline.json")
    }

    pub fn is_initialized(root: &Path) -> bool {
        Self::config_path(root).exists()
    }

    /// Loads project config, returning default if not yet initialized.
    pub fn load_config(root: &Path) -> ProjectConfig {
        let path = Self::config_path(root);
        if let Ok(content) = fs::read_to_string(&path) {
            if let Ok(cfg) = serde_json::from_str(&content) {
                return cfg;
            }
        }
        ProjectConfig::default()
    }

    /// Loads project security policy, returning default if missing.
    pub fn load_policy(root: &Path) -> ProjectPolicy {
        let path = Self::policy_path(root);
        if let Ok(content) = fs::read_to_string(&path) {
            if let Ok(policy) = serde_json::from_str(&content) {
                return policy;
            }
        }
        ProjectPolicy::default()
    }

    /// Saves config, creating `.bugkiller` directory if needed.
    pub fn save_config(root: &Path, config: &ProjectConfig) -> Result<(), String> {
        let dir = Self::config_dir(root);
        fs::create_dir_all(&dir).map_err(|e| format!("Failed to create .bugkiller dir: {}", e))?;
        let content = serde_json::to_string_pretty(config)
            .map_err(|e| format!("Failed to serialize config: {}", e))?;
        fs::write(Self::config_path(root), content)
            .map_err(|e| format!("Failed to write config.json: {}", e))?;
        Ok(())
    }

    /// Saves policy, creating `.bugkiller` directory if needed.
    pub fn save_policy(root: &Path, policy: &ProjectPolicy) -> Result<(), String> {
        let dir = Self::config_dir(root);
        fs::create_dir_all(&dir).map_err(|e| format!("Failed to create .bugkiller dir: {}", e))?;
        let content = serde_json::to_string_pretty(policy)
            .map_err(|e| format!("Failed to serialize policy: {}", e))?;
        fs::write(Self::policy_path(root), content)
            .map_err(|e| format!("Failed to write policy.json: {}", e))?;
        Ok(())
    }
}
