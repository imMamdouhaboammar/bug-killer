use std::fs;
use std::path::Path;
use std::process::Command;
use regex::Regex;
use crate::cve_db::CveDatabase;
use crate::types::*;

pub struct PhpScanner;

impl PhpScanner {
    /// Inspects the host machine's installed PHP binary via `php -v`.
    pub fn scan_host_runtime() -> Option<Finding> {
        let output = Command::new("php").arg("-v").output().ok()?;
        if !output.status.success() {
            return None;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let re = Regex::new(r"PHP\s+(\d+\.\d+\.\d+)").ok()?;
        if let Some(caps) = re.captures(&stdout) {
            let ver_str = &caps[1];
            if let Some((major, minor, patch)) = CveDatabase::parse_semver(ver_str) {
                if let Some((cve, severity, safe_threshold)) = CveDatabase::check_php_version(major, minor, patch) {
                    return Some(Finding {
                        id: format!("PHP-HOST-{}", cve.as_str()),
                        cve: cve.clone(),
                        severity,
                        target_kind: TargetKind::PhpRuntime,
                        file_path: None,
                        line_number: None,
                        detected_version_or_pattern: format!("Host PHP {}", ver_str),
                        safe_threshold: safe_threshold.to_string(),
                        description: format!(
                            "Host PHP binary is vulnerable to {}: {}. Unauthenticated remote memory corruption via OOM/abnormal request exit.",
                            cve.as_str(),
                            cve.title()
                        ),
                        suggested_remediation: format!("Update system PHP package to {}", safe_threshold),
                    });
                }
            }
        }
        None
    }

    /// Scans a `composer.json` file for vulnerable PHP requirements.
    pub fn scan_composer_json(path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => return findings,
        };

        let json: serde_json::Value = match serde_json::from_str(&content) {
            Ok(j) => j,
            Err(_) => return findings,
        };

        if let Some(req) = json.get("require").and_then(|r| r.as_object()) {
            if let Some(php_val) = req.get("php").and_then(|p| p.as_str()) {
                // Check if constraint allows vulnerable versions, e.g. "^8.2", ">=8.2", "~8.3.0"
                let re = Regex::new(r"(\d+\.\d+(?:\.\d+)?)").unwrap();
                for cap in re.captures_iter(php_val) {
                    let ver_str = &cap[1];
                    if let Some((major, minor, patch)) = CveDatabase::parse_semver(ver_str) {
                        if let Some((cve, severity, safe_threshold)) = CveDatabase::check_php_version(major, minor, patch) {
                            findings.push(Finding {
                                id: format!("COMPOSER-{}", cve.as_str()),
                                cve,
                                severity,
                                target_kind: TargetKind::ComposerManifest,
                                file_path: Some(path.to_path_buf()),
                                line_number: None,
                                detected_version_or_pattern: format!("require.php: '{}'", php_val),
                                safe_threshold: safe_threshold.to_string(),
                                description: format!(
                                    "composer.json explicitly permits vulnerable PHP versions ({}) exposed to PHP2Shell.",
                                    php_val
                                ),
                                suggested_remediation: format!(
                                    "Update require.php to enforce safe patch levels (e.g. '{}')",
                                    safe_threshold
                                ),
                            });
                            break;
                        }
                    }
                }
            }
        }

        findings
    }

    /// Scans Dockerfiles for vulnerable base images (`FROM php:8.2-fpm`, `FROM php:8.3-apache`).
    pub fn scan_dockerfile(path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => return findings,
        };

        let re = Regex::new(r"(?i)^FROM\s+php:([0-9\.\-a-z]+)").unwrap();
        for (idx, line) in content.lines().enumerate() {
            if let Some(caps) = re.captures(line) {
                let tag = &caps[1];
                if let Some((major, minor, patch)) = CveDatabase::parse_semver(tag) {
                    if let Some((cve, severity, safe_threshold)) = CveDatabase::check_php_version(major, minor, patch) {
                        findings.push(Finding {
                            id: format!("DOCKER-PHP-{}", cve.as_str()),
                            cve,
                            severity,
                            target_kind: TargetKind::Dockerfile,
                            file_path: Some(path.to_path_buf()),
                            line_number: Some(idx + 1),
                            detected_version_or_pattern: line.trim().to_string(),
                            safe_threshold: safe_threshold.to_string(),
                            description: format!(
                                "Dockerfile pins vulnerable base image 'php:{}' susceptible to PHP2Shell RCE.",
                                tag
                            ),
                            suggested_remediation: format!(
                                "Update base image tag in Dockerfile to safe release: {}",
                                safe_threshold
                            ),
                        });
                    }
                }
            }
        }

        findings
    }

    /// Scans `php.ini` or PHP-FPM configuration files for dangerous settings.
    pub fn scan_php_config(path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => return findings,
        };

        // Notice: CVE-2026-109618 OOM heap corruption is exacerbated by unlimited or extremely low memory_limit
        // combined with uncaught fatal error handlers or max_execution_time traps.
        for (idx, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with(';') || trimmed.starts_with('#') {
                continue;
            }

            if trimmed.contains("memory_limit") && (trimmed.contains("-1") || trimmed.contains("= -1")) {
                findings.push(Finding {
                    id: "PHP-INI-UNLIMITED-MEMORY".to_string(),
                    cve: CveId::Php2ShellOom("CVE-2026-109618".into()),
                    severity: Severity::Medium,
                    target_kind: TargetKind::PhpConfigFile,
                    file_path: Some(path.to_path_buf()),
                    line_number: Some(idx + 1),
                    detected_version_or_pattern: trimmed.to_string(),
                    safe_threshold: "memory_limit = 256M".to_string(),
                    description: "Disabling memory_limit (-1) allows unbounded heap growth, exacerbating out-of-memory exhaustion attack vectors.".to_string(),
                    suggested_remediation: "Set a deterministic memory_limit (e.g. 256M) in php.ini".to_string(),
                });
            }
        }

        findings
    }
}
