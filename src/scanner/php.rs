use crate::cve_db::CveDatabase;
use crate::types::*;
use regex::Regex;
use std::fs;
use std::path::Path;
use std::process::Command;

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
                if let Some((cve, severity, safe_threshold)) =
                    CveDatabase::check_php_version(major, minor, patch)
                {
                    let mut finding = Finding::new(
                        format!("PHP-HOST-{}", cve.as_str()),
                        cve.clone(),
                        severity,
                        TargetKind::PhpRuntime,
                        None,
                        None,
                        format!("Host PHP {}", ver_str),
                        safe_threshold.to_string(),
                        format!(
                            "Host PHP binary is vulnerable to {}: {}. Unauthenticated remote memory corruption via OOM/abnormal request exit.",
                            cve.as_str(),
                            cve.title()
                        ),
                        format!("Update system PHP package to {}", safe_threshold),
                    );
                    finding.detector_id = "php-runtime".to_string();
                    finding.installed_build = Some(ver_str.to_string());
                    finding.affectedness = Affectedness::ConfirmedAffected;
                    finding.reachability = Reachability::ConfirmedReachable;
                    finding.confidence = Confidence::High;
                    finding.exploitability_signal = ExploitabilitySignal::PublicPocAvailable;
                    finding.compute_dedupe_fingerprint();
                    return Some(finding);
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
                        if let Some((cve, severity, safe_threshold)) =
                            CveDatabase::check_php_version(major, minor, patch)
                        {
                            let mut finding = Finding::new(
                                format!("COMPOSER-{}", cve.as_str()),
                                cve,
                                severity,
                                TargetKind::ComposerManifest,
                                Some(path.to_path_buf()),
                                None,
                                format!("require.php: '{}'", php_val),
                                safe_threshold.to_string(),
                                format!(
                                    "composer.json explicitly permits vulnerable PHP versions ({}) exposed to PHP2Shell.",
                                    php_val
                                ),
                                format!(
                                    "Update require.php to enforce safe patch levels (e.g. '{}')",
                                    safe_threshold
                                ),
                            );
                            finding.detector_id = "php-composer".to_string();
                            finding.affectedness = Affectedness::PotentiallyAffected;
                            finding.reachability = Reachability::Unknown;
                            finding.confidence = Confidence::Medium;
                            finding.uncertainty_reasons.push(
                                "composer.json allows vulnerable PHP version, but active host/container interpreter was not verified.".to_string(),
                            );
                            finding
                                .missing_checks
                                .push("verify_installed_php_version".to_string());
                            finding
                                .missing_checks
                                .push("verify_fpm_process".to_string());
                            finding.compute_dedupe_fingerprint();
                            findings.push(finding);
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
                    if let Some((cve, severity, safe_threshold)) =
                        CveDatabase::check_php_version(major, minor, patch)
                    {
                        let mut finding = Finding::new(
                            format!("DOCKER-PHP-{}", cve.as_str()),
                            cve,
                            severity,
                            TargetKind::Dockerfile,
                            Some(path.to_path_buf()),
                            Some(idx + 1),
                            line.trim(),
                            safe_threshold.to_string(),
                            format!(
                                "Dockerfile pins vulnerable base image 'php:{}' susceptible to PHP2Shell RCE.",
                                tag
                            ),
                            format!(
                                "Update base image tag in Dockerfile to safe release: {}",
                                safe_threshold
                            ),
                        );
                        finding.detector_id = "docker-php".to_string();
                        finding.affectedness = Affectedness::ConfirmedAffected;
                        finding.reachability = Reachability::PotentiallyReachable;
                        finding.confidence = Confidence::High;
                        finding.compute_dedupe_fingerprint();
                        findings.push(finding);
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

            if trimmed.contains("memory_limit")
                && (trimmed.contains("-1") || trimmed.contains("= -1"))
            {
                let mut finding = Finding::new(
                    "PHP-INI-UNLIMITED-MEMORY",
                    CveId::Php2ShellOom("CVE-2026-109618".into()),
                    Severity::Medium,
                    TargetKind::PhpConfigFile,
                    Some(path.to_path_buf()),
                    Some(idx + 1),
                    trimmed,
                    "memory_limit = 256M",
                    "Disabling memory_limit (-1) allows unbounded heap growth, exacerbating out-of-memory exhaustion attack vectors.",
                    "Set a deterministic memory_limit (e.g. 256M) in php.ini",
                );
                finding.detector_id = "php-config".to_string();
                finding.affectedness = Affectedness::PotentiallyAffected;
                finding.reachability = Reachability::PotentiallyReachable;
                finding.confidence = Confidence::Medium;
                finding.compute_dedupe_fingerprint();
                findings.push(finding);
            }
        }

        findings
    }
}
