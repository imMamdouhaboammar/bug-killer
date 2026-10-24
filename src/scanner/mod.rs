pub mod php;
pub mod node;
pub mod webserver;

use std::path::Path;
use walkdir::WalkDir;
use chrono::Utc;
use crate::types::*;
use crate::rules::{RuleEngine, VulnerabilityRule};
use self::php::PhpScanner;
use self::node::NodeScanner;
use self::webserver::WebServerScanner;

pub struct FleetScanner;

impl FleetScanner {
    /// Recursively scans a filesystem root directory for both built-in CVEs and dynamic rules.
    pub fn scan_directory(root: &Path, check_host_runtimes: bool) -> ScanReport {
        let rules = RuleEngine::load_rules(None, root);
        Self::scan_directory_with_rules(root, check_host_runtimes, &rules)
    }

    /// Recursively scans a filesystem root directory using an explicit set of vulnerability rules.
    pub fn scan_directory_with_rules(root: &Path, check_host_runtimes: bool, rules: &[VulnerabilityRule]) -> ScanReport {
        Self::scan_directory_with_rules_and_taint(root, check_host_runtimes, rules, false)
    }

    /// Recursively scans a filesystem root directory with rules and optional taint analysis.
    pub fn scan_directory_with_rules_and_taint(
        root: &Path,
        check_host_runtimes: bool,
        rules: &[VulnerabilityRule],
        enable_taint: bool,
    ) -> ScanReport {
        let mut findings = Vec::new();
        let mut total_files = 0;

        // 1. Optionally inspect host runtimes (PHP & Node binaries on PATH)
        if check_host_runtimes {
            if let Some(php_finding) = PhpScanner::scan_host_runtime() {
                findings.push(php_finding);
            }
            if let Some(node_finding) = NodeScanner::scan_host_runtime() {
                findings.push(node_finding);
            }
        }

        // 2. Walk directory files
        for entry in WalkDir::new(root)
            .into_iter()
            .filter_entry(|e| {
                if e.depth() == 0 {
                    return true;
                }
                let name = e.file_name().to_string_lossy();
                // Skip version control and heavy build directories
                name != ".git" && name != "node_modules" && name != "vendor" && name != "target" && name != ".aegis"
            })
            .filter_map(|e| e.ok())
        {
            if !entry.file_type().is_file() {
                continue;
            }

            total_files += 1;
            let path = entry.path();
            let file_name = path.file_name().unwrap_or_default().to_string_lossy();

            // Composer manifests
            if file_name == "composer.json" {
                findings.extend(PhpScanner::scan_composer_json(path));
            }

            // Node manifests
            if file_name == "package.json" {
                findings.extend(NodeScanner::scan_package_json(path));
            }

            // Dockerfiles
            if file_name == "Dockerfile" || file_name.starts_with("Dockerfile.") {
                findings.extend(PhpScanner::scan_dockerfile(path));
                findings.extend(NodeScanner::scan_dockerfile(path));
            }

            // PHP configs
            if file_name == "php.ini" || file_name.ends_with(".ini") || file_name == "www.conf" {
                findings.extend(PhpScanner::scan_php_config(path));
            }

            // Web server configs
            if file_name == "nginx.conf" || path.to_string_lossy().contains("nginx") && file_name.ends_with(".conf") {
                findings.extend(WebServerScanner::scan_nginx_config(path));
            }
            if file_name == "httpd.conf" || file_name == "apache2.conf" || file_name == ".htaccess" {
                findings.extend(WebServerScanner::scan_apache_config(path));
            }

            // Source files (.js, .ts, .mjs, .cjs)
            if file_name.ends_with(".js")
                || file_name.ends_with(".ts")
                || file_name.ends_with(".mjs")
                || file_name.ends_with(".cjs")
            {
                findings.extend(NodeScanner::scan_source_file(path));
            }

            // 3. Dynamic vulnerability rules evaluation
            if !rules.is_empty() && rules.iter().any(|r| RuleEngine::matches_file_pattern(path, &r.file_patterns)) {
                if let Ok(content) = std::fs::read_to_string(path) {
                    for rule in rules {
                        if let Some(finding) = RuleEngine::scan_file(path, &content, rule) {
                            findings.push(finding);
                        }
                    }
                }
            }

            // 4. Lightweight Scope-Aware Taint Analysis
            if enable_taint
                && (file_name.ends_with(".js")
                    || file_name.ends_with(".ts")
                    || file_name.ends_with(".mjs")
                    || file_name.ends_with(".cjs")
                    || file_name.ends_with(".py")
                    || file_name.ends_with(".php")
                    || file_name.ends_with(".go"))
            {
                if let Ok(content) = std::fs::read_to_string(path) {
                    for tf in crate::taint::TaintEngine::scan_source(path, &content) {
                        findings.push(tf.into_finding());
                    }
                }
            }
        }

        let is_vulnerable = !findings.is_empty();
        let critical_count = findings.iter().filter(|f| f.severity == Severity::Critical).count();
        let high_count = findings.iter().filter(|f| f.severity == Severity::High).count();

        ScanReport {
            target_dir: root.to_path_buf(),
            scan_time: Utc::now().to_rfc3339(),
            total_files_scanned: total_files,
            findings,
            is_vulnerable,
            critical_count,
            high_count,
        }
    }
}
