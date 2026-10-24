pub mod node;
pub mod php;
pub mod webserver;

use self::node::NodeScanner;
use self::php::PhpScanner;
use self::webserver::WebServerScanner;
use crate::rules::{RuleEngine, VulnerabilityRule};
use crate::types::*;
use chrono::Utc;
use std::collections::HashSet;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use walkdir::WalkDir;

pub struct FleetScanner;

impl FleetScanner {
    /// Recursively scans a filesystem root directory for both built-in CVEs and dynamic rules.
    pub fn scan_directory(root: &Path, check_host_runtimes: bool) -> ScanReport {
        let rules = RuleEngine::load_rules(None, root);
        Self::scan_directory_with_rules(root, check_host_runtimes, &rules)
    }

    /// Recursively scans a filesystem root directory using an explicit set of vulnerability rules.
    pub fn scan_directory_with_rules(
        root: &Path,
        check_host_runtimes: bool,
        rules: &[VulnerabilityRule],
    ) -> ScanReport {
        Self::scan_directory_with_rules_and_taint(root, check_host_runtimes, rules, false)
    }

    /// Recursively scans a filesystem root directory with rules and optional taint analysis.
    pub fn scan_directory_with_rules_and_taint(
        root: &Path,
        check_host_runtimes: bool,
        rules: &[VulnerabilityRule],
        enable_taint: bool,
    ) -> ScanReport {
        let mut raw_findings = Vec::new();
        let mut total_files = 0;
        let mut parser_failures = Vec::new();
        let files_excluded = AtomicUsize::new(0);

        // 1. Optionally inspect host runtimes (PHP & Node binaries on PATH)
        if check_host_runtimes {
            if let Some(php_finding) = PhpScanner::scan_host_runtime() {
                raw_findings.push(php_finding);
            }
            if let Some(node_finding) = NodeScanner::scan_host_runtime() {
                raw_findings.push(node_finding);
            }
        }

        // 2. Walk directory files with explicit exclusion tracking
        for entry in WalkDir::new(root)
            .into_iter()
            .filter_entry(|e| {
                if e.depth() == 0 {
                    return true;
                }
                let name = e.file_name().to_string_lossy();
                let skip = name == ".git"
                    || name == "node_modules"
                    || name == "vendor"
                    || name == "target"
                    || name == ".aegis";
                if skip {
                    files_excluded.fetch_add(1, Ordering::Relaxed);
                    return false;
                }
                true
            })
            .filter_map(|e| e.ok())
        {
            if !entry.file_type().is_file() {
                continue;
            }

            total_files += 1;
            let path = entry.path();
            let file_name = path.file_name().unwrap_or_default().to_string_lossy();

            // Verify readability for candidate targets
            let is_candidate = file_name == "composer.json"
                || file_name == "package.json"
                || file_name == "Dockerfile"
                || file_name.starts_with("Dockerfile.")
                || file_name == "php.ini"
                || file_name.ends_with(".ini")
                || file_name == "www.conf"
                || file_name == "nginx.conf"
                || file_name == "httpd.conf"
                || file_name == "apache2.conf"
                || file_name == ".htaccess"
                || file_name.ends_with(".js")
                || file_name.ends_with(".ts")
                || file_name.ends_with(".mjs")
                || file_name.ends_with(".cjs")
                || file_name.ends_with(".py")
                || file_name.ends_with(".php")
                || file_name.ends_with(".go");

            if is_candidate {
                if let Err(e) = std::fs::read_to_string(path) {
                    parser_failures.push(ParserFailure {
                        path: path.to_path_buf(),
                        reason: format!("I/O or UTF-8 read failure: {}", e),
                    });
                    continue;
                }
            }

            // Composer manifests
            if file_name == "composer.json" {
                raw_findings.extend(PhpScanner::scan_composer_json(path));
            }

            // Node manifests
            if file_name == "package.json" {
                raw_findings.extend(NodeScanner::scan_package_json(path));
            }

            // Dockerfiles
            if file_name == "Dockerfile" || file_name.starts_with("Dockerfile.") {
                raw_findings.extend(PhpScanner::scan_dockerfile(path));
                raw_findings.extend(NodeScanner::scan_dockerfile(path));
            }

            // PHP configs
            if file_name == "php.ini" || file_name.ends_with(".ini") || file_name == "www.conf" {
                raw_findings.extend(PhpScanner::scan_php_config(path));
            }

            // Web server configs
            if file_name == "nginx.conf"
                || path.to_string_lossy().contains("nginx") && file_name.ends_with(".conf")
            {
                raw_findings.extend(WebServerScanner::scan_nginx_config(path));
            }
            if file_name == "httpd.conf" || file_name == "apache2.conf" || file_name == ".htaccess"
            {
                raw_findings.extend(WebServerScanner::scan_apache_config(path));
            }

            // Source files (.js, .ts, .mjs, .cjs)
            if file_name.ends_with(".js")
                || file_name.ends_with(".ts")
                || file_name.ends_with(".mjs")
                || file_name.ends_with(".cjs")
            {
                raw_findings.extend(NodeScanner::scan_source_file(path));
            }

            // 3. Dynamic vulnerability rules evaluation
            if !rules.is_empty()
                && rules
                    .iter()
                    .any(|r| RuleEngine::matches_file_pattern(path, &r.file_patterns))
            {
                if let Ok(content) = std::fs::read_to_string(path) {
                    for rule in rules {
                        if let Some(finding) = RuleEngine::scan_file(path, &content, rule) {
                            raw_findings.push(finding);
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
                        raw_findings.push(tf.into_finding());
                    }
                }
            }
        }

        // Deduplication using cryptographic dedupe fingerprints
        let mut findings = Vec::new();
        let mut seen = HashSet::new();
        for mut f in raw_findings {
            if f.dedupe_fingerprint.is_empty() {
                f.compute_dedupe_fingerprint();
            }
            if seen.insert(f.dedupe_fingerprint.clone()) {
                findings.push(f);
            }
        }

        let is_vulnerable = !findings.is_empty();
        let critical_count = findings
            .iter()
            .filter(|f| f.severity == Severity::Critical)
            .count();
        let high_count = findings
            .iter()
            .filter(|f| f.severity == Severity::High)
            .count();

        let coverage_status = if parser_failures.is_empty() {
            CoverageStatus::Complete
        } else {
            CoverageStatus::Partial
        };

        let coverage = ScanCoverage {
            files_scanned: total_files,
            files_excluded: files_excluded.load(Ordering::Relaxed),
            parser_failures,
            unsupported_targets: Vec::new(),
            coverage_status,
        };

        ScanReport {
            target_dir: root.to_path_buf(),
            scan_time: Utc::now().to_rfc3339(),
            total_files_scanned: total_files,
            findings,
            is_vulnerable,
            critical_count,
            high_count,
            coverage,
        }
    }
}
