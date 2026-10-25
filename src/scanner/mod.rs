pub mod ai_agent;
pub mod ai_agent_ext;
pub mod api;
pub mod auth;
pub mod authz;
pub mod binary;
pub mod biz_concurrency;
pub mod bkh_safety;
pub mod cicd;
pub mod container;
pub mod crypto;
pub mod data_privacy;
pub mod filesystem_ext;
pub mod host;
pub mod iac;
pub mod injection;
pub mod language_pitfalls;
pub mod mem_temp;
pub mod native_desktop;
pub mod network_dos;
pub mod node;
pub mod ops_qa;
pub mod parser_security;
pub mod php;
pub mod secret;
pub mod supply_chain;
pub mod web;
pub mod webserver;

use self::ai_agent::AgentSecurityScanner;
use self::binary::BinaryScanner;
use self::cicd::CicdScanner;
use self::container::ContainerScanner;
use self::host::HostProcessScanner;
use self::node::NodeScanner;
use self::php::PhpScanner;
use self::secret::SecretScanner;
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
        let mut taint_files_evaluated = 0;
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
                    || name == ".aegis"
                    || name == ".bugkiller";
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
                || file_name == "package-lock.json"
                || file_name == "composer.lock"
                || file_name == "Dockerfile"
                || file_name.starts_with("Dockerfile.")
                || file_name == "Containerfile"
                || file_name.starts_with("Containerfile.")
                || file_name == "php.ini"
                || file_name.ends_with(".ini")
                || file_name == "www.conf"
                || file_name == "nginx.conf"
                || file_name == "httpd.conf"
                || file_name == "apache2.conf"
                || file_name == ".htaccess"
                || file_name == ".mcp.json"
                || file_name == "claude_desktop_config.json"
                || file_name == "gemini.json"
                || file_name == "SKILL.md"
                || file_name.ends_with(".skill")
                || file_name == "bom.json"
                || file_name == "cyclonedx.json"
                || file_name.ends_with(".cdx.json")
                || file_name == "spdx.json"
                || file_name.ends_with(".spdx.json")
                || file_name.ends_with(".js")
                || file_name.ends_with(".ts")
                || file_name.ends_with(".mjs")
                || file_name.ends_with(".cjs")
                || file_name.ends_with(".py")
                || file_name.ends_with(".php")
                || file_name.ends_with(".go")
                || file_name.ends_with(".yml")
                || file_name.ends_with(".yaml")
                || file_name.starts_with(".env")
                || file_name.ends_with(".key")
                || file_name.ends_with(".pem");

            if is_candidate {
                match std::fs::read_to_string(path) {
                    Err(e) => {
                        // Packaged .skill bundles are binary zip archives, not text files.
                        if file_name.ends_with(".skill") {
                            if let Ok(bytes) = std::fs::read(path) {
                                if bytes.starts_with(b"PK") {
                                    continue;
                                }
                            }
                        }
                        parser_failures.push(ParserFailure {
                            path: path.to_path_buf(),
                            reason: format!("I/O or UTF-8 read failure: {}", e),
                        });
                        continue;
                    }
                    Ok(content) => {
                        if file_name.ends_with(".json")
                            || file_name.ends_with(".cdx.json")
                            || file_name.ends_with(".spdx.json")
                        {
                            if let Err(e) = serde_json::from_str::<serde_json::Value>(&content) {
                                parser_failures.push(ParserFailure {
                                    path: path.to_path_buf(),
                                    reason: format!("JSON parse failure: {}", e),
                                });
                                continue;
                            }
                        }
                    }
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

            // Dockerfiles and Containerfiles
            if file_name == "Dockerfile"
                || file_name.starts_with("Dockerfile.")
                || file_name == "Containerfile"
                || file_name.starts_with("Containerfile.")
            {
                raw_findings.extend(PhpScanner::scan_dockerfile(path));
                raw_findings.extend(NodeScanner::scan_dockerfile(path));
                raw_findings.extend(ContainerScanner::scan_dockerfile(path));
            }

            // AI agent and MCP configurations
            if file_name == ".mcp.json"
                || file_name == "claude_desktop_config.json"
                || file_name == "gemini.json"
            {
                raw_findings.extend(AgentSecurityScanner::scan_mcp_config(path));
            }
            if file_name.ends_with(".json")
                && !path.to_string_lossy().contains("/tests/")
                && !path.to_string_lossy().starts_with("tests/")
            {
                raw_findings.extend(AgentSecurityScanner::scan_agent_config(path));
            }
            if file_name == "SKILL.md" || file_name.ends_with(".skill") {
                raw_findings.extend(AgentSecurityScanner::scan_agent_skill(path));
            }

            // Binary executable inspection
            if BinaryScanner::is_binary_executable(path) {
                match BinaryScanner::scan_binary(path) {
                    Ok(findings) => raw_findings.extend(findings),
                    Err(reason) => parser_failures.push(ParserFailure {
                        path: path.to_path_buf(),
                        reason,
                    }),
                }
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

            // CI/CD workflow security (.github/workflows/*.yml, .gitlab-ci.yml)
            if (path.to_string_lossy().contains(".github")
                && (file_name.ends_with(".yml") || file_name.ends_with(".yaml")))
                || file_name == ".gitlab-ci.yml"
            {
                if let Ok(content) = std::fs::read_to_string(path) {
                    raw_findings.extend(CicdScanner::scan_workflow(path, &content));
                }
            }

            // YAML expression injection in non-GitHub YAML files
            if (file_name.ends_with(".yml") || file_name.ends_with(".yaml"))
                && !path.to_string_lossy().contains(".github")
                && !path.to_string_lossy().contains("/tests/")
                && !path.to_string_lossy().starts_with("tests/")
            {
                if let Ok(content) = std::fs::read_to_string(path) {
                    raw_findings.extend(
                        self::injection::InjectionScanner::scan_yaml_expr_injection(path, &content),
                    );
                }
            }

            // Cryptographic weakness inspection, ReDoS checks, and LLM output sink checks across application sources
            let is_script_source = file_name.ends_with(".js")
                || file_name.ends_with(".ts")
                || file_name.ends_with(".mjs")
                || file_name.ends_with(".cjs")
                || file_name.ends_with(".py")
                || file_name.ends_with(".go")
                || file_name.ends_with(".php");

            let is_native_source = [
                ".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".rs", ".zig", ".swift", ".kt", ".java",
                ".m", ".mm",
            ]
            .iter()
            .any(|extension| file_name.ends_with(extension))
                || file_name == "AndroidManifest.xml"
                || file_name == "CMakeLists.txt";

            let is_test_file = path.to_string_lossy().contains("/tests/")
                || path.to_string_lossy().starts_with("tests/")
                || file_name.ends_with("_test.rs")
                || file_name.ends_with(".test.js")
                || file_name.ends_with(".test.ts");

            if is_script_source && !is_test_file {
                if let Ok(content) = std::fs::read_to_string(path) {
                    raw_findings.extend(self::crypto::CryptoScanner::scan_source(path, &content));
                    raw_findings.extend(self::injection::InjectionScanner::scan_redos(
                        path, &content,
                    ));
                    raw_findings.extend(AgentSecurityScanner::scan_model_output_execution(
                        path, &content,
                    ));
                    raw_findings.extend(self::web::WebSecurityScanner::scan_source(path, &content));
                    raw_findings.extend(self::api::ApiSecurityScanner::scan_source(path, &content));
                    raw_findings
                        .extend(self::auth::AuthSecurityScanner::scan_source(path, &content));
                    raw_findings.extend(self::authz::AuthzSecurityScanner::scan_source(
                        path, &content,
                    ));
                    raw_findings.extend(self::filesystem_ext::FilesystemExtScanner::scan_source(
                        path, &content,
                    ));
                    raw_findings.extend(self::data_privacy::DataPrivacyScanner::scan_source(
                        path, &content,
                    ));
                    raw_findings.extend(self::parser_security::ParserSecurityScanner::scan_source(
                        path, &content,
                    ));
                    raw_findings.extend(self::network_dos::NetworkDosScanner::scan_source(
                        path, &content,
                    ));
                    raw_findings.extend(self::iac::IacScanner::scan_source(path, &content));
                    raw_findings.extend(self::supply_chain::SupplyChainScanner::scan_source(
                        path, &content,
                    ));
                    raw_findings.extend(self::biz_concurrency::BizConcurrencyScanner::scan_source(
                        path, &content,
                    ));
                    raw_findings.extend(self::ai_agent_ext::AiAgentExtScanner::scan_source(
                        path, &content,
                    ));
                    raw_findings.extend(
                        self::language_pitfalls::LanguagePitfallsScanner::scan_source(
                            path, &content,
                        ),
                    );
                    raw_findings.extend(self::native_desktop::NativeDesktopScanner::scan_source(
                        path, &content,
                    ));
                    raw_findings.extend(self::ops_qa::OpsQaScanner::scan_source(path, &content));
                    raw_findings.extend(self::bkh_safety::BkhSafetyScanner::scan_source(
                        path, &content,
                    ));
                    raw_findings
                        .extend(self::mem_temp::MemTempScanner::scan_source(path, &content));
                }
            }

            // Native-memory detectors must also receive native languages and
            // native build/manifest files, not only JS/Python/Go scripts.
            if is_native_source && !is_test_file {
                if let Ok(content) = std::fs::read_to_string(path) {
                    raw_findings.extend(self::native_desktop::NativeDesktopScanner::scan_source(
                        path, &content,
                    ));
                    raw_findings
                        .extend(self::mem_temp::MemTempScanner::scan_source(path, &content));
                }
            }

            let is_iac_or_manifest = file_name.ends_with(".tf")
                || file_name.ends_with(".toml")
                || file_name == "package.json"
                || file_name == "requirements.txt"
                || file_name == "Pipfile"
                || file_name == "go.mod"
                || file_name == "Dockerfile"
                || file_name.starts_with("Dockerfile.")
                || file_name == "Containerfile"
                || file_name.starts_with("Containerfile.");

            if is_iac_or_manifest && !is_test_file {
                if let Ok(content) = std::fs::read_to_string(path) {
                    raw_findings.extend(self::iac::IacScanner::scan_source(path, &content));
                    raw_findings.extend(self::supply_chain::SupplyChainScanner::scan_source(
                        path, &content,
                    ));
                }
            }

            if (file_name.ends_with(".html") || file_name.ends_with(".htm")) && !is_test_file {
                if let Ok(content) = std::fs::read_to_string(path) {
                    raw_findings.extend(self::web::WebSecurityScanner::scan_source(path, &content));
                }
            }

            // Secret detection across source code, config files, keys, and environment files
            if file_name.ends_with(".js")
                || file_name.ends_with(".ts")
                || file_name.ends_with(".mjs")
                || file_name.ends_with(".cjs")
                || file_name.ends_with(".py")
                || file_name.ends_with(".php")
                || file_name.ends_with(".go")
                || file_name.ends_with(".rs")
                || file_name.starts_with(".env")
                || file_name.ends_with(".key")
                || file_name.ends_with(".pem")
                || file_name == "Dockerfile"
                || file_name.starts_with("Dockerfile.")
            {
                if let Ok(content) = std::fs::read_to_string(path) {
                    raw_findings.extend(SecretScanner::scan_file(path, &content));
                }
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
                taint_files_evaluated += 1;
                if let Ok(content) = std::fs::read_to_string(path) {
                    for tf in crate::taint::TaintEngine::scan_source(path, &content) {
                        raw_findings.push(tf.into_finding());
                    }
                }
            }
        }

        // Correlate live runtime process identities when host inspection is enabled
        if check_host_runtimes {
            let procs = HostProcessScanner::discover_running_processes();
            HostProcessScanner::correlate_findings_with_runtime(&mut raw_findings, &procs);
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

        let mut receipts = Vec::new();
        if enable_taint {
            receipts.push(CoverageReceipt {
                scanner_id: "taint-sast".to_string(),
                scanner_version: env!("CARGO_PKG_VERSION").to_string(),
                target_id: root.display().to_string(),
                status: CoverageStatus::Complete,
                items_examined: taint_files_evaluated as u64,
                skipped_reasons: Vec::new(),
                errors: Vec::new(),
                completed_at: chrono::Utc::now().to_rfc3339(),
            });
        }

        let coverage = ScanCoverage {
            files_scanned: total_files,
            files_excluded: files_excluded.load(Ordering::Relaxed),
            parser_failures,
            unsupported_targets: Vec::new(),
            coverage_status,
            receipts,
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
