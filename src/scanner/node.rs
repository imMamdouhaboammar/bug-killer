use crate::cve_db::CveDatabase;
use crate::types::*;
use regex::Regex;
use std::fs;
use std::path::Path;
use std::process::Command;

pub struct NodeScanner;

impl NodeScanner {
    /// Inspects the host machine's installed Node.js binary via `node -v`.
    pub fn scan_host_runtime() -> Option<Finding> {
        let output = Command::new("node").arg("-v").output().ok()?;
        if !output.status.success() {
            return None;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let ver_str = stdout.trim().trim_start_matches('v');
        if let Some((major, minor, patch)) = CveDatabase::parse_semver(ver_str) {
            if let Some((cve, severity, safe_threshold)) =
                CveDatabase::check_node_version(major, minor, patch)
            {
                let mut finding = Finding::new(
                    format!("NODE-HOST-{}", cve.as_str()),
                    cve.clone(),
                    severity,
                    TargetKind::NodeRuntime,
                    None,
                    None,
                    format!("Host Node.js v{}", ver_str),
                    safe_threshold.to_string(),
                    format!(
                        "Host Node.js binary bundles vulnerable Google Brotli decoder ({}: {}). Out-of-bounds write / buffer overflow on malformed compressed streams.",
                        cve.as_str(),
                        cve.title()
                    ),
                    format!("Update system Node.js to {}", safe_threshold),
                );
                finding.detector_id = "node-runtime".to_string();
                finding.installed_build = Some(format!("v{}", ver_str));
                finding.affectedness = Affectedness::ConfirmedAffected;
                finding.reachability = Reachability::PotentiallyReachable;
                finding.confidence = Confidence::High;
                finding.exploitability_signal = ExploitabilitySignal::PublicPocAvailable;
                finding.compute_dedupe_fingerprint();
                return Some(finding);
            }
        }
        None
    }

    /// Scans a `package.json` file for vulnerable `engines.node` requirements or dangerous middleware.
    pub fn scan_package_json(path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => return findings,
        };

        let json: serde_json::Value = match serde_json::from_str(&content) {
            Ok(j) => j,
            Err(_) => return findings,
        };

        // 1. Check engines.node
        if let Some(engines) = json.get("engines").and_then(|e| e.as_object()) {
            if let Some(node_val) = engines.get("node").and_then(|n| n.as_str()) {
                let re = Regex::new(r"(\d+\.\d+(?:\.\d+)?)").unwrap();
                for cap in re.captures_iter(node_val) {
                    let ver_str = &cap[1];
                    if let Some((major, minor, patch)) = CveDatabase::parse_semver(ver_str) {
                        if let Some((cve, severity, safe_threshold)) =
                            CveDatabase::check_node_version(major, minor, patch)
                        {
                            let mut finding = Finding::new(
                                format!("PACKAGE-JSON-{}", cve.as_str()),
                                cve,
                                severity,
                                TargetKind::NodePackageManifest,
                                Some(path.to_path_buf()),
                                None,
                                format!("engines.node: '{}'", node_val),
                                safe_threshold.to_string(),
                                format!(
                                    "package.json specifies Node.js engine constraint '{}' matching vulnerable Brotli decoder.",
                                    node_val
                                ),
                                format!("Bump engines.node to '{}'", safe_threshold),
                            );
                            finding.detector_id = "node-manifest".to_string();
                            finding.affectedness = Affectedness::ConfirmedAffected;
                            finding.reachability = Reachability::PotentiallyReachable;
                            finding.confidence = Confidence::High;
                            finding.compute_dedupe_fingerprint();
                            findings.push(finding);
                            break;
                        }
                    }
                }
            }
        }

        // 2. Check dependencies exposing automatic body decompression (e.g. Express, body-parser, fastify)
        let check_deps =
            |deps: Option<&serde_json::Map<String, serde_json::Value>>| -> (bool, bool, bool) {
                let mut bp = false;
                let mut exp = false;
                let mut fst = false;
                if let Some(d) = deps {
                    if d.contains_key("body-parser") {
                        bp = true;
                    }
                    if d.contains_key("express") {
                        exp = true;
                    }
                    if d.contains_key("fastify") {
                        fst = true;
                    }
                }
                (bp, exp, fst)
            };

        let (b1, e1, f1) = check_deps(json.get("dependencies").and_then(|d| d.as_object()));
        let (b2, e2, f2) = check_deps(json.get("devDependencies").and_then(|d| d.as_object()));
        let has_body_parser = b1 || b2;
        let has_express = e1 || e2;
        let has_fastify = f1 || f2;

        if has_body_parser || has_express || has_fastify {
            let mut finding = Finding::new(
                "NODE-HTTP-BODY-DECOMPRESSOR",
                CveId::Node2ShellBrotli("CVE-2026-111497".into()),
                Severity::Medium,
                TargetKind::NodePackageManifest,
                Some(path.to_path_buf()),
                None,
                format!(
                    "HTTP server dependencies detected: express={}, body-parser={}, fastify={}",
                    has_express, has_body_parser, has_fastify
                ),
                "Runtime patch or WAF/middleware Brotli request body filtering",
                "Application declares HTTP frameworks capable of body decompression. Attacker reachability to bundled Brotli decoder is unproven without source/runtime verification.",
                "Deploy Bug Killer middleware guard or reverse-proxy WAF rule to reject or sanitize 'Content-Encoding: br' request bodies until runtime is upgraded.",
            );
            finding.detector_id = "node-manifest".to_string();
            finding.affectedness = Affectedness::PotentiallyAffected;
            finding.reachability = Reachability::Unknown;
            finding.confidence = Confidence::Low;
            finding.uncertainty_reasons.push(
                "Framework presence detected, but attacker-controlled Brotli decompression reachability is unproven without source/runtime proof.".to_string(),
            );
            finding
                .missing_checks
                .push("verify_runtime_node_version".to_string());
            finding
                .missing_checks
                .push("verify_brotli_decompression_call".to_string());
            finding.compute_dedupe_fingerprint();
            findings.push(finding);
        }

        // Check for unguarded Express / HTTP body parsing in code if package.json has scripts
        let has_express_app = content.contains("express()");
        let has_body_parser = content.contains("bodyParser")
            || content.contains("body-parser")
            || content.contains("express.json")
            || content.contains("express.urlencoded");
        let has_guard = content.contains("[BUG-KILLER-GUARD]") || content.contains("[AEGIS-GUARD]");

        if has_express_app && has_body_parser && !has_guard {
            let mut finding = Finding::new(
                format!(
                    "EXPRESS-UNGUARDED-BODY-PARSER-{}",
                    path.file_name().unwrap_or_default().to_string_lossy()
                ),
                CveId::Node2ShellBrotli("CVE-2026-111497".into()),
                Severity::Medium,
                TargetKind::NodeSourceFile,
                Some(path.to_path_buf()),
                None,
                "Express HTTP server parsing bodies without Brotli payload guard",
                "Inject Bug Killer [BUG-KILLER-GUARD] middleware before body parsers",
                "Express application parses request bodies without rejecting 'Content-Encoding: br', exposing native Brotli decoder (CVE-2026-111497).",
                "Inject Bug Killer middleware guard or apply reverse proxy WAF rule.",
            );
            finding.detector_id = "node-source-guard".to_string();
            finding.affectedness = Affectedness::PotentiallyAffected;
            finding.reachability = Reachability::PotentiallyReachable;
            finding.confidence = Confidence::Medium;
            finding.compute_dedupe_fingerprint();
            findings.push(finding);
        }

        findings
    }

    /// Scans JavaScript / TypeScript source files for explicit or implicit Brotli decompression calls.
    pub fn scan_source_file(path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => return findings,
        };

        // Match patterns like:
        // zlib.createBrotliDecompress()
        // zlib.brotliDecompress()
        // zlib.brotliDecompressSync()
        // createBrotliDecompress()
        let re_brotli =
            Regex::new(r"(?i)(createBrotliDecompress|brotliDecompress|brotliDecompressSync)")
                .unwrap();

        for (idx, line) in content.lines().enumerate() {
            if let Some(caps) = re_brotli.captures(line) {
                let mut finding = Finding::new(
                    format!("CODE-BROTLI-CALL-{}", idx + 1),
                    CveId::Node2ShellBrotli("CVE-2026-111497".into()),
                    Severity::High,
                    TargetKind::NodeSourceFile,
                    Some(path.to_path_buf()),
                    Some(idx + 1),
                    line.trim(),
                    "Node.js runtime >= v22.23.4 / v24.22.1 / v26.12.1",
                    format!(
                        "Direct call to native Brotli decompression API ('{}') found in source code. Susceptible to memory corruption if input is untrusted.",
                        &caps[1]
                    ),
                    "Wrap input in size and chunk verification guards or upgrade runtime immediately.",
                );
                finding.detector_id = "node-source-brotli".to_string();
                finding.affectedness = Affectedness::ConfirmedAffected;
                finding.reachability = Reachability::ConfirmedReachable;
                finding.confidence = Confidence::Confirmed;
                finding.exploitability_signal = ExploitabilitySignal::PublicPocAvailable;
                finding.compute_dedupe_fingerprint();
                findings.push(finding);
            }
        }

        // Check for unguarded Express / HTTP body parsing
        let has_express_app = content.contains("express()");
        let has_body_parser = content.contains("bodyParser")
            || content.contains("body-parser")
            || content.contains("express.json")
            || content.contains("express.urlencoded");
        let has_guard = content.contains("[BUG-KILLER-GUARD]") || content.contains("[AEGIS-GUARD]");

        if has_express_app && has_body_parser && !has_guard {
            let mut finding = Finding::new(
                format!(
                    "EXPRESS-UNGUARDED-BODY-PARSER-{}",
                    path.file_name().unwrap_or_default().to_string_lossy()
                ),
                CveId::Node2ShellBrotli("CVE-2026-111497".into()),
                Severity::Medium,
                TargetKind::NodeSourceFile,
                Some(path.to_path_buf()),
                None,
                "Express HTTP server parsing bodies without Brotli payload guard",
                "Inject Bug Killer [BUG-KILLER-GUARD] middleware before body parsers",
                "Express application parses request bodies without rejecting 'Content-Encoding: br', exposing native Brotli decoder (CVE-2026-111497).",
                "Inject Bug Killer middleware guard or apply reverse proxy WAF rule.",
            );
            finding.detector_id = "node-source-guard".to_string();
            finding.affectedness = Affectedness::PotentiallyAffected;
            finding.reachability = Reachability::PotentiallyReachable;
            finding.confidence = Confidence::Medium;
            finding.compute_dedupe_fingerprint();
            findings.push(finding);
        }

        findings
    }

    /// Scans Dockerfiles for vulnerable Node base images (`FROM node:22.20`, `FROM node:20.15`).
    pub fn scan_dockerfile(path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => return findings,
        };

        let re = Regex::new(r"(?i)^FROM\s+node:([0-9\.\-a-z]+)").unwrap();
        for (idx, line) in content.lines().enumerate() {
            if let Some(caps) = re.captures(line) {
                let tag = &caps[1];
                if let Some((major, minor, patch)) = CveDatabase::parse_semver(tag) {
                    if let Some((cve, severity, safe_threshold)) =
                        CveDatabase::check_node_version(major, minor, patch)
                    {
                        let mut finding = Finding::new(
                            format!("DOCKER-NODE-{}", cve.as_str()),
                            cve,
                            severity,
                            TargetKind::Dockerfile,
                            Some(path.to_path_buf()),
                            Some(idx + 1),
                            line.trim(),
                            safe_threshold.to_string(),
                            format!(
                                "Dockerfile pins vulnerable base image 'node:{}' carrying vulnerable bundled Brotli decoder.",
                                tag
                            ),
                            format!(
                                "Update base image tag in Dockerfile to safe release: {}",
                                safe_threshold
                            ),
                        );
                        finding.detector_id = "docker-node".to_string();
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
}
