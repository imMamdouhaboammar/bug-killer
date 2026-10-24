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
                return Some(Finding {
                    id: format!("NODE-HOST-{}", cve.as_str()),
                    cve: cve.clone(),
                    severity,
                    target_kind: TargetKind::NodeRuntime,
                    file_path: None,
                    line_number: None,
                    detected_version_or_pattern: format!("Host Node.js v{}", ver_str),
                    safe_threshold: safe_threshold.to_string(),
                    description: format!(
                        "Host Node.js binary bundles vulnerable Google Brotli decoder ({}: {}). Out-of-bounds write / buffer overflow on malformed compressed streams.",
                        cve.as_str(),
                        cve.title()
                    ),
                    suggested_remediation: format!("Update system Node.js to {}", safe_threshold),
                });
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
                            findings.push(Finding {
                                id: format!("PACKAGE-JSON-{}", cve.as_str()),
                                cve,
                                severity,
                                target_kind: TargetKind::NodePackageManifest,
                                file_path: Some(path.to_path_buf()),
                                line_number: None,
                                detected_version_or_pattern: format!("engines.node: '{}'", node_val),
                                safe_threshold: safe_threshold.to_string(),
                                description: format!(
                                    "package.json specifies Node.js engine constraint '{}' matching vulnerable Brotli decoder.",
                                    node_val
                                ),
                                suggested_remediation: format!("Bump engines.node to '{}'", safe_threshold),
                            });
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
            findings.push(Finding {
                id: "NODE-HTTP-BODY-DECOMPRESSOR".to_string(),
                cve: CveId::Node2ShellBrotli("CVE-2026-111497".into()),
                severity: Severity::Medium,
                target_kind: TargetKind::NodePackageManifest,
                file_path: Some(path.to_path_buf()),
                line_number: None,
                detected_version_or_pattern: format!(
                    "HTTP server dependencies detected: express={}, body-parser={}, fastify={}",
                    has_express, has_body_parser, has_fastify
                ),
                safe_threshold: "Runtime patch or WAF/middleware Brotli request body filtering".to_string(),
                description: "Application uses HTTP frameworks capable of automatic body decompression. Untrusted 'Content-Encoding: br' payloads reach bundled Brotli decoder.".to_string(),
                suggested_remediation: "Deploy Aegis middleware guard or reverse-proxy WAF rule to reject or sanitize 'Content-Encoding: br' request bodies until runtime is upgraded.".to_string(),
            });
        }

        // Check for unguarded Express / HTTP body parsing
        let has_express_app = content.contains("express()");
        let has_body_parser = content.contains("bodyParser")
            || content.contains("body-parser")
            || content.contains("express.json")
            || content.contains("express.urlencoded");
        let has_guard = content.contains("[BUG-KILLER-GUARD]") || content.contains("[AEGIS-GUARD]");

        if has_express_app && has_body_parser && !has_guard {
            findings.push(Finding {
                id: format!("EXPRESS-UNGUARDED-BODY-PARSER-{}", path.file_name().unwrap_or_default().to_string_lossy()),
                cve: CveId::Node2ShellBrotli("CVE-2026-111497".into()),
                severity: Severity::Medium,
                target_kind: TargetKind::NodeSourceFile,
                file_path: Some(path.to_path_buf()),
                line_number: None,
                detected_version_or_pattern: "Express HTTP server parsing bodies without Brotli payload guard".to_string(),
                safe_threshold: "Inject Bug Killer [BUG-KILLER-GUARD] middleware before body parsers".to_string(),
                description: "Express application parses request bodies without rejecting 'Content-Encoding: br', exposing native Brotli decoder (CVE-2026-111497).".to_string(),
                suggested_remediation: "Inject Bug Killer middleware guard or apply reverse proxy WAF rule.".to_string(),
            });
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
                findings.push(Finding {
                    id: format!("CODE-BROTLI-CALL-{}", idx + 1),
                    cve: CveId::Node2ShellBrotli("CVE-2026-111497".into()),
                    severity: Severity::High,
                    target_kind: TargetKind::NodeSourceFile,
                    file_path: Some(path.to_path_buf()),
                    line_number: Some(idx + 1),
                    detected_version_or_pattern: line.trim().to_string(),
                    safe_threshold: "Node.js runtime >= v22.23.4 / v24.22.1 / v26.12.1".to_string(),
                    description: format!(
                        "Direct call to native Brotli decompression API ('{}') found in source code. Susceptible to memory corruption if input is untrusted.",
                        &caps[1]
                    ),
                    suggested_remediation: "Wrap input in size and chunk verification guards or upgrade runtime immediately.".to_string(),
                });
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
            findings.push(Finding {
                id: format!("EXPRESS-UNGUARDED-BODY-PARSER-{}", path.file_name().unwrap_or_default().to_string_lossy()),
                cve: CveId::Node2ShellBrotli("CVE-2026-111497".into()),
                severity: Severity::Medium,
                target_kind: TargetKind::NodeSourceFile,
                file_path: Some(path.to_path_buf()),
                line_number: None,
                detected_version_or_pattern: "Express HTTP server parsing bodies without Brotli payload guard".to_string(),
                safe_threshold: "Inject Bug Killer [BUG-KILLER-GUARD] middleware before body parsers".to_string(),
                description: "Express application parses request bodies without rejecting 'Content-Encoding: br', exposing native Brotli decoder (CVE-2026-111497).".to_string(),
                suggested_remediation: "Inject Bug Killer middleware guard or apply reverse proxy WAF rule.".to_string(),
            });
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
                        findings.push(Finding {
                            id: format!("DOCKER-NODE-{}", cve.as_str()),
                            cve,
                            severity,
                            target_kind: TargetKind::Dockerfile,
                            file_path: Some(path.to_path_buf()),
                            line_number: Some(idx + 1),
                            detected_version_or_pattern: line.trim().to_string(),
                            safe_threshold: safe_threshold.to_string(),
                            description: format!(
                                "Dockerfile pins vulnerable base image 'node:{}' carrying vulnerable bundled Brotli decoder.",
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
}
