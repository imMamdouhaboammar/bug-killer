use std::fs;
use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use walkdir::WalkDir;
use crate::types::*;

pub struct OsvClient {
    pub endpoint: String,
}

impl Default for OsvClient {
    fn default() -> Self {
        Self {
            endpoint: "https://api.osv.dev/v1/query".into(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct DiscoveredPackage {
    pub file_path: PathBuf,
    pub name: String,
    pub version: String,
    pub ecosystem: &'static str,
    pub target_kind: TargetKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsvRangeEvent {
    #[serde(default)]
    pub introduced: Option<String>,
    #[serde(default)]
    pub fixed: Option<String>,
    #[serde(default)]
    pub last_affected: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsvRange {
    #[serde(default)]
    pub r#type: String,
    #[serde(default)]
    pub events: Vec<OsvRangeEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsvAffected {
    #[serde(default)]
    pub ranges: Vec<OsvRange>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsvVulnerabilityItem {
    pub id: String,
    #[serde(default)]
    pub summary: Option<String>,
    #[serde(default)]
    pub details: Option<String>,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default)]
    pub affected: Vec<OsvAffected>,
    #[serde(default)]
    pub database_specific: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OsvQueryResponse {
    #[serde(default)]
    pub vulns: Vec<OsvVulnerabilityItem>,
}

impl OsvClient {
    pub fn new() -> Self {
        Self::default()
    }

    /// Discovers all package dependencies across package.json, composer.json, requirements.txt, and Cargo.lock.
    pub fn discover_packages(root: &Path) -> Vec<DiscoveredPackage> {
        let mut packages = Vec::new();

        for entry in WalkDir::new(root)
            .into_iter()
            .filter_entry(|e| {
                if e.depth() == 0 {
                    return true;
                }
                let name = e.file_name().to_string_lossy();
                name != ".git" && name != "node_modules" && name != "vendor" && name != "target" && name != ".aegis"
            })
            .filter_map(|e| e.ok())
        {
            if !entry.file_type().is_file() {
                continue;
            }

            let path = entry.path();
            let file_name = path.file_name().unwrap_or_default().to_string_lossy();

            if file_name == "package.json" {
                packages.extend(Self::extract_node_packages(path));
            } else if file_name == "composer.json" {
                packages.extend(Self::extract_composer_packages(path));
            } else if file_name == "requirements.txt" {
                packages.extend(Self::extract_python_requirements(path));
            } else if file_name == "Cargo.lock" {
                packages.extend(Self::extract_cargo_lock_packages(path));
            } else if file_name == "go.mod" {
                packages.extend(Self::extract_go_mod_packages(path));
            } else if file_name == "pom.xml" {
                packages.extend(Self::extract_java_pom_packages(path));
            } else if file_name.ends_with(".csproj") || file_name == "packages.lock.json" {
                packages.extend(Self::extract_dotnet_packages(path));
            } else if file_name == "Gemfile.lock" {
                packages.extend(Self::extract_ruby_gemfile_packages(path));
            } else if file_name == "poetry.lock" {
                packages.extend(Self::extract_poetry_packages(path));
            }
        }

        packages
    }

    fn clean_version(raw: &str) -> Option<String> {
        let trimmed = raw.trim();
        let cleaned = trimmed
            .trim_start_matches('^')
            .trim_start_matches('~')
            .trim_start_matches(">=")
            .trim_start_matches("<=")
            .trim_start_matches('>')
            .trim_start_matches('<')
            .trim_start_matches('=')
            .trim();

        if cleaned.is_empty() || cleaned.contains('*') || cleaned == "latest" {
            None
        } else {
            let first_part = cleaned.split_whitespace().next().unwrap_or(cleaned);
            Some(first_part.to_string())
        }
    }

    fn extract_node_packages(path: &Path) -> Vec<DiscoveredPackage> {
        let mut list = Vec::new();
        if let Ok(content) = fs::read_to_string(path) {
            if let Ok(val) = serde_json::from_str::<Value>(&content) {
                let sections = ["dependencies", "devDependencies"];
                for sec in sections {
                    if let Some(deps) = val.get(sec).and_then(|d| d.as_object()) {
                        for (pkg, ver_val) in deps {
                            if let Some(ver_str) = ver_val.as_str() {
                                if let Some(cleaned) = Self::clean_version(ver_str) {
                                    list.push(DiscoveredPackage {
                                        file_path: path.to_path_buf(),
                                        name: pkg.clone(),
                                        version: cleaned,
                                        ecosystem: "npm",
                                        target_kind: TargetKind::NodePackageManifest,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
        list
    }

    fn extract_composer_packages(path: &Path) -> Vec<DiscoveredPackage> {
        let mut list = Vec::new();
        if let Ok(content) = fs::read_to_string(path) {
            if let Ok(val) = serde_json::from_str::<Value>(&content) {
                let sections = ["require", "require-dev"];
                for sec in sections {
                    if let Some(deps) = val.get(sec).and_then(|d| d.as_object()) {
                        for (pkg, ver_val) in deps {
                            if pkg.starts_with("php") || pkg.starts_with("ext-") {
                                continue;
                            }
                            if let Some(ver_str) = ver_val.as_str() {
                                if let Some(cleaned) = Self::clean_version(ver_str) {
                                    list.push(DiscoveredPackage {
                                        file_path: path.to_path_buf(),
                                        name: pkg.clone(),
                                        version: cleaned,
                                        ecosystem: "Packagist",
                                        target_kind: TargetKind::ComposerManifest,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
        list
    }

    fn extract_python_requirements(path: &Path) -> Vec<DiscoveredPackage> {
        let mut list = Vec::new();
        if let Ok(content) = fs::read_to_string(path) {
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('-') {
                    continue;
                }
                if let Some((pkg, ver)) = trimmed.split_once("==") {
                    list.push(DiscoveredPackage {
                        file_path: path.to_path_buf(),
                        name: pkg.trim().to_string(),
                        version: ver.trim().to_string(),
                        ecosystem: "PyPI",
                        target_kind: TargetKind::GenericConfigFile,
                    });
                }
            }
        }
        list
    }

    fn extract_cargo_lock_packages(path: &Path) -> Vec<DiscoveredPackage> {
        let mut list = Vec::new();
        if let Ok(content) = fs::read_to_string(path) {
            let mut current_name = None;
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("name = ") {
                    let name = trimmed.trim_start_matches("name = ").trim_matches('"');
                    current_name = Some(name.to_string());
                } else if trimmed.starts_with("version = ") {
                    if let Some(name) = current_name.take() {
                        let ver = trimmed.trim_start_matches("version = ").trim_matches('"');
                        list.push(DiscoveredPackage {
                            file_path: path.to_path_buf(),
                            name,
                            version: ver.to_string(),
                            ecosystem: "crates.io",
                            target_kind: TargetKind::CargoLockManifest,
                        });
                    }
                }
            }
        }
        list
    }

    fn extract_go_mod_packages(path: &Path) -> Vec<DiscoveredPackage> {
        let mut list = Vec::new();
        if let Ok(content) = fs::read_to_string(path) {
            let mut in_require_block = false;
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("//") || trimmed.is_empty() {
                    continue;
                }
                if trimmed == "require (" {
                    in_require_block = true;
                    continue;
                }
                if in_require_block && trimmed == ")" {
                    in_require_block = false;
                    continue;
                }
                if in_require_block {
                    let parts: Vec<&str> = trimmed.split_whitespace().collect();
                    if parts.len() >= 2 {
                        let pkg = parts[0];
                        let ver = parts[1];
                        list.push(DiscoveredPackage {
                            file_path: path.to_path_buf(),
                            name: pkg.to_string(),
                            version: ver.to_string(),
                            ecosystem: "Go",
                            target_kind: TargetKind::GoModManifest,
                        });
                    }
                } else if let Some(stripped) = trimmed.strip_prefix("require ") {
                    let parts: Vec<&str> = stripped.split_whitespace().collect();
                    if parts.len() >= 2 {
                        let pkg = parts[0];
                        let ver = parts[1];
                        list.push(DiscoveredPackage {
                            file_path: path.to_path_buf(),
                            name: pkg.to_string(),
                            version: ver.to_string(),
                            ecosystem: "Go",
                            target_kind: TargetKind::GoModManifest,
                        });
                    }
                }
            }
        }
        list
    }

    fn extract_java_pom_packages(path: &Path) -> Vec<DiscoveredPackage> {
        let mut list = Vec::new();
        if let Ok(content) = fs::read_to_string(path) {
            let mut in_dep = false;
            let mut group_id = String::new();
            let mut artifact_id = String::new();
            let mut version = String::new();

            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.contains("<dependency>") {
                    in_dep = true;
                    group_id.clear();
                    artifact_id.clear();
                    version.clear();
                } else if trimmed.contains("</dependency>") {
                    if in_dep && !group_id.is_empty() && !artifact_id.is_empty() && !version.is_empty() && !version.starts_with("${") {
                        let pkg_name = format!("{}:{}", group_id, artifact_id);
                        if let Some(cleaned) = Self::clean_version(&version) {
                            list.push(DiscoveredPackage {
                                file_path: path.to_path_buf(),
                                name: pkg_name,
                                version: cleaned,
                                ecosystem: "Maven",
                                target_kind: TargetKind::JavaPomManifest,
                            });
                        }
                    }
                    in_dep = false;
                } else if in_dep {
                    if let Some(val) = Self::extract_xml_tag(trimmed, "groupId") {
                        group_id = val.to_string();
                    } else if let Some(val) = Self::extract_xml_tag(trimmed, "artifactId") {
                        artifact_id = val.to_string();
                    } else if let Some(val) = Self::extract_xml_tag(trimmed, "version") {
                        version = val.to_string();
                    }
                }
            }
        }
        list
    }

    fn extract_xml_tag<'a>(line: &'a str, tag: &str) -> Option<&'a str> {
        let open_tag = format!("<{}>", tag);
        let close_tag = format!("</{}>", tag);
        if let Some(start) = line.find(&open_tag) {
            if let Some(end) = line.find(&close_tag) {
                let val = &line[start + open_tag.len()..end];
                return Some(val.trim());
            }
        }
        None
    }

    fn extract_dotnet_packages(path: &Path) -> Vec<DiscoveredPackage> {
        let mut list = Vec::new();
        if let Ok(content) = fs::read_to_string(path) {
            let file_name = path.file_name().unwrap_or_default().to_string_lossy();
            if file_name == "packages.lock.json" {
                if let Ok(val) = serde_json::from_str::<Value>(&content) {
                    if let Some(deps) = val.get("dependencies").and_then(|d| d.as_object()) {
                        for (_framework, fw_deps) in deps {
                            if let Some(pkgs) = fw_deps.as_object() {
                                for (pkg_name, details) in pkgs {
                                    if let Some(ver) = details.get("resolved").and_then(|v| v.as_str()) {
                                        if let Some(cleaned) = Self::clean_version(ver) {
                                            list.push(DiscoveredPackage {
                                                file_path: path.to_path_buf(),
                                                name: pkg_name.clone(),
                                                version: cleaned,
                                                ecosystem: "NuGet",
                                                target_kind: TargetKind::DotnetCsprojManifest,
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            } else {
                for line in content.lines() {
                    let trimmed = line.trim();
                    if trimmed.contains("<PackageReference") {
                        let pkg_opt = Self::extract_attr_value(trimmed, "Include");
                        let ver_opt = Self::extract_attr_value(trimmed, "Version");
                        if let (Some(pkg), Some(ver)) = (pkg_opt, ver_opt) {
                            if let Some(cleaned) = Self::clean_version(ver) {
                                list.push(DiscoveredPackage {
                                    file_path: path.to_path_buf(),
                                    name: pkg.to_string(),
                                    version: cleaned,
                                    ecosystem: "NuGet",
                                    target_kind: TargetKind::DotnetCsprojManifest,
                                });
                            }
                        }
                    }
                }
            }
        }
        list
    }

    fn extract_attr_value<'a>(line: &'a str, attr: &str) -> Option<&'a str> {
        let pattern = format!("{}=\"", attr);
        if let Some(pos) = line.find(&pattern) {
            let rest = &line[pos + pattern.len()..];
            if let Some(end) = rest.find('"') {
                return Some(&rest[..end]);
            }
        }
        None
    }

    fn extract_ruby_gemfile_packages(path: &Path) -> Vec<DiscoveredPackage> {
        let mut list = Vec::new();
        if let Ok(content) = fs::read_to_string(path) {
            let mut in_specs = false;
            for line in content.lines() {
                if line.starts_with("  specs:") {
                    in_specs = true;
                    continue;
                }
                if in_specs {
                    if !line.starts_with("    ") {
                        if !line.starts_with(' ') && !line.is_empty() {
                            in_specs = false;
                        }
                        continue;
                    }
                    if line.starts_with("    ") && !line.starts_with("      ") {
                        let trimmed = line.trim();
                        if let Some((name, rest)) = trimmed.split_once(' ') {
                            let ver = rest.trim_matches('(').trim_matches(')').trim();
                            if let Some(cleaned) = Self::clean_version(ver) {
                                list.push(DiscoveredPackage {
                                    file_path: path.to_path_buf(),
                                    name: name.to_string(),
                                    version: cleaned,
                                    ecosystem: "RubyGems",
                                    target_kind: TargetKind::RubyGemfileManifest,
                                });
                            }
                        }
                    }
                }
            }
        }
        list
    }

    fn extract_poetry_packages(path: &Path) -> Vec<DiscoveredPackage> {
        let mut list = Vec::new();
        if let Ok(content) = fs::read_to_string(path) {
            let mut current_name = None;
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("name = ") {
                    let name = trimmed.trim_start_matches("name = ").trim_matches('"').trim_matches('\'');
                    current_name = Some(name.to_string());
                } else if trimmed.starts_with("version = ") {
                    if let Some(name) = current_name.take() {
                        let ver = trimmed.trim_start_matches("version = ").trim_matches('"').trim_matches('\'');
                        if let Some(cleaned) = Self::clean_version(ver) {
                            list.push(DiscoveredPackage {
                                file_path: path.to_path_buf(),
                                name,
                                version: cleaned,
                                ecosystem: "PyPI",
                                target_kind: TargetKind::PythonPoetryManifest,
                            });
                        }
                    }
                }
            }
        }
        list
    }

    /// Queries the OSV REST API for a single package and returns any confirmed findings.
    pub fn query_package(&self, pkg: &DiscoveredPackage) -> Result<Vec<Finding>, String> {
        let body = serde_json::json!({
            "package": {
                "name": pkg.name,
                "ecosystem": pkg.ecosystem
            },
            "version": pkg.version
        });

        let resp = ureq::post(&self.endpoint)
            .header("Content-Type", "application/json")
            .send_json(&body)
            .map_err(|e| format!("OSV API query error for {}: {}", pkg.name, e))?;

        let mut reader = resp.into_body().into_reader();
        let query_resp: OsvQueryResponse = serde_json::from_reader(&mut reader)
            .map_err(|e| format!("OSV JSON parse error: {}", e))?;

        let mut findings = Vec::new();

        for vuln in query_resp.vulns {
            let primary_id = vuln
                .aliases
                .iter()
                .find(|a| a.starts_with("CVE-"))
                .cloned()
                .unwrap_or_else(|| vuln.id.clone());

            let summary = vuln
                .summary
                .clone()
                .unwrap_or_else(|| format!("Security vulnerability in {}", pkg.name));

            let mut fixed_version = None;
            for aff in &vuln.affected {
                for r in &aff.ranges {
                    for ev in &r.events {
                        if let Some(ref fix) = ev.fixed {
                            fixed_version = Some(fix.clone());
                            break;
                        }
                    }
                    if fixed_version.is_some() {
                        break;
                    }
                }
                if fixed_version.is_some() {
                    break;
                }
            }

            let severity = if let Some(ref db) = vuln.database_specific {
                if let Some(sev_str) = db.get("severity").and_then(|s| s.as_str()) {
                    match sev_str.to_uppercase().as_str() {
                        "CRITICAL" => Severity::Critical,
                        "HIGH" => Severity::High,
                        "MODERATE" | "MEDIUM" => Severity::Medium,
                        _ => Severity::Low,
                    }
                } else {
                    Severity::High
                }
            } else {
                Severity::High
            };

            let safe_threshold = fixed_version
                .as_ref()
                .map(|f| format!("Upgrade to >= {}", f))
                .unwrap_or_else(|| "Check upstream advisory for fixed version".into());

            let remediation = if let Some(ref fix) = fixed_version {
                format!("Upgrade {} from {} to {} in {}", pkg.name, pkg.version, fix, pkg.file_path.display())
            } else {
                format!("Inspect advisory {} and update {} to patched release", primary_id, pkg.name)
            };

            findings.push(Finding {
                id: format!("osv-{}-{}", vuln.id, pkg.name),
                cve: CveId::Custom {
                    id: primary_id,
                    title: summary,
                },
                severity,
                target_kind: pkg.target_kind.clone(),
                file_path: Some(pkg.file_path.clone()),
                line_number: None,
                detected_version_or_pattern: format!("{} @ {} ({})", pkg.name, pkg.version, pkg.ecosystem),
                safe_threshold,
                description: vuln.details.unwrap_or_else(|| "No extended advisory details provided.".into()),
                suggested_remediation: remediation,
            });
        }

        Ok(findings)
    }

    /// Scans a workspace root directory against OSV.dev using high-throughput querybatch API.
    pub fn scan_workspace(&self, root: &Path) -> Vec<Finding> {
        let packages = Self::discover_packages(root);
        if packages.is_empty() {
            return Vec::new();
        }

        let mut findings = Vec::new();

        // Process in batches of 50 for near-instant execution
        for chunk in packages.chunks(50) {
            let queries: Vec<Value> = chunk
                .iter()
                .map(|p| {
                    serde_json::json!({
                        "package": {
                            "name": p.name,
                            "ecosystem": p.ecosystem
                        },
                        "version": p.version
                    })
                })
                .collect();

            let batch_body = serde_json::json!({ "queries": queries });

            let resp = match ureq::post("https://api.osv.dev/v1/querybatch")
                .header("Content-Type", "application/json")
                .send_json(&batch_body)
            {
                Ok(r) => r,
                Err(_) => {
                    for pkg in chunk {
                        if let Ok(vulns) = self.query_package(pkg) {
                            findings.extend(vulns);
                        }
                    }
                    continue;
                }
            };

            let mut reader = resp.into_body().into_reader();
            let batch_val: Value = match serde_json::from_reader(&mut reader) {
                Ok(v) => v,
                Err(_) => continue,
            };

            if let Some(results) = batch_val.get("results").and_then(|r| r.as_array()) {
                for (idx, res) in results.iter().enumerate() {
                    if let Some(vulns) = res.get("vulns").and_then(|v| v.as_array()) {
                        if !vulns.is_empty() {
                            let pkg = &chunk[idx];
                            if let Ok(full_findings) = self.query_package(pkg) {
                                findings.extend(full_findings);
                            }
                        }
                    }
                }
            }
        }

        findings
    }
}
