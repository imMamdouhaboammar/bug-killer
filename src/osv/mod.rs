use crate::types::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VersionResolution {
    ResolvedExact,
    DeclaredRequirement,
}

fn default_version_resolution() -> VersionResolution {
    VersionResolution::ResolvedExact
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredPackage {
    pub file_path: PathBuf,
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub declared_requirement: Option<String>,
    #[serde(default = "default_version_resolution")]
    pub resolution: VersionResolution,
    pub ecosystem: &'static str,
    pub target_kind: TargetKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsvPackageRef {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub ecosystem: String,
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
    pub package: Option<OsvPackageRef>,
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

    #[allow(dead_code)]
    pub fn with_endpoint(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
        }
    }

    pub fn is_exact_version(raw: &str) -> bool {
        let trimmed = raw.trim();
        if trimmed.is_empty()
            || trimmed.contains('^')
            || trimmed.contains('~')
            || trimmed.contains('>')
            || trimmed.contains('<')
            || trimmed.contains('*')
            || trimmed.contains("||")
            || trimmed.contains(" - ")
            || trimmed == "latest"
            || trimmed.chars().any(char::is_whitespace)
        {
            return false;
        }
        let stripped = trimmed.trim_start_matches('=').trim_start_matches('v');
        stripped
            .chars()
            .next()
            .map(|c| c.is_ascii_digit())
            .unwrap_or(false)
    }

    pub fn clean_version(raw: &str) -> Option<String> {
        let trimmed = raw.trim();
        if !Self::is_exact_version(trimmed) {
            None
        } else {
            let ver = trimmed
                .trim_start_matches('=')
                .trim_start_matches('v')
                .trim();
            if ver.is_empty() {
                None
            } else {
                Some(ver.to_string())
            }
        }
    }

    /// Discovers all package dependencies across package.json, composer.json, requirements.txt, Cargo.lock, etc.
    pub fn discover_packages(root: &Path) -> Vec<DiscoveredPackage> {
        let mut packages = Vec::new();

        for entry in WalkDir::new(root)
            .into_iter()
            .filter_entry(|e| {
                if e.depth() == 0 {
                    return true;
                }
                let name = e.file_name().to_string_lossy();
                name != ".git"
                    && name != "node_modules"
                    && name != "vendor"
                    && name != "target"
                    && name != ".aegis"
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
            } else if file_name == "package-lock.json" {
                packages.extend(Self::extract_package_lock_packages(path));
            } else if file_name == "composer.json" {
                packages.extend(Self::extract_composer_packages(path));
            } else if file_name == "composer.lock" {
                packages.extend(Self::extract_composer_lock_packages(path));
            } else if file_name == "yarn.lock" {
                packages.extend(Self::extract_yarn_lock_packages(path));
            } else if file_name == "pnpm-lock.yaml" || file_name == "pnpm-lock.yml" {
                packages.extend(Self::extract_pnpm_lock_packages(path));
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
            } else if file_name == "bom.json"
                || file_name == "cyclonedx.json"
                || file_name.ends_with(".cdx.json")
            {
                packages.extend(Self::extract_cyclonedx_packages(path));
            } else if file_name == "spdx.json" || file_name.ends_with(".spdx.json") {
                packages.extend(Self::extract_spdx_packages(path));
            }
        }

        packages
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
                                        declared_requirement: None,
                                        resolution: VersionResolution::ResolvedExact,
                                        ecosystem: "npm",
                                        target_kind: TargetKind::NodePackageManifest,
                                    });
                                } else {
                                    list.push(DiscoveredPackage {
                                        file_path: path.to_path_buf(),
                                        name: pkg.clone(),
                                        version: ver_str.to_string(),
                                        declared_requirement: Some(ver_str.to_string()),
                                        resolution: VersionResolution::DeclaredRequirement,
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
                                        declared_requirement: None,
                                        resolution: VersionResolution::ResolvedExact,
                                        ecosystem: "Packagist",
                                        target_kind: TargetKind::ComposerManifest,
                                    });
                                } else {
                                    list.push(DiscoveredPackage {
                                        file_path: path.to_path_buf(),
                                        name: pkg.clone(),
                                        version: ver_str.to_string(),
                                        declared_requirement: Some(ver_str.to_string()),
                                        resolution: VersionResolution::DeclaredRequirement,
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
                        declared_requirement: None,
                        resolution: VersionResolution::ResolvedExact,
                        ecosystem: "PyPI",
                        target_kind: TargetKind::GenericConfigFile,
                    });
                } else {
                    let name = trimmed
                        .split(['>', '<', '~', '=', ';', '!'])
                        .next()
                        .unwrap_or(trimmed)
                        .trim();
                    if !name.is_empty() {
                        list.push(DiscoveredPackage {
                            file_path: path.to_path_buf(),
                            name: name.to_string(),
                            version: trimmed.to_string(),
                            declared_requirement: Some(trimmed.to_string()),
                            resolution: VersionResolution::DeclaredRequirement,
                            ecosystem: "PyPI",
                            target_kind: TargetKind::GenericConfigFile,
                        });
                    }
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
                            declared_requirement: None,
                            resolution: VersionResolution::ResolvedExact,
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
                            declared_requirement: None,
                            resolution: VersionResolution::ResolvedExact,
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
                            declared_requirement: None,
                            resolution: VersionResolution::ResolvedExact,
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
                    if in_dep && !group_id.is_empty() && !artifact_id.is_empty() {
                        let pkg_name = format!("{}:{}", group_id, artifact_id);
                        if !version.is_empty() && !version.starts_with("${") {
                            if let Some(cleaned) = Self::clean_version(&version) {
                                list.push(DiscoveredPackage {
                                    file_path: path.to_path_buf(),
                                    name: pkg_name,
                                    version: cleaned,
                                    declared_requirement: None,
                                    resolution: VersionResolution::ResolvedExact,
                                    ecosystem: "Maven",
                                    target_kind: TargetKind::JavaPomManifest,
                                });
                            } else {
                                list.push(DiscoveredPackage {
                                    file_path: path.to_path_buf(),
                                    name: pkg_name,
                                    version: version.clone(),
                                    declared_requirement: Some(version.clone()),
                                    resolution: VersionResolution::DeclaredRequirement,
                                    ecosystem: "Maven",
                                    target_kind: TargetKind::JavaPomManifest,
                                });
                            }
                        } else if version.starts_with("${") {
                            list.push(DiscoveredPackage {
                                file_path: path.to_path_buf(),
                                name: pkg_name,
                                version: version.clone(),
                                declared_requirement: Some(version.clone()),
                                resolution: VersionResolution::DeclaredRequirement,
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
                                    if let Some(ver) =
                                        details.get("resolved").and_then(|v| v.as_str())
                                    {
                                        if let Some(cleaned) = Self::clean_version(ver) {
                                            list.push(DiscoveredPackage {
                                                file_path: path.to_path_buf(),
                                                name: pkg_name.clone(),
                                                version: cleaned,
                                                declared_requirement: None,
                                                resolution: VersionResolution::ResolvedExact,
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
                                    declared_requirement: None,
                                    resolution: VersionResolution::ResolvedExact,
                                    ecosystem: "NuGet",
                                    target_kind: TargetKind::DotnetCsprojManifest,
                                });
                            } else {
                                list.push(DiscoveredPackage {
                                    file_path: path.to_path_buf(),
                                    name: pkg.to_string(),
                                    version: ver.to_string(),
                                    declared_requirement: Some(ver.to_string()),
                                    resolution: VersionResolution::DeclaredRequirement,
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
                                    declared_requirement: None,
                                    resolution: VersionResolution::ResolvedExact,
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
                    let name = trimmed
                        .trim_start_matches("name = ")
                        .trim_matches('"')
                        .trim_matches('\'');
                    current_name = Some(name.to_string());
                } else if trimmed.starts_with("version = ") {
                    if let Some(name) = current_name.take() {
                        let ver = trimmed
                            .trim_start_matches("version = ")
                            .trim_matches('"')
                            .trim_matches('\'');
                        if let Some(cleaned) = Self::clean_version(ver) {
                            list.push(DiscoveredPackage {
                                file_path: path.to_path_buf(),
                                name,
                                version: cleaned,
                                declared_requirement: None,
                                resolution: VersionResolution::ResolvedExact,
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

    pub fn parse_purl(purl: &str) -> Option<(String, String, &'static str)> {
        let stripped = purl.strip_prefix("pkg:")?;
        let (ecosystem_part, rest) = stripped.split_once('/')?;
        let (name_part, version_part) = rest.split_once('@')?;
        let version = version_part
            .split('?')
            .next()
            .unwrap_or(version_part)
            .split('#')
            .next()
            .unwrap_or(version_part);

        let (ecosystem, norm_name) = match ecosystem_part.to_lowercase().as_str() {
            "npm" => ("npm", name_part.replace("%40", "@")),
            "pypi" => ("PyPI", name_part.to_string()),
            "cargo" | "crates.io" => ("crates.io", name_part.to_string()),
            "composer" => ("Packagist", name_part.to_string()),
            "golang" | "go" => ("Go", name_part.to_string()),
            "maven" => {
                let parts: Vec<&str> = name_part.split('/').collect();
                if parts.len() >= 2 {
                    ("Maven", format!("{}:{}", parts[0], parts[1]))
                } else {
                    ("Maven", name_part.to_string())
                }
            }
            "nuget" => ("NuGet", name_part.to_string()),
            "gem" | "rubygems" => ("RubyGems", name_part.to_string()),
            _ => return None,
        };

        Some((norm_name, version.to_string(), ecosystem))
    }

    pub fn extract_cyclonedx_packages(path: &Path) -> Vec<DiscoveredPackage> {
        let mut list = Vec::new();
        if let Ok(content) = fs::read_to_string(path) {
            if let Ok(val) = serde_json::from_str::<Value>(&content) {
                if let Some(components) = val.get("components").and_then(|c| c.as_array()) {
                    for comp in components {
                        let name_opt = comp.get("name").and_then(|n| n.as_str());
                        let ver_opt = comp.get("version").and_then(|v| v.as_str());
                        let purl_opt = comp.get("purl").and_then(|p| p.as_str());

                        if let Some(purl) = purl_opt {
                            if let Some((purl_name, purl_ver, eco)) = Self::parse_purl(purl) {
                                list.push(DiscoveredPackage {
                                    file_path: path.to_path_buf(),
                                    name: purl_name,
                                    version: purl_ver,
                                    declared_requirement: None,
                                    resolution: VersionResolution::ResolvedExact,
                                    ecosystem: eco,
                                    target_kind: TargetKind::CycloneDxSbom,
                                });
                                continue;
                            }
                        }

                        if let (Some(name), Some(ver)) = (name_opt, ver_opt) {
                            if let Some(cleaned) = Self::clean_version(ver) {
                                let eco = if comp
                                    .get("group")
                                    .and_then(|g| g.as_str())
                                    .is_some_and(|g| g.contains('.'))
                                {
                                    "Maven"
                                } else {
                                    "npm"
                                };
                                list.push(DiscoveredPackage {
                                    file_path: path.to_path_buf(),
                                    name: name.to_string(),
                                    version: cleaned,
                                    declared_requirement: None,
                                    resolution: VersionResolution::ResolvedExact,
                                    ecosystem: eco,
                                    target_kind: TargetKind::CycloneDxSbom,
                                });
                            }
                        }
                    }
                }
            }
        }
        list
    }

    pub fn extract_spdx_packages(path: &Path) -> Vec<DiscoveredPackage> {
        let mut list = Vec::new();
        if let Ok(content) = fs::read_to_string(path) {
            if let Ok(val) = serde_json::from_str::<Value>(&content) {
                if let Some(packages) = val.get("packages").and_then(|p| p.as_array()) {
                    for pkg in packages {
                        let name = pkg.get("name").and_then(|n| n.as_str()).unwrap_or_default();
                        let version = pkg
                            .get("versionInfo")
                            .and_then(|v| v.as_str())
                            .unwrap_or_default();

                        let mut matched_purl = None;
                        if let Some(refs) = pkg.get("externalRefs").and_then(|r| r.as_array()) {
                            for r in refs {
                                if r.get("referenceType").and_then(|t| t.as_str()) == Some("purl") {
                                    if let Some(locator) =
                                        r.get("referenceLocator").and_then(|l| l.as_str())
                                    {
                                        if let Some(parsed) = Self::parse_purl(locator) {
                                            matched_purl = Some(parsed);
                                            break;
                                        }
                                    }
                                }
                            }
                        }

                        if let Some((pname, pver, eco)) = matched_purl {
                            list.push(DiscoveredPackage {
                                file_path: path.to_path_buf(),
                                name: pname,
                                version: pver,
                                declared_requirement: None,
                                resolution: VersionResolution::ResolvedExact,
                                ecosystem: eco,
                                target_kind: TargetKind::SpdxSbom,
                            });
                        } else if !name.is_empty() && !version.is_empty() {
                            if let Some(cleaned) = Self::clean_version(version) {
                                list.push(DiscoveredPackage {
                                    file_path: path.to_path_buf(),
                                    name: name.to_string(),
                                    version: cleaned,
                                    declared_requirement: None,
                                    resolution: VersionResolution::ResolvedExact,
                                    ecosystem: "npm",
                                    target_kind: TargetKind::SpdxSbom,
                                });
                            }
                        }
                    }
                }
            }
        }
        list
    }

    pub fn extract_package_lock_packages(path: &Path) -> Vec<DiscoveredPackage> {
        let mut list = Vec::new();
        if let Ok(content) = fs::read_to_string(path) {
            if let Ok(val) = serde_json::from_str::<Value>(&content) {
                if let Some(packages) = val.get("packages").and_then(|p| p.as_object()) {
                    for (pkg_path, details) in packages {
                        if pkg_path.is_empty() || !pkg_path.contains("node_modules/") {
                            continue;
                        }
                        let name = pkg_path.rsplit("node_modules/").next().unwrap_or(pkg_path);
                        if let Some(ver) = details.get("version").and_then(|v| v.as_str()) {
                            if let Some(cleaned) = Self::clean_version(ver) {
                                list.push(DiscoveredPackage {
                                    file_path: path.to_path_buf(),
                                    name: name.to_string(),
                                    version: cleaned,
                                    declared_requirement: None,
                                    resolution: VersionResolution::ResolvedExact,
                                    ecosystem: "npm",
                                    target_kind: TargetKind::NodeLockfile,
                                });
                            }
                        }
                    }
                }
                if list.is_empty() {
                    if let Some(deps) = val.get("dependencies").and_then(|d| d.as_object()) {
                        for (name, details) in deps {
                            if let Some(ver) = details.get("version").and_then(|v| v.as_str()) {
                                if let Some(cleaned) = Self::clean_version(ver) {
                                    list.push(DiscoveredPackage {
                                        file_path: path.to_path_buf(),
                                        name: name.clone(),
                                        version: cleaned,
                                        declared_requirement: None,
                                        resolution: VersionResolution::ResolvedExact,
                                        ecosystem: "npm",
                                        target_kind: TargetKind::NodeLockfile,
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

    pub fn extract_composer_lock_packages(path: &Path) -> Vec<DiscoveredPackage> {
        let mut list = Vec::new();
        if let Ok(content) = fs::read_to_string(path) {
            if let Ok(val) = serde_json::from_str::<Value>(&content) {
                let sections = ["packages", "packages-dev"];
                for sec in sections {
                    if let Some(pkgs) = val.get(sec).and_then(|p| p.as_array()) {
                        for pkg in pkgs {
                            let name_opt = pkg.get("name").and_then(|n| n.as_str());
                            let ver_opt = pkg.get("version").and_then(|v| v.as_str());
                            if let (Some(name), Some(ver)) = (name_opt, ver_opt) {
                                if name.starts_with("php") || name.starts_with("ext-") {
                                    continue;
                                }
                                if let Some(cleaned) = Self::clean_version(ver) {
                                    list.push(DiscoveredPackage {
                                        file_path: path.to_path_buf(),
                                        name: name.to_string(),
                                        version: cleaned,
                                        declared_requirement: None,
                                        resolution: VersionResolution::ResolvedExact,
                                        ecosystem: "Packagist",
                                        target_kind: TargetKind::ComposerLockfile,
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

    pub fn extract_yarn_lock_packages(path: &Path) -> Vec<DiscoveredPackage> {
        let mut list = Vec::new();
        if let Ok(content) = fs::read_to_string(path) {
            let mut current_pkg = None;
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }
                if !line.starts_with(' ') && !line.starts_with('\t') {
                    let header = trimmed.trim_end_matches(':');
                    let first = header
                        .split(',')
                        .next()
                        .unwrap_or(header)
                        .trim()
                        .trim_matches('"');
                    if let Some((name, _)) = first.rsplit_once('@') {
                        if !name.is_empty() {
                            current_pkg = Some(name.to_string());
                        }
                    }
                } else if let Some(pkg_name) = current_pkg.as_ref() {
                    if let Some(stripped) = trimmed.strip_prefix("version ") {
                        let ver = stripped.trim().trim_matches('"');
                        if let Some(cleaned) = Self::clean_version(ver) {
                            list.push(DiscoveredPackage {
                                file_path: path.to_path_buf(),
                                name: pkg_name.clone(),
                                version: cleaned,
                                declared_requirement: None,
                                resolution: VersionResolution::ResolvedExact,
                                ecosystem: "npm",
                                target_kind: TargetKind::NodeLockfile,
                            });
                        }
                        current_pkg = None;
                    }
                }
            }
        }
        list
    }

    pub fn extract_pnpm_lock_packages(path: &Path) -> Vec<DiscoveredPackage> {
        let mut list = Vec::new();
        if let Ok(content) = fs::read_to_string(path) {
            let mut in_packages = false;
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed == "packages:" {
                    in_packages = true;
                    continue;
                }
                if in_packages {
                    if !line.starts_with(' ') && !trimmed.is_empty() {
                        in_packages = false;
                        continue;
                    }
                    if line.starts_with("  /")
                        || line.starts_with("  '")
                        || line.starts_with("  \"")
                    {
                        let entry = trimmed
                            .trim_start_matches('/')
                            .trim_matches('\'')
                            .trim_matches('"')
                            .trim_end_matches(':');
                        if let Some((name, ver)) = entry.rsplit_once('@') {
                            let clean_ver = ver.split('(').next().unwrap_or(ver).trim();
                            if let Some(cleaned) = Self::clean_version(clean_ver) {
                                list.push(DiscoveredPackage {
                                    file_path: path.to_path_buf(),
                                    name: name.to_string(),
                                    version: cleaned,
                                    declared_requirement: None,
                                    resolution: VersionResolution::ResolvedExact,
                                    ecosystem: "npm",
                                    target_kind: TargetKind::NodeLockfile,
                                });
                            }
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
            let mut aliases = vuln.aliases.clone();
            aliases.sort();
            aliases.dedup();

            let primary_id = aliases
                .iter()
                .find(|a| a.starts_with("CVE-"))
                .cloned()
                .unwrap_or_else(|| vuln.id.clone());

            let summary = vuln
                .summary
                .clone()
                .unwrap_or_else(|| format!("Security vulnerability in {}", pkg.name));

            // M2-C: Extract fixed version only from affected entry matching pkg.name
            let mut fixed_version = None;
            for aff in &vuln.affected {
                if let Some(ref p) = aff.package {
                    if !p.name.is_empty() && !p.name.eq_ignore_ascii_case(&pkg.name) {
                        continue;
                    }
                }
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
                format!(
                    "Upgrade {} from {} to {} in {}",
                    pkg.name,
                    pkg.version,
                    fix,
                    pkg.file_path.display()
                )
            } else {
                format!(
                    "Inspect advisory {} and update {} to patched release",
                    primary_id, pkg.name
                )
            };

            let mut finding = Finding::new(
                format!("osv-{}-{}", vuln.id, pkg.name),
                CveId::Custom {
                    id: primary_id.clone(),
                    title: summary,
                },
                severity,
                pkg.target_kind.clone(),
                Some(pkg.file_path.clone()),
                None,
                format!("{} @ {} ({})", pkg.name, pkg.version, pkg.ecosystem),
                safe_threshold,
                vuln.details
                    .unwrap_or_else(|| "No extended advisory details provided.".into()),
                remediation,
            );
            finding.detector_id = "osv-dev".to_string();
            finding.package_source = Some(pkg.ecosystem.to_string());
            finding.component_identity = pkg.name.clone();
            finding.installed_build = Some(pkg.version.clone());
            finding.advisory_ids = if aliases.is_empty() {
                vec![vuln.id.clone()]
            } else {
                aliases
            };
            finding.affectedness = Affectedness::ConfirmedAffected;
            finding.reachability = Reachability::PotentiallyReachable;
            finding.confidence = Confidence::High;
            finding.evidence_certainty = EvidenceCertainty::Confirmed;
            if fixed_version.is_none() {
                finding
                    .uncertainty_reasons
                    .push("Fixed version not disclosed in package affected ranges".into());
            }
            finding.compute_dedupe_fingerprint();
            findings.push(finding);
        }

        Ok(findings)
    }

    /// Scans a workspace root directory against OSV.dev and returns both findings and a truthful CoverageReceipt.
    pub fn scan_workspace_with_receipt(&self, root: &Path) -> (Vec<Finding>, CoverageReceipt) {
        let mut receipt = CoverageReceipt {
            scanner_id: "sca-osv".into(),
            scanner_version: "1.0.0".into(),
            target_id: root.to_string_lossy().to_string(),
            status: CoverageStatus::Complete,
            items_examined: 0,
            skipped_reasons: Vec::new(),
            errors: Vec::new(),
            completed_at: chrono::Utc::now().to_rfc3339(),
        };

        let packages = Self::discover_packages(root);
        receipt.items_examined = packages.len() as u64;

        if packages.is_empty() {
            receipt.status = CoverageStatus::NotRun;
            return (Vec::new(), receipt);
        }

        let mut exact_packages = Vec::new();
        for pkg in &packages {
            if pkg.resolution == VersionResolution::ResolvedExact {
                exact_packages.push(pkg);
            } else {
                let req = pkg.declared_requirement.as_deref().unwrap_or(&pkg.version);
                receipt.skipped_reasons.push(format!(
                    "{}: declared constraint '{}' skipped from exact OSV lookup (requires resolved lockfile)",
                    pkg.name, req
                ));
            }
        }

        if exact_packages.is_empty() {
            if !receipt.skipped_reasons.is_empty() {
                receipt.status = CoverageStatus::Partial;
            }
            return (Vec::new(), receipt);
        }

        let mut findings = Vec::new();
        let mut had_network_error = false;

        let batch_endpoint = if self.endpoint.ends_with("/query") {
            format!("{}batch", self.endpoint)
        } else if self.endpoint.ends_with("/query/") {
            format!("{}batch", self.endpoint.trim_end_matches('/'))
        } else {
            format!("{}/batch", self.endpoint.trim_end_matches('/'))
        };

        // Process in batches of 50
        for chunk in exact_packages.chunks(50) {
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

            let resp = match ureq::post(&batch_endpoint)
                .header("Content-Type", "application/json")
                .send_json(&batch_body)
            {
                Ok(r) => r,
                Err(e) => {
                    let err_msg = format!("OSV querybatch API error: {}", e);
                    let mut fallback_success = true;
                    for pkg in chunk {
                        match self.query_package(pkg) {
                            Ok(vulns) => findings.extend(vulns),
                            Err(fallback_err) => {
                                receipt
                                    .errors
                                    .push(format!("{}: {}", pkg.name, fallback_err));
                                fallback_success = false;
                            }
                        }
                    }
                    if !fallback_success {
                        had_network_error = true;
                        receipt.errors.push(err_msg);
                    }
                    continue;
                }
            };

            let mut reader = resp.into_body().into_reader();
            let batch_val: Value = match serde_json::from_reader(&mut reader) {
                Ok(v) => v,
                Err(e) => {
                    had_network_error = true;
                    receipt
                        .errors
                        .push(format!("OSV batch JSON parse error: {}", e));
                    continue;
                }
            };

            if let Some(results) = batch_val.get("results").and_then(|r| r.as_array()) {
                for (idx, res) in results.iter().enumerate() {
                    if let Some(vulns) = res.get("vulns").and_then(|v| v.as_array()) {
                        if !vulns.is_empty() && idx < chunk.len() {
                            let pkg = chunk[idx];
                            match self.query_package(pkg) {
                                Ok(full_findings) => findings.extend(full_findings),
                                Err(e) => {
                                    had_network_error = true;
                                    receipt.errors.push(format!("{}: {}", pkg.name, e));
                                }
                            }
                        }
                    }
                }
            }
        }

        if had_network_error {
            receipt.status = if findings.is_empty() {
                CoverageStatus::Error
            } else {
                CoverageStatus::Partial
            };
        } else if !receipt.skipped_reasons.is_empty() {
            receipt.status = CoverageStatus::Partial;
        }

        (findings, receipt)
    }

    /// Scans a workspace root directory against OSV.dev using high-throughput querybatch API.
    pub fn scan_workspace(&self, root: &Path) -> Vec<Finding> {
        self.scan_workspace_with_receipt(root).0
    }
}
