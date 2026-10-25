use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ResolutionKind {
    LockedExact,
    InstalledExact,
    GitCommit,
    DeclaredRange,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageIdentity {
    pub ecosystem: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purl: Option<String>,
    pub direct: bool,
    pub resolution_kind: ResolutionKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declared_requirement: Option<String>,
}

/// Generates a standardized Package URL (PURL).
pub fn make_purl(ecosystem: &str, name: &str, version: &str) -> String {
    let eco_lower = ecosystem.to_lowercase();
    let type_name = match eco_lower.as_str() {
        "npm" | "node" => "npm",
        "pypi" | "python" => "pypi",
        "cargo" | "crates.io" | "rust" => "cargo",
        "golang" | "go" => "golang",
        "composer" | "packagist" | "php" => "composer",
        other => other,
    };

    let clean_name = name.trim();
    let clean_version = version.trim();

    if clean_version.is_empty() {
        format!("pkg:{}/{}", type_name, clean_name)
    } else {
        format!("pkg:{}/{}@{}", type_name, clean_name, clean_version)
    }
}

/// Parses a PURL into (ecosystem, package_name, version).
pub fn parse_purl(purl: &str) -> Option<(String, String, Option<String>)> {
    let stripped = purl.strip_prefix("pkg:")?;
    let (ecosystem_part, rest) = stripped.split_once('/')?;

    let ecosystem = match ecosystem_part.to_lowercase().as_str() {
        "npm" => "npm",
        "pypi" => "pypi",
        "cargo" => "cargo",
        "golang" | "go" => "golang",
        "composer" => "composer",
        other => other,
    }
    .to_string();

    let (name, version) = if let Some((n, v)) = rest.split_once('@') {
        let v_clean = v.split(['?', '#']).next().unwrap_or(v);
        (n.to_string(), Some(v_clean.to_string()))
    } else {
        (rest.to_string(), None)
    };

    Some((ecosystem, name, version))
}

/// Ingests a requirements.txt file.
pub fn parse_requirements_txt(
    content: &str,
    file_path: Option<&str>,
) -> Result<Vec<PackageIdentity>, String> {
    let mut packages = Vec::new();

    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('-') {
            continue;
        }

        // Check if exact pinned version (==)
        if let Some((pkg, ver)) = line.split_once("==") {
            let pkg_name = pkg.trim().to_string();
            let pkg_ver = ver
                .split([';', '#'])
                .next()
                .unwrap_or(ver)
                .trim()
                .to_string();
            let purl = make_purl("pypi", &pkg_name, &pkg_ver);

            packages.push(PackageIdentity {
                ecosystem: "pypi".to_string(),
                name: pkg_name,
                resolved_version: Some(pkg_ver),
                purl: Some(purl),
                direct: true,
                resolution_kind: ResolutionKind::LockedExact,
                commit: None,
                origin: None,
                path: file_path.map(|s| s.to_string()),
                source_digest: None,
                declared_requirement: None,
            });
        } else {
            // Range or unpinned requirement, e.g. requests>=2.20.0 or flask~=2.0
            let op_pos = line.find(['>', '<', '~', '!', ';', '=']);
            let (pkg_name, requirement) = if let Some(idx) = op_pos {
                (
                    line[..idx].trim().to_string(),
                    line[idx..].trim().to_string(),
                )
            } else {
                (line.to_string(), "*".to_string())
            };

            if !pkg_name.is_empty() {
                let purl = make_purl("pypi", &pkg_name, "");
                packages.push(PackageIdentity {
                    ecosystem: "pypi".to_string(),
                    name: pkg_name,
                    resolved_version: None,
                    purl: Some(purl),
                    direct: true,
                    resolution_kind: ResolutionKind::DeclaredRange,
                    commit: None,
                    origin: None,
                    path: file_path.map(|s| s.to_string()),
                    source_digest: None,
                    declared_requirement: Some(requirement),
                });
            }
        }
    }

    Ok(packages)
}

/// Ingests a pyproject.toml file.
pub fn parse_pyproject_toml(
    content: &str,
    file_path: Option<&str>,
) -> Result<Vec<PackageIdentity>, String> {
    let mut packages = Vec::new();
    let mut in_deps_array = false;
    let mut in_poetry_table = false;

    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if line.starts_with('[') {
            in_deps_array = false;
            in_poetry_table = line.starts_with("[tool.poetry.dependencies]");
            continue;
        }

        if line.starts_with("dependencies = [") || line == "dependencies = [" {
            in_deps_array = true;
            if line.contains(']') {
                let inner = line
                    .trim_start_matches("dependencies = [")
                    .trim_end_matches(']')
                    .trim();
                for entry in inner.split(',') {
                    let clean_entry = entry.trim().trim_matches('"').trim_matches('\'');
                    if !clean_entry.is_empty() {
                        add_pyproject_dep(&mut packages, clean_entry, file_path);
                    }
                }
                in_deps_array = false;
            }
            continue;
        }

        if in_deps_array {
            if line.starts_with(']') {
                in_deps_array = false;
                continue;
            }
            let entry = line.trim_matches(',').trim_matches('"').trim_matches('\'');
            if !entry.is_empty() {
                add_pyproject_dep(&mut packages, entry, file_path);
            }
        } else if in_poetry_table {
            if let Some((name, req)) = line.split_once('=') {
                let pkg_name = name.trim().to_string();
                if pkg_name.eq_ignore_ascii_case("python") {
                    continue;
                }
                let requirement = req.trim().trim_matches('"').trim_matches('\'').to_string();
                let purl = make_purl("pypi", &pkg_name, "");
                packages.push(PackageIdentity {
                    ecosystem: "pypi".to_string(),
                    name: pkg_name,
                    resolved_version: None,
                    purl: Some(purl),
                    direct: true,
                    resolution_kind: ResolutionKind::DeclaredRange,
                    commit: None,
                    origin: None,
                    path: file_path.map(|s| s.to_string()),
                    source_digest: None,
                    declared_requirement: Some(requirement),
                });
            }
        }
    }

    Ok(packages)
}

fn add_pyproject_dep(packages: &mut Vec<PackageIdentity>, entry: &str, file_path: Option<&str>) {
    let op_pos = entry.find(['>', '<', '~', '!', ';', '=']);
    let (pkg_name, requirement) = if let Some(idx) = op_pos {
        (
            entry[..idx].trim().to_string(),
            entry[idx..].trim().to_string(),
        )
    } else {
        (entry.trim().to_string(), "*".to_string())
    };

    if !pkg_name.is_empty() && !pkg_name.contains(' ') {
        let purl = make_purl("pypi", &pkg_name, "");
        packages.push(PackageIdentity {
            ecosystem: "pypi".to_string(),
            name: pkg_name,
            resolved_version: None,
            purl: Some(purl),
            direct: true,
            resolution_kind: ResolutionKind::DeclaredRange,
            commit: None,
            origin: None,
            path: file_path.map(|s| s.to_string()),
            source_digest: None,
            declared_requirement: Some(requirement),
        });
    }
}

/// Ingests an npm package-lock.json file.
pub fn parse_package_lock(
    content: &str,
    file_path: Option<&str>,
) -> Result<Vec<PackageIdentity>, String> {
    let mut packages = Vec::new();
    let root: Value =
        serde_json::from_str(content).map_err(|e| format!("Invalid package-lock.json: {}", e))?;

    // Check v2/v3 "packages" map
    if let Some(pkg_map) = root.get("packages").and_then(|p| p.as_object()) {
        let root_deps = pkg_map
            .get("")
            .and_then(|r| r.get("dependencies"))
            .and_then(|d| d.as_object());
        let root_dev_deps = pkg_map
            .get("")
            .and_then(|r| r.get("devDependencies"))
            .and_then(|d| d.as_object());

        for (pkg_key, details) in pkg_map {
            if pkg_key.is_empty() {
                continue; // Root application itself
            }

            let name = if let Some(last_seg) = pkg_key.rsplit("node_modules/").next() {
                last_seg
            } else {
                pkg_key.as_str()
            };

            let Some(ver) = details.get("version").and_then(|v| v.as_str()) else {
                continue;
            };

            // Direct if it only has one "node_modules/" segment and is in root deps
            let is_nested = pkg_key.matches("node_modules/").count() > 1;
            let is_in_root_deps = root_deps.map(|d| d.contains_key(name)).unwrap_or(false)
                || root_dev_deps.map(|d| d.contains_key(name)).unwrap_or(false);
            let direct = !is_nested && is_in_root_deps;

            let purl = make_purl("npm", name, ver);
            packages.push(PackageIdentity {
                ecosystem: "npm".to_string(),
                name: name.to_string(),
                resolved_version: Some(ver.to_string()),
                purl: Some(purl),
                direct,
                resolution_kind: ResolutionKind::LockedExact,
                commit: None,
                origin: None,
                path: file_path.map(|s| s.to_string()),
                source_digest: None,
                declared_requirement: None,
            });
        }
    } else if let Some(deps) = root.get("dependencies").and_then(|d| d.as_object()) {
        // Fallback for v1 package-lock format
        for (name, details) in deps {
            if let Some(ver) = details.get("version").and_then(|v| v.as_str()) {
                let purl = make_purl("npm", name, ver);
                packages.push(PackageIdentity {
                    ecosystem: "npm".to_string(),
                    name: name.clone(),
                    resolved_version: Some(ver.to_string()),
                    purl: Some(purl),
                    direct: true,
                    resolution_kind: ResolutionKind::LockedExact,
                    commit: None,
                    origin: None,
                    path: file_path.map(|s| s.to_string()),
                    source_digest: None,
                    declared_requirement: None,
                });
            }
        }
    }

    Ok(packages)
}

/// Ingests a Cargo.lock file.
pub fn parse_cargo_lock(
    content: &str,
    file_path: Option<&str>,
) -> Result<Vec<PackageIdentity>, String> {
    let mut packages = Vec::new();
    let mut current_name: Option<String> = None;
    let mut current_version: Option<String> = None;

    for raw_line in content.lines() {
        let line = raw_line.trim();

        if line == "[[package]]" {
            if let (Some(name), Some(ver)) = (current_name.take(), current_version.take()) {
                let purl = make_purl("cargo", &name, &ver);
                packages.push(PackageIdentity {
                    ecosystem: "cargo".to_string(),
                    name,
                    resolved_version: Some(ver),
                    purl: Some(purl),
                    direct: true,
                    resolution_kind: ResolutionKind::LockedExact,
                    commit: None,
                    origin: None,
                    path: file_path.map(|s| s.to_string()),
                    source_digest: None,
                    declared_requirement: None,
                });
            }
        } else if let Some(stripped) = line.strip_prefix("name = ") {
            current_name = Some(stripped.trim_matches('"').to_string());
        } else if let Some(stripped) = line.strip_prefix("version = ") {
            current_version = Some(stripped.trim_matches('"').to_string());
        }
    }

    if let (Some(name), Some(ver)) = (current_name.take(), current_version.take()) {
        let purl = make_purl("cargo", &name, &ver);
        packages.push(PackageIdentity {
            ecosystem: "cargo".to_string(),
            name,
            resolved_version: Some(ver),
            purl: Some(purl),
            direct: true,
            resolution_kind: ResolutionKind::LockedExact,
            commit: None,
            origin: None,
            path: file_path.map(|s| s.to_string()),
            source_digest: None,
            declared_requirement: None,
        });
    }

    Ok(packages)
}

/// Ingests a composer.lock file.
pub fn parse_composer_lock(
    content: &str,
    file_path: Option<&str>,
) -> Result<Vec<PackageIdentity>, String> {
    let mut packages = Vec::new();
    let root: Value =
        serde_json::from_str(content).map_err(|e| format!("Invalid composer.lock: {}", e))?;

    for section in ["packages", "packages-dev"] {
        if let Some(list) = root.get(section).and_then(|p| p.as_array()) {
            for pkg in list {
                let name = pkg.get("name").and_then(|n| n.as_str());
                let ver = pkg.get("version").and_then(|v| v.as_str());

                if let (Some(n), Some(v)) = (name, ver) {
                    let clean_ver = v.trim_start_matches('v').to_string();
                    let purl = make_purl("composer", n, &clean_ver);
                    packages.push(PackageIdentity {
                        ecosystem: "composer".to_string(),
                        name: n.to_string(),
                        resolved_version: Some(clean_ver),
                        purl: Some(purl),
                        direct: section == "packages",
                        resolution_kind: ResolutionKind::LockedExact,
                        commit: None,
                        origin: None,
                        path: file_path.map(|s| s.to_string()),
                        source_digest: None,
                        declared_requirement: None,
                    });
                }
            }
        }
    }

    Ok(packages)
}

/// Dispatches ingestion based on file name and content.
pub fn ingest_from_content(file_name: &str, content: &str) -> Result<Vec<PackageIdentity>, String> {
    let lower = file_name.to_lowercase();
    if lower == "package-lock.json" {
        parse_package_lock(content, Some(file_name))
    } else if lower == "cargo.lock" {
        parse_cargo_lock(content, Some(file_name))
    } else if lower == "composer.lock" {
        parse_composer_lock(content, Some(file_name))
    } else if lower.ends_with("requirements.txt") {
        parse_requirements_txt(content, Some(file_name))
    } else if lower == "pyproject.toml" {
        parse_pyproject_toml(content, Some(file_name))
    } else {
        Err(format!("Unsupported manifest/lockfile: {}", file_name))
    }
}

/// Reads and ingests a manifest or lockfile from disk.
pub fn ingest_manifest_or_lockfile(path: &Path) -> Result<Vec<PackageIdentity>, String> {
    let content = fs::read_to_string(path)
        .map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;
    let file_name = path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();
    ingest_from_content(&file_name, &content)
}
