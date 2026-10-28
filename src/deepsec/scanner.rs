use crate::deepsec::matchers::MatcherRegistry;
use crate::deepsec::storage::StorageManager;
use crate::deepsec::types::*;
use chrono::Utc;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use walkdir::WalkDir;

pub const DEFAULT_IGNORE_PATTERNS: &[&str] = &[
    "node_modules",
    ".git",
    ".deepsec",
    "dist",
    "build",
    "target",
    ".next",
    "coverage",
    ".turbo",
    "__tests__",
    "fixtures",
];

pub fn detect_tech(root_path: &Path) -> Vec<String> {
    let mut tags = Vec::new();

    if root_path.join("package.json").exists() {
        tags.push("node".to_string());
        if let Ok(content) = fs::read_to_string(root_path.join("package.json")) {
            if content.contains("\"next\"") {
                tags.push("nextjs".to_string());
            }
            if content.contains("\"express\"") {
                tags.push("express".to_string());
            }
            if content.contains("\"fastify\"") {
                tags.push("fastify".to_string());
            }
            if content.contains("\"@nestjs/core\"") {
                tags.push("nestjs".to_string());
            }
            if content.contains("\"hono\"") {
                tags.push("hono".to_string());
            }
            if content.contains("\"@trpc/server\"") {
                tags.push("trpc".to_string());
            }
        }
    }

    if root_path.join("Cargo.toml").exists() {
        tags.push("rust".to_string());
        if let Ok(content) = fs::read_to_string(root_path.join("Cargo.toml")) {
            if content.contains("actix-web") {
                tags.push("actix".to_string());
            }
            if content.contains("axum") {
                tags.push("axum".to_string());
            }
            if content.contains("rocket") {
                tags.push("rocket".to_string());
            }
        }
    }

    if root_path.join("go.mod").exists() {
        tags.push("go".to_string());
        if let Ok(content) = fs::read_to_string(root_path.join("go.mod")) {
            if content.contains("gin-gonic") {
                tags.push("gin".to_string());
            }
            if content.contains("go-chi") {
                tags.push("chi".to_string());
            }
            if content.contains("labstack/echo") {
                tags.push("echo".to_string());
            }
        }
    }

    if root_path.join("requirements.txt").exists() || root_path.join("pyproject.toml").exists() {
        tags.push("python".to_string());
        let req_content = fs::read_to_string(root_path.join("requirements.txt")).unwrap_or_default();
        let pyproj_content = fs::read_to_string(root_path.join("pyproject.toml")).unwrap_or_default();
        let combined = format!("{}\n{}", req_content, pyproj_content);

        if combined.contains("django") || combined.contains("Django") {
            tags.push("django".to_string());
        }
        if combined.contains("fastapi") || combined.contains("FastAPI") {
            tags.push("fastapi".to_string());
        }
        if combined.contains("flask") || combined.contains("Flask") {
            tags.push("flask".to_string());
        }
    }

    if root_path.join("Gemfile").exists() {
        tags.push("ruby".to_string());
        if let Ok(content) = fs::read_to_string(root_path.join("Gemfile")) {
            if content.contains("rails") {
                tags.push("rails".to_string());
            }
        }
    }

    tags
}

#[derive(Debug, Clone, Default)]
pub struct ScanOptions {
    pub only_slugs: Option<HashSet<String>>,
    pub skip_slugs: Option<HashSet<String>>,
    pub filter_path: Option<String>,
}

pub fn is_ignored_path(path: &Path) -> bool {
    for comp in path.components() {
        if let std::path::Component::Normal(os_str) = comp {
            if let Some(s) = os_str.to_str() {
                if DEFAULT_IGNORE_PATTERNS.contains(&s) {
                    return true;
                }
            }
        }
    }

    if let Some(file_name) = path.file_name().and_then(|s| s.to_str()) {
        if file_name.ends_with(".test.ts")
            || file_name.ends_with(".test.js")
            || file_name.ends_with(".spec.ts")
            || file_name.ends_with(".spec.js")
            || file_name.ends_with(".d.ts")
            || file_name.ends_with(".md")
            || file_name.ends_with(".png")
            || file_name.ends_with(".jpg")
            || file_name.ends_with(".lock")
        {
            return true;
        }
    }

    false
}

pub fn scan_content(
    rel_path: &str,
    content: &str,
    registry: &MatcherRegistry,
    detected_tech: &[String],
    options: &ScanOptions,
) -> Vec<CandidateMatch> {
    let mut matches = Vec::new();
    let ext = Path::new(rel_path)
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("");

    let lines: Vec<&str> = content.lines().collect();

    for matcher in registry.matchers() {
        if let Some(only) = &options.only_slugs {
            if !only.contains(matcher.vuln_slug) {
                continue;
            }
        }
        if let Some(skip) = &options.skip_slugs {
            if skip.contains(matcher.vuln_slug) {
                continue;
            }
        }

        if !matcher.file_extensions.is_empty() && !matcher.file_extensions.contains(&ext) {
            continue;
        }

        if let Some(required) = &matcher.requires_tech {
            let has_required = required.iter().any(|t| detected_tech.contains(&t.to_string()));
            if !has_required {
                continue;
            }
        }

        for pattern in &matcher.patterns {
            for (idx, line) in lines.iter().enumerate() {
                if pattern.is_match(line) {
                    let line_no = idx + 1;
                    let start_line = idx.saturating_sub(2);
                    let end_line = (idx + 3).min(lines.len());
                    let snippet = lines[start_line..end_line].join("\n");

                    matches.push(CandidateMatch {
                        vuln_slug: matcher.vuln_slug.to_string(),
                        line_numbers: vec![line_no],
                        snippet,
                        matched_pattern: matcher.label.to_string(),
                    });
                    break;
                }
            }
        }
    }

    matches
}

pub fn scan_repository(
    root_path: &Path,
    project_id: &str,
    storage: &StorageManager,
    options: &ScanOptions,
) -> IoResult<RunStats> {
    storage.ensure_project(project_id, &root_path.to_string_lossy())?;
    let run_id = format!(
        "{}-{}",
        Utc::now().format("%Y%m%d%H%M%S"),
        crate::identity::to_hex(rand::random::<[u8; 2]>())
    );
    let mut run_meta = RunMeta::new(
        run_id.clone(),
        project_id.to_string(),
        root_path.to_string_lossy().to_string(),
        "scan".to_string(),
    );

    let registry = MatcherRegistry::new();
    let detected_tech = detect_tech(root_path);

    let mut files_scanned = 0;
    let mut candidates_found = 0;

    for entry in WalkDir::new(root_path)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
    {
        let abs_path = entry.path();
        if is_ignored_path(abs_path) {
            continue;
        }

        let rel_path = match abs_path.strip_prefix(root_path) {
            Ok(p) => p.to_string_lossy().to_string(),
            Err(_) => continue,
        };

        if let Some(filter) = &options.filter_path {
            if !rel_path.starts_with(filter) {
                continue;
            }
        }

        if let Ok(content) = fs::read_to_string(abs_path) {
            files_scanned += 1;
            let mut hasher = Sha256::new();
            hasher.update(content.as_bytes());
            let file_hash = crate::identity::to_hex(hasher.finalize());

            let candidates = scan_content(&rel_path, &content, &registry, &detected_tech, options);
            if !candidates.is_empty() {
                candidates_found += candidates.len();
                let mut record = storage
                    .read_file_record(project_id, &rel_path)
                    .unwrap_or_else(|| {
                        FileRecord::new(
                            rel_path.clone(),
                            project_id.to_string(),
                            file_hash.clone(),
                            run_id.clone(),
                        )
                    });

                record.candidates = candidates;
                record.last_scanned_at = Utc::now().to_rfc3339();
                record.last_scanned_run_id = run_id.clone();
                record.file_hash = file_hash;
                record.status = FileStatus::Pending;
                storage.write_file_record(&record)?;
            }
        }
    }

    run_meta.phase = "done".to_string();
    run_meta.completed_at = Some(Utc::now().to_rfc3339());
    run_meta.stats.files_scanned = files_scanned;
    run_meta.stats.candidates_found = candidates_found;
    storage.write_run_meta(&run_meta)?;

    Ok(run_meta.stats)
}

type IoResult<T> = std::io::Result<T>;
