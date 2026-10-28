use crate::deepsec::scanner::{detect_tech, scan_repository, ScanOptions};
use crate::deepsec::storage::StorageManager;
use crate::deepsec::types::*;
use chrono::Utc;
use std::fs;
use std::io;
use std::path::Path;

pub fn initialize_project(
    root_path: &Path,
    project_id: &str,
    storage: &StorageManager,
) -> io::Result<()> {
    storage.ensure_project(project_id, &root_path.to_string_lossy())?;

    let pdir = storage.project_dir(project_id);
    let sdir = storage.setup_dir(project_id);

    let tech_tags = detect_tech(root_path);

    // 1. Generate INFO.md
    let info_path = pdir.join("INFO.md");
    if !info_path.exists() {
        let mut info_content = format!(
            "# Repository Security Context: {}\n\n- Detected Technologies: {}\n- Initialized At: {}\n\n## Architecture Boundaries\n- Static Analysis Mode: strictly defensive.\n- Primary Ingress: API endpoints, CLI arguments, background jobs.\n",
            project_id,
            tech_tags.join(", "),
            Utc::now().to_rfc3339()
        );

        if tech_tags.contains(&"nextjs".to_string()) {
            info_content.push_str("- Next.js App Router detected: review server actions for unauthenticated mutations.\n");
        }
        if tech_tags.contains(&"fastapi".to_string()) || tech_tags.contains(&"django".to_string()) {
            info_content.push_str("- Python web surface: inspect parameter injection and serialization.\n");
        }
        if tech_tags.contains(&"rust".to_string()) {
            info_content.push_str("- Rust workspace: check unsafe blocks and external process execution.\n");
        }
        if tech_tags.contains(&"go".to_string()) {
            info_content.push_str("- Go microservices: inspect concurrency race conditions and HTTP handlers.\n");
        }

        fs::write(info_path, info_content)?;
    }

    // 2. Generate surface-inventory.json
    let inv_path = sdir.join("surface-inventory.json");
    if !inv_path.exists() {
        let mut surfaces = Vec::new();

        if tech_tags.contains(&"nextjs".to_string()) {
            surfaces.push(SurfaceEntry {
                id: "nextjs-routes".to_string(),
                kind: "http".to_string(),
                exposure: "public".to_string(),
                file_globs: vec!["app/**/route.{ts,js}".to_string()],
                representative_files: vec!["app/api/auth/route.ts".to_string()],
            });
        }

        if tech_tags.contains(&"rust".to_string()) {
            surfaces.push(SurfaceEntry {
                id: "rust-cli-commands".to_string(),
                kind: "cli".to_string(),
                exposure: "local".to_string(),
                file_globs: vec!["src/**/*.rs".to_string()],
                representative_files: vec!["src/main.rs".to_string()],
            });
        }

        if tech_tags.contains(&"go".to_string()) {
            surfaces.push(SurfaceEntry {
                id: "go-services".to_string(),
                kind: "rpc".to_string(),
                exposure: "internal".to_string(),
                file_globs: vec!["services/**/*.go".to_string()],
                representative_files: vec!["services/orchestrator/main.go".to_string()],
            });
        }

        let inv = SurfaceInventory {
            project_id: project_id.to_string(),
            generated_at: Utc::now().to_rfc3339(),
            surfaces,
        };

        fs::write(inv_path, serde_json::to_vec_pretty(&inv)?)?;
    }

    // 3. Baseline Scan
    let scan_opts = ScanOptions::default();
    let _ = scan_repository(root_path, project_id, storage, &scan_opts);

    Ok(())
}
