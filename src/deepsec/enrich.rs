use crate::deepsec::storage::StorageManager;
use crate::deepsec::types::*;
use chrono::Utc;
use std::path::Path;
use std::process::Command;

pub fn enrich_findings(
    root_path: &Path,
    project_id: &str,
    storage: &StorageManager,
) -> Result<usize, String> {
    let all_records = storage.load_all_file_records(project_id);
    let mut enriched_count = 0;

    for mut rec in all_records {
        if rec.findings.is_empty() {
            continue;
        }

        let output = Command::new("git")
            .arg("log")
            .arg("-n")
            .arg("5")
            .arg("--format=%an|%ae|%aI")
            .arg("--")
            .arg(&rec.file_path)
            .current_dir(root_path)
            .output();

        let mut committers = Vec::new();
        if let Ok(out) = output {
            if out.status.success() {
                let stdout = String::from_utf8_lossy(&out.stdout);
                for line in stdout.lines() {
                    let parts: Vec<&str> = line.split('|').collect();
                    if parts.len() >= 3 {
                        committers.push(GitCommitter {
                            name: parts[0].to_string(),
                            email: parts[1].to_string(),
                            date: parts[2].to_string(),
                        });
                    }
                }
            }
        }

        if committers.is_empty() {
            committers.push(GitCommitter {
                name: "Repository Contributor".to_string(),
                email: "dev@local".to_string(),
                date: Utc::now().to_rfc3339(),
            });
        }

        rec.git_info = Some(GitInfo {
            recent_committers: committers,
            enriched_at: Utc::now().to_rfc3339(),
        });

        storage.write_file_record(&rec).map_err(|e| e.to_string())?;
        enriched_count += 1;
    }

    Ok(enriched_count)
}
