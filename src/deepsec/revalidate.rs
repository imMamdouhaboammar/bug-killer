use crate::deepsec::storage::StorageManager;
use crate::deepsec::types::*;
use chrono::Utc;
use std::collections::HashSet;
use std::path::Path;

pub struct RevalidateOptions {
    pub force: bool,
    pub model: String,
}

impl Default for RevalidateOptions {
    fn default() -> Self {
        Self {
            force: false,
            model: "claude-opus-4-8".to_string(),
        }
    }
}

pub fn revalidate_findings(
    root_path: &Path,
    project_id: &str,
    storage: &StorageManager,
    options: &RevalidateOptions,
) -> Result<RunStats, String> {
    let run_id = format!(
        "reval-{}-{}",
        Utc::now().format("%Y%m%d%H%M%S"),
        crate::identity::to_hex(rand::random::<[u8; 2]>())
    );

    let mut run_meta = RunMeta::new(
        run_id.clone(),
        project_id.to_string(),
        root_path.to_string_lossy().to_string(),
        "revalidate".to_string(),
    );

    let all_records = storage.load_all_file_records(project_id);
    let mut total_revalidated = 0;
    let true_positives = 0;
    let false_positives = 0;
    let fixed = 0;
    let mut duplicates = 0;

    for mut rec in all_records {
        if rec.findings.is_empty() {
            continue;
        }

        let mut changed = false;
        let mut seen_titles: HashSet<String> = HashSet::new();

        for finding in &mut rec.findings {
            if finding.revalidation.is_some() && !options.force {
                continue;
            }

            // Deduplication logic
            let normalized_title = finding.title.trim().to_lowercase();
            if seen_titles.contains(&normalized_title) {
                finding.revalidation = Some(Revalidation {
                    verdict: RevalidationVerdict::Duplicate,
                    reasoning:
                        "Duplicate finding in same file with matching vulnerability signature"
                            .to_string(),
                    adjusted_severity: None,
                    duplicate_of: Some(finding.title.clone()),
                    revalidated_at: Utc::now().to_rfc3339(),
                    run_id: run_id.clone(),
                    model: "deterministic-dedup-v1".to_string(),
                });
                duplicates += 1;
                total_revalidated += 1;
                changed = true;
                continue;
            }
            seen_titles.insert(normalized_title);

            // File presence and keyword matching are not evidence that a
            // vulnerability is real, remediated, or a false positive.
            let abs_file = root_path.join(&rec.file_path);
            let file_exists = abs_file.exists();

            if !file_exists {
                finding.revalidation = Some(Revalidation {
                    verdict: RevalidationVerdict::Uncertain,
                    reasoning: "File unavailable; remediation cannot be verified".to_string(),
                    adjusted_severity: None,
                    duplicate_of: None,
                    revalidated_at: Utc::now().to_rfc3339(),
                    run_id: run_id.clone(),
                    model: "deterministic-presence-check-v1".to_string(),
                });
            } else {
                finding.revalidation = Some(Revalidation {
                    verdict: RevalidationVerdict::Uncertain,
                    reasoning:
                        "File exists, but no independent security verification was performed"
                            .to_string(),
                    adjusted_severity: None,
                    duplicate_of: None,
                    revalidated_at: Utc::now().to_rfc3339(),
                    run_id: run_id.clone(),
                    model: "deterministic-presence-check-v1".to_string(),
                });
            }

            total_revalidated += 1;
            changed = true;
        }

        if changed {
            storage.write_file_record(&rec).map_err(|e| e.to_string())?;
        }
    }

    run_meta.phase = "done".to_string();
    run_meta.completed_at = Some(Utc::now().to_rfc3339());
    run_meta.stats.findings_revalidated = total_revalidated;
    run_meta.stats.true_positives = true_positives;
    run_meta.stats.false_positives = false_positives;
    run_meta.stats.fixed = fixed;
    run_meta.stats.duplicates = duplicates;
    storage
        .write_run_meta(&run_meta)
        .map_err(|e| e.to_string())?;

    Ok(run_meta.stats)
}
