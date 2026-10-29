use crate::cli::DeepsecCommands;
use crate::deepsec;

pub fn handle_deepsec(cmd: DeepsecCommands) -> i32 {
    match cmd {
        DeepsecCommands::Init { path, project_id } => {
            let pid = project_id.unwrap_or_else(|| {
                path.canonicalize()
                    .ok()
                    .and_then(|p| p.file_name().map(|s| s.to_string_lossy().to_string()))
                    .unwrap_or_else(|| "default-project".to_string())
            });
            let storage = deepsec::StorageManager::new(&path);
            if let Err(e) = deepsec::initialize_project(&path, &pid, &storage) {
                eprintln!("DeepSec init error: {}", e);
                return 1;
            }
            println!("DeepSec project initialized successfully for '{}'", pid);
            0
        }
        DeepsecCommands::Scan {
            path,
            project_id,
            filter,
            json,
        } => {
            let pid = project_id.unwrap_or_else(|| "default-project".to_string());
            let storage = deepsec::StorageManager::new(&path);
            let opts = deepsec::ScanOptions {
                filter_path: filter,
                ..Default::default()
            };
            match deepsec::scan_repository(&path, &pid, &storage, &opts) {
                Ok(stats) => {
                    if json {
                        println!("{}", serde_json::to_string_pretty(&stats).unwrap());
                    } else {
                        println!(
                            "Scan complete: {} files scanned, {} candidate matches found.",
                            stats.files_scanned, stats.candidates_found
                        );
                    }
                    0
                }
                Err(e) => {
                    eprintln!("DeepSec scan error: {}", e);
                    1
                }
            }
        }
        DeepsecCommands::Process {
            path,
            project_id,
            batch_size,
            limit,
            filter,
            max_cost_usd,
            model,
            agent,
            json,
        } => {
            let pid = project_id.unwrap_or_else(|| "default-project".to_string());
            let storage = deepsec::StorageManager::new(&path);
            let opts = deepsec::ProcessOptions {
                concurrency: 1,
                batch_size,
                limit,
                filter,
                max_cost_usd,
                model,
                agent_type: agent,
            };
            // Never silently use a synthetic backend in production commands.
            let endpoint_url = match std::env::var("DEEPSEC_AI_ENDPOINT") {
                Ok(url) if url.starts_with("https://") => url,
                _ => {
                    eprintln!("DeepSec process requires a configured HTTPS DEEPSEC_AI_ENDPOINT");
                    return 1;
                }
            };
            let api_key = match std::env::var("DEEPSEC_AI_KEY") {
                Ok(key) if !key.trim().is_empty() => key,
                _ => {
                    eprintln!("DeepSec process requires DEEPSEC_AI_KEY");
                    return 1;
                }
            };
            let client = deepsec::HttpAIClient {
                endpoint_url,
                api_key,
                model: opts.model.clone(),
            };
            match deepsec::process_repository(&path, &pid, &storage, &client, &opts) {
                Ok(stats) => {
                    if json {
                        println!("{}", serde_json::to_string_pretty(&stats).unwrap());
                    } else {
                        println!(
                            "Processing complete: {} files processed, {} findings surfaced.",
                            stats.files_processed, stats.findings_count
                        );
                    }
                    0
                }
                Err(e) => {
                    eprintln!("DeepSec process error: {}", e);
                    1
                }
            }
        }
        DeepsecCommands::Revalidate {
            path,
            project_id,
            force,
            model,
            json,
        } => {
            let pid = project_id.unwrap_or_else(|| "default-project".to_string());
            let storage = deepsec::StorageManager::new(&path);
            let opts = deepsec::RevalidateOptions { force, model };
            match deepsec::revalidate_findings(&path, &pid, &storage, &opts) {
                Ok(stats) => {
                    if json {
                        println!("{}", serde_json::to_string_pretty(&stats).unwrap());
                    } else {
                        println!(
                            "Revalidation complete: {} revalidated (TP: {}, FP: {}, Fixed: {}, Dup: {}).",
                            stats.findings_revalidated,
                            stats.true_positives,
                            stats.false_positives,
                            stats.fixed,
                            stats.duplicates
                        );
                    }
                    0
                }
                Err(e) => {
                    eprintln!("DeepSec revalidate error: {}", e);
                    1
                }
            }
        }
        DeepsecCommands::Triage {
            path,
            project_id,
            json,
        } => {
            let pid = project_id.unwrap_or_else(|| "default-project".to_string());
            let storage = deepsec::StorageManager::new(&path);
            match deepsec::triage_findings(&pid, &storage) {
                Ok(count) => {
                    if json {
                        println!("{}", serde_json::json!({ "triaged_count": count }));
                    } else {
                        println!("Triage complete: {} findings prioritized.", count);
                    }
                    0
                }
                Err(e) => {
                    eprintln!("DeepSec triage error: {}", e);
                    1
                }
            }
        }
        DeepsecCommands::Enrich {
            path,
            project_id,
            json,
        } => {
            let pid = project_id.unwrap_or_else(|| "default-project".to_string());
            let storage = deepsec::StorageManager::new(&path);
            match deepsec::enrich_findings(&path, &pid, &storage) {
                Ok(count) => {
                    if json {
                        println!("{}", serde_json::json!({ "enriched_count": count }));
                    } else {
                        println!(
                            "Enrichment complete: {} files annotated with git history.",
                            count
                        );
                    }
                    0
                }
                Err(e) => {
                    eprintln!("DeepSec enrich error: {}", e);
                    1
                }
            }
        }
        DeepsecCommands::Report {
            path,
            project_id,
            json,
        } => {
            let pid = project_id.unwrap_or_else(|| "default-project".to_string());
            let storage = deepsec::StorageManager::new(&path);
            if json {
                let records = storage.load_all_file_records(&pid);
                println!("{}", serde_json::to_string_pretty(&records).unwrap());
            } else {
                let records = storage.load_all_file_records(&pid);
                println!("{}", deepsec::render_terminal_summary(&records));
            }
            0
        }
        DeepsecCommands::Export {
            path,
            project_id,
            format,
            out,
        } => {
            let pid = project_id.unwrap_or_else(|| "default-project".to_string());
            let storage = deepsec::StorageManager::new(&path);
            let res = if format == "md-dir" {
                deepsec::export_md_dir(&pid, &storage, &out)
            } else {
                deepsec::export_json(&pid, &storage, &out)
            };
            if let Err(e) = res {
                eprintln!("DeepSec export error: {}", e);
                return 1;
            }
            println!("Exported findings to '{}' ({})", out.display(), format);
            0
        }
        DeepsecCommands::Status {
            path,
            project_id,
            json,
        } => {
            let pid = project_id.unwrap_or_else(|| "default-project".to_string());
            let storage = deepsec::StorageManager::new(&path);
            let records = storage.load_all_file_records(&pid);
            let total_files = records.len();
            let pending_files = records
                .iter()
                .filter(|r| r.status == deepsec::FileStatus::Pending)
                .count();
            let analyzed_files = records
                .iter()
                .filter(|r| r.status == deepsec::FileStatus::Analyzed)
                .count();
            let total_findings: usize = records.iter().map(|r| r.findings.len()).sum();

            if json {
                let out = serde_json::json!({
                    "project_id": pid,
                    "total_files": total_files,
                    "pending_files": pending_files,
                    "analyzed_files": analyzed_files,
                    "total_findings": total_findings,
                });
                println!("{}", serde_json::to_string_pretty(&out).unwrap());
            } else {
                println!("DeepSec Status for project '{}':", pid);
                println!("  Indexed Files:    {}", total_files);
                println!("  Pending Files:    {}", pending_files);
                println!("  Analyzed Files:   {}", analyzed_files);
                println!("  Total Findings:   {}", total_findings);
            }
            0
        }
    }
}
