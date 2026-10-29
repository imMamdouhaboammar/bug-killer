use bug_killer::deepsec::*;
use std::fs;
use std::process::Command;
use tempfile::tempdir;

// @lat: [[tests#Test Suite Specifications#DeepSec Harness Specifications#Full Pipeline Lifecycle Verification]]
#[test]
fn test_deepsec_lifecycle_end_to_end() {
    let tmp = tempdir().expect("temp dir");
    let root = tmp.path();

    // 1. Scaffold sample project files
    fs::create_dir_all(root.join("src/api")).expect("create src/api");
    fs::write(
        root.join("src/api/users.ts"),
        r#"
import { db } from "../db";
export async function getUser(req, res) {
    const id = req.query.id;
    const query = "SELECT * FROM users WHERE id = '" + id + "' AND active = 1";
    const result = await db.query(query);
    res.json(result);
}
"#,
    )
    .expect("write users.ts");

    fs::write(
        root.join("src/utils.py"),
        r#"
import subprocess
def run_command(user_input):
    subprocess.call("ping -c 1 " + user_input, shell=True)
"#,
    )
    .expect("write utils.py");

    fs::write(
        root.join("config.json"),
        r#"
{
    "apiKey": "AKIAIOSFODNN7EXAMPLE",
    "dbUri": "postgres://admin:secret@localhost:5432/prod"
}
"#,
    )
    .expect("write config.json");

    let storage = StorageManager::new(root);
    let project_id = "test-e2e-project";

    // 2. Project Initialization (Coordinator)
    initialize_project(root, project_id, &storage).expect("initialize_project succeeds");
    assert!(storage.project_dir(project_id).join("INFO.md").exists());
    assert!(
        storage
            .setup_dir(project_id)
            .join("surface-inventory.json")
            .exists()
    );

    // 3. Scanner Stage
    let scan_opts = ScanOptions::default();
    let scan_stats =
        scan_repository(root, project_id, &storage, &scan_opts).expect("scan succeeds");
    assert!(scan_stats.files_scanned >= 3);
    assert!(scan_stats.candidates_found >= 3);

    let records = storage.load_all_file_records(project_id);
    assert_eq!(records.len(), 3);
    for r in &records {
        assert_eq!(r.status, FileStatus::Pending);
        assert!(!r.candidates.is_empty());
    }

    // 4. Processor Stage (AI Investigation with Mock client)
    let proc_opts = ProcessOptions {
        concurrency: 1,
        batch_size: 5,
        limit: None,
        filter: None,
        max_cost_usd: None,
        model: "claude-opus-4-8".to_string(),
        agent_type: "claude".to_string(),
    };
    let mock_ai = MockAIClient;
    let proc_stats = process_repository(root, project_id, &storage, &mock_ai, &proc_opts)
        .expect("process succeeds");
    assert_eq!(proc_stats.files_processed, 3);
    assert!(proc_stats.findings_count >= 1);
    assert_eq!(
        proc_stats.total_cost_usd, 0.0,
        "No cost telemetry is available from the mock"
    );

    let analyzed_records = storage.load_all_file_records(project_id);
    for r in &analyzed_records {
        assert_eq!(r.status, FileStatus::Analyzed);
        assert!(!r.analysis_history.is_empty());
        assert!(
            r.analysis_history
                .iter()
                .all(|entry| entry.cost_usd.is_none() && entry.usage.is_none())
        );
    }

    // 5. Triage Stage
    let triaged_count = triage_findings(project_id, &storage).expect("triage succeeds");
    assert!(triaged_count >= 1);

    // 6. Revalidation Stage
    let reval_opts = RevalidateOptions {
        force: true,
        model: "claude-opus-4-8".to_string(),
    };
    let reval_stats =
        revalidate_findings(root, project_id, &storage, &reval_opts).expect("revalidate succeeds");
    assert!(reval_stats.findings_revalidated >= 1);
    assert_eq!(
        reval_stats.true_positives, 0,
        "Text-only heuristic inspection must not certify true positives"
    );
    for record in storage.load_all_file_records(project_id) {
        for finding in record.findings {
            assert_ne!(
                finding.revalidation.unwrap().verdict,
                RevalidationVerdict::TruePositive
            );
        }
    }

    // 7. Enrichment Stage
    let enriched = enrich_findings(root, project_id, &storage).expect("enrich succeeds");
    assert!(enriched >= 1);

    // 8. Export Stage
    let report_md = generate_markdown_report(project_id, &storage);
    assert!(report_md.contains("DeepSec Security Scan Report"));

    let export_json_path = root.join("out/findings.json");
    export_json(project_id, &storage, &export_json_path).expect("export json succeeds");
    assert!(export_json_path.exists());

    let export_md_dir_path = root.join("out/findings_dir");
    export_md_dir(project_id, &storage, &export_md_dir_path).expect("export md-dir succeeds");
    assert!(export_md_dir_path.exists());

    // 9. Status & Terminal Table
    let table = render_terminal_summary(&analyzed_records);
    assert!(!table.is_empty());
}

#[test]
fn test_process_cli_requires_real_analysis_backend() {
    let tmp = tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_bug-killer"))
        .args(["deepsec", "process", tmp.path().to_str().unwrap()])
        .env_remove("DEEPSEC_AI_ENDPOINT")
        .env_remove("DEEPSEC_AI_KEY")
        .output()
        .expect("invoke real DeepSec CLI");
    assert!(
        !output.status.success(),
        "CLI must not run an implicit mock backend"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("DEEPSEC_AI_ENDPOINT"),
        "missing backend should be explained: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

struct InvalidResponseClient;

impl DeepSecAIClient for InvalidResponseClient {
    fn investigate(&self, _prompt: &str) -> Result<String, String> {
        Ok("this is not a structured finding response".to_string())
    }
}

struct WrongFileResponseClient;

impl DeepSecAIClient for WrongFileResponseClient {
    fn investigate(&self, _prompt: &str) -> Result<String, String> {
        Ok(serde_json::json!({"findings": [{
            "filePath": "unscanned/file.py", "vulnSlug": "rce", "title": "Unattributed",
            "severity": "CRITICAL", "lineNumbers": [1]
        }]})
        .to_string())
    }
}

#[test]
fn test_invalid_ai_response_does_not_mark_file_analyzed() {
    let tmp = tempdir().unwrap();
    let storage = StorageManager::new(tmp.path());
    let project = "invalid-response";
    storage
        .ensure_project(project, tmp.path().to_str().unwrap())
        .unwrap();

    let mut record = FileRecord::new(
        "src/test.py".to_string(),
        project.to_string(),
        "filehash".to_string(),
        "scan-run".to_string(),
    );
    record.candidates.push(CandidateMatch {
        vuln_slug: "rce".to_string(),
        line_numbers: vec![1],
        snippet: "exec(user_input)".to_string(),
        matched_pattern: "exec".to_string(),
    });
    storage.write_file_record(&record).unwrap();

    let result = process_repository(
        tmp.path(),
        project,
        &storage,
        &InvalidResponseClient,
        &ProcessOptions::default(),
    );
    assert!(result.is_err());
    let stored = storage.read_file_record(project, "src/test.py").unwrap();
    assert_ne!(stored.status, FileStatus::Analyzed);
    assert!(stored.findings.is_empty());

    let mut pending_again = stored;
    pending_again.status = FileStatus::Pending;
    storage.write_file_record(&pending_again).unwrap();
    let wrong_path_result = process_repository(
        tmp.path(),
        project,
        &storage,
        &WrongFileResponseClient,
        &ProcessOptions::default(),
    );
    assert!(
        wrong_path_result.is_err(),
        "AI findings for unscanned paths must not be silently assigned or ignored"
    );
}

#[test]
fn test_storage_rejects_project_and_file_path_traversal() {
    let tmp = tempdir().unwrap();
    let storage = StorageManager::new(tmp.path());
    assert!(storage.ensure_project("../escaped", "ignored").is_err());
    storage.ensure_project("valid-project", "ignored").unwrap();
    let record = FileRecord::new(
        "../../escaped".to_string(),
        "valid-project".to_string(),
        "hash".to_string(),
        "run".to_string(),
    );
    assert!(storage.write_file_record(&record).is_err());
}

// @lat: [[tests#Test Suite Specifications#DeepSec Harness Specifications#Atomic File Locking And Reclaim]]
#[test]
fn test_atomic_file_lock_and_stale_reclaim() {
    let tmp = tempdir().expect("temp dir");
    let storage = StorageManager::new(tmp.path());
    let project_id = "test-lock-proj";
    storage
        .ensure_project(project_id, "/dummy")
        .expect("ensure project");

    let mut record = FileRecord::new(
        "src/auth.ts".to_string(),
        project_id.to_string(),
        "hash123".to_string(),
        "run-1".to_string(),
    );
    storage.write_file_record(&record).expect("write record");

    // Acquire lock
    assert!(storage.acquire_file_lock(&mut record, "run-worker-1"));
    assert_eq!(record.status, FileStatus::Processing);
    assert_eq!(record.locked_by_run_id, Some("run-worker-1".to_string()));

    // Active lock cannot be acquired by another run if run is alive
    let record2 = storage
        .read_file_record(project_id, "src/auth.ts")
        .expect("read record");

    // An unknown, recently-acquired owner cannot be reclaimed immediately.
    assert!(!storage.is_reclaimable_lock(&record2));
    let mut contender = record2.clone();
    assert!(!storage.acquire_file_lock(&mut contender, "run-worker-2"));

    let mut stale_owner = record2.clone();
    stale_owner.locked_by_run_id = Some("run-worker-2".to_string());
    assert!(
        storage.release_file_lock(&mut stale_owner).is_err(),
        "a different worker must not release a lock it does not own"
    );

    // Release lock
    storage
        .release_file_lock(&mut record)
        .expect("release lock");
    assert_eq!(record.locked_by_run_id, None);
    assert_eq!(record.locked_at, None);
}

#[test]
fn test_concurrent_file_lock_only_one_worker_wins() {
    use std::sync::{Arc, Barrier};

    let tmp = tempdir().unwrap();
    let storage = StorageManager::new(tmp.path());
    storage.ensure_project("concurrent", "ignored").unwrap();
    let record = FileRecord::new(
        "src/shared.ts".to_string(),
        "concurrent".to_string(),
        "hash".to_string(),
        "scan-run".to_string(),
    );
    storage.write_file_record(&record).unwrap();

    let barrier = Arc::new(Barrier::new(3));
    let handles: Vec<_> = (0..2)
        .map(|worker| {
            let root = tmp.path().to_path_buf();
            let barrier = Arc::clone(&barrier);
            let mut own_copy = record.clone();
            std::thread::spawn(move || {
                let storage = StorageManager::new(root);
                barrier.wait();
                storage.acquire_file_lock(&mut own_copy, &format!("worker-{worker}"))
            })
        })
        .collect();
    barrier.wait();
    let winners = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .filter(|won| *won)
        .count();
    assert_eq!(winners, 1, "a single record cannot have two live owners");
}

#[test]
fn test_finding_id_deterministic_and_unique() {
    let id1 = compute_finding_id("proj-a", "src/db.ts", "SQL Injection");
    let id2 = compute_finding_id("proj-a", "src/db.ts", "SQL Injection");
    let id3 = compute_finding_id("proj-a", "src/db.ts", "RCE Injection");

    assert_eq!(id1, id2, "Finding IDs with same signature must match");
    assert_ne!(
        id1, id3,
        "Different vulnerability titles must have distinct finding IDs"
    );
    assert!(id1.starts_with("finding_"));
}
