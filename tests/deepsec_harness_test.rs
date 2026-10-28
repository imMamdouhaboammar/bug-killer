use bug_killer::deepsec::*;
use std::fs;
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
    assert!(storage.setup_dir(project_id).join("surface-inventory.json").exists());

    // 3. Scanner Stage
    let scan_opts = ScanOptions::default();
    let scan_stats = scan_repository(root, project_id, &storage, &scan_opts).expect("scan succeeds");
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
        batch_size: 2,
        limit: None,
        filter: None,
        max_cost_usd: Some(10.0),
        model: "claude-opus-4-8".to_string(),
        agent_type: "claude".to_string(),
    };
    let mock_ai = MockAIClient;
    let proc_stats = process_repository(root, project_id, &storage, &mock_ai, &proc_opts)
        .expect("process succeeds");
    assert_eq!(proc_stats.files_processed, 3);
    assert!(proc_stats.findings_count >= 1);

    let analyzed_records = storage.load_all_file_records(project_id);
    for r in &analyzed_records {
        assert_eq!(r.status, FileStatus::Analyzed);
        assert!(!r.analysis_history.is_empty());
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

// @lat: [[tests#Test Suite Specifications#DeepSec Harness Specifications#Atomic File Locking And Reclaim]]
#[test]
fn test_atomic_file_lock_and_stale_reclaim() {
    let tmp = tempdir().expect("temp dir");
    let storage = StorageManager::new(tmp.path());
    let project_id = "test-lock-proj";
    storage.ensure_project(project_id, "/dummy").expect("ensure project");

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

    // Because run-worker-1 has no completed RunMeta, is_reclaimable_lock checks if run exists.
    // Since no RunMeta exists for run-worker-1 on disk, is_reclaimable_lock returns true.
    assert!(storage.is_reclaimable_lock(&record2));

    // Release lock
    storage.release_file_lock(&mut record).expect("release lock");
    assert_eq!(record.locked_by_run_id, None);
    assert_eq!(record.locked_at, None);
}

#[test]
fn test_finding_id_deterministic_and_unique() {
    let id1 = compute_finding_id("proj-a", "src/db.ts", "SQL Injection");
    let id2 = compute_finding_id("proj-a", "src/db.ts", "SQL Injection");
    let id3 = compute_finding_id("proj-a", "src/db.ts", "RCE Injection");

    assert_eq!(id1, id2, "Finding IDs with same signature must match");
    assert_ne!(id1, id3, "Different vulnerability titles must have distinct finding IDs");
    assert!(id1.starts_with("finding_"));
}
