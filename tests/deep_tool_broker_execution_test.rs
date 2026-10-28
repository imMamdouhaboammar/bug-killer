use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::thread;
use std::time::Duration;

use bug_killer::deep::*;
use bug_killer::engine::runner::CancellationToken;
use sha2::{Digest, Sha256};
use tempfile::tempdir;

const DUMMY_SNAPSHOT: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn create_request(tool_id: &str) -> BrokerExecutionRequest {
    let _ = tool_id;
    BrokerExecutionRequest {
        plan_id: "plan-test-broker-01".to_string(),
        run_id: "run-test-broker-01".to_string(),
        snapshot_sha256: DUMMY_SNAPSHOT.to_string(),
        target_ids: vec!["src/lib.rs".to_string()],
        check_ids: vec!["RULE-SEC-01".to_string()],
        authorization_ref: Some("AUTH-OWNER-TEST".to_string()),
        timeout_seconds: Some(5),
        args: Vec::new(),
        working_dir: None,
    }
}

// -------------------------------------------------------------------------
// 1. Missing Tool & Unlicensed Engine Tests
// -------------------------------------------------------------------------

#[test]
fn test_broker_missing_tool_honest_not_run_and_no_mock_artifacts() {
    let broker = ToolCapabilityBroker::new();
    let req = create_request("missing-tool");

    let cancel = CancellationToken::new();
    let receipt = broker.execute("missing-tool-that-does-not-exist", &req, &cancel);

    assert_eq!(receipt.status, ToolExecutionStatus::NotRun);
    assert_eq!(receipt.reason_code, "ENGINE_MISSING");
    assert!(receipt.is_engine_missing());
    assert_eq!(receipt.resources.duration_ms, 0);
    assert!(
        receipt.artifacts.is_empty(),
        "Missing tool must never produce fake artifacts"
    );
    assert!(receipt.validate().is_ok());
}

#[test]
fn test_broker_unlicensed_codeql_blocked_with_no_mock_artifacts() {
    let mut broker = ToolCapabilityBroker::new();
    broker.set_codeql_license_approved(false);

    let req = create_request("codeql");
    let cancel = CancellationToken::new();
    let receipt = broker.execute("codeql", &req, &cancel);

    assert_eq!(receipt.status, ToolExecutionStatus::Blocked);
    assert_eq!(receipt.reason_code, "UNLICENSED_ENVIRONMENT");
    assert!(receipt.is_unlicensed());
    assert!(
        receipt.artifacts.is_empty(),
        "Unlicensed tool must never emit artifacts"
    );
    assert!(receipt.validate().is_ok());
}

// -------------------------------------------------------------------------
// 2. Real Subprocess Execution & Cryptographic Artifact Receipts
// -------------------------------------------------------------------------

#[test]
fn test_broker_real_execution_invokes_process_and_hashes_actual_output() {
    let tmp = tempdir().expect("temp dir");
    let script_path = tmp.path().join("real_tool.sh");
    let output_body = b"{\"findings\": [{\"id\": \"CWE-89\", \"file\": \"db.js\"}]}\n";

    fs::write(
        &script_path,
        format!(
            "#!/bin/sh\ncat << 'EOF'\n{}\nEOF\nexit 0\n",
            std::str::from_utf8(output_body).unwrap().trim_end()
        ),
    )
    .expect("write script");

    // Mark script as executable
    let mut perms = fs::metadata(&script_path).expect("meta").permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&script_path, perms).expect("set perms");

    let mut broker = ToolCapabilityBroker::new();
    broker.set_tool_path("real-mock-tool", script_path);

    let mut req = create_request("real-mock-tool");
    req.timeout_seconds = Some(10);

    let cancel = CancellationToken::new();
    let receipt = broker.execute("real-mock-tool", &req, &cancel);

    assert_eq!(receipt.status, ToolExecutionStatus::Completed);
    assert_eq!(receipt.reason_code, "COMPLETED");
    assert!(receipt.validate().is_ok());

    // Invariant: The artifact hash must be the real SHA-256 of the output bytes, NOT dummy hash!
    assert!(
        !receipt.artifacts.is_empty(),
        "Real tool output must produce artifact receipt"
    );
    let expected_hash = {
        let mut hasher = Sha256::new();
        hasher.update(output_body);
        bug_killer::identity::to_hex(hasher.finalize())
    };

    assert_ne!(
        receipt.artifacts[0].sha256,
        "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        "Broker must not emit hardcoded dummy artifact hash for real executions"
    );
    assert_eq!(receipt.artifacts[0].sha256, expected_hash);
}

// -------------------------------------------------------------------------
// 3. Process Group Timeout and Cancellation Cleanup
// -------------------------------------------------------------------------

#[test]
fn test_broker_timeout_kills_process_group_and_reaps_child() {
    let tmp = tempdir().expect("temp dir");
    let script_path = tmp.path().join("slow_tool.sh");

    // Script spawns background child sleep and sleeps in foreground
    fs::write(&script_path, "#!/bin/sh\nsleep 60 &\nsleep 60\n").expect("write script");

    let mut perms = fs::metadata(&script_path).expect("meta").permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&script_path, perms).expect("set perms");

    let mut broker = ToolCapabilityBroker::new();
    broker.set_tool_path("slow-tool", script_path);

    let mut req = create_request("slow-tool");
    // Strict 1-second timeout
    req.timeout_seconds = Some(1);

    let cancel = CancellationToken::new();
    let start = std::time::Instant::now();
    let receipt = broker.execute("slow-tool", &req, &cancel);
    let elapsed = start.elapsed();

    // Must return in roughly 1-2 seconds, not hang for 60 seconds
    assert!(
        elapsed < Duration::from_secs(5),
        "Timeout must fire promptly"
    );
    assert_eq!(receipt.status, ToolExecutionStatus::Error);
    assert_eq!(receipt.reason_code, "TIMEOUT");
    assert!(receipt.validate().is_ok());
}

#[test]
fn test_broker_cancellation_kills_process_group() {
    let tmp = tempdir().expect("temp dir");
    let script_path = tmp.path().join("cancellable_tool.sh");

    fs::write(&script_path, "#!/bin/sh\nsleep 30\n").expect("write script");

    let mut perms = fs::metadata(&script_path).expect("meta").permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&script_path, perms).expect("set perms");

    let mut broker = ToolCapabilityBroker::new();
    broker.set_tool_path("cancellable-tool", script_path);

    let req = create_request("cancellable-tool");
    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();

    // Cancel after 100ms
    thread::spawn(move || {
        thread::sleep(Duration::from_millis(100));
        cancel_clone.cancel();
    });

    let start = std::time::Instant::now();
    let receipt = broker.execute("cancellable-tool", &req, &cancel);
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_secs(3),
        "Cancellation must terminate process quickly"
    );
    assert_eq!(receipt.status, ToolExecutionStatus::Cancelled);
    assert_eq!(receipt.reason_code, "CANCELLED");
    assert!(receipt.validate().is_ok());
}

// -------------------------------------------------------------------------
// 4. Execution Ledger Integrity and Mock Rejection
// -------------------------------------------------------------------------

#[test]
fn test_execution_ledger_integrity_and_tamper_detection() {
    let mut ledger = ExecutionLedger::new();
    assert!(ledger.is_empty());

    let receipt = ToolExecutionReceipt {
        schema_version: "1.0".to_string(),
        receipt_id: "rcpt-001".to_string(),
        plan_id: "plan-01".to_string(),
        run_id: "run-01".to_string(),
        tool_id: "semgrep".to_string(),
        adapter_version: "0.1.0".to_string(),
        engine_version: Some("1.80.0".to_string()),
        snapshot_sha256: DUMMY_SNAPSHOT.to_string(),
        target_ids: vec!["src/lib.rs".to_string()],
        check_ids: vec!["RULE-01".to_string()],
        status: ToolExecutionStatus::Completed,
        reason_code: "COMPLETED".to_string(),
        authorization_ref: Some("AUTH-REF".to_string()),
        resources: ExecutionResources {
            duration_ms: 120,
            peak_memory_bytes: Some(1024 * 1024),
            cost_estimate_usd: None,
            cost_actual_usd: None,
        },
        artifacts: vec![ReceiptArtifact {
            kind: ArtifactKind::RawOutput,
            sha256: "1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809".to_string(),
            access_class: ArtifactAccessClass::LocalRedacted,
            storage_ref: Some("receipts/out.json".to_string()),
        }],
        started_at: "2026-10-27T10:00:00Z".to_string(),
        completed_at: "2026-10-27T10:00:01Z".to_string(),
    };

    ledger
        .record_receipt(receipt.clone(), true)
        .expect("record real receipt");
    assert_eq!(ledger.len(), 1);
    assert!(ledger.is_real_execution("rcpt-001"));

    let digest = ledger.compute_digest();
    assert_eq!(digest.len(), 64);
    assert!(ledger.verify_integrity(&digest).is_ok());

    // Tampering test: modified ledger digest does not match
    let mut tampered = ledger.clone();
    tampered.receipts[0].reason_code = "FORGED_REASON".to_string();
    assert!(
        tampered.verify_integrity(&digest).is_err(),
        "Tampered receipt must fail integrity check"
    );
}

#[test]
fn test_execution_ledger_rejects_mock_execution_as_real() {
    let mut ledger = ExecutionLedger::new();

    // Mock receipt with dummy artifact hash
    let dummy_receipt = ToolExecutionReceipt {
        schema_version: "1.0".to_string(),
        receipt_id: "rcpt-mock-01".to_string(),
        plan_id: "plan-mock".to_string(),
        run_id: "run-mock".to_string(),
        tool_id: "semgrep".to_string(),
        adapter_version: "0.1.0".to_string(),
        engine_version: None,
        snapshot_sha256: DUMMY_SNAPSHOT.to_string(),
        target_ids: vec!["target/default".to_string()],
        check_ids: vec!["ALL".to_string()],
        status: ToolExecutionStatus::Completed,
        reason_code: "COMPLETED".to_string(),
        authorization_ref: None,
        resources: ExecutionResources::default(),
        artifacts: vec![ReceiptArtifact {
            kind: ArtifactKind::NormalizedFindings,
            sha256: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".to_string(),
            access_class: ArtifactAccessClass::LocalRedacted,
            storage_ref: None,
        }],
        started_at: "2026-10-27T10:00:00Z".to_string(),
        completed_at: "2026-10-27T10:00:00Z".to_string(),
    };

    // Attempting to register mock receipt as real execution MUST fail
    let res = ledger.record_receipt(dummy_receipt.clone(), true);
    assert!(
        res.is_err(),
        "Mock receipt claiming real execution must be rejected"
    );

    // But can be recorded honestly as non-real execution
    assert!(ledger.record_receipt(dummy_receipt, false).is_ok());
    assert!(!ledger.is_real_execution("rcpt-mock-01"));
}

// -------------------------------------------------------------------------
// 5. Real Installed Security Tool Execution
// -------------------------------------------------------------------------

#[test]
fn test_broker_executes_osv_scanner_when_installed() {
    let broker = ToolCapabilityBroker::new();
    if let Some(binary) = broker.find_binary("osv-scanner") {
        assert!(binary.is_file());
        let cap = broker
            .get_capability("osv-scanner")
            .expect("osv-scanner cap");
        assert_eq!(cap.installation, Installation::Available);

        let mut req = create_request("osv-scanner");
        req.args = vec!["--version".to_string()];
        req.timeout_seconds = Some(10);

        let cancel = CancellationToken::new();
        let receipt = broker.execute("osv-scanner", &req, &cancel);

        assert_eq!(receipt.status, ToolExecutionStatus::Completed);
        assert!(
            !receipt.artifacts.is_empty(),
            "osv-scanner --version produces stdout artifact"
        );
        assert!(receipt.validate().is_ok());

        let mut ledger = ExecutionLedger::new();
        assert!(
            ledger.record_receipt(receipt, true).is_ok(),
            "Real tool receipt must record cleanly as real execution"
        );
    }
}
