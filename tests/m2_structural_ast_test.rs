use std::fs;
use std::sync::Arc;
use tempfile::TempDir;

use bug_killer::engine::adapter::AnalyzerAdapter;
use bug_killer::engine::protocol::{
    AnalysisRequest, CoverageReceiptStatus, EngineStatus, NormalizedSeverity, ReceiptReasonCode,
};
use bug_killer::engine::registry::EngineRegistry;
use bug_killer::engine::runner::CancellationToken;
use bug_killer::structural::adapter::AstGrepAdapter;
use bug_killer::types::ScanProfile;

const DUMMY_SNAPSHOT_SHA: &str = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";

fn create_test_request(snapshot_path: &str, check_ids: Vec<String>) -> AnalysisRequest {
    AnalysisRequest::new(
        "run-m2-structural-001",
        "ast-grep-adapter",
        snapshot_path,
        DUMMY_SNAPSHOT_SHA,
        ScanProfile::Deep,
        check_ids,
        vec![snapshot_path.to_string()],
    )
}

/// Test 1: Comments containing SQL injection strings are NOT detected as findings
/// (proves AST structural checking eliminates regex false positives).
#[test]
fn test_1_comments_containing_sql_injection_not_flagged() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("safe_comment.py");

    let code = r#"
# In legacy versions, developers used to write:
# cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
# execute("SELECT * FROM accounts WHERE name = '" + name + "'")
# subprocess.run(f"rm -rf {path}", shell=True)

def safe_database_query(user_id: int):
    """
    Example docstring: execute(f"SELECT * FROM table WHERE id = {user_id}")
    """
    return user_id * 2
"#;
    fs::write(&file_path, code).unwrap();

    let adapter = AstGrepAdapter::new();
    let cancel = CancellationToken::new();
    let req = create_test_request(
        file_path.to_str().unwrap(),
        vec!["BK-AI-INJ-001".to_string(), "BK-AI-INJ-002".to_string()],
    );

    let resp = adapter.analyze(&req, &cancel).expect("Analysis succeeds");
    assert_eq!(resp.status, EngineStatus::Completed);
    assert!(
        resp.findings.is_empty(),
        "Expected 0 findings because SQL injection strings only exist in comments/docstrings, got {}",
        resp.findings.len()
    );
    assert_eq!(resp.receipts.len(), 1);
    assert_eq!(resp.receipts[0].status, CoverageReceiptStatus::Evaluated);
    resp.validate().expect("Response validation succeeds");
}

/// Test 2: True SQL injection (f-strings / concat) is detected with exact AST line & column span.
#[test]
fn test_2_true_sql_injection_detected_with_exact_ast_span() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("vulnerable_sql.py");

    let code = r#"import sqlite3
def get_user(cursor, user_id):
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
"#;
    fs::write(&file_path, code).unwrap();

    let adapter = AstGrepAdapter::new();
    let cancel = CancellationToken::new();
    let req = create_test_request(
        file_path.to_str().unwrap(),
        vec!["BK-AI-INJ-001".to_string()],
    );

    let resp = adapter.analyze(&req, &cancel).expect("Analysis succeeds");
    assert_eq!(resp.status, EngineStatus::Completed);
    assert_eq!(
        resp.findings.len(),
        1,
        "Expected exactly 1 SQL injection finding"
    );

    let finding = &resp.findings[0];
    assert_eq!(finding.rule_id.as_deref(), Some("BK-AI-INJ-001"));
    assert_eq!(finding.severity, NormalizedSeverity::High);
    assert_eq!(finding.weakness_ids, vec!["CWE-89"]);

    let span = finding.target.span.as_ref().expect("Span must be present");
    assert_eq!(span.start_line, 3, "f-string execute is on line 3");
    assert_eq!(span.end_line, 3);
    assert_eq!(
        span.start_column,
        Some(5),
        "cursor.execute starts at column 5"
    );
    assert!(span.end_column.unwrap() > span.start_column.unwrap());

    finding.validate().expect("Finding validation succeeds");
    resp.validate().expect("Response validation succeeds");
}

/// Test 3: Parameterized queries pass cleanly (True Negative).
#[test]
fn test_3_parameterized_queries_pass_cleanly() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("parameterized_sql.py");

    let code = r#"
def safe_queries(cursor, user_id: int, status: str):
    # Parameterized query with tuple
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    # Parameterized query with dictionary
    cursor.execute("SELECT * FROM users WHERE status = %(status)s", {"status": status})
    # Parameterized query with qmark syntax
    cursor.execute("SELECT * FROM orders WHERE id = ?", (user_id,))
"#;
    fs::write(&file_path, code).unwrap();

    let adapter = AstGrepAdapter::new();
    let cancel = CancellationToken::new();
    let req = create_test_request(
        file_path.to_str().unwrap(),
        vec!["BK-AI-INJ-001".to_string()],
    );

    let resp = adapter.analyze(&req, &cancel).expect("Analysis succeeds");
    assert_eq!(resp.status, EngineStatus::Completed);
    assert!(
        resp.findings.is_empty(),
        "Parameterized queries must not produce any findings"
    );
    assert_eq!(resp.receipts.len(), 1);
    assert_eq!(resp.receipts[0].status, CoverageReceiptStatus::Evaluated);
    resp.validate().expect("Response validation succeeds");
}

/// Test 4: Command injection with `shell=True` detected; array args pass.
#[test]
fn test_4_command_injection_shell_true_detected_and_array_args_pass() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("command_execution.py");

    let code = r#"
import subprocess

def insecure_ping(host: str):
    subprocess.run(f"ping -c 1 {host}", shell=True)

def secure_ping(host: str):
    subprocess.run(["ping", "-c", "1", host], shell=False)

def secure_list(path: str):
    subprocess.run(["ls", "-la", path])
"#;
    fs::write(&file_path, code).unwrap();

    let adapter = AstGrepAdapter::new();
    let cancel = CancellationToken::new();
    let req = create_test_request(
        file_path.to_str().unwrap(),
        vec!["BK-AI-INJ-002".to_string()],
    );

    let resp = adapter.analyze(&req, &cancel).expect("Analysis succeeds");
    assert_eq!(resp.status, EngineStatus::Completed);
    assert_eq!(
        resp.findings.len(),
        1,
        "Expected exactly 1 command injection finding for shell=True"
    );

    let finding = &resp.findings[0];
    assert_eq!(finding.rule_id.as_deref(), Some("BK-AI-INJ-002"));
    assert_eq!(finding.severity, NormalizedSeverity::Critical);
    assert_eq!(finding.weakness_ids, vec!["CWE-78"]);
    let span = finding.target.span.as_ref().unwrap();
    assert_eq!(span.start_line, 5, "Insecure subprocess.run is on line 5");

    resp.validate().expect("Response validation succeeds");
}

/// Test 5: Hardcoded secret literal detected; env lookup passes.
#[test]
fn test_5_hardcoded_secret_literal_detected_and_env_lookup_passes() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("credentials.py");

    let code = r#"
import os

# Hardcoded secrets (Positive)
api_key = "synthetic_mock_api_token_value_for_testing"
stripe_secret = "synthetic_mock_webhook_secret_value"
db_password = "SyntheticMockPassword123!"

# Safe environment variable lookups (Negative)
safe_api_key = os.environ.get("API_KEY")
safe_token = os.getenv("AUTH_TOKEN")
safe_db_pass = os.environ["DATABASE_PASSWORD"]

# Non-secret literal and dummy placeholders (Negative)
username = "admin_user"
dummy_token = "YOUR_API_KEY_HERE"
empty_secret = ""
"#;
    fs::write(&file_path, code).unwrap();

    let adapter = AstGrepAdapter::new();
    let cancel = CancellationToken::new();
    let req = create_test_request(
        file_path.to_str().unwrap(),
        vec!["BK-AI-SEC-001".to_string()],
    );

    let resp = adapter.analyze(&req, &cancel).expect("Analysis succeeds");
    assert_eq!(resp.status, EngineStatus::Completed);

    // Verify hardcoded secrets are caught
    let rule_ids: Vec<&str> = resp
        .findings
        .iter()
        .map(|f| f.rule_id.as_deref().unwrap())
        .collect();
    assert_eq!(rule_ids.len(), 3, "Expected 3 hardcoded secret findings");
    for id in &rule_ids {
        assert_eq!(*id, "BK-AI-SEC-001");
    }

    // Verify none of the findings target the safe environment variables
    for f in &resp.findings {
        let summary = f.summary.as_deref().unwrap_or("");
        assert!(!summary.contains("safe_api_key"));
        assert!(!summary.contains("safe_token"));
        assert!(!summary.contains("safe_db_pass"));
        assert!(!summary.contains("username"));
        assert!(!summary.contains("dummy_token"));
        assert!(!summary.contains("empty_secret"));
    }

    resp.validate().expect("Response validation succeeds");
}

/// Test for BK-AI-LNG-001: Insecure dynamic eval catches eval/exec with dynamic inputs.
#[test]
fn test_insecure_dynamic_eval_positive_and_negative() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("eval_code.py");

    let code = r#"
def run_user_code(user_input: str):
    # Dynamic expressions (Positive)
    eval(user_input)
    exec(f"process_{user_input}()")

    # Static literal expressions (Negative / Safe)
    eval("1 + 1")
    exec("x = 42")
"#;
    fs::write(&file_path, code).unwrap();

    let adapter = AstGrepAdapter::new();
    let cancel = CancellationToken::new();
    let req = create_test_request(
        file_path.to_str().unwrap(),
        vec!["BK-AI-LNG-001".to_string()],
    );

    let resp = adapter.analyze(&req, &cancel).expect("Analysis succeeds");
    assert_eq!(resp.status, EngineStatus::Completed);
    assert_eq!(resp.findings.len(), 2, "Expected 2 dynamic eval findings");
    for f in &resp.findings {
        assert_eq!(f.rule_id.as_deref(), Some("BK-AI-LNG-001"));
        assert_eq!(f.weakness_ids, vec!["CWE-95"]);
    }
}

/// Test 6: Source hash cache hits on identical file SHA-256; re-parsing bypassed.
#[test]
fn test_6_source_hash_cache_hits_and_invalidation() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("cached_target.py");

    let code_v1 = "api_key = \"sk_live_1234567890abcdef\"\n";
    fs::write(&file_path, code_v1).unwrap();

    let adapter = AstGrepAdapter::new();
    let cancel = CancellationToken::new();
    let req = create_test_request(file_path.to_str().unwrap(), vec!["ALL_ACTIVE".to_string()]);

    // First scan: cache miss
    let resp1 = adapter.analyze(&req, &cancel).expect("Scan 1 succeeds");
    assert_eq!(resp1.findings.len(), 1);
    assert_eq!(adapter.cache().miss_count(), 1);
    assert_eq!(adapter.cache().hit_count(), 0);

    // Second scan with identical content: cache hit, re-parsing bypassed
    let resp2 = adapter.analyze(&req, &cancel).expect("Scan 2 succeeds");
    assert_eq!(resp2.findings.len(), 1);
    assert_eq!(adapter.cache().miss_count(), 1);
    assert_eq!(adapter.cache().hit_count(), 1);
    assert_eq!(resp1.findings[0].finding_id, resp2.findings[0].finding_id);

    // Mutate source: write new content
    let code_v2 = "api_key = \"sk_live_different_value_1234567\"\n";
    fs::write(&file_path, code_v2).unwrap();

    // Third scan: new content SHA-256 causes a cache miss for the new key
    let resp3 = adapter.analyze(&req, &cancel).expect("Scan 3 succeeds");
    assert_eq!(resp3.findings.len(), 1);
    assert_eq!(adapter.cache().miss_count(), 2);
    assert_eq!(adapter.cache().hit_count(), 1);
}

/// Test 7: Syntax error in source yields honest CoverageReceiptV1 with ReasonCode::ParseError and does NOT panic.
#[test]
fn test_7_syntax_error_yields_honest_parse_error_receipt_without_panic() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("syntax_error.py");

    let malformed_code = r#"
def broken_syntax(
    this is completely broken syntax !!! &&& %%%
    not even close to valid python :::
"#;
    fs::write(&file_path, malformed_code).unwrap();

    let adapter = AstGrepAdapter::new();
    let cancel = CancellationToken::new();
    let req = create_test_request(file_path.to_str().unwrap(), vec!["ALL_ACTIVE".to_string()]);

    // Must NOT panic!
    let resp = adapter
        .analyze(&req, &cancel)
        .expect("Analysis finishes honestly");

    // Must report Partial status due to parse errors
    assert_eq!(resp.status, EngineStatus::Partial);
    assert_eq!(resp.receipts.len(), 1);

    let receipt = &resp.receipts[0];
    assert_eq!(receipt.status, CoverageReceiptStatus::Partial);
    assert!(
        receipt
            .reason_codes
            .contains(&ReceiptReasonCode::ParseError),
        "Expected ReasonCode::ParseError, got {:?}",
        receipt.reason_codes
    );

    receipt.validate().expect("Receipt validation succeeds");
    resp.validate().expect("Response validation succeeds");
}

/// Test 8: Integration with EngineRegistry: AstGrepAdapter registered and dispatched via AnalysisRequest.
#[test]
fn test_8_engine_registry_integration_and_dispatch() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("vuln.py");
    let code = "eval(user_supplied_string)\n";
    fs::write(&file_path, code).unwrap();

    let mut registry = EngineRegistry::new();
    let adapter = Arc::new(AstGrepAdapter::new());
    registry.register(adapter.clone());

    // Check registry lookup
    let retrieved = registry.get("ast-grep-adapter").expect("Adapter found");
    assert_eq!(retrieved.engine_id(), "ast-grep-adapter");
    assert_eq!(retrieved.engine_version(), "0.51.0");

    // Profile lookup
    let profile_adapters = registry.find_for_profile(ScanProfile::Deep);
    assert!(
        profile_adapters
            .iter()
            .any(|a| a.engine_id() == "ast-grep-adapter"),
        "ast-grep-adapter must be present for Deep profile"
    );

    // Language capability check
    assert!(retrieved.can_handle_language("python"));
    assert!(retrieved.can_handle_language("rust"));
    assert!(retrieved.can_handle_language("javascript"));

    // Dispatch via EngineRegistry
    let cancel = CancellationToken::new();
    let req = create_test_request(
        file_path.to_str().unwrap(),
        vec!["BK-AI-LNG-001".to_string()],
    );

    let resp = registry
        .dispatch(&req, &cancel)
        .expect("Registry dispatch succeeds");

    assert_eq!(resp.engine_id, "ast-grep-adapter");
    assert_eq!(resp.status, EngineStatus::Completed);
    assert_eq!(resp.findings.len(), 1);
    assert_eq!(resp.findings[0].rule_id.as_deref(), Some("BK-AI-LNG-001"));
    resp.validate().expect("Response validation succeeds");
}
