use bug_killer::scanner::FleetScanner;
use bug_killer::taint::{TaintEngine, TaintSinkKind};
use bug_killer::types::Severity;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_taint_analysis_sql_injection_and_sanitization() {
    let dir = tempdir().expect("Failed to create tempdir");
    let root = dir.path();

    // 1. Vulnerable JavaScript file: user input directly concatenated into SQL query
    let vuln_js = root.join("vuln.js");
    let vuln_content = r#"
const express = require('express');
const app = express();

app.get('/user', async (req, res) => {
    const userId = req.query.id;
    const sql = "SELECT * FROM users WHERE id = " + userId;
    const result = await db.query(sql);
    res.json(result);
});
"#;
    fs::write(&vuln_js, vuln_content).unwrap();

    let findings = TaintEngine::scan_source(&vuln_js, vuln_content);
    assert_eq!(
        findings.len(),
        1,
        "Should detect 1 SQL injection vulnerability"
    );
    assert_eq!(findings[0].sink_kind, TaintSinkKind::SqlInjection);
    assert_eq!(findings[0].variable_name, "sql");
    assert_eq!(findings[0].source_line, 6);
    assert_eq!(findings[0].sink_line, 8);

    // 2. Safe JavaScript file: user input passed through parseInt sanitizer
    let safe_js = root.join("safe.js");
    let safe_content = r#"
app.get('/user', async (req, res) => {
    const userId = req.query.id;
    const safeId = parseInt(userId, 10);
    const sql = "SELECT * FROM users WHERE id = " + safeId;
    const result = await db.query(sql);
    res.json(result);
});
"#;
    fs::write(&safe_js, safe_content).unwrap();

    let safe_findings = TaintEngine::scan_source(&safe_js, safe_content);
    assert!(
        safe_findings.is_empty(),
        "Sanitized parseInt should not trigger SQL injection"
    );
}

#[test]
fn test_taint_analysis_command_injection_and_path_traversal() {
    let dir = tempdir().expect("Failed to create tempdir");
    let root = dir.path();

    // Python command injection
    let py_file = root.join("app.py");
    let py_content = r#"
from flask import Flask, request
import os

app = Flask(__name__)

@app.route('/ping')
def ping():
    host = request.args.get('host')
    os.system("ping -c 1 " + host)
    return "ok"
"#;
    fs::write(&py_file, py_content).unwrap();

    let findings = TaintEngine::scan_source(&py_file, py_content);
    assert!(
        findings
            .iter()
            .any(|f| f.sink_kind == TaintSinkKind::CommandInjection && f.variable_name == "host")
    );

    // FleetScanner end-to-end integration with --taint
    let report = FleetScanner::scan_directory_with_rules_and_taint(root, false, &[], true);
    assert!(report.is_vulnerable);
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.severity == Severity::Critical && f.id.starts_with("taint-cwe-78"))
    );
}
