use bug_killer::scanner::FleetScanner;
use bug_killer::taint::TaintEngine;
use bug_killer::types::{Affectedness, CoverageStatus, EvidenceCertainty};
use std::fs;
use std::path::Path;

#[test]
fn test_sast_multi_language_fixture_corpus() {
    let fixtures_dir = Path::new("tests/fixtures/sast");
    assert!(
        fixtures_dir.exists(),
        "SAST fixtures directory tests/fixtures/sast must exist"
    );

    // 1. JavaScript Suite
    let js_vuln = fixtures_dir.join("js/vulnerable_eval.js");
    let js_vuln_content = fs::read_to_string(&js_vuln).expect("Read js_vuln");
    let js_vuln_findings = TaintEngine::scan_source(&js_vuln, &js_vuln_content);
    assert_eq!(
        js_vuln_findings.len(),
        1,
        "vulnerable_eval.js must yield 1 finding"
    );

    let js_finding = js_vuln_findings[0].clone().into_finding();
    assert_eq!(
        js_finding.evidence_certainty,
        EvidenceCertainty::PatternIndicator,
        "SAST findings must be labeled PatternIndicator, not Confirmed"
    );
    assert_eq!(
        js_finding.affectedness,
        Affectedness::PotentiallyAffected,
        "SAST findings must not claim confirmed affectedness"
    );
    assert!(
        !js_finding.uncertainty_reasons.is_empty(),
        "SAST findings must include explicit uncertainty reasons"
    );

    let js_safe = fixtures_dir.join("js/safe_sanitized.js");
    let js_safe_content = fs::read_to_string(&js_safe).expect("Read js_safe");
    let js_safe_findings = TaintEngine::scan_source(&js_safe, &js_safe_content);
    assert!(
        js_safe_findings.is_empty(),
        "safe_sanitized.js must yield 0 findings"
    );

    // 2. Python Suite
    let py_vuln = fixtures_dir.join("python/vulnerable_cmd.py");
    let py_vuln_content = fs::read_to_string(&py_vuln).expect("Read py_vuln");
    let py_vuln_findings = TaintEngine::scan_source(&py_vuln, &py_vuln_content);
    assert_eq!(
        py_vuln_findings.len(),
        1,
        "vulnerable_cmd.py must yield 1 finding"
    );

    let py_safe = fixtures_dir.join("python/safe_cmd.py");
    let py_safe_content = fs::read_to_string(&py_safe).expect("Read py_safe");
    let py_safe_findings = TaintEngine::scan_source(&py_safe, &py_safe_content);
    assert!(
        py_safe_findings.is_empty(),
        "safe_cmd.py must yield 0 findings"
    );

    // 3. PHP Suite
    let php_vuln = fixtures_dir.join("php/vulnerable_sql.php");
    let php_vuln_content = fs::read_to_string(&php_vuln).expect("Read php_vuln");
    let php_vuln_findings = TaintEngine::scan_source(&php_vuln, &php_vuln_content);
    assert_eq!(
        php_vuln_findings.len(),
        1,
        "vulnerable_sql.php must yield 1 finding"
    );

    let php_safe = fixtures_dir.join("php/safe_sql.php");
    let php_safe_content = fs::read_to_string(&php_safe).expect("Read php_safe");
    let php_safe_findings = TaintEngine::scan_source(&php_safe, &php_safe_content);
    assert!(
        php_safe_findings.is_empty(),
        "safe_sql.php must yield 0 findings"
    );

    // 4. Go Suite
    let go_vuln = fixtures_dir.join("go/vulnerable_traversal.go");
    let go_vuln_content = fs::read_to_string(&go_vuln).expect("Read go_vuln");
    let go_vuln_findings = TaintEngine::scan_source(&go_vuln, &go_vuln_content);
    assert_eq!(
        go_vuln_findings.len(),
        1,
        "vulnerable_traversal.go must yield 1 finding"
    );

    let go_safe = fixtures_dir.join("go/safe_traversal.go");
    let go_safe_content = fs::read_to_string(&go_safe).expect("Read go_safe");
    let go_safe_findings = TaintEngine::scan_source(&go_safe, &go_safe_content);
    assert!(
        go_safe_findings.is_empty(),
        "safe_traversal.go must yield 0 findings"
    );
}

#[test]
fn test_sast_fleet_scanner_receipt_generation() {
    let fixtures_dir = Path::new("tests/fixtures/sast");
    let report = FleetScanner::scan_directory_with_rules_and_taint(fixtures_dir, false, &[], true);

    assert!(report.is_vulnerable);
    assert!(report.findings.len() >= 4);

    let sast_receipt = report
        .coverage
        .receipts
        .iter()
        .find(|r| r.scanner_id == "taint-sast")
        .expect("ScanCoverage must contain taint-sast CoverageReceipt");

    assert_eq!(sast_receipt.status, CoverageStatus::Complete);
    assert!(
        sast_receipt.items_examined >= 8,
        "Should have evaluated at least 8 fixture files"
    );
    assert!(sast_receipt.errors.is_empty());
}
