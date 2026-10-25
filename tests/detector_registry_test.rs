use bug_killer::detectors::DetectorRegistry;
use bug_killer::scanner::cicd::CicdScanner;
use bug_killer::types::*;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_detector_registry_metadata() {
    let registry = DetectorRegistry::default();
    let detectors = registry.all_detectors();
    assert!(
        detectors.len() >= 6,
        "Expected at least 6 core security detectors"
    );

    let supported_rules = registry.supported_rule_ids();
    assert!(
        supported_rules.contains("BK-AI-INJ-001"),
        "Must support SQL injection rule"
    );
    assert!(
        supported_rules.contains("BK-AI-SEC-001"),
        "Must support hardcoded secret rule"
    );
    assert!(
        supported_rules.contains("BK-AI-CIC-001"),
        "Must support CI/CD injection rule"
    );
    assert!(
        supported_rules.contains("BK-AI-INF-003"),
        "Must support Docker root user rule"
    );
}

#[test]
fn distinct_paths_with_equal_finding_ids_are_preserved() {
    let dir = tempdir().unwrap();
    let root = dir.path();
    fs::write(root.join("Dockerfile"), "FROM alpine:3.18\nUSER root\n").unwrap();
    fs::create_dir(root.join("nested")).unwrap();
    fs::write(
        root.join("nested/Dockerfile"),
        "FROM alpine:3.18\nUSER root\n",
    )
    .unwrap();
    let registry = DetectorRegistry::default();
    let report = registry.execute_guard_scan(root, ScanProfile::Quick, None, false);
    let container_findings: Vec<_> = report
        .findings
        .iter()
        .filter(|finding| finding.cve.as_str() == "BK-AI-INF-003")
        .collect();
    assert_eq!(container_findings.len(), 2);

    let changed_report = registry.execute_guard_scan(
        root,
        ScanProfile::Quick,
        Some(vec![root.join("nested/Dockerfile")]),
        false,
    );
    assert_eq!(
        changed_report
            .findings
            .iter()
            .filter(|finding| finding.cve.as_str() == "BK-AI-INF-003")
            .count(),
        1
    );
    assert_eq!(
        changed_report
            .findings
            .iter()
            .find(|finding| finding.cve.as_str() == "BK-AI-INF-003")
            .unwrap()
            .file_path
            .as_deref(),
        Some(root.join("nested/Dockerfile").as_path())
    );
}

#[test]
fn offline_osv_receipt_is_not_marked_complete() {
    let dir = tempdir().unwrap();
    let report =
        DetectorRegistry::default().execute_guard_scan(dir.path(), ScanProfile::Quick, None, false);
    let osv = report
        .receipts
        .iter()
        .find(|receipt| receipt.scanner_id == "osv-sca")
        .unwrap();
    assert_eq!(osv.status, CoverageStatus::NotRun);
}

#[test]
fn github_actions_env_sibling_is_not_mistaken_for_run_script() {
    let workflow = "jobs:\n  test:\n    steps:\n      - run: echo safe\n        env:\n          COMMENT_BODY: ${{ github.event.comment.body }}\n";
    let findings =
        CicdScanner::scan_workflow(std::path::Path::new(".github/workflows/test.yml"), workflow);
    assert!(
        !findings
            .iter()
            .any(|finding| finding.cve.as_str() == "BK-AI-CIC-001")
    );
}

#[test]
fn test_detector_execution_on_vulnerable_and_safe_fixtures() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    // 1. Create a vulnerable CI/CD workflow
    let workflow_dir = root.join(".github").join("workflows");
    fs::create_dir_all(&workflow_dir).unwrap();
    let vuln_workflow = r#"
name: Issue Comment
on: [issue_comment]
jobs:
  echo:
    runs-on: ubuntu-latest
    steps:
      - run: echo "User commented: ${{ github.event.comment.body }}"
"#;
    fs::write(workflow_dir.join("test.yml"), vuln_workflow).unwrap();

    // 2. Create a vulnerable source file with hardcoded secret
    let vuln_code = r#"
const apiKey = "AKIA1234567890ABCDEF";
console.log("Connecting...");
"#;
    fs::write(root.join("app.js"), vuln_code).unwrap();

    // 3. Create a safe Dockerfile
    let safe_docker = r#"
FROM node:20-alpine
USER node
WORKDIR /app
COPY package*.json ./
"#;
    fs::write(root.join("Dockerfile"), safe_docker).unwrap();

    let registry = DetectorRegistry::default();
    let report = registry.execute_guard_scan(root, ScanProfile::Quick, None, false);

    assert_eq!(report.status, ScanStatus::Completed);
    assert_eq!(
        report.result_classification,
        ResultClassification::Confirmed
    );
    assert!(!report.is_clean());

    // Verify findings include secret and cicd
    let has_secret = report
        .findings
        .iter()
        .any(|f| f.cve.as_str() == "BK-AI-SEC-001");
    let has_cicd = report
        .findings
        .iter()
        .any(|f| f.cve.as_str() == "BK-AI-CIC-001");
    assert!(has_secret, "Report must detect hardcoded AWS key");
    assert!(
        has_cicd,
        "Report must detect CI/CD context script injection"
    );

    // Verify reporting exposes rules evaluated, applicable rules, and unsupported rules
    assert!(!report.rules_evaluated.is_empty());
    assert!(!report.applicable_rules.is_empty());
    assert!(!report.unsupported_rules.is_empty());
    assert!(!report.unexamined_reasons.is_empty());
}

#[test]
fn test_clean_workspace_classification() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    // Create purely clean, safe code
    let safe_code = r#"
function add(a, b) {
    return a + b;
}
module.exports = { add };
"#;
    fs::write(root.join("math.js"), safe_code).unwrap();

    let registry = DetectorRegistry::default();
    let report = registry.execute_guard_scan(root, ScanProfile::Quick, None, false);

    assert_eq!(report.status, ScanStatus::Completed);
    assert_eq!(
        report.result_classification,
        ResultClassification::NoFindingInCoverage
    );
    assert!(report.findings.is_empty());
    assert!(report.is_clean());
}
