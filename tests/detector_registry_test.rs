use bug_killer::detectors::DetectorRegistry;
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
        supported_rules.contains("BK-AI-INF-001"),
        "Must support Docker root user rule"
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
