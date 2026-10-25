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
    let vuln_code = format!(
        "const apiKey = \"{}{}\";\nconsole.log(\"Connecting...\");\n",
        "AKIA", "1234567890ABCDEF"
    );
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

    println!("FINDINGS COUNT: {}", report.findings.len());
    for f in &report.findings {
        println!(
            "FINDING: id={} cve={} desc={}",
            f.id,
            f.cve.as_str(),
            f.description
        );
    }

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
    assert!(
        report.unsupported_rules.is_empty(),
        "Expected 0 unsupported rules when all rules in coverage are supported"
    );
    assert!(
        report.unexamined_reasons.is_empty(),
        "Expected 0 unexamined reasons when all rules are supported"
    );
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

    println!("FINDINGS COUNT: {}", report.findings.len());
    for f in &report.findings {
        println!(
            "FINDING: id={} cve={} desc={}",
            f.id,
            f.cve.as_str(),
            f.description
        );
    }

    assert_eq!(report.status, ScanStatus::Completed);
    assert_eq!(
        report.result_classification,
        ResultClassification::NoFindingInCoverage
    );
    assert!(report.findings.is_empty());
    assert!(report.is_clean());
}

#[test]
fn test_expanded_detector_catalog_rules() {
    let registry = DetectorRegistry::default();
    let supported = registry.supported_rule_ids();

    assert!(
        supported.contains("BK-AI-CIC-003"),
        "Must support unpinned CI action rule"
    );
    assert!(
        supported.contains("BK-AI-CIC-004"),
        "Must support CI untrusted shell expression rule"
    );
    assert!(
        supported.contains("BK-AI-CIC-006"),
        "Must support CI secret debug trace detector rule"
    );
    assert!(
        supported.contains("BK-AI-INF-001"),
        "Must support 0.0.0.0 bind exposure rule"
    );
    assert!(
        supported.contains("BK-AI-INF-007"),
        "Must support container layer secret rule"
    );
    assert!(
        supported.contains("BK-AI-INF-008"),
        "Must support container TLS disabled rule"
    );
    assert!(
        supported.contains("BK-AI-INF-010"),
        "Must support debug/metrics port exposure rule"
    );
    assert!(
        supported.contains("BK-AI-INJ-014"),
        "Must support YAML expression injection rule"
    );
    assert!(
        supported.contains("BK-AI-INJ-015"),
        "Must support ReDoS user regex rule"
    );
    assert!(
        supported.contains("BK-AI-CRY-001"),
        "Must support weak hash function rule"
    );
    assert!(
        supported.contains("BK-AI-CRY-002"),
        "Must support hardcoded static IV rule"
    );
    assert!(
        supported.contains("BK-AI-CRY-003"),
        "Must support AES ECB mode rule"
    );
    assert!(
        supported.contains("BK-AI-LLM-004"),
        "Must support model output execution rule"
    );
    assert!(
        supported.contains("BK-AI-LLM-017"),
        "Must support agent missing budget rule"
    );
    assert!(
        supported.contains("BK-AI-SEC-003"),
        "Must support committed secret / key rule"
    );
    assert!(
        supported.contains("BK-AI-SEC-010"),
        "Must support client/IaC secret rule"
    );
    assert!(
        supported.contains("BK-AI-LLM-003"),
        "Must support direct model execution rule"
    );
}

#[test]
fn test_cicd_unpinned_action_and_script_injection_detection() {
    let dir = tempdir().unwrap();
    let root = dir.path();
    let wf_dir = root.join(".github/workflows");
    fs::create_dir_all(&wf_dir).unwrap();

    let yaml_content = r#"
name: CI
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run script
        run: echo "${{ github.event.issue.title }}"
"#;
    fs::write(wf_dir.join("build.yml"), yaml_content).unwrap();

    let registry = DetectorRegistry::default();
    let report = registry.execute_guard_scan(root, ScanProfile::Quick, None, false);

    assert!(
        report
            .findings
            .iter()
            .any(|f| f.cve.as_str() == "BK-AI-CIC-003"),
        "Must flag unpinned action tag @v3"
    );
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.cve.as_str() == "BK-AI-CIC-004" || f.cve.as_str() == "BK-AI-CIC-001"),
        "Must flag script expression injection"
    );
}

#[test]
fn test_container_secret_and_bind_exposure_detection() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    let dockerfile = r#"
FROM alpine:3.20
USER app
ENV API_SECRET_KEY=supersecret123
CMD ["--bind", "0.0.0.0:8080"]
"#;
    fs::write(root.join("Dockerfile"), dockerfile).unwrap();

    let registry = DetectorRegistry::default();
    let report = registry.execute_guard_scan(root, ScanProfile::Quick, None, false);

    assert!(
        report
            .findings
            .iter()
            .any(|f| f.cve.as_str() == "BK-CONTAINER-003"
                || f.advisory_ids.iter().any(|a| a == "BK-AI-INF-007")),
        "Must flag ENV secret exposure in Dockerfile"
    );
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.cve.as_str() == "BK-AI-INF-001"),
        "Must flag 0.0.0.0 public interface binding"
    );
}

#[test]
fn test_dynamic_rules_detector_in_registry() {
    let dir = tempdir().unwrap();
    let root = dir.path();
    let rules_dir = root.join("rules");
    fs::create_dir_all(&rules_dir).unwrap();

    let custom_rule = r#"[
  {
    "id": "CUSTOM-INSECURE-DEBUG-001",
    "title": "Debug mode enabled in production",
    "severity": "High",
    "description": "Debug mode must not be enabled",
    "target_kind": "GenericSourceFile",
    "file_patterns": ["*.py"],
    "detection": {
      "type": "regex",
      "pattern": "DEBUG\\s*=\\s*True"
    }
  }
]"#;
    fs::write(rules_dir.join("debug.json"), custom_rule).unwrap();
    fs::write(root.join("app.py"), "DEBUG = True\n").unwrap();

    let registry = DetectorRegistry::default();
    let report = registry.execute_guard_scan(root, ScanProfile::Quick, None, false);

    assert!(
        report
            .findings
            .iter()
            .any(|f| f.cve.as_str() == "CUSTOM-INSECURE-DEBUG-001"),
        "Dynamic rule detector in registry must discover and execute custom rules from rules/ directory"
    );
}

#[test]
fn test_cicd_secret_debug_trace_detection() {
    let dir = tempdir().unwrap();
    let root = dir.path();
    let wf_dir = root.join(".github/workflows");
    fs::create_dir_all(&wf_dir).unwrap();

    let yaml_content = r#"
name: Debug Trace Secret Exposure
on: [push]
env:
  ACTIONS_STEP_DEBUG: "true"
jobs:
  debug_job:
    runs-on: ubuntu-latest
    steps:
      - name: Print secrets in step
        run: |
          echo "Debug token: ${{ secrets.DEPLOY_KEY }}"
"#;
    fs::write(wf_dir.join("debug_trace.yml"), yaml_content).unwrap();

    let registry = DetectorRegistry::default();
    let report = registry.execute_guard_scan(root, ScanProfile::Quick, None, false);

    let cic_006_findings: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.cve.as_str() == "BK-AI-CIC-006")
        .collect();

    assert!(
        !cic_006_findings.is_empty(),
        "Must flag secret debug trace / echoed secret in CI/CD workflow (BK-AI-CIC-006)"
    );
}
