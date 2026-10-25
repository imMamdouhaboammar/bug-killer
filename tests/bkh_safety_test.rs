#[path = "../src/scanner/bkh_safety.rs"]
mod bkh_safety;

use bkh_safety::BkhSafetyScanner;
pub use bug_killer::types;
use bug_killer::types::Severity;
use std::path::Path;

const EXPECTED_CATEGORY: &str = "2.26 Bug Killer-specific scanner, reporter and healer safety";
const EXPECTED_DETECTOR: &str = "bkh-safety";

// ===========================================================================
// Category 26: Bug Killer-Specific Scanner, Reporter & Healer Safety Tests
// Rules: BK-AI-BKH-001 through BK-AI-BKH-018
// ===========================================================================

#[test]
fn test_bkh_001_fail_clean() {
    let vuln_code = r#"
fn run_scan(target: &str) -> Result<Report, ScanError> {
    if let Err(e) = scanner.parse_target(target) {
        return Ok(Report::clean());
    }
    Ok(report)
}
"#;
    let path = Path::new("src/scanner/runner.rs");
    let findings = BkhSafetyScanner::scan_source(path, vuln_code);
    assert_eq!(
        findings
            .iter()
            .filter(|f| f.cve.as_str() == "BK-AI-BKH-001")
            .count(),
        1,
        "One unsafe return must generate one finding, not a finding for surrounding lines"
    );
    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-BKH-001")
        .expect("Must detect scanner reporting clean on failure");

    assert_eq!(f.severity, Severity::Critical);
    assert_eq!(f.detector_id, EXPECTED_DETECTOR);
    assert_eq!(f.category, EXPECTED_CATEGORY);
    assert!(f.advisory_ids.contains(&"CWE-754".to_string()));

    let safe_code = r#"
fn run_scan(target: &str) -> Result<Report, ScanError> {
    if let Err(e) = scanner.parse_target(target) {
        logger.error("Scan parser failed: {}", e);
        return Err(ScanError::Failed(e));
    }
    Ok(report)
}
"#;
    let safe_findings = BkhSafetyScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-BKH-001"),
        "Safe error propagation must not flag BK-AI-BKH-001"
    );
}

#[test]
fn test_bkh_002_unresolved_manifest_constraint() {
    let vuln_code = r#"
fn evaluate_dependency(dep: &Dependency) -> VersionStatus {
    let installed_ver = dep.version.unwrap_or("0.0.0");
    check_vulnerability(installed_ver)
}
"#;
    let path = Path::new("src/scanner/manifest.rs");
    let findings = BkhSafetyScanner::scan_source(path, vuln_code);
    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-BKH-002")
        .expect("Must detect unresolved manifest constraint defaulted to 0.0.0");

    assert_eq!(f.severity, Severity::High);
    assert_eq!(f.detector_id, EXPECTED_DETECTOR);
    assert_eq!(f.category, EXPECTED_CATEGORY);
    assert!(f.advisory_ids.contains(&"CWE-704".to_string()));

    let safe_code = r#"
fn evaluate_dependency(dep: &Dependency) -> Result<VersionStatus, ResolveError> {
    let resolved = lockfile_resolved_version(dep)
        .ok_or(ResolveError::UnresolvedConstraint)?;
    Ok(check_vulnerability(&resolved))
}
"#;
    let safe_findings = BkhSafetyScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-BKH-002"),
        "Lockfile verification must not flag BK-AI-BKH-002"
    );
}

#[test]
fn test_bkh_003_healer_on_model_belief() {
    let vuln_code = r#"
fn process_candidate(finding: &Finding) {
    if model.believes_exploitable {
        dispatch_to_healer(finding);
    }
}
"#;
    let path = Path::new("src/orchestrator/triage.rs");
    let findings = BkhSafetyScanner::scan_source(path, vuln_code);
    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-BKH-003")
        .expect("Must detect healer dispatch on model belief alone");

    assert_eq!(f.severity, Severity::High);
    assert_eq!(f.detector_id, EXPECTED_DETECTOR);
    assert_eq!(f.category, EXPECTED_CATEGORY);
    assert!(f.advisory_ids.contains(&"CWE-693".to_string()));

    let safe_code = r#"
fn process_candidate(finding: &Finding) {
    if model.believes_exploitable && finding.taint_proof.is_some() {
        verify_ast_flow(finding);
        dispatch_to_healer(finding);
    }
}
"#;
    let safe_findings = BkhSafetyScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-BKH-003"),
        "Deterministic taint proof must not flag BK-AI-BKH-003"
    );
}

#[test]
fn test_bkh_004_run_build_hooks_unconsented() {
    let vuln_code = r#"
fn prepare_ast(repo_path: &Path) {
    Command::new("cargo").arg("build").current_dir(repo_path).status().unwrap();
}
"#;
    let path = Path::new("src/analyzer/prep.rs");
    let findings = BkhSafetyScanner::scan_source(path, vuln_code);
    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-BKH-004")
        .expect("Must detect arbitrary cargo build execution without consent");

    assert_eq!(f.severity, Severity::Critical);
    assert_eq!(f.detector_id, EXPECTED_DETECTOR);
    assert_eq!(f.category, EXPECTED_CATEGORY);
    assert!(f.advisory_ids.contains(&"CWE-829".to_string()));

    let safe_code = r#"
fn prepare_ast(repo_path: &Path, consent: &UserConsent) {
    if prompt_user_consent(consent) {
        sandbox::run_in_container("cargo", &["build"], repo_path);
    }
}
"#;
    let safe_findings = BkhSafetyScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-BKH-004"),
        "User consent and sandbox runner must not flag BK-AI-BKH-004"
    );
}

#[test]
fn test_bkh_005_dast_unscoped_redirect() {
    let vuln_code = r#"
fn configure_dast_client() -> reqwest::Client {
    let follow_redirects_unrestricted = true;
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::custom(|attempt| attempt.follow()))
        .build()
        .unwrap()
}
"#;
    let path = Path::new("src/dast/client.rs");
    let findings = BkhSafetyScanner::scan_source(path, vuln_code);
    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-BKH-005")
        .expect("Must detect DAST following unrestricted redirects");

    assert_eq!(f.severity, Severity::Critical);
    assert_eq!(f.detector_id, EXPECTED_DETECTOR);
    assert_eq!(f.category, EXPECTED_CATEGORY);
    assert!(f.advisory_ids.contains(&"CWE-918".to_string()));

    let safe_code = r#"
fn configure_dast_client(scope: &AllowedScope) -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::custom(move |attempt| {
            if scope.is_in_scope(attempt.url()) {
                attempt.follow()
            } else {
                attempt.stop()
            }
        }))
        .build()
        .unwrap()
}
"#;
    let safe_findings = BkhSafetyScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-BKH-005"),
        "In-scope validated redirection must not flag BK-AI-BKH-005"
    );
}

#[test]
fn test_bkh_006_inherit_secrets() {
    let vuln_code = r#"
fn launch_external_scanner(tool_bin: &str) {
    Command::new(tool_bin)
        .envs(std::env::vars())
        .spawn()
        .expect("failed to spawn");
}
"#;
    let path = Path::new("src/scanner/plugin.rs");
    let findings = BkhSafetyScanner::scan_source(path, vuln_code);
    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-BKH-006")
        .expect("Must detect external scanner inheriting host environment");

    assert_eq!(f.severity, Severity::High);
    assert_eq!(f.detector_id, EXPECTED_DETECTOR);
    assert_eq!(f.category, EXPECTED_CATEGORY);
    assert!(f.advisory_ids.contains(&"CWE-250".to_string()));

    let safe_code = r#"
fn launch_external_scanner(tool_bin: &str) {
    Command::new(tool_bin)
        .env_clear()
        .envs(filtered_env())
        .spawn()
        .expect("failed to spawn");
}
"#;
    let safe_findings = BkhSafetyScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-BKH-006"),
        "Clean isolated environment must not flag BK-AI-BKH-006"
    );
}

#[test]
fn test_bkh_007_report_leaks_creds() {
    let vuln_code = r#"
fn record_finding_evidence(report: &mut Report, token: &str) {
    report.add_evidence("auth_token", token);
}
"#;
    let path = Path::new("src/reporter/evidence.rs");
    let findings = BkhSafetyScanner::scan_source(path, vuln_code);
    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-BKH-007")
        .expect("Must detect security report leaking credentials");

    assert_eq!(f.severity, Severity::High);
    assert_eq!(f.detector_id, EXPECTED_DETECTOR);
    assert_eq!(f.category, EXPECTED_CATEGORY);
    assert!(f.advisory_ids.contains(&"CWE-532".to_string()));

    let safe_code = r#"
fn record_finding_evidence(report: &mut Report, token: &str) {
    let redacted_token = redact(token);
    report.add_evidence("auth_token", &redacted_token);
}
"#;
    let safe_findings = BkhSafetyScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-BKH-007"),
        "Redacted token must not flag BK-AI-BKH-007"
    );
}

#[test]
fn test_bkh_008_basename_match() {
    let vuln_code = r#"
fn locate_patch_target(workspace: &Workspace, path: &Path) -> Option<PathBuf> {
    workspace.find_by_basename(path.file_name().unwrap())
}
"#;
    let path = Path::new("src/healer/locator.rs");
    let findings = BkhSafetyScanner::scan_source(path, vuln_code);
    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-BKH-008")
        .expect("Must detect target file match by basename");

    assert_eq!(f.severity, Severity::High);
    assert_eq!(f.detector_id, EXPECTED_DETECTOR);
    assert_eq!(f.category, EXPECTED_CATEGORY);
    assert!(f.advisory_ids.contains(&"CWE-22".to_string()));

    let safe_code = r#"
fn locate_patch_target(workspace: &Workspace, path: &Path) -> Option<PathBuf> {
    let canonical = path.canonicalize().ok()?;
    if canonical.starts_with(&workspace.root) {
        Some(canonical)
    } else {
        None
    }
}
"#;
    let safe_findings = BkhSafetyScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-BKH-008"),
        "Canonical path resolution must not flag BK-AI-BKH-008"
    );
}

#[test]
fn test_bkh_009_unapproved_mutation() {
    let vuln_code = r#"
fn execute_virtual_patch(target: &Path, patch: &str) {
    let allow_modifications_outside_workspace = true;
    healer.mutate_unrestricted(target, patch);
}
"#;
    let path = Path::new("src/healer/patcher.rs");
    let findings = BkhSafetyScanner::scan_source(path, vuln_code);
    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-BKH-009")
        .expect("Must detect healing allowing unapproved modifications outside workspace");

    assert_eq!(f.severity, Severity::Critical);
    assert_eq!(f.detector_id, EXPECTED_DETECTOR);
    assert_eq!(f.category, EXPECTED_CATEGORY);
    assert!(f.advisory_ids.contains(&"CWE-284".to_string()));

    let safe_code = r#"
fn execute_virtual_patch(workspace_root: &Path, target: &Path, patch: &str) -> std::io::Result<()> {
    let canonical = target.canonicalize()?;
    if canonical.starts_with(workspace_root) {
        std::fs::write(canonical, patch)
    } else {
        Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "Out of bounds"))
    }
}
"#;
    let safe_findings = BkhSafetyScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-BKH-009"),
        "Workspace boundary check must not flag BK-AI-BKH-009"
    );
}

#[test]
fn test_bkh_010_unauthenticated_backup() {
    let vuln_code = r#"
fn snapshot_files(files: Vec<PathBuf>) -> BackupManifest {
    let skip_backup_signature = true;
    BackupManifest::new_unsigned(files)
}
"#;
    let path = Path::new("src/healer/backup.rs");
    let findings = BkhSafetyScanner::scan_source(path, vuln_code);
    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-BKH-010")
        .expect("Must detect unsigned or unverified backup manifest");

    assert_eq!(f.severity, Severity::High);
    assert_eq!(f.detector_id, EXPECTED_DETECTOR);
    assert_eq!(f.category, EXPECTED_CATEGORY);
    assert!(f.advisory_ids.contains(&"CWE-345".to_string()));

    let safe_code = r#"
fn snapshot_files(files: Vec<PathBuf>, key: &SigningKey) -> BackupManifest {
    let sig = ed25519::sign(&files, key);
    test_restore(&files).expect("Restore verification failed");
    BackupManifest {
        files,
        timestamp: 123456,
        signature: Some(sig),
    }
}
"#;
    let safe_findings = BkhSafetyScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-BKH-010"),
        "Ed25519 signed backup must not flag BK-AI-BKH-010"
    );
}

#[test]
fn test_bkh_011_no_batch_rollback() {
    let vuln_code = r#"
fn apply_batch_fixes(config: &FixConfig) {
    let disable_atomic_batch_rollback = true;
    execute_fixes();
}
"#;
    let path = Path::new("src/healer/batch.rs");
    let findings = BkhSafetyScanner::scan_source(path, vuln_code);
    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-BKH-011")
        .expect("Must detect batch healing with disabled rollback");

    assert_eq!(f.severity, Severity::High);
    assert_eq!(f.detector_id, EXPECTED_DETECTOR);
    assert_eq!(f.category, EXPECTED_CATEGORY);
    assert!(f.advisory_ids.contains(&"CWE-693".to_string()));

    let safe_code = r#"
fn apply_batch_fixes(manifest: &Manifest) -> Result<RollbackReceipt, Error> {
    let mut tx = TransactionalPatch::begin()?;
    if let Err(e) = tx.apply_all() {
        tx.rollback()?;
        return Err(e);
    }
    tx.commit()
}
"#;
    let safe_findings = BkhSafetyScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-BKH-011"),
        "Transactional rollback must not flag BK-AI-BKH-011"
    );
}

#[test]
fn test_bkh_012_merge_without_tests() {
    let vuln_code = r#"
fn publish_remediation_branch() {
    let _cmd = format!("git push origin main --no-verify");
}
"#;
    let path = Path::new("src/healer/vcs.rs");
    let findings = BkhSafetyScanner::scan_source(path, vuln_code);
    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-BKH-012")
        .expect("Must detect git push with --no-verify");

    assert_eq!(f.severity, Severity::Critical);
    assert_eq!(f.detector_id, EXPECTED_DETECTOR);
    assert_eq!(f.category, EXPECTED_CATEGORY);
    assert!(f.advisory_ids.contains(&"CWE-693".to_string()));

    let safe_code = r#"
fn publish_remediation_branch(test_results: &TestResults) -> Result<(), Error> {
    if !test_results.all_passed() {
        return Err(Error::VerificationFailed);
    }
    run_git_cmd(&["git", "push", "origin", "main"]);
    Ok(())
}
"#;
    let safe_findings = BkhSafetyScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-BKH-012"),
        "Test verification guard must not flag BK-AI-BKH-012"
    );
}

#[test]
fn test_bkh_013_unbounded_suppression() {
    let vuln_code = r#"
fn configure_filter() -> SuppressRule {
    SuppressRule {
        rule_id: "*".to_string(),
        expires_at: None,
    }
}
"#;
    let path = Path::new("src/scanner/suppress.rs");
    let findings = BkhSafetyScanner::scan_source(path, vuln_code);
    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-BKH-013")
        .expect("Must detect unbounded suppression without expiration");

    assert_eq!(f.severity, Severity::Medium);
    assert_eq!(f.detector_id, EXPECTED_DETECTOR);
    assert_eq!(f.category, EXPECTED_CATEGORY);
    assert!(f.advisory_ids.contains(&"CWE-1059".to_string()));

    let safe_code = r#"
fn configure_filter() -> SuppressRule {
    SuppressRule {
        rule_id: "BK-AI-SQL-001".to_string(),
        expires_at: Some("2026-12-31"),
    }
}
"#;
    let safe_findings = BkhSafetyScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-BKH-013"),
        "Expiring specific rule suppression must not flag BK-AI-BKH-013"
    );
}

#[test]
fn test_bkh_014_regex_taint_claim() {
    let vuln_code = r#"
fn analyze_line(line: &str, finding: &mut Finding) {
    let claim_reachability_from_regex_only = true;
    if regex.is_match(line) {
        finding.reachability = Reachability::Reachable;
    }
}
"#;
    let path = Path::new("src/scanner/taint.rs");
    let findings = BkhSafetyScanner::scan_source(path, vuln_code);
    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-BKH-014")
        .expect("Must detect reachability claimed from regex alone");

    assert_eq!(f.severity, Severity::High);
    assert_eq!(f.detector_id, EXPECTED_DETECTOR);
    assert_eq!(f.category, EXPECTED_CATEGORY);
    assert!(f.advisory_ids.contains(&"CWE-1059".to_string()));

    let safe_code = r#"
fn analyze_line(line: &str, finding: &mut Finding, ast: &AstGraph) {
    if regex.is_match(line) {
        finding.reachability = Reachability::PotentiallyReachable;
        if let Some(_trace) = ast.dfg_trace(line) {
            finding.reachability = Reachability::Reachable;
        }
    }
}
"#;
    let safe_findings = BkhSafetyScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-BKH-014"),
        "Data-flow verification must not flag BK-AI-BKH-014"
    );
}

#[test]
fn test_bkh_015_ci_skips_services() {
    let vuln_code = r#"
jobs:
  test:
    name: CI Test Suite
    skip_go_services: true
    steps:
      - run: cargo test
"#;
    let path = Path::new(".github/workflows/ci.yml");
    let findings = BkhSafetyScanner::scan_source(path, vuln_code);
    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-BKH-015")
        .expect("Must detect CI configuration skipping Go services");

    assert_eq!(f.severity, Severity::Medium);
    assert_eq!(f.detector_id, EXPECTED_DETECTOR);
    assert_eq!(f.category, EXPECTED_CATEGORY);
    assert!(f.advisory_ids.contains(&"CWE-1059".to_string()));

    let safe_code = r#"
jobs:
  test:
    name: Full Matrix CI
    steps:
      - run: cargo test --workspace
      - run: cd services/orchestrator && go test ./...
      - run: cd services/healer && go test ./...
"#;
    let safe_findings = BkhSafetyScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-BKH-015"),
        "Full test coverage for Go services must not flag BK-AI-BKH-015"
    );
}

#[test]
fn test_bkh_016_unauthorized_unrated_scan() {
    let vuln_code = r#"
fn start_dast_job(host: &str) {
    let bypass_asset_authorization = true;
    scan_remote_target(host, auth_token: None);
}
"#;
    let path = Path::new("src/dast/job.rs");
    let findings = BkhSafetyScanner::scan_source(path, vuln_code);
    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-BKH-016")
        .expect("Must detect remote scan bypassing asset authorization");

    assert_eq!(f.severity, Severity::High);
    assert_eq!(f.detector_id, EXPECTED_DETECTOR);
    assert_eq!(f.category, EXPECTED_CATEGORY);
    assert!(f.advisory_ids.contains(&"CWE-770".to_string()));

    let safe_code = r#"
fn start_dast_job(host: &str, token: &str, limiter: &RateLimiter) -> Result<(), ScanError> {
    verify_asset_ownership(host, token)?;
    limiter.rate_limit_rps(50);
    scan_remote_target_authorized(host, token)
}
"#;
    let safe_findings = BkhSafetyScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-BKH-016"),
        "Asset authorization check and rate limiter must not flag BK-AI-BKH-016"
    );
}

#[test]
fn test_bkh_017_racing_healers() {
    let vuln_code = r#"
fn update_shared_config() {
    let disable_manifest_file_lock = true;
    mutate_manifest_file("shared_manifest.json");
}
"#;
    let path = Path::new("src/healer/sync.rs");
    let findings = BkhSafetyScanner::scan_source(path, vuln_code);
    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-BKH-017")
        .expect("Must detect parallel healers disabling manifest file lock");

    assert_eq!(f.severity, Severity::High);
    assert_eq!(f.detector_id, EXPECTED_DETECTOR);
    assert_eq!(f.category, EXPECTED_CATEGORY);
    assert!(f.advisory_ids.contains(&"CWE-362".to_string()));

    let safe_code = r#"
fn update_shared_config(lock: &Mutex<()>) {
    let _guard = lock.lock().unwrap();
    let mut file = FileLock::acquire_lock("shared_manifest.json").unwrap();
    mutate_manifest_file(&mut file);
}
"#;
    let safe_findings = BkhSafetyScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-BKH-017"),
        "Acquired FileLock and Mutex must not flag BK-AI-BKH-017"
    );
}

#[test]
fn test_bkh_018_unverified_claim() {
    let vuln_code = r#"
## Supported Features
- Rule BK-AI-BKH-099: status: "Production Ready" # TODO: not implemented, stub
"#;
    let path = Path::new("README.md");
    let findings = BkhSafetyScanner::scan_source(path, vuln_code);
    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-BKH-018")
        .expect("Must detect unverified support claim for stub check");

    assert_eq!(f.severity, Severity::Medium);
    assert_eq!(f.detector_id, EXPECTED_DETECTOR);
    assert_eq!(f.category, EXPECTED_CATEGORY);
    assert!(f.advisory_ids.contains(&"CWE-1059".to_string()));

    let safe_code = r#"
## Planned Features
- Rule BK-AI-BKH-099: status: "Planned" (detector in active design)
"#;
    let safe_findings = BkhSafetyScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-BKH-018"),
        "Marking check status as planned must not flag BK-AI-BKH-018"
    );
}
