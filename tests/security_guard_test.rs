use bug_killer::healer::backup::BackupManager;
use bug_killer::healer::rollback::RollbackManager;
use bug_killer::security_guard::SecurityGuard;
use bug_killer::security_guard::config::{ConfigManager, RemediationLevel};
use bug_killer::security_guard::remediation::FixProposal;
use bug_killer::types::*;
use std::fs;
use tempfile::tempdir;

#[test]
fn guarded_fix_respects_separate_project_policy() {
    let dir = tempdir().unwrap();
    let root = dir.path();
    SecurityGuard::init(root, false).unwrap();
    let mut config = ConfigManager::load_config(root);
    config.remediation_level = RemediationLevel::GuardedLocalFix;
    ConfigManager::save_config(root, &config).unwrap();
    let target = root.join("Dockerfile");
    fs::write(&target, "FROM node:20-alpine\nUSER root\n").unwrap();
    let report = SecurityGuard::scan(root, ScanProfile::Quick, false, false);
    let finding = report
        .findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-INF-003")
        .unwrap();
    let proposal = SecurityGuard::plan_fix(&finding.id, root).unwrap();
    assert!(SecurityGuard::apply_fix(&proposal, root, None).is_err());
    assert_eq!(
        fs::read_to_string(&target).unwrap(),
        "FROM node:20-alpine\nUSER root\n"
    );
}

#[test]
fn unsupported_image_and_non_js_secret_fixes_are_advisory_only() {
    let dir = tempdir().unwrap();
    let root = dir.path();
    fs::write(root.join("Dockerfile"), "FROM alpine:3.18\nUSER root\n").unwrap();
    fs::write(root.join("settings.py"), "token = 'AKIA1234567890ABCDEF'\n").unwrap();
    let report = SecurityGuard::scan(root, ScanProfile::Quick, false, false);
    for rule in ["BK-AI-INF-003", "BK-AI-SEC-001"] {
        let finding = report
            .findings
            .iter()
            .find(|f| f.cve.as_str() == rule)
            .unwrap();
        let proposal = SecurityGuard::plan_fix(&finding.id, root).unwrap();
        assert_eq!(proposal.required_level, RemediationLevel::Propose);
        assert!(proposal.replacement_content.is_empty());
    }
}

#[test]
fn changed_files_include_unstaged_modifications() {
    use std::process::Command;
    let dir = tempdir().unwrap();
    let root = dir.path();
    if Command::new("git")
        .args(["init", "-q"])
        .current_dir(root)
        .status()
        .is_err()
    {
        return;
    }
    fs::write(root.join("file.js"), "const safe = true;\n").unwrap();
    assert!(
        Command::new("git")
            .args(["add", "file.js"])
            .current_dir(root)
            .status()
            .unwrap()
            .success()
    );
    fs::write(root.join("file.js"), "const safe = false;\n").unwrap();
    let changed = SecurityGuard::discover_changed_files(root).unwrap();
    assert!(changed.contains(&root.join("file.js")));
}

#[test]
fn rollback_validates_every_record_before_restoring_any_file() {
    let dir = tempdir().unwrap();
    let root = dir.path();
    let a = root.join("a.txt");
    let b = root.join("b.txt");
    fs::write(&a, "original a").unwrap();
    fs::write(&b, "original b").unwrap();
    let backup = BackupManager::create_backup(root, &[a.clone(), b.clone()]).unwrap();
    fs::write(&a, "edited a").unwrap();
    fs::write(&b, "edited b").unwrap();
    let second = root
        .join(".aegis/backups")
        .join(&backup.backup_id)
        .join(&backup.records[1].backup_file_name);
    fs::write(second, "tampered").unwrap();
    assert!(RollbackManager::rollback(root, &backup.backup_id).is_err());
    assert_eq!(fs::read_to_string(&a).unwrap(), "edited a");
    assert_eq!(fs::read_to_string(&b).unwrap(), "edited b");
}

#[test]
fn json_security_scan_retains_failure_exit_status() {
    use std::process::Command;
    let dir = tempdir().unwrap();
    fs::write(
        dir.path().join("Dockerfile"),
        "FROM alpine:3.18\nUSER root\n",
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_bug-killer"))
        .args([
            "security",
            "scan",
            dir.path().to_str().unwrap(),
            "--fail-on",
            "high",
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| finding["severity"] == "High")
    );
}

#[test]
fn test_project_initialization_is_idempotent_and_preserves_config() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    // 1. Initial project init
    let receipt1 = SecurityGuard::init(root, false).expect("Init should succeed");
    assert!(receipt1.initialized);
    assert!(ConfigManager::is_initialized(root));
    assert!(ConfigManager::config_path(root).exists());
    assert!(ConfigManager::policy_path(root).exists());
    assert!(ConfigManager::baseline_path(root).exists());

    // Modify config with custom remediation level
    let mut config = ConfigManager::load_config(root);
    config.remediation_level = RemediationLevel::GuardedLocalFix;
    ConfigManager::save_config(root, &config).expect("Save config");

    // 2. Second init must be idempotent and preserve custom remediation level
    let receipt2 = SecurityGuard::init(root, false).expect("Second init should succeed");
    assert!(receipt2.initialized);

    let reloaded_config = ConfigManager::load_config(root);
    assert_eq!(
        reloaded_config.remediation_level,
        RemediationLevel::GuardedLocalFix,
        "Idempotent init must preserve user configuration"
    );
}

#[test]
fn test_security_status_and_baseline() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    // Before init
    let status_before = SecurityGuard::status(root);
    assert!(!status_before.is_initialized);

    // After init
    SecurityGuard::init(root, false).unwrap();
    let status_after = SecurityGuard::status(root);
    assert!(status_after.is_initialized);
    assert!(status_after.agent_identity_configured);
}

#[test]
fn test_finding_explanation_catalog_grounding() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    // Write a file with hardcoded secret
    let code = "const key = 'AKIA1234567890ABCDEF';\n";
    fs::write(root.join("test.js"), code).unwrap();

    let report = SecurityGuard::scan(root, ScanProfile::Quick, false, false);
    assert!(!report.findings.is_empty());
    let finding = &report.findings[0];

    let explanation = SecurityGuard::explain(&finding.id, root)
        .expect("Finding explanation should resolve from catalog");

    assert_eq!(explanation.rule_id, "BK-AI-SEC-001");
    assert!(!explanation.remediation_guidance.is_empty());
    assert!(!explanation.verification_requirements.is_empty());
}

#[test]
fn test_guarded_local_fix_and_independent_verification() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    // 1. Initialize project with GuardedLocalFix policy
    SecurityGuard::init(root, false).unwrap();
    let mut config = ConfigManager::load_config(root);
    config.remediation_level = RemediationLevel::GuardedLocalFix;
    ConfigManager::save_config(root, &config).unwrap();

    let mut policy = ConfigManager::load_policy(root);
    policy.allow_guarded_local_fix = true;
    ConfigManager::save_policy(root, &policy).unwrap();

    // 2. Create vulnerable Dockerfile (BK-AI-INF-003: running as root)
    let dockerfile_path = root.join("Dockerfile");
    let vuln_dockerfile = "FROM node:20-alpine\nWORKDIR /app\nUSER root\nCOPY . .\n";
    fs::write(&dockerfile_path, vuln_dockerfile).unwrap();

    // 3. Scan and identify finding
    let report = SecurityGuard::scan(root, ScanProfile::Quick, false, false);
    let finding = report
        .findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-INF-003")
        .expect("Docker root finding must be detected");

    // 4. Generate prospective fix plan
    let proposal = SecurityGuard::plan_fix(&finding.id, root).expect("Plan fix");
    assert_eq!(proposal.required_level, RemediationLevel::GuardedLocalFix);
    assert!(proposal.replacement_content.contains("USER node"));

    // 5. Apply fix
    let outcome = SecurityGuard::apply_fix(&proposal, root, None).expect("Apply fix");
    assert!(
        outcome.success,
        "Remediation should succeed: {}",
        outcome.message
    );
    assert_eq!(outcome.verification_status, "VERIFIED_CLEAN");
    assert!(outcome.backup_id.is_some());

    // 6. Verify file content on disk has been updated
    let updated_content = fs::read_to_string(&dockerfile_path).unwrap();
    assert!(updated_content.contains("USER node"));
    assert!(!updated_content.contains("USER root"));

    // 7. Re-scan confirms zero findings for Dockerfile
    let post_report = SecurityGuard::scan(root, ScanProfile::Quick, false, false);
    let still_vulnerable = post_report
        .findings
        .iter()
        .any(|f| f.cve.as_str() == "BK-AI-INF-003");
    assert!(!still_vulnerable, "Vulnerability must be eliminated");
}

#[test]
fn test_failed_verification_triggers_automatic_rollback() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    SecurityGuard::init(root, false).unwrap();
    let mut config = ConfigManager::load_config(root);
    config.remediation_level = RemediationLevel::GuardedLocalFix;
    ConfigManager::save_config(root, &config).unwrap();
    let mut policy = ConfigManager::load_policy(root);
    policy.allow_guarded_local_fix = true;
    ConfigManager::save_policy(root, &policy).unwrap();

    let target_file = root.join("test.js");
    let original_content = "const key = 'AKIA1234567890ABCDEF';\n";
    fs::write(&target_file, original_content).unwrap();

    let report = SecurityGuard::scan(root, ScanProfile::Quick, false, false);
    let finding = &report.findings[0];
    let original_sha =
        bug_killer::healer::backup::BackupManager::compute_sha256(&target_file).unwrap();

    // Create a bogus proposal that does NOT remove the vulnerability
    let bogus_proposal = FixProposal {
        finding_id: finding.id.clone(),
        rule_id: finding.cve.as_str().to_string(),
        target_file: target_file.clone(),
        original_sha256: original_sha.clone(),
        replacement_content: "const key = 'AKIA1234567890ABCDEF'; // still vulnerable\n"
            .to_string(),
        diff_preview: "fake patch".to_string(),
        explanation: "fake explanation".to_string(),
        required_level: RemediationLevel::GuardedLocalFix,
    };

    let outcome = SecurityGuard::apply_fix(&bogus_proposal, root, None).unwrap();
    assert!(!outcome.success, "Remediation must fail verification");
    assert_eq!(outcome.verification_status, "VERIFICATION_FAILED");

    // Verify automatic rollback restored original content
    let restored_content = fs::read_to_string(&target_file).unwrap();
    assert_eq!(restored_content, original_content);
}

#[test]
fn test_pre_generation_guidance_for_auth_and_upload() {
    let auth_guidance =
        SecurityGuard::guidance("Implement JWT login and session refresh", "typescript");
    assert!(!auth_guidance.relevant_rules.is_empty());
    assert!(
        auth_guidance
            .relevant_rules
            .iter()
            .any(|r| r.rule_id == "BK-AI-AUT-001" || r.rule_id == "BK-AI-AUT-011")
    );
    assert!(!auth_guidance.recommended_safe_patterns.is_empty());
    assert!(!auth_guidance.banned_anti_patterns.is_empty());

    let upload_guidance =
        SecurityGuard::guidance("Create image file upload and unzip handler", "python");
    assert!(
        upload_guidance
            .relevant_rules
            .iter()
            .any(|r| r.rule_id == "BK-AI-FIL-001" || r.rule_id == "BK-AI-FIL-002")
    );
}
