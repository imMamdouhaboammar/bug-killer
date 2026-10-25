use bug_killer::healer::AutopilotHealer;
use bug_killer::healer::approval::ApprovalManager;
use bug_killer::healer::rollback::RollbackManager;
use bug_killer::scanner::FleetScanner;
use bug_killer::types::*;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_m6_plan_checksum_determinism_and_tamper_detection() {
    let action1 = PatchAction {
        action_type: PatchActionType::PackageManifestVersionBump,
        target_file: std::path::PathBuf::from("package.json"),
        original_checksum: "abc123456789".into(),
        replacement_content: "{\"name\": \"app\", \"dependencies\": {\"express\": \"4.19.2\"}}"
            .into(),
        diff_description: "Bump express".into(),
    };

    let actions = vec![action1.clone()];
    let hash1 = ApprovalManager::compute_plan_checksum(&actions);
    let hash2 = ApprovalManager::compute_plan_checksum(&actions);

    assert_eq!(hash1, hash2, "Checksum must be strictly deterministic");
    assert_eq!(hash1.len(), 64);

    // Tampered replacement content
    let mut tampered_action = action1.clone();
    tampered_action.replacement_content = "{\"name\": \"hacked\"}".into();
    let tampered_hash = ApprovalManager::compute_plan_checksum(&[tampered_action]);
    assert_ne!(hash1, tampered_hash);
}

#[test]
fn test_m6_operator_approval_receipt_verification_and_expiry() {
    let dir = tempdir().unwrap();
    let plan_id = "plan-cve-2026-express";
    let plan_checksum = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    let approver = "secops-lead@company.internal";

    // 1. Create valid approval receipt
    let receipt = ApprovalManager::create_approval_receipt(
        dir.path(),
        plan_id,
        plan_checksum,
        approver,
        60, // 60 mins validity
    )
    .expect("Failed to create receipt");

    assert_eq!(receipt.plan_id, plan_id);
    assert_eq!(receipt.approver, approver);
    assert!(!receipt.signature.is_empty());

    // 2. Successful verification
    let verify_res = ApprovalManager::verify_approval_receipt(dir.path(), &receipt, plan_checksum);
    assert!(
        verify_res.is_ok(),
        "Valid receipt should pass verification: {:?}",
        verify_res.err()
    );

    // 3. Plan checksum mismatch (tampered plan) fails closed
    let mismatch_res = ApprovalManager::verify_approval_receipt(
        dir.path(),
        &receipt,
        "1111111111111111111111111111111111111111111111111111111111111111",
    );
    assert!(mismatch_res.is_err());
    assert!(mismatch_res.unwrap_err().contains("Integrity Mismatch"));

    // 4. Expired receipt fails closed
    let mut expired_receipt = receipt.clone();
    expired_receipt.valid_until = "2020-01-01T00:00:00+00:00".into();
    let expired_res =
        ApprovalManager::verify_approval_receipt(dir.path(), &expired_receipt, plan_checksum);
    assert!(expired_res.is_err());
    assert!(expired_res.unwrap_err().contains("Approval Expired"));

    // 5. Tampered signature fails closed
    let mut forged_receipt = receipt;
    forged_receipt.signature = "0".repeat(128);
    let forged_res =
        ApprovalManager::verify_approval_receipt(dir.path(), &forged_receipt, plan_checksum);
    assert!(forged_res.is_err());
    assert!(forged_res.unwrap_err().contains("Verification Failed"));
}

#[test]
fn test_m6_end_to_end_supervised_l4_incident_drill() {
    let dir = tempdir().unwrap();
    let pkg_path = dir.path().join("package.json");

    // Phase 1: Discovered asset inventory with vulnerable express and node engine
    let original_content = r#"{
  "name": "incident-drill-app",
  "version": "1.0.0",
  "engines": {
    "node": "20.10.0"
  },
  "dependencies": {
    "express": "4.17.1"
  }
}"#;
    fs::write(&pkg_path, original_content).unwrap();

    // Phase 2: Vulnerability scan detects confirmed affected finding
    let scan1 = FleetScanner::scan_directory(dir.path(), false);
    assert!(
        scan1
            .findings
            .iter()
            .any(|f| matches!(f.cve, CveId::Node2ShellBrotli(_)) && f.severity == Severity::High)
    );

    // Phase 3: Prospective plan formulated without disk mutation
    let plan = AutopilotHealer::plan_healing(&scan1);
    assert!(!plan.is_empty());
    assert_eq!(
        fs::read_to_string(&pkg_path).unwrap(),
        original_content,
        "File must be untouched during plan phase"
    );

    // Phase 4: Compute plan checksum and issue operator approval receipt
    let plan_checksum = ApprovalManager::compute_plan_checksum(&plan);
    let plan_id = "incident-drill-plan-001";
    let receipt = ApprovalManager::create_approval_receipt(
        dir.path(),
        plan_id,
        &plan_checksum,
        "ciso@enterprise.corp",
        30,
    )
    .expect("Failed to issue receipt");

    // Phase 5: Supervised execution with post-verification
    let (manifest, count) =
        ApprovalManager::execute_supervised_healing(dir.path(), &receipt, &plan)
            .expect("Supervised healing failed");

    assert_eq!(count, 1);
    assert!(!manifest.backup_id.is_empty());

    // Content should now be updated to safe version
    let updated_content = fs::read_to_string(&pkg_path).unwrap();
    assert!(updated_content.contains(">=22.23.4"));

    // Phase 6: Post-execution independent scan confirms manifest vulnerability is resolved
    let scan2 = FleetScanner::scan_directory(dir.path(), false);
    assert!(
        !scan2
            .findings
            .iter()
            .any(|f| f.target_kind == TargetKind::NodePackageManifest
                && f.severity == Severity::High),
        "High vulnerability in package manifest must be resolved"
    );

    // Phase 7: Cryptographic non-repudiation rollback drill
    let rollback_count =
        RollbackManager::rollback(dir.path(), &manifest.backup_id).expect("Rollback drill failed");
    assert_eq!(rollback_count, 1);

    // File restored to exact original bitwise state
    let restored_content = fs::read_to_string(&pkg_path).unwrap();
    assert_eq!(restored_content, original_content);
}

#[test]
fn test_m6_fault_injection_post_verification_triggers_automatic_rollback() {
    let dir = tempdir().unwrap();
    let pkg_path = dir.path().join("package.json");

    let original_content = r#"{
  "name": "fault-injection-app",
  "version": "1.0.0",
  "engines": {
    "node": "20.10.0"
  }
}"#;
    fs::write(&pkg_path, original_content).unwrap();

    // Fabricate a flawed patch action that writes another vulnerable version instead of fixing
    let pkg_sha256 = bug_killer::healer::backup::BackupManager::compute_sha256(&pkg_path).unwrap();
    let flawed_action = PatchAction {
        action_type: PatchActionType::PackageManifestVersionBump,
        target_file: pkg_path.clone(),
        original_checksum: pkg_sha256,
        replacement_content: r#"{
  "name": "fault-injection-app",
  "version": "1.0.0",
  "engines": {
    "node": "20.9.0"
  }
}"#
        .into(),
        diff_description: "Flawed upgrade to older vulnerable version".into(),
    };

    let actions = vec![flawed_action];
    let plan_checksum = ApprovalManager::compute_plan_checksum(&actions);
    let receipt = ApprovalManager::create_approval_receipt(
        dir.path(),
        "flawed-plan",
        &plan_checksum,
        "operator@test.local",
        15,
    )
    .unwrap();

    // Execute supervised healing: should catch unresolved critical finding in post-scan and roll back!
    let exec_res = ApprovalManager::execute_supervised_healing(dir.path(), &receipt, &actions);

    assert!(
        exec_res.is_err(),
        "Flawed patch must fail post-execution verification"
    );
    let err = exec_res.err().unwrap();
    assert!(
        err.contains("Automatic rollback triggered"),
        "Expected automatic rollback trigger, got: {}",
        err
    );

    // Verify disk was rolled back to original content
    let content_after = fs::read_to_string(&pkg_path).unwrap();
    assert_eq!(
        content_after, original_content,
        "Target file must be restored to original state after failed post-verification"
    );
}
