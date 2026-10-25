use bug_killer::detectors::{DetectorRegistry, ScanContext, SecretDetector, SecurityDetector};
use bug_killer::healer::AutopilotHealer;
use bug_killer::healer::approval::ApprovalManager;
use bug_killer::healer::backup::BackupManager;
use bug_killer::healer::rollback::RollbackManager;
use bug_killer::identity::OperatorIdentity;
use bug_killer::rules::{DetectionMatcher, RuleEngine, RuleProvenance, VulnerabilityRule};
use bug_killer::scanner::FleetScanner;
use bug_killer::types::{
    CoverageStatus, ParserFailure, PatchAction, PatchActionType, ScanProfile, Severity, TargetKind,
};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::tempdir;

#[test]
fn corrupted_nonce_ledger_must_not_authorize_healing() {
    let workspace = tempdir().unwrap();
    let root = workspace.path();
    let operator = OperatorIdentity::get_or_create(root).unwrap();
    let receipt = ApprovalManager::create_approval_receipt_with_operator(
        &operator,
        root,
        "plan",
        "hash",
        "owner",
        5,
        "PrivilegedRemediation",
    )
    .unwrap();
    let nonce_dir = root.join(".bug-killer/approvals");
    fs::create_dir_all(&nonce_dir).unwrap();
    fs::write(nonce_dir.join("used_nonces.json"), "{invalid-json").unwrap();

    assert!(
        ApprovalManager::verify_approval_receipt_with_trusted_keys(
            root,
            &receipt,
            "hash",
            &[operator.public_key_hex()],
        )
        .is_err()
    );
}

#[test]
fn legacy_backup_without_post_hash_must_not_overwrite_modified_content() {
    let workspace = tempdir().unwrap();
    let root = workspace.path();
    let target = root.join("user-edited.txt");
    fs::write(&target, "original").unwrap();
    let backup = BackupManager::create_backup(root, std::slice::from_ref(&target)).unwrap();
    assert!(backup.records[0].post_heal_sha256.is_none());
    fs::write(&target, "user's new edit").unwrap();

    let refused = RollbackManager::rollback(root, &backup.backup_id);
    assert!(
        refused.is_err(),
        "rollback must fail closed on unknown drift"
    );
    assert_eq!(fs::read_to_string(&target).unwrap(), "user's new edit");
}

#[test]
fn workspace_operator_key_must_not_establish_its_own_trust() {
    let workspace = tempdir().unwrap();
    let root = workspace.path();
    let operator = OperatorIdentity::get_or_create(root).unwrap();
    let receipt = ApprovalManager::create_approval_receipt_with_operator(
        &operator,
        root,
        "plan",
        "hash",
        "owner",
        5,
        "PrivilegedRemediation",
    )
    .unwrap();
    assert!(
        ApprovalManager::verify_approval_receipt(root, &receipt, "hash").is_err(),
        "a workspace-created signing key is not a trusted operator authority"
    );
}

#[test]
fn receipt_verification_must_not_create_operator_keys() {
    let workspace = tempdir().unwrap();
    let root = workspace.path();
    let operator = OperatorIdentity::from_bytes(&[7; 32]);
    let receipt = ApprovalManager::create_approval_receipt_with_operator(
        &operator,
        root,
        "plan",
        "hash",
        "owner",
        5,
        "PrivilegedRemediation",
    )
    .unwrap();
    let _ = ApprovalManager::verify_approval_receipt(root, &receipt, "hash");
    assert!(!root.join(".aegis/operator_identity.key").exists());
}

#[test]
fn cli_heal_apply_must_require_independent_operator_approval() {
    let workspace = tempdir().unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bug-killer"))
        .args(["heal", workspace.path().to_str().unwrap(), "--apply"])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "heal --apply must not bypass approval"
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("approval"));
}

#[test]
fn approval_payload_must_unambiguously_frame_each_field() {
    let a = ApprovalManager::compute_receipt_payload(
        "a:b", "c", "/repo", "owner", "risk", "expiry", "nonce",
    );
    let b = ApprovalManager::compute_receipt_payload(
        "a", "b:c", "/repo", "owner", "risk", "expiry", "nonce",
    );
    assert_ne!(
        a, b,
        "distinct approval tuples must never have the same signed bytes"
    );
}

#[test]
fn cli_supervised_approval_requires_external_pinned_public_key() {
    let workspace = tempdir().unwrap();
    let external_config = tempdir().unwrap();
    let cfg = external_config.path().join("bug-killer");
    fs::create_dir_all(&cfg).unwrap();
    let operator = OperatorIdentity::from_bytes(&[27u8; 32]);
    fs::write(cfg.join("operator_identity.key"), [27u8; 32]).unwrap();
    fs::write(
        workspace.path().join("package.json"),
        r#"{"name":"approval-fixture","engines":{"node":"20.10.0"},"dependencies":{"express":"4.17.1"}}"#,
    )
    .unwrap();

    let binary = env!("CARGO_BIN_EXE_bug-killer");
    let public_key = std::process::Command::new(binary)
        .arg("operator-public-key")
        .env("XDG_CONFIG_HOME", external_config.path())
        .output()
        .unwrap();
    assert!(public_key.status.success());
    assert_eq!(
        String::from_utf8_lossy(&public_key.stdout).trim(),
        operator.public_key_hex()
    );

    let approve = std::process::Command::new(binary)
        .args([
            "approve",
            "all",
            workspace.path().to_str().unwrap(),
            "--json",
        ])
        .env("XDG_CONFIG_HOME", external_config.path())
        .output()
        .unwrap();
    assert!(
        approve.status.success(),
        "{}",
        String::from_utf8_lossy(&approve.stderr)
    );

    let apply = || {
        std::process::Command::new(binary)
            .args(["apply", "all", workspace.path().to_str().unwrap()])
            .env("XDG_CONFIG_HOME", external_config.path())
            .output()
            .unwrap()
    };
    let denied = apply();
    assert!(
        !denied.status.success(),
        "unpinned signer must not authorize writes"
    );

    fs::write(
        cfg.join("trusted_operator_keys.json"),
        serde_json::to_vec(&vec![operator.public_key_hex()]).unwrap(),
    )
    .unwrap();
    let authorized = apply();
    assert!(
        authorized.status.success(),
        "{}",
        String::from_utf8_lossy(&authorized.stderr)
    );
    let fixed = fs::read_to_string(workspace.path().join("package.json")).unwrap();
    assert!(
        fixed.contains(">=22.23.4"),
        "approved plan must reach the target"
    );
}

#[test]
fn healing_relative_target_has_restorable_canonical_backup() {
    let workspace = tempdir().unwrap();
    let root = workspace.path();
    let target = root.join("relative-target.txt");
    fs::write(&target, "original").unwrap();
    let action = PatchAction {
        target_file: PathBuf::from("relative-target.txt"),
        original_checksum: BackupManager::compute_sha256(&target).unwrap(),
        replacement_content: "changed".into(),
        action_type: PatchActionType::GenericReplace,
        diff_description: "Test relative target".into(),
    };
    let (manifest, applied) = AutopilotHealer::execute_healing(root, &[action]).unwrap();
    assert_eq!(applied, 1);
    assert_eq!(
        manifest.records.len(),
        1,
        "preflighted target must be backed up"
    );
    assert_eq!(fs::read_to_string(&target).unwrap(), "changed");
    assert_eq!(
        RollbackManager::rollback(root, &manifest.backup_id).unwrap(),
        1
    );
    assert_eq!(fs::read_to_string(&target).unwrap(), "original");
}

#[test]
fn id_only_pinning_must_not_authorize_workspace_remediation() {
    let workspace = tempdir().unwrap();
    let root = workspace.path();
    fs::create_dir_all(root.join("rules")).unwrap();
    fs::create_dir_all(root.join(".bug-killer")).unwrap();
    let rule = VulnerabilityRule {
        id: "RULE-1".into(),
        title: "test".into(),
        severity: Severity::Medium,
        description: "untrusted".into(),
        target_kind: TargetKind::GenericSourceFile,
        file_patterns: vec![],
        detection: DetectionMatcher::StringContains {
            search: "bad".into(),
            except_if_contains: None,
        },
        remediation: None,
        provenance: RuleProvenance::OperatorApproved,
        trusted: true,
    };
    fs::write(
        root.join("rules/rule.json"),
        serde_json::to_vec(&rule).unwrap(),
    )
    .unwrap();
    fs::write(root.join(".bug-killer/trusted_rules.json"), r#"["RULE-1"]"#).unwrap();

    let loaded = RuleEngine::load_rules(None, root);
    assert_eq!(loaded.len(), 1);
    assert!(
        !loaded[0].is_trusted(),
        "ID-only pins must never confer trust"
    );
}

#[test]
fn manifest_discovery_must_cover_nested_packages() {
    let workspace = tempdir().unwrap();
    let nested = workspace.path().join("a/b/c/d/e/f");
    fs::create_dir_all(&nested).unwrap();
    fs::write(nested.join("package.json"), "{}").unwrap();
    let registry = DetectorRegistry::new();
    assert!(
        registry
            .try_workspace_has_package_manifests(workspace.path())
            .unwrap()
    );
    assert!(registry.workspace_has_package_manifests(workspace.path()));
}

#[test]
fn secret_detector_must_not_claim_complete_when_file_parse_failed() {
    let workspace = tempdir().unwrap();
    let mut report = FleetScanner::scan_directory(workspace.path(), false);
    report.coverage.coverage_status = CoverageStatus::Partial;
    report.coverage.parser_failures.push(ParserFailure {
        path: workspace.path().join("unreadable.env"),
        reason: "permission denied".into(),
    });
    assert!(!report.coverage.is_complete());
    let result = SecretDetector.run(&ScanContext {
        root: workspace.path().to_path_buf(),
        profile: ScanProfile::Project,
        changed_files: None,
        enable_network_osv: false,
        cached_report: Some(Arc::new(report)),
    });
    assert_ne!(result.receipt.status, CoverageStatus::Complete);
    assert!(!result.receipt.errors.is_empty());
}
