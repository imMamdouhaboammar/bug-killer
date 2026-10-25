use bug_killer::detectors::{DetectorRegistry, ScanContext, SecretDetector, SecurityDetector};
use bug_killer::healer::AutopilotHealer;
use bug_killer::healer::approval::ApprovalManager;
use bug_killer::healer::backup::BackupManager;
use bug_killer::healer::rollback::RollbackManager;
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
    let receipt =
        ApprovalManager::create_approval_receipt(root, "plan", "hash", "owner", 5).unwrap();
    let nonce_dir = root.join(".bug-killer/approvals");
    fs::create_dir_all(&nonce_dir).unwrap();
    fs::write(nonce_dir.join("used_nonces.json"), "{invalid-json").unwrap();

    assert!(ApprovalManager::verify_approval_receipt(root, &receipt, "hash").is_err());
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
