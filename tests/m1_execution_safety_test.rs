use bug_killer::healer::AutopilotHealer;
use bug_killer::healer::rollback::RollbackManager;
use bug_killer::identity::AgentIdentity;
use bug_killer::types::{BackupManifest, BackupRecord, PatchAction, PatchActionType};
use std::fs;
use tempfile::tempdir;

#[test]
fn test_m1_untrusted_signer_fails_closed() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    // 1. Initialize legitimate local agent identity
    let _trusted_identity = AgentIdentity::get_or_create(root).unwrap();

    // 2. Attacker generates separate rogue identity key
    let rogue_dir = tempdir().unwrap();
    let rogue_identity = AgentIdentity::get_or_create(rogue_dir.path()).unwrap();

    let backup_dir = root.join(".aegis").join("backups").join("rogue_backup_001");
    fs::create_dir_all(&backup_dir).unwrap();

    let dummy_target = root.join("test.txt");
    fs::write(&dummy_target, "original").unwrap();

    let backup_file = backup_dir.join("0_test.txt");
    fs::write(&backup_file, "original").unwrap();

    let mut rogue_manifest = BackupManifest {
        backup_id: "rogue_backup_001".into(),
        created_at: "2026-10-24T00:00:00Z".into(),
        root_dir: root.to_string_lossy().to_string(),
        records: vec![BackupRecord {
            relative_target_path: "test.txt".into(),
            original_sha256: bug_killer::healer::backup::BackupManager::compute_sha256(
                &dummy_target,
            )
            .unwrap(),
            backup_file_name: "0_test.txt".into(),
        }],
        signer_public_key: None,
        signature: None,
    };

    // Attacker signs manifest with their rogue key
    rogue_identity.sign_manifest(&mut rogue_manifest);

    let manifest_path = backup_dir.join("manifest.json");
    fs::write(
        manifest_path,
        serde_json::to_string_pretty(&rogue_manifest).unwrap(),
    )
    .unwrap();

    // Rollback MUST fail closed because signer is untrusted by root
    let res = RollbackManager::rollback(root, "rogue_backup_001");
    assert!(res.is_err(), "Untrusted signer must fail closed");
    let err_msg = res.unwrap_err();
    assert!(
        err_msg.contains("Untrusted signer"),
        "Error should report untrusted signer, got: {}",
        err_msg
    );
}

#[test]
fn test_m1_unsigned_manifest_fails_closed() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    let _identity = AgentIdentity::get_or_create(root).unwrap();

    let backup_dir = root
        .join(".aegis")
        .join("backups")
        .join("unsigned_backup_002");
    fs::create_dir_all(&backup_dir).unwrap();

    let dummy_target = root.join("test.txt");
    fs::write(&dummy_target, "content").unwrap();

    let backup_file = backup_dir.join("0_test.txt");
    fs::write(&backup_file, "content").unwrap();

    let unsigned_manifest = BackupManifest {
        backup_id: "unsigned_backup_002".into(),
        created_at: "2026-10-24T00:00:00Z".into(),
        root_dir: root.to_string_lossy().to_string(),
        records: vec![BackupRecord {
            relative_target_path: "test.txt".into(),
            original_sha256: bug_killer::healer::backup::BackupManager::compute_sha256(
                &dummy_target,
            )
            .unwrap(),
            backup_file_name: "0_test.txt".into(),
        }],
        signer_public_key: None,
        signature: None,
    };

    let manifest_path = backup_dir.join("manifest.json");
    fs::write(
        manifest_path,
        serde_json::to_string_pretty(&unsigned_manifest).unwrap(),
    )
    .unwrap();

    let res = RollbackManager::rollback(root, "unsigned_backup_002");
    assert!(res.is_err(), "Unsigned manifest must fail closed");
    let err_msg = res.unwrap_err();
    assert!(
        err_msg.contains("untrusted"),
        "Error should report untrusted, got: {}",
        err_msg
    );
}

#[test]
fn test_m1_path_traversal_fails_closed() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    let identity = AgentIdentity::get_or_create(root).unwrap();

    let backup_dir = root
        .join(".aegis")
        .join("backups")
        .join("traversal_backup_003");
    fs::create_dir_all(&backup_dir).unwrap();

    let backup_file = backup_dir.join("0_malicious.txt");
    fs::write(&backup_file, "malicious payload").unwrap();

    let mut manifest = BackupManifest {
        backup_id: "traversal_backup_003".into(),
        created_at: "2026-10-24T00:00:00Z".into(),
        root_dir: root.to_string_lossy().to_string(),
        records: vec![BackupRecord {
            relative_target_path: "../../etc/malicious_escape.txt".into(),
            original_sha256: bug_killer::healer::backup::BackupManager::compute_sha256(
                &backup_file,
            )
            .unwrap(),
            backup_file_name: "0_malicious.txt".into(),
        }],
        signer_public_key: None,
        signature: None,
    };

    identity.sign_manifest(&mut manifest);

    let manifest_path = backup_dir.join("manifest.json");
    fs::write(
        manifest_path,
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();

    let res = RollbackManager::rollback(root, "traversal_backup_003");
    assert!(res.is_err(), "Path traversal must fail closed");
    let err_msg = res.unwrap_err();
    assert!(
        err_msg.contains("Path traversal attempt rejected"),
        "Got: {}",
        err_msg
    );
}

#[test]
fn test_m1_multi_file_transaction_rollback_on_failure() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    let file1 = root.join("file1.txt");
    let file2 = root.join("file2.txt");

    fs::write(&file1, "file1 original").unwrap();
    fs::write(&file2, "file2 original").unwrap();

    let sha1 = bug_killer::healer::backup::BackupManager::compute_sha256(&file1).unwrap();
    let sha2 = bug_killer::healer::backup::BackupManager::compute_sha256(&file2).unwrap();

    // Point action 2 to an unwritable directory to force a write error
    let invalid_target = root
        .join("nonexistent_parent_dir")
        .join("sub")
        .join("file2.txt");

    let actions = vec![
        PatchAction {
            action_type: PatchActionType::GenericReplace,
            target_file: file1.clone(),
            original_checksum: sha1,
            diff_description: "modify file 1".into(),
            replacement_content: "file1 modified".into(),
        },
        PatchAction {
            action_type: PatchActionType::GenericReplace,
            target_file: invalid_target,
            original_checksum: sha2,
            diff_description: "modify file 2".into(),
            replacement_content: "file2 modified".into(),
        },
    ];

    let result = AutopilotHealer::execute_healing(root, &actions);
    assert!(
        result.is_err(),
        "Multi-file transaction must abort on error"
    );
    assert!(
        result.unwrap_err().contains("Restored"),
        "Error must report verified rollback outcome, not an unconditional safety claim"
    );

    // CRITICAL: File 1 MUST be rolled back to original content, not left modified!
    let content1 = fs::read_to_string(&file1).unwrap();
    assert_eq!(
        content1, "file1 original",
        "File 1 must be cleanly rolled back when transaction fails"
    );
}
