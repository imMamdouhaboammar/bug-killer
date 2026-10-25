use bug_killer::healer::AutopilotHealer;
use bug_killer::healer::rollback::RollbackManager;
use bug_killer::identity::AgentIdentity;
use bug_killer::types::{BackupManifest, BackupRecord, PatchAction, PatchActionType};
use std::fs;
use std::path::PathBuf;
use tempfile::tempdir;

fn directory_rejects_tempfiles(path: &std::path::Path) -> bool {
    matches!(
        tempfile::NamedTempFile::new_in(path),
        Err(ref error) if error.kind() == std::io::ErrorKind::PermissionDenied
    )
}

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
            mode: None,
            post_heal_sha256: None,
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
            mode: None,
            post_heal_sha256: None,
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
            mode: None,
            post_heal_sha256: None,
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
    if !cfg!(unix) {
        eprintln!("skipped: Unix directory mode required to force second write failure");
        return;
    }
    let dir = tempdir().unwrap();
    let root = dir.path();

    let file1 = root.join("file1.txt");
    let sub_dir = root.join("unwritable_sub");
    fs::create_dir_all(&sub_dir).unwrap();
    let file2 = sub_dir.join("file2.txt");

    fs::write(&file1, "file1 original").unwrap();
    fs::write(&file2, "file2 original").unwrap();

    let sha1 = bug_killer::healer::backup::BackupManager::compute_sha256(&file1).unwrap();
    let sha2 = bug_killer::healer::backup::BackupManager::compute_sha256(&file2).unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // 0o500 allows stat and read (so preflight passes), but denies writing/creating tempfiles
        fs::set_permissions(&sub_dir, fs::Permissions::from_mode(0o500)).unwrap();
        if !directory_rejects_tempfiles(&sub_dir) {
            fs::set_permissions(&sub_dir, fs::Permissions::from_mode(0o700)).unwrap();
            eprintln!("skipped: current privilege bypasses read-only directory restrictions");
            return;
        }
    }

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
            target_file: file2.clone(),
            original_checksum: sha2,
            diff_description: "modify file 2".into(),
            replacement_content: "file2 modified".into(),
        },
    ];

    let result = AutopilotHealer::execute_healing(root, &actions);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Restore permissions for clean teardown
        let _ = fs::set_permissions(&sub_dir, fs::Permissions::from_mode(0o700));
    }

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

#[test]
fn test_m1_nonexistent_target_rejected_before_writing() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    let file1 = root.join("file1.txt");
    fs::write(&file1, "file1 original").unwrap();
    let sha1 = bug_killer::healer::backup::BackupManager::compute_sha256(&file1).unwrap();

    let nonexistent = root.join("nonexistent_sub").join("missing.txt");

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
            target_file: nonexistent,
            original_checksum: "0000000000000000000000000000000000000000000000000000000000000000"
                .into(),
            diff_description: "modify nonexistent".into(),
            replacement_content: "missing modified".into(),
        },
    ];

    let result = AutopilotHealer::execute_healing(root, &actions);
    assert!(result.is_err(), "Must abort before modifying any file");
    assert_eq!(
        fs::read_to_string(&file1).unwrap(),
        "file1 original",
        "File 1 must not be modified if preflight fails on action 2"
    );

    let backups_dir = root.join(".aegis").join("backups");
    assert!(
        !backups_dir.exists(),
        "No backup should be created when preflight fails"
    );
}

#[test]
fn test_m1_wrong_checksum_rejected_before_writing() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    let file = root.join("app.js");
    let original = "console.log('original');\n";
    fs::write(&file, original).unwrap();

    let action = PatchAction {
        action_type: PatchActionType::GenericReplace,
        target_file: file.clone(),
        original_checksum: "deadbeef00000000000000000000000000000000000000000000000000000000"
            .into(),
        diff_description: "tampered patch".into(),
        replacement_content: "console.log('pwned');\n".into(),
    };

    let res = AutopilotHealer::execute_healing(root, &[action]);
    assert!(res.is_err(), "Must reject wrong checksum before write");
    let content = fs::read_to_string(&file).unwrap();
    assert_eq!(
        content, original,
        "File must not be modified if checksum fails preflight"
    );

    let backups_dir = root.join(".aegis").join("backups");
    assert!(
        !backups_dir.exists(),
        "No backup directory should be created if preflight fails"
    );
}

#[test]
fn test_m1_rapid_backups_no_collision() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    let file = root.join("test.txt");
    fs::write(&file, "test content").unwrap();

    let mut ids = std::collections::HashSet::new();
    for _ in 0..50 {
        let manifest = bug_killer::healer::backup::BackupManager::create_backup(
            root,
            std::slice::from_ref(&file),
        )
        .unwrap();
        assert!(
            ids.insert(manifest.backup_id),
            "Backup ID collision detected!"
        );
    }
    assert_eq!(ids.len(), 50);
}

#[test]
fn test_m1_path_traversal_target_rejected_before_writing() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    let action = PatchAction {
        action_type: PatchActionType::GenericReplace,
        target_file: PathBuf::from("../escaped.txt"),
        original_checksum: "0000000000000000000000000000000000000000000000000000000000000000"
            .into(),
        diff_description: "escape attempt".into(),
        replacement_content: "pwned".into(),
    };

    let res = AutopilotHealer::execute_healing(root, &[action]);
    assert!(
        res.is_err(),
        "Must reject path traversal target before writing"
    );
    let backups_dir = root.join(".aegis").join("backups");
    assert!(
        !backups_dir.exists(),
        "No backup should be created on traversal preflight rejection"
    );
}

#[test]
fn test_m1_symlink_target_rejected_before_writing() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    let target_file = root.join("real.txt");
    fs::write(&target_file, "real content").unwrap();
    let sha = bug_killer::healer::backup::BackupManager::compute_sha256(&target_file).unwrap();

    let symlink_file = root.join("link.txt");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&target_file, &symlink_file).unwrap();

    #[cfg(unix)]
    {
        let action = PatchAction {
            action_type: PatchActionType::GenericReplace,
            target_file: symlink_file.clone(),
            original_checksum: sha,
            diff_description: "symlink overwrite attempt".into(),
            replacement_content: "mutated".into(),
        };

        let res = AutopilotHealer::execute_healing(root, &[action]);
        assert!(res.is_err(), "Must reject symlink target before writing");
        assert_eq!(fs::read_to_string(&target_file).unwrap(), "real content");
        let backups_dir = root.join(".aegis").join("backups");
        assert!(
            !backups_dir.exists(),
            "No backup should be created on symlink preflight rejection"
        );
    }
}

#[test]
fn test_m1_symlink_parent_dir_rejected_before_writing() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    let real_dir = root.join("real_dir");
    fs::create_dir_all(&real_dir).unwrap();
    let target_file = real_dir.join("subfile.txt");
    fs::write(&target_file, "subfile content").unwrap();
    let sha = bug_killer::healer::backup::BackupManager::compute_sha256(&target_file).unwrap();

    let symlink_dir = root.join("link_dir");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&real_dir, &symlink_dir).unwrap();

    #[cfg(unix)]
    {
        let action = PatchAction {
            action_type: PatchActionType::GenericReplace,
            target_file: symlink_dir.join("subfile.txt"),
            original_checksum: sha,
            diff_description: "symlink parent overwrite attempt".into(),
            replacement_content: "mutated".into(),
        };

        let res = AutopilotHealer::execute_healing(root, &[action]);
        assert!(
            res.is_err(),
            "Must reject symlink parent directory before writing"
        );
        assert_eq!(fs::read_to_string(&target_file).unwrap(), "subfile content");
        let backups_dir = root.join(".aegis").join("backups");
        assert!(
            !backups_dir.exists(),
            "No backup should be created on symlink parent rejection"
        );
    }
}

#[cfg(unix)]
#[test]
fn test_m1_executable_permissions_preserved_after_heal_and_rollback() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempdir().unwrap();
    let root = dir.path();

    let script = root.join("deploy.sh");
    let original = "#!/bin/sh\necho deploy\n";
    fs::write(&script, original).unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();

    let sha = bug_killer::healer::backup::BackupManager::compute_sha256(&script).unwrap();
    let action = PatchAction {
        action_type: PatchActionType::GenericReplace,
        target_file: script.clone(),
        original_checksum: sha,
        diff_description: "harden deploy script".into(),
        replacement_content: "#!/bin/sh\nset -eu\necho hardened\n".into(),
    };

    let (manifest, count) = AutopilotHealer::execute_healing(root, &[action]).unwrap();
    assert_eq!(count, 1);

    // Rollback
    let restored = RollbackManager::rollback(root, &manifest.backup_id).unwrap();
    assert_eq!(restored, 1);

    assert_eq!(fs::read_to_string(&script).unwrap(), original);
    let mode = fs::metadata(&script).unwrap().permissions().mode();
    assert_eq!(
        mode & 0o777,
        0o755,
        "Executable permissions must be preserved after rollback"
    );
}

#[test]
fn test_m1_post_heal_drift_detection() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    let file = root.join("config.json");
    let original = "{\"safe\": true}\n";
    fs::write(&file, original).unwrap();

    let sha = bug_killer::healer::backup::BackupManager::compute_sha256(&file).unwrap();
    let action = PatchAction {
        action_type: PatchActionType::GenericReplace,
        target_file: file.clone(),
        original_checksum: sha,
        diff_description: "patch config".into(),
        replacement_content: "{\"safe\": true, \"hardened\": true}\n".into(),
    };

    let (manifest, count) = AutopilotHealer::execute_healing(root, &[action]).unwrap();
    assert_eq!(count, 1);

    // External drift occurs!
    fs::write(&file, "{\"safe\": false, \"tampered\": true}\n").unwrap();

    // Rollback without force must fail with drift detection!
    let res = RollbackManager::rollback(root, &manifest.backup_id);
    assert!(res.is_err(), "Must reject rollback on drifted file");
    assert!(
        res.unwrap_err().contains("drift"),
        "Error must report drift"
    );

    // File remains untouched by failed rollback
    assert_eq!(
        fs::read_to_string(&file).unwrap(),
        "{\"safe\": false, \"tampered\": true}\n"
    );

    // Rollback with explicit force succeeds!
    let force_res = RollbackManager::rollback_with_force(root, &manifest.backup_id, true);
    assert!(
        force_res.is_ok(),
        "Rollback with explicit force must succeed"
    );
    assert_eq!(fs::read_to_string(&file).unwrap(), original);
}

#[test]
fn test_m1_partial_rollback_structured_reporting() {
    if !cfg!(unix) {
        eprintln!("skipped: Unix directory mode required to force rollback failure");
        return;
    }
    let dir = tempdir().unwrap();
    let root = dir.path();

    let file1 = root.join("file1.txt");
    let sub = root.join("sub_restore_fail");
    fs::create_dir_all(&sub).unwrap();
    let file2 = sub.join("file2.txt");

    fs::write(&file1, "orig1").unwrap();
    fs::write(&file2, "orig2").unwrap();

    let sha1 = bug_killer::healer::backup::BackupManager::compute_sha256(&file1).unwrap();
    let sha2 = bug_killer::healer::backup::BackupManager::compute_sha256(&file2).unwrap();

    let actions = vec![
        PatchAction {
            action_type: PatchActionType::GenericReplace,
            target_file: file1.clone(),
            original_checksum: sha1,
            diff_description: "patch 1".into(),
            replacement_content: "patched1".into(),
        },
        PatchAction {
            action_type: PatchActionType::GenericReplace,
            target_file: file2.clone(),
            original_checksum: sha2,
            diff_description: "patch 2".into(),
            replacement_content: "patched2".into(),
        },
    ];

    let (manifest, count) = AutopilotHealer::execute_healing(root, &actions).unwrap();
    assert_eq!(count, 2);

    // Now before rollback, make file2's parent directory read-only so restoring file2 fails!
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&sub, fs::Permissions::from_mode(0o500)).unwrap();
        if !directory_rejects_tempfiles(&sub) {
            fs::set_permissions(&sub, fs::Permissions::from_mode(0o700)).unwrap();
            eprintln!("skipped: current privilege bypasses read-only directory restrictions");
            return;
        }
    }

    let res = RollbackManager::rollback(root, &manifest.backup_id);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&sub, fs::Permissions::from_mode(0o700));
    }

    #[cfg(unix)]
    {
        assert!(res.is_err(), "Must report partial restore failure");
        let err = res.unwrap_err();
        assert!(
            err.contains("PARTIALLY_RESTORED"),
            "Error must report PARTIALLY_RESTORED, got: {}",
            err
        );
        assert!(
            err.contains("Restored files"),
            "Error must list Restored files"
        );
        assert!(
            err.contains("Un-restored files"),
            "Error must list Un-restored files"
        );
    }
}
