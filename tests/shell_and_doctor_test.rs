use bug_killer::completion::CompletionGenerator;
use bug_killer::doctor::SystemDoctor;
use bug_killer::watcher::WatcherEngine;
use clap::Command;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_doctor_diagnostic_execution() {
    let dir = tempdir().unwrap();
    let report = SystemDoctor::diagnose(dir.path());

    assert!(!report.os.is_empty());
    assert!(!report.arch.is_empty());
    assert!(report.items.len() >= 6);

    let has_permissions = report.items.iter().any(|i| i.name.contains("Permissions"));
    assert!(
        has_permissions,
        "Doctor must evaluate workspace permissions"
    );
}

#[test]
fn test_watcher_snapshot_mtimes() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    let file_a = root.join("app.js");
    let file_b = root.join("package.json");
    fs::write(&file_a, "console.log('test');").unwrap();
    fs::write(&file_b, "{}").unwrap();

    let mtimes = WatcherEngine::snapshot_mtimes(root);
    assert!(mtimes.contains_key(&file_a));
    assert!(mtimes.contains_key(&file_b));
    assert_eq!(mtimes.len(), 2);
}

#[test]
fn test_completion_generation() {
    let mut cmd = Command::new("bug-killer");
    let bash_res = CompletionGenerator::generate_completion("bash", &mut cmd);
    assert!(bash_res.is_ok());

    let zsh_res = CompletionGenerator::generate_completion("zsh", &mut cmd);
    assert!(zsh_res.is_ok());

    let invalid_res = CompletionGenerator::generate_completion("invalid_shell", &mut cmd);
    assert!(invalid_res.is_err());
}

#[test]
fn test_agent_identity_signature_and_tamper_detection() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    let identity = bug_killer::identity::AgentIdentity::get_or_create(root).unwrap();
    assert_eq!(identity.public_key_hex().len(), 64);

    let mut manifest = bug_killer::types::BackupManifest {
        backup_id: "20261024_000000".into(),
        created_at: "2026-10-24T00:00:00Z".into(),
        root_dir: root.to_string_lossy().to_string(),
        records: vec![bug_killer::types::BackupRecord {
            relative_target_path: "server.js".into(),
            original_sha256: "abcdef123456".into(),
            backup_file_name: "0_server.js".into(),
        }],
        signer_public_key: None,
        signature: None,
    };

    // Sign manifest
    identity.sign_manifest(&mut manifest);
    assert!(manifest.signature.is_some());
    assert!(manifest.signer_public_key.is_some());

    // Verify legitimate manifest
    assert!(bug_killer::identity::AgentIdentity::verify_manifest(&manifest).is_ok());

    // Tamper with records: verification MUST fail closed
    manifest.records[0].original_sha256 = "corrupted_hash_9999".into();
    assert!(bug_killer::identity::AgentIdentity::verify_manifest(&manifest).is_err());
}
