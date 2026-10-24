use std::fs;
use tempfile::tempdir;
use bug_killer::doctor::SystemDoctor;
use bug_killer::watcher::WatcherEngine;
use bug_killer::completion::CompletionGenerator;
use clap::Command;

#[test]
fn test_doctor_diagnostic_execution() {
    let dir = tempdir().unwrap();
    let report = SystemDoctor::diagnose(dir.path());

    assert!(!report.os.is_empty());
    assert!(!report.arch.is_empty());
    assert!(report.items.len() >= 6);

    let has_permissions = report.items.iter().any(|i| i.name.contains("Permissions"));
    assert!(has_permissions, "Doctor must evaluate workspace permissions");
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
