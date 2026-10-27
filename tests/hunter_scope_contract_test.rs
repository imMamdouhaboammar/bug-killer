use bug_killer::engine::scope::{ResearchScope, ScopeError};
use bug_killer::engine::snapshot::{InventoryStatus, TargetSnapshot};
use bug_killer::hunter::hypothesis::CandidateState;
use bug_killer::hunter::orchestrator::AutonomousHunter;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_research_fails_closed_without_owner_opt_in() {
    let dir = tempdir().expect("Failed to create tempdir");
    let target_path = dir.path();

    // Explicit opt-in false must fail closed with ScopeError::OwnerOptInRequired
    let scope_res = ResearchScope::new(target_path, false);
    assert!(
        matches!(scope_res, Err(ScopeError::OwnerOptInRequired)),
        "ResearchScope must fail closed when owner_opt_in is false"
    );

    // Creating scope with opt-in true must succeed
    let scope = ResearchScope::new(target_path, true).expect("Valid scope with opt-in");
    assert!(scope.owner_opt_in, "Owner opt-in must be true");
}

#[test]
fn test_scope_denies_outside_root_traversal() {
    let dir = tempdir().expect("Failed to create tempdir");
    let target_path = dir.path();
    let scope = ResearchScope::new(target_path, true).expect("Valid scope");

    // Path attempting traversal outside root must be rejected
    let outside_traversal = target_path.join("../../etc/passwd");
    let res = scope.is_path_in_scope(&outside_traversal);
    assert!(
        matches!(res, Err(ScopeError::OutsideRoot { .. })),
        "Path escaping target root via traversal must be denied"
    );
}

#[test]
fn test_scope_denies_symlink_escape_outside_root() {
    let dir = tempdir().expect("Failed to create tempdir");
    let target_path = dir.path();

    // Create a file outside the target root
    let outside_dir = tempdir().expect("Failed to create outside tempdir");
    let outside_file = outside_dir.path().join("secret.txt");
    fs::write(&outside_file, "sensitive_data").expect("Failed to write outside file");

    // Create a symlink inside target root pointing outside
    let escape_symlink = target_path.join("escaped_link");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&outside_file, &escape_symlink).expect("Failed to create symlink");

    let scope = ResearchScope::new(target_path, true).expect("Valid scope");

    // TargetSnapshot creation or is_path_in_scope must detect and deny the escaping symlink
    let res = scope.is_path_in_scope(&escape_symlink);
    assert!(
        matches!(res, Err(ScopeError::SymlinkEscape { .. })),
        "Symlink pointing outside target root must be denied"
    );

    // TargetSnapshot must also fail or quarantine the escaping symlink
    let snapshot_res = TargetSnapshot::create(&scope);
    assert!(
        matches!(snapshot_res, Err(ScopeError::SymlinkEscape { .. })),
        "TargetSnapshot must fail closed on symlink escaping root"
    );
}

#[test]
fn test_scope_allows_valid_internal_symlink() {
    let dir = tempdir().expect("Failed to create tempdir");
    let target_path = dir.path();

    // Create internal file
    let internal_file = target_path.join("src").join("index.ts");
    fs::create_dir_all(internal_file.parent().unwrap()).expect("create_dir_all");
    fs::write(&internal_file, "console.log('hello');").expect("write file");

    // Create internal symlink pointing to internal file
    let internal_symlink = target_path.join("link_to_index.ts");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&internal_file, &internal_symlink).expect("create symlink");

    let scope = ResearchScope::new(target_path, true).expect("Valid scope");
    let res = scope.is_path_in_scope(&internal_symlink);
    assert!(
        res.is_ok(),
        "Internal symlink within root must be allowed: {:?}",
        res
    );
}

#[test]
fn test_snapshot_computes_deterministic_sha256() {
    let dir1 = tempdir().expect("tempdir 1");
    let dir2 = tempdir().expect("tempdir 2");

    // Populate dir1
    fs::create_dir_all(dir1.path().join("src")).unwrap();
    fs::write(dir1.path().join("src/b.ts"), "const b = 2;").unwrap();
    fs::write(dir1.path().join("src/a.ts"), "const a = 1;").unwrap();
    fs::write(dir1.path().join("package.json"), "{\"name\":\"test\"}").unwrap();

    // Populate dir2 in different creation order
    fs::create_dir_all(dir2.path().join("src")).unwrap();
    fs::write(dir2.path().join("package.json"), "{\"name\":\"test\"}").unwrap();
    fs::write(dir2.path().join("src/a.ts"), "const a = 1;").unwrap();
    fs::write(dir2.path().join("src/b.ts"), "const b = 2;").unwrap();

    let scope1 = ResearchScope::new(dir1.path(), true).unwrap();
    let scope2 = ResearchScope::new(dir2.path(), true).unwrap();

    let snap1 = TargetSnapshot::create(&scope1).expect("Snapshot 1");
    let snap2 = TargetSnapshot::create(&scope2).expect("Snapshot 2");

    assert_eq!(
        snap1.snapshot_sha256, snap2.snapshot_sha256,
        "Snapshot SHA-256 must be deterministic regardless of filesystem iteration order"
    );
    assert_eq!(snap1.snapshot_sha256.len(), 64);
    assert_eq!(snap1.inventory.status, InventoryStatus::Complete);
    assert_eq!(snap1.inventory.unreadable_files.len(), 0);

    // Modify a file in dir2 and verify digest changes
    fs::write(dir2.path().join("src/a.ts"), "const a = 999;").unwrap();
    let snap3 = TargetSnapshot::create(&scope2).expect("Snapshot 3");
    assert_ne!(
        snap1.snapshot_sha256, snap3.snapshot_sha256,
        "Snapshot SHA-256 must change when file contents change"
    );
}

#[test]
fn test_snapshot_marks_incomplete_inventory_as_partial() {
    let dir = tempdir().expect("tempdir");
    let target_path = dir.path();

    fs::create_dir_all(target_path.join("src")).unwrap();
    fs::write(target_path.join("src/readable.ts"), "export const ok = 1;").unwrap();

    let unreadable = target_path.join("src/unreadable.ts");
    fs::write(&unreadable, "unreadable data").unwrap();

    // On Unix, remove read permissions to make it unreadable
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&unreadable).unwrap().permissions();
        perms.set_mode(0o000);
        fs::set_permissions(&unreadable, perms).unwrap();
    }

    let scope = ResearchScope::new(target_path, true).unwrap();
    let snap = TargetSnapshot::create_allow_partial(&scope).expect("Snapshot created");

    #[cfg(unix)]
    {
        // Must be marked Partial due to unreadable file
        assert_eq!(
            snap.inventory.status,
            InventoryStatus::Partial,
            "Inventory must be marked Partial when unreadable files are encountered"
        );
        assert!(
            snap.inventory
                .unreadable_files
                .iter()
                .any(|p| p.contains("unreadable.ts")),
            "Unreadable files list must contain unreadable.ts"
        );

        // Restore permissions for clean tempdir cleanup
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&unreadable).unwrap().permissions();
        perms.set_mode(0o644);
        fs::set_permissions(&unreadable, perms).unwrap();
    }
}

#[test]
fn test_candidate_blocked_by_scope_when_outside_allowed_boundary() {
    let dir = tempdir().expect("tempdir");
    let target_path = dir.path();
    fs::create_dir_all(target_path.join("src")).unwrap();
    fs::write(
        target_path.join("src/app.js"),
        "app.post('/api/pay', (req, res) => { transfer(); });",
    )
    .unwrap();

    // Scope only allows "src/api", so "src/app.js" is outside the allowed subpaths
    let scope = ResearchScope::new(target_path, true)
        .unwrap()
        .with_allowed_subpaths(vec![target_path.join("src/api")]);

    let hunter = AutonomousHunter::new();
    let report = hunter
        .hunt_with_scope(&scope, 10)
        .expect("Hunt should complete");

    // Candidates in un-allowed subpaths must be blocked by scope
    assert!(
        report.blocked_by_scope_count > 0
            || report
                .candidates
                .iter()
                .all(|c| { matches!(c.state, CandidateState::BlockedByScope(_)) }),
        "Candidates outside allowed subpaths must be marked BlockedByScope"
    );
}
