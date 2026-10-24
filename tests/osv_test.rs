use std::fs;
use tempfile::tempdir;
use bug_killer::osv::OsvClient;
use bug_killer::types::*;
use bug_killer::healer::AutopilotHealer;
use bug_killer::healer::rollback::RollbackManager;

#[test]
fn test_osv_package_discovery_and_live_query() {
    let dir = tempdir().expect("Failed to create tempdir");
    let root = dir.path();

    // 1. Create a package.json with known vulnerable dependency (minimist 1.2.5 has prototype pollution CVE-2021-44906)
    let package_json = root.join("package.json");
    let content = r#"{
  "name": "vulnerable-app",
  "version": "1.0.0",
  "dependencies": {
    "minimist": "1.2.5"
  }
}
"#;
    fs::write(&package_json, content).unwrap();

    // 2. Discover packages
    let discovered = OsvClient::discover_packages(root);
    assert_eq!(discovered.len(), 1);
    assert_eq!(discovered[0].name, "minimist");
    assert_eq!(discovered[0].version, "1.2.5");
    assert_eq!(discovered[0].ecosystem, "npm");

    // 3. Query OSV.dev
    let client = OsvClient::new();
    let findings = client.query_package(&discovered[0]).expect("OSV query should succeed");
    assert!(!findings.is_empty(), "Minimist 1.2.5 should return confirmed CVEs from OSV.dev");

    let first = &findings[0];
    assert!(first.id.starts_with("osv-"));
    assert!(first.suggested_remediation.contains("Upgrade minimist"));

    // 4. Test Autopilot healing of OSV finding
    let report = ScanReport {
        target_dir: root.to_path_buf(),
        scan_time: "2026-10-24T00:00:00Z".into(),
        total_files_scanned: 1,
        findings: findings.clone(),
        is_vulnerable: true,
        critical_count: 0,
        high_count: findings.len(),
    };

    let plan = AutopilotHealer::plan_healing(&report);
    assert!(!plan.is_empty(), "Should plan version bump for vulnerable package");

    let (manifest, applied) = AutopilotHealer::execute_healing(root, &plan).expect("Healing should execute");
    assert_eq!(applied, 1);

    // Verify package.json updated
    let healed_content = fs::read_to_string(&package_json).unwrap();
    assert!(healed_content.contains("minimist"));
    assert!(!healed_content.contains("\"1.2.5\""), "Version 1.2.5 should be upgraded");

    // 5. Test Cryptographic Rollback
    let restored = RollbackManager::rollback(root, &manifest.backup_id).expect("Rollback should succeed");
    assert_eq!(restored, 1);

    let restored_content = fs::read_to_string(&package_json).unwrap();
    assert_eq!(restored_content, content, "Package.json should be restored byte-for-byte");
}
