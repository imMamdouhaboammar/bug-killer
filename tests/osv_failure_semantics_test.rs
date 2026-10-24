use bug_killer::osv::{OsvClient, VersionResolution};
use bug_killer::types::*;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_osv_range_constraints_are_never_sent_as_exact_version() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    // Manifest with range constraints only (no resolved lockfile)
    let pkg_json = root.join("package.json");
    fs::write(
        &pkg_json,
        r#"{
  "name": "range-only-app",
  "dependencies": {
    "lodash": "^4.17.15",
    "express": ">=4.18.0",
    "debug": "~2.6.9",
    "wildcard-pkg": "*"
  }
}"#,
    )
    .unwrap();

    let packages = OsvClient::discover_packages(root);
    assert_eq!(packages.len(), 4);

    for p in &packages {
        assert_eq!(
            p.resolution,
            VersionResolution::DeclaredRequirement,
            "Package {} with range constraint must be classified as DeclaredRequirement",
            p.name
        );
        assert!(
            p.declared_requirement.is_some(),
            "Declared requirement must be preserved for {}",
            p.name
        );
    }

    let client = OsvClient::new();
    let (findings, receipt) = client.scan_workspace_with_receipt(root);

    // No exact queries should be made to OSV for range constraints
    assert!(
        findings.is_empty(),
        "Unresolved ranges must never return fabricated findings"
    );
    assert_eq!(
        receipt.status,
        CoverageStatus::Partial,
        "Coverage for range-only manifest without lockfile must be Partial"
    );
    assert_eq!(receipt.skipped_reasons.len(), 4);
    for reason in &receipt.skipped_reasons {
        assert!(reason.contains("skipped from exact OSV lookup"));
    }
}

#[test]
fn test_osv_failure_semantics_network_error_fails_closed() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    // Package with an exact pinned version
    let pkg_json = root.join("package.json");
    fs::write(
        &pkg_json,
        r#"{
  "name": "exact-pinned-app",
  "dependencies": {
    "minimist": "1.2.5"
  }
}"#,
    )
    .unwrap();

    let packages = OsvClient::discover_packages(root);
    assert_eq!(packages.len(), 1);
    assert_eq!(packages[0].resolution, VersionResolution::ResolvedExact);
    assert_eq!(packages[0].version, "1.2.5");

    // Point OsvClient to a non-existent port to simulate network failure / 500
    let unreachable_client = OsvClient::with_endpoint("http://127.0.0.1:59999/v1/query");
    let (findings, receipt) = unreachable_client.scan_workspace_with_receipt(root);

    assert!(findings.is_empty());
    assert_eq!(
        receipt.status,
        CoverageStatus::Error,
        "Network outage or API failure must produce CoverageStatus::Error"
    );
    assert!(
        !receipt.errors.is_empty(),
        "Receipt must record the exact network/API error"
    );

    let coverage = ScanCoverage {
        files_scanned: 1,
        files_excluded: 0,
        parser_failures: vec![],
        unsupported_targets: vec![],
        coverage_status: CoverageStatus::Complete,
        receipts: vec![receipt],
    };

    let report = ScanReport {
        target_dir: root.to_path_buf(),
        scan_time: "2026-10-24T12:00:00Z".into(),
        total_files_scanned: 1,
        findings,
        is_vulnerable: false,
        critical_count: 0,
        high_count: 0,
        coverage,
    };

    // MUST NOT REPORT CLEAN
    assert!(
        !report.is_clean(),
        "Network error in OSV lookup must NEVER report clean scan!"
    );
}
