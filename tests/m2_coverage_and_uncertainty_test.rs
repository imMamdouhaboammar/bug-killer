use bug_killer::scanner::FleetScanner;
use bug_killer::types::*;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_m2_framework_presence_without_call_is_potentially_affected_and_unknown_reachability() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    // package.json declaring express but with safe/fixed node engine, and no source code
    let package_json = root.join("package.json");
    fs::write(
        &package_json,
        r#"{
  "name": "api-service",
  "dependencies": {
    "express": "^4.19.2",
    "fastify": "^4.26.0"
  }
}"#,
    )
    .unwrap();

    let report = FleetScanner::scan_directory(root, false);
    assert!(report.is_vulnerable);

    let http_finding = report
        .findings
        .iter()
        .find(|f| f.id == "NODE-HTTP-BODY-DECOMPRESSOR")
        .expect("Expected NODE-HTTP-BODY-DECOMPRESSOR finding");

    // Invariant: framework presence alone MUST NOT be claimed as confirmed exposure
    assert_eq!(
        http_finding.affectedness,
        Affectedness::PotentiallyAffected,
        "Framework presence must be POTENTIALLY_AFFECTED, not CONFIRMED_AFFECTED"
    );
    assert_eq!(
        http_finding.reachability,
        Reachability::Unknown,
        "Brotli reachability must be UNKNOWN when only framework is declared"
    );
    assert_eq!(
        http_finding.confidence,
        Confidence::Low,
        "Detection confidence must be Low without proven call graph"
    );
    assert!(
        !http_finding.uncertainty_reasons.is_empty(),
        "Uncertainty reasons must document unproven reachability"
    );
    assert!(
        http_finding
            .missing_checks
            .contains(&"verify_brotli_decompression_call".to_string()),
        "Missing checks must specify needed verification"
    );
}

#[test]
fn test_m2_direct_brotli_call_is_confirmed_affected_and_reachable() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    let decompressor_js = root.join("decompressor.js");
    fs::write(
        &decompressor_js,
        r#"
const zlib = require('zlib');
function unpackPayload(buf) {
    return zlib.brotliDecompressSync(buf);
}
module.exports = { unpackPayload };
"#,
    )
    .unwrap();

    let report = FleetScanner::scan_directory(root, false);
    assert!(report.is_vulnerable);

    let call_finding = report
        .findings
        .iter()
        .find(|f| f.detector_id == "node-source-brotli")
        .expect("Expected node-source-brotli finding");

    assert_eq!(
        call_finding.affectedness,
        Affectedness::ConfirmedAffected,
        "Direct decompressor call must be CONFIRMED_AFFECTED"
    );
    assert_eq!(
        call_finding.reachability,
        Reachability::ConfirmedReachable,
        "Direct decompressor call must be CONFIRMED_REACHABLE"
    );
    assert_eq!(call_finding.confidence, Confidence::Confirmed);
    assert!(!call_finding.dedupe_fingerprint.is_empty());
}

#[test]
fn test_m2_composer_php_constraint_is_potentially_affected_with_missing_checks() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    let composer_json = root.join("composer.json");
    fs::write(
        &composer_json,
        r#"{
  "name": "vendor/app",
  "require": {
    "php": "^8.2.10"
  }
}"#,
    )
    .unwrap();

    let report = FleetScanner::scan_directory(root, false);
    assert!(report.is_vulnerable);

    let php_finding = report
        .findings
        .iter()
        .find(|f| f.detector_id == "php-composer")
        .expect("Expected php-composer finding");

    assert_eq!(
        php_finding.affectedness,
        Affectedness::PotentiallyAffected,
        "Composer requirement alone must be POTENTIALLY_AFFECTED without running interpreter"
    );
    assert_eq!(php_finding.reachability, Reachability::Unknown);
    assert_eq!(php_finding.confidence, Confidence::Medium);
    assert!(
        php_finding
            .missing_checks
            .contains(&"verify_installed_php_version".to_string()),
        "Must require verifying installed interpreter"
    );
}

#[test]
fn test_m2_unreadable_file_fails_closed_in_coverage_not_clean() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    // Create an invalid non-UTF8 / unreadable file named package.json
    let bad_package_json = root.join("package.json");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::write(&bad_package_json, b"\xFF\xFE\x00\x00corrupt-bytes").unwrap();
        // Remove read permissions so std::fs::read_to_string fails with PermissionDenied
        fs::set_permissions(&bad_package_json, fs::Permissions::from_mode(0o000)).unwrap();
    }
    #[cfg(not(unix))]
    {
        // On non-unix, write invalid UTF-8 bytes which fails read_to_string
        fs::write(&bad_package_json, b"\xFF\xFE\x00\x00invalid-utf8").unwrap();
    }

    let report = FleetScanner::scan_directory(root, false);

    // Invariant: An incomplete scan with parser/I/O failures MUST NOT report is_clean() == true!
    assert_eq!(
        report.coverage.coverage_status,
        CoverageStatus::Partial,
        "Coverage must be Partial when target files fail to read"
    );
    assert!(
        !report.coverage.parser_failures.is_empty(),
        "Parser failures must record the failed target"
    );
    assert_eq!(
        report.coverage.parser_failures[0].path, bad_package_json,
        "Failed target path must be preserved in coverage report"
    );
    assert!(
        !report.is_clean(),
        "Incomplete/failed scan must NEVER be reported as clean!"
    );

    // Cleanup permissions so tempdir can be removed
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&bad_package_json, fs::Permissions::from_mode(0o600));
    }
}

#[test]
fn test_m2_coverage_accounting_records_excluded_directories() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    // Create excluded directories
    let node_modules = root.join("node_modules");
    fs::create_dir_all(&node_modules).unwrap();
    fs::write(node_modules.join("dep.js"), "console.log('ignored');").unwrap();

    let git_dir = root.join(".git");
    fs::create_dir_all(&git_dir).unwrap();
    fs::write(git_dir.join("config"), "git-config").unwrap();

    let clean_file = root.join("index.html");
    fs::write(&clean_file, "<html><body>Clean</body></html>").unwrap();

    let report = FleetScanner::scan_directory(root, false);
    assert!(report.is_clean());
    assert_eq!(report.coverage.coverage_status, CoverageStatus::Complete);
    assert!(
        report.coverage.files_excluded >= 2,
        "Coverage must accurately count excluded directories (.git, node_modules)"
    );
    assert_eq!(report.total_files_scanned, 1);
}
