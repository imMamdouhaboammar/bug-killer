use bug_killer::healer::AutopilotHealer;
use bug_killer::healer::approval::{ApprovalManager, ApprovalReceipt};
use bug_killer::scanner::FleetScanner;
use bug_killer::types::*;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use tempfile::tempdir;

fn hash_directory_files(root: &Path) -> HashMap<String, String> {
    let mut file_hashes = HashMap::new();
    for entry in walkdir::WalkDir::new(root)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if entry.file_type().is_file() {
            let rel_path = entry
                .path()
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .to_string();
            let content = fs::read(entry.path()).unwrap();
            let mut hasher = Sha256::new();
            hasher.update(&content);
            file_hashes.insert(rel_path, format!("{:x}", hasher.finalize()));
        }
    }
    file_hashes
}

#[test]
fn test_m0_scan_is_strictly_read_only_and_preserves_hashes() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    // Setup dummy workspace with vulnerable package.json, php config, and python source
    fs::write(
        root.join("package.json"),
        r#"{
  "name": "vulnerable-app",
  "dependencies": {
    "express": "^4.17.1",
    "brotli": "1.3.2"
  }
}"#,
    )
    .unwrap();

    fs::write(
        root.join("index.js"),
        r#"
const query = req.query.input;
eval(query);
"#,
    )
    .unwrap();

    fs::write(
        root.join("php.ini"),
        "memory_limit = -1\nmax_execution_time = 0\n",
    )
    .unwrap();

    let hashes_before = hash_directory_files(root);
    assert!(!hashes_before.is_empty());

    // Execute scan with taint enabled
    let report = FleetScanner::scan_directory_with_rules_and_taint(root, false, &[], true);
    assert!(report.is_vulnerable);

    let hashes_after = hash_directory_files(root);

    // Cryptographic proof: zero filesystem mutations
    assert_eq!(
        hashes_before, hashes_after,
        "Scanner must be strictly read-only and never mutate files"
    );
}

#[test]
fn test_m0_unauthorized_sca_and_taint_findings_cannot_auto_heal() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    let pkg_file = root.join("package.json");
    let original_pkg = r#"{
  "name": "test-unauth-heal",
  "dependencies": {
    "lodash": "4.17.15"
  }
}"#;
    fs::write(&pkg_file, original_pkg).unwrap();

    let js_file = root.join("app.js");
    let original_js = r#"
const cmd = req.query.cmd;
require('child_process').exec(cmd);
"#;
    fs::write(&js_file, original_js).unwrap();

    let report = ScanReport {
        target_dir: root.to_path_buf(),
        scan_time: "2026-10-24T00:00:00Z".into(),
        total_files_scanned: 2,
        findings: vec![
            Finding::new(
                "osv-GHSA-p6mc-m468-83gw-lodash",
                CveId::Custom {
                    id: "CVE-2020-8203".into(),
                    title: "Prototype Pollution in lodash".into(),
                },
                Severity::High,
                TargetKind::NodePackageManifest,
                Some(pkg_file.clone()),
                Some(4),
                "lodash @ 4.17.15 (npm)",
                "Upgrade to >= 4.17.19",
                "Prototype pollution vulnerability",
                "Upgrade lodash to 4.17.19",
            ),
            Finding::new(
                "taint-cwe-78-L3",
                CveId::Custom {
                    id: "CWE-78".into(),
                    title: "Command Injection".into(),
                },
                Severity::Critical,
                TargetKind::GenericSourceFile,
                Some(js_file.clone()),
                Some(3),
                "exec(cmd)",
                "Validate and sanitize inputs",
                "Untrusted input reaches exec sink",
                "Use execFile with argument array",
            ),
        ],
        is_vulnerable: true,
        critical_count: 1,
        high_count: 1,
        coverage: ScanCoverage::default(),
    };

    // Attempting to plan healing for these findings:
    // Taint findings must never produce auto-patches (they require human architectural redesign).
    // OSV dependency bumps must NOT be automatically applied without explicit operator approval.
    let plan = AutopilotHealer::plan_healing(&report);

    // Verify taint finding has zero automatic patch actions
    assert!(
        !plan.iter().any(|act| act.target_file == js_file),
        "Taint findings must NEVER generate automated patch actions"
    );

    // If an OSV patch action was planned, verify it requires explicit operator approval and cannot be executed directly
    if let Some(osv_action) = plan.iter().find(|act| act.target_file == pkg_file) {
        let plan_checksum =
            ApprovalManager::compute_plan_checksum(std::slice::from_ref(osv_action));
        // Verification without an approval receipt must fail closed
        let verify_res = ApprovalManager::verify_approval_receipt(
            root,
            &ApprovalReceipt {
                plan_id: "forged-plan".into(),
                plan_checksum: plan_checksum.clone(),
                approver: "attacker@untrusted.org".into(),
                timestamp: "2026-10-24T00:00:00Z".into(),
                valid_until: "2026-10-24T01:00:00Z".into(),
                signature: "forged-sig".into(),
            },
            &plan_checksum,
        );
        assert!(
            verify_res.is_err(),
            "Forged approval receipt must fail closed"
        );
    }

    // Direct execute without approved apply flag
    assert_eq!(fs::read_to_string(&pkg_file).unwrap(), original_pkg);
    assert_eq!(fs::read_to_string(&js_file).unwrap(), original_js);
}

#[test]
fn test_m0_characterization_incomplete_coverage_is_not_clean() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    let report = ScanReport {
        target_dir: root.to_path_buf(),
        scan_time: "2026-10-24T00:00:00Z".into(),
        total_files_scanned: 10,
        findings: vec![], // Zero findings!
        is_vulnerable: false,
        critical_count: 0,
        high_count: 0,
        coverage: ScanCoverage {
            files_scanned: 8,
            files_excluded: 2,
            parser_failures: vec![ParserFailure {
                path: root.join("corrupted.json"),
                reason: "Unexpected EOF while parsing JSON".into(),
            }],
            unsupported_targets: vec!["custom.dsl".into()],
            coverage_status: CoverageStatus::Partial,
            receipts: vec![],
        },
    };

    // Incomplete coverage with zero findings MUST NOT report is_clean() == true!
    assert!(
        !report.is_clean(),
        "Report with parser failures or partial coverage must NEVER report clean!"
    );
}
