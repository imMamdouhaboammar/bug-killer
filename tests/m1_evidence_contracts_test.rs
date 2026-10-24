use bug_killer::types::*;
use std::path::PathBuf;

#[test]
fn test_m1_coverage_receipt_contract_and_serialization() {
    let receipt = CoverageReceipt {
        scanner_id: "sca-osv".into(),
        scanner_version: "1.0.0".into(),
        target_id: "npm/package-lock.json".into(),
        status: CoverageStatus::Complete,
        items_examined: 42,
        skipped_reasons: vec![],
        errors: vec![],
        completed_at: "2026-10-24T12:00:00Z".into(),
    };

    let serialized = serde_json::to_string_pretty(&receipt).expect("Serialization failed");
    let deserialized: CoverageReceipt =
        serde_json::from_str(&serialized).expect("Deserialization failed");

    assert_eq!(deserialized.scanner_id, "sca-osv");
    assert_eq!(deserialized.status, CoverageStatus::Complete);
    assert_eq!(deserialized.items_examined, 42);
}

#[test]
fn test_m1_coverage_receipt_error_prevents_clean_status() {
    let receipt_error = CoverageReceipt {
        scanner_id: "sca-osv".into(),
        scanner_version: "1.0.0".into(),
        target_id: "workspace".into(),
        status: CoverageStatus::Error,
        items_examined: 5,
        skipped_reasons: vec![],
        errors: vec!["OSV API HTTP 503 Service Unavailable".into()],
        completed_at: "2026-10-24T12:00:00Z".into(),
    };

    let coverage = ScanCoverage {
        files_scanned: 10,
        files_excluded: 0,
        parser_failures: vec![],
        unsupported_targets: vec![],
        coverage_status: CoverageStatus::Complete,
        receipts: vec![receipt_error],
    };

    let report = ScanReport {
        target_dir: PathBuf::from("."),
        scan_time: "2026-10-24T12:00:00Z".into(),
        total_files_scanned: 10,
        findings: vec![], // Zero findings!
        is_vulnerable: false,
        critical_count: 0,
        high_count: 0,
        coverage,
    };

    // A scanner error in receipts MUST prevent the scan from falsely reporting clean!
    assert!(
        !report.is_clean(),
        "Report with scanner error receipt must NOT report clean even with zero findings"
    );
}

#[test]
fn test_m1_backward_compatibility_old_scan_report_json() {
    // Legacy JSON from v0.1.0 without 'receipts' and without 'evidence_certainty'
    let legacy_json = r#"{
  "target_dir": "/tmp/test",
  "scan_time": "2026-10-24T10:00:00Z",
  "total_files_scanned": 5,
  "findings": [
    {
      "id": "legacy-finding-1",
      "cve": { "Custom": { "id": "CVE-2026-0001", "title": "Test CVE" } },
      "severity": "High",
      "target_kind": "GenericSourceFile",
      "file_path": "/tmp/test/app.js",
      "line_number": 12,
      "detected_version_or_pattern": "eval(x)",
      "safe_threshold": "None",
      "description": "Legacy finding",
      "suggested_remediation": "Do not use eval"
    }
  ],
  "is_vulnerable": true,
  "critical_count": 0,
  "high_count": 1,
  "coverage": {
    "files_scanned": 5,
    "files_excluded": 0,
    "parser_failures": [],
    "unsupported_targets": [],
    "coverage_status": "Complete"
  }
}"#;

    let report: ScanReport =
        serde_json::from_str(legacy_json).expect("Legacy JSON must deserialize");
    assert_eq!(report.findings.len(), 1);
    assert_eq!(
        report.findings[0].evidence_certainty,
        EvidenceCertainty::Unknown
    );
    assert!(report.coverage.receipts.is_empty());
    assert_eq!(report.coverage.coverage_status, CoverageStatus::Complete);
}

#[test]
fn test_m1_evidence_certainty_labels() {
    assert_eq!(EvidenceCertainty::Confirmed.as_str(), "CONFIRMED");
    assert_eq!(
        EvidenceCertainty::StronglySupported.as_str(),
        "STRONGLY_SUPPORTED"
    );
    assert_eq!(EvidenceCertainty::Suspected.as_str(), "SUSPECTED");
    assert_eq!(
        EvidenceCertainty::PatternIndicator.as_str(),
        "PATTERN_INDICATOR"
    );
    assert_eq!(EvidenceCertainty::Unknown.as_str(), "UNKNOWN");
}
