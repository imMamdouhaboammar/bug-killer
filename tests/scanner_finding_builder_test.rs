// @lat: [[tests#Scanner Finding Builder Parity Tests]]
use bug_killer::scanner::auth::AuthSecurityScanner;
use bug_killer::scanner::finding_builder::{ScannerFindingBuilder, ScannerFindingSpec};
use bug_killer::scanner::native_desktop::NativeDesktopScanner;
use bug_killer::types::{
    Affectedness, Confidence, CveId, EvidenceCertainty, Finding, Reachability, Severity, TargetKind,
};
use std::collections::HashSet;
use std::path::Path;

#[test]
fn test_scanner_finding_builder_defaults_and_spec() {
    let path = Path::new("src/auth/login.ts");
    let target_kind = TargetKind::NodeSourceFile;
    let spec = ScannerFindingSpec {
        rule_id: "BK-AI-AUT-001",
        title: "Protected route lacks server-side authentication",
        severity: Severity::High,
        category: "2.2 Authentication and account lifecycle",
        path,
        target_kind: &target_kind,
        line_no: 42,
        snippet: "app.get('/admin', (req, res) => {})",
        safe_threshold: "Protected routes must declare server-side auth middleware.",
        description: "Route handler directly exposes an admin endpoint without authentication.",
        remediation: "Add requireAuth middleware before handler.",
    };

    let builder = ScannerFindingBuilder::new(spec.clone());
    assert_eq!(builder.spec().rule_id, "BK-AI-AUT-001");
    assert_eq!(builder.spec().line_no, 42);

    let finding = builder.build();
    assert_eq!(finding.id, "AUT-001-login.ts-L42");
    assert_eq!(
        finding.cve,
        CveId::Custom {
            id: "BK-AI-AUT-001".to_string(),
            title: "Protected route lacks server-side authentication".to_string(),
        }
    );
    assert_eq!(finding.severity, Severity::High);
    assert_eq!(finding.target_kind, TargetKind::NodeSourceFile);
    assert_eq!(finding.file_path, Some(path.to_path_buf()));
    assert_eq!(finding.line_number, Some(42));
    assert_eq!(finding.detector_id, "generic-scanner");
    assert_eq!(finding.detector_version, "1.0.0");
    assert_eq!(finding.category, "2.2 Authentication and account lifecycle");
    assert_eq!(finding.affectedness, Affectedness::ConfirmedAffected);
    assert_eq!(finding.reachability, Reachability::PotentiallyReachable);
    assert_eq!(finding.confidence, Confidence::High);
    assert_eq!(
        finding.evidence_certainty,
        EvidenceCertainty::StronglySupported
    );
    assert!(finding.advisory_ids.is_empty());

    // Evidence ref verification
    assert_eq!(finding.evidence_refs.len(), 1);
    let ev = &finding.evidence_refs[0];
    assert_eq!(ev.location, "src/auth/login.ts:42");
    assert_eq!(ev.line_number, Some(42));
    assert_eq!(
        ev.snippet.as_deref(),
        Some("app.get('/admin', (req, res) => {})")
    );
    assert_eq!(ev.sha256, None);

    // Deterministic deduplication fingerprint
    let mut expected_finding = finding.clone();
    expected_finding.compute_dedupe_fingerprint();
    assert_eq!(
        finding.dedupe_fingerprint,
        expected_finding.dedupe_fingerprint
    );
    assert!(!finding.dedupe_fingerprint.is_empty());
}

#[test]
fn test_scanner_finding_builder_deduplication_semantics() {
    let path = Path::new("src/native/mem.c");
    let target_kind = TargetKind::NodeSourceFile;
    let spec1 = ScannerFindingSpec {
        rule_id: "BK-AI-MEM-004",
        title: "Null pointer dereference",
        severity: Severity::High,
        category: "2.18 Native code, FFI and memory safety",
        path,
        target_kind: &target_kind,
        line_no: 10,
        snippet: "*raw_ptr = 42;",
        safe_threshold: "Check null before deref",
        description: "Deref without check",
        remediation: "if (ptr != NULL)",
    };

    let mut findings: Vec<Finding> = Vec::new();
    let mut seen: HashSet<(String, usize)> = HashSet::new();

    // First push succeeds
    let pushed =
        ScannerFindingBuilder::native_desktop(spec1.clone()).push_deduped(&mut findings, &mut seen);
    assert!(pushed);
    assert_eq!(findings.len(), 1);

    // Duplicate (same rule_id and line_no) is rejected
    let pushed_again =
        ScannerFindingBuilder::native_desktop(spec1).push_deduped(&mut findings, &mut seen);
    assert!(!pushed_again);
    assert_eq!(findings.len(), 1);

    // Distinct line number succeeds
    let spec2 = ScannerFindingSpec {
        rule_id: "BK-AI-MEM-004",
        title: "Null pointer dereference",
        severity: Severity::High,
        category: "2.18 Native code, FFI and memory safety",
        path,
        target_kind: &target_kind,
        line_no: 25,
        snippet: "*raw_ptr = 84;",
        safe_threshold: "Check null before deref",
        description: "Deref without check",
        remediation: "if (ptr != NULL)",
    };
    let pushed_line25 =
        ScannerFindingBuilder::native_desktop(spec2).push_deduped(&mut findings, &mut seen);
    assert!(pushed_line25);
    assert_eq!(findings.len(), 2);
}

#[test]
fn test_native_desktop_golden_semantics_preserved() {
    let source = r#"
fn deref_raw(raw_ptr: *const i32) -> i32 {
    unsafe {
        *raw_ptr
    }
}
"#;
    let path = Path::new("src/ffi/pointer.rs");
    let findings = NativeDesktopScanner::scan_source(path, source);

    assert_eq!(findings.len(), 1);
    let f = &findings[0];

    assert_eq!(f.id, "MEM-004-pointer.rs-L4");
    assert_eq!(f.cve.as_str(), "BK-AI-MEM-004");
    assert_eq!(f.severity, Severity::High);
    assert_eq!(f.detector_id, "native-desktop");
    assert_eq!(f.detector_version, "1.0.0");
    assert_eq!(f.category, "2.18 Native code, FFI and memory safety");
    assert_eq!(f.reachability, Reachability::PotentiallyReachable);
    assert_eq!(f.confidence, Confidence::High);
    assert_eq!(f.affectedness, Affectedness::ConfirmedAffected);
    assert_eq!(f.evidence_certainty, EvidenceCertainty::StronglySupported);
    assert_eq!(
        f.advisory_ids,
        vec!["CWE-476".to_string(), "BK-AI-MEM-004".to_string()]
    );
    assert_eq!(f.evidence_refs.len(), 1);
    assert_eq!(f.evidence_refs[0].location, "src/ffi/pointer.rs:4");
    assert_eq!(f.evidence_refs[0].line_number, Some(4));
    assert_eq!(f.evidence_refs[0].snippet.as_deref(), Some("*raw_ptr"));
    assert!(!f.dedupe_fingerprint.is_empty());
}

#[test]
fn test_auth_security_golden_semantics_preserved() {
    let source = r#"
const express = require('express');
const app = express();

app.get('/admin', (req, res) => {
    res.send('secret admin page');
});
"#;
    let path = Path::new("server/routes/admin.js");
    let findings = AuthSecurityScanner::scan_source(path, source);

    assert_eq!(findings.len(), 1);
    let f = &findings[0];

    assert_eq!(f.id, "AUT-001-admin.js-L5");
    assert_eq!(f.cve.as_str(), "BK-AI-AUT-001");
    assert_eq!(f.severity, Severity::High);
    assert_eq!(f.detector_id, "auth-security");
    assert_eq!(f.detector_version, "1.0.0");
    assert_eq!(f.category, "2.2 Authentication and account lifecycle");
    assert_eq!(f.reachability, Reachability::ConfirmedReachable);
    assert_eq!(f.confidence, Confidence::High);
    assert_eq!(f.affectedness, Affectedness::ConfirmedAffected);
    assert_eq!(f.evidence_certainty, EvidenceCertainty::StronglySupported);
    assert!(f.advisory_ids.is_empty());
    assert_eq!(f.evidence_refs.len(), 1);
    assert_eq!(f.evidence_refs[0].location, "server/routes/admin.js:5");
    assert_eq!(f.evidence_refs[0].line_number, Some(5));
    assert!(!f.dedupe_fingerprint.is_empty());
}
