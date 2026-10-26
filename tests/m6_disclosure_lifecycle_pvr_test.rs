//! Integration tests for Milestone M6: Responsible Disclosure, Lifecycle State Machine,
//! GitHub PVR Formatting, and Offline Guarantees conforming to Chapter 12 and Card M6.1.

use bug_killer::disclosure::{
    AffectedTarget, ContactChannel, DisclosureDraftBuilder, DisclosureLifecycleState,
    DisclosurePacket, DisclosureSeverity, DisclosureStateError, DisclosureValidationError,
    ReporterInfo, RootCause, SafeReproduction, SecurityImpact, SuggestedMitigation,
};
use bug_killer::engine::protocol::{
    EngineDescriptor, EvidenceCertaintyV1, FindingKind, FindingStatus, FindingV1,
    NormalizedSeverity, NormalizedTargetKind, TargetDescriptor,
};
use bug_killer::hunter::candidate::{CandidateState, ReproductionArtifact, ResearchCandidate};

fn sample_sha256() -> String {
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string()
}

#[test]
fn test_disclosure_lifecycle_state_machine_valid_transitions() {
    let mut state = DisclosureLifecycleState::PrivateDraft;
    assert!(!state.is_submittable());
    assert!(!state.is_terminal());

    // 1. PrivateDraft -> UserReviewed
    state
        .transition_to(DisclosureLifecycleState::UserReviewed)
        .expect("PrivateDraft -> UserReviewed must succeed");
    assert_eq!(state, DisclosureLifecycleState::UserReviewed);
    assert!(state.is_submittable());
    assert!(!state.is_terminal());

    // 2. UserReviewed -> SubmittedPrivately
    state
        .transition_to(DisclosureLifecycleState::SubmittedPrivately)
        .expect("UserReviewed -> SubmittedPrivately must succeed");
    assert_eq!(state, DisclosureLifecycleState::SubmittedPrivately);
    assert!(!state.is_submittable());
    assert!(!state.is_terminal());

    // 3. SubmittedPrivately -> MaintainerTriaged
    state
        .transition_to(DisclosureLifecycleState::MaintainerTriaged)
        .expect("SubmittedPrivately -> MaintainerTriaged must succeed");
    assert_eq!(state, DisclosureLifecycleState::MaintainerTriaged);
    assert!(!state.is_submittable());
    assert!(!state.is_terminal());

    // 4. MaintainerTriaged -> FixAvailable
    state
        .transition_to(DisclosureLifecycleState::FixAvailable)
        .expect("MaintainerTriaged -> FixAvailable must succeed");
    assert_eq!(state, DisclosureLifecycleState::FixAvailable);
    assert!(!state.is_submittable());
    assert!(!state.is_terminal());

    // 5. FixAvailable -> CoordinatedPublished
    state
        .transition_to(DisclosureLifecycleState::CoordinatedPublished)
        .expect("FixAvailable -> CoordinatedPublished must succeed");
    assert_eq!(state, DisclosureLifecycleState::CoordinatedPublished);
    assert!(!state.is_submittable());
    assert!(state.is_terminal());
}

#[test]
fn test_disclosure_lifecycle_illegal_transitions_fail_closed() {
    let mut draft = DisclosureLifecycleState::PrivateDraft;

    // Direct transition to SubmittedPrivately is strictly forbidden without UserReviewed
    let err = draft.transition_to(DisclosureLifecycleState::SubmittedPrivately);
    assert!(err.is_err());
    assert_eq!(
        err.unwrap_err(),
        DisclosureStateError::InvalidTransition {
            from: DisclosureLifecycleState::PrivateDraft,
            to: DisclosureLifecycleState::SubmittedPrivately,
        }
    );

    // Direct transition to CoordinatedPublished is strictly forbidden
    let pub_err = draft.transition_to(DisclosureLifecycleState::CoordinatedPublished);
    assert!(pub_err.is_err());

    // Terminal states cannot transition to other states without reactivation
    let mut terminal_withdrawn = DisclosureLifecycleState::Withdrawn;
    let term_err = terminal_withdrawn.transition_to(DisclosureLifecycleState::SubmittedPrivately);
    assert!(term_err.is_err());
    assert_eq!(
        term_err.unwrap_err(),
        DisclosureStateError::InvalidTransition {
            from: DisclosureLifecycleState::Withdrawn,
            to: DisclosureLifecycleState::SubmittedPrivately,
        }
    );

    // Reactivation to PrivateDraft is explicitly permitted
    terminal_withdrawn
        .reactivate()
        .expect("Reactivation must succeed");
    assert_eq!(terminal_withdrawn, DisclosureLifecycleState::PrivateDraft);

    // Published state cannot even be reactivated
    let mut published = DisclosureLifecycleState::CoordinatedPublished;
    let pub_reactivate_err = published.reactivate();
    assert!(pub_reactivate_err.is_err());
}

#[test]
fn test_github_pvr_markdown_rendering() {
    let packet = DisclosureDraftBuilder::new()
        .packet_id("packet-f1e2d3c4b5a60718")
        .draft_id("draft-2026-cve-prep")
        .finding_id("finding-novel-zip-001")
        .title("Path Traversal in ExtractArchive Leading to Arbitrary File Overwrite")
        .vulnerability_type("Directory Traversal")
        .severity(DisclosureSeverity::High)
        .affected_target(AffectedTarget {
            package: "example-archive-pkg".to_string(),
            commit_range: "v1.0.0..v1.3.2".to_string(),
            repository: "https://github.com/example/archive-pkg".to_string(),
            source_snapshot_sha256: sample_sha256(),
        })
        .security_impact(SecurityImpact {
            prerequisites: "Target application unpacks an untrusted archive.".to_string(),
            attack_vector: "Local".to_string(),
            privileges_required: "None".to_string(),
            user_interaction: "Required".to_string(),
            scope: "Unchanged".to_string(),
            confidential_impact: "None".to_string(),
            integrity_impact: "High".to_string(),
            availability_impact: "Low".to_string(),
        })
        .safe_reproduction(SafeReproduction {
            test_type: "offline_unit_test".to_string(),
            harness_code: "fn test_reproduce_traversal() { let archive = fixture(\"../../test.txt\"); assert!(extract(&archive).is_err()); }".to_string(),
            sanitized_input: "archive_entry: ../../harmless_synthetic_target.txt".to_string(),
            expected_behavior: "Extraction verifies destination path and rejects escaping entries.".to_string(),
            observed_behavior: "Extraction writes outside destination directory.".to_string(),
        })
        .root_cause(RootCause {
            summary: "Canonicalization omitted before file creation.".to_string(),
            cwe_id: "CWE-22".to_string(),
            trace_evidence_hashes: vec![sample_sha256()],
        })
        .suggested_mitigation(SuggestedMitigation {
            diff: "--- a/extract.rs\n+++ b/extract.rs\n@@ -1,1 +1,3 @@\n+    ensure_destination_boundary(&dest)?;\n".to_string(),
            compatibility_notes: "Fully backward-compatible with legitimate archives.".to_string(),
            fixed_versions: vec!["1.3.3".to_string()],
        })
        .contact_channel(ContactChannel {
            channel_type: "GitHubPrivateVulnerabilityReporting".to_string(),
            contact_target: "example/archive-pkg#pvr".to_string(),
            security_policy_url: Some("https://github.com/example/archive-pkg/security/policy".to_string()),
        })
        .reporter(ReporterInfo {
            credit_name: "Bug Killer Autonomous Security Lab".to_string(),
            contact_email: "security-research@example.com".to_string(),
            embargo_requested_days: 90,
        })
        .build()
        .expect("Valid packet must build cleanly");

    let pvr_md = packet.to_github_pvr_markdown();

    // Verify all mandatory PVR sections
    assert!(pvr_md.contains("# [PVR Draft] Path Traversal in ExtractArchive"));
    assert!(pvr_md.contains("## Summary"));
    assert!(pvr_md.contains("## Severity & Impact"));
    assert!(pvr_md.contains("## Affected Components"));
    assert!(pvr_md.contains("## Safe Reproduction Steps (Offline Unit / Property Test)"));
    assert!(pvr_md.contains("## Root Cause Analysis"));
    assert!(pvr_md.contains("## Proposed Fix / Mitigation"));
    assert!(pvr_md.contains("## Coordination & Embargo Timeline"));

    // Verify key fields
    assert!(pvr_md.contains("**Finding ID**: `finding-novel-zip-001`"));
    assert!(pvr_md.contains("**Severity**: High"));
    assert!(pvr_md.contains("**CWE**: `CWE-22`"));
    assert!(pvr_md.contains("90 days"));
    assert!(pvr_md.contains("example/archive-pkg#pvr"));
}

#[test]
fn test_defensive_perimeter_prohibits_weaponized_payloads() {
    let res = DisclosureDraftBuilder::new()
        .finding_id("finding-novel-001")
        .title("Valid title")
        .vulnerability_type("Buffer Overflow")
        .safe_reproduction(SafeReproduction {
            test_type: "offline_unit_test".to_string(),
            harness_code: "fn test() { let shellcode = \"\\x90\\x90\\x90\\x31\\xc0\"; }"
                .to_string(),
            sanitized_input: "test".to_string(),
            expected_behavior: "safe".to_string(),
            observed_behavior: "crash".to_string(),
        })
        .root_cause(RootCause {
            summary: "Buffer overflow".to_string(),
            cwe_id: "CWE-120".to_string(),
            trace_evidence_hashes: vec![],
        })
        .build();

    assert!(res.is_err());
    let err = res.unwrap_err();
    assert!(matches!(
        err,
        DisclosureValidationError::WeaponizedPayloadDetected(_)
    ));
}

#[test]
fn test_draft_builder_from_finding_v1() {
    let finding = FindingV1 {
        schema_version: "1.0".to_string(),
        run_id: "run-test-101".to_string(),
        finding_id: "finding-fuzz-007".to_string(),
        fingerprint: Some("fp-abc1234567890".to_string()),
        kind: FindingKind::ResearchCandidate,
        status: FindingStatus::Verified,
        title: "Integer Overflow in Memory Allocation".to_string(),
        summary: Some(
            "Arithmetic wrap leads to tiny heap allocation followed by out of bounds copy."
                .to_string(),
        ),
        severity: NormalizedSeverity::Critical,
        evidence_certainty: EvidenceCertaintyV1::Confirmed,
        engine: EngineDescriptor {
            id: "bk-fuzz-hunter".to_string(),
            version: "0.1.0".to_string(),
            rule_pack_sha256: Some(sample_sha256()),
        },
        target: TargetDescriptor {
            target_id: "src/allocator.c".to_string(),
            kind: NormalizedTargetKind::File,
            path: Some("src/allocator.c".to_string()),
            package_purl: None,
            version: None,
            span: None,
        },
        source_snapshot_sha256: sample_sha256(),
        evidence: vec![],
        coverage_receipt_ids: vec!["receipt-01".to_string()],
        advisory_ids: vec![],
        rule_id: Some("CWE-190".to_string()),
        weakness_ids: vec!["CWE-190".to_string()],
        uncertainty_reasons: vec![],
        proof: None,
        remediation_plan_id: None,
        created_at: "2026-10-26T00:00:00Z".to_string(),
        updated_at: Some("2026-10-26T00:00:00Z".to_string()),
        extensions: serde_json::Map::new(),
    };

    let packet = DisclosureDraftBuilder::from_finding(&finding)
        .build()
        .expect("Packet validation must succeed");

    assert_eq!(packet.finding_id, "finding-fuzz-007");
    assert_eq!(packet.severity, DisclosureSeverity::Critical);
    assert_eq!(packet.root_cause.cwe_id, "CWE-190");
    assert_eq!(
        packet.lifecycle_state,
        DisclosureLifecycleState::PrivateDraft
    );
}

#[test]
fn test_draft_builder_from_research_candidate() {
    let candidate = ResearchCandidate {
        candidate_id: "cand-arith-001".to_string(),
        target_path: "src/parser.rs".to_string(),
        title: "Missing integer check causes buffer overrun".to_string(),
        weakness: "CWE-120".to_string(),
        hypothesis: "Missing integer check causes buffer overrun".to_string(),
        state: CandidateState::Verified,
        reproduction_artifact: Some(ReproductionArtifact::new(
            b"raw_trigger".to_vec(),
            b"minimized".to_vec(),
            "Process terminated with SIGSEGV",
        )),
        created_at: "2026-10-26T00:00:00Z".to_string(),
        updated_at: "2026-10-26T00:00:00Z".to_string(),
    };

    let packet = DisclosureDraftBuilder::from_candidate(&candidate, &sample_sha256())
        .build()
        .expect("Packet validation must succeed");

    assert_eq!(packet.finding_id, "cand-arith-001");
    assert_eq!(packet.root_cause.cwe_id, "CWE-120");
    assert_eq!(
        packet.lifecycle_state,
        DisclosureLifecycleState::PrivateDraft
    );
    assert!(
        packet
            .safe_reproduction
            .observed_behavior
            .contains("SIGSEGV")
    );
}

#[test]
fn test_json_schema_roundtrip_fidelity() {
    let packet = DisclosureDraftBuilder::new()
        .packet_id("packet-0011223344556677")
        .draft_id("draft-test-roundtrip")
        .finding_id("finding-json-001")
        .title("SQL Injection in Query Builder")
        .vulnerability_type("SQL Injection")
        .severity(DisclosureSeverity::High)
        .root_cause(RootCause {
            summary: "Unsanitized input concatenated into query string.".to_string(),
            cwe_id: "CWE-89".to_string(),
            trace_evidence_hashes: vec![sample_sha256()],
        })
        .safe_reproduction(SafeReproduction {
            test_type: "offline_unit_test".to_string(),
            harness_code: "fn test() { let q = build_query(\"test' OR '1'='1\"); assert!(!q.contains(\"OR\")); }".to_string(),
            sanitized_input: "input: test' OR '1'='1".to_string(),
            expected_behavior: "Parameter is properly escaped or parameterized.".to_string(),
            observed_behavior: "Raw single quote inserted into SQL query string.".to_string(),
        })
        .build()
        .expect("Building packet must succeed");

    let json = packet
        .to_json()
        .expect("Serialization to JSON must succeed");
    let deserialized: DisclosurePacket =
        DisclosurePacket::from_json(&json).expect("Deserialization from JSON must succeed");

    assert_eq!(packet, deserialized);
    assert_eq!(packet.schema_version, "1.0");
}
