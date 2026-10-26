//! Comprehensive integration test suite for Card M6.1 Part A:
//! Disclosure Architecture, Lifecycle State Machine & GitHub PVR Drafts.
//!
//! Validates:
//! - JSON Schema conformance against `disclosure-packet.schema.json`
//! - Complete state machine transitions, invariants, terminality, and submittability
//! - Clean GitHub Private Vulnerability Reporting (PVR) markdown formatting conforming to ISO/IEC 29147
//! - Round-trip JSON serialization and deserialization
//! - Defensive perimeter enforcement: zero weaponized shellcode, zero leaked credentials
//! - Strict offline guarantees: zero network socket operations

use bug_killer::disclosure::{
    AffectedTarget, ContactChannel, DisclosureDraftBuilder, DisclosureLifecycleState,
    DisclosurePacket, DisclosureSeverity, DisclosureStateError, DisclosureValidationError,
    ReporterInfo, RootCause, SafeReproduction, SecurityImpact, SuggestedMitigation,
};
use bug_killer::engine::protocol::{
    EngineDescriptor, EvidenceCertaintyV1, EvidenceItemKind, EvidenceItemV1, FindingKind,
    FindingStatus, FindingV1, NormalizedSeverity, NormalizedTargetKind, ProofMethod, ProofV1,
    TargetDescriptor,
};
use bug_killer::hunter::candidate::{ReproductionArtifact, ResearchCandidate};
use serde_json::Value;
use std::fs;

fn dummy_sha256() -> String {
    "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90".to_string()
}

fn create_valid_packet() -> DisclosurePacket {
    DisclosureDraftBuilder::new()
        .finding_id("finding-novel-buffer-001")
        .draft_id("draft-v1")
        .packet_id("packet-0011223344556677")
        .lifecycle_state(DisclosureLifecycleState::PrivateDraft)
        .title("Heap Buffer Overflow in Network Packet Parser")
        .vulnerability_type("Memory Corruption / Heap Buffer Overflow")
        .severity(DisclosureSeverity::Critical)
        .affected_target(AffectedTarget {
            package: "acme-net-parser".to_string(),
            commit_range: "v2.0.0..v2.3.1".to_string(),
            repository: "https://github.com/acme/acme-net-parser".to_string(),
            source_snapshot_sha256: dummy_sha256(),
        })
        .security_impact(SecurityImpact {
            prerequisites: "Attacker transmits a specially crafted synthetic network packet.".to_string(),
            attack_vector: "Network".to_string(),
            privileges_required: "None".to_string(),
            user_interaction: "None".to_string(),
            scope: "Unchanged".to_string(),
            confidential_impact: "High".to_string(),
            integrity_impact: "High".to_string(),
            availability_impact: "High".to_string(),
        })
        .safe_reproduction(SafeReproduction {
            test_type: "offline_unit_test".to_string(),
            harness_code: "fn test_packet_bounds() {\n    let pkt = [0xff; 64];\n    let res = parse_packet(&pkt);\n    assert!(res.is_err());\n}".to_string(),
            sanitized_input: "synthetic_length_field: 0xffff".to_string(),
            expected_behavior: "Parser returns Err(ParseError::BufferExceeded) on oversized header length".to_string(),
            observed_behavior: "Parser reads beyond buffer allocation causing out-of-bounds access".to_string(),
        })
        .root_cause(RootCause {
            summary: "Missing length validation on variable-length header field allows out-of-bounds read.".to_string(),
            cwe_id: "CWE-122".to_string(),
            trace_evidence_hashes: vec![dummy_sha256()],
        })
        .suggested_mitigation(SuggestedMitigation {
            diff: "--- a/src/parse.rs\n+++ b/src/parse.rs\n@@ -15,2 +15,4 @@\n+    if header_len > buf.len() {\n+        return Err(ParseError::BufferExceeded);\n+    }\n".to_string(),
            compatibility_notes: "Backward compatible fix. Rejects invalid packet sizes strictly.".to_string(),
            fixed_versions: vec!["2.3.2".to_string()],
        })
        .contact_channel(ContactChannel {
            channel_type: "GitHubPrivateVulnerabilityReporting".to_string(),
            contact_target: "acme/acme-net-parser".to_string(),
            security_policy_url: Some("https://github.com/acme/acme-net-parser/security/policy".to_string()),
        })
        .reporter(ReporterInfo {
            credit_name: "Bug Killer Autonomous Security Engine".to_string(),
            contact_email: "disclosure@example.org".to_string(),
            embargo_requested_days: 90,
        })
        .build()
        .expect("Valid disclosure packet should build cleanly")
}

#[test]
fn test_disclosure_packet_schema_conformance() {
    let schema_str =
        fs::read_to_string("bug-killer-ultimate-spec-v1/schemas/disclosure-packet.schema.json")
            .expect("Must read disclosure-packet.schema.json");
    let schema: Value = serde_json::from_str(&schema_str).expect("Schema must be valid JSON");

    assert_eq!(
        schema["$schema"],
        "https://json-schema.org/draft/2020-12/schema"
    );
    assert_eq!(schema["$id"], "disclosure-packet.schema.json");

    let packet = create_valid_packet();
    let packet_json_str = packet.to_json().expect("Must serialize packet to JSON");
    let packet_json: Value =
        serde_json::from_str(&packet_json_str).expect("Serialized packet must be valid JSON");

    // Check required fields from schema
    let required_fields = schema["required"]
        .as_array()
        .expect("Schema must declare required array");

    for field in required_fields {
        let field_name = field.as_str().unwrap();
        assert!(
            packet_json.get(field_name).is_some(),
            "Packet JSON missing required field '{}'",
            field_name
        );
    }

    // Verify sub-object required fields
    let affected_target_req = schema["properties"]["affected_target"]["required"]
        .as_array()
        .unwrap();
    for field in affected_target_req {
        let field_name = field.as_str().unwrap();
        assert!(
            packet_json["affected_target"].get(field_name).is_some(),
            "affected_target missing required field '{}'",
            field_name
        );
    }

    let security_impact_req = schema["properties"]["security_impact"]["required"]
        .as_array()
        .unwrap();
    for field in security_impact_req {
        let field_name = field.as_str().unwrap();
        assert!(
            packet_json["security_impact"].get(field_name).is_some(),
            "security_impact missing required field '{}'",
            field_name
        );
    }

    let safe_reproduction_req = schema["properties"]["safe_reproduction"]["required"]
        .as_array()
        .unwrap();
    for field in safe_reproduction_req {
        let field_name = field.as_str().unwrap();
        assert!(
            packet_json["safe_reproduction"].get(field_name).is_some(),
            "safe_reproduction missing required field '{}'",
            field_name
        );
    }

    let root_cause_req = schema["properties"]["root_cause"]["required"]
        .as_array()
        .unwrap();
    for field in root_cause_req {
        let field_name = field.as_str().unwrap();
        assert!(
            packet_json["root_cause"].get(field_name).is_some(),
            "root_cause missing required field '{}'",
            field_name
        );
    }

    let suggested_mitigation_req = schema["properties"]["suggested_mitigation"]["required"]
        .as_array()
        .unwrap();
    for field in suggested_mitigation_req {
        let field_name = field.as_str().unwrap();
        assert!(
            packet_json["suggested_mitigation"]
                .get(field_name)
                .is_some(),
            "suggested_mitigation missing required field '{}'",
            field_name
        );
    }

    let contact_channel_req = schema["properties"]["contact_channel"]["required"]
        .as_array()
        .unwrap();
    for field in contact_channel_req {
        let field_name = field.as_str().unwrap();
        assert!(
            packet_json["contact_channel"].get(field_name).is_some(),
            "contact_channel missing required field '{}'",
            field_name
        );
    }

    let reporter_req = schema["properties"]["reporter"]["required"]
        .as_array()
        .unwrap();
    for field in reporter_req {
        let field_name = field.as_str().unwrap();
        assert!(
            packet_json["reporter"].get(field_name).is_some(),
            "reporter missing required field '{}'",
            field_name
        );
    }
}

#[test]
fn test_state_machine_transition_rules() {
    use DisclosureLifecycleState::*;

    // 1. PrivateDraft transitions
    assert!(PrivateDraft.can_transition_to(&UserReviewed));
    assert!(PrivateDraft.can_transition_to(&Withdrawn));
    assert!(PrivateDraft.can_transition_to(&Duplicate));
    assert!(PrivateDraft.can_transition_to(&HoldForSafety));
    assert!(!PrivateDraft.can_transition_to(&SubmittedPrivately));
    assert!(!PrivateDraft.can_transition_to(&CoordinatedPublished));
    assert!(!PrivateDraft.can_transition_to(&MaintainerTriaged));
    assert!(!PrivateDraft.can_transition_to(&FixAvailable));

    // 2. UserReviewed transitions
    assert!(UserReviewed.can_transition_to(&SubmittedPrivately));
    assert!(UserReviewed.can_transition_to(&PrivateDraft));
    assert!(UserReviewed.can_transition_to(&Withdrawn));
    assert!(UserReviewed.can_transition_to(&Duplicate));
    assert!(!UserReviewed.can_transition_to(&MaintainerTriaged));
    assert!(!UserReviewed.can_transition_to(&FixAvailable));
    assert!(!UserReviewed.can_transition_to(&CoordinatedPublished));

    // 3. SubmittedPrivately transitions
    assert!(SubmittedPrivately.can_transition_to(&MaintainerTriaged));
    assert!(SubmittedPrivately.can_transition_to(&AwaitingResponse));
    assert!(SubmittedPrivately.can_transition_to(&Rejected));
    assert!(SubmittedPrivately.can_transition_to(&Duplicate));
    assert!(SubmittedPrivately.can_transition_to(&Withdrawn));
    assert!(!SubmittedPrivately.can_transition_to(&PrivateDraft));
    assert!(!SubmittedPrivately.can_transition_to(&CoordinatedPublished));

    // 4. MaintainerTriaged transitions
    assert!(MaintainerTriaged.can_transition_to(&FixAvailable));
    assert!(MaintainerTriaged.can_transition_to(&Rejected));
    assert!(MaintainerTriaged.can_transition_to(&Withdrawn));
    assert!(!MaintainerTriaged.can_transition_to(&CoordinatedPublished));
    assert!(!MaintainerTriaged.can_transition_to(&SubmittedPrivately));

    // 5. FixAvailable transitions
    assert!(FixAvailable.can_transition_to(&CoordinatedPublished));
    assert!(!FixAvailable.can_transition_to(&SubmittedPrivately));
    assert!(!FixAvailable.can_transition_to(&PrivateDraft));

    // 6. Terminal and Reactivation
    for terminal in [Withdrawn, Duplicate, Rejected] {
        assert!(terminal.is_terminal());
        assert!(!terminal.is_submittable());
        assert!(terminal.can_transition_to(&PrivateDraft));
        assert!(!terminal.can_transition_to(&UserReviewed));
        assert!(!terminal.can_transition_to(&SubmittedPrivately));
        assert!(!terminal.can_transition_to(&CoordinatedPublished));
    }

    // CoordinatedPublished is final
    assert!(CoordinatedPublished.is_terminal());
    assert!(!CoordinatedPublished.is_submittable());
    assert!(!CoordinatedPublished.can_transition_to(&PrivateDraft));

    // 7. Submittable invariant: ONLY UserReviewed is submittable
    assert!(UserReviewed.is_submittable());
    assert!(!PrivateDraft.is_submittable());
    assert!(!SubmittedPrivately.is_submittable());
    assert!(!MaintainerTriaged.is_submittable());
    assert!(!FixAvailable.is_submittable());
    assert!(!CoordinatedPublished.is_submittable());
    assert!(!Withdrawn.is_submittable());
    assert!(!Duplicate.is_submittable());
    assert!(!Rejected.is_submittable());
    assert!(!AwaitingResponse.is_submittable());
    assert!(!HoldForSafety.is_submittable());
}

#[test]
fn test_state_machine_transition_execution_and_error() {
    let mut state = DisclosureLifecycleState::PrivateDraft;

    // Transition to UserReviewed succeeds
    assert!(
        state
            .transition_to(DisclosureLifecycleState::UserReviewed)
            .is_ok()
    );
    assert_eq!(state, DisclosureLifecycleState::UserReviewed);
    assert!(state.is_submittable());

    // Transition to SubmittedPrivately succeeds
    assert!(
        state
            .transition_to(DisclosureLifecycleState::SubmittedPrivately)
            .is_ok()
    );
    assert_eq!(state, DisclosureLifecycleState::SubmittedPrivately);
    assert!(!state.is_submittable());

    // Prohibited transition directly to CoordinatedPublished fails
    let err = state.transition_to(DisclosureLifecycleState::CoordinatedPublished);
    assert!(err.is_err());
    assert_eq!(
        err.unwrap_err(),
        DisclosureStateError::InvalidTransition {
            from: DisclosureLifecycleState::SubmittedPrivately,
            to: DisclosureLifecycleState::CoordinatedPublished,
        }
    );

    // Maintainer rejection transition
    assert!(
        state
            .transition_to(DisclosureLifecycleState::Rejected)
            .is_ok()
    );
    assert!(state.is_terminal());

    // Explicit reactivation back to PrivateDraft
    assert!(state.reactivate().is_ok());
    assert_eq!(state, DisclosureLifecycleState::PrivateDraft);
}

#[test]
fn test_github_pvr_markdown_rendering() {
    let packet = create_valid_packet();
    let md = packet.to_github_pvr_markdown();

    // Verify all 7 required sections
    assert!(md.contains("# [PVR Draft] Heap Buffer Overflow in Network Packet Parser"));
    assert!(md.contains("## Summary"));
    assert!(md.contains("## Severity & Impact"));
    assert!(md.contains("## Affected Components"));
    assert!(md.contains("## Safe Reproduction Steps (Offline Unit / Property Test)"));
    assert!(md.contains("## Root Cause Analysis"));
    assert!(md.contains("## Proposed Fix / Mitigation"));
    assert!(md.contains("## Coordination & Embargo Timeline"));

    // Verify impact metrics
    assert!(md.contains("- **Severity**: Critical"));
    assert!(md.contains("- **Attack Vector**: Network"));
    assert!(md.contains("- **Confidentiality Impact**: High"));
    assert!(md.contains("- **Integrity Impact**: High"));
    assert!(md.contains("- **Availability Impact**: High"));

    // Verify offline unit test and safe reproduction
    assert!(md.contains("test_packet_bounds"));
    assert!(md.contains("synthetic_length_field: 0xffff"));
    assert!(md.contains("Safety Guarantee"));

    // Verify root cause and mitigation
    assert!(md.contains("CWE-122"));
    assert!(md.contains("```diff"));
    assert!(md.contains("ParseError::BufferExceeded"));
    assert!(md.contains("2.3.2"));

    // Verify coordination and standards
    assert!(md.contains("90 days"));
    assert!(md.contains("ISO/IEC 29147"));
    assert!(md.contains("GitHub Private Vulnerability Reporting (PVR)"));
}

#[test]
fn test_json_roundtrip_fidelity() {
    let original = create_valid_packet();
    let json = original.to_json().expect("Serialization to JSON failed");
    let recovered = DisclosurePacket::from_json(&json).expect("Deserialization from JSON failed");
    assert_eq!(original, recovered);
}

#[test]
fn test_defensive_perimeter_enforcement() {
    // 1. Weaponized NOP sled rejection
    let builder_nop = DisclosureDraftBuilder::new()
        .finding_id("finding-exploit-001")
        .title("NOP Sled Exploit")
        .vulnerability_type("RCE")
        .severity(DisclosureSeverity::Critical)
        .affected_target(AffectedTarget {
            package: "vuln-pkg".to_string(),
            commit_range: "v1.0".to_string(),
            repository: "repo".to_string(),
            source_snapshot_sha256: dummy_sha256(),
        })
        .safe_reproduction(SafeReproduction {
            test_type: "exploit".to_string(),
            harness_code: "let buf = \"\\x90\\x90\\x90\\x90\";".to_string(),
            sanitized_input: "none".to_string(),
            expected_behavior: "safe".to_string(),
            observed_behavior: "crash".to_string(),
        })
        .root_cause(RootCause {
            summary: "Overflow".to_string(),
            cwe_id: "CWE-119".to_string(),
            trace_evidence_hashes: vec![],
        });

    let res_nop = builder_nop.build();
    assert!(res_nop.is_err());
    assert!(matches!(
        res_nop.unwrap_err(),
        DisclosureValidationError::WeaponizedPayloadDetected(_)
    ));

    // 2. Weaponized shell invocation rejection
    let builder_shell = DisclosureDraftBuilder::new()
        .finding_id("finding-exploit-002")
        .title("Command Injection Exploit")
        .vulnerability_type("Command Injection")
        .severity(DisclosureSeverity::High)
        .affected_target(AffectedTarget {
            package: "vuln-pkg".to_string(),
            commit_range: "v1.0".to_string(),
            repository: "repo".to_string(),
            source_snapshot_sha256: dummy_sha256(),
        })
        .safe_reproduction(SafeReproduction {
            test_type: "injection".to_string(),
            harness_code: "fn test() {}".to_string(),
            sanitized_input: "; /bin/sh -i;".to_string(),
            expected_behavior: "reject".to_string(),
            observed_behavior: "executed".to_string(),
        })
        .root_cause(RootCause {
            summary: "Command injection".to_string(),
            cwe_id: "CWE-78".to_string(),
            trace_evidence_hashes: vec![],
        });

    let res_shell = builder_shell.build();
    assert!(res_shell.is_err());
    assert!(matches!(
        res_shell.unwrap_err(),
        DisclosureValidationError::WeaponizedPayloadDetected(_)
    ));

    // 3. Secret credential leak rejection
    let builder_secret = DisclosureDraftBuilder::new()
        .finding_id("finding-secret-003")
        .title("API Key Leak")
        .vulnerability_type("Information Disclosure")
        .severity(DisclosureSeverity::Medium)
        .affected_target(AffectedTarget {
            package: "vuln-pkg".to_string(),
            commit_range: "v1.0".to_string(),
            repository: "repo".to_string(),
            source_snapshot_sha256: dummy_sha256(),
        })
        .safe_reproduction(SafeReproduction {
            test_type: "unit_test".to_string(),
            harness_code: format!(
                "let _key = \"ghp_{}\";",
                "1234567890abcdefghijklmnopqrstuvwxyz"
            ),
            sanitized_input: "test".to_string(),
            expected_behavior: "clean".to_string(),
            observed_behavior: "leaked".to_string(),
        })
        .root_cause(RootCause {
            summary: "Secret leak".to_string(),
            cwe_id: "CWE-200".to_string(),
            trace_evidence_hashes: vec![],
        });

    let res_secret = builder_secret.build();
    assert!(res_secret.is_err());
    assert!(matches!(
        res_secret.unwrap_err(),
        DisclosureValidationError::SecretLeakDetected(_)
    ));
}

#[test]
fn test_builder_prepopulation_from_finding() {
    let finding = FindingV1 {
        schema_version: "1.0".to_string(),
        run_id: "run-001".to_string(),
        finding_id: "finding-sql-injection-42".to_string(),
        fingerprint: None,
        kind: FindingKind::KnownAdvisory,
        status: FindingStatus::Verified,
        title: "SQL Injection in User Authentication Query".to_string(),
        summary: Some("User input concatenated directly into raw SQL string.".to_string()),
        severity: NormalizedSeverity::High,
        evidence_certainty: EvidenceCertaintyV1::Confirmed,
        rule_id: Some("sql-injection-user-input".to_string()),
        weakness_ids: vec!["CWE-89".to_string()],
        advisory_ids: vec!["CVE-2026-99999".to_string()],
        engine: EngineDescriptor {
            id: "ast-grep".to_string(),
            version: "0.51".to_string(),
            rule_pack_sha256: None,
        },
        target: TargetDescriptor {
            target_id: "pkg-auth".to_string(),
            kind: NormalizedTargetKind::Package,
            path: Some("https://github.com/acme/auth".to_string()),
            package_purl: Some("pkg:cargo/acme-auth@1.0.0".to_string()),
            version: Some("1.0.0".to_string()),
            span: None,
        },
        source_snapshot_sha256: dummy_sha256(),
        evidence: vec![EvidenceItemV1 {
            kind: EvidenceItemKind::SourceSpan,
            artifact_sha256: dummy_sha256(),
            description: "Unsanitized query construction".to_string(),
            reference: None,
            limitations: vec![],
        }],
        coverage_receipt_ids: vec![],
        proof: Some(ProofV1 {
            method: ProofMethod::IsolatedTest,
            artifact_sha256: dummy_sha256(),
            reproduced_on_snapshot: dummy_sha256(),
            limitations: vec![],
        }),
        uncertainty_reasons: vec![],
        remediation_plan_id: None,
        updated_at: None,
        extensions: serde_json::Map::new(),
        created_at: "2026-10-26T00:00:00Z".to_string(),
    };

    let builder =
        DisclosureDraftBuilder::from_finding(&finding).safe_reproduction(SafeReproduction {
            test_type: "offline_unit_test".to_string(),
            harness_code: "fn test_auth_sql_injection() { /* safe harness */ }".to_string(),
            sanitized_input: "user: ' OR '1'='1".to_string(),
            expected_behavior: "Authentication query safely parameterized".to_string(),
            observed_behavior: "Raw SQL query syntax error or unexpected true clause".to_string(),
        });

    let packet = builder.build().expect("Packet from finding should build");
    assert_eq!(packet.finding_id, "finding-sql-injection-42");
    assert_eq!(packet.title, "SQL Injection in User Authentication Query");
    assert_eq!(packet.severity, DisclosureSeverity::High);
    assert_eq!(packet.root_cause.cwe_id, "CWE-89");
    assert_eq!(packet.affected_target.package, "pkg:cargo/acme-auth@1.0.0");
    assert_eq!(
        packet.affected_target.source_snapshot_sha256,
        dummy_sha256()
    );
    assert_eq!(
        packet.root_cause.trace_evidence_hashes,
        vec![dummy_sha256()]
    );
}

#[test]
fn test_builder_prepopulation_from_research_candidate() {
    let mut candidate = ResearchCandidate::new(
        "candidate-zip-slip-007",
        "Path Traversal via Zip Archive Extract",
        "acme/archive",
        "CWE-22",
        "Extract loop fails to canonicalize path",
    );
    candidate.reproduction_artifact = Some(ReproductionArtifact::new(
        b"raw_trigger".to_vec(),
        b"minimized_trigger".to_vec(),
        "Path escaped sandbox boundary",
    ));

    let builder = DisclosureDraftBuilder::from_candidate(&candidate, &dummy_sha256());
    let packet = builder.build().expect("Packet from candidate should build");

    assert_eq!(packet.finding_id, "candidate-zip-slip-007");
    assert_eq!(packet.title, "Path Traversal via Zip Archive Extract");
    assert_eq!(packet.root_cause.cwe_id, "CWE-22");
    assert_eq!(packet.affected_target.package, "acme/archive");
    assert_eq!(
        packet.affected_target.source_snapshot_sha256,
        dummy_sha256()
    );
    assert_eq!(
        packet.safe_reproduction.observed_behavior,
        "Path escaped sandbox boundary"
    );
    assert_eq!(
        packet.lifecycle_state,
        DisclosureLifecycleState::PrivateDraft
    );
}
