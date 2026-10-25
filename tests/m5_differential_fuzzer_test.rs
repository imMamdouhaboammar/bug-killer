use serde_json::Value;
use std::fs;

use bug_killer::engine::protocol::{
    EvidenceCertaintyV1, EvidenceItemKind, FindingKind, FindingStatus, FindingV1, ProofMethod,
};
use bug_killer::hunter::fuzzer::{DifferentialFuzzer, FuzzOutcome, InvariantKind};
use bug_killer::hunter::hypothesis::{
    CandidateDismissReason, CandidateState, ExperimentKind, HypothesisCandidate,
    ThreatHypothesisFamily,
};

// ============================================================================
// Test 1: InvariantKind and FuzzOutcome Representation
// ============================================================================

#[test]
fn test_m5_invariant_kinds_and_outcomes() {
    let invariants = [
        InvariantKind::NoPanic,
        InvariantKind::BoundedMemory,
        InvariantKind::OutputEquivalence,
        InvariantKind::AuthPreconditionHold,
        InvariantKind::IdempotentState,
    ];

    assert_eq!(invariants[0].as_str(), "NoPanic");
    assert_eq!(invariants[1].as_str(), "BoundedMemory");
    assert_eq!(invariants[2].as_str(), "OutputEquivalence");
    assert_eq!(invariants[3].as_str(), "AuthPreconditionHold");
    assert_eq!(invariants[4].as_str(), "IdempotentState");

    let outcome_satisfied = FuzzOutcome::InvariantSatisfied;
    assert!(outcome_satisfied.is_satisfied());
    assert!(!outcome_satisfied.is_violation());

    let outcome_violated = FuzzOutcome::InvariantViolated {
        minimized_input: vec![0xDE, 0xAD],
        error_description: "Segmentation fault".to_string(),
        trace: vec!["Step 1".to_string(), "Step 2".to_string()],
    };
    assert!(outcome_violated.is_violation());
    assert!(!outcome_violated.is_satisfied());

    let outcome_timeout = FuzzOutcome::TimedOut;
    assert!(outcome_timeout.is_timed_out());

    let outcome_budget = FuzzOutcome::BudgetExhausted;
    assert!(outcome_budget.is_budget_exhausted());
}

// ============================================================================
// Test 2: Bounded Property Fuzzing & Binary Delta Shrinking on Panic
// ============================================================================

#[test]
fn test_m5_fuzz_property_panic_catching_and_binary_delta_shrinking() {
    let fuzzer = DifferentialFuzzer::new(200, 1000, 2048);

    // Target crashes on exact 4-byte sequence surrounded by arbitrary noise
    let crash_magic = b"BOOM";
    let property_checker = |input: &[u8]| -> Result<(), String> {
        if input.windows(crash_magic.len()).any(|w| w == crash_magic) {
            panic!("Fatal crash: buffer dereference null pointer upon encountering BOOM");
        }
        Ok(())
    };

    // Generator produces inputs with noise and inserts the trigger sequence
    let noisy_prefix = b"PADDING_PREFIX_1234567890_".to_vec();
    let noisy_suffix = b"_SUFFIX_NOISE_9876543210_TRAILING".to_vec();
    let mut payload = Vec::new();
    payload.extend_from_slice(&noisy_prefix);
    payload.extend_from_slice(crash_magic);
    payload.extend_from_slice(&noisy_suffix);

    let generator = |iteration: usize| -> Vec<u8> {
        if iteration == 10 {
            payload.clone()
        } else {
            format!("harmless_input_iteration_{}", iteration).into_bytes()
        }
    };

    let outcome = fuzzer.fuzz_property(generator, property_checker);
    match outcome {
        FuzzOutcome::InvariantViolated {
            minimized_input,
            error_description,
            trace,
        } => {
            assert_eq!(
                minimized_input, crash_magic,
                "Delta shrinking must isolate the exact 4-byte crash sequence"
            );
            assert!(
                error_description.contains("BOOM"),
                "Error description must capture panic payload: {}",
                error_description
            );
            assert!(!trace.is_empty(), "Trace must record minimization history");
            assert!(trace.iter().any(|t| t.contains("Delta shrinking")));
        }
        other => panic!("Expected InvariantViolated, got {:?}", other),
    }
}

// ============================================================================
// Test 3: Bounded Property Fuzzing Invariant Satisfaction
// ============================================================================

#[test]
fn test_m5_fuzz_property_invariant_satisfied() {
    let fuzzer = DifferentialFuzzer::new(100, 1000, 512);

    // Invariant: arithmetic check always holds for positive integers
    let property = |input: &[u8]| -> Result<(), String> {
        if input.len() >= 4 {
            let val = u32::from_le_bytes(input[0..4].try_into().unwrap());
            // Idempotent identity check
            if val ^ val != 0 {
                return Err("XOR self identity violated".to_string());
            }
        }
        Ok(())
    };

    let generator = |i: usize| -> Vec<u8> { (i as u32).to_le_bytes().to_vec() };

    let outcome = fuzzer.fuzz_property(generator, property);
    assert_eq!(outcome, FuzzOutcome::InvariantSatisfied);
}

// ============================================================================
// Test 4: Differential Compare Divergence Detection & Minimization
// ============================================================================

#[test]
fn test_m5_differential_compare_divergence() {
    let fuzzer = DifferentialFuzzer::new(50, 1000, 1024);

    // Baseline: Reference parser that safely sanitizes control characters
    let baseline = |input: &[u8]| -> Result<Vec<u8>, String> {
        let mut clean = Vec::new();
        for &b in input {
            if (0x20..=0x7E).contains(&b) {
                clean.push(b);
            }
        }
        Ok(clean)
    };

    // Target: Patched implementation with a flaw: panics on null byte '\0' or divergence on 0xFF
    let target = |input: &[u8]| -> Result<Vec<u8>, String> {
        if input.contains(&0x00) {
            panic!("NullByteCrash: Unchecked null byte dereference in target parser");
        }
        let mut clean = Vec::new();
        for &b in input {
            if (0x20..=0x7E).contains(&b) {
                clean.push(b);
            } else if b == 0xFF {
                // Behavioral divergence: target erroneously accepts 0xFF
                clean.push(b);
            }
        }
        Ok(clean)
    };

    let noisy_divergent_input = vec![b'A', b'B', b'C', 0x00, b'D', b'E', b'F'];
    let generator = |i: usize| -> Vec<u8> {
        if i == 5 {
            noisy_divergent_input.clone()
        } else {
            vec![b'X', b'Y', b'Z']
        }
    };

    let outcome = fuzzer.differential_compare(generator, baseline, target);
    match outcome {
        FuzzOutcome::InvariantViolated {
            minimized_input,
            error_description,
            trace,
        } => {
            assert_eq!(
                minimized_input,
                vec![0x00],
                "Delta shrinking must minimize the trigger to a single null byte [0x00]"
            );
            assert!(
                error_description.contains("NullByteCrash"),
                "Error description should describe the panic: {}",
                error_description
            );
            assert!(!trace.is_empty());
        }
        other => panic!("Expected InvariantViolated, got {:?}", other),
    }
}

// ============================================================================
// Test 5: Differential Compare Outputs Equivalence
// ============================================================================

#[test]
fn test_m5_differential_compare_equivalent() {
    let fuzzer = DifferentialFuzzer::new(50, 1000, 256);

    let baseline = |input: &[u8]| -> u64 {
        let mut hash: u64 = 5381;
        for &b in input {
            hash = hash.wrapping_mul(33).wrapping_add(b as u64);
        }
        hash
    };

    let target = |input: &[u8]| -> u64 {
        // Equivalent implementation unrolled
        let mut hash: u64 = 5381;
        for &b in input {
            hash = (hash << 5).wrapping_add(hash).wrapping_add(b as u64);
        }
        hash
    };

    let generator = |i: usize| -> Vec<u8> { format!("input-seed-{}", i).into_bytes() };

    let outcome = fuzzer.differential_compare(generator, baseline, target);
    assert_eq!(outcome, FuzzOutcome::InvariantSatisfied);
}

// ============================================================================
// Test 6: Finding Synthesis Gate (Verified Only) & Schema Conformance
// ============================================================================

#[test]
fn test_m5_synthesize_finding_promotion_gate_and_schema_validation() {
    let fuzzer = DifferentialFuzzer::default();
    let snapshot_sha256 = "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff";

    let mut candidate = HypothesisCandidate::new(
        "cand-auth-m5-001",
        ThreatHypothesisFamily::AuthAuthz,
        "Broken Object-Level Authorization in Tenant Storage Handler",
        "services/storage",
        "api/tenant_boundary",
        "malformed_jwt_claims",
        "tenant_id invariant must not match across distinct tenants",
        "src/api/storage.rs",
        ExperimentKind::PropertyInvariant,
        vec!["authenticated_session".to_string()],
        vec!["tenant_isolation_violation_receipt".to_string()],
    );

    let outcome_violation = FuzzOutcome::InvariantViolated {
        minimized_input: vec![
            0x7B, 0x22, 0x74, 0x65, 0x6E, 0x61, 0x6E, 0x74, 0x22, 0x3A, 0x20, 0x30, 0x7D,
        ],
        error_description: "Invariant violated: Cross-tenant data returned to unauthorized caller"
            .to_string(),
        trace: vec![
            "Initial input 256 bytes".to_string(),
            "Delta shrinking: reduced to 13 bytes".to_string(),
        ],
    };

    // 6a. UNVERIFIED candidate in initial Candidate state MUST NOT synthesize finding
    assert_eq!(candidate.state, CandidateState::Candidate);
    assert!(!candidate.can_promote_to_finding());
    assert!(
        fuzzer
            .synthesize_finding(&candidate, &outcome_violation, snapshot_sha256)
            .is_none(),
        "Unverified candidate in Candidate state must return None"
    );

    // 6b. Candidate in Reproducing state MUST NOT synthesize finding
    assert!(candidate.start_reproduction().is_ok());
    assert_eq!(candidate.state, CandidateState::Reproducing);
    assert!(!candidate.can_promote_to_finding());
    assert!(
        fuzzer
            .synthesize_finding(&candidate, &outcome_violation, snapshot_sha256)
            .is_none(),
        "Candidate in Reproducing state must return None"
    );

    // 6c. Candidate in Dismissed state MUST NOT synthesize finding
    let mut dismissed = candidate.clone();
    assert!(
        dismissed
            .dismiss(CandidateDismissReason::BenignBehavior)
            .is_ok()
    );
    assert!(!dismissed.can_promote_to_finding());
    assert!(
        fuzzer
            .synthesize_finding(&dismissed, &outcome_violation, snapshot_sha256)
            .is_none()
    );

    // 6d. Candidate promoted to Verified with reproduction receipt MUST synthesize a valid FindingV1
    assert!(
        candidate
            .mark_verified("receipt-sandbox-physical-repro-001")
            .is_ok()
    );
    assert_eq!(candidate.state, CandidateState::Verified);
    assert!(candidate.can_promote_to_finding());

    let finding_opt = fuzzer.synthesize_finding(&candidate, &outcome_violation, snapshot_sha256);
    assert!(
        finding_opt.is_some(),
        "Verified candidate must synthesize a FindingV1"
    );
    let finding: FindingV1 = finding_opt.unwrap();

    // Protocol contract checks
    assert_eq!(finding.schema_version, "1.0");
    assert_eq!(finding.finding_id, "novel-finding-cand-auth-m5-001");
    assert_eq!(finding.kind, FindingKind::ResearchCandidate);
    assert_eq!(finding.status, FindingStatus::Verified);
    assert_eq!(finding.evidence_certainty, EvidenceCertaintyV1::Confirmed);
    assert_eq!(finding.weakness_ids, vec!["CWE-285"]); // AuthAuthz maps to CWE-285

    // Proof checks
    let proof = finding.proof.as_ref().expect("ProofV1 must be present");
    assert_eq!(proof.method, ProofMethod::ReproductionArtifact);
    assert_eq!(proof.reproduced_on_snapshot, snapshot_sha256);
    assert_eq!(proof.artifact_sha256.len(), 64);

    // Evidence checks
    assert_eq!(finding.evidence.len(), 2);
    assert_eq!(finding.evidence[0].kind, EvidenceItemKind::TestReproduction);
    assert_eq!(finding.evidence[1].kind, EvidenceItemKind::RuntimeTrace);
    assert_eq!(finding.evidence[0].artifact_sha256, proof.artifact_sha256);

    // Validate FindingV1 with built-in validation rules
    finding.validate().expect("FindingV1::validate() must pass");

    // Conformance test against finding.schema.json
    let schema_content =
        fs::read_to_string("bug-killer-ultimate-spec-v1/schemas/finding.schema.json")
            .expect("finding.schema.json must exist");
    let schema_val: Value = serde_json::from_str(&schema_content).unwrap();
    let finding_val = serde_json::to_value(&finding).unwrap();

    let required = schema_val["required"].as_array().unwrap();
    for req in required {
        let field = req.as_str().unwrap();
        assert!(
            finding_val.get(field).is_some(),
            "Missing required schema field: {}",
            field
        );
    }

    assert_eq!(finding_val["proof"]["method"], "REPRODUCTION_ARTIFACT");
    assert_eq!(finding_val["evidence_certainty"], "CONFIRMED");
    assert_eq!(finding_val["status"], "VERIFIED");

    // 6e. InvariantSatisfied or TimedOut MUST NOT produce a finding
    assert!(
        fuzzer
            .synthesize_finding(
                &candidate,
                &FuzzOutcome::InvariantSatisfied,
                snapshot_sha256
            )
            .is_none(),
        "Satisfied outcome must not synthesize a finding"
    );
    assert!(
        fuzzer
            .synthesize_finding(&candidate, &FuzzOutcome::TimedOut, snapshot_sha256)
            .is_none()
    );
    assert!(
        fuzzer
            .synthesize_finding(&candidate, &FuzzOutcome::BudgetExhausted, snapshot_sha256)
            .is_none()
    );
}
