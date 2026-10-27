use std::fs;

use bug_killer::engine::protocol::{EvidenceCertaintyV1, FindingKind, FindingStatus, ProofMethod};
use bug_killer::hunter::{
    CandidateState, DifferentialComparator, DifferentialResult, DismissalReason, FuzzReproduction,
    NoveltyChecker, PropertyFuzzer, ReproductionArtifact, ResearchCandidate, ResearchSandbox,
    SandboxConfig,
};
use serde_json::Value;

// ============================================================================
// Test 1: Candidate State Machine Lifecycle & Promotion Gate
// ============================================================================

#[test]
fn test_m5_candidate_state_machine_lifecycle_and_promotion_gate() {
    let mut candidate = ResearchCandidate::new(
        "cand-cwe787-001",
        "Heap Out-of-Bounds Write in Buffer Manager",
        "src/buffer/manager.c",
        "CWE-787",
        "Unchecked length offset allows 8-byte write past buffer boundary",
    );

    // Initial state: Candidate
    assert_eq!(candidate.state, CandidateState::Candidate);
    assert!(!candidate.can_promote_to_finding());

    let snapshot_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    assert!(
        candidate
            .synthesize_finding("run-100", snapshot_sha256)
            .is_err(),
        "Cannot promote candidate from initial Candidate state"
    );

    // Transition to Reproducing
    assert!(candidate.start_reproduction().is_ok());
    assert_eq!(candidate.state, CandidateState::Reproducing);
    assert!(!candidate.can_promote_to_finding());
    assert!(
        candidate
            .synthesize_finding("run-100", snapshot_sha256)
            .is_err(),
        "Cannot promote candidate from Reproducing state"
    );

    // Cannot mark verified without reproduction artifact
    assert!(
        candidate.mark_verified().is_err(),
        "Cannot mark verified without an artifact"
    );

    // Attach reproduction artifact -> Reproduced
    let trigger_payload = b"\x7f\x45\x4c\x46\x02\x01\x01\x00_OVERFLOW_CHUNK".to_vec();
    let artifact = ReproductionArtifact::new(
        trigger_payload.clone(),
        b"_OVERFLOW_CHUNK".to_vec(),
        "SIGSEGV: write at address 0xdeadbeef past allocated heap range",
    );
    assert!(candidate.mark_reproduced(artifact).is_ok());
    assert_eq!(candidate.state, CandidateState::Reproduced);
    assert!(candidate.reproduction_artifact.is_some());
    assert!(!candidate.can_promote_to_finding());

    // Promote to Verified
    assert!(candidate.mark_verified().is_ok());
    assert_eq!(candidate.state, CandidateState::Verified);
    assert!(
        candidate.can_promote_to_finding(),
        "Verified candidate must satisfy promotion gate"
    );

    // Once in Verified, promotion produces a valid finding
    let finding = candidate
        .synthesize_finding("run-100", snapshot_sha256)
        .expect("Synthesis must succeed for Verified candidate");
    assert_eq!(finding.status, FindingStatus::Verified);

    // Test rejection on Dismissed
    let mut dismissed_candidate = ResearchCandidate::new(
        "cand-dismissed-002",
        "Duplicate Pointer Flaw",
        "src/util.c",
        "CWE-476",
        "Hypothesis turns out to be not reproducible",
    );
    dismissed_candidate.dismiss(DismissalReason::NotReproducible);
    assert!(!dismissed_candidate.can_promote_to_finding());
    assert!(
        dismissed_candidate
            .synthesize_finding("run-100", snapshot_sha256)
            .is_err()
    );

    // Test rejection on Inconclusive
    let mut inconclusive_cand = ResearchCandidate::new(
        "cand-inconclusive-003",
        "Potential Race Condition",
        "src/sync.c",
        "CWE-362",
        "Nondeterministic timing variance under load",
    );
    inconclusive_cand.mark_inconclusive("Fails to reproduce under single-core bound");
    assert!(!inconclusive_cand.can_promote_to_finding());
    assert!(
        inconclusive_cand
            .synthesize_finding("run-100", snapshot_sha256)
            .is_err()
    );
}

// ============================================================================
// Test 2: Novelty Invariant & Known Advisory Check
// ============================================================================

#[test]
fn test_m5_novelty_invariant_and_known_advisory_check() {
    let mut checker = NoveltyChecker::new();
    checker.register_known_advisory("CVE-2023-38408");
    checker.register_known_advisory("GHSA-7rjr-3q55-234w");
    checker.register_known_advisory("CVE-2024-21626");

    // Case 2a: Hypothesis directly targets an already known CVE
    let mut known_candidate = ResearchCandidate::new(
        "cand-known-001",
        "OpenSSH PKCS#11 Provider Command Injection",
        "ssh-pkcs11.c",
        "CWE-78",
        "Researching vulnerability fixed in CVE-2023-38408",
    );

    let is_novel = checker.evaluate_novelty(&mut known_candidate, Some("CVE-2023-38408"));
    assert!(!is_novel, "Cannot claim novelty for known CVE-2023-38408");
    assert_eq!(
        known_candidate.state,
        CandidateState::Dismissed(DismissalReason::AlreadyKnownAdvisory(
            "CVE-2023-38408".to_string()
        ))
    );
    assert!(!known_candidate.can_promote_to_finding());

    // Case 2b: Hypothesis text references a registered GHSA advisory
    let mut ghsa_candidate = ResearchCandidate::new(
        "cand-known-002",
        "Container Escape via Leaked File Descriptor",
        "runc/libcontainer.go",
        "CWE-403",
        "Investigating flaw described in GHSA-7rjr-3q55-234w advisory",
    );
    let is_ghsa_novel = checker.evaluate_novelty(&mut ghsa_candidate, None);
    assert!(
        !is_ghsa_novel,
        "Cannot claim novelty when hypothesis mentions known GHSA"
    );
    assert_eq!(
        ghsa_candidate.state,
        CandidateState::Dismissed(DismissalReason::AlreadyKnownAdvisory(
            "GHSA-7RJR-3Q55-234W".to_string()
        ))
    );

    // Case 2c: Slice-based batch check against known advisories
    let mut batch_candidate = ResearchCandidate::new(
        "cand-batch-003",
        "Runc File Descriptor Leak",
        "nsenter.c",
        "CWE-403",
        "Hypothesis mentions CVE-2024-21626 boundary issue",
    );
    let slice_check = checker
        .check_against_advisories(&mut batch_candidate, &["CVE-2024-21626", "CVE-2021-3156"]);
    assert!(!slice_check);
    assert_eq!(
        batch_candidate.state,
        CandidateState::Dismissed(DismissalReason::AlreadyKnownAdvisory(
            "CVE-2024-21626".to_string()
        ))
    );

    // Case 2d: Genuinely novel research hypothesis
    let mut novel_candidate = ResearchCandidate::new(
        "cand-novel-004",
        "Novel Integer Overflow in Custom Serialization Parser",
        "src/codec/custom.rs",
        "CWE-190",
        "Previously undocumented boundary mismatch during variable-length tag parsing",
    );
    let is_truly_novel = checker.evaluate_novelty(&mut novel_candidate, None);
    assert!(
        is_truly_novel,
        "Genuine novel candidate must pass novelty check"
    );
    assert_eq!(novel_candidate.state, CandidateState::Candidate);
}

// ============================================================================
// Test 3: Sandbox Execution Isolation
// ============================================================================

#[test]
fn test_m5_sandbox_execution_isolation() {
    let config = SandboxConfig {
        allow_network: false,
        timeout_ms: 1000,
        max_memory_bytes: 64 * 1024 * 1024,
        max_output_bytes: 1024 * 1024,
        max_file_size_bytes: 1024 * 1024,
        strip_ambient_env: true,
        stripped_env_prefixes: vec![
            "AWS_".to_string(),
            "GITHUB_".to_string(),
            "SECRET_".to_string(),
            "TOKEN_".to_string(),
        ],
        ..Default::default()
    };

    let sandbox = ResearchSandbox::new(config.clone());

    // 3a. Ambient secret sanitization
    let ambient_env = vec![
        ("AWS_ACCESS_KEY_ID", "mock_dummy_aws_access_key_12345"),
        (
            "AWS_SECRET_ACCESS_KEY",
            "mock_dummy_aws_secret_access_key_67890",
        ),
        ("GITHUB_TOKEN", "mock_dummy_github_token_synthetic_abcde"),
        ("SECRET_KEY_PROD", "super_secret_payload"),
        ("TOKEN_SERVICE_AUTH", "bearer_token_val"),
        ("SAFE_VARIABLE_PATH", "/tmp/safe_research_path"),
        ("BENCHMARK_ENV", "local_isolated"),
    ];

    let sanitized = sandbox.sanitize_env(&ambient_env);
    assert_eq!(
        sanitized.len(),
        2,
        "Only non-sensitive variables must survive"
    );
    assert!(!sanitized.iter().any(|(k, _)| k.contains("AWS_")));
    assert!(!sanitized.iter().any(|(k, _)| k.contains("GITHUB_")));
    assert!(!sanitized.iter().any(|(k, _)| k.contains("SECRET_")));
    assert!(!sanitized.iter().any(|(k, _)| k.contains("TOKEN_")));
    assert!(sanitized.iter().any(|(k, _)| *k == "SAFE_VARIABLE_PATH"));
    assert!(sanitized.iter().any(|(k, _)| *k == "BENCHMARK_ENV"));

    // 3b. Network egress prevention
    assert!(
        sandbox.validate_network_policy().is_err(),
        "Sandbox policy must strictly forbid network egress"
    );
    let egress_attempt = sandbox.attempt_network_egress("169.254.169.254");
    assert!(
        egress_attempt.is_err(),
        "Network egress attempt must be blocked by sandbox policy"
    );

    // 3c. Clean timeout termination without leaking background processes
    let timeout_env: Vec<(String, String)> = ambient_env
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    // Spawn command that attempts to sleep for 5 seconds when timeout is 1000ms
    let result = sandbox
        .execute_bounded("/bin/sh", &["-c", "sleep 5"], None, &timeout_env)
        .expect("Execution invocation must be handled");

    assert!(
        result.timed_out,
        "Long-running process must be cleanly timed out"
    );
    assert_eq!(result.exit_code, -1);
    assert!(result.duration_ms >= 900 && result.duration_ms < 3000);
    assert!(result.sanitized_vars_count >= 5);

    // 3d. Normal bounded execution completes cleanly within timeout
    let ok_res = sandbox
        .execute_bounded(
            "/bin/sh",
            &["-c", "echo 'sandbox-test-ok'"],
            None,
            &timeout_env,
        )
        .expect("Bounded echo command must succeed");

    assert!(!ok_res.timed_out);
    assert_eq!(ok_res.exit_code, 0);
    assert!(ok_res.stdout.contains("sandbox-test-ok"));
}

// ============================================================================
// Test 4: Bounded Property Fuzzing & Delta Minimization
// ============================================================================

#[test]
fn test_m5_bounded_property_fuzzing_and_delta_minimization() {
    let fuzzer = PropertyFuzzer::new().with_iterations(500);

    // 4a. Property checker with an intentional crash / invariant violation on specific trigger
    let target_needle = b"EXPLOIT_CRASH_MAGIC_SEQUENCE";
    let property = |input: &[u8]| -> Result<(), String> {
        if input
            .windows(target_needle.len())
            .any(|w| w == target_needle)
        {
            Err("INVARIANT_VIOLATION: Memory buffer write out of bounds detected".to_string())
        } else {
            Ok(())
        }
    };

    // Provide large padded payload with noise bytes before and after trigger
    let noisy_payload = [
        b"AAAABBBBCCCCDDDDEEEE".as_slice(),
        target_needle.as_slice(),
        b"1111222233334444555566667777".as_slice(),
    ]
    .concat();

    // Verify initial violation triggers
    assert!(property(&noisy_payload).is_err());

    // Delta minimization must shrink the noisy payload to the exact trigger sequence
    let minimized = fuzzer.minimize_trigger(&noisy_payload, &property);
    assert_eq!(
        minimized, target_needle,
        "Delta minimization must reduce to exact minimal invariant trigger"
    );

    // 4b. Fuzzer exploration with seeded corpus
    let mut custom_fuzzer = PropertyFuzzer::new().with_iterations(200);
    custom_fuzzer.add_seed(noisy_payload);

    let reproduction: Option<FuzzReproduction> = custom_fuzzer.fuzz(property);
    assert!(reproduction.is_some());
    let rep = reproduction.unwrap();
    assert_eq!(rep.minimized_trigger, target_needle);
    assert!(rep.error_message.contains("INVARIANT_VIOLATION"));
    assert!(rep.iterations_run >= 1);
}

// ============================================================================
// Test 5: Differential Comparison & Divergence Detection
// ============================================================================

#[test]
fn test_m5_differential_comparison_and_divergence_detection() {
    // Baseline implementation: Safe signed arithmetic with saturation
    let baseline = |input: &[u8]| -> Result<Vec<u8>, String> {
        if input.is_empty() {
            return Ok(vec![0]);
        }
        let mut sum: i64 = 0;
        for &byte in input {
            sum = sum.saturating_add(byte as i64);
        }
        Ok(sum.to_le_bytes().to_vec())
    };

    // Candidate / buggy implementation: Unchecked 8-bit overflow causing divergence
    let candidate = |input: &[u8]| -> Result<Vec<u8>, String> {
        if input.is_empty() {
            return Ok(vec![0]);
        }
        let mut sum: u8 = 0;
        for &byte in input {
            // Unchecked addition: overflows when sum + byte > 255
            sum = sum.wrapping_add(byte);
        }
        // When overflow occurred (input sum > 255), return raw 8-bit wrap or error
        if input.iter().map(|&b| b as usize).sum::<usize>() > 255 {
            Err("IntegerOverflowPanic: accumulator overflowed 8-bit width".to_string())
        } else {
            Ok((sum as i64).to_le_bytes().to_vec())
        }
    };

    let comparator = DifferentialComparator::new().with_corpus(vec![
        vec![10, 20, 30],
        vec![50, 50, 50],
        vec![100, 100, 100], // Sum = 300 > 255 -> triggers divergence!
        vec![1, 2, 3],
    ]);

    let diff_result = comparator.compare(&baseline, &candidate);
    match diff_result {
        DifferentialResult::Divergence(violation) => {
            assert_eq!(violation.reason, "InvariantViolated");
            assert_eq!(violation.input, vec![100, 100, 100]);

            // Convert to reproduction artifact
            let artifact = comparator.create_reproduction_artifact(&violation);
            assert_eq!(artifact.raw_payload, vec![100, 100, 100]);
            assert_eq!(artifact.minimized_trigger, vec![100, 100, 100]);
            assert!(artifact.error_message.contains("InvariantViolated"));
            assert_eq!(artifact.artifact_sha256.len(), 64);
        }
        DifferentialResult::Equivalent => {
            panic!("Expected divergence between baseline and buggy candidate!");
        }
    }
}

// ============================================================================
// Test 6: Verified Finding Synthesis with Reproduction Artifact & Schema Check
// ============================================================================

#[test]
fn test_m5_verified_finding_synthesis_with_reproduction_artifact() {
    let mut candidate = ResearchCandidate::new(
        "novel-cwe190-777",
        "Novel Integer Overflow in Custom Parser Length Calculation",
        "src/parser/length.c",
        "CWE-190",
        "Accumulator wrapping leads to negative allocation size and heap corruption",
    );

    let raw_trigger = vec![0xFF, 0xFF, 0x01, 0x42, 0x99];
    let minimized_trigger = vec![0xFF, 0xFF, 0x01];
    let artifact = ReproductionArtifact::new(
        raw_trigger,
        minimized_trigger,
        "SIGSEGV: integer overflow resulted in malloc(0) followed by 65535-byte memcpy",
    );

    assert!(candidate.mark_reproduced(artifact).is_ok());
    assert!(candidate.mark_verified().is_ok());
    assert!(candidate.can_promote_to_finding());

    let snapshot_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let run_id = "run-novel-hunter-m5-verification";

    let finding = candidate
        .synthesize_finding(run_id, snapshot_sha256)
        .expect("Synthesis must succeed for verified candidate");

    // Rust protocol contract assertions
    assert_eq!(finding.schema_version, "1.0");
    assert_eq!(finding.run_id, run_id);
    assert_eq!(finding.finding_id, "novel-finding-novel-cwe190-777");
    assert_eq!(finding.kind, FindingKind::ResearchCandidate);
    assert_eq!(finding.status, FindingStatus::Verified);
    assert_eq!(finding.evidence_certainty, EvidenceCertaintyV1::Confirmed);
    assert_eq!(finding.weakness_ids, vec!["CWE-190"]);
    assert_eq!(finding.source_snapshot_sha256, snapshot_sha256);

    let proof = finding.proof.as_ref().expect("Proof is strictly required");
    assert_eq!(proof.method, ProofMethod::ReproductionArtifact);
    assert_eq!(proof.reproduced_on_snapshot, snapshot_sha256);
    assert_eq!(proof.artifact_sha256.len(), 64);

    let evidence = &finding.evidence;
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].artifact_sha256.len(), 64);
    assert!(evidence[0].description.contains("Deterministic fuzzed"));

    // Protocol validate method assertion
    finding
        .validate()
        .expect("FindingV1::validate() must pass cleanly");

    // Conformance against schemas/finding.schema.json
    let finding_json = serde_json::to_value(&finding).expect("Serialize FindingV1 to JSON");

    let schema_raw = fs::read_to_string("bug-killer-ultimate-spec-v1/schemas/finding.schema.json")
        .expect("Read finding.schema.json");
    let schema: Value = serde_json::from_str(&schema_raw).expect("Parse finding.schema.json");

    let required_fields = schema["required"]
        .as_array()
        .expect("Schema must declare required array");

    for field in required_fields {
        let field_name = field.as_str().unwrap();
        assert!(
            finding_json.get(field_name).is_some(),
            "Finding missing required schema field: {}",
            field_name
        );
    }

    assert_eq!(finding_json["schema_version"], "1.0");
    assert_eq!(finding_json["kind"], "RESEARCH_CANDIDATE");
    assert_eq!(finding_json["status"], "VERIFIED");
    assert_eq!(finding_json["evidence_certainty"], "CONFIRMED");
    assert_eq!(
        finding_json["proof"]["method"], "REPRODUCTION_ARTIFACT",
        "proof.method must match REPRODUCTION_ARTIFACT enum"
    );

    // Verify SHA-256 strings match 64 hex characters regex requirement
    let hex_re = regex::Regex::new("^[a-f0-9]{64}$").unwrap();
    assert!(hex_re.is_match(finding_json["source_snapshot_sha256"].as_str().unwrap()));
    assert!(hex_re.is_match(finding_json["proof"]["artifact_sha256"].as_str().unwrap()));
    assert!(
        hex_re.is_match(
            finding_json["proof"]["reproduced_on_snapshot"]
                .as_str()
                .unwrap()
        )
    );
    assert!(
        hex_re.is_match(
            finding_json["evidence"][0]["artifact_sha256"]
                .as_str()
                .unwrap()
        )
    );
}

// ============================================================================
// Test 6: Cloudflare-Style Audit Coverage Ledger & Validation Gate
// ============================================================================

#[test]
fn test_m5_coverage_ledger_validation_and_integrity() {
    use bug_killer::hunter::{CoverageLedger, CoverageUnit, CoverageUnitStatus};

    let mut ledger = CoverageLedger::new("/workspace");

    // Unit 1: Planned
    let u1 = CoverageUnit::new("web", "ingress", "api_gateway", "injection");
    assert_eq!(u1.coverage_id, "web:ingress:api_gateway:injection");
    assert_eq!(u1.status, CoverageUnitStatus::Planned);
    ledger.add_unit(u1).unwrap();

    // Unit 2: Completed with reviewed paths
    let mut u2 = CoverageUnit::new("runtime", "kernel", "memory_allocator", "buffer_overflow");
    u2.status = CoverageUnitStatus::Completed;
    u2.reviewed_paths = vec!["src/alloc/heap.rs".to_string()];
    u2.local_checks = vec!["bounds_check".to_string()];
    ledger.add_unit(u2).unwrap();

    // Valid ledger passes validation
    assert!(ledger.validate().is_ok());

    // Digest computation is deterministic
    let d1 = ledger.compute_digest();
    let d2 = ledger.compute_digest();
    assert_eq!(d1, d2);
    assert_eq!(d1.len(), 64);

    // Duplicate unit ID is rejected
    let duplicate_u1 = CoverageUnit::new("web", "ingress", "api_gateway", "injection");
    assert!(ledger.add_unit(duplicate_u1).is_err());

    // Completed unit without reviewed paths or local checks fails validation
    let mut invalid_ledger = CoverageLedger::new("/workspace");
    let mut incomplete_u = CoverageUnit::new("cloud", "iam", "authz", "privilege_escalation");
    incomplete_u.status = CoverageUnitStatus::Completed;
    invalid_ledger.add_unit(incomplete_u).unwrap();
    assert!(invalid_ledger.validate().is_err());
}
