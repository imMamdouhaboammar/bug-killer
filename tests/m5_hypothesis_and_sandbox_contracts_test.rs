use bug_killer::advisory::provider::{
    AdvisoryAffected, AdvisoryEvent, AdvisoryRange, AdvisoryRecord, AdvisorySource, AdvisoryStatus,
    MockAdvisoryProvider,
};
use bug_killer::hunter::hypothesis::*;
use bug_killer::hunter::sandbox::*;
use bug_killer::types::{Confidence, EvidenceCertainty, Severity};
use std::time::Duration;

#[test]
fn test_threat_hypothesis_families_and_experiment_kinds() {
    let families = [
        ThreatHypothesisFamily::TrustBoundary,
        ThreatHypothesisFamily::AuthAuthz,
        ThreatHypothesisFamily::ParserDecoder,
        ThreatHypothesisFamily::StateMachineConcurrency,
        ThreatHypothesisFamily::Cryptography,
        ThreatHypothesisFamily::SupplyChain,
        ThreatHypothesisFamily::BuildCi,
        ThreatHypothesisFamily::AgentMcp,
    ];

    for family in families {
        assert!(!family.as_str().is_empty());
        assert!(!family.required_evidence().is_empty());
    }

    let experiments = [
        ExperimentKind::HarnessFuzz,
        ExperimentKind::PropertyInvariant,
        ExperimentKind::DifferentialComparison,
        ExperimentKind::SanitizerFault,
    ];

    for exp in experiments {
        assert!(!exp.as_str().is_empty());
    }
}

#[test]
fn test_hypothesis_candidate_state_machine_and_promotion_gate() {
    let mut candidate = HypothesisCandidate::new(
        "cand-tb-001",
        ThreatHypothesisFamily::TrustBoundary,
        "Untrusted input reaches privileged command",
        "service-executor",
        "api-boundary",
        "unvalidated-string",
        "exec-target must be sanitized and allowlisted",
        "src/executor/handler.rs",
        ExperimentKind::PropertyInvariant,
        vec!["authenticated_session".into()],
        vec!["trace_to_sink".into()],
    );

    // Initial state: Candidate
    assert_eq!(candidate.state, CandidateState::Candidate);
    assert!(!candidate.can_promote_to_finding());
    assert!(
        candidate
            .promote_to_finding("find-001", Severity::High)
            .is_err()
    );

    // Cannot transition directly from Candidate to Verified
    assert!(candidate.transition_to(CandidateState::Verified).is_err());

    // Transition to Reproducing
    assert!(candidate.start_reproduction().is_ok());
    assert_eq!(candidate.state, CandidateState::Reproducing);
    assert!(!candidate.can_promote_to_finding());
    assert!(
        candidate
            .promote_to_finding("find-001", Severity::High)
            .is_err()
    );

    // Transition to Verified without reproduction receipt MUST fail
    assert!(candidate.transition_to(CandidateState::Verified).is_err());

    // Attach receipt and verify
    let receipt_id = "receipt-sbx-99887766";
    assert!(candidate.mark_verified(receipt_id).is_ok());
    assert_eq!(candidate.state, CandidateState::Verified);
    assert!(candidate.can_promote_to_finding());

    // Promotion gate succeeds when Verified with receipt
    let finding = candidate
        .promote_to_finding("finding-tb-verified", Severity::Critical)
        .expect("Promotion must succeed for verified candidate");

    assert_eq!(finding.id, "finding-tb-verified");
    assert_eq!(finding.severity, Severity::Critical);
    assert_eq!(finding.evidence_certainty, EvidenceCertainty::Confirmed);
    assert_eq!(finding.confidence, Confidence::Confirmed);
    assert_eq!(finding.category, "NOVEL_RESEARCH");
    assert_eq!(finding.evidence_digest, receipt_id);
    assert_eq!(finding.evidence_refs.len(), 1);
    assert_eq!(finding.evidence_refs[0].location, "src/executor/handler.rs");

    // Synthesis of FindingV1 also succeeds
    let snapshot_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let finding_v1 = candidate
        .synthesize_finding_v1("run-hunter-01", snapshot_sha256)
        .expect("FindingV1 synthesis must succeed");
    assert_eq!(finding_v1.finding_id, "novel-finding-cand-tb-001");
}

#[test]
fn test_dismissal_and_inconclusive_states() {
    let mut cand1 = HypothesisCandidate::new(
        "cand-dis-001",
        ThreatHypothesisFamily::ParserDecoder,
        "Malformed byte chunk causes panic",
        "custom-parser",
        "network-io",
        "arbitrary-bytes",
        "parser must return Result, never panic",
        "src/parser.rs",
        ExperimentKind::HarnessFuzz,
        vec![],
        vec![],
    );

    assert!(cand1.start_reproduction().is_ok());
    assert!(
        cand1
            .dismiss(CandidateDismissReason::NotReproducible)
            .is_ok()
    );
    assert_eq!(
        cand1.state,
        CandidateState::Dismissed(CandidateDismissReason::NotReproducible)
    );
    assert!(!cand1.can_promote_to_finding());
    assert!(cand1.promote_to_finding("find-dis", Severity::Low).is_err());

    let mut cand2 = HypothesisCandidate::new(
        "cand-inc-002",
        ThreatHypothesisFamily::StateMachineConcurrency,
        "Race condition in worker shutdown",
        "worker-pool",
        "concurrency",
        "parallel-signals",
        "all jobs finish before termination",
        "src/worker.rs",
        ExperimentKind::SanitizerFault,
        vec![],
        vec![],
    );

    assert!(cand2.start_reproduction().is_ok());
    assert!(
        cand2
            .mark_inconclusive("Timing dependent; did not reproduce in single thread bound")
            .is_ok()
    );
    assert!(!cand2.can_promote_to_finding());
    assert!(
        cand2
            .promote_to_finding("find-inc", Severity::Medium)
            .is_err()
    );
}

#[test]
fn test_novelty_validation_against_known_advisories() {
    let mut candidate = HypothesisCandidate::new(
        "cand-nov-001",
        ThreatHypothesisFamily::SupplyChain,
        "Known flaw in lodash",
        "npm",
        "dependency",
        "json",
        "prototype must remain clean",
        "node_modules/lodash/lodash.js",
        ExperimentKind::DifferentialComparison,
        vec![],
        vec![],
    );

    let known_advisory = AdvisoryRecord {
        schema_version: "1.5.0".to_string(),
        advisory_id: "GHSA-p6mc-m468-83gw".to_string(),
        aliases: vec!["CVE-2019-10744".to_string()],
        source: AdvisorySource {
            provider: "GHSA".to_string(),
            url: "https://github.com/advisories/GHSA-p6mc-m468-83gw".to_string(),
            retrieved_at: "2026-10-25T00:00:00Z".to_string(),
        },
        source_sha256: "deadbeef".to_string(),
        published_at: Some("2019-07-15T00:00:00Z".to_string()),
        modified_at: None,
        withdrawn_at: None,
        affected: vec![AdvisoryAffected {
            purl: Some("pkg:npm/lodash".to_string()),
            ecosystem: "npm".to_string(),
            name: Some("lodash".to_string()),
            ranges: vec![AdvisoryRange {
                range_type: "SEMVER".to_string(),
                events: vec![AdvisoryEvent {
                    introduced: Some("0".to_string()),
                    fixed: Some("4.17.12".to_string()),
                    last_affected: None,
                }],
            }],
            fixed_versions: vec!["4.17.12".to_string()],
        }],
        references: vec![],
        status: AdvisoryStatus::Active,
        summary: Some("Prototype Pollution in lodash".to_string()),
        details: None,
        severity: Some("HIGH".to_string()),
    };

    let mut provider = MockAdvisoryProvider::new();
    provider.add_advisory(known_advisory.clone());

    // Case A: Package and version match known advisory -> Novelty check fails
    let is_novel =
        candidate.check_novelty_against_advisories(&[known_advisory], "lodash", "4.17.11");
    assert!(!is_novel, "Cannot claim novelty for known advisory");
    assert_eq!(
        candidate.state,
        CandidateState::Dismissed(CandidateDismissReason::AlreadyKnownAdvisory(
            "GHSA-p6mc-m468-83gw".to_string()
        ))
    );
    assert!(!candidate.can_promote_to_finding());

    // Case B: Known advisory ID string match
    let mut candidate2 = HypothesisCandidate::new(
        "cand-nov-002",
        ThreatHypothesisFamily::SupplyChain,
        "Issue referencing CVE-2024-21626 in runc",
        "golang",
        "container",
        "proc-mount",
        "file descriptors must not leak",
        "runc/libcontainer.go",
        ExperimentKind::PropertyInvariant,
        vec![],
        vec![],
    );

    let is_novel_id = candidate2.check_novelty_against_advisory_ids(&["CVE-2024-21626"]);
    assert!(!is_novel_id);
    assert_eq!(
        candidate2.state,
        CandidateState::Dismissed(CandidateDismissReason::AlreadyKnownAdvisory(
            "CVE-2024-21626".to_string()
        ))
    );

    // Case C: Truly novel package / version passes
    let mut candidate3 = HypothesisCandidate::new(
        "cand-nov-003",
        ThreatHypothesisFamily::ParserDecoder,
        "Novel parser bug in proprietary protocol",
        "custom",
        "binary-stream",
        "frame",
        "length prefix bounded",
        "src/parser.rs",
        ExperimentKind::HarnessFuzz,
        vec![],
        vec![],
    );
    let passes =
        candidate3.check_novelty_against_advisory_ids(&["CVE-2024-21626", "GHSA-xxxx-yyyy"]);
    assert!(passes);
    assert_eq!(candidate3.state, CandidateState::Candidate);
}

#[test]
fn test_sandbox_config_defaults_and_validation() {
    let default_cfg = SandboxConfig::default();
    assert_eq!(default_cfg.max_memory_bytes, 512 * 1024 * 1024);
    assert_eq!(default_cfg.timeout_ms, 5000);
    assert_eq!(default_cfg.max_output_bytes, 1024 * 1024);
    assert!(!default_cfg.allow_network);
    assert!(default_cfg.strip_ambient_env);
    assert!(default_cfg.validate().is_ok());

    // Strict invariant: allow_network MUST be false
    let invalid_network_cfg = SandboxConfig {
        allow_network: true,
        ..default_cfg.clone()
    };
    assert!(invalid_network_cfg.validate().is_err());
    assert!(SandboxRunner::new(invalid_network_cfg).is_err());

    // Invalid timeout
    let invalid_timeout_cfg = SandboxConfig {
        timeout_ms: 0,
        ..default_cfg
    };
    assert!(invalid_timeout_cfg.validate().is_err());
}

#[test]
fn test_sandbox_runner_closure_execution() {
    let runner = SandboxRunner::default_runner().expect("Default runner must construct");

    let (res, receipt) = runner
        .run_closure(|temp_path| {
            assert!(temp_path.exists());
            let test_file = temp_path.join("candidate_artifact.bin");
            std::fs::write(&test_file, b"fuzzed_payload")?;
            Ok(test_file.exists())
        })
        .expect("Closure execution must succeed");

    assert!(res);
    assert_eq!(receipt.status, SandboxStatus::Completed);
    assert_eq!(receipt.exit_code, Some(0));
    assert!(receipt.network_egress_prevented);
    assert!(receipt.receipt_id.starts_with("receipt-sbx-"));
    assert_eq!(receipt.receipt_sha256.len(), 64);
}

#[test]
fn test_sandbox_runner_command_execution_and_env_stripping() {
    let config = SandboxConfig::default()
        .with_timeout_ms(4000)
        .with_max_output_bytes(1024 * 1024);

    let runner = SandboxRunner::new(config).expect("Runner must construct");

    let receipt = runner
        .run_command("/bin/sh", &["-c", "echo 'hunter-sandbox-ok'"])
        .expect("Command must execute");

    assert_eq!(receipt.status, SandboxStatus::Completed);
    assert_eq!(receipt.exit_code, Some(0));
    assert!(receipt.stdout_lossy().contains("hunter-sandbox-ok"));
    assert!(receipt.network_egress_prevented);
}

#[test]
fn test_sandbox_runner_timeout_and_cancellation() {
    // 1. Timeout enforcement
    let timeout_cfg = SandboxConfig::default().with_timeout_ms(500);
    let runner = SandboxRunner::new(timeout_cfg).expect("Runner must construct");

    let receipt = runner
        .run_command("/bin/sh", &["-c", "sleep 3"])
        .expect("Command execution handled");

    assert_eq!(receipt.status, SandboxStatus::TimedOut);
    assert!(receipt.duration_ms >= 450 && receipt.duration_ms < 2500);

    // 2. Cooperative cancellation token
    let token = CancellationToken::new();
    let runner_canceller = SandboxRunner::default_runner()
        .expect("Runner must construct")
        .with_cancellation_token(token.clone());

    // Spawn cancellation in background after 100ms
    let token_clone = token.clone();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(100));
        token_clone.cancel();
    });

    let receipt_cancelled = runner_canceller
        .run_command("/bin/sh", &["-c", "sleep 5"])
        .expect("Command execution handled");

    assert_eq!(receipt_cancelled.status, SandboxStatus::Killed);
}

#[test]
fn test_sandbox_output_truncation() {
    let small_output_cfg = SandboxConfig::default()
        .with_timeout_ms(3000)
        .with_max_output_bytes(64); // Only 64 bytes

    let runner = SandboxRunner::new(small_output_cfg).expect("Runner must construct");

    let receipt = runner
        .run_command(
            "/bin/sh",
            &["-c", "for i in $(seq 1 100); do echo -n 'A'; done"],
        )
        .expect("Command must execute");

    assert_eq!(receipt.status, SandboxStatus::Completed);
    assert!(receipt.output_truncated);
    assert_eq!(receipt.stdout.len(), 64);
}

#[test]
fn test_sandbox_zero_egress_preflight_blocks_outbound() {
    let runner = SandboxRunner::default_runner().expect("Runner must construct");

    let res = runner.run_command("curl", &["https://example.com/api"]);
    assert!(res.is_err(), "Outbound curl must be blocked fail-closed");

    let res_wget = runner.run_command("wget", &["http://1.2.3.4/malicious"]);
    assert!(res_wget.is_err(), "Outbound wget must be blocked fail-closed");
}
