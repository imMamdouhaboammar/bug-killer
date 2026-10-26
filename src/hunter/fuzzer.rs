use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::Instant;

use crate::engine::protocol::{
    EngineDescriptor, EvidenceCertaintyV1, EvidenceItemKind, EvidenceItemV1, FindingKind,
    FindingStatus, FindingV1, NormalizedSeverity, NormalizedTargetKind, ProofMethod, ProofV1,
    SourceSpanV1, TargetDescriptor,
};
use crate::hunter::hypothesis::{HypothesisCandidate, ThreatHypothesisFamily};

/// Security and behavioral invariant types tested by the differential fuzzer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum InvariantKind {
    /// Target must not panic, crash, or abort upon arbitrary valid or malformed input.
    NoPanic,
    /// Target execution memory must stay within strictly bounded limits.
    BoundedMemory,
    /// Target execution output must match baseline/oracle output under identical input.
    OutputEquivalence,
    /// Unauthenticated or unauthorized input must never satisfy privileged preconditions.
    AuthPreconditionHold,
    /// Repeated or sequential execution must yield equivalent idempotent state.
    IdempotentState,
}

impl InvariantKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            InvariantKind::NoPanic => "NoPanic",
            InvariantKind::BoundedMemory => "BoundedMemory",
            InvariantKind::OutputEquivalence => "OutputEquivalence",
            InvariantKind::AuthPreconditionHold => "AuthPreconditionHold",
            InvariantKind::IdempotentState => "IdempotentState",
        }
    }
}

/// Outcome of bounded property fuzzing and differential comparison.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FuzzOutcome {
    /// Invariant held across all generated inputs within configured iteration and time budgets.
    InvariantSatisfied,
    /// An invariant violation was discovered and deterministically minimized.
    InvariantViolated {
        minimized_input: Vec<u8>,
        error_description: String,
        trace: Vec<String>,
    },
    /// A test case exceeded configured per-case execution timeout.
    TimedOut,
    /// Iteration or resource budget was exhausted without conclusive invariant violation.
    BudgetExhausted,
}

impl FuzzOutcome {
    pub fn is_violation(&self) -> bool {
        matches!(self, FuzzOutcome::InvariantViolated { .. })
    }

    pub fn is_satisfied(&self) -> bool {
        matches!(self, FuzzOutcome::InvariantSatisfied)
    }

    pub fn is_timed_out(&self) -> bool {
        matches!(self, FuzzOutcome::TimedOut)
    }

    pub fn is_budget_exhausted(&self) -> bool {
        matches!(self, FuzzOutcome::BudgetExhausted)
    }
}

/// Bounded Property-Based Testing & Differential Execution Engine.
///
/// Executes candidate implementations against baseline oracles or security property invariants,
/// detects behavioral divergence or panic failures, and deterministically minimizes crashing inputs
/// using hierarchical binary delta shrinking (ddmin).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DifferentialFuzzer {
    pub max_iterations: usize,
    pub timeout_per_case_ms: u64,
    pub max_input_size_bytes: usize,
}

impl Default for DifferentialFuzzer {
    fn default() -> Self {
        Self {
            max_iterations: 100,
            timeout_per_case_ms: 1000,
            max_input_size_bytes: 4096,
        }
    }
}

impl DifferentialFuzzer {
    /// Creates a new `DifferentialFuzzer` with custom configuration bounds.
    pub fn new(
        max_iterations: usize,
        timeout_per_case_ms: u64,
        max_input_size_bytes: usize,
    ) -> Self {
        Self {
            max_iterations,
            timeout_per_case_ms,
            max_input_size_bytes,
        }
    }

    pub fn with_max_iterations(mut self, max_iterations: usize) -> Self {
        self.max_iterations = max_iterations;
        self
    }

    pub fn with_timeout_per_case_ms(mut self, timeout_per_case_ms: u64) -> Self {
        self.timeout_per_case_ms = timeout_per_case_ms;
        self
    }

    pub fn with_max_input_size_bytes(mut self, max_input_size_bytes: usize) -> Self {
        self.max_input_size_bytes = max_input_size_bytes;
        self
    }

    /// Fuzzes an invariant property checker with inputs supplied by `generator`.
    ///
    /// If an invariant violation occurs (either via `Err(err)` or process panic),
    /// the input is deterministically minimized via binary delta shrinking.
    pub fn fuzz_property<G, F>(&self, mut generator: G, property_checker: F) -> FuzzOutcome
    where
        G: FnMut(usize) -> Vec<u8>,
        F: Fn(&[u8]) -> Result<(), String>,
    {
        if self.max_iterations == 0 {
            return FuzzOutcome::BudgetExhausted;
        }

        for iteration in 0..self.max_iterations {
            let mut input = generator(iteration);
            if input.len() > self.max_input_size_bytes {
                input.truncate(self.max_input_size_bytes);
            }

            let start = Instant::now();
            let check_res =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| property_checker(&input)));
            let elapsed_ms = start.elapsed().as_millis() as u64;

            if self.timeout_per_case_ms > 0 && elapsed_ms > self.timeout_per_case_ms {
                return FuzzOutcome::TimedOut;
            }

            match check_res {
                Ok(Ok(())) => {
                    // Property invariant holds for this input
                    continue;
                }
                Ok(Err(err_msg)) => {
                    let mut trace = vec![format!(
                        "Iteration {}: Invariant violation with {}-byte input: {}",
                        iteration,
                        input.len(),
                        err_msg
                    )];
                    let (minimized_input, final_err) =
                        Self::minimize_delta_shrinking(&input, &property_checker, &mut trace);
                    return FuzzOutcome::InvariantViolated {
                        minimized_input,
                        error_description: final_err,
                        trace,
                    };
                }
                Err(payload) => {
                    let panic_msg = extract_panic_message(&*payload);
                    let mut trace = vec![format!(
                        "Iteration {}: Target panic/abort with {}-byte input: {}",
                        iteration,
                        input.len(),
                        panic_msg
                    )];
                    let (minimized_input, final_err) =
                        Self::minimize_delta_shrinking(&input, &property_checker, &mut trace);
                    return FuzzOutcome::InvariantViolated {
                        minimized_input,
                        error_description: final_err,
                        trace,
                    };
                }
            }
        }

        FuzzOutcome::InvariantSatisfied
    }

    /// Performs differential testing between a `baseline` implementation and a `target` implementation.
    ///
    /// Compares outputs on identical inputs; any divergence in output or termination behavior
    /// is treated as an invariant violation and deterministically minimized.
    pub fn differential_compare<G, F1, F2, O>(
        &self,
        mut generator: G,
        baseline: F1,
        target: F2,
    ) -> FuzzOutcome
    where
        G: FnMut(usize) -> Vec<u8>,
        F1: Fn(&[u8]) -> O,
        F2: Fn(&[u8]) -> O,
        O: PartialEq + std::fmt::Debug,
    {
        if self.max_iterations == 0 {
            return FuzzOutcome::BudgetExhausted;
        }

        let run_baseline = |inp: &[u8]| -> Result<O, String> {
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| baseline(inp))) {
                Ok(out) => Ok(out),
                Err(payload) => Err(format!(
                    "Baseline panicked: {}",
                    extract_panic_message(&*payload)
                )),
            }
        };

        let run_target = |inp: &[u8]| -> Result<O, String> {
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| target(inp))) {
                Ok(out) => Ok(out),
                Err(payload) => Err(format!(
                    "Target panicked: {}",
                    extract_panic_message(&*payload)
                )),
            }
        };

        let check_divergence = |inp: &[u8]| -> Result<(), String> {
            let out_b = run_baseline(inp);
            let out_t = run_target(inp);
            if out_b != out_t {
                Err(format!(
                    "Behavioral divergence detected:\n  Baseline: {:?}\n  Target:   {:?}",
                    out_b, out_t
                ))
            } else {
                Ok(())
            }
        };

        for iteration in 0..self.max_iterations {
            let mut input = generator(iteration);
            if input.len() > self.max_input_size_bytes {
                input.truncate(self.max_input_size_bytes);
            }

            let start = Instant::now();
            let div_res = check_divergence(&input);
            let elapsed_ms = start.elapsed().as_millis() as u64;

            if self.timeout_per_case_ms > 0 && elapsed_ms > self.timeout_per_case_ms {
                return FuzzOutcome::TimedOut;
            }

            if let Err(diff_msg) = div_res {
                let mut trace = vec![
                    format!(
                        "Iteration {}: Behavioral divergence detected with {}-byte input",
                        iteration,
                        input.len()
                    ),
                    diff_msg.clone(),
                ];
                let (minimized_input, final_err) =
                    Self::minimize_delta_shrinking(&input, &check_divergence, &mut trace);
                return FuzzOutcome::InvariantViolated {
                    minimized_input,
                    error_description: final_err,
                    trace,
                };
            }
        }

        FuzzOutcome::InvariantSatisfied
    }

    /// Minimizes a failing input using deterministic hierarchical binary delta shrinking (ddmin).
    pub fn minimize_delta_shrinking<F>(
        initial_input: &[u8],
        checker: &F,
        trace: &mut Vec<String>,
    ) -> (Vec<u8>, String)
    where
        F: Fn(&[u8]) -> Result<(), String>,
    {
        let is_failing = |candidate: &[u8]| -> Option<String> {
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| checker(candidate))) {
                Ok(Err(err)) => Some(err),
                Err(payload) => Some(extract_panic_message(&*payload)),
                Ok(Ok(())) => None,
            }
        };

        let mut current = initial_input.to_vec();
        let mut last_error = match is_failing(&current) {
            Some(err) => err,
            None => return (current, "Input did not violate property".to_string()),
        };

        trace.push(format!(
            "Delta shrinking initiated on {}-byte payload...",
            current.len()
        ));

        // Phase 1: Hierarchical chunk removal and isolation (classical ddmin)
        let mut granularity = 2usize;
        while current.len() >= 2 && granularity <= current.len() {
            let chunk_size = current.len().div_ceil(granularity);
            let mut reduced = false;
            let num_chunks = granularity;

            // Pass 1A: Try removing each chunk (test complement)
            for i in 0..num_chunks {
                let start = i * chunk_size;
                if start >= current.len() {
                    break;
                }
                let end = (start + chunk_size).min(current.len());

                let mut candidate = Vec::with_capacity(current.len() - (end - start));
                candidate.extend_from_slice(&current[..start]);
                candidate.extend_from_slice(&current[end..]);

                if candidate.is_empty() {
                    continue;
                }

                if let Some(err) = is_failing(&candidate) {
                    trace.push(format!(
                        "Delta shrinking: reduced {} -> {} bytes (removed chunk {}/{})",
                        current.len(),
                        candidate.len(),
                        i + 1,
                        granularity
                    ));
                    current = candidate;
                    last_error = err;
                    granularity = granularity.saturating_sub(1).max(2);
                    reduced = true;
                    break;
                }
            }

            if !reduced {
                // Pass 1B: Try isolating each chunk (test sub-chunk)
                for i in 0..num_chunks {
                    let start = i * chunk_size;
                    if start >= current.len() {
                        break;
                    }
                    let end = (start + chunk_size).min(current.len());
                    let candidate = current[start..end].to_vec();

                    if candidate.len() < current.len() && !candidate.is_empty() {
                        if let Some(err) = is_failing(&candidate) {
                            trace.push(format!(
                                "Delta shrinking: reduced {} -> {} bytes (isolated chunk {}/{})",
                                current.len(),
                                candidate.len(),
                                i + 1,
                                granularity
                            ));
                            current = candidate;
                            last_error = err;
                            granularity = 2;
                            reduced = true;
                            break;
                        }
                    }
                }
            }

            if !reduced {
                if granularity >= current.len() {
                    break;
                }
                granularity = (granularity * 2).min(current.len());
            }
        }

        // Phase 2: Single-byte deletion sweep
        let mut i = 0;
        while i < current.len() && current.len() > 1 {
            let mut candidate = current.clone();
            candidate.remove(i);
            if let Some(err) = is_failing(&candidate) {
                trace.push(format!(
                    "Single-byte reduction: removed byte at index {}, {} -> {} bytes",
                    i,
                    current.len(),
                    candidate.len()
                ));
                current = candidate;
                last_error = err;
            } else {
                i += 1;
            }
        }

        // Phase 3: Byte simplification pass (reducing bytes to 0 if still failing)
        for idx in 0..current.len() {
            if current[idx] != 0 {
                let mut candidate = current.clone();
                candidate[idx] = 0;
                if let Some(err) = is_failing(&candidate) {
                    current = candidate;
                    last_error = err;
                    trace.push(format!(
                        "Byte simplification: zeroed byte at offset {}",
                        idx
                    ));
                }
            }
        }

        let hex_encoded: String = current.iter().map(|b| format!("{:02x}", b)).collect();
        trace.push(format!(
            "Binary delta shrinking converged to {} bytes: [0x{}]",
            current.len(),
            hex_encoded
        ));

        (current, last_error)
    }

    /// Synthesizes a schema-compliant `FindingV1` conforming to `finding.schema.json`.
    ///
    /// Invariant: ONLY candidates in `CandidateState::Verified` with reliable test reproduction
    /// can be synthesized into a finding with `EvidenceCertaintyV1::Confirmed` and `FindingStatus::Verified`.
    pub fn synthesize_finding(
        &self,
        candidate: &HypothesisCandidate,
        outcome: &FuzzOutcome,
        snapshot_sha256: &str,
    ) -> Option<FindingV1> {
        // Enforce: ONLY verified candidates with reproducible invariant violation can be promoted
        if !candidate.can_promote_to_finding() {
            return None;
        }

        let (minimized_input, error_description, trace) = match outcome {
            FuzzOutcome::InvariantViolated {
                minimized_input,
                error_description,
                trace,
            } => (minimized_input, error_description, trace),
            _ => return None,
        };

        // Normalize source_snapshot_sha256 to 64-char lowercase hex
        let clean_snapshot_sha256 = if snapshot_sha256.len() == 64
            && snapshot_sha256
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        {
            snapshot_sha256.to_string()
        } else {
            let mut hasher = Sha256::new();
            hasher.update(snapshot_sha256.as_bytes());
            crate::to_hex(hasher.finalize())
        };

        // Artifact SHA-256 for minimized reproduction trigger
        let mut payload_hasher = Sha256::new();
        payload_hasher.update(minimized_input);
        let artifact_sha256 = crate::to_hex(payload_hasher.finalize());

        // Artifact SHA-256 for execution trace
        let trace_joined = trace.join("\n");
        let mut trace_hasher = Sha256::new();
        trace_hasher.update(trace_joined.as_bytes());
        let trace_sha256 = crate::to_hex(trace_hasher.finalize());

        // Map ThreatHypothesisFamily to standard CWE weakness ID
        let weakness_id = match candidate.family {
            ThreatHypothesisFamily::TrustBoundary => "CWE-20".to_string(),
            ThreatHypothesisFamily::AuthAuthz => "CWE-285".to_string(),
            ThreatHypothesisFamily::ParserDecoder => "CWE-125".to_string(),
            ThreatHypothesisFamily::StateMachineConcurrency => "CWE-362".to_string(),
            ThreatHypothesisFamily::Cryptography => "CWE-327".to_string(),
            ThreatHypothesisFamily::SupplyChain => "CWE-1395".to_string(),
            ThreatHypothesisFamily::BuildCi => "CWE-74".to_string(),
            ThreatHypothesisFamily::AgentMcp => "CWE-269".to_string(),
        };

        let hex_trigger: String = minimized_input
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        let evidence_items = vec![
            EvidenceItemV1 {
                kind: EvidenceItemKind::TestReproduction,
                artifact_sha256: artifact_sha256.clone(),
                description: format!(
                    "Fuzzed reproduction payload ({} bytes) violating invariant '{}': {}",
                    minimized_input.len(),
                    candidate.invariant,
                    error_description
                ),
                reference: Some(candidate.affected_path.clone()),
                limitations: Vec::new(),
            },
            EvidenceItemV1 {
                kind: EvidenceItemKind::RuntimeTrace,
                artifact_sha256: trace_sha256,
                description: format!(
                    "Deterministic minimization trace ({} steps) converging to [0x{}]",
                    trace.len(),
                    hex_trigger
                ),
                reference: None,
                limitations: Vec::new(),
            },
        ];

        let proof = ProofV1 {
            method: ProofMethod::ReproductionArtifact,
            artifact_sha256: artifact_sha256.clone(),
            reproduced_on_snapshot: clean_snapshot_sha256.clone(),
            limitations: Vec::new(),
        };

        let now = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let rule_id = format!("novel.hunter.{}", candidate.family.as_str().to_lowercase());

        let finding = FindingV1 {
            schema_version: "1.0".to_string(),
            run_id: format!("novel-hunter-{}", &clean_snapshot_sha256[..16]),
            finding_id: format!("novel-finding-{}", candidate.candidate_id),
            fingerprint: Some(artifact_sha256),
            kind: FindingKind::ResearchCandidate,
            status: FindingStatus::Verified,
            title: candidate.title.clone(),
            summary: Some(format!(
                "Verified novel vulnerability hypothesis: {}. Invariant '{}' violated: {}",
                candidate.title, candidate.invariant, error_description
            )),
            severity: match candidate.family {
                ThreatHypothesisFamily::TrustBoundary | ThreatHypothesisFamily::AuthAuthz => {
                    NormalizedSeverity::Critical
                }
                ThreatHypothesisFamily::ParserDecoder | ThreatHypothesisFamily::Cryptography => {
                    NormalizedSeverity::High
                }
                _ => NormalizedSeverity::Medium,
            },
            evidence_certainty: EvidenceCertaintyV1::Confirmed,
            rule_id: Some(rule_id),
            weakness_ids: vec![weakness_id],
            advisory_ids: Vec::new(),
            engine: EngineDescriptor {
                id: "bugkiller-differential-fuzzer".to_string(),
                version: "0.1.0".to_string(),
                rule_pack_sha256: Some(clean_snapshot_sha256.clone()),
            },
            target: TargetDescriptor {
                target_id: candidate.affected_path.clone(),
                kind: NormalizedTargetKind::File,
                path: Some(candidate.affected_path.clone()),
                package_purl: None,
                version: None,
                span: Some(SourceSpanV1 {
                    start_line: 1,
                    end_line: 1,
                    start_column: None,
                    end_column: None,
                }),
            },
            source_snapshot_sha256: clean_snapshot_sha256,
            evidence: evidence_items,
            proof: Some(proof),
            coverage_receipt_ids: vec![
                candidate
                    .reproduction_receipt_id
                    .clone()
                    .unwrap_or_else(|| format!("receipt-hunter-{}", candidate.candidate_id)),
            ],
            uncertainty_reasons: Vec::new(),
            remediation_plan_id: None,
            created_at: now,
            updated_at: None,
            extensions: serde_json::Map::new(),
        };

        if finding.validate().is_ok() {
            Some(finding)
        } else {
            None
        }
    }
}

/// Helper extracting panic payload message safely.
fn extract_panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&'static str>() {
        s.to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else if let Some(s) = payload.downcast_ref::<&str>() {
        s.to_string()
    } else {
        "Process panic/abort (unspecified payload)".to_string()
    }
}

// ----------------------------------------------------------------------------
// Compatibility layer for PropertyFuzzer and FuzzReproduction
// ----------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FuzzReproduction {
    pub raw_trigger: Vec<u8>,
    pub minimized_trigger: Vec<u8>,
    pub error_message: String,
    pub iterations_run: usize,
}

pub trait InvariantProperty {
    fn check(&self, input: &[u8]) -> Result<(), String>;
}

impl<F> InvariantProperty for F
where
    F: Fn(&[u8]) -> Result<(), String>,
{
    fn check(&self, input: &[u8]) -> Result<(), String> {
        self(input)
    }
}

#[derive(Debug, Clone)]
pub struct PropertyFuzzer {
    pub max_iterations: usize,
    pub seed_corpus: Vec<Vec<u8>>,
    pub max_input_len: usize,
}

impl Default for PropertyFuzzer {
    fn default() -> Self {
        Self::new()
    }
}

impl PropertyFuzzer {
    pub fn new() -> Self {
        Self {
            max_iterations: 1000,
            seed_corpus: vec![
                vec![],
                b"test".to_vec(),
                b"admin".to_vec(),
                b"0".to_vec(),
                b"-1".to_vec(),
                b"\x00".to_vec(),
                b"\xff".to_vec(),
            ],
            max_input_len: 256,
        }
    }

    pub fn with_iterations(mut self, max_iterations: usize) -> Self {
        self.max_iterations = max_iterations;
        self
    }

    pub fn with_seed_corpus(mut self, seeds: Vec<Vec<u8>>) -> Self {
        self.seed_corpus = seeds;
        self
    }

    pub fn with_max_input_len(mut self, max_input_len: usize) -> Self {
        self.max_input_len = max_input_len;
        self
    }

    pub fn add_seed(&mut self, seed: Vec<u8>) {
        self.seed_corpus.push(seed);
    }

    pub fn minimize_trigger<P: InvariantProperty + std::panic::RefUnwindSafe>(
        &self,
        trigger: &[u8],
        property: &P,
    ) -> Vec<u8> {
        let mut trace = Vec::new();
        let checker = |input: &[u8]| property.check(input);
        let (minimized, _) =
            DifferentialFuzzer::minimize_delta_shrinking(trigger, &checker, &mut trace);
        minimized
    }

    pub fn fuzz<P: InvariantProperty + std::panic::RefUnwindSafe>(
        &self,
        property: P,
    ) -> Option<FuzzReproduction> {
        let mut iterations_run = 0;

        // 1. Check seed corpus
        for seed in &self.seed_corpus {
            iterations_run += 1;
            if let Err(err) = property.check(seed) {
                let minimized = self.minimize_trigger(seed, &property);
                return Some(FuzzReproduction {
                    raw_trigger: seed.clone(),
                    minimized_trigger: minimized,
                    error_message: err,
                    iterations_run,
                });
            }
        }

        // 2. Deterministic PRNG exploration
        let mut current_corpus = if self.seed_corpus.is_empty() {
            vec![b"seed".to_vec()]
        } else {
            self.seed_corpus.clone()
        };

        let mut rng_state: u64 = 0x853c49e6748fea9b;
        let mut next_rand = || {
            rng_state = rng_state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            rng_state
        };

        for i in 0..self.max_iterations {
            iterations_run += 1;
            let parent_idx = (next_rand() as usize) % current_corpus.len();
            let mut candidate = current_corpus[parent_idx].clone();

            let mutation_kind = (next_rand() % 4) as usize;
            match mutation_kind {
                0 => {
                    // Bit flip
                    if !candidate.is_empty() {
                        let byte_idx = (next_rand() as usize) % candidate.len();
                        let bit_idx = (next_rand() % 8) as u8;
                        candidate[byte_idx] ^= 1 << bit_idx;
                    }
                }
                1 => {
                    // Byte insertion
                    if candidate.len() < self.max_input_len {
                        let insert_byte = (next_rand() % 256) as u8;
                        let insert_idx = if candidate.is_empty() {
                            0
                        } else {
                            (next_rand() as usize) % candidate.len()
                        };
                        candidate.insert(insert_idx, insert_byte);
                    }
                }
                2 => {
                    // Byte deletion
                    if candidate.len() > 1 {
                        let del_idx = (next_rand() as usize) % candidate.len();
                        candidate.remove(del_idx);
                    }
                }
                _ => {
                    // Byte replacement
                    if !candidate.is_empty() {
                        let byte_idx = (next_rand() as usize) % candidate.len();
                        candidate[byte_idx] = (next_rand() % 256) as u8;
                    }
                }
            }

            if let Err(err) = property.check(&candidate) {
                let minimized = self.minimize_trigger(&candidate, &property);
                return Some(FuzzReproduction {
                    raw_trigger: candidate,
                    minimized_trigger: minimized,
                    error_message: err,
                    iterations_run,
                });
            }

            if i % 50 == 0 && candidate.len() <= self.max_input_len {
                current_corpus.push(candidate);
            }
        }

        None
    }
}
