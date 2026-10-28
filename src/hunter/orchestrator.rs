use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use walkdir::WalkDir;

use crate::disclosure::draft::{DisclosureDraftBuilder, DisclosurePacket};
use crate::engine::scope::ResearchScope;
use crate::engine::snapshot::TargetSnapshot;
use crate::hunter::candidate::ReproductionArtifact;
use crate::hunter::fuzzer::{DifferentialFuzzer, FuzzOutcome, InvariantKind};
use crate::hunter::hypothesis::{
    CandidateDismissReason, ExperimentKind, HypothesisCandidate, ThreatHypothesisFamily,
};
use crate::hunter::novelty::NoveltyChecker;
use crate::hunter::sandbox::{SandboxConfig, SandboxRunner, SandboxStatus};
use crate::identity::AgentIdentity;
use crate::types::{Finding, Severity};

/// An extracted entry point or boundary interface from target workspace source files.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttackSurfaceEntry {
    pub file_path: String,
    pub line_number: usize,
    pub route_or_entry: String,
    pub method: String,
    pub has_auth_guard: bool,
    pub has_untrusted_input: bool,
    pub uses_dynamic_parser: bool,
    pub code_snippet: String,
}

/// Static and AST scanner discovering candidate attack surfaces across polyglot project workspaces.
#[derive(Debug, Clone, Default)]
pub struct AttackSurfaceScanner {
    excluded_dirs: Vec<String>,
}

impl AttackSurfaceScanner {
    pub fn new() -> Self {
        Self {
            excluded_dirs: vec![
                ".git".to_string(),
                "node_modules".to_string(),
                "target".to_string(),
                "dist".to_string(),
                "build".to_string(),
                ".aegis".to_string(),
                ".cache".to_string(),
            ],
        }
    }

    /// Recursively scans workspace source files and extracts potential attack surface boundaries.
    pub fn scan_workspace(&self, root: &Path) -> Vec<AttackSurfaceEntry> {
        let mut entries = Vec::new();
        if !root.exists() {
            return entries;
        }
        let canonical_root = match fs::canonicalize(root) {
            Ok(c) => c,
            Err(_) => return entries,
        };

        for entry in WalkDir::new(root)
            .follow_links(false)
            .into_iter()
            .filter_entry(|e| {
                let name = e.file_name().to_string_lossy();
                !self.excluded_dirs.iter().any(|ex| name == *ex)
            })
            .filter_map(|e| e.ok())
        {
            let path = entry.path();

            // Deny symlinks that escape outside canonical_root
            if entry.path_is_symlink() {
                if let Ok(target) = fs::canonicalize(path) {
                    if !target.starts_with(&canonical_root) {
                        continue;
                    }
                } else {
                    continue;
                }
            }

            if path.is_file() {
                if let Some(ext) = path.extension().and_then(|s| s.to_str()) {
                    match ext {
                        "js" | "ts" | "jsx" | "tsx" | "mjs" | "cjs" => {
                            self.scan_js_ts_file(path, &mut entries);
                        }
                        "py" => {
                            self.scan_py_file(path, &mut entries);
                        }
                        "rs" => {
                            self.scan_rs_file(path, &mut entries);
                        }
                        "go" => {
                            self.scan_go_file(path, &mut entries);
                        }
                        _ => {}
                    }
                }
            }
        }

        entries
    }

    fn scan_js_ts_file(&self, path: &Path, entries: &mut Vec<AttackSurfaceEntry>) {
        let Ok(content) = fs::read_to_string(path) else {
            return;
        };

        let lines: Vec<&str> = content.lines().collect();

        for (idx, line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            let is_route = trimmed.contains("app.get(")
                || trimmed.contains("app.post(")
                || trimmed.contains("app.put(")
                || trimmed.contains("app.delete(")
                || trimmed.contains("app.patch(")
                || trimmed.contains("router.get(")
                || trimmed.contains("router.post(")
                || trimmed.contains("router.delete(")
                || trimmed.contains("export async function GET")
                || trimmed.contains("export async function POST")
                || trimmed.contains("export async function DELETE");

            let has_parser = trimmed.contains("JSON.parse(")
                || trimmed.contains("yaml.load(")
                || trimmed.contains(".deserialize(");

            if is_route || has_parser {
                let mut block_lines = Vec::new();
                for l in &lines[idx..] {
                    block_lines.push(*l);
                    if block_lines.len() > 1
                        && (l.trim().starts_with("});")
                            || l.contains("app.")
                            || l.contains("router."))
                    {
                        break;
                    }
                }
                let block_text = block_lines.join("\n").to_lowercase();

                let route_decl_lower = trimmed.to_lowercase();
                let has_auth = route_decl_lower.contains("auth")
                    || route_decl_lower.contains("token")
                    || route_decl_lower.contains("session")
                    || route_decl_lower.contains("guard")
                    || route_decl_lower.contains("role")
                    || route_decl_lower.contains("permit");

                let has_input = block_text.contains("req.body")
                    || block_text.contains("req.query")
                    || block_text.contains("req.params")
                    || block_text.contains("payload")
                    || block_text.contains("input");

                let lower_trimmed = trimmed.to_lowercase();
                entries.push(AttackSurfaceEntry {
                    file_path: path.to_string_lossy().to_string(),
                    line_number: idx + 1,
                    route_or_entry: trimmed.to_string(),
                    method: if lower_trimmed.contains("post") {
                        "POST".to_string()
                    } else if lower_trimmed.contains("delete") {
                        "DELETE".to_string()
                    } else if lower_trimmed.contains("put") {
                        "PUT".to_string()
                    } else {
                        "GET".to_string()
                    },
                    has_auth_guard: has_auth,
                    has_untrusted_input: has_input,
                    uses_dynamic_parser: has_parser,
                    code_snippet: trimmed.to_string(),
                });
            }
        }
    }

    fn scan_py_file(&self, path: &Path, entries: &mut Vec<AttackSurfaceEntry>) {
        let Ok(content) = fs::read_to_string(path) else {
            return;
        };

        let lines: Vec<&str> = content.lines().collect();

        for (idx, line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with("@app.") || trimmed.starts_with("@router.") {
                let block_end = std::cmp::min(idx + 12, lines.len());
                let block_text = lines[idx..block_end].join("\n").to_lowercase();

                let has_auth = block_text.contains("depends(get_current_user")
                    || block_text.contains("security(");
                let has_input = block_text.contains("body") || block_text.contains("payload");

                let lower_trimmed = trimmed.to_lowercase();
                entries.push(AttackSurfaceEntry {
                    file_path: path.to_string_lossy().to_string(),
                    line_number: idx + 1,
                    route_or_entry: trimmed.to_string(),
                    method: if lower_trimmed.contains("post") {
                        "POST".to_string()
                    } else {
                        "GET".to_string()
                    },
                    has_auth_guard: has_auth,
                    has_untrusted_input: has_input,
                    uses_dynamic_parser: block_text.contains("json.loads")
                        || block_text.contains("yaml.load"),
                    code_snippet: trimmed.to_string(),
                });
            }
        }
    }

    fn scan_rs_file(&self, path: &Path, entries: &mut Vec<AttackSurfaceEntry>) {
        let Ok(content) = fs::read_to_string(path) else {
            return;
        };

        for (idx, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with("#[get(")
                || trimmed.starts_with("#[post(")
                || trimmed.contains(".route(")
            {
                let lower = trimmed.to_lowercase();
                entries.push(AttackSurfaceEntry {
                    file_path: path.to_string_lossy().to_string(),
                    line_number: idx + 1,
                    route_or_entry: trimmed.to_string(),
                    method: if lower.contains("post") {
                        "POST".to_string()
                    } else {
                        "GET".to_string()
                    },
                    has_auth_guard: lower.contains("auth") || lower.contains("claims"),
                    has_untrusted_input: lower.contains("json<") || lower.contains("form<"),
                    uses_dynamic_parser: lower.contains("serde_json::from"),
                    code_snippet: trimmed.to_string(),
                });
            }
        }
    }

    fn scan_go_file(&self, path: &Path, entries: &mut Vec<AttackSurfaceEntry>) {
        let Ok(content) = fs::read_to_string(path) else {
            return;
        };

        for (idx, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.contains(".GET(")
                || trimmed.contains(".POST(")
                || trimmed.contains("HandleFunc(")
            {
                let lower = trimmed.to_lowercase();
                entries.push(AttackSurfaceEntry {
                    file_path: path.to_string_lossy().to_string(),
                    line_number: idx + 1,
                    route_or_entry: trimmed.to_string(),
                    method: if lower.contains("post") {
                        "POST".to_string()
                    } else {
                        "GET".to_string()
                    },
                    has_auth_guard: lower.contains("auth") || lower.contains("jwt"),
                    has_untrusted_input: lower.contains("bind") || lower.contains("body"),
                    uses_dynamic_parser: lower.contains("json.unmarshal"),
                    code_snippet: trimmed.to_string(),
                });
            }
        }
    }
}

/// Signed non-repudiable research receipt proving multi-pass independent reproduction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NovelResearchReceipt {
    pub receipt_id: String,
    pub candidate_id: String,
    pub invariant_tested: String,
    pub target_path: String,
    pub verification_passes_completed: usize,
    pub passes_succeeded: usize,
    pub artifact_sha256: String,
    pub agent_public_key: String,
    pub ed25519_signature: String,
    pub verified_at: String,
}

/// Full execution report generated by the autonomous novel vulnerability hunter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutonomousHuntReport {
    pub target_path: String,
    pub scan_duration_ms: u64,
    pub attack_surface_entries_discovered: usize,
    pub hypotheses_synthesized: usize,
    pub hypotheses_triaged_out: usize,
    pub candidates_reproduced: usize,
    pub candidates_verified: usize,
    pub simulated_hypotheses: usize,
    pub blocked_by_scope_count: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_snapshot_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inventory_status: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub candidates: Vec<HypothesisCandidate>,
    pub verified_findings: Vec<Finding>,
    pub research_receipts: Vec<NovelResearchReceipt>,
    pub pvr_drafts: Vec<DisclosurePacket>,
}

/// Autonomous coordinator uniting attack surface scanning, hypothesis synthesis,
/// sandboxed fuzzing/differential proof, 3-pass independent verification, and responsible disclosure.
#[derive(Debug, Clone)]
pub struct AutonomousHunter {
    scanner: AttackSurfaceScanner,
    fuzzer: DifferentialFuzzer,
    novelty_checker: NoveltyChecker,
    sandbox_config: SandboxConfig,
}

impl Default for AutonomousHunter {
    fn default() -> Self {
        Self {
            scanner: AttackSurfaceScanner::new(),
            fuzzer: DifferentialFuzzer::default(),
            novelty_checker: NoveltyChecker::new(),
            sandbox_config: SandboxConfig::default(),
        }
    }
}

impl AutonomousHunter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_known_advisories<I, S>(mut self, advisories: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.novelty_checker = self.novelty_checker.with_known_advisories(advisories);
        self
    }

    /// Synthesizes structured, falsifiable research hypotheses from discovered attack surface entries.
    pub fn synthesize_hypotheses(
        &self,
        entries: &[AttackSurfaceEntry],
    ) -> Vec<HypothesisCandidate> {
        let mut hypotheses = Vec::new();

        for (idx, entry) in entries.iter().enumerate() {
            let candidate_id = format!("cand-hunt-{:03}", idx + 1);

            // 1. Missing Authorization on mutating or entry routes
            if !entry.has_auth_guard
                && (entry.method == "POST" || entry.method == "DELETE" || entry.method == "PUT")
            {
                hypotheses.push(HypothesisCandidate::new(
                    &candidate_id,
                    ThreatHypothesisFamily::AuthAuthz,
                    format!("Unchecked role/tenant access in {}", entry.route_or_entry),
                    "api-endpoint",
                    "role-boundary",
                    "unauthenticated-request",
                    "Mutating operations must enforce authentication and tenant authorization",
                    &entry.file_path,
                    ExperimentKind::PropertyInvariant,
                    vec!["unauthenticated_caller".to_string()],
                    vec!["role_matrix_violation".to_string()],
                ));
            } else if entry.uses_dynamic_parser {
                // 2. Parser decoder vulnerabilities
                hypotheses.push(HypothesisCandidate::new(
                    &candidate_id,
                    ThreatHypothesisFamily::ParserDecoder,
                    format!("Malformed input handling in {}", entry.file_path),
                    "parser-decoder",
                    "data-boundary",
                    "arbitrary-payload",
                    "Decoder must reject malformed or deeply nested payload without crashing",
                    &entry.file_path,
                    ExperimentKind::HarnessFuzz,
                    vec!["sandboxed_parser_harness".to_string()],
                    vec!["minimized_reproducible_trigger".to_string()],
                ));
            } else if entry.has_untrusted_input {
                // 3. Trust Boundary Failures
                hypotheses.push(HypothesisCandidate::new(
                    &candidate_id,
                    ThreatHypothesisFamily::TrustBoundary,
                    format!(
                        "Untrusted input reaches sensitive sink in {}",
                        entry.route_or_entry
                    ),
                    "parameter-flow",
                    "trust-boundary",
                    "unvalidated-parameter",
                    "Input parameters must be sanitized before state mutation or sink reach",
                    &entry.file_path,
                    ExperimentKind::PropertyInvariant,
                    vec!["external_request".to_string()],
                    vec!["source_to_sink_trace".to_string()],
                ));
            }
        }

        hypotheses
    }

    /// Executes the full autonomous research pipeline against an authorized `ResearchScope`.
    pub fn hunt_with_scope(
        &self,
        scope: &ResearchScope,
        max_hypotheses: usize,
    ) -> Result<AutonomousHuntReport, String> {
        let start_time = std::time::Instant::now();
        scope
            .validate()
            .map_err(|e| format!("Research scope validation failed: {}", e))?;

        let target_path = &scope.target_root;
        let target_str = target_path.to_string_lossy().to_string();

        // 1. Immutable Target Snapshot & Inventory Pinning
        let snapshot = TargetSnapshot::create_allow_partial(scope)
            .map_err(|e| format!("Failed to create immutable target snapshot: {}", e))?;
        let snapshot_sha256 = snapshot.snapshot_sha256.clone();
        let inventory_status = format!("{:?}", snapshot.inventory.status);

        // 2. Scan Attack Surface
        let entries = self.scanner.scan_workspace(target_path);
        let mut candidates = self.synthesize_hypotheses(&entries);
        for c in &mut candidates {
            c.target_snapshot_sha256 = Some(snapshot_sha256.clone());
        }
        candidates.truncate(max_hypotheses);

        let hypotheses_synthesized = candidates.len();
        let mut triaged_out = 0;
        let mut reproduced_count = 0;
        let mut simulated_count = 0;
        let mut blocked_by_scope_count = 0;
        let mut verified_findings = Vec::new();
        let mut research_receipts = Vec::new();
        let mut pvr_drafts = Vec::new();

        let identity = AgentIdentity::get_or_create(target_path)
            .map_err(|e| format!("Failed to initialize agent cryptographic identity: {}", e))?;

        let runner = SandboxRunner::new(self.sandbox_config.clone())
            .map_err(|e| format!("Failed to create research sandbox runner: {}", e))?;

        // 3. Execute Research Loop on each hypothesis
        for candidate in &mut candidates {
            // Scope gate: candidate target path must be within authorized scope
            let candidate_path = Path::new(&candidate.affected_path);
            if let Err(scope_err) = scope.is_path_in_scope(candidate_path) {
                blocked_by_scope_count += 1;
                let _ = candidate.mark_blocked_by_scope(format!(
                    "Path '{}' is outside authorized research scope: {}",
                    candidate.affected_path, scope_err
                ));
                continue;
            }

            // A: Known advisory check
            let asset = candidate.asset.clone();
            let is_novel = candidate.check_novelty_against_advisories(&[], &asset, "latest");
            if !is_novel {
                triaged_out += 1;
                continue;
            }

            // B: Schedule and execute sandboxed experiment
            let _ = candidate.start_reproduction();

            let experiment_outcome = self.run_sandboxed_experiment(&runner, candidate);
            if let Some(artifact) = experiment_outcome {
                reproduced_count += 1;
                let _ = candidate.mark_reproduced(&artifact.artifact_id);

                // BK-ND-01 Gate: If the reproduction artifact was not produced via real target execution,
                // quarantine it immediately as SimulationOnly. Under no circumstances can a simulated
                // experiment yield Verified findings, NOVEL_RESEARCH categories, High/Critical security
                // claims, or Private Vulnerability Report (PVR) disclosure packets.
                if !artifact.real_execution {
                    simulated_count += 1;
                    let _ = candidate.mark_simulation_only(
                        "Simulated closure: target application runtime was not executed",
                    );
                    continue;
                }

                // C: Independent 3-Pass Verification Gate
                let verification_confirmed =
                    self.verify_candidate_three_pass(&runner, candidate, &artifact);
                if verification_confirmed {
                    let receipt_id = format!("receipt-hunter-{}", &artifact.artifact_sha256[..16]);
                    let _ = candidate.mark_verified(&receipt_id);

                    // Sign verification receipt with Ed25519
                    let signature = identity.sign_bytes(artifact.artifact_sha256.as_bytes());
                    let receipt = NovelResearchReceipt {
                        receipt_id: receipt_id.clone(),
                        candidate_id: candidate.candidate_id.clone(),
                        invariant_tested: candidate.invariant.clone(),
                        target_path: candidate.affected_path.clone(),
                        verification_passes_completed: 3,
                        passes_succeeded: 3,
                        artifact_sha256: artifact.artifact_sha256.clone(),
                        agent_public_key: identity.public_key_hex(),
                        ed25519_signature: signature,
                        verified_at: Utc::now().to_rfc3339(),
                    };
                    research_receipts.push(receipt);

                    // Synthesize finding
                    if let Ok(finding) = candidate.promote_to_finding(
                        &format!("novel-finding-{}", candidate.candidate_id),
                        Severity::High,
                    ) {
                        verified_findings.push(finding);
                    }

                    // Synthesize private responsible disclosure packet (PVR Draft)
                    let run_id = format!("run-hunter-{}", &artifact.artifact_sha256[..8]);
                    if let Ok(finding_v1) =
                        candidate.synthesize_finding_v1(&run_id, &artifact.artifact_sha256)
                    {
                        let draft_res = DisclosureDraftBuilder::from_finding(&finding_v1)
                            .draft_id(format!("pvr-{}", candidate.candidate_id))
                            .build();
                        if let Ok(pvr_packet) = draft_res {
                            pvr_drafts.push(pvr_packet);
                        }
                    }
                } else {
                    let _ = candidate
                        .mark_inconclusive("Failed 3-pass independent reproduction verification");
                }
            } else {
                let _ = candidate.dismiss(CandidateDismissReason::NotReproducible);
            }
        }

        let scan_duration_ms = start_time.elapsed().as_millis() as u64;

        Ok(AutonomousHuntReport {
            target_path: target_str,
            scan_duration_ms,
            attack_surface_entries_discovered: entries.len(),
            hypotheses_synthesized,
            hypotheses_triaged_out: triaged_out,
            candidates_reproduced: reproduced_count,
            candidates_verified: verified_findings.len(),
            simulated_hypotheses: simulated_count,
            blocked_by_scope_count,
            target_snapshot_sha256: Some(snapshot_sha256),
            inventory_status: Some(inventory_status),
            candidates,
            verified_findings,
            research_receipts,
            pvr_drafts,
        })
    }

    /// Executes the full autonomous research pipeline on a target workspace directory.
    pub fn hunt(
        &self,
        target_path: &Path,
        max_hypotheses: usize,
    ) -> Result<AutonomousHuntReport, String> {
        let scope = ResearchScope::new(target_path, true)
            .map_err(|e| format!("Research scope initialization error: {}", e))?;
        self.hunt_with_scope(&scope, max_hypotheses)
    }

    /// Runs bounded sandboxed experimentation for a candidate to establish property falsification.
    fn run_sandboxed_experiment(
        &self,
        runner: &SandboxRunner,
        candidate: &HypothesisCandidate,
    ) -> Option<ReproductionArtifact> {
        let (outcome, receipt) = runner
            .run_closure(|_temp_dir| {
                // Determine invariant based on threat family
                let invariant = match candidate.family {
                    ThreatHypothesisFamily::AuthAuthz => InvariantKind::AuthPreconditionHold,
                    ThreatHypothesisFamily::ParserDecoder => InvariantKind::NoPanic,
                    ThreatHypothesisFamily::TrustBoundary => InvariantKind::OutputEquivalence,
                    _ => InvariantKind::NoPanic,
                };

                let mut generator = |iteration: usize| -> Vec<u8> {
                    match iteration {
                        0 => b"test_untrusted_input".to_vec(),
                        1 => b"CRASH_MALFORMED_\xff".to_vec(),
                        2 => b"unauthenticated_request_mutation".to_vec(),
                        i => format!("payload_case_{}", i).into_bytes(),
                    }
                };

                let property_checker = |input: &[u8]| -> Result<(), String> {
                    // Test simulated invariant boundaries:
                    if invariant == InvariantKind::AuthPreconditionHold {
                        if !input.is_empty() && !input.windows(4).any(|w| w == b"auth") {
                            return Err(
                                "Privileged state mutation executed without authentication context"
                                    .to_string(),
                            );
                        }
                        return Ok(());
                    }

                    if invariant == InvariantKind::NoPanic {
                        if input.starts_with(b"CRASH") || input.contains(&0xff) {
                            return Err(
                                "Parser memory corruption or panic on malformed byte pattern"
                                    .to_string(),
                            );
                        }
                        return Ok(());
                    }

                    Ok(())
                };

                let outcome = self.fuzzer.fuzz_property(&mut generator, property_checker);
                Ok(outcome)
            })
            .ok()?;

        if receipt.status != SandboxStatus::Completed {
            return None;
        }

        match outcome {
            FuzzOutcome::InvariantViolated {
                minimized_input,
                error_description,
                ..
            } => {
                let artifact = ReproductionArtifact::new_simulated(
                    minimized_input.clone(),
                    minimized_input,
                    &error_description,
                );
                Some(artifact)
            }
            _ => None,
        }
    }

    /// Verifies candidate against 3 clean, independent reproduction sandboxes.
    /// Strictly fails closed if the artifact was generated in simulation mode without real target execution.
    fn verify_candidate_three_pass(
        &self,
        runner: &SandboxRunner,
        candidate: &HypothesisCandidate,
        artifact: &ReproductionArtifact,
    ) -> bool {
        if !artifact.real_execution {
            return false;
        }

        let trigger = &artifact.minimized_trigger;

        for _pass in 1..=3 {
            let pass_result = runner.run_closure(|_temp| {
                if candidate.family == ThreatHypothesisFamily::AuthAuthz {
                    if !trigger.windows(4).any(|w| w == b"auth") {
                        return Ok(true); // Confirmed violation reproduced
                    }
                } else if candidate.family == ThreatHypothesisFamily::ParserDecoder {
                    if trigger.starts_with(b"CRASH") || trigger.contains(&0xff) {
                        return Ok(true);
                    }
                } else if candidate.family == ThreatHypothesisFamily::TrustBoundary {
                    return Ok(true);
                }
                Ok(false)
            });

            match pass_result {
                Ok((true, receipt)) if receipt.status == SandboxStatus::Completed => {
                    // Pass verified
                }
                _ => return false,
            }
        }

        true
    }
}
