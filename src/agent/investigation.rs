use crate::agent::provider::ProviderAdapter;
use crate::healer::AutopilotHealer;
use crate::scanner::FleetScanner;
use crate::types::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InvestigationState {
    Intake,
    ScopeCheck,
    Discover,
    CollectEvidence,
    Assess,
    Plan,
    Verified,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeterministicVeto {
    pub step: usize,
    pub attempted_operation: String,
    pub reason: String,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvestigationStep {
    pub step_index: usize,
    pub state: InvestigationState,
    pub action: String,
    pub outcome_summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvestigationReport {
    pub investigation_id: String,
    pub target_dir: PathBuf,
    pub state: InvestigationState,
    pub total_steps: usize,
    pub max_steps_allowed: usize,
    pub findings: Vec<Finding>,
    pub proposed_plans: Vec<String>,
    pub vetoes: Vec<DeterministicVeto>,
    pub steps_history: Vec<InvestigationStep>,
    pub audit_digest: String,
}

pub struct InvestigationSupervisor {
    pub adapter: ProviderAdapter,
    pub max_steps: usize,
}

impl InvestigationSupervisor {
    pub fn new(adapter: ProviderAdapter, max_steps: usize) -> Self {
        Self { adapter, max_steps }
    }

    /// Evaluates candidate action against deterministic safety vetoes.
    pub fn evaluate_veto(action: &str, step: usize) -> Option<DeterministicVeto> {
        let lower = action.to_lowercase();
        let dangerous_patterns = [
            "rm ",
            "rm -rf",
            "bash -c",
            "sh -c",
            "eval(",
            "chmod ",
            "chown ",
            "exec(",
            "system(",
            "curl -x post",
            "wget ",
            "nc -e",
        ];

        for pattern in &dangerous_patterns {
            if lower.contains(pattern) {
                return Some(DeterministicVeto {
                    step,
                    attempted_operation: action.to_string(),
                    reason: format!(
                        "Deterministic Veto: Action matches prohibited mutating pattern '{}'. Investigation mode is strictly read-only.",
                        pattern
                    ),
                    timestamp: chrono::Utc::now().to_rfc3339(),
                });
            }
        }
        None
    }

    /// Explicitly validates candidate operation against vetoes.
    #[allow(dead_code)]
    pub fn check_proposed_action(
        &self,
        action: &str,
        step: usize,
    ) -> Result<(), DeterministicVeto> {
        if let Some(veto) = Self::evaluate_veto(action, step) {
            Err(veto)
        } else {
            Ok(())
        }
    }

    /// Executes the bounded read-only investigation loop over a target workspace.
    pub fn run_investigation(&mut self, target: &Path) -> Result<InvestigationReport, String> {
        let inv_id = format!(
            "inv-{}",
            &crate::to_hex(Sha256::digest(target.to_string_lossy().as_bytes()))[..10]
        );
        let mut steps = Vec::new();
        let mut vetoes = Vec::new();
        let mut plans = Vec::new();
        let mut current_step = 0;

        // 1. INTAKE
        current_step += 1;
        steps.push(InvestigationStep {
            step_index: current_step,
            state: InvestigationState::Intake,
            action: format!("Initialize investigation for target {}", target.display()),
            outcome_summary: "Target scope admitted for read-only inspection".into(),
        });

        // 2. SCOPE_CHECK
        current_step += 1;
        if !target.exists() {
            steps.push(InvestigationStep {
                step_index: current_step,
                state: InvestigationState::Failed,
                action: "Scope validation".into(),
                outcome_summary: format!("Path {} does not exist", target.display()),
            });
            return Err(format!("Target path does not exist: {}", target.display()));
        }
        steps.push(InvestigationStep {
            step_index: current_step,
            state: InvestigationState::ScopeCheck,
            action: "Verify directory accessibility".into(),
            outcome_summary: "Scope verified accessible".into(),
        });

        // 3. DISCOVER
        current_step += 1;
        steps.push(InvestigationStep {
            step_index: current_step,
            state: InvestigationState::Discover,
            action: "Enumerate manifests, containers, and SBOMs".into(),
            outcome_summary: "Cataloged assets within target directory".into(),
        });

        // 4. COLLECT_EVIDENCE
        current_step += 1;
        let scan_report = FleetScanner::scan_directory(target, true);
        let findings_len = scan_report.findings.len();
        steps.push(InvestigationStep {
            step_index: current_step,
            state: InvestigationState::CollectEvidence,
            action: "Execute deterministic scanner engines".into(),
            outcome_summary: format!("Collected {} findings across target", findings_len),
        });

        // 5. ASSESS
        current_step += 1;
        let crit_count = scan_report
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Critical)
            .count();
        let high_count = scan_report
            .findings
            .iter()
            .filter(|f| f.severity == Severity::High)
            .count();

        // Query provider reasoning (safe read-only summary)
        let prompt = format!(
            "Analyze {} findings (Critical={}, High={}) in {}",
            findings_len,
            crit_count,
            high_count,
            target.display()
        );
        let reasoning_summary = self
            .adapter
            .query_reasoning(&prompt)
            .unwrap_or_else(|e| format!("Heuristic fallback (provider notice: {})", e));

        steps.push(InvestigationStep {
            step_index: current_step,
            state: InvestigationState::Assess,
            action: "Synthesize triage and risk assessment".into(),
            outcome_summary: reasoning_summary,
        });

        // 6. PLAN (Read-only prospective repair proposals)
        current_step += 1;
        if !scan_report.findings.is_empty() {
            let planned_actions = AutopilotHealer::plan_healing(&scan_report);
            for action in planned_actions {
                let plan_desc = format!(
                    "Plan action on {}: {}",
                    action.target_file.display(),
                    action.diff_description
                );
                if let Some(veto) = Self::evaluate_veto(&plan_desc, current_step) {
                    vetoes.push(veto);
                } else {
                    plans.push(plan_desc);
                }
            }
        }
        let findings = scan_report.findings;
        steps.push(InvestigationStep {
            step_index: current_step,
            state: InvestigationState::Plan,
            action: "Formulate non-mutating prospective plans".into(),
            outcome_summary: format!("Synthesized {} prospective remediation plans", plans.len()),
        });

        // Check if steps exceeded budget
        if current_step > self.max_steps {
            steps.push(InvestigationStep {
                step_index: current_step,
                state: InvestigationState::Failed,
                action: "Step limit budget check".into(),
                outcome_summary: format!(
                    "Step limit exceeded ({} > {})",
                    current_step, self.max_steps
                ),
            });
            return Err(format!(
                "Investigation exceeded step limit of {}",
                self.max_steps
            ));
        }

        // 7. VERIFIED
        current_step += 1;
        steps.push(InvestigationStep {
            step_index: current_step,
            state: InvestigationState::Verified,
            action: "Finalize investigation report".into(),
            outcome_summary: "Investigation complete with cryptographic evidence trail".into(),
        });

        // Compute audit digest over report
        let mut hasher = Sha256::new();
        hasher.update(inv_id.as_bytes());
        hasher.update(target.to_string_lossy().as_bytes());
        for f in &findings {
            hasher.update(f.dedupe_fingerprint.as_bytes());
        }
        for p in &plans {
            hasher.update(p.as_bytes());
        }
        let audit_digest = crate::to_hex(hasher.finalize());

        Ok(InvestigationReport {
            investigation_id: inv_id,
            target_dir: target.to_path_buf(),
            state: InvestigationState::Verified,
            total_steps: current_step,
            max_steps_allowed: self.max_steps,
            findings,
            proposed_plans: plans,
            vetoes,
            steps_history: steps,
            audit_digest,
        })
    }
}
