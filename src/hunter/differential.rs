use serde::{Deserialize, Serialize};

use super::candidate::ReproductionArtifact;
use super::fuzzer::PropertyFuzzer;

/// Details of an invariant violation detected via differential testing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvariantViolated {
    pub input: Vec<u8>,
    pub baseline_output: Vec<u8>,
    pub candidate_output: Vec<u8>,
    pub reason: String,
}

/// Outcome of differential comparison.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DifferentialResult {
    Equivalent,
    Divergence(InvariantViolated),
}

/// Target execution trait for baseline and candidate implementations.
pub trait TargetImplementation {
    fn execute(&self, input: &[u8]) -> Result<Vec<u8>, String>;
}

impl<F> TargetImplementation for F
where
    F: Fn(&[u8]) -> Result<Vec<u8>, String>,
{
    fn execute(&self, input: &[u8]) -> Result<Vec<u8>, String> {
        self(input)
    }
}

/// Performs differential comparison between a baseline implementation
/// and a candidate/divergent implementation under identical inputs.
pub struct DifferentialComparator {
    corpus: Vec<Vec<u8>>,
}

impl Default for DifferentialComparator {
    fn default() -> Self {
        Self::new()
    }
}

impl DifferentialComparator {
    pub fn new() -> Self {
        Self { corpus: Vec::new() }
    }

    pub fn with_corpus(mut self, corpus: Vec<Vec<u8>>) -> Self {
        self.corpus = corpus;
        self
    }

    pub fn add_input(&mut self, input: Vec<u8>) {
        self.corpus.push(input);
    }

    /// Compares baseline and candidate over the registered corpus.
    /// If behavior diverges, returns `DifferentialResult::Divergence(InvariantViolated)`.
    pub fn compare<B: TargetImplementation, C: TargetImplementation>(
        &self,
        baseline: &B,
        candidate: &C,
    ) -> DifferentialResult {
        for input in &self.corpus {
            let base_res = baseline.execute(input);
            let cand_res = candidate.execute(input);

            match (base_res, cand_res) {
                (Ok(base_out), Ok(cand_out)) => {
                    if base_out != cand_out {
                        return DifferentialResult::Divergence(InvariantViolated {
                            input: input.clone(),
                            baseline_output: base_out,
                            candidate_output: cand_out,
                            reason: "InvariantViolated".to_string(),
                        });
                    }
                }
                (Ok(base_out), Err(cand_err)) => {
                    return DifferentialResult::Divergence(InvariantViolated {
                        input: input.clone(),
                        baseline_output: base_out,
                        candidate_output: cand_err.into_bytes(),
                        reason: "InvariantViolated".to_string(),
                    });
                }
                (Err(base_err), Ok(cand_out)) => {
                    return DifferentialResult::Divergence(InvariantViolated {
                        input: input.clone(),
                        baseline_output: base_err.into_bytes(),
                        candidate_output: cand_out,
                        reason: "InvariantViolated".to_string(),
                    });
                }
                (Err(base_err), Err(cand_err)) => {
                    if base_err != cand_err {
                        return DifferentialResult::Divergence(InvariantViolated {
                            input: input.clone(),
                            baseline_output: base_err.into_bytes(),
                            candidate_output: cand_err.into_bytes(),
                            reason: "InvariantViolated".to_string(),
                        });
                    }
                }
            }
        }

        DifferentialResult::Equivalent
    }

    /// Compares implementations with property fuzzer generation.
    pub fn compare_with_fuzzer<
        B: TargetImplementation + std::panic::RefUnwindSafe + Sync,
        C: TargetImplementation + std::panic::RefUnwindSafe + Sync,
    >(
        &self,
        baseline: &B,
        candidate: &C,
        fuzzer: &PropertyFuzzer,
    ) -> DifferentialResult {
        let static_res = self.compare(baseline, candidate);
        if let DifferentialResult::Divergence(_) = static_res {
            return static_res;
        }

        let prop = |input: &[u8]| -> Result<(), String> {
            let b_out = baseline.execute(input);
            let c_out = candidate.execute(input);
            match (b_out, c_out) {
                (Ok(b), Ok(c)) if b == c => Ok(()),
                (Err(b), Err(c)) if b == c => Ok(()),
                (Ok(b), Ok(c)) => Err(format!("Divergence: baseline {:?} != candidate {:?}", b, c)),
                (Ok(_), Err(e)) => Err(format!("Candidate error: {}", e)),
                (Err(e), Ok(_)) => Err(format!("Baseline error: {}", e)),
                (Err(b), Err(c)) => Err(format!("Error mismatch: '{}' vs '{}'", b, c)),
            }
        };

        if let Some(fuzz_rep) = fuzzer.fuzz(prop) {
            let base_out = baseline
                .execute(&fuzz_rep.minimized_trigger)
                .unwrap_or_default();
            let cand_out = candidate
                .execute(&fuzz_rep.minimized_trigger)
                .unwrap_or_else(|e| e.into_bytes());

            DifferentialResult::Divergence(InvariantViolated {
                input: fuzz_rep.minimized_trigger,
                baseline_output: base_out,
                candidate_output: cand_out,
                reason: "InvariantViolated".to_string(),
            })
        } else {
            DifferentialResult::Equivalent
        }
    }

    /// Converts a divergence into a verified `ReproductionArtifact`.
    pub fn create_reproduction_artifact(
        &self,
        divergence: &InvariantViolated,
    ) -> ReproductionArtifact {
        ReproductionArtifact::new(
            divergence.input.clone(),
            divergence.input.clone(),
            &format!(
                "Differential divergence detected: reason={}",
                divergence.reason
            ),
        )
    }
}
