use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::advisory::correlator::{Affectedness, AffectednessCorrelator};
use crate::advisory::provider::{AdvisoryProvider, AdvisoryRecord};
use crate::advisory::sbom::{PackageIdentity, ResolutionKind};
use crate::engine::protocol::{
    EngineDescriptor, EvidenceCertaintyV1, EvidenceItemKind, EvidenceItemV1, FindingKind,
    FindingStatus, FindingV1, NormalizedSeverity, NormalizedTargetKind, ProofMethod, ProofV1,
    SourceSpanV1, TargetDescriptor,
};
use crate::types::{
    Affectedness as FindingAffectedness, Confidence, CveId, EvidenceCertainty, EvidenceRef,
    Finding, Severity, TargetKind,
};

/// High-level threat hypothesis taxonomy family from Chapter 5.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ThreatHypothesisFamily {
    TrustBoundary,
    AuthAuthz,
    ParserDecoder,
    StateMachineConcurrency,
    Cryptography,
    SupplyChain,
    BuildCi,
    AgentMcp,
}

impl ThreatHypothesisFamily {
    pub fn as_str(&self) -> &'static str {
        match self {
            ThreatHypothesisFamily::TrustBoundary => "TrustBoundary",
            ThreatHypothesisFamily::AuthAuthz => "AuthAuthz",
            ThreatHypothesisFamily::ParserDecoder => "ParserDecoder",
            ThreatHypothesisFamily::StateMachineConcurrency => "StateMachineConcurrency",
            ThreatHypothesisFamily::Cryptography => "Cryptography",
            ThreatHypothesisFamily::SupplyChain => "SupplyChain",
            ThreatHypothesisFamily::BuildCi => "BuildCi",
            ThreatHypothesisFamily::AgentMcp => "AgentMcp",
        }
    }

    pub fn required_evidence(&self) -> &'static str {
        match self {
            ThreatHypothesisFamily::TrustBoundary => "Source/sink trace + bounded reproduction",
            ThreatHypothesisFamily::AuthAuthz => "Role matrix + failing assertion",
            ThreatHypothesisFamily::ParserDecoder => {
                "Minimized deterministic crash or invariant violation"
            }
            ThreatHypothesisFamily::StateMachineConcurrency => "Deterministic scheduled trace",
            ThreatHypothesisFamily::Cryptography => "Cryptographic invariant test failures",
            ThreatHypothesisFamily::SupplyChain => "Local vendored source + bounded reproduction",
            ThreatHypothesisFamily::BuildCi => {
                "Synthetic CI policy fixture without live pipeline compromise"
            }
            ThreatHypothesisFamily::AgentMcp => "Sandboxed permission-contract test receipt",
        }
    }

    pub fn default_cwe(&self) -> &'static str {
        match self {
            ThreatHypothesisFamily::TrustBoundary => "CWE-501",
            ThreatHypothesisFamily::AuthAuthz => "CWE-285",
            ThreatHypothesisFamily::ParserDecoder => "CWE-1287",
            ThreatHypothesisFamily::StateMachineConcurrency => "CWE-362",
            ThreatHypothesisFamily::Cryptography => "CWE-310",
            ThreatHypothesisFamily::SupplyChain => "CWE-1357",
            ThreatHypothesisFamily::BuildCi => "CWE-1384",
            ThreatHypothesisFamily::AgentMcp => "CWE-269",
        }
    }
}

/// Permitted experiment kinds executed by the sandboxed research runner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ExperimentKind {
    HarnessFuzz,
    PropertyInvariant,
    DifferentialComparison,
    SanitizerFault,
}

impl ExperimentKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            ExperimentKind::HarnessFuzz => "HarnessFuzz",
            ExperimentKind::PropertyInvariant => "PropertyInvariant",
            ExperimentKind::DifferentialComparison => "DifferentialComparison",
            ExperimentKind::SanitizerFault => "SanitizerFault",
        }
    }
}

/// Specific reason why a research candidate was dismissed from novel vulnerability tracking.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CandidateDismissReason {
    NotReproducible,
    AlreadyKnownAdvisory(String),
    OutOfScope,
    BenignBehavior,
    DuplicateHypothesis(String),
}

pub type DismissalReason = CandidateDismissReason;

impl CandidateDismissReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            CandidateDismissReason::NotReproducible => "NotReproducible",
            CandidateDismissReason::AlreadyKnownAdvisory(_) => "AlreadyKnownAdvisory",
            CandidateDismissReason::OutOfScope => "OutOfScope",
            CandidateDismissReason::BenignBehavior => "BenignBehavior",
            CandidateDismissReason::DuplicateHypothesis(_) => "DuplicateHypothesis",
        }
    }
}

/// Lifecycle state machine for novel threat hypothesis candidates:
/// `Candidate -> Reproducing -> Verified / Dismissed / Inconclusive`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CandidateState {
    Candidate,
    Reproducing,
    Reproduced,
    Verified,
    Dismissed(CandidateDismissReason),
    Inconclusive(String),
    Blocked(String),
    SimulationOnly(String),
}

impl CandidateState {
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            CandidateState::Verified
                | CandidateState::Dismissed(_)
                | CandidateState::SimulationOnly(_)
        )
    }

    pub fn name(&self) -> &'static str {
        match self {
            CandidateState::Candidate => "Candidate",
            CandidateState::Reproducing => "Reproducing",
            CandidateState::Reproduced => "Reproduced",
            CandidateState::Verified => "Verified",
            CandidateState::Dismissed(_) => "Dismissed",
            CandidateState::Inconclusive(_) => "Inconclusive",
            CandidateState::Blocked(_) => "Blocked",
            CandidateState::SimulationOnly(_) => "SimulationOnly",
        }
    }
}

/// Errors raised during candidate lifecycle transitions and promotion gates.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum HypothesisError {
    #[error("Invalid state transition from {from} to {to}")]
    InvalidTransition { from: String, to: String },

    #[error(
        "Candidate cannot be promoted to finding: current state is {state}, must be Verified with physical reproduction receipt"
    )]
    CannotPromoteToFinding { state: String },

    #[error("Missing reproduction receipt required for candidate verification")]
    MissingReproductionReceipt,

    #[error(
        "Known advisory {advisory_id} exists for package {package}@{version}; cannot be claimed as novel"
    )]
    KnownAdvisoryExists {
        advisory_id: String,
        package: String,
        version: String,
    },

    #[error("Speculative hypothesis cannot self-certify without physical test reproduction")]
    SpeculativeSelfCertificationProhibited,

    #[error("Validation error: {0}")]
    Validation(String),
}

/// A structured novel vulnerability hypothesis candidate awaiting sandboxed physical reproduction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HypothesisCandidate {
    pub candidate_id: String,
    pub family: ThreatHypothesisFamily,
    pub title: String,
    pub asset: String,
    pub trust_boundary: String,
    pub input_class: String,
    pub invariant: String,
    pub affected_path: String,
    pub experiment_kind: ExperimentKind,
    pub preconditions: Vec<String>,
    pub evidence_requirements: Vec<String>,
    pub state: CandidateState,
    pub created_at: String,
    pub updated_at: String,
    pub reproduction_receipt_id: Option<String>,
}

impl HypothesisCandidate {
    /// Creates a new candidate in the initial `CandidateState::Candidate` state.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        candidate_id: impl Into<String>,
        family: ThreatHypothesisFamily,
        title: impl Into<String>,
        asset: impl Into<String>,
        trust_boundary: impl Into<String>,
        input_class: impl Into<String>,
        invariant: impl Into<String>,
        affected_path: impl Into<String>,
        experiment_kind: ExperimentKind,
        preconditions: Vec<String>,
        evidence_requirements: Vec<String>,
    ) -> Self {
        let now = Utc::now().to_rfc3339();
        Self {
            candidate_id: candidate_id.into(),
            family,
            title: title.into(),
            asset: asset.into(),
            trust_boundary: trust_boundary.into(),
            input_class: input_class.into(),
            invariant: invariant.into(),
            affected_path: affected_path.into(),
            experiment_kind,
            preconditions,
            evidence_requirements,
            state: CandidateState::Candidate,
            created_at: now.clone(),
            updated_at: now,
            reproduction_receipt_id: None,
        }
    }

    /// Evaluates if state transition is allowed and performs state transition.
    /// Invariant: Speculative AI/LLM hypotheses CANNOT self-certify as findings or claim Confirmed certainty
    /// without physical test reproduction (must have `reproduction_receipt_id` to enter `Verified`).
    pub fn transition_to(&mut self, next: CandidateState) -> Result<(), HypothesisError> {
        match (&self.state, &next) {
            // Candidate -> Reproducing, Reproduced, Dismissed, Inconclusive, Blocked, SimulationOnly
            (CandidateState::Candidate, CandidateState::Reproducing)
            | (CandidateState::Candidate, CandidateState::Dismissed(_))
            | (CandidateState::Candidate, CandidateState::Inconclusive(_))
            | (CandidateState::Candidate, CandidateState::Blocked(_))
            | (CandidateState::Candidate, CandidateState::SimulationOnly(_)) => {}

            // Reproducing -> Reproduced, Verified (MUST have reproduction receipt), Dismissed, Inconclusive, Reproducing (retry), SimulationOnly
            (CandidateState::Reproducing, CandidateState::Reproduced) => {}
            (CandidateState::Reproducing, CandidateState::Verified) => {
                if self.reproduction_receipt_id.is_none() {
                    return Err(HypothesisError::MissingReproductionReceipt);
                }
            }
            (CandidateState::Reproduced, CandidateState::Verified) => {
                if self.reproduction_receipt_id.is_none() {
                    return Err(HypothesisError::MissingReproductionReceipt);
                }
            }
            (CandidateState::Reproducing, CandidateState::Dismissed(_))
            | (CandidateState::Reproducing, CandidateState::Inconclusive(_))
            | (CandidateState::Reproducing, CandidateState::Reproducing)
            | (CandidateState::Reproduced, CandidateState::Dismissed(_))
            | (CandidateState::Reproducing, CandidateState::SimulationOnly(_))
            | (CandidateState::Reproduced, CandidateState::SimulationOnly(_)) => {}

            // Inconclusive -> Reproducing (retry with adjusted parameters), Dismissed
            (CandidateState::Inconclusive(_), CandidateState::Reproducing)
            | (CandidateState::Inconclusive(_), CandidateState::Dismissed(_)) => {}

            // Verified -> Dismissed (if subsequent analysis reveals duplicate or out-of-scope)
            (CandidateState::Verified, CandidateState::Dismissed(_)) => {}

            // Terminal Dismissed or invalid transition
            (from, to) => {
                return Err(HypothesisError::InvalidTransition {
                    from: format!("{:?}", from),
                    to: format!("{:?}", to),
                });
            }
        }

        self.state = next;
        self.touch();
        Ok(())
    }

    /// Transitions candidate to `CandidateState::Reproducing`.
    pub fn start_reproduction(&mut self) -> Result<(), HypothesisError> {
        self.transition_to(CandidateState::Reproducing)
    }

    /// Marks candidate as reproduced.
    pub fn mark_reproduced(
        &mut self,
        receipt_id: impl Into<String>,
    ) -> Result<(), HypothesisError> {
        self.reproduction_receipt_id = Some(receipt_id.into());
        self.transition_to(CandidateState::Reproduced)
    }

    /// Attaches physical test reproduction receipt and transitions candidate to `CandidateState::Verified`.
    pub fn mark_verified(&mut self, receipt_id: impl Into<String>) -> Result<(), HypothesisError> {
        self.reproduction_receipt_id = Some(receipt_id.into());
        self.transition_to(CandidateState::Verified)
    }

    /// Dismisses candidate with a specific dismiss reason.
    pub fn dismiss(&mut self, reason: CandidateDismissReason) -> Result<(), HypothesisError> {
        self.transition_to(CandidateState::Dismissed(reason))
    }

    /// Marks candidate as inconclusive when reproduction cannot definitively confirm or refute hypothesis.
    pub fn mark_inconclusive(&mut self, reason: impl Into<String>) -> Result<(), HypothesisError> {
        self.transition_to(CandidateState::Inconclusive(reason.into()))
    }

    /// Marks candidate as simulation only, quarantining it from verification and promotion.
    pub fn mark_simulation_only(
        &mut self,
        reason: impl Into<String>,
    ) -> Result<(), HypothesisError> {
        self.transition_to(CandidateState::SimulationOnly(reason.into()))
    }

    /// Sets reproduction receipt identifier without changing current state.
    pub fn set_reproduction_receipt(&mut self, receipt_id: impl Into<String>) {
        self.reproduction_receipt_id = Some(receipt_id.into());
        self.touch();
    }

    /// Promotion Gate: Returns true IF AND ONLY IF candidate is `CandidateState::Verified`
    /// AND has a valid physical reproduction receipt.
    ///
    /// Candidates in `Candidate`, `Reproducing`, `Dismissed`, or `Inconclusive` state return `false`.
    pub fn can_promote_to_finding(&self) -> bool {
        matches!(self.state, CandidateState::Verified) && self.reproduction_receipt_id.is_some()
    }

    /// Checks candidate novelty against known advisory database (OSV/GHSA).
    /// If an advisory already exists for the package/component at that version,
    /// it cannot be claimed as novel, transitioning state to `Dismissed(AlreadyKnownAdvisory)`
    /// and returning `false`.
    pub fn check_novelty_against_advisories(
        &mut self,
        advisories: &[AdvisoryRecord],
        package_name: &str,
        version: &str,
    ) -> bool {
        let pkg = PackageIdentity {
            ecosystem: self.asset.clone(),
            name: package_name.to_string(),
            resolved_version: Some(version.to_string()),
            purl: Some(format!("pkg:{}/{}@{}", self.asset, package_name, version)),
            direct: true,
            resolution_kind: ResolutionKind::LockedExact,
            commit: None,
            origin: None,
            path: None,
            source_digest: None,
            declared_requirement: None,
        };

        let correlator = AffectednessCorrelator::new();
        for adv in advisories {
            if correlator.evaluate_affectedness(&pkg, adv) == Affectedness::VersionAffected {
                let _ = self.dismiss(CandidateDismissReason::AlreadyKnownAdvisory(
                    adv.advisory_id.clone(),
                ));
                return false;
            }
        }

        true
    }

    /// Queries an `AdvisoryProvider` and verifies candidate novelty against returned advisories.
    /// Transitions to `Dismissed(AlreadyKnownAdvisory)` if a matching advisory affects this package/version.
    pub fn check_novelty_with_provider<P: AdvisoryProvider>(
        &mut self,
        provider: &P,
        purl: &str,
        version: &str,
    ) -> bool {
        let advisories = provider.get_advisories_for_package(purl);
        let pkg_name = purl
            .split('/')
            .next_back()
            .unwrap_or(purl)
            .split('@')
            .next()
            .unwrap_or(purl);

        self.check_novelty_against_advisories(&advisories, pkg_name, version)
    }

    /// Checks candidate novelty against a slice of known advisory IDs (CVE, GHSA, etc.).
    /// If title, asset, invariant, or affected path references any known advisory,
    /// or if any candidate ID is known, transitions to `Dismissed(AlreadyKnownAdvisory)`.
    pub fn check_novelty_against_advisory_ids(&mut self, known_ids: &[&str]) -> bool {
        let haystacks = [
            self.title.to_uppercase(),
            self.asset.to_uppercase(),
            self.invariant.to_uppercase(),
            self.affected_path.to_uppercase(),
            self.candidate_id.to_uppercase(),
        ];

        for &adv_id in known_ids {
            let needle = adv_id.to_uppercase();
            if haystacks.iter().any(|h| h.contains(&needle)) {
                let _ = self.dismiss(CandidateDismissReason::AlreadyKnownAdvisory(
                    adv_id.to_string(),
                ));
                return false;
            }
        }

        true
    }

    /// Promotes a verified novel candidate into a full `Finding` model.
    /// Fails closed if the candidate is not verified or lacks a reproduction receipt.
    pub fn promote_to_finding(
        &self,
        finding_id: &str,
        severity: Severity,
    ) -> Result<Finding, HypothesisError> {
        if !self.can_promote_to_finding() {
            return Err(HypothesisError::CannotPromoteToFinding {
                state: format!("{:?}", self.state),
            });
        }

        let receipt_id = self
            .reproduction_receipt_id
            .as_deref()
            .ok_or(HypothesisError::MissingReproductionReceipt)?;

        let mut finding = Finding::new(
            finding_id,
            CveId::Custom {
                id: self.candidate_id.clone(),
                title: self.title.clone(),
            },
            severity,
            TargetKind::GenericSourceFile,
            Some(PathBuf::from(&self.affected_path)),
            None,
            format!("Novel Candidate: {}", self.candidate_id),
            self.invariant.clone(),
            format!(
                "[Novel Vulnerability Hunter - {}] {}",
                self.family.as_str(),
                self.title
            ),
            "Physical sandboxed test reproduction confirmed invariant violation. Implement boundary validation or patch.".to_string(),
        );

        finding.evidence_certainty = EvidenceCertainty::Confirmed;
        finding.affectedness = FindingAffectedness::ConfirmedAffected;
        finding.confidence = Confidence::Confirmed;
        finding.category = "NOVEL_RESEARCH".to_string();
        finding.evidence_digest = receipt_id.to_string();
        finding.evidence_refs.push(EvidenceRef {
            location: self.affected_path.clone(),
            line_number: None,
            snippet: Some(format!(
                "Invariant: {} | Input Class: {}",
                self.invariant, self.input_class
            )),
            sha256: Some(receipt_id.to_string()),
        });
        finding.compute_dedupe_fingerprint();

        Ok(finding)
    }

    /// Synthesizes a schema-compliant `FindingV1` engine response from a verified candidate.
    pub fn synthesize_finding_v1(
        &self,
        run_id: &str,
        snapshot_sha256: &str,
    ) -> Result<FindingV1, HypothesisError> {
        if !self.can_promote_to_finding() {
            return Err(HypothesisError::CannotPromoteToFinding {
                state: format!("{:?}", self.state),
            });
        }

        let receipt_id = self
            .reproduction_receipt_id
            .as_deref()
            .ok_or(HypothesisError::MissingReproductionReceipt)?;

        let rule_id = format!("novel.hunter.{}", self.family.as_str().to_lowercase());

        let artifact_sha256 =
            if receipt_id.len() == 64 && receipt_id.chars().all(|c| c.is_ascii_hexdigit()) {
                receipt_id.to_string()
            } else {
                use sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();
                hasher.update(receipt_id.as_bytes());
                crate::to_hex(hasher.finalize())
            };

        let evidence_item = EvidenceItemV1 {
            kind: EvidenceItemKind::TestReproduction,
            artifact_sha256: artifact_sha256.clone(),
            description: format!(
                "Physical test reproduction confirmed invariant violation: {}",
                self.invariant
            ),
            reference: Some(self.affected_path.clone()),
            limitations: Vec::new(),
        };

        let proof = ProofV1 {
            method: ProofMethod::ReproductionArtifact,
            artifact_sha256: artifact_sha256.clone(),
            reproduced_on_snapshot: snapshot_sha256.to_string(),
            limitations: Vec::new(),
        };

        let finding = FindingV1 {
            schema_version: "1.0".to_string(),
            run_id: run_id.to_string(),
            finding_id: format!("novel-finding-{}", self.candidate_id),
            fingerprint: Some(receipt_id.to_string()),
            kind: FindingKind::ResearchCandidate,
            status: FindingStatus::Verified,
            title: self.title.clone(),
            summary: Some(format!(
                "{}: Invariant '{}' violated under input class '{}'",
                self.title, self.invariant, self.input_class
            )),
            severity: NormalizedSeverity::High,
            evidence_certainty: EvidenceCertaintyV1::Confirmed,
            rule_id: Some(rule_id),
            weakness_ids: vec![self.family.default_cwe().to_string()],
            advisory_ids: Vec::new(),
            engine: EngineDescriptor {
                id: "novel-hunter-engine".to_string(),
                version: "0.1.0".to_string(),
                rule_pack_sha256: Some(snapshot_sha256.to_string()),
            },
            target: TargetDescriptor {
                target_id: self.affected_path.clone(),
                kind: NormalizedTargetKind::File,
                path: Some(self.affected_path.clone()),
                package_purl: None,
                version: None,
                span: Some(SourceSpanV1 {
                    start_line: 1,
                    end_line: 1,
                    start_column: None,
                    end_column: None,
                }),
            },
            source_snapshot_sha256: snapshot_sha256.to_string(),
            evidence: vec![evidence_item],
            proof: Some(proof),
            coverage_receipt_ids: vec![receipt_id.to_string()],
            uncertainty_reasons: Vec::new(),
            remediation_plan_id: None,
            created_at: Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            updated_at: None,
            extensions: serde_json::Map::new(),
        };

        finding.validate().map_err(HypothesisError::Validation)?;

        Ok(finding)
    }

    fn touch(&mut self) {
        self.updated_at = Utc::now().to_rfc3339();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simulation_only_candidate_cannot_be_verified_or_promoted() {
        let mut candidate = HypothesisCandidate::new(
            "hypo-001",
            ThreatHypothesisFamily::AuthAuthz,
            "Unchecked mutation route",
            "endpoint",
            "boundary",
            "input",
            "Invariant holds",
            "src/server.js",
            ExperimentKind::PropertyInvariant,
            vec!["precondition".to_string()],
            vec!["evidence".to_string()],
        );

        assert_eq!(candidate.state, CandidateState::Candidate);
        assert!(!candidate.can_promote_to_finding());

        // Mark simulation only
        assert!(
            candidate
                .mark_simulation_only("Simulated experiment without runtime execution")
                .is_ok()
        );
        assert_eq!(
            candidate.state,
            CandidateState::SimulationOnly(
                "Simulated experiment without runtime execution".to_string()
            )
        );
        assert!(!candidate.can_promote_to_finding());

        // Cannot promote to finding
        assert!(
            candidate
                .promote_to_finding("finding-001", Severity::High)
                .is_err()
        );
        assert!(
            candidate
                .synthesize_finding_v1("run-001", "snapshot-hash")
                .is_err()
        );
    }
}
