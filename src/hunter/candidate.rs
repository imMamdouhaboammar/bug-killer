use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub use super::hypothesis::{CandidateDismissReason, CandidateState, DismissalReason};
use crate::engine::protocol::{
    EngineDescriptor, EvidenceCertaintyV1, EvidenceItemKind, EvidenceItemV1, FindingKind,
    FindingStatus, FindingV1, NormalizedSeverity, NormalizedTargetKind, ProofMethod, ProofV1,
    SourceSpanV1, TargetDescriptor,
};

/// A deterministic reproduction artifact capturing the triggering input and evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReproductionArtifact {
    pub artifact_id: String,
    pub artifact_sha256: String,
    pub raw_payload: Vec<u8>,
    pub minimized_trigger: Vec<u8>,
    pub error_message: String,
    pub captured_at: String,
    pub real_execution: bool,
}

impl ReproductionArtifact {
    pub fn new(raw_payload: Vec<u8>, minimized_trigger: Vec<u8>, error_message: &str) -> Self {
        Self::with_execution(raw_payload, minimized_trigger, error_message, true)
    }

    pub fn new_simulated(
        raw_payload: Vec<u8>,
        minimized_trigger: Vec<u8>,
        error_message: &str,
    ) -> Self {
        Self::with_execution(raw_payload, minimized_trigger, error_message, false)
    }

    pub fn with_execution(
        raw_payload: Vec<u8>,
        minimized_trigger: Vec<u8>,
        error_message: &str,
        real_execution: bool,
    ) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(&minimized_trigger);
        let artifact_sha256 = crate::to_hex(hasher.finalize());
        let artifact_id = format!("artifact-{}", &artifact_sha256[..16]);

        Self {
            artifact_id,
            artifact_sha256,
            raw_payload,
            minimized_trigger,
            error_message: error_message.to_string(),
            captured_at: Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            real_execution,
        }
    }
}

/// A research candidate undergoing bounded hypothesis generation and differential proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResearchCandidate {
    pub candidate_id: String,
    pub title: String,
    pub target_path: String,
    pub weakness: String,
    pub hypothesis: String,
    pub state: CandidateState,
    pub reproduction_artifact: Option<ReproductionArtifact>,
    pub created_at: String,
    pub updated_at: String,
}

pub type NovelCandidate = ResearchCandidate;

impl ResearchCandidate {
    /// Creates a new candidate in the initial `CandidateState::Candidate` state.
    pub fn new(
        candidate_id: &str,
        title: &str,
        target_path: &str,
        weakness: &str,
        hypothesis: &str,
    ) -> Self {
        let now = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        Self {
            candidate_id: candidate_id.to_string(),
            title: title.to_string(),
            target_path: target_path.to_string(),
            weakness: weakness.to_string(),
            hypothesis: hypothesis.to_string(),
            state: CandidateState::Candidate,
            reproduction_artifact: None,
            created_at: now.clone(),
            updated_at: now,
        }
    }

    /// Promotion Gate: Returns true if and only if the candidate has been successfully reproduced
    /// through real target execution and verified (`CandidateState::Verified`).
    pub fn can_promote_to_finding(&self) -> bool {
        if !matches!(self.state, CandidateState::Verified) {
            return false;
        }
        match &self.reproduction_artifact {
            Some(artifact) => artifact.real_execution,
            None => false,
        }
    }

    /// Transitions the candidate from Candidate into Reproducing.
    pub fn start_reproduction(&mut self) -> Result<(), String> {
        match self.state {
            CandidateState::Candidate => {
                self.state = CandidateState::Reproducing;
                self.touch();
                Ok(())
            }
            _ => Err(format!(
                "Cannot start reproduction from state {:?}",
                self.state
            )),
        }
    }

    /// Records a successful reproduction artifact, moving candidate to `Reproduced`.
    pub fn mark_reproduced(&mut self, artifact: ReproductionArtifact) -> Result<(), String> {
        match self.state {
            CandidateState::Reproducing | CandidateState::Candidate => {
                self.reproduction_artifact = Some(artifact);
                self.state = CandidateState::Reproduced;
                self.touch();
                Ok(())
            }
            _ => Err(format!(
                "Cannot mark reproduced from state {:?}",
                self.state
            )),
        }
    }

    /// Promotes candidate to `Verified` once reproduction is independently verified.
    /// Fails closed if the reproduction artifact was produced via simulation without real target execution.
    pub fn mark_verified(&mut self) -> Result<(), String> {
        let artifact = self
            .reproduction_artifact
            .as_ref()
            .ok_or_else(|| "Cannot mark verified without reproduction artifact".to_string())?;

        if !artifact.real_execution {
            return Err("Cannot mark candidate verified: reproduction artifact was produced via simulation without target runtime execution".to_string());
        }

        match self.state {
            CandidateState::Reproduced | CandidateState::Reproducing => {
                self.state = CandidateState::Verified;
                self.touch();
                Ok(())
            }
            _ => Err(format!("Cannot mark verified from state {:?}", self.state)),
        }
    }

    /// Marks candidate as simulation only, preventing verification or promotion to confirmed finding.
    pub fn mark_simulation_only(&mut self, reason: &str) {
        self.state = CandidateState::SimulationOnly(reason.to_string());
        self.touch();
    }

    /// Dismisses candidate with a specific reason (e.g. already known advisory).
    pub fn dismiss(&mut self, reason: DismissalReason) {
        self.state = CandidateState::Dismissed(reason);
        self.touch();
    }

    /// Marks candidate as inconclusive.
    pub fn mark_inconclusive(&mut self, reason: &str) {
        self.state = CandidateState::Inconclusive(reason.to_string());
        self.touch();
    }

    /// Synthesizes a schema-compliant `FindingV1` from a verified candidate and reproduction artifact.
    pub fn synthesize_finding(
        &self,
        run_id: &str,
        snapshot_sha256: &str,
    ) -> Result<FindingV1, String> {
        if !self.can_promote_to_finding() {
            return Err(format!(
                "Candidate cannot be promoted to finding: current state is {:?}",
                self.state
            ));
        }

        let artifact = self
            .reproduction_artifact
            .as_ref()
            .ok_or_else(|| "Verified candidate is missing reproduction artifact".to_string())?;

        let rule_id = format!(
            "novel.hunter.{}",
            self.weakness.to_lowercase().replace('-', "_")
        );
        let evidence_item = EvidenceItemV1 {
            kind: EvidenceItemKind::TestReproduction,
            artifact_sha256: artifact.artifact_sha256.clone(),
            description: format!(
                "Deterministic fuzzed invariant violation reproduced: {}",
                artifact.error_message
            ),
            reference: Some(self.target_path.clone()),
            limitations: Vec::new(),
        };

        let proof = ProofV1 {
            method: ProofMethod::ReproductionArtifact,
            artifact_sha256: artifact.artifact_sha256.clone(),
            reproduced_on_snapshot: snapshot_sha256.to_string(),
            limitations: Vec::new(),
        };

        let finding = FindingV1 {
            schema_version: "1.0".to_string(),
            run_id: run_id.to_string(),
            finding_id: format!("novel-finding-{}", self.candidate_id),
            fingerprint: Some(artifact.artifact_sha256.clone()),
            kind: FindingKind::ResearchCandidate,
            status: FindingStatus::Verified,
            title: self.title.clone(),
            summary: Some(self.hypothesis.clone()),
            severity: NormalizedSeverity::Critical,
            evidence_certainty: EvidenceCertaintyV1::Confirmed,
            rule_id: Some(rule_id),
            weakness_ids: vec![self.weakness.clone()],
            advisory_ids: Vec::new(),
            engine: EngineDescriptor {
                id: "novel-hunter-fuzzer".to_string(),
                version: "0.1.0".to_string(),
                rule_pack_sha256: Some(snapshot_sha256.to_string()),
            },
            target: TargetDescriptor {
                target_id: self.target_path.clone(),
                kind: NormalizedTargetKind::File,
                path: Some(self.target_path.clone()),
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
            coverage_receipt_ids: vec![format!("receipt-{}", self.candidate_id)],
            uncertainty_reasons: Vec::new(),
            remediation_plan_id: None,
            created_at: Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            updated_at: None,
            extensions: serde_json::Map::new(),
        };

        finding.validate()?;
        Ok(finding)
    }

    fn touch(&mut self) {
        self.updated_at = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    }
}

/// Status of an individual coverage unit in the Cloudflare-style audit coverage ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CoverageUnitStatus {
    Planned,
    InProgress,
    Completed,
    Blocked,
    Exempt,
}

impl CoverageUnitStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            CoverageUnitStatus::Planned => "Planned",
            CoverageUnitStatus::InProgress => "InProgress",
            CoverageUnitStatus::Completed => "Completed",
            CoverageUnitStatus::Blocked => "Blocked",
            CoverageUnitStatus::Exempt => "Exempt",
        }
    }
}

/// A structured, auditable unit of attack surface coverage mapped across boundaries and attack classes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageUnit {
    pub coverage_id: String,
    pub surface: String,
    pub boundary: String,
    pub subsystem: String,
    pub attack_class: String,
    #[serde(default)]
    pub starting_paths: Vec<String>,
    #[serde(default)]
    pub reviewed_paths: Vec<String>,
    #[serde(default)]
    pub local_checks: Vec<String>,
    pub status: CoverageUnitStatus,
    #[serde(default)]
    pub result_fingerprints: Vec<String>,
    #[serde(default)]
    pub evidence_digest: Option<String>,
}

impl CoverageUnit {
    pub fn new(
        surface: impl Into<String>,
        boundary: impl Into<String>,
        subsystem: impl Into<String>,
        attack_class: impl Into<String>,
    ) -> Self {
        let s = surface.into();
        let b = boundary.into();
        let sub = subsystem.into();
        let ac = attack_class.into();
        let coverage_id = format!("{}:{}:{}:{}", s, b, sub, ac);

        Self {
            coverage_id,
            surface: s,
            boundary: b,
            subsystem: sub,
            attack_class: ac,
            starting_paths: Vec::new(),
            reviewed_paths: Vec::new(),
            local_checks: Vec::new(),
            status: CoverageUnitStatus::Planned,
            result_fingerprints: Vec::new(),
            evidence_digest: None,
        }
    }
}

/// A tamper-evident ledger tracking verifiable vulnerability audit coverage across the codebase.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageLedger {
    pub ledger_version: String,
    pub target_root: String,
    pub units: Vec<CoverageUnit>,
}

impl CoverageLedger {
    pub fn new(target_root: impl Into<String>) -> Self {
        Self {
            ledger_version: "1.0.0".to_string(),
            target_root: target_root.into(),
            units: Vec::new(),
        }
    }

    pub fn add_unit(&mut self, unit: CoverageUnit) -> Result<(), String> {
        if self.units.len() >= 10_000 {
            return Err("Coverage ledger exceeds maximum unit limit of 10,000".to_string());
        }
        if self.units.iter().any(|u| u.coverage_id == unit.coverage_id) {
            return Err(format!("Duplicate coverage unit ID '{}'", unit.coverage_id));
        }
        self.units.push(unit);
        Ok(())
    }

    /// Validates ledger integrity: bounds, canonical coverage_id format, non-empty fields,
    /// and ensures Completed units have reviewed paths or local checks.
    pub fn validate(&self) -> Result<(), String> {
        if self.units.is_empty() {
            return Err(
                "Coverage ledger is empty: at least one coverage unit is required".to_string(),
            );
        }
        if self.units.len() > 10_000 {
            return Err("Coverage ledger exceeds maximum allowed units (10,000)".to_string());
        }

        let mut seen_ids = std::collections::HashSet::new();
        for (idx, unit) in self.units.iter().enumerate() {
            if unit.coverage_id.is_empty() {
                return Err(format!("Unit at index {} has empty coverage_id", idx));
            }
            if !seen_ids.insert(&unit.coverage_id) {
                return Err(format!("Duplicate coverage_id '{}'", unit.coverage_id));
            }
            let colon_count = unit.coverage_id.chars().filter(|&c| c == ':').count();
            if colon_count < 3 {
                return Err(format!(
                    "Invalid coverage_id format '{}', expected 'surface:boundary:subsystem:attack_class'",
                    unit.coverage_id
                ));
            }

            if unit.status == CoverageUnitStatus::Completed
                && unit.reviewed_paths.is_empty()
                && unit.local_checks.is_empty()
            {
                return Err(format!(
                    "Completed coverage unit '{}' must declare reviewed_paths or local_checks",
                    unit.coverage_id
                ));
            }
        }

        Ok(())
    }

    /// Computes deterministic SHA-256 digest of canonical serialized coverage ledger.
    pub fn compute_digest(&self) -> String {
        let serialized = serde_json::to_string(&self.units).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(serialized.as_bytes());
        crate::to_hex(hasher.finalize())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simulated_artifact_fails_closed_on_verification() {
        let mut candidate = ResearchCandidate::new(
            "cand-sim-01",
            "Simulated Candidate",
            "src/target.rs",
            "CWE-285",
            "Synthetic hypothesis",
        );

        let simulated_artifact = ReproductionArtifact::new_simulated(
            b"test_payload".to_vec(),
            b"payload".to_vec(),
            "Simulated invariant failure",
        );
        assert!(!simulated_artifact.real_execution);

        assert!(candidate.mark_reproduced(simulated_artifact).is_ok());
        assert_eq!(candidate.state, CandidateState::Reproduced);
        assert!(!candidate.can_promote_to_finding());

        let snapshot_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

        // Attempting to verify a simulated artifact must fail closed
        let verify_result = candidate.mark_verified();
        assert!(verify_result.is_err());
        assert!(!candidate.can_promote_to_finding());
        assert!(
            candidate
                .synthesize_finding("run-001", snapshot_sha256)
                .is_err()
        );
    }

    #[test]
    fn test_real_artifact_can_be_verified_and_promoted() {
        let mut candidate = ResearchCandidate::new(
            "cand-real-01",
            "Real Candidate",
            "src/target.rs",
            "CWE-285",
            "Real hypothesis",
        );

        let real_artifact = ReproductionArtifact::new(
            b"real_payload".to_vec(),
            b"payload".to_vec(),
            "Real execution violation",
        );
        assert!(real_artifact.real_execution);

        assert!(candidate.mark_reproduced(real_artifact).is_ok());
        assert!(candidate.mark_verified().is_ok());
        assert_eq!(candidate.state, CandidateState::Verified);
        assert!(candidate.can_promote_to_finding());

        let snapshot_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert!(
            candidate
                .synthesize_finding("run-001", snapshot_sha256)
                .is_ok()
        );
    }
}
