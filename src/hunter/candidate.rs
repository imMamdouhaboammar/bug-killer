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
}

impl ReproductionArtifact {
    pub fn new(raw_payload: Vec<u8>, minimized_trigger: Vec<u8>, error_message: &str) -> Self {
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
    /// and verified (`CandidateState::Verified`).
    pub fn can_promote_to_finding(&self) -> bool {
        matches!(self.state, CandidateState::Verified)
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
    pub fn mark_verified(&mut self) -> Result<(), String> {
        if self.reproduction_artifact.is_none() {
            return Err("Cannot mark verified without reproduction artifact".to_string());
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
