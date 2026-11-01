//! Standardized finding builder for security rule and AST scanners.
//!
//! Consolidates repeated [`Finding`] instantiation, ID formatting, CveId wrapping,
//! evidence reference generation, and cryptographic deduplication fingerprints
//! without erasing detector-specific policies (reachability, certainty, detector metadata).

use crate::types::{
    Affectedness, Confidence, CveId, EvidenceCertainty, EvidenceRef, Finding, Reachability,
    Severity, TargetKind,
};
use std::collections::HashSet;
use std::path::Path;

/// Specification describing the common textual and location parameters for a rule finding.
#[derive(Debug, Clone)]
pub struct ScannerFindingSpec<'a> {
    pub rule_id: &'a str,
    pub title: &'a str,
    pub severity: Severity,
    pub category: &'a str,
    pub path: &'a Path,
    pub target_kind: &'a TargetKind,
    pub line_no: usize,
    pub snippet: &'a str,
    pub safe_threshold: &'a str,
    pub description: &'a str,
    pub remediation: &'a str,
}

/// Typed builder that transforms a [`ScannerFindingSpec`] into a validated [`Finding`].
#[derive(Debug, Clone)]
pub struct ScannerFindingBuilder<'a> {
    spec: ScannerFindingSpec<'a>,
    detector_id: &'a str,
    detector_version: &'a str,
    affectedness: Affectedness,
    reachability: Reachability,
    confidence: Confidence,
    evidence_certainty: EvidenceCertainty,
    advisories: Vec<String>,
}

impl<'a> ScannerFindingBuilder<'a> {
    /// Creates a new builder for the specified finding spec with default detector policies:
    /// - `affectedness`: `Affectedness::ConfirmedAffected`
    /// - `reachability`: `Reachability::PotentiallyReachable`
    /// - `confidence`: `Confidence::High`
    /// - `evidence_certainty`: `EvidenceCertainty::StronglySupported`
    /// - `detector_version`: `"1.0.0"`
    pub fn new(spec: ScannerFindingSpec<'a>) -> Self {
        Self {
            spec,
            detector_id: "generic-scanner",
            detector_version: "1.0.0",
            affectedness: Affectedness::ConfirmedAffected,
            reachability: Reachability::PotentiallyReachable,
            confidence: Confidence::High,
            evidence_certainty: EvidenceCertainty::StronglySupported,
            advisories: Vec::new(),
        }
    }

    /// Pre-configures the builder for the `native-desktop` scanner policy:
    /// - `detector_id`: `"native-desktop"`
    /// - `reachability`: `Reachability::PotentiallyReachable`
    pub fn native_desktop(spec: ScannerFindingSpec<'a>) -> Self {
        Self::new(spec).detector("native-desktop", "1.0.0")
    }

    /// Pre-configures the builder for the `auth-security` scanner policy:
    /// - `detector_id`: `"auth-security"`
    /// - `reachability`: `Reachability::ConfirmedReachable`
    pub fn auth_security(spec: ScannerFindingSpec<'a>) -> Self {
        Self::new(spec)
            .detector("auth-security", "1.0.0")
            .reachability(Reachability::ConfirmedReachable)
    }

    /// Returns a reference to the underlying [`ScannerFindingSpec`].
    pub fn spec(&self) -> &ScannerFindingSpec<'a> {
        &self.spec
    }

    pub fn detector(mut self, id: &'a str, version: &'a str) -> Self {
        self.detector_id = id;
        self.detector_version = version;
        self
    }

    pub fn reachability(mut self, reachability: Reachability) -> Self {
        self.reachability = reachability;
        self
    }

    pub fn confidence(mut self, confidence: Confidence) -> Self {
        self.confidence = confidence;
        self
    }

    pub fn affectedness(mut self, affectedness: Affectedness) -> Self {
        self.affectedness = affectedness;
        self
    }

    pub fn evidence_certainty(mut self, certainty: EvidenceCertainty) -> Self {
        self.evidence_certainty = certainty;
        self
    }

    pub fn advisory<S: Into<String>>(mut self, advisory: S) -> Self {
        self.advisories.push(advisory.into());
        self
    }

    pub fn advisories<I, S>(mut self, advisories: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.advisories
            .extend(advisories.into_iter().map(Into::into));
        self
    }

    /// Builds the concrete [`Finding`] with normalized IDs, evidence references, and fingerprints.
    pub fn build(self) -> Finding {
        let file_tag = self
            .spec
            .path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("source");
        let short_id = self.spec.rule_id.trim_start_matches("BK-AI-");
        let finding_id = format!("{}-{}-L{}", short_id, file_tag, self.spec.line_no);

        let mut finding = Finding::new(
            finding_id,
            CveId::Custom {
                id: self.spec.rule_id.to_string(),
                title: self.spec.title.to_string(),
            },
            self.spec.severity,
            self.spec.target_kind.clone(),
            Some(self.spec.path.to_path_buf()),
            Some(self.spec.line_no),
            self.spec.snippet,
            self.spec.safe_threshold,
            self.spec.description,
            self.spec.remediation,
        );
        finding.detector_id = self.detector_id.to_string();
        finding.detector_version = self.detector_version.to_string();
        finding.category = self.spec.category.to_string();
        finding.affectedness = self.affectedness;
        finding.reachability = self.reachability;
        finding.confidence = self.confidence;
        finding.evidence_certainty = self.evidence_certainty;
        finding.advisory_ids = self.advisories;
        finding.evidence_refs.push(EvidenceRef {
            location: format!("{}:{}", self.spec.path.display(), self.spec.line_no),
            line_number: Some(self.spec.line_no),
            snippet: Some(self.spec.snippet.trim().to_string()),
            sha256: None,
        });
        finding.compute_dedupe_fingerprint();
        finding
    }

    /// Pushes the built finding into `findings` if `(rule_id, line_no)` has not already been seen.
    pub fn push_deduped(
        self,
        findings: &mut Vec<Finding>,
        seen: &mut HashSet<(String, usize)>,
    ) -> bool {
        if !seen.insert((self.spec.rule_id.to_string(), self.spec.line_no)) {
            return false;
        }
        findings.push(self.build());
        true
    }
}
