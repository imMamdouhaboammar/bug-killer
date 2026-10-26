//! Draft representation and builder for private disclosure packets.
//!
//! Conforms strictly to `disclosure-packet.schema.json`, Chapter 12, and Card M6.1.
//! Implements GitHub Private Vulnerability Reporting (PVR) markdown export,
//! ISO/IEC 29147 coordinated disclosure standards, defensive perimeter safety checks,
//! and strict offline guarantees (zero network or socket operations).

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

use super::state::DisclosureLifecycleState;
use crate::engine::protocol::{FindingV1, NormalizedSeverity};
use crate::hunter::candidate::ResearchCandidate;

/// Severity qualification for disclosure packets conforming to standard CVSS levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DisclosureSeverity {
    Critical,
    High,
    Medium,
    Low,
}

impl DisclosureSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            DisclosureSeverity::Critical => "Critical",
            DisclosureSeverity::High => "High",
            DisclosureSeverity::Medium => "Medium",
            DisclosureSeverity::Low => "Low",
        }
    }
}

impl fmt::Display for DisclosureSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl From<NormalizedSeverity> for DisclosureSeverity {
    fn from(sev: NormalizedSeverity) -> Self {
        match sev {
            NormalizedSeverity::Critical => DisclosureSeverity::Critical,
            NormalizedSeverity::High => DisclosureSeverity::High,
            NormalizedSeverity::Medium => DisclosureSeverity::Medium,
            NormalizedSeverity::Low | NormalizedSeverity::Info | NormalizedSeverity::Unknown => {
                DisclosureSeverity::Low
            }
        }
    }
}

/// Affected component, version range, and cryptographic source snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AffectedTarget {
    pub package: String,
    pub commit_range: String,
    pub repository: String,
    pub source_snapshot_sha256: String,
}

/// Structured security impact assessment covering CVSS metrics and operational assumptions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityImpact {
    pub prerequisites: String,
    pub attack_vector: String,
    pub privileges_required: String,
    pub user_interaction: String,
    pub scope: String,
    pub confidential_impact: String,
    pub integrity_impact: String,
    pub availability_impact: String,
}

impl Default for SecurityImpact {
    fn default() -> Self {
        Self {
            prerequisites: "Standard environment configuration with default execution privileges."
                .to_string(),
            attack_vector: "Local".to_string(),
            privileges_required: "None".to_string(),
            user_interaction: "Required".to_string(),
            scope: "Unchanged".to_string(),
            confidential_impact: "Low".to_string(),
            integrity_impact: "Low".to_string(),
            availability_impact: "Low".to_string(),
        }
    }
}

/// Safe offline reproduction steps, sanitized inputs, and unit/property test harness.
///
/// Defensive perimeter guarantee: MUST NOT contain weaponized shellcode, live credentials,
/// or binary exploit payloads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SafeReproduction {
    pub test_type: String,
    pub harness_code: String,
    pub sanitized_input: String,
    pub expected_behavior: String,
    pub observed_behavior: String,
}

/// Root cause analysis containing standardized CWE classification and verifiable evidence hashes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootCause {
    pub summary: String,
    pub cwe_id: String,
    pub trace_evidence_hashes: Vec<String>,
}

/// Proposed remediation including unified diff patch, compatibility notes, and target versions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuggestedMitigation {
    pub diff: String,
    pub compatibility_notes: String,
    pub fixed_versions: Vec<String>,
}

/// Upstream contact channel qualified from SECURITY.md or maintainer policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContactChannel {
    pub channel_type: String,
    pub contact_target: String,
    #[serde(default)]
    pub security_policy_url: Option<String>,
}

/// Security researcher credit and coordinated embargo preferences.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReporterInfo {
    pub credit_name: String,
    pub contact_email: String,
    pub embargo_requested_days: u32,
}

impl Default for ReporterInfo {
    fn default() -> Self {
        Self {
            credit_name: "Bug Killer Security Research".to_string(),
            contact_email: "security-research@example.com".to_string(),
            embargo_requested_days: 90,
        }
    }
}

/// Authoritative private vulnerability disclosure packet conforming to `disclosure-packet.schema.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisclosurePacket {
    pub schema_version: String,
    pub packet_id: String,
    pub draft_id: String,
    pub finding_id: String,
    pub lifecycle_state: DisclosureLifecycleState,
    pub title: String,
    pub vulnerability_type: String,
    pub severity: DisclosureSeverity,
    pub affected_target: AffectedTarget,
    pub security_impact: SecurityImpact,
    pub safe_reproduction: SafeReproduction,
    pub root_cause: RootCause,
    pub suggested_mitigation: SuggestedMitigation,
    pub contact_channel: ContactChannel,
    pub reporter: ReporterInfo,
    pub created_at: String,
    pub updated_at: String,
}

impl DisclosurePacket {
    /// Formats this disclosure packet into clean GitHub Private Vulnerability Reporting (PVR) markdown.
    ///
    /// Formatted sections strictly adhere to Chapter 12 and ISO/IEC 29147:
    /// - Summary
    /// - Severity & Impact
    /// - Affected Components
    /// - Safe Reproduction Steps (Offline Unit / Property Test)
    /// - Root Cause Analysis
    /// - Proposed Fix / Mitigation
    /// - Coordination & Embargo Timeline
    pub fn to_github_pvr_markdown(&self) -> String {
        let hashes_md = if self.root_cause.trace_evidence_hashes.is_empty() {
            "  *None recorded*".to_string()
        } else {
            self.root_cause
                .trace_evidence_hashes
                .iter()
                .map(|h| format!("- `{}`", h))
                .collect::<Vec<_>>()
                .join("\n")
        };

        let fixed_versions_str = if self.suggested_mitigation.fixed_versions.is_empty() {
            "Pending maintainer coordination".to_string()
        } else {
            self.suggested_mitigation.fixed_versions.join(", ")
        };

        let policy_url_str = self
            .contact_channel
            .security_policy_url
            .as_deref()
            .unwrap_or("None provided");

        format!(
            "# [PVR Draft] {}\n\n\
            ## Summary\n\
            - **Finding ID**: `{}`\n\
            - **Draft ID**: `{}`\n\
            - **Packet ID**: `{}`\n\
            - **Lifecycle State**: `{}`\n\
            - **Vulnerability Type**: {}\n\n\
            ### Description\n\
            {}\n\n\
            ## Severity & Impact\n\
            - **Severity**: {}\n\
            - **Attack Vector**: {}\n\
            - **Privileges Required**: {}\n\
            - **User Interaction**: {}\n\
            - **Scope**: {}\n\
            - **Impact Metrics**:\n\
              - **Confidentiality Impact**: {}\n\
              - **Integrity Impact**: {}\n\
              - **Availability Impact**: {}\n\n\
            ### Prerequisites & Operational Assumptions\n\
            {}\n\n\
            ## Affected Components\n\
            - **Package / Component**: `{}`\n\
            - **Repository**: {}\n\
            - **Vulnerable Commit Range**: `{}`\n\
            - **Source Snapshot SHA256**: `{}`\n\n\
            ## Safe Reproduction Steps (Offline Unit / Property Test)\n\
            - **Test Harness Type**: {}\n\
            - **Expected Safe Behavior**: {}\n\
            - **Observed Behavior / Failure**: {}\n\n\
            ### Sanitized Trigger Input\n\
            ```\n\
            {}\n\
            ```\n\n\
            ### Harmless Offline Test Harness\n\
            ```rust\n\
            {}\n\
            ```\n\n\
            > **Safety Guarantee**: This reproduction harness executes entirely offline within local synthetic boundaries. It contains zero weaponized exploits or shellcode, conforming to Bug Killer safety invariants.\n\n\
            ## Root Cause Analysis\n\
            - **CWE**: `{}`\n\
            - **Technical Explanation**:\n\
            {}\n\n\
            ### Verifiable Trace Evidence Hashes\n\
            {}\n\n\
            ## Proposed Fix / Mitigation\n\
            - **Compatibility Notes**: {}\n\
            - **Target Fixed Versions**: {}\n\n\
            ### Proposed Mitigation Patch\n\
            ```diff\n\
            {}\n\
            ```\n\n\
            ## Coordination & Embargo Timeline\n\
            - **Reporter Credit**: {}\n\
            - **Contact Email**: {}\n\
            - **Requested Embargo Window**: {} days\n\
            - **Coordinated Channel**: {} (`{}`)\n\
            - **Verified Security Policy URL**: {}\n\
            - **Standards Conformance**: Coordinated vulnerability disclosure adhering to ISO/IEC 29147 and GitHub Private Vulnerability Reporting (PVR).\n",
            self.title,
            self.finding_id,
            self.draft_id,
            self.packet_id,
            self.lifecycle_state.as_str(),
            self.vulnerability_type,
            self.root_cause.summary,
            self.severity,
            self.security_impact.attack_vector,
            self.security_impact.privileges_required,
            self.security_impact.user_interaction,
            self.security_impact.scope,
            self.security_impact.confidential_impact,
            self.security_impact.integrity_impact,
            self.security_impact.availability_impact,
            self.security_impact.prerequisites,
            self.affected_target.package,
            self.affected_target.repository,
            self.affected_target.commit_range,
            self.affected_target.source_snapshot_sha256,
            self.safe_reproduction.test_type,
            self.safe_reproduction.expected_behavior,
            self.safe_reproduction.observed_behavior,
            self.safe_reproduction.sanitized_input,
            self.safe_reproduction.harness_code,
            self.root_cause.cwe_id,
            self.root_cause.summary,
            hashes_md,
            self.suggested_mitigation.compatibility_notes,
            fixed_versions_str,
            self.suggested_mitigation.diff,
            self.reporter.credit_name,
            self.reporter.contact_email,
            self.reporter.embargo_requested_days,
            self.contact_channel.channel_type,
            self.contact_channel.contact_target,
            policy_url_str
        )
    }

    /// Serializes this packet to formatted JSON string.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Serializes this packet to deterministic canonical JSON representation.
    pub fn to_canonical_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Deserializes a disclosure packet from JSON string.
    pub fn from_json(json: &str) -> Result<DisclosurePacket, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Validates internal invariants against `disclosure-packet.schema.json`
    /// and the defensive perimeter requirements.
    pub fn validate(&self) -> Result<(), DisclosureValidationError> {
        // Defensive perimeter safety audit: zero weaponized shellcode, live payloads, or leaked credentials
        self.audit_defensive_perimeter()?;

        if self.schema_version != "1.0" {
            return Err(DisclosureValidationError::InvalidSchemaVersion(
                self.schema_version.clone(),
            ));
        }
        if self.packet_id.trim().is_empty() {
            return Err(DisclosureValidationError::MissingRequiredField("packet_id"));
        }
        if self.draft_id.trim().is_empty() {
            return Err(DisclosureValidationError::MissingRequiredField("draft_id"));
        }
        if self.finding_id.trim().is_empty() {
            return Err(DisclosureValidationError::MissingRequiredField(
                "finding_id",
            ));
        }
        if self.title.trim().is_empty() {
            return Err(DisclosureValidationError::MissingRequiredField("title"));
        }
        if self.title.len() > 300 {
            return Err(DisclosureValidationError::TitleTooLong(self.title.len()));
        }
        if self.vulnerability_type.trim().is_empty() {
            return Err(DisclosureValidationError::MissingRequiredField(
                "vulnerability_type",
            ));
        }
        if self.vulnerability_type.len() > 100 {
            return Err(DisclosureValidationError::VulnerabilityTypeTooLong(
                self.vulnerability_type.len(),
            ));
        }

        // Validate hash format (64-character lowercase hexadecimal)
        if !is_valid_sha256_hex(&self.affected_target.source_snapshot_sha256) {
            return Err(DisclosureValidationError::InvalidSnapshotHash(
                self.affected_target.source_snapshot_sha256.clone(),
            ));
        }

        for hash in &self.root_cause.trace_evidence_hashes {
            if !is_valid_sha256_hex(hash) {
                return Err(DisclosureValidationError::InvalidEvidenceHash(hash.clone()));
            }
        }

        // Validate CWE identifier format (CWE-[0-9]+)
        if !is_valid_cwe_id(&self.root_cause.cwe_id) {
            return Err(DisclosureValidationError::InvalidCweId(
                self.root_cause.cwe_id.clone(),
            ));
        }

        Ok(())
    }

    /// Defensive perimeter audit scanning reproduction harnesses and sanitized inputs
    /// for weaponized exploit signatures or accidental credential exposure.
    fn audit_defensive_perimeter(&self) -> Result<(), DisclosureValidationError> {
        let inspect_targets = [
            ("sanitized_input", &self.safe_reproduction.sanitized_input),
            ("harness_code", &self.safe_reproduction.harness_code),
            ("mitigation_diff", &self.suggested_mitigation.diff),
        ];

        for (field, content) in inspect_targets {
            // Check for NOP sled signatures or raw machine shellcode sequences
            if content.contains("\\x90\\x90\\x90")
                || content.contains("0x90, 0x90, 0x90")
                || content.contains("\\x31\\xc0")
            {
                return Err(DisclosureValidationError::WeaponizedPayloadDetected(
                    format!("NOP sled pattern or shellcode sequence found in {field}"),
                ));
            }

            // Check for interactive reverse shell invocations
            if content.contains("/bin/sh -i")
                || content.contains("/bin/bash -i")
                || content.contains("bash -i >& /dev/tcp")
                || content.contains("nc -e /bin/sh")
                || content.contains("execve(\"/bin/sh\"")
            {
                return Err(DisclosureValidationError::WeaponizedPayloadDetected(
                    format!("Interactive shell or weaponized command payload detected in {field}"),
                ));
            }

            // Check for leaked API tokens or private keys
            if content.contains("ghp_")
                || content.contains("gho_")
                || content.contains("-----BEGIN PRIVATE KEY-----")
                || content.contains("-----BEGIN RSA PRIVATE KEY-----")
            {
                return Err(DisclosureValidationError::SecretLeakDetected(format!(
                    "Suspected secret key or authorization token detected in {field}"
                )));
            }
        }

        Ok(())
    }
}

/// Validates whether a string is a 64-character lowercase hexadecimal hash.
fn is_valid_sha256_hex(s: &str) -> bool {
    s.len() == 64
        && s.chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

/// Validates whether a string matches CWE identifier format (`CWE-[0-9]+`).
fn is_valid_cwe_id(s: &str) -> bool {
    if !s.starts_with("CWE-") {
        return false;
    }
    let digits = &s[4..];
    !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit())
}

/// Errors raised during disclosure packet validation.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum DisclosureValidationError {
    #[error("Invalid schema_version: expected '1.0', got '{0}'")]
    InvalidSchemaVersion(String),

    #[error("Missing or empty required field: {0}")]
    MissingRequiredField(&'static str),

    #[error("Title exceeds 300 characters (length: {0})")]
    TitleTooLong(usize),

    #[error("Vulnerability type exceeds 100 characters (length: {0})")]
    VulnerabilityTypeTooLong(usize),

    #[error("Invalid source snapshot SHA-256 hash: expected 64 hex characters, got '{0}'")]
    InvalidSnapshotHash(String),

    #[error("Invalid trace evidence hash: expected 64 hex characters, got '{0}'")]
    InvalidEvidenceHash(String),

    #[error("Invalid CWE identifier: expected 'CWE-<digits>', got '{0}'")]
    InvalidCweId(String),

    #[error(
        "Defensive perimeter violation: weaponized shellcode or exploit payload detected in reproduction data: {0}"
    )]
    WeaponizedPayloadDetected(String),

    #[error("Defensive perimeter violation: sensitive API key or secret token detected: {0}")]
    SecretLeakDetected(String),
}

/// Fluent builder for constructing and validating `DisclosurePacket` instances strictly offline.
#[derive(Debug, Clone, Default)]
pub struct DisclosureDraftBuilder {
    packet_id: Option<String>,
    draft_id: Option<String>,
    finding_id: Option<String>,
    lifecycle_state: Option<DisclosureLifecycleState>,
    title: Option<String>,
    vulnerability_type: Option<String>,
    severity: Option<DisclosureSeverity>,
    affected_target: Option<AffectedTarget>,
    security_impact: Option<SecurityImpact>,
    safe_reproduction: Option<SafeReproduction>,
    root_cause: Option<RootCause>,
    suggested_mitigation: Option<SuggestedMitigation>,
    contact_channel: Option<ContactChannel>,
    reporter: Option<ReporterInfo>,
    created_at: Option<String>,
    updated_at: Option<String>,
}

impl DisclosureDraftBuilder {
    /// Creates a new empty builder instance.
    pub fn new() -> Self {
        Self::default()
    }

    /// Pre-populates disclosure draft fields from an engine `FindingV1`.
    pub fn from_finding(finding: &FindingV1) -> Self {
        let cwe_id = finding
            .weakness_ids
            .first()
            .cloned()
            .unwrap_or_else(|| "CWE-20".to_string());

        let kind_str = match finding.kind {
            crate::engine::protocol::FindingKind::KnownAdvisory => "Known Advisory",
            crate::engine::protocol::FindingKind::Catalog => "Catalog Vulnerability",
            crate::engine::protocol::FindingKind::ResearchCandidate => "Research Candidate",
        };

        let vuln_type = if !finding.weakness_ids.is_empty() {
            format!("Security Weakness ({})", cwe_id)
        } else {
            kind_str.to_string()
        };

        let severity: DisclosureSeverity = finding.severity.into();

        let trace_hashes: Vec<String> = finding
            .evidence
            .iter()
            .filter_map(|ev| {
                if is_valid_sha256_hex(&ev.artifact_sha256) {
                    Some(ev.artifact_sha256.clone())
                } else {
                    None
                }
            })
            .collect();

        let package = finding
            .target
            .package_purl
            .clone()
            .unwrap_or_else(|| finding.target.target_id.clone());

        let repository = finding.target.path.clone().unwrap_or_default();

        let safe_repro = SafeReproduction {
            test_type: "offline_unit_test".to_string(),
            harness_code: format!(
                "// Offline reproduction test for finding {}\nfn test_reproduce_{}() {{\n    // Assert safe handling without panic\n}}",
                finding.finding_id,
                finding.finding_id.replace('-', "_")
            ),
            sanitized_input: "Sanitized synthetic trigger fixture".to_string(),
            expected_behavior:
                "Component rejects malformed input or handles it safely without crashing"
                    .to_string(),
            observed_behavior: finding
                .summary
                .clone()
                .unwrap_or_else(|| "Security invariant violation observed".to_string()),
        };

        Self::new()
            .finding_id(&finding.finding_id)
            .title(&finding.title)
            .vulnerability_type(vuln_type)
            .severity(severity)
            .affected_target(AffectedTarget {
                package,
                commit_range: "HEAD".to_string(),
                repository,
                source_snapshot_sha256: finding.source_snapshot_sha256.clone(),
            })
            .safe_reproduction(safe_repro)
            .root_cause(RootCause {
                summary: finding.summary.clone().unwrap_or_default(),
                cwe_id,
                trace_evidence_hashes: trace_hashes,
            })
    }

    /// Pre-populates disclosure draft fields from a Novel Hunter `ResearchCandidate`.
    pub fn from_candidate(candidate: &ResearchCandidate, source_snapshot_sha256: &str) -> Self {
        let mut trace_hashes = Vec::new();
        let (sanitized_input, harness_code, observed_behavior) = match &candidate
            .reproduction_artifact
        {
            Some(artifact) => {
                trace_hashes.push(artifact.artifact_sha256.clone());
                (
                    format!("Trigger artifact sha256: {}", artifact.artifact_sha256),
                    format!(
                        "// Offline minimized trigger harness\nfn test_reproduce_{}() {{\n    // Invariant check for {}\n}}",
                        candidate.candidate_id.replace('-', "_"),
                        candidate.weakness
                    ),
                    artifact.error_message.clone(),
                )
            }
            None => (
                "Synthetic harmless input".to_string(),
                "// Bounded offline reproduction test".to_string(),
                "Observed security assertion violation during research trial".to_string(),
            ),
        };

        Self::new()
            .finding_id(&candidate.candidate_id)
            .title(&candidate.title)
            .vulnerability_type(candidate.weakness.clone())
            .severity(DisclosureSeverity::High)
            .affected_target(AffectedTarget {
                package: candidate.target_path.clone(),
                commit_range: "HEAD".to_string(),
                repository: "local".to_string(),
                source_snapshot_sha256: source_snapshot_sha256.to_string(),
            })
            .safe_reproduction(SafeReproduction {
                test_type: "offline_differential_harness".to_string(),
                harness_code,
                sanitized_input,
                expected_behavior: "Software safely handles input or returns validation error"
                    .to_string(),
                observed_behavior,
            })
            .root_cause(RootCause {
                summary: candidate.hypothesis.clone(),
                cwe_id: if candidate.weakness.starts_with("CWE-") {
                    candidate.weakness.clone()
                } else {
                    "CWE-20".to_string()
                },
                trace_evidence_hashes: trace_hashes,
            })
    }

    pub fn packet_id(mut self, id: impl Into<String>) -> Self {
        self.packet_id = Some(id.into());
        self
    }

    pub fn draft_id(mut self, id: impl Into<String>) -> Self {
        self.draft_id = Some(id.into());
        self
    }

    pub fn finding_id(mut self, id: impl Into<String>) -> Self {
        self.finding_id = Some(id.into());
        self
    }

    pub fn lifecycle_state(mut self, state: DisclosureLifecycleState) -> Self {
        self.lifecycle_state = Some(state);
        self
    }

    pub fn title(mut self, title: impl Into<String>) -> Self {
        self.title = Some(title.into());
        self
    }

    pub fn vulnerability_type(mut self, vtype: impl Into<String>) -> Self {
        self.vulnerability_type = Some(vtype.into());
        self
    }

    pub fn severity(mut self, severity: DisclosureSeverity) -> Self {
        self.severity = Some(severity);
        self
    }

    pub fn affected_target(mut self, target: AffectedTarget) -> Self {
        self.affected_target = Some(target);
        self
    }

    pub fn target_components(
        mut self,
        package: impl Into<String>,
        commit_range: impl Into<String>,
        repository: impl Into<String>,
        source_snapshot_sha256: impl Into<String>,
    ) -> Self {
        self.affected_target = Some(AffectedTarget {
            package: package.into(),
            commit_range: commit_range.into(),
            repository: repository.into(),
            source_snapshot_sha256: source_snapshot_sha256.into(),
        });
        self
    }

    pub fn security_impact(mut self, impact: SecurityImpact) -> Self {
        self.security_impact = Some(impact);
        self
    }

    pub fn safe_reproduction(mut self, repro: SafeReproduction) -> Self {
        self.safe_reproduction = Some(repro);
        self
    }

    pub fn root_cause(mut self, cause: RootCause) -> Self {
        self.root_cause = Some(cause);
        self
    }

    pub fn suggested_mitigation(mut self, mitigation: SuggestedMitigation) -> Self {
        self.suggested_mitigation = Some(mitigation);
        self
    }

    pub fn contact_channel(mut self, channel: ContactChannel) -> Self {
        self.contact_channel = Some(channel);
        self
    }

    pub fn reporter(mut self, reporter: ReporterInfo) -> Self {
        self.reporter = Some(reporter);
        self
    }

    pub fn created_at(mut self, ts: impl Into<String>) -> Self {
        self.created_at = Some(ts.into());
        self
    }

    pub fn updated_at(mut self, ts: impl Into<String>) -> Self {
        self.updated_at = Some(ts.into());
        self
    }

    /// Builds and validates the `DisclosurePacket` with strict offline guarantees.
    ///
    /// Offline invariant: Takes zero network handles and performs zero outbound socket calls.
    pub fn build(self) -> Result<DisclosurePacket, DisclosureValidationError> {
        let finding_id = self
            .finding_id
            .ok_or(DisclosureValidationError::MissingRequiredField(
                "finding_id",
            ))?;

        let draft_id = self.draft_id.unwrap_or_else(|| "draft-001".to_string());

        let packet_id = self.packet_id.unwrap_or_else(|| {
            let mut hasher = Sha256::new();
            hasher.update(finding_id.as_bytes());
            hasher.update(draft_id.as_bytes());
            format!("packet-{}", &format!("{:x}", hasher.finalize())[..16])
        });

        let lifecycle_state = self
            .lifecycle_state
            .unwrap_or(DisclosureLifecycleState::PrivateDraft);

        let title = self
            .title
            .ok_or(DisclosureValidationError::MissingRequiredField("title"))?;

        let vulnerability_type =
            self.vulnerability_type
                .ok_or(DisclosureValidationError::MissingRequiredField(
                    "vulnerability_type",
                ))?;

        let severity = self.severity.unwrap_or(DisclosureSeverity::High);

        let affected_target = self.affected_target.unwrap_or_else(|| AffectedTarget {
            package: "workspace".to_string(),
            commit_range: "HEAD".to_string(),
            repository: "local".to_string(),
            source_snapshot_sha256:
                "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        });

        let security_impact = self.security_impact.unwrap_or_default();

        let safe_reproduction =
            self.safe_reproduction
                .ok_or(DisclosureValidationError::MissingRequiredField(
                    "safe_reproduction",
                ))?;

        let root_cause = self.root_cause.unwrap_or_else(|| RootCause {
            summary: format!("Vulnerability identified as {}", vulnerability_type),
            cwe_id: "CWE-20".to_string(),
            trace_evidence_hashes: Vec::new(),
        });

        let suggested_mitigation =
            self.suggested_mitigation
                .unwrap_or_else(|| SuggestedMitigation {
                    diff: String::new(),
                    compatibility_notes: "Mitigation pending maintainer triage".to_string(),
                    fixed_versions: Vec::new(),
                });

        let contact_channel = self.contact_channel.unwrap_or_else(|| ContactChannel {
            channel_type: "GitHubPrivateVulnerabilityReporting".to_string(),
            contact_target: affected_target.repository.clone(),
            security_policy_url: None,
        });

        let reporter = self.reporter.unwrap_or_default();

        let now_rfc3339 = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let created_at = self.created_at.unwrap_or_else(|| now_rfc3339.clone());
        let updated_at = self.updated_at.unwrap_or(now_rfc3339);

        let packet = DisclosurePacket {
            schema_version: "1.0".to_string(),
            packet_id,
            draft_id,
            finding_id,
            lifecycle_state,
            title,
            vulnerability_type,
            severity,
            affected_target,
            security_impact,
            safe_reproduction,
            root_cause,
            suggested_mitigation,
            contact_channel,
            reporter,
            created_at,
            updated_at,
        };

        packet.validate()?;
        Ok(packet)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_sha256() -> String {
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string()
    }

    fn sample_valid_packet() -> DisclosurePacket {
        DisclosureDraftBuilder::new()
            .finding_id("finding-novel-zip-slip-001")
            .title("Path Traversal in Archive Extraction leading to Arbitrary File Overwrite")
            .vulnerability_type("Arbitrary File Overwrite via Directory Traversal")
            .severity(DisclosureSeverity::High)
            .affected_target(AffectedTarget {
                package: "acme-archive-extractor".to_string(),
                commit_range: "v1.2.0..v1.4.2".to_string(),
                repository: "https://github.com/acme-org/acme-archive-extractor".to_string(),
                source_snapshot_sha256: dummy_sha256(),
            })
            .safe_reproduction(SafeReproduction {
                test_type: "offline_unit_test".to_string(),
                harness_code: "fn test_archive_traversal() { assert!(true); }".to_string(),
                sanitized_input: "test_archive_entry: ../../synthetic_target.txt".to_string(),
                expected_behavior: "Extraction rejects entry with path escaping destination root".to_string(),
                observed_behavior: "Entry was extracted outside destination directory".to_string(),
            })
            .root_cause(RootCause {
                summary: "Path canonicalization check was omitted in unpack loop".to_string(),
                cwe_id: "CWE-22".to_string(),
                trace_evidence_hashes: vec![dummy_sha256()],
            })
            .suggested_mitigation(SuggestedMitigation {
                diff: "--- a/src/extract.rs\n+++ b/src/extract.rs\n@@ -10,1 +10,3 @@\n+    canonical_check();".to_string(),
                compatibility_notes: "Non-breaking change for valid relative paths.".to_string(),
                fixed_versions: vec!["1.4.3".to_string()],
            })
            .contact_channel(ContactChannel {
                channel_type: "GitHubPrivateVulnerabilityReporting".to_string(),
                contact_target: "acme-org/acme-archive-extractor".to_string(),
                security_policy_url: Some("https://github.com/acme-org/acme-archive-extractor/security/policy".to_string()),
            })
            .reporter(ReporterInfo {
                credit_name: "Bug Killer Security Research".to_string(),
                contact_email: "researcher@example.com".to_string(),
                embargo_requested_days: 90,
            })
            .build()
            .expect("Valid packet should build cleanly")
    }

    #[test]
    fn test_valid_packet_build_and_validate() {
        let packet = sample_valid_packet();
        assert_eq!(packet.schema_version, "1.0");
        assert_eq!(
            packet.lifecycle_state,
            DisclosureLifecycleState::PrivateDraft
        );
        assert!(packet.packet_id.starts_with("packet-"));
        assert_eq!(packet.draft_id, "draft-001");
        assert!(packet.validate().is_ok());
    }

    #[test]
    fn test_github_pvr_markdown_format() {
        let packet = sample_valid_packet();
        let markdown = packet.to_github_pvr_markdown();

        // Verify required sections exist
        assert!(markdown.contains("# [PVR Draft] Path Traversal in Archive Extraction"));
        assert!(markdown.contains("## Summary"));
        assert!(markdown.contains("## Severity & Impact"));
        assert!(markdown.contains("## Affected Components"));
        assert!(markdown.contains("## Safe Reproduction Steps (Offline Unit / Property Test)"));
        assert!(markdown.contains("## Root Cause Analysis"));
        assert!(markdown.contains("## Proposed Fix / Mitigation"));
        assert!(markdown.contains("## Coordination & Embargo Timeline"));

        // Verify key fields are properly presented
        assert!(markdown.contains("CWE-22"));
        assert!(markdown.contains("acme-archive-extractor"));
        assert!(markdown.contains("90 days"));
        assert!(markdown.contains("ISO/IEC 29147"));
    }

    #[test]
    fn test_json_roundtrip() {
        let packet = sample_valid_packet();
        let json = packet.to_json().expect("Serialization should succeed");
        let deserialized =
            DisclosurePacket::from_json(&json).expect("Deserialization should succeed");
        assert_eq!(packet, deserialized);
    }

    #[test]
    fn test_defensive_perimeter_blocks_weaponized_payloads() {
        // Test NOP sled detection
        let builder = DisclosureDraftBuilder::new()
            .finding_id("finding-001")
            .title("Vulnerability with weaponized payload")
            .vulnerability_type("Memory Corruption")
            .severity(DisclosureSeverity::Critical)
            .affected_target(AffectedTarget {
                package: "demo-package".to_string(),
                commit_range: "v1.0.0".to_string(),
                repository: "https://example.com/demo".to_string(),
                source_snapshot_sha256: dummy_sha256(),
            })
            .safe_reproduction(SafeReproduction {
                test_type: "exploit".to_string(),
                harness_code: "let shellcode = \"\\x90\\x90\\x90\\x90\";".to_string(),
                sanitized_input: "test".to_string(),
                expected_behavior: "safe".to_string(),
                observed_behavior: "crash".to_string(),
            })
            .root_cause(RootCause {
                summary: "Memory corruption".to_string(),
                cwe_id: "CWE-119".to_string(),
                trace_evidence_hashes: vec![],
            });

        let result = builder.build();
        assert!(result.is_err());
        match result.unwrap_err() {
            DisclosureValidationError::WeaponizedPayloadDetected(msg) => {
                assert!(msg.contains("NOP sled pattern"));
            }
            other => panic!("Expected WeaponizedPayloadDetected, got {:?}", other),
        }
    }

    #[test]
    fn test_defensive_perimeter_blocks_leaked_credentials() {
        let builder = DisclosureDraftBuilder::new()
            .finding_id("finding-002")
            .title("Test with leaked secret token")
            .vulnerability_type("Auth")
            .severity(DisclosureSeverity::High)
            .affected_target(AffectedTarget {
                package: "demo".to_string(),
                commit_range: "v1".to_string(),
                repository: "repo".to_string(),
                source_snapshot_sha256: dummy_sha256(),
            })
            .safe_reproduction(SafeReproduction {
                test_type: "auth_test".to_string(),
                harness_code: "fn test() {}".to_string(),
                sanitized_input: format!(
                    "Authorization: Bearer ghp_{}",
                    "ABC1234567890123456789012345678901234567"
                ),
                expected_behavior: "reject".to_string(),
                observed_behavior: "accept".to_string(),
            })
            .root_cause(RootCause {
                summary: "Auth bypass".to_string(),
                cwe_id: "CWE-287".to_string(),
                trace_evidence_hashes: vec![],
            });

        let result = builder.build();
        assert!(result.is_err());
        match result.unwrap_err() {
            DisclosureValidationError::SecretLeakDetected(msg) => {
                assert!(msg.contains("Suspected secret key"));
            }
            other => panic!("Expected SecretLeakDetected, got {:?}", other),
        }
    }

    #[test]
    fn test_invalid_cwe_format_rejected() {
        let builder = DisclosureDraftBuilder::new()
            .finding_id("finding-003")
            .title("Test invalid CWE")
            .vulnerability_type("Input Validation")
            .severity(DisclosureSeverity::Medium)
            .affected_target(AffectedTarget {
                package: "demo".to_string(),
                commit_range: "v1".to_string(),
                repository: "repo".to_string(),
                source_snapshot_sha256: dummy_sha256(),
            })
            .safe_reproduction(SafeReproduction {
                test_type: "unit_test".to_string(),
                harness_code: "fn test() {}".to_string(),
                sanitized_input: "clean_synthetic_input".to_string(),
                expected_behavior: "ok".to_string(),
                observed_behavior: "fail".to_string(),
            })
            .root_cause(RootCause {
                summary: "Invalid input handling".to_string(),
                cwe_id: "NOT_A_CWE".to_string(),
                trace_evidence_hashes: vec![],
            });

        let result = builder.build();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            DisclosureValidationError::InvalidCweId(_)
        ));
    }
}
