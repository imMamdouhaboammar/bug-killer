use crate::types::ScanProfile;
use serde::{Deserialize, Serialize};

/// Versioned analysis request strictly compliant with `analysis-request.schema.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalysisRequest {
    pub schema_version: String,
    pub run_id: String,
    pub engine_id: String,
    pub snapshot_ref: String,
    pub snapshot_sha256: String,
    pub profile: ScanProfile,
    pub check_ids: Vec<String>,
    pub target_ids: Vec<String>,
    pub budgets: ResourceBudgets,
    pub permissions: EnginePermissions,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_pack_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub extensions: serde_json::Map<String, serde_json::Value>,
}

impl AnalysisRequest {
    pub fn new(
        run_id: impl Into<String>,
        engine_id: impl Into<String>,
        snapshot_ref: impl Into<String>,
        snapshot_sha256: impl Into<String>,
        profile: ScanProfile,
        check_ids: Vec<String>,
        target_ids: Vec<String>,
    ) -> Self {
        Self {
            schema_version: "1.0".to_string(),
            run_id: run_id.into(),
            engine_id: engine_id.into(),
            snapshot_ref: snapshot_ref.into(),
            snapshot_sha256: snapshot_sha256.into(),
            profile,
            check_ids,
            target_ids,
            budgets: ResourceBudgets::default(),
            permissions: EnginePermissions::default(),
            rule_pack_sha256: None,
            extensions: serde_json::Map::new(),
        }
    }

    /// Validates request invariants against `analysis-request.schema.json`.
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != "1.0" {
            return Err(format!(
                "Invalid schema_version: expected '1.0', got '{}'",
                self.schema_version
            ));
        }
        if self.run_id.trim().is_empty() {
            return Err("run_id must not be empty".to_string());
        }
        if self.engine_id.trim().is_empty() {
            return Err("engine_id must not be empty".to_string());
        }
        if self.snapshot_ref.trim().is_empty() {
            return Err("snapshot_ref must not be empty".to_string());
        }
        if self.snapshot_sha256.len() != 64
            || !self
                .snapshot_sha256
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        {
            return Err(format!(
                "snapshot_sha256 must be a 64-character lowercase hex string, got '{}'",
                self.snapshot_sha256
            ));
        }
        if self.check_ids.is_empty() {
            return Err("check_ids must contain at least 1 check ID".to_string());
        }
        if self.target_ids.is_empty() {
            return Err("target_ids must contain at least 1 target ID".to_string());
        }
        if self.budgets.timeout_seconds < 1 || self.budgets.timeout_seconds > 86400 {
            return Err(format!(
                "timeout_seconds must be between 1 and 86400, got {}",
                self.budgets.timeout_seconds
            ));
        }
        if self.budgets.memory_mb < 64 {
            return Err(format!(
                "memory_mb must be at least 64, got {}",
                self.budgets.memory_mb
            ));
        }
        if self.budgets.max_output_bytes < 1024 {
            return Err(format!(
                "max_output_bytes must be at least 1024, got {}",
                self.budgets.max_output_bytes
            ));
        }
        if let Some(ref rp) = self.rule_pack_sha256 {
            if rp.len() != 64 || !rp.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err("rule_pack_sha256 must be a 64-character hex string".to_string());
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceBudgets {
    pub timeout_seconds: u64,
    pub memory_mb: u64,
    pub max_output_bytes: u64,
}

impl Default for ResourceBudgets {
    fn default() -> Self {
        Self {
            timeout_seconds: 300,
            memory_mb: 512,
            max_output_bytes: 10 * 1024 * 1024, // 10 MB
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct EnginePermissions {
    pub allow_network: bool,
    pub allow_mutation: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_destinations: Vec<String>,
}

// ---------------- Response Types ----------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EngineStatus {
    Completed,
    Partial,
    Error,
    Blocked,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticV1 {
    pub code: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ResourceUsage {
    pub duration_ms: u64,
    pub peak_memory_bytes: u64,
}

/// Versioned analysis response strictly compliant with `analysis-response.schema.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalysisResponse {
    pub schema_version: String,
    pub run_id: String,
    pub engine_id: String,
    pub engine_version: String,
    pub snapshot_sha256: String,
    pub status: EngineStatus,
    pub findings: Vec<FindingV1>,
    pub receipts: Vec<CoverageReceiptV1>,
    pub diagnostics: Vec<DiagnosticV1>,
    pub resources: ResourceUsage,
    pub completed_at: String,
}

impl AnalysisResponse {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != "1.0" {
            return Err(format!(
                "Invalid response schema_version: expected '1.0', got '{}'",
                self.schema_version
            ));
        }
        if self.run_id.trim().is_empty() {
            return Err("run_id must not be empty".to_string());
        }
        if self.engine_id.trim().is_empty() {
            return Err("engine_id must not be empty".to_string());
        }
        if self.engine_version.trim().is_empty() {
            return Err("engine_version must not be empty".to_string());
        }
        if self.snapshot_sha256.len() != 64
            || !self
                .snapshot_sha256
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        {
            return Err("snapshot_sha256 must be a 64-character lowercase hex string".to_string());
        }
        for finding in &self.findings {
            finding.validate()?;
        }
        for receipt in &self.receipts {
            receipt.validate()?;
        }
        Ok(())
    }
}

// ---------------- Finding V1 ----------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FindingKind {
    KnownAdvisory,
    Catalog,
    ResearchCandidate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FindingStatus {
    Suspected,
    VersionAffected,
    ReachabilitySuspected,
    Reproduced,
    Verified,
    DuplicateKnown,
    FalsePositive,
    Inconclusive,
    Blocked,
    FixProposed,
    FixedVerified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NormalizedSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceCertaintyV1 {
    Unknown,
    PatternIndicator,
    Suspected,
    StronglySupported,
    Confirmed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineDescriptor {
    pub id: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_pack_sha256: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NormalizedTargetKind {
    File,
    Package,
    Binary,
    Service,
    Config,
    Workspace,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceSpanV1 {
    pub start_line: u32,
    pub end_line: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_column: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_column: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetDescriptor {
    pub target_id: String,
    pub kind: NormalizedTargetKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package_purl: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub span: Option<SourceSpanV1>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceItemKind {
    SourceSpan,
    AstMatch,
    DataflowTrace,
    AdvisoryMatch,
    TestReproduction,
    RuntimeTrace,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceItemV1 {
    pub kind: EvidenceItemKind,
    pub artifact_sha256: String,
    pub description: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProofMethod {
    IsolatedTest,
    AuthoritativeRange,
    StaticInvariant,
    RuntimeTrace,
    ReproductionArtifact,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofV1 {
    pub method: ProofMethod,
    pub artifact_sha256: String,
    pub reproduced_on_snapshot: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub limitations: Vec<String>,
}

/// Versioned finding strictly compliant with `finding.schema.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingV1 {
    pub schema_version: String,
    pub run_id: String,
    pub finding_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    pub kind: FindingKind,
    pub status: FindingStatus,
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    pub severity: NormalizedSeverity,
    pub evidence_certainty: EvidenceCertaintyV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub weakness_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub advisory_ids: Vec<String>,
    pub engine: EngineDescriptor,
    pub target: TargetDescriptor,
    pub source_snapshot_sha256: String,
    pub evidence: Vec<EvidenceItemV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<ProofV1>,
    pub coverage_receipt_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub uncertainty_reasons: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remediation_plan_id: Option<String>,
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
    #[serde(default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub extensions: serde_json::Map<String, serde_json::Value>,
}

impl FindingV1 {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != "1.0" {
            return Err("Finding schema_version must be '1.0'".to_string());
        }
        if self.run_id.trim().is_empty() {
            return Err("run_id must not be empty".to_string());
        }
        if self.finding_id.trim().is_empty() {
            return Err("finding_id must not be empty".to_string());
        }
        if self.title.trim().is_empty() || self.title.len() > 300 {
            return Err("Finding title must be between 1 and 300 characters".to_string());
        }
        if let Some(ref s) = self.summary {
            if s.len() > 5000 {
                return Err("Finding summary must not exceed 5000 characters".to_string());
            }
        }
        if self.source_snapshot_sha256.len() != 64
            || !self
                .source_snapshot_sha256
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        {
            return Err(
                "source_snapshot_sha256 must be a 64-character lowercase hex string".to_string(),
            );
        }
        // Schema rule: if evidence_certainty is CONFIRMED, proof is required
        if self.evidence_certainty == EvidenceCertaintyV1::Confirmed && self.proof.is_none() {
            return Err("Finding with evidence_certainty CONFIRMED requires proof".to_string());
        }
        // Schema rule: if status is FIXED_VERIFIED, remediation_plan_id is required
        if self.status == FindingStatus::FixedVerified && self.remediation_plan_id.is_none() {
            return Err(
                "Finding with status FIXED_VERIFIED requires remediation_plan_id".to_string(),
            );
        }
        for item in &self.evidence {
            if item.artifact_sha256.len() != 64
                || !item
                    .artifact_sha256
                    .chars()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
            {
                return Err(
                    "EvidenceItem artifact_sha256 must be a 64-character lowercase hex string"
                        .to_string(),
                );
            }
            if item.description.len() > 2000 {
                return Err("EvidenceItem description must not exceed 2000 characters".to_string());
            }
        }
        for cwe in &self.weakness_ids {
            if !cwe.starts_with("CWE-")
                || cwe[4..].is_empty()
                || !cwe[4..].chars().all(|c| c.is_ascii_digit())
            {
                return Err(format!(
                    "weakness_id '{}' must match pattern ^CWE-[0-9]+$",
                    cwe
                ));
            }
        }
        Ok(())
    }
}

// ---------------- Coverage Receipt V1 ----------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CoverageReceiptStatus {
    Evaluated,
    Partial,
    NotRun,
    Unsupported,
    NotApplicable,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReceiptReasonCode {
    Timeout,
    ParseError,
    ReadError,
    BudgetExceeded,
    EngineMissing,
    UnsupportedLanguage,
    NotApplicable,
    AuthBlocked,
    NetworkDisabled,
    Cancelled,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ReceiptCounts {
    pub items_discovered: u64,
    pub items_examined: u64,
    pub items_excluded: u64,
    pub items_skipped: u64,
}

/// Versioned coverage receipt strictly compliant with `coverage-receipt.schema.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageReceiptV1 {
    pub schema_version: String,
    pub receipt_id: String,
    pub run_id: String,
    pub engine_id: String,
    pub engine_version: String,
    pub check_id: String,
    pub target_id: String,
    pub snapshot_sha256: String,
    pub status: CoverageReceiptStatus,
    pub counts: ReceiptCounts,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reason_codes: Vec<ReceiptReasonCode>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub details: Vec<String>,
    pub started_at: String,
    pub completed_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_by_policy: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub artifact_digests: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_receipt_id: Option<String>,
}

impl CoverageReceiptV1 {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != "1.0" {
            return Err("CoverageReceipt schema_version must be '1.0'".to_string());
        }
        if self.receipt_id.trim().is_empty() {
            return Err("receipt_id must not be empty".to_string());
        }
        if self.run_id.trim().is_empty() {
            return Err("run_id must not be empty".to_string());
        }
        if self.engine_id.trim().is_empty() {
            return Err("engine_id must not be empty".to_string());
        }
        if self.engine_version.trim().is_empty() {
            return Err("engine_version must not be empty".to_string());
        }
        if self.check_id.trim().is_empty() {
            return Err("check_id must not be empty".to_string());
        }
        if self.target_id.trim().is_empty() {
            return Err("target_id must not be empty".to_string());
        }
        if self.snapshot_sha256.len() != 64
            || !self
                .snapshot_sha256
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        {
            return Err(
                "CoverageReceipt snapshot_sha256 must be 64-character lowercase hex".to_string(),
            );
        }
        // Schema rule: if status is PARTIAL, NOT_RUN, UNSUPPORTED, or ERROR, reason_codes is required with minItems 1
        if matches!(
            self.status,
            CoverageReceiptStatus::Partial
                | CoverageReceiptStatus::NotRun
                | CoverageReceiptStatus::Unsupported
                | CoverageReceiptStatus::Error
        ) && self.reason_codes.is_empty()
        {
            return Err(format!(
                "reason_codes must contain at least 1 reason code when status is {:?}",
                self.status
            ));
        }
        for digest in &self.artifact_digests {
            if digest.len() != 64
                || !digest
                    .chars()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
            {
                return Err("artifact_digest must be 64-character lowercase hex".to_string());
            }
        }
        Ok(())
    }
}

// ---------------- Repair Plan V1 ----------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RepairRiskLevel {
    L1,
    L2,
    L3,
    L4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProposedActionKind {
    SourcePatch,
    LockfileUpdate,
    ConfigPatch,
    WafRule,
    PackageUpgrade,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposedActionV1 {
    pub action_id: String,
    pub kind: ProposedActionKind,
    pub target_relative_path: String,
    pub preimage_sha256: String,
    pub expected_postimage_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diff_artifact_sha256: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VerificationKind {
    Parser,
    Format,
    Typecheck,
    Build,
    Test,
    SecurityRescan,
    ServiceHealth,
    DependencyRequery,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequiredVerificationV1 {
    pub verification_id: String,
    pub kind: VerificationKind,
    pub required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepairApprovalV1 {
    pub operator_id: String,
    pub approval_id: String,
    pub plan_digest: String,
    pub issued_at: String,
    pub expires_at: String,
    pub signature_ref: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RepairPlanStatus {
    Proposed,
    Reviewed,
    Authorized,
    Staged,
    Applied,
    Verified,
    Failed,
    RolledBack,
    RecoveryRequired,
}

/// Versioned repair plan strictly compliant with `repair-plan.schema.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepairPlanV1 {
    pub schema_version: String,
    pub plan_id: String,
    pub run_id: String,
    pub finding_ids: Vec<String>,
    pub workspace_root_digest: String,
    pub risk_level: RepairRiskLevel,
    pub proposed_actions: Vec<ProposedActionV1>,
    pub required_verifications: Vec<RequiredVerificationV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval: Option<RepairApprovalV1>,
    pub status: RepairPlanStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup_manifest_ref: Option<String>,
    pub created_at: String,
    pub expires_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
}

impl RepairPlanV1 {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != "1.0" {
            return Err("RepairPlan schema_version must be '1.0'".to_string());
        }
        if self.plan_id.trim().is_empty() {
            return Err("plan_id must not be empty".to_string());
        }
        if self.run_id.trim().is_empty() {
            return Err("run_id must not be empty".to_string());
        }
        if self.finding_ids.is_empty() {
            return Err("finding_ids must contain at least 1 finding ID".to_string());
        }
        if self.proposed_actions.is_empty() {
            return Err("proposed_actions must contain at least 1 action".to_string());
        }
        if self.required_verifications.is_empty() {
            return Err("required_verifications must contain at least 1 verification".to_string());
        }
        if self.workspace_root_digest.len() != 64
            || !self
                .workspace_root_digest
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        {
            return Err("workspace_root_digest must be 64-character lowercase hex".to_string());
        }
        // Schema rule: if status in AUTHORIZED, STAGED, APPLIED, VERIFIED, approval is required
        if matches!(
            self.status,
            RepairPlanStatus::Authorized
                | RepairPlanStatus::Staged
                | RepairPlanStatus::Applied
                | RepairPlanStatus::Verified
        ) && self.approval.is_none()
        {
            return Err(format!(
                "approval is required when status is {:?}",
                self.status
            ));
        }
        Ok(())
    }
}

// ---------------- Aliases for Milestone Card M1.1 ----------------

pub type NormalizedFinding = FindingV1;
pub type NormalizedCoverageReceipt = CoverageReceiptV1;
pub type NormalizedRepairPlan = RepairPlanV1;
