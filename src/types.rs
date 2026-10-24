use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CveId {
    Php2ShellOom(String),     // CVE-2026-109618
    Php2ShellStale(String),   // CVE-2026-109619
    Node2ShellBrotli(String), // CVE-2026-111497
    Custom { id: String, title: String },
}

impl CveId {
    pub fn as_str(&self) -> &str {
        match self {
            CveId::Php2ShellOom(_) => "CVE-2026-109618",
            CveId::Php2ShellStale(_) => "CVE-2026-109619",
            CveId::Node2ShellBrotli(_) => "CVE-2026-111497",
            CveId::Custom { id, .. } => id.as_str(),
        }
    }

    pub fn title(&self) -> &str {
        match self {
            CveId::Php2ShellOom(_) => "PHP2Shell: RCE via Out-of-Memory (OOM) Heap Corruption",
            CveId::Php2ShellStale(_) => {
                "PHP2Shell: RCE via Stale Global State / Use-After-Free Across Requests"
            }
            CveId::Node2ShellBrotli(_) => {
                "Node2Shell: Out-of-Bounds Memory Write in Bundled Google Brotli Decoder"
            }
            CveId::Custom { title, .. } => title.as_str(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TargetKind {
    PhpRuntime,
    PhpConfigFile,
    PhpFpmPool,
    ComposerManifest,
    NodeRuntime,
    NodePackageManifest,
    NodeLockfile,
    NodeSourceFile,
    NginxConfig,
    ApacheConfig,
    CaddyConfig,
    Dockerfile,
    GenericSourceFile,
    GenericConfigFile,
    EnvironmentFile,
    GoModManifest,
    JavaPomManifest,
    DotnetCsprojManifest,
    RubyGemfileManifest,
    PythonPoetryManifest,
    CargoLockManifest,
    ComposerLockfile,
    CycloneDxSbom,
    SpdxSbom,
    BinaryExecutable,
    AgentSkillManifest,
    McpServerConfig,
}

/// Affectedness status modeled separately from reachability, severity, and remediation readiness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Affectedness {
    ConfirmedAffected,
    LikelyAffected,
    PotentiallyAffected,
    NotAffectedWithEvidence,
    Unknown,
    NotAssessed,
}

impl Affectedness {
    pub fn as_str(&self) -> &'static str {
        match self {
            Affectedness::ConfirmedAffected => "CONFIRMED_AFFECTED",
            Affectedness::LikelyAffected => "LIKELY_AFFECTED",
            Affectedness::PotentiallyAffected => "POTENTIALLY_AFFECTED",
            Affectedness::NotAffectedWithEvidence => "NOT_AFFECTED_WITH_EVIDENCE",
            Affectedness::Unknown => "UNKNOWN",
            Affectedness::NotAssessed => "NOT_ASSESSED",
        }
    }
}

/// Reachability of the vulnerable code path from untrusted external inputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Reachability {
    ConfirmedReachable,
    PotentiallyReachable,
    UnreachableWithEvidence,
    Unknown,
    NotApplicable,
}

impl Reachability {
    pub fn as_str(&self) -> &'static str {
        match self {
            Reachability::ConfirmedReachable => "CONFIRMED_REACHABLE",
            Reachability::PotentiallyReachable => "POTENTIALLY_REACHABLE",
            Reachability::UnreachableWithEvidence => "UNREACHABLE_WITH_EVIDENCE",
            Reachability::Unknown => "UNKNOWN",
            Reachability::NotApplicable => "NOT_APPLICABLE",
        }
    }
}

/// Evidence confidence level of detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Confidence {
    Confirmed,
    High,
    Medium,
    Low,
    Tentative,
}

impl Confidence {
    pub fn as_str(&self) -> &'static str {
        match self {
            Confidence::Confirmed => "CONFIRMED",
            Confidence::High => "HIGH",
            Confidence::Medium => "MEDIUM",
            Confidence::Low => "LOW",
            Confidence::Tentative => "TENTATIVE",
        }
    }
}

/// Observed or known exploitability signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExploitabilitySignal {
    ActiveWildExploitation,
    PublicPocAvailable,
    TheoreticalVulnerability,
    NoKnownExploit,
    Unknown,
}

impl ExploitabilitySignal {
    #[allow(dead_code)]
    pub fn as_str(&self) -> &'static str {
        match self {
            ExploitabilitySignal::ActiveWildExploitation => "ACTIVE_WILD_EXPLOITATION",
            ExploitabilitySignal::PublicPocAvailable => "PUBLIC_POC_AVAILABLE",
            ExploitabilitySignal::TheoreticalVulnerability => "THEORETICAL_VULNERABILITY",
            ExploitabilitySignal::NoKnownExploit => "NO_KNOWN_EXPLOIT",
            ExploitabilitySignal::Unknown => "UNKNOWN",
        }
    }
}

/// Human operator review status for a detected finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OperatorStatus {
    Unreviewed,
    Acknowledged,
    FalsePositive,
    AcceptedRisk,
    Remediated,
}

impl OperatorStatus {
    #[allow(dead_code)]
    pub fn as_str(&self) -> &'static str {
        match self {
            OperatorStatus::Unreviewed => "UNREVIEWED",
            OperatorStatus::Acknowledged => "ACKNOWLEDGED",
            OperatorStatus::FalsePositive => "FALSE_POSITIVE",
            OperatorStatus::AcceptedRisk => "ACCEPTED_RISK",
            OperatorStatus::Remediated => "REMEDIATED",
        }
    }
}

/// Specific evidence reference anchoring a finding to code or system state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceRef {
    pub location: String,
    #[serde(default)]
    pub line_number: Option<usize>,
    #[serde(default)]
    pub snippet: Option<String>,
    #[serde(default)]
    pub sha256: Option<String>,
}

fn default_affectedness() -> Affectedness {
    Affectedness::PotentiallyAffected
}

fn default_reachability() -> Reachability {
    Reachability::Unknown
}

fn default_confidence() -> Confidence {
    Confidence::Medium
}

fn default_exploitability() -> ExploitabilitySignal {
    ExploitabilitySignal::Unknown
}

fn default_operator_status() -> OperatorStatus {
    OperatorStatus::Unreviewed
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceCertainty {
    Confirmed,
    StronglySupported,
    Suspected,
    PatternIndicator,
    Unknown,
}

impl EvidenceCertainty {
    #[allow(dead_code)]
    pub fn as_str(&self) -> &'static str {
        match self {
            EvidenceCertainty::Confirmed => "CONFIRMED",
            EvidenceCertainty::StronglySupported => "STRONGLY_SUPPORTED",
            EvidenceCertainty::Suspected => "SUSPECTED",
            EvidenceCertainty::PatternIndicator => "PATTERN_INDICATOR",
            EvidenceCertainty::Unknown => "UNKNOWN",
        }
    }
}

fn default_evidence_certainty() -> EvidenceCertainty {
    EvidenceCertainty::Unknown
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub cve: CveId,
    pub severity: Severity,
    pub target_kind: TargetKind,
    pub file_path: Option<PathBuf>,
    pub line_number: Option<usize>,
    pub detected_version_or_pattern: String,
    pub safe_threshold: String,
    pub description: String,
    pub suggested_remediation: String,

    // Schema v2 fields from Master Prompt Section 7
    #[serde(default)]
    pub asset_id: String,
    #[serde(default)]
    pub detector_id: String,
    #[serde(default)]
    pub detector_version: String,
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub advisory_ids: Vec<String>,
    #[serde(default)]
    pub component_identity: String,
    #[serde(default)]
    pub installed_build: Option<String>,
    #[serde(default)]
    pub package_source: Option<String>,
    #[serde(default)]
    pub vendor_advisory: Option<String>,
    #[serde(default)]
    pub vendor_fix_state: Option<String>,
    #[serde(default)]
    pub runtime_process_identity: Option<String>,
    #[serde(default)]
    pub evidence_refs: Vec<EvidenceRef>,
    #[serde(default)]
    pub evidence_digest: String,
    #[serde(default)]
    pub observation_time: String,
    #[serde(default = "default_affectedness")]
    pub affectedness: Affectedness,
    #[serde(default = "default_reachability")]
    pub reachability: Reachability,
    #[serde(default = "default_confidence")]
    pub confidence: Confidence,
    #[serde(default = "default_exploitability")]
    pub exploitability_signal: ExploitabilitySignal,
    #[serde(default)]
    pub impact: String,
    #[serde(default)]
    pub uncertainty_reasons: Vec<String>,
    #[serde(default)]
    pub supported_checks: Vec<String>,
    #[serde(default)]
    pub missing_checks: Vec<String>,
    #[serde(default)]
    pub proposed_remediation_ids: Vec<String>,
    #[serde(default = "default_operator_status")]
    pub operator_status: OperatorStatus,
    #[serde(default = "default_evidence_certainty")]
    pub evidence_certainty: EvidenceCertainty,
    #[serde(default)]
    pub dedupe_fingerprint: String,
}

impl Default for Finding {
    fn default() -> Self {
        Self {
            id: String::new(),
            cve: CveId::Custom {
                id: String::new(),
                title: String::new(),
            },
            severity: Severity::Low,
            target_kind: TargetKind::GenericSourceFile,
            file_path: None,
            line_number: None,
            detected_version_or_pattern: String::new(),
            safe_threshold: String::new(),
            description: String::new(),
            suggested_remediation: String::new(),
            asset_id: String::new(),
            detector_id: String::new(),
            detector_version: "1.0.0".to_string(),
            category: "VULNERABILITY".to_string(),
            advisory_ids: Vec::new(),
            component_identity: String::new(),
            installed_build: None,
            package_source: None,
            vendor_advisory: None,
            vendor_fix_state: None,
            runtime_process_identity: None,
            evidence_refs: Vec::new(),
            evidence_digest: String::new(),
            observation_time: chrono::Utc::now().to_rfc3339(),
            affectedness: Affectedness::PotentiallyAffected,
            reachability: Reachability::Unknown,
            confidence: Confidence::Medium,
            exploitability_signal: ExploitabilitySignal::Unknown,
            impact: String::new(),
            uncertainty_reasons: Vec::new(),
            supported_checks: Vec::new(),
            missing_checks: Vec::new(),
            proposed_remediation_ids: Vec::new(),
            operator_status: OperatorStatus::Unreviewed,
            evidence_certainty: EvidenceCertainty::Unknown,
            dedupe_fingerprint: String::new(),
        }
    }
}

impl Finding {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: impl Into<String>,
        cve: CveId,
        severity: Severity,
        target_kind: TargetKind,
        file_path: Option<PathBuf>,
        line_number: Option<usize>,
        detected_version_or_pattern: impl Into<String>,
        safe_threshold: impl Into<String>,
        description: impl Into<String>,
        suggested_remediation: impl Into<String>,
    ) -> Self {
        let pattern = detected_version_or_pattern.into();
        let mut finding = Self {
            id: id.into(),
            cve,
            severity,
            target_kind,
            file_path,
            line_number,
            detected_version_or_pattern: pattern,
            safe_threshold: safe_threshold.into(),
            description: description.into(),
            suggested_remediation: suggested_remediation.into(),
            ..Default::default()
        };
        finding.compute_dedupe_fingerprint();
        finding
    }

    /// Computes deterministic SHA-256 deduplication fingerprint based on target identity, CVE, and file location.
    pub fn compute_dedupe_fingerprint(&mut self) {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(self.cve.as_str().as_bytes());
        hasher.update(b":");
        hasher.update(format!("{:?}", self.target_kind).as_bytes());
        hasher.update(b":");
        if let Some(ref p) = self.file_path {
            hasher.update(p.to_string_lossy().as_bytes());
        }
        hasher.update(b":");
        if let Some(line) = self.line_number {
            hasher.update(line.to_string().as_bytes());
        }
        hasher.update(b":");
        hasher.update(self.detected_version_or_pattern.as_bytes());
        self.dedupe_fingerprint = format!("{:x}", hasher.finalize());
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PatchActionType {
    NginxVirtualPatch,
    ApacheVirtualPatch,
    NodeMiddlewareGuard,
    PackageManifestVersionBump,
    ComposerVersionBump,
    DockerfileBaseImageBump,
    PhpIniHardening,
    GenericReplace,
    GenericAppend,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchAction {
    pub action_type: PatchActionType,
    pub target_file: PathBuf,
    pub original_checksum: String,
    pub diff_description: String,
    pub replacement_content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupRecord {
    pub relative_target_path: String,
    pub original_sha256: String,
    pub backup_file_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupManifest {
    pub backup_id: String,
    pub created_at: String,
    pub root_dir: String,
    pub records: Vec<BackupRecord>,
    #[serde(default)]
    pub signer_public_key: Option<String>,
    #[serde(default)]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CoverageStatus {
    Complete,
    Partial,
    ScanIncomplete,
    Unsupported,
    NotRun,
    Error,
}

impl CoverageStatus {
    #[allow(dead_code)]
    pub fn as_str(&self) -> &'static str {
        match self {
            CoverageStatus::Complete => "COMPLETE",
            CoverageStatus::Partial => "PARTIAL",
            CoverageStatus::ScanIncomplete => "SCAN_INCOMPLETE",
            CoverageStatus::Unsupported => "UNSUPPORTED",
            CoverageStatus::NotRun => "NOT_RUN",
            CoverageStatus::Error => "ERROR",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageReceipt {
    pub scanner_id: String,
    pub scanner_version: String,
    pub target_id: String,
    pub status: CoverageStatus,
    pub items_examined: u64,
    #[serde(default)]
    pub skipped_reasons: Vec<String>,
    #[serde(default)]
    pub errors: Vec<String>,
    pub completed_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct ScanLimits {
    pub max_file_size_bytes: u64,
    pub max_files_scanned: usize,
    pub max_depth: usize,
    pub follow_symlinks: bool,
    pub timeout_seconds: u64,
}

impl Default for ScanLimits {
    fn default() -> Self {
        Self {
            max_file_size_bytes: 5 * 1024 * 1024, // 5 MB
            max_files_scanned: 50_000,
            max_depth: 32,
            follow_symlinks: false,
            timeout_seconds: 300,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParserFailure {
    pub path: PathBuf,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanCoverage {
    pub files_scanned: usize,
    pub files_excluded: usize,
    pub parser_failures: Vec<ParserFailure>,
    pub unsupported_targets: Vec<String>,
    pub coverage_status: CoverageStatus,
    #[serde(default)]
    pub receipts: Vec<CoverageReceipt>,
}

impl Default for ScanCoverage {
    fn default() -> Self {
        Self {
            files_scanned: 0,
            files_excluded: 0,
            parser_failures: Vec::new(),
            unsupported_targets: Vec::new(),
            coverage_status: CoverageStatus::Complete,
            receipts: Vec::new(),
        }
    }
}

impl ScanCoverage {
    pub fn is_complete(&self) -> bool {
        self.coverage_status == CoverageStatus::Complete
            && self.parser_failures.is_empty()
            && self
                .receipts
                .iter()
                .all(|r| r.status == CoverageStatus::Complete && r.errors.is_empty())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub target_dir: PathBuf,
    pub scan_time: String,
    pub total_files_scanned: usize,
    pub findings: Vec<Finding>,
    pub is_vulnerable: bool,
    pub critical_count: usize,
    pub high_count: usize,
    #[serde(default)]
    pub coverage: ScanCoverage,
}

impl ScanReport {
    /// True only if no vulnerabilities were detected AND coverage was 100% complete with zero parser failures.
    pub fn is_clean(&self) -> bool {
        !self.is_vulnerable && self.coverage.is_complete()
    }
}
