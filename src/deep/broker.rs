use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// =========================================================================
// Enums conforming strictly to tool-capability.schema.json &
// tool-execution-receipt.schema.json
// =========================================================================

/// Installation state of an external security tool on the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Installation {
    Available,
    Missing,
    Incompatible,
    Unlicensed,
    Unhealthy,
    Disabled,
}

pub type InstallationState = Installation;
pub type InstallationStatus = Installation;

/// The capability classification of an external engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CapabilityKind {
    Sast,
    Sca,
    Sbom,
    Secrets,
    Iac,
    Dast,
    Fuzz,
    Symbolic,
    Runtime,
    Repair,
    Advisory,
    Context,
}

pub type ToolKind = CapabilityKind;

/// Output format emitted by the tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OutputFormat {
    Json,
    Sarif,
    Text,
    Crash,
    Sbom,
}

/// Upper bound on the evidence certainty this tool can claim on its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceLimit {
    Unknown,
    PatternIndicator,
    Suspected,
    StronglySupported,
    Confirmed,
}

/// Transport used to execute or interact with the tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExecutionTransport {
    Library,
    Cli,
    Container,
    Mcp,
    Ci,
    VendorApi,
}

/// Governance review status for tool licensing and legal eligibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LicenseReview {
    Approved,
    Pending,
    Rejected,
    NotApplicable,
}

pub type LicenseReviewStatus = LicenseReview;

/// Cost model under which the external tool runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CostModel {
    LocalResources,
    PerInvocation,
    Subscription,
    Unknown,
}

/// Terminal or execution state for an attempted tool run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ToolExecutionStatus {
    Completed,
    Partial,
    NotRun,
    Blocked,
    Error,
    Cancelled,
}

pub type ReceiptStatus = ToolExecutionStatus;

pub type ExecutionStatus = ToolExecutionStatus;
pub type ExecutionReceiptStatus = ToolExecutionStatus;

/// Classification of artifacts produced during tool execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ArtifactKind {
    RawOutput,
    NormalizedFindings,
    Coverage,
    TestProof,
    SanitizedDiagnostics,
}

/// Access class of an artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ArtifactAccessClass {
    LocalRedacted,
    PrivateRestricted,
}

pub type AccessClass = ArtifactAccessClass;

// =========================================================================
// Tool Capability Data Types (schemas/tool-capability.schema.json)
// =========================================================================

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolCapabilityDetails {
    pub kinds: Vec<CapabilityKind>,
    pub languages: Vec<String>,
    pub asset_types: Vec<String>,
    pub check_ids: Vec<String>,
    pub output_formats: Vec<OutputFormat>,
    pub evidence_limit: EvidenceLimit,
}

pub type ToolCapabilitiesDescriptor = ToolCapabilityDetails;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolExecutionDetails {
    pub transport: ExecutionTransport,
    pub local: bool,
    pub network_required: bool,
    pub scoped_permission_classes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub platforms: Vec<String>,
}

pub type ToolExecutionConfig = ToolExecutionDetails;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolGovernanceDetails {
    pub license_review: LicenseReview,
    pub entitlement_verified: bool,
    pub source_export_required: bool,
    pub cost_model: CostModel,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub restrictions: Vec<String>,
}

pub type ToolGovernance = ToolGovernanceDetails;

/// Discovered capability record conforming strictly to `schemas/tool-capability.schema.json`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolCapability {
    pub schema_version: String,
    pub tool_id: String,
    pub adapter_version: String,
    pub engine_version: Option<String>,
    pub binary_sha256: Option<String>,
    pub installation: Installation,
    pub capabilities: ToolCapabilityDetails,
    pub execution: ToolExecutionDetails,
    pub governance: ToolGovernanceDetails,
    pub verified_at: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

impl ToolCapability {
    /// Validates the tool capability record against schema requirements.
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != "1.0" {
            return Err(format!(
                "Invalid schema_version: expected '1.0', got '{}'",
                self.schema_version
            ));
        }
        if self.tool_id.trim().is_empty() {
            return Err("tool_id must not be empty".to_string());
        }
        if self.adapter_version.trim().is_empty() {
            return Err("adapter_version must not be empty".to_string());
        }
        if let Some(ref sha) = self.binary_sha256 {
            if sha.len() != 64
                || !sha
                    .chars()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
            {
                return Err("binary_sha256 must be a 64-character lowercase hex string".to_string());
            }
        }
        if self.capabilities.kinds.is_empty() {
            return Err("capabilities.kinds must contain at least 1 kind".to_string());
        }
        if DateTime::parse_from_rfc3339(&self.verified_at).is_err() {
            return Err(format!(
                "verified_at must be valid RFC3339 date-time: {}",
                self.verified_at
            ));
        }
        Ok(())
    }
}

// =========================================================================
// Tool Execution Receipt Data Types (schemas/tool-execution-receipt.schema.json)
// =========================================================================

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct ExecutionResources {
    pub duration_ms: u64,
    pub peak_memory_bytes: Option<u64>,
    pub cost_estimate_usd: Option<f64>,
    pub cost_actual_usd: Option<f64>,
}

pub type ReceiptResources = ExecutionResources;

/// Request payload for broker tool execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrokerExecutionRequest {
    pub plan_id: String,
    pub run_id: String,
    pub snapshot_sha256: String,
    pub target_ids: Vec<String>,
    pub check_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub working_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptArtifact {
    pub kind: ArtifactKind,
    pub sha256: String,
    pub access_class: ArtifactAccessClass,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage_ref: Option<String>,
}

/// Immutable, host-authored execution receipt conforming strictly to `schemas/tool-execution-receipt.schema.json`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolExecutionReceipt {
    pub schema_version: String,
    pub receipt_id: String,
    pub plan_id: String,
    pub run_id: String,
    pub tool_id: String,
    pub adapter_version: String,
    pub engine_version: Option<String>,
    pub snapshot_sha256: String,
    pub target_ids: Vec<String>,
    pub check_ids: Vec<String>,
    pub status: ToolExecutionStatus,
    pub reason_code: String,
    pub authorization_ref: Option<String>,
    pub resources: ExecutionResources,
    pub artifacts: Vec<ReceiptArtifact>,
    pub started_at: String,
    pub completed_at: String,
}

impl ToolExecutionReceipt {
    /// Validates receipt invariants against `tool-execution-receipt.schema.json`.
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != "1.0" {
            return Err(format!(
                "Invalid schema_version: expected '1.0', got '{}'",
                self.schema_version
            ));
        }
        if self.receipt_id.trim().is_empty() {
            return Err("receipt_id must not be empty".to_string());
        }
        if self.plan_id.trim().is_empty() {
            return Err("plan_id must not be empty".to_string());
        }
        if self.run_id.trim().is_empty() {
            return Err("run_id must not be empty".to_string());
        }
        if self.tool_id.trim().is_empty() {
            return Err("tool_id must not be empty".to_string());
        }
        if self.adapter_version.trim().is_empty() {
            return Err("adapter_version must not be empty".to_string());
        }
        if self.snapshot_sha256.len() != 64
            || !self
                .snapshot_sha256
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        {
            return Err(format!(
                "snapshot_sha256 must be a 64-character lowercase hex string: {}",
                self.snapshot_sha256
            ));
        }
        if self.target_ids.is_empty() {
            return Err("target_ids must contain at least 1 item".to_string());
        }
        if self.check_ids.is_empty() {
            return Err("check_ids must contain at least 1 item".to_string());
        }
        if self.reason_code.trim().is_empty() {
            return Err("reason_code must not be empty".to_string());
        }
        for artifact in &self.artifacts {
            if artifact.sha256.len() != 64
                || !artifact
                    .sha256
                    .chars()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
            {
                return Err(
                    "artifact sha256 must be a 64-character lowercase hex string".to_string(),
                );
            }
        }
        if DateTime::parse_from_rfc3339(&self.started_at).is_err() {
            return Err(format!(
                "started_at must be valid RFC3339 date-time: {}",
                self.started_at
            ));
        }
        if DateTime::parse_from_rfc3339(&self.completed_at).is_err() {
            return Err(format!(
                "completed_at must be valid RFC3339 date-time: {}",
                self.completed_at
            ));
        }
        Ok(())
    }

    /// Helper to test if this receipt represents an engine missing condition.
    pub fn is_engine_missing(&self) -> bool {
        self.reason_code.eq_ignore_ascii_case("EngineMissing")
            || self.reason_code.eq_ignore_ascii_case("ENGINE_MISSING")
    }

    /// Helper to test if this receipt represents an unlicensed environment condition.
    pub fn is_unlicensed(&self) -> bool {
        self.reason_code
            .eq_ignore_ascii_case("UnlicensedEnvironment")
            || self
                .reason_code
                .eq_ignore_ascii_case("UNLICENSED_ENVIRONMENT")
    }
}

// =========================================================================
// Standard Reason Codes
// =========================================================================

pub const REASON_ENGINE_MISSING: &str = "EngineMissing";
pub const REASON_UNLICENSED_ENVIRONMENT: &str = "UnlicensedEnvironment";
pub const REASON_COMPLETED: &str = "Completed";
pub const REASON_BLOCKED: &str = "Blocked";
pub const REASON_TIMEOUT: &str = "Timeout";
pub const REASON_EXECUTION_ERROR: &str = "ExecutionError";
pub const REASON_CANCELLED: &str = "Cancelled";

// =========================================================================
// Execution Ledger Data Types
// =========================================================================

/// In-memory receipt ledger with a digest suitable for comparison against an
/// independently retained checkpoint. This is not an authenticated audit log.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExecutionLedger {
    pub schema_version: String,
    pub ledger_id: String,
    pub receipts: Vec<ToolExecutionReceipt>,
    /// Tracks which receipts have been verified as real OS-level executions (vs synthetic/mock).
    pub verified_real_executions: HashMap<String, bool>,
}

impl Default for ExecutionLedger {
    fn default() -> Self {
        Self::new()
    }
}

impl ExecutionLedger {
    pub fn new() -> Self {
        let nonce: [u8; 8] = rand::random();
        Self {
            schema_version: "1.0".to_string(),
            ledger_id: format!("ledger-{}", crate::identity::to_hex(nonce)),
            receipts: Vec::new(),
            verified_real_executions: HashMap::new(),
        }
    }

    pub fn with_ledger_id(ledger_id: impl Into<String>) -> Self {
        Self {
            schema_version: "1.0".to_string(),
            ledger_id: ledger_id.into(),
            receipts: Vec::new(),
            verified_real_executions: HashMap::new(),
        }
    }

    /// Records an execution receipt into the ledger.
    /// If `is_real_execution` is true, enforces that the receipt represents an actual executed tool run
    /// with valid non-dummy artifacts, rejecting any mock or synthetic results trying to pass as real.
    pub fn record_receipt(
        &mut self,
        receipt: ToolExecutionReceipt,
        is_real_execution: bool,
    ) -> Result<(), String> {
        receipt.validate()?;

        if is_real_execution {
            if receipt.status == ToolExecutionStatus::NotRun {
                return Err("Cannot record a NOT_RUN receipt as a real execution".to_string());
            }

            // Check for mock/dummy hashes
            for art in &receipt.artifacts {
                if art.sha256 == "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
                    || art.sha256.chars().all(|c| c == '0')
                    || art.sha256.chars().all(|c| c == '1')
                {
                    return Err(
                        "Mock execution artifact detected; cannot pass as real execution in ledger"
                            .to_string(),
                    );
                }
            }
        }

        self.verified_real_executions
            .insert(receipt.receipt_id.clone(), is_real_execution);
        self.receipts.push(receipt);
        Ok(())
    }

    /// Computes a deterministic SHA-256 commitment over every serialized field,
    /// the append order and the caller-supplied execution provenance flags.
    /// The expected digest must be kept outside this mutable structure.
    pub fn compute_digest(&self) -> String {
        let mut hasher = Sha256::new();
        for value in [&self.schema_version, &self.ledger_id] {
            hasher.update((value.len() as u64).to_be_bytes());
            hasher.update(value.as_bytes());
        }

        for r in &self.receipts {
            let bytes = serde_json::to_vec(r)
                .expect("serializing validated execution receipts must not fail");
            hasher.update((bytes.len() as u64).to_be_bytes());
            hasher.update(&bytes);
            let is_real = self.is_real_execution(&r.receipt_id);
            hasher.update([u8::from(is_real)]);
        }

        crate::identity::to_hex(hasher.finalize())
    }

    /// Verifies the cryptographic integrity of the execution ledger against an expected digest.
    pub fn verify_integrity(&self, expected_digest: &str) -> Result<(), String> {
        for r in &self.receipts {
            r.validate()?;
        }
        let actual = self.compute_digest();
        if actual != expected_digest {
            return Err(format!(
                "Execution ledger integrity violation: expected {}, got {}",
                expected_digest, actual
            ));
        }
        Ok(())
    }

    pub fn is_real_execution(&self, receipt_id: &str) -> bool {
        self.verified_real_executions
            .get(receipt_id)
            .copied()
            .unwrap_or(false)
    }

    pub fn len(&self) -> usize {
        self.receipts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.receipts.is_empty()
    }

    pub fn receipts(&self) -> &[ToolExecutionReceipt] {
        &self.receipts
    }

    pub fn get_receipt(&self, receipt_id: &str) -> Option<&ToolExecutionReceipt> {
        self.receipts.iter().find(|r| r.receipt_id == receipt_id)
    }
}

// =========================================================================
// Tool Capability Broker
// =========================================================================

/// Discovers installed vs missing tools, tracks capabilities, and emits honest execution receipts.
#[derive(Debug, Clone)]
pub struct ToolCapabilityBroker {
    tool_paths: HashMap<String, PathBuf>,
    capabilities: HashMap<String, ToolCapability>,
    receipts: Vec<ToolExecutionReceipt>,
    codeql_license_override: Option<bool>,
    ledger: ExecutionLedger,
}

impl Default for ToolCapabilityBroker {
    fn default() -> Self {
        Self::new()
    }
}

impl ToolCapabilityBroker {
    /// Creates a new broker with default known external tools registered.
    pub fn new() -> Self {
        let mut broker = Self {
            tool_paths: HashMap::new(),
            capabilities: HashMap::new(),
            receipts: Vec::new(),
            codeql_license_override: None,
            ledger: ExecutionLedger::new(),
        };
        broker.discover_all();
        broker
    }

    /// Configures an explicit path to a tool binary.
    pub fn with_tool_path(mut self, tool_id: &str, path: impl Into<PathBuf>) -> Self {
        self.set_tool_path(tool_id, path.into());
        self
    }

    /// Sets or updates a tool binary path and refreshes its capability.
    pub fn set_tool_path(&mut self, tool_id: &str, path: PathBuf) {
        self.tool_paths.insert(tool_id.to_string(), path);
        self.discover_tool(tool_id);
    }

    /// Overrides CodeQL licensing verification status for testing or authorized enterprise environments.
    pub fn set_codeql_license_approved(&mut self, approved: bool) {
        self.codeql_license_override = Some(approved);
        self.discover_tool("codeql");
    }

    /// Locates the binary for a given tool ID by checking configured paths, env vars, or PATH.
    pub fn find_binary(&self, tool_id: &str) -> Option<PathBuf> {
        // 1. Explicitly configured path
        if let Some(path) = self.tool_paths.get(tool_id) {
            if path.is_file() {
                return Some(path.clone());
            }
        }

        // 2. Specific environment variable
        let env_var = match tool_id {
            "semgrep" | "semgrep-ce-adapter" => "SEMGREP_BIN",
            "codeql" | "codeql-adapter" => "CODEQL_BIN",
            "joern" | "joern-cpg-adapter" => "JOERN_BIN",
            "trivy" | "trivy-adapter" => "TRIVY_BIN",
            "osv-scanner" | "osv-scanner-adapter" | "osv" => "OSV_SCANNER_BIN",
            _ => "",
        };
        if !env_var.is_empty() {
            if let Ok(val) = std::env::var(env_var) {
                let p = PathBuf::from(val);
                if p.is_file() {
                    return Some(p);
                }
            }
        }

        // 3. Search PATH
        let binary_names: &[&str] = match tool_id {
            "semgrep" | "semgrep-ce-adapter" => &["semgrep"],
            "codeql" | "codeql-adapter" => &["codeql"],
            "joern" | "joern-cpg-adapter" => &["joern", "joern-cli"],
            "trivy" | "trivy-adapter" => &["trivy"],
            "osv-scanner" | "osv-scanner-adapter" | "osv" => &["osv-scanner"],
            other => &[other],
        };

        if let Some(path_os) = std::env::var_os("PATH") {
            for dir in std::env::split_paths(&path_os) {
                for name in binary_names {
                    let candidate = dir.join(name);
                    if candidate.is_file() {
                        return Some(candidate);
                    }
                    #[cfg(windows)]
                    {
                        let candidate_exe = dir.join(format!("{}.exe", name));
                        if candidate_exe.is_file() {
                            return Some(candidate_exe);
                        }
                    }
                }
            }
        }

        None
    }

    /// Computes the lowercase SHA-256 hex digest of a binary file.
    pub fn hash_binary(path: &Path) -> Option<String> {
        let mut file = File::open(path).ok()?;
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 8192];
        loop {
            let n = file.read(&mut buffer).ok()?;
            if n == 0 {
                break;
            }
            hasher.update(&buffer[..n]);
        }
        Some(crate::to_hex(hasher.finalize()))
    }

    /// Discovers all standard external tools.
    pub fn discover_all(&mut self) -> Vec<ToolCapability> {
        let tools = [
            "semgrep",
            "joern",
            "codeql",
            "trivy",
            "osv-scanner",
            "privacy-engine",
            "threatswarm",
            "cve-mcp",
        ];
        let mut results = Vec::new();
        for tool in tools {
            let cap = self.discover_tool(tool);
            results.push(cap);
        }
        results
    }

    /// Probes and builds a ToolCapability record for a given tool ID.
    pub fn discover_tool(&mut self, tool_id: &str) -> ToolCapability {
        let canonical_id = match tool_id {
            "semgrep" | "semgrep-ce-adapter" | "semgrep-sast-adapter" => "semgrep",
            "codeql" | "codeql-adapter" => "codeql",
            "joern" | "joern-cpg-adapter" => "joern",
            "trivy" | "trivy-adapter" => "trivy",
            "osv-scanner" | "osv-scanner-adapter" | "osv" => "osv-scanner",
            "privacy-engine" | "privacy-adapter" | "bk-privacy" | "data-protection" => {
                "privacy-engine"
            }
            "threatswarm"
            | "threatswarm-deep-adapter"
            | "threatswarm-adapter"
            | "bk-threatswarm" => "threatswarm",
            other => other,
        };

        let binary_path = self.find_binary(canonical_id);
        let now = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

        let cap = match canonical_id {
            "semgrep" => self.build_semgrep_capability(binary_path.as_deref(), &now),
            "codeql" => self.build_codeql_capability(binary_path.as_deref(), &now),
            "joern" => self.build_joern_capability(binary_path.as_deref(), &now),
            "trivy" => self.build_trivy_capability(binary_path.as_deref(), &now),
            "osv-scanner" => self.build_osv_scanner_capability(binary_path.as_deref(), &now),
            "privacy-engine" => self.build_privacy_capability(&now),
            "threatswarm" => self.build_threatswarm_capability(&now),
            "cve-mcp" => self.build_cve_mcp_capability(binary_path.as_deref(), &now),
            custom => self.build_custom_capability(custom, binary_path.as_deref(), &now),
        };

        self.capabilities
            .insert(canonical_id.to_string(), cap.clone());
        self.capabilities.insert(cap.tool_id.clone(), cap.clone());
        self.capabilities
            .insert(format!("{}-adapter", canonical_id), cap.clone());
        if canonical_id == "semgrep" {
            self.capabilities
                .insert("semgrep-sast-adapter".to_string(), cap.clone());
            self.capabilities
                .insert("semgrep-ce-adapter".to_string(), cap.clone());
        }
        if canonical_id == "joern" {
            self.capabilities
                .insert("joern-cpg-adapter".to_string(), cap.clone());
        }
        if canonical_id == "osv-scanner" {
            self.capabilities
                .insert("osv-scanner-adapter".to_string(), cap.clone());
            self.capabilities.insert("osv".to_string(), cap.clone());
        }
        if canonical_id == "privacy-engine" {
            self.capabilities
                .insert("privacy-engine-adapter".to_string(), cap.clone());
            self.capabilities
                .insert("bk-privacy".to_string(), cap.clone());
        }
        if canonical_id == "threatswarm" {
            self.capabilities
                .insert("threatswarm-deep-adapter".to_string(), cap.clone());
            self.capabilities
                .insert("bk-threatswarm".to_string(), cap.clone());
        }
        if canonical_id == "cve-mcp" {
            self.capabilities
                .insert("cve-mcp-adapter".to_string(), cap.clone());
            self.capabilities
                .insert("cve-mcp-server".to_string(), cap.clone());
        }
        cap
    }

    /// Default discovery for standard security tools.
    pub fn discover_default_tools() -> Self {
        Self::new()
    }

    /// Retrieve a tool capability by tool ID.
    pub fn get_tool(&self, tool_id: &str) -> Option<&ToolCapability> {
        self.get_capability(tool_id)
    }

    /// Access the deep cybersecurity skills registry.
    pub fn skills(&self) -> &'static crate::deep::skills::CybersecuritySkillsRegistry {
        crate::deep::skills::CybersecuritySkillsRegistry::default_embedded()
    }

    /// Recommends cybersecurity skills associated with an external tool ID.
    pub fn recommend_skills_for_tool(
        &self,
        tool_id: &str,
    ) -> Vec<&'static crate::deep::skills::CybersecuritySkill> {
        crate::deep::skills::CybersecuritySkillsRegistry::default_embedded()
            .recommend_for_tool(tool_id)
    }

    /// Access the deep privacy & data protection skills registry.
    pub fn privacy_skills(&self) -> &'static crate::deep::privacy::PrivacySkillsRegistry {
        crate::deep::privacy::PrivacySkillsRegistry::default_embedded()
    }

    /// Recommends privacy & data protection skills for a given check ID or regulatory term.
    pub fn recommend_privacy_skills(
        &self,
        check_id: &str,
    ) -> Vec<&'static crate::deep::privacy::PrivacySkill> {
        crate::deep::privacy::PrivacySkillsRegistry::default_embedded()
            .recommend_for_check(check_id)
    }

    /// Register or override a tool capability.
    pub fn register_tool(&mut self, tool: ToolCapability) {
        let id = tool.tool_id.clone();
        self.capabilities.insert(id.clone(), tool.clone());
        if id.ends_with("-adapter") {
            let prefix = id.trim_end_matches("-adapter");
            self.capabilities.insert(prefix.to_string(), tool.clone());
        } else {
            self.capabilities
                .insert(format!("{}-adapter", id), tool.clone());
        }
    }

    /// Executes a tool run via broker, enforcing timeouts, cancellations, and emitting honest receipts.
    pub fn execute(
        &self,
        tool_id: &str,
        request: &BrokerExecutionRequest,
        cancel_token: &crate::engine::runner::CancellationToken,
    ) -> ToolExecutionReceipt {
        let now = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let receipt_id = format!(
            "{}-receipt-{}",
            tool_id,
            &request.snapshot_sha256[..8.min(request.snapshot_sha256.len())]
        );

        if cancel_token.is_cancelled() {
            return ToolExecutionReceipt {
                schema_version: "1.0".to_string(),
                receipt_id,
                plan_id: request.plan_id.clone(),
                run_id: request.run_id.clone(),
                tool_id: tool_id.to_string(),
                adapter_version: "0.1.0".to_string(),
                engine_version: None,
                snapshot_sha256: request.snapshot_sha256.clone(),
                target_ids: request.target_ids.clone(),
                check_ids: request.check_ids.clone(),
                status: ToolExecutionStatus::Cancelled,
                reason_code: "CANCELLED".to_string(),
                authorization_ref: request.authorization_ref.clone(),
                resources: ExecutionResources::default(),
                artifacts: Vec::new(),
                started_at: now.clone(),
                completed_at: now,
            };
        }

        let cap = match self.get_capability(tool_id) {
            Some(c) => c,
            None => {
                return ToolExecutionReceipt {
                    schema_version: "1.0".to_string(),
                    receipt_id,
                    plan_id: request.plan_id.clone(),
                    run_id: request.run_id.clone(),
                    tool_id: tool_id.to_string(),
                    adapter_version: "0.1.0".to_string(),
                    engine_version: None,
                    snapshot_sha256: request.snapshot_sha256.clone(),
                    target_ids: request.target_ids.clone(),
                    check_ids: request.check_ids.clone(),
                    status: ToolExecutionStatus::NotRun,
                    reason_code: "ENGINE_MISSING".to_string(),
                    authorization_ref: request.authorization_ref.clone(),
                    resources: ExecutionResources::default(),
                    artifacts: Vec::new(),
                    started_at: now.clone(),
                    completed_at: now,
                };
            }
        };

        let (status, reason_code, duration_ms, artifacts) = match cap.installation {
            Installation::Missing => (
                ToolExecutionStatus::NotRun,
                "ENGINE_MISSING".to_string(),
                0,
                Vec::new(),
            ),
            Installation::Unlicensed => (
                ToolExecutionStatus::NotRun,
                "UNLICENSED_ENVIRONMENT".to_string(),
                0,
                Vec::new(),
            ),
            Installation::Incompatible => (
                ToolExecutionStatus::NotRun,
                "INCOMPATIBLE_ENGINE".to_string(),
                0,
                Vec::new(),
            ),
            Installation::Unhealthy => (
                ToolExecutionStatus::Error,
                "ENGINE_UNHEALTHY".to_string(),
                0,
                Vec::new(),
            ),
            Installation::Disabled => (
                ToolExecutionStatus::NotRun,
                "ENGINE_DISABLED".to_string(),
                0,
                Vec::new(),
            ),
            Installation::Available => {
                let bin = self
                    .find_binary(&cap.tool_id)
                    .or_else(|| self.find_binary(tool_id));
                match bin {
                    Some(b) => {
                        let timeout = request.timeout_seconds.unwrap_or(30);
                        Self::run_subprocess(
                            &b,
                            &request.args,
                            request.working_dir.as_deref(),
                            timeout,
                            cancel_token,
                            &cap.tool_id,
                            &request.snapshot_sha256,
                        )
                    }
                    None => (
                        ToolExecutionStatus::NotRun,
                        "ENGINE_MISSING".to_string(),
                        0,
                        Vec::new(),
                    ),
                }
            }
        };

        ToolExecutionReceipt {
            schema_version: "1.0".to_string(),
            receipt_id,
            plan_id: request.plan_id.clone(),
            run_id: request.run_id.clone(),
            tool_id: cap.tool_id.clone(),
            adapter_version: cap.adapter_version.clone(),
            engine_version: cap.engine_version.clone(),
            snapshot_sha256: request.snapshot_sha256.clone(),
            target_ids: request.target_ids.clone(),
            check_ids: request.check_ids.clone(),
            status,
            reason_code,
            authorization_ref: request.authorization_ref.clone(),
            resources: ExecutionResources {
                duration_ms,
                peak_memory_bytes: None,
                cost_estimate_usd: None,
                cost_actual_usd: None,
            },
            artifacts,
            started_at: now.clone(),
            completed_at: now,
        }
    }

    /// Returns the cached capability for a tool ID if discovered.
    pub fn get_capability(&self, tool_id: &str) -> Option<&ToolCapability> {
        self.capabilities.get(tool_id)
    }

    /// Lists all discovered tool capabilities.
    pub fn list_capabilities(&self) -> Vec<ToolCapability> {
        let mut caps: Vec<_> = self.capabilities.values().cloned().collect();
        caps.sort_by(|a, b| a.tool_id.cmp(&b.tool_id));
        caps.dedup_by(|a, b| a.tool_id == b.tool_id);
        caps
    }

    /// Checks if a tool is currently installed and available.
    pub fn is_available(&self, tool_id: &str) -> bool {
        self.capabilities
            .get(tool_id)
            .map(|c| c.installation == Installation::Available)
            .unwrap_or(false)
    }

    /// Directly registers or overrides a capability descriptor.
    pub fn register_capability(&mut self, capability: ToolCapability) {
        self.capabilities
            .insert(capability.tool_id.clone(), capability);
    }

    /// Emits and records an honest ToolExecutionReceipt for an attempted execution.
    pub fn emit_receipt(
        &mut self,
        plan_id: &str,
        run_id: &str,
        tool_id: &str,
        snapshot_sha256: &str,
        target_ids: Vec<String>,
        check_ids: Vec<String>,
    ) -> ToolExecutionReceipt {
        let cap = self.discover_tool(tool_id);
        let now = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let receipt_id = format!(
            "{}-receipt-{}",
            tool_id,
            &snapshot_sha256[..8.min(snapshot_sha256.len())]
        );

        let (status, reason_code) = match cap.installation {
            Installation::Missing => (
                ToolExecutionStatus::NotRun,
                REASON_ENGINE_MISSING.to_string(),
            ),
            Installation::Unlicensed => (
                ToolExecutionStatus::NotRun,
                REASON_UNLICENSED_ENVIRONMENT.to_string(),
            ),
            Installation::Incompatible => (
                ToolExecutionStatus::NotRun,
                "IncompatibleEngineVersion".to_string(),
            ),
            Installation::Unhealthy => (ToolExecutionStatus::Error, "EngineUnhealthy".to_string()),
            Installation::Disabled => (ToolExecutionStatus::NotRun, "EngineDisabled".to_string()),
            Installation::Available => (ToolExecutionStatus::NotRun, "NOT_EXECUTED".to_string()),
        };

        let receipt = ToolExecutionReceipt {
            schema_version: "1.0".to_string(),
            receipt_id,
            plan_id: plan_id.to_string(),
            run_id: run_id.to_string(),
            tool_id: cap.tool_id.clone(),
            adapter_version: cap.adapter_version.clone(),
            engine_version: cap.engine_version.clone(),
            snapshot_sha256: snapshot_sha256.to_string(),
            target_ids: if target_ids.is_empty() {
                vec!["target/default".to_string()]
            } else {
                target_ids
            },
            check_ids: if check_ids.is_empty() {
                vec!["ALL".to_string()]
            } else {
                check_ids
            },
            status,
            reason_code,
            authorization_ref: None,
            resources: ExecutionResources::default(),
            artifacts: Vec::new(),
            started_at: now.clone(),
            completed_at: now,
        };

        self.receipts.push(receipt.clone());
        receipt
    }

    /// Access reference to the execution ledger.
    pub fn ledger(&self) -> &ExecutionLedger {
        &self.ledger
    }

    /// Access mutable reference to the execution ledger.
    pub fn ledger_mut(&mut self) -> &mut ExecutionLedger {
        &mut self.ledger
    }

    /// Imports a caller-provided receipt without claiming its execution was verified.
    pub fn record_receipt(&mut self, receipt: ToolExecutionReceipt) {
        let _ = self.ledger.record_receipt(receipt.clone(), false);
        self.receipts.push(receipt);
    }

    /// Executes a tool run via broker, recording the verified receipt into the ledger.
    pub fn execute_and_record(
        &mut self,
        tool_id: &str,
        request: &BrokerExecutionRequest,
        cancel_token: &crate::engine::runner::CancellationToken,
    ) -> ToolExecutionReceipt {
        let receipt = self.execute(tool_id, request, cancel_token);
        let is_real =
            receipt.status == ToolExecutionStatus::Completed && !receipt.artifacts.is_empty();
        let _ = self.ledger.record_receipt(receipt.clone(), is_real);
        self.receipts.push(receipt.clone());
        receipt
    }

    /// Access all execution receipts emitted or recorded by this broker.
    pub fn receipts(&self) -> &[ToolExecutionReceipt] {
        &self.receipts
    }

    /// Clears all recorded execution receipts.
    pub fn clear_receipts(&mut self) {
        self.receipts.clear();
    }

    // ---------------- Subprocess Runner with Process Group Isolation ----------------

    pub fn run_subprocess(
        binary: &Path,
        args: &[String],
        working_dir: Option<&Path>,
        timeout_seconds: u64,
        cancel_token: &crate::engine::runner::CancellationToken,
        _tool_id: &str,
        _snapshot_sha256: &str,
    ) -> (ToolExecutionStatus, String, u64, Vec<ReceiptArtifact>) {
        let start = Instant::now();
        let mut cmd = Command::new(binary);
        for arg in args {
            cmd.arg(arg);
        }
        if let Some(dir) = working_dir {
            cmd.current_dir(dir);
        }
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());

        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            cmd.process_group(0);
        }

        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                let dur = start.elapsed().as_millis() as u64;
                return (
                    ToolExecutionStatus::Error,
                    format!("SPAWN_FAILED: {}", e),
                    dur,
                    Vec::new(),
                );
            }
        };

        // Drain both pipes while the child runs. Waiting first deadlocks when
        // either pipe fills and can turn a successful scan into a timeout.
        // Stream through the hasher instead of retaining unbounded raw output.
        let stdout_reader = child
            .stdout
            .take()
            .map(|out| std::thread::spawn(move || Self::hash_stream(out)));
        let stderr_reader = child
            .stderr
            .take()
            .map(|err| std::thread::spawn(move || Self::hash_stream(err)));

        let pid = child.id();
        let timeout_dur = Duration::from_secs(timeout_seconds);
        let poll_interval = Duration::from_millis(20);

        let exit_status = loop {
            if cancel_token.is_cancelled() {
                Self::kill_process_group(pid);
                let _ = child.wait();
                let dur = start.elapsed().as_millis() as u64;
                return (
                    ToolExecutionStatus::Cancelled,
                    "CANCELLED".to_string(),
                    dur,
                    Vec::new(),
                );
            }

            if start.elapsed() >= timeout_dur {
                Self::kill_process_group(pid);
                let _ = child.wait();
                let dur = start.elapsed().as_millis() as u64;
                return (
                    ToolExecutionStatus::Error,
                    "TIMEOUT".to_string(),
                    dur,
                    Vec::new(),
                );
            }

            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) => std::thread::sleep(poll_interval),
                Err(e) => {
                    Self::kill_process_group(pid);
                    let _ = child.wait();
                    let dur = start.elapsed().as_millis() as u64;
                    return (
                        ToolExecutionStatus::Error,
                        format!("WAIT_ERROR: {}", e),
                        dur,
                        Vec::new(),
                    );
                }
            }
        };

        let dur = start.elapsed().as_millis() as u64;

        let mut artifacts = Vec::new();
        // The two possible artifacts are ordered stdout, then stderr. No
        // storage reference is advertised: only their byte digests are kept.
        for reader in [stdout_reader, stderr_reader].into_iter().flatten() {
            match reader.join() {
                Ok(Ok(Some(digest))) => artifacts.push(ReceiptArtifact {
                    kind: ArtifactKind::RawOutput,
                    sha256: digest,
                    access_class: ArtifactAccessClass::PrivateRestricted,
                    storage_ref: None,
                }),
                Ok(Ok(None)) => {}
                Ok(Err(_)) | Err(_) => {
                    return (
                        ToolExecutionStatus::Error,
                        "OUTPUT_CAPTURE_FAILED".to_string(),
                        dur,
                        Vec::new(),
                    );
                }
            }
        }

        let (status, reason_code) = if exit_status.success() {
            (ToolExecutionStatus::Completed, "COMPLETED".to_string())
        } else if let Some(code) = exit_status.code() {
            (ToolExecutionStatus::Error, format!("EXIT_CODE_{}", code))
        } else {
            (
                ToolExecutionStatus::Error,
                "PROCESS_TERMINATED_BY_SIGNAL".to_string(),
            )
        };

        (status, reason_code, dur, artifacts)
    }

    fn hash_stream(mut stream: impl Read) -> std::io::Result<Option<String>> {
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 8192];
        let mut total = 0u64;
        loop {
            let n = stream.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            total += n as u64;
            hasher.update(&buffer[..n]);
        }
        if total == 0 {
            Ok(None)
        } else {
            Ok(Some(crate::identity::to_hex(hasher.finalize())))
        }
    }

    fn kill_process_group(pid: u32) {
        #[cfg(unix)]
        unsafe {
            libc::kill(-(pid as i32), libc::SIGKILL);
        }
        #[cfg(not(unix))]
        {
            let _ = Command::new("taskkill")
                .args(["/F", "/T", "/PID", &pid.to_string()])
                .output();
        }
    }

    // ---------------- Builder Helpers for Standard Tools ----------------

    fn probe_version(binary: &Path, arg: &str) -> Option<String> {
        let output = Command::new(binary).arg(arg).output().ok()?;
        if output.status.success() {
            let text = String::from_utf8_lossy(&output.stdout);
            let first_line = text.lines().next()?.trim();
            if !first_line.is_empty() {
                return Some(first_line.to_string());
            }
        }
        None
    }

    fn build_semgrep_capability(&self, binary: Option<&Path>, now: &str) -> ToolCapability {
        let (installation, engine_version, binary_sha256) = match binary {
            Some(path) => {
                let sha = Self::hash_binary(path);
                let ver = Self::probe_version(path, "--version");
                (Installation::Available, ver, sha)
            }
            None => (Installation::Missing, None, None),
        };

        ToolCapability {
            schema_version: "1.0".to_string(),
            tool_id: "semgrep-ce-adapter".to_string(),
            adapter_version: "0.1.0".to_string(),
            engine_version,
            binary_sha256,
            installation,
            capabilities: ToolCapabilityDetails {
                kinds: vec![CapabilityKind::Sast],
                languages: vec![
                    "python".to_string(),
                    "javascript".to_string(),
                    "typescript".to_string(),
                    "go".to_string(),
                    "java".to_string(),
                    "c".to_string(),
                    "cpp".to_string(),
                    "ruby".to_string(),
                    "rust".to_string(),
                    "php".to_string(),
                    "csharp".to_string(),
                ],
                asset_types: vec!["source".to_string(), "config".to_string()],
                check_ids: vec!["semgrep.rules".to_string()],
                output_formats: vec![OutputFormat::Json, OutputFormat::Sarif],
                evidence_limit: EvidenceLimit::PatternIndicator,
            },
            execution: ToolExecutionDetails {
                transport: ExecutionTransport::Cli,
                local: true,
                network_required: false,
                scoped_permission_classes: vec!["workspace:read".to_string()],
                platforms: vec![std::env::consts::OS.to_string()],
            },
            governance: ToolGovernanceDetails {
                license_review: LicenseReview::Approved,
                entitlement_verified: true,
                source_export_required: false,
                cost_model: CostModel::LocalResources,
                restrictions: vec![
                    "Semgrep CE rules only; local execution without metrics".to_string(),
                ],
            },
            verified_at: now.to_string(),
            notes: vec![
                "Semgrep Community Edition adapter with local sandbox isolation".to_string(),
            ],
        }
    }

    fn build_codeql_capability(&self, binary: Option<&Path>, now: &str) -> ToolCapability {
        let is_licensed = self.codeql_license_override.unwrap_or_else(|| {
            std::env::var("CODEQL_LICENSE_REVIEW")
                .map(|v| v.eq_ignore_ascii_case("APPROVED"))
                .unwrap_or(false)
                || std::env::var("CODEQL_ENTITLEMENT_VERIFIED")
                    .map(|v| v.eq_ignore_ascii_case("TRUE") || v == "1")
                    .unwrap_or(false)
        });

        let (installation, engine_version, binary_sha256, license_review) = match binary {
            Some(path) => {
                let sha = Self::hash_binary(path);
                let ver = Self::probe_version(path, "version");
                if is_licensed {
                    (Installation::Available, ver, sha, LicenseReview::Approved)
                } else {
                    (Installation::Unlicensed, ver, sha, LicenseReview::Pending)
                }
            }
            None => {
                if is_licensed {
                    (Installation::Missing, None, None, LicenseReview::Approved)
                } else {
                    (Installation::Unlicensed, None, None, LicenseReview::Pending)
                }
            }
        };

        ToolCapability {
            schema_version: "1.0".to_string(),
            tool_id: "codeql-adapter".to_string(),
            adapter_version: "0.1.0".to_string(),
            engine_version,
            binary_sha256,
            installation,
            capabilities: ToolCapabilityDetails {
                kinds: vec![CapabilityKind::Sast, CapabilityKind::Symbolic],
                languages: vec![
                    "javascript".to_string(),
                    "typescript".to_string(),
                    "python".to_string(),
                    "go".to_string(),
                    "java".to_string(),
                    "cpp".to_string(),
                    "csharp".to_string(),
                    "ruby".to_string(),
                    "rust".to_string(),
                ],
                asset_types: vec!["source".to_string(), "database".to_string()],
                check_ids: vec!["codeql.queries".to_string()],
                output_formats: vec![OutputFormat::Sarif],
                evidence_limit: EvidenceLimit::StronglySupported,
            },
            execution: ToolExecutionDetails {
                transport: ExecutionTransport::Cli,
                local: true,
                network_required: false,
                scoped_permission_classes: vec!["workspace:read".to_string(), "workspace:cache".to_string()],
                platforms: vec![std::env::consts::OS.to_string()],
            },
            governance: ToolGovernanceDetails {
                license_review,
                entitlement_verified: is_licensed,
                source_export_required: false,
                cost_model: CostModel::LocalResources,
                restrictions: vec![
                    "Requires GitHub Advanced Security license or open-source repository entitlement"
                        .to_string(),
                ],
            },
            verified_at: now.to_string(),
            notes: vec![
                "CodeQL semantic and interprocedural dataflow adapter (fail closed if unlicensed)".to_string(),
            ],
        }
    }

    fn build_joern_capability(&self, binary: Option<&Path>, now: &str) -> ToolCapability {
        let (installation, engine_version, binary_sha256) = match binary {
            Some(path) => {
                let sha = Self::hash_binary(path);
                let ver = Self::probe_version(path, "--version");
                (Installation::Available, ver, sha)
            }
            None => (Installation::Missing, None, None),
        };

        ToolCapability {
            schema_version: "1.0".to_string(),
            tool_id: "joern-cpg-adapter".to_string(),
            adapter_version: "0.1.0".to_string(),
            engine_version,
            binary_sha256,
            installation,
            capabilities: ToolCapabilityDetails {
                kinds: vec![CapabilityKind::Sast, CapabilityKind::Symbolic],
                languages: vec![
                    "c".to_string(),
                    "cpp".to_string(),
                    "java".to_string(),
                    "javascript".to_string(),
                    "typescript".to_string(),
                    "python".to_string(),
                    "go".to_string(),
                    "php".to_string(),
                ],
                asset_types: vec!["source".to_string(), "cpg".to_string()],
                check_ids: vec!["joern.cpg.queries".to_string()],
                output_formats: vec![OutputFormat::Json, OutputFormat::Sarif],
                evidence_limit: EvidenceLimit::StronglySupported,
            },
            execution: ToolExecutionDetails {
                transport: ExecutionTransport::Cli,
                local: true,
                network_required: false,
                scoped_permission_classes: vec!["workspace:read".to_string()],
                platforms: vec![std::env::consts::OS.to_string()],
            },
            governance: ToolGovernanceDetails {
                license_review: LicenseReview::Approved,
                entitlement_verified: true,
                source_export_required: false,
                cost_model: CostModel::LocalResources,
                restrictions: vec![
                    "Open-source Apache 2.0; isolated sidecar execution".to_string(),
                ],
            },
            verified_at: now.to_string(),
            notes: vec![
                "Joern code property graph and deep interprocedural taint adapter".to_string(),
            ],
        }
    }

    fn build_trivy_capability(&self, binary: Option<&Path>, now: &str) -> ToolCapability {
        let (installation, engine_version, binary_sha256) = match binary {
            Some(path) => {
                let sha = Self::hash_binary(path);
                let ver = Self::probe_version(path, "--version");
                (Installation::Available, ver, sha)
            }
            None => (Installation::Missing, None, None),
        };

        ToolCapability {
            schema_version: "1.0".to_string(),
            tool_id: "trivy-adapter".to_string(),
            adapter_version: "0.1.0".to_string(),
            engine_version,
            binary_sha256,
            installation,
            capabilities: ToolCapabilityDetails {
                kinds: vec![
                    CapabilityKind::Sca,
                    CapabilityKind::Sbom,
                    CapabilityKind::Secrets,
                    CapabilityKind::Iac,
                ],
                languages: vec!["all".to_string()],
                asset_types: vec![
                    "lockfile".to_string(),
                    "container".to_string(),
                    "iac".to_string(),
                    "sbom".to_string(),
                ],
                check_ids: vec!["trivy.vuln".to_string(), "trivy.misconfig".to_string()],
                output_formats: vec![OutputFormat::Json, OutputFormat::Sarif, OutputFormat::Sbom],
                evidence_limit: EvidenceLimit::Suspected,
            },
            execution: ToolExecutionDetails {
                transport: ExecutionTransport::Cli,
                local: true,
                network_required: false,
                scoped_permission_classes: vec!["workspace:read".to_string()],
                platforms: vec![std::env::consts::OS.to_string()],
            },
            governance: ToolGovernanceDetails {
                license_review: LicenseReview::Approved,
                entitlement_verified: true,
                source_export_required: false,
                cost_model: CostModel::LocalResources,
                restrictions: vec!["Apache-2.0 open-source; pinned local DB snapshot".to_string()],
            },
            verified_at: now.to_string(),
            notes: vec!["Trivy SCA, SBOM and IaC security scanner".to_string()],
        }
    }

    fn build_osv_scanner_capability(&self, binary: Option<&Path>, now: &str) -> ToolCapability {
        let (installation, engine_version, binary_sha256) = match binary {
            Some(path) => {
                let sha = Self::hash_binary(path);
                let ver = Self::probe_version(path, "--version");
                (Installation::Available, ver, sha)
            }
            None => (Installation::Missing, None, None),
        };

        ToolCapability {
            schema_version: "1.0".to_string(),
            tool_id: "osv-scanner".to_string(),
            adapter_version: "0.1.0".to_string(),
            engine_version,
            binary_sha256,
            installation,
            capabilities: ToolCapabilityDetails {
                kinds: vec![CapabilityKind::Sca, CapabilityKind::Advisory],
                languages: vec![
                    "all".to_string(),
                    "rust".to_string(),
                    "go".to_string(),
                    "javascript".to_string(),
                    "typescript".to_string(),
                    "python".to_string(),
                    "java".to_string(),
                ],
                asset_types: vec!["package-manifest".to_string(), "lockfile".to_string()],
                check_ids: vec!["OSV-VULN-CHECK".to_string()],
                output_formats: vec![OutputFormat::Json],
                evidence_limit: EvidenceLimit::StronglySupported,
            },
            execution: ToolExecutionDetails {
                transport: ExecutionTransport::Cli,
                local: true,
                network_required: true,
                scoped_permission_classes: vec![
                    "filesystem:read".to_string(),
                    "network:egress".to_string(),
                ],
                platforms: vec![std::env::consts::OS.to_string()],
            },
            governance: ToolGovernanceDetails {
                license_review: LicenseReview::Approved,
                entitlement_verified: true,
                source_export_required: false,
                cost_model: CostModel::LocalResources,
                restrictions: Vec::new(),
            },
            verified_at: now.to_string(),
            notes: vec!["Google OSV open-source vulnerability scanner".to_string()],
        }
    }

    fn build_privacy_capability(&self, now: &str) -> ToolCapability {
        ToolCapability {
            schema_version: "1.0".to_string(),
            tool_id: "privacy-engine-adapter".to_string(),
            adapter_version: "1.0.0".to_string(),
            engine_version: Some("1.0.0".to_string()),
            binary_sha256: None,
            installation: Installation::Available,
            capabilities: ToolCapabilityDetails {
                kinds: vec![
                    CapabilityKind::Sast,
                    CapabilityKind::Context,
                    CapabilityKind::Advisory,
                    CapabilityKind::Secrets,
                ],
                languages: vec![
                    "all".to_string(),
                    "python".to_string(),
                    "javascript".to_string(),
                    "typescript".to_string(),
                    "go".to_string(),
                    "rust".to_string(),
                    "php".to_string(),
                    "java".to_string(),
                    "ruby".to_string(),
                    "csharp".to_string(),
                    "yaml".to_string(),
                    "json".to_string(),
                ],
                asset_types: vec![
                    "source".to_string(),
                    "config".to_string(),
                    "dataset".to_string(),
                    "privacy_manifest".to_string(),
                    "ropa".to_string(),
                    "dpia".to_string(),
                ],
                check_ids: vec![
                    "privacy.gdpr".to_string(),
                    "privacy.ccpa".to_string(),
                    "privacy.hipaa".to_string(),
                    "privacy.eu_ai_act".to_string(),
                    "privacy.linddun".to_string(),
                    "privacy.owasp_top10".to_string(),
                    "BK-AI-PRIV-001".to_string(),
                    "BK-AI-PRIV-002".to_string(),
                    "BK-AI-PRIV-003".to_string(),
                    "BK-AI-PRIV-004".to_string(),
                    "BK-AI-PRIV-005".to_string(),
                    "BK-AI-PRIV-006".to_string(),
                    "BK-AI-PRIV-007".to_string(),
                    "BK-AI-PRIV-008".to_string(),
                    "BK-AI-PRIV-009".to_string(),
                    "BK-AI-PRIV-010".to_string(),
                ],
                output_formats: vec![OutputFormat::Json, OutputFormat::Sarif, OutputFormat::Text],
                evidence_limit: EvidenceLimit::Confirmed,
            },
            execution: ToolExecutionDetails {
                transport: ExecutionTransport::Library,
                local: true,
                network_required: false,
                scoped_permission_classes: vec!["workspace:read".to_string()],
                platforms: vec![std::env::consts::OS.to_string()],
            },
            governance: ToolGovernanceDetails {
                license_review: LicenseReview::Approved,
                entitlement_verified: true,
                source_export_required: false,
                cost_model: CostModel::LocalResources,
                restrictions: vec![
                    "Strictly defensive data protection, privacy compliance, and LINDDUN threat modeling"
                        .to_string(),
                ],
            },
            verified_at: now.to_string(),
            notes: vec![
                "Embedded 282+ procedure Privacy & Data Protection Deep Engine (GDPR, CCPA, HIPAA, EU AI Act, LINDDUN, ISO 27701)"
                    .to_string(),
            ],
        }
    }

    fn build_custom_capability(
        &self,
        tool_id: &str,
        binary: Option<&Path>,
        now: &str,
    ) -> ToolCapability {
        let (installation, engine_version, binary_sha256) = match binary {
            Some(path) => {
                let sha = Self::hash_binary(path);
                let ver = Self::probe_version(path, "--version");
                (Installation::Available, ver, sha)
            }
            None => (Installation::Missing, None, None),
        };

        ToolCapability {
            schema_version: "1.0".to_string(),
            tool_id: tool_id.to_string(),
            adapter_version: "0.1.0".to_string(),
            engine_version,
            binary_sha256,
            installation,
            capabilities: ToolCapabilityDetails {
                kinds: vec![CapabilityKind::Sast],
                languages: vec!["generic".to_string()],
                asset_types: vec!["source".to_string()],
                check_ids: vec![format!("{}.checks", tool_id)],
                output_formats: vec![OutputFormat::Json],
                evidence_limit: EvidenceLimit::Unknown,
            },
            execution: ToolExecutionDetails {
                transport: ExecutionTransport::Cli,
                local: true,
                network_required: false,
                scoped_permission_classes: vec!["workspace:read".to_string()],
                platforms: vec![std::env::consts::OS.to_string()],
            },
            governance: ToolGovernanceDetails {
                license_review: LicenseReview::Pending,
                entitlement_verified: false,
                source_export_required: false,
                cost_model: CostModel::Unknown,
                restrictions: Vec::new(),
            },
            verified_at: now.to_string(),
            notes: vec!["Generic discovered external tool".to_string()],
        }
    }

    fn build_threatswarm_capability(&self, now: &str) -> ToolCapability {
        ToolCapability {
            schema_version: "1.0".to_string(),
            tool_id: "threatswarm-deep-adapter".to_string(),
            adapter_version: "1.0.0".to_string(),
            engine_version: Some("1.0.0".to_string()),
            binary_sha256: None,
            installation: Installation::Available,
            capabilities: ToolCapabilityDetails {
                kinds: vec![
                    CapabilityKind::Context,
                    CapabilityKind::Advisory,
                    CapabilityKind::Sast,
                ],
                languages: vec![
                    "all".to_string(),
                    "rust".to_string(),
                    "go".to_string(),
                    "python".to_string(),
                    "javascript".to_string(),
                    "typescript".to_string(),
                    "php".to_string(),
                ],
                asset_types: vec![
                    "source".to_string(),
                    "config".to_string(),
                    "boundary".to_string(),
                    "network".to_string(),
                ],
                check_ids: vec![
                    "threatswarm.scope.unauthorized_egress".to_string(),
                    "threatswarm.defense.disabled_tls_validation".to_string(),
                    "threatswarm.cvss.base_score".to_string(),
                    "threatswarm.mitre.technique_map".to_string(),
                ],
                output_formats: vec![OutputFormat::Json, OutputFormat::Sarif, OutputFormat::Text],
                evidence_limit: EvidenceLimit::StronglySupported,
            },
            execution: ToolExecutionDetails {
                transport: ExecutionTransport::Library,
                local: true,
                network_required: false,
                scoped_permission_classes: vec!["workspace:read".to_string()],
                platforms: vec![std::env::consts::OS.to_string()],
            },
            governance: ToolGovernanceDetails {
                license_review: LicenseReview::Approved,
                entitlement_verified: true,
                source_export_required: false,
                cost_model: CostModel::LocalResources,
                restrictions: vec![
                    "Strictly defensive perimeter: scope boundary enforcement, MITRE ATT&CK mapping, and CVSS 3.1 base scoring"
                        .to_string(),
                ],
            },
            verified_at: now.to_string(),
            notes: vec![
                "Integrated ThreatSwarm defensive intelligence engine for autonomous boundary containment, CVSS 3.1 scoring, and MITRE enterprise mapping"
                    .to_string(),
            ],
        }
    }

    fn build_cve_mcp_capability(&self, binary_path: Option<&Path>, now: &str) -> ToolCapability {
        let server_dir = crate::deep::cve_mcp::CveMcpAdapter::discover_server_dir();
        let installed = server_dir
            .as_ref()
            .map(|p| p.join("src/cve_mcp/server.py").is_file())
            .unwrap_or(false)
            || binary_path.is_some()
            || self.find_binary("python3").is_some()
            || self.find_binary("uv").is_some();
        let installation = if installed {
            Installation::Available
        } else {
            Installation::Missing
        };

        ToolCapability {
            schema_version: "1.0".to_string(),
            tool_id: "cve-mcp-adapter".to_string(),
            adapter_version: "0.2.0".to_string(),
            engine_version: Some("0.2.0".to_string()),
            binary_sha256: None,
            installation,
            capabilities: ToolCapabilityDetails {
                kinds: vec![
                    CapabilityKind::Advisory,
                    CapabilityKind::Context,
                    CapabilityKind::Sca,
                ],
                languages: vec![
                    "all".to_string(),
                    "python".to_string(),
                    "javascript".to_string(),
                    "typescript".to_string(),
                    "go".to_string(),
                    "rust".to_string(),
                    "php".to_string(),
                    "c".to_string(),
                    "cpp".to_string(),
                ],
                asset_types: vec![
                    "source".to_string(),
                    "binary".to_string(),
                    "container".to_string(),
                    "advisory".to_string(),
                    "cve".to_string(),
                ],
                check_ids: vec![
                    "cve.lookup".to_string(),
                    "cve.triage".to_string(),
                    "cve.epss".to_string(),
                    "cve.kev".to_string(),
                    "cve.cvss".to_string(),
                    "cve.risk_score".to_string(),
                ],
                output_formats: vec![OutputFormat::Json, OutputFormat::Sarif, OutputFormat::Text],
                evidence_limit: EvidenceLimit::StronglySupported,
            },
            execution: ToolExecutionDetails {
                transport: ExecutionTransport::Mcp,
                local: true,
                network_required: false,
                scoped_permission_classes: vec!["workspace:read".to_string()],
                platforms: vec![std::env::consts::OS.to_string()],
            },
            governance: ToolGovernanceDetails {
                license_review: LicenseReview::Approved,
                entitlement_verified: true,
                source_export_required: false,
                cost_model: CostModel::LocalResources,
                restrictions: vec![
                    "Strictly defensive CVE intelligence triage, CISA KEV validation, and EPSS correlation"
                        .to_string(),
                ],
            },
            verified_at: now.to_string(),
            notes: vec![
                "CVE MCP server integration providing deterministic risk scoring (0-100), CISA KEV priority override, and EPSS probabilities"
                    .to_string(),
            ],
        }
    }
}
