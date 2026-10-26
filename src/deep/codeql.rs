use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use chrono::Utc;
use sha2::{Digest, Sha256};

use crate::deep::broker::{
    Installation, InstallationState, LicenseReview, REASON_ENGINE_MISSING,
    REASON_UNLICENSED_ENVIRONMENT, ToolCapabilityBroker,
};
use crate::engine::adapter::{AdapterCapabilities, AnalyzerAdapter};
use crate::engine::protocol::{
    AnalysisRequest, AnalysisResponse, CoverageReceiptStatus, CoverageReceiptV1, DiagnosticV1,
    EngineDescriptor, EngineStatus, EvidenceCertaintyV1, EvidenceItemKind, EvidenceItemV1,
    FindingKind, FindingStatus, FindingV1, NormalizedSeverity, NormalizedTargetKind, ReceiptCounts,
    ReceiptReasonCode, ResourceUsage, SourceSpanV1, TargetDescriptor,
};
use crate::engine::runner::{AnalysisError, CancellationToken};
use crate::types::{ScanProfile, TargetKind};

/// Explicit licensing and entitlement configuration for CodeQL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeQlLicenseConfig {
    /// Whether an explicit commercial license (e.g. GitHub Advanced Security) or verified authorization exists.
    pub entitlement_verified: bool,
    /// License review governance state.
    pub license_review: LicenseReview,
    /// Whether the target is an open source repository eligible under CodeQL free terms.
    pub is_open_source_eligible: bool,
}

impl Default for CodeQlLicenseConfig {
    fn default() -> Self {
        Self {
            entitlement_verified: false,
            license_review: LicenseReview::Pending,
            is_open_source_eligible: false,
        }
    }
}

impl CodeQlLicenseConfig {
    /// Creates a configuration asserting an approved commercial license.
    pub fn approved_commercial() -> Self {
        Self {
            entitlement_verified: true,
            license_review: LicenseReview::Approved,
            is_open_source_eligible: false,
        }
    }

    /// Creates a configuration asserting open source entitlement eligibility.
    pub fn open_source_eligible() -> Self {
        Self {
            entitlement_verified: true,
            license_review: LicenseReview::Approved,
            is_open_source_eligible: true,
        }
    }

    /// Creates a configuration asserting an unlicensed or rejected state.
    pub fn unlicensed() -> Self {
        Self {
            entitlement_verified: false,
            license_review: LicenseReview::Rejected,
            is_open_source_eligible: false,
        }
    }

    /// Checks if the environment is legally eligible to execute CodeQL.
    pub fn is_eligible(&self) -> bool {
        self.entitlement_verified
            || self.license_review == LicenseReview::Approved
            || self.is_open_source_eligible
    }
}

/// Analyzer adapter for CodeQL semantic and interprocedural dataflow analysis.
/// Strictly enforces license verification and fails closed if unlicensed.
#[derive(Debug, Clone)]
pub struct CodeQlAdapter {
    engine_id: String,
    engine_version: String,
    binary_path: Option<PathBuf>,
    license_config: CodeQlLicenseConfig,
}

impl Default for CodeQlAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl CodeQlAdapter {
    /// Creates a new `CodeQlAdapter` with default (unverified/pending) license configuration.
    pub fn new() -> Self {
        let broker = ToolCapabilityBroker::new();
        let binary_path = broker.find_binary("codeql");
        Self {
            engine_id: "codeql-adapter".to_string(),
            engine_version: "0.1.0".to_string(),
            binary_path,
            license_config: CodeQlLicenseConfig::default(),
        }
    }

    /// Configures the adapter with an explicit binary path.
    pub fn with_binary_path(mut self, path: impl Into<PathBuf>) -> Self {
        let p = path.into();
        self.binary_path = if p.is_file() { Some(p) } else { None };
        self
    }

    /// Configures the adapter with explicit license review and entitlement parameters.
    pub fn with_license(mut self, license_config: CodeQlLicenseConfig) -> Self {
        self.license_config = license_config;
        self
    }

    /// Checks if the CodeQL binary exists on host.
    pub fn is_installed(&self) -> bool {
        self.binary_path
            .as_ref()
            .map(|p| p.is_file())
            .unwrap_or(false)
    }

    /// Checks if the environment is authorized and verified to run CodeQL.
    pub fn is_licensed(&self) -> bool {
        if self.license_config.is_eligible() {
            return true;
        }

        // Check environment variables as secondary mechanism
        if let Ok(review) = std::env::var("CODEQL_LICENSE_REVIEW") {
            if review.eq_ignore_ascii_case("APPROVED") {
                return true;
            }
        }
        if let Ok(entitled) = std::env::var("CODEQL_ENTITLEMENT_VERIFIED") {
            if entitled.eq_ignore_ascii_case("TRUE") || entitled == "1" {
                return true;
            }
        }

        false
    }

    /// Returns the host installation state for CodeQL (Available, Missing, or Unlicensed).
    pub fn installation_state(&self) -> InstallationState {
        if !self.is_installed() {
            Installation::Missing
        } else if !self.is_licensed() {
            Installation::Unlicensed
        } else {
            Installation::Available
        }
    }

    /// Extracts a valid CWE ID formatted strictly as `^CWE-[0-9]+$`.
    pub fn normalize_cwe_id(raw: &str) -> Option<String> {
        let upper = raw.to_ascii_uppercase();
        if let Some(pos) = upper.find("CWE-") {
            let after = &upper[pos + 4..];
            let digits: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
            if !digits.is_empty() {
                return Some(format!("CWE-{}", digits));
            }
        } else if raw.chars().all(|c| c.is_ascii_digit()) && !raw.is_empty() {
            return Some(format!("CWE-{}", raw));
        }
        None
    }

    fn map_severity(raw: &str) -> NormalizedSeverity {
        match raw.to_ascii_uppercase().as_str() {
            "ERROR" | "CRITICAL" => NormalizedSeverity::High,
            "WARNING" | "MEDIUM" => NormalizedSeverity::Medium,
            "INFO" | "LOW" | "NOTE" | "RECOMMENDATION" => NormalizedSeverity::Low,
            _ => NormalizedSeverity::Unknown,
        }
    }

    /// Parses CodeQL SARIF v2.1.0 output into normalized `FindingV1` and `CoverageReceiptV1`.
    pub fn parse_sarif(
        sarif_str: &str,
        request: &AnalysisRequest,
    ) -> Result<(Vec<FindingV1>, Vec<CoverageReceiptV1>), String> {
        let v: serde_json::Value = serde_json::from_str(sarif_str)
            .map_err(|e| format!("Failed to parse CodeQL SARIF JSON: {}", e))?;

        let mut findings = Vec::new();
        let mut receipts = Vec::new();
        let now = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

        if let Some(runs) = v.get("runs").and_then(|r| r.as_array()) {
            for (run_idx, run) in runs.iter().enumerate() {
                // Collect rule CWE tags from driver rules
                let mut rule_cwes: std::collections::HashMap<String, Vec<String>> =
                    std::collections::HashMap::new();
                if let Some(rules) = run.pointer("/tool/driver/rules").and_then(|r| r.as_array()) {
                    for r in rules {
                        if let Some(id) = r.get("id").and_then(|i| i.as_str()) {
                            let mut cwes = Vec::new();
                            if let Some(tags) =
                                r.pointer("/properties/tags").and_then(|t| t.as_array())
                            {
                                for tag in tags {
                                    if let Some(s) = tag.as_str() {
                                        if let Some(norm) = Self::normalize_cwe_id(s) {
                                            cwes.push(norm);
                                        }
                                    }
                                }
                            }
                            rule_cwes.insert(id.to_string(), cwes);
                        }
                    }
                }

                if let Some(results) = run.get("results").and_then(|r| r.as_array()) {
                    for (res_idx, res) in results.iter().enumerate() {
                        let rule_id = res
                            .get("ruleId")
                            .and_then(|r| r.as_str())
                            .unwrap_or("codeql.query");

                        let level = res.get("level").and_then(|l| l.as_str()).unwrap_or("error");
                        let severity = Self::map_severity(level);

                        let message = res
                            .pointer("/message/text")
                            .and_then(|m| m.as_str())
                            .unwrap_or("CodeQL security query match");

                        let mut file_path = "unknown".to_string();
                        let mut start_line = 1u32;
                        let mut end_line = 1u32;
                        let mut start_col = None;
                        let mut end_col = None;

                        if let Some(locs) = res.get("locations").and_then(|l| l.as_array()) {
                            if let Some(loc) = locs.first() {
                                if let Some(uri) = loc
                                    .pointer("/physicalLocation/artifactLocation/uri")
                                    .and_then(|u| u.as_str())
                                {
                                    file_path = uri.to_string();
                                }
                                if let Some(region) = loc.pointer("/physicalLocation/region") {
                                    if let Some(sl) =
                                        region.get("startLine").and_then(|l| l.as_u64())
                                    {
                                        start_line = sl as u32;
                                    }
                                    if let Some(el) = region.get("endLine").and_then(|l| l.as_u64())
                                    {
                                        end_line = el as u32;
                                    } else {
                                        end_line = start_line;
                                    }
                                    if let Some(sc) =
                                        region.get("startColumn").and_then(|c| c.as_u64())
                                    {
                                        start_col = Some(sc as u32);
                                    }
                                    if let Some(ec) =
                                        region.get("endColumn").and_then(|c| c.as_u64())
                                    {
                                        end_col = Some(ec as u32);
                                    }
                                }
                            }
                        }

                        // Parse CodeQL dataflow paths if present in codeFlows
                        let mut dataflow_steps = Vec::new();
                        if let Some(cfs) = res.get("codeFlows").and_then(|c| c.as_array()) {
                            for cf in cfs {
                                if let Some(tfs) = cf.get("threadFlows").and_then(|t| t.as_array())
                                {
                                    for tf in tfs {
                                        if let Some(locations) =
                                            tf.get("locations").and_then(|l| l.as_array())
                                        {
                                            for loc in locations {
                                                if let Some(loc_inner) = loc.get("location") {
                                                    if let Some(uri) = loc_inner
                                                        .pointer("/physicalLocation/artifactLocation/uri")
                                                        .and_then(|u| u.as_str())
                                                    {
                                                        let line = loc_inner
                                                            .pointer("/physicalLocation/region/startLine")
                                                            .and_then(|l| l.as_u64())
                                                            .unwrap_or(0);
                                                        dataflow_steps.push(format!("{}:{}", uri, line));
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        let mut weakness_ids = rule_cwes.get(rule_id).cloned().unwrap_or_default();
                        if weakness_ids.is_empty() {
                            if let Some(norm) = Self::normalize_cwe_id(message) {
                                weakness_ids.push(norm);
                            }
                        }
                        weakness_ids.dedup();

                        let receipt_id = format!(
                            "codeql-receipt-{}-{}-{}",
                            &request.snapshot_sha256[..8],
                            run_idx,
                            res_idx
                        );

                        let finding_id = {
                            let mut h = Sha256::new();
                            h.update(request.run_id.as_bytes());
                            h.update(rule_id.as_bytes());
                            h.update(file_path.as_bytes());
                            h.update(start_line.to_be_bytes());
                            crate::to_hex(h.finalize())
                        };

                        let title = if message.len() > 200 {
                            format!("{}: {}", rule_id, &message[..190])
                        } else {
                            format!("{}: {}", rule_id, message)
                        };

                        let mut evidence = vec![EvidenceItemV1 {
                            kind: EvidenceItemKind::SourceSpan,
                            artifact_sha256: request.snapshot_sha256.clone(),
                            description: format!(
                                "CodeQL rule '{}' matched at {}:{}",
                                rule_id, file_path, start_line
                            ),
                            reference: Some(format!("{}:{}", file_path, start_line)),
                            limitations: Vec::new(),
                        }];

                        if !dataflow_steps.is_empty() {
                            evidence.push(EvidenceItemV1 {
                                kind: EvidenceItemKind::DataflowTrace,
                                artifact_sha256: request.snapshot_sha256.clone(),
                                description: format!(
                                    "CodeQL interprocedural taint flow ({} steps): {}",
                                    dataflow_steps.len(),
                                    dataflow_steps.join(" -> ")
                                ),
                                reference: Some(dataflow_steps[0].clone()),
                                limitations: Vec::new(),
                            });
                        }

                        let finding = FindingV1 {
                            schema_version: "1.0".to_string(),
                            run_id: request.run_id.clone(),
                            finding_id: finding_id.clone(),
                            fingerprint: Some(finding_id),
                            kind: FindingKind::Catalog,
                            status: FindingStatus::Suspected,
                            title,
                            summary: Some(message.to_string()),
                            severity,
                            evidence_certainty: EvidenceCertaintyV1::StronglySupported,
                            rule_id: Some(rule_id.to_string()),
                            weakness_ids,
                            advisory_ids: Vec::new(),
                            engine: EngineDescriptor {
                                id: "codeql-adapter".to_string(),
                                version: "0.1.0".to_string(),
                                rule_pack_sha256: None,
                            },
                            target: TargetDescriptor {
                                target_id: file_path.clone(),
                                kind: NormalizedTargetKind::File,
                                path: Some(file_path.clone()),
                                package_purl: None,
                                version: None,
                                span: Some(SourceSpanV1 {
                                    start_line,
                                    end_line,
                                    start_column: start_col,
                                    end_column: end_col,
                                }),
                            },
                            source_snapshot_sha256: request.snapshot_sha256.clone(),
                            evidence,
                            proof: None,
                            coverage_receipt_ids: vec![receipt_id.clone()],
                            uncertainty_reasons: Vec::new(),
                            remediation_plan_id: None,
                            created_at: now.clone(),
                            updated_at: None,
                            extensions: serde_json::Map::new(),
                        };

                        let receipt = CoverageReceiptV1 {
                            schema_version: "1.0".to_string(),
                            receipt_id,
                            run_id: request.run_id.clone(),
                            engine_id: "codeql-adapter".to_string(),
                            engine_version: "0.1.0".to_string(),
                            check_id: rule_id.to_string(),
                            target_id: file_path,
                            snapshot_sha256: request.snapshot_sha256.clone(),
                            status: CoverageReceiptStatus::Evaluated,
                            counts: ReceiptCounts {
                                items_discovered: 1,
                                items_examined: 1,
                                items_excluded: 0,
                                items_skipped: 0,
                            },
                            reason_codes: Vec::new(),
                            details: Vec::new(),
                            started_at: now.clone(),
                            completed_at: now.clone(),
                            required_by_policy: Some(false),
                            artifact_digests: Vec::new(),
                            previous_receipt_id: None,
                        };

                        findings.push(finding);
                        receipts.push(receipt);
                    }
                }
            }
        }

        if receipts.is_empty() {
            receipts.push(CoverageReceiptV1 {
                schema_version: "1.0".to_string(),
                receipt_id: format!("codeql-receipt-clean-{}", &request.snapshot_sha256[..8]),
                run_id: request.run_id.clone(),
                engine_id: "codeql-adapter".to_string(),
                engine_version: "0.1.0".to_string(),
                check_id: request
                    .check_ids
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "ALL".to_string()),
                target_id: request
                    .target_ids
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "ALL".to_string()),
                snapshot_sha256: request.snapshot_sha256.clone(),
                status: CoverageReceiptStatus::Evaluated,
                counts: ReceiptCounts {
                    items_discovered: 1,
                    items_examined: 1,
                    items_excluded: 0,
                    items_skipped: 0,
                },
                reason_codes: Vec::new(),
                details: Vec::new(),
                started_at: now.clone(),
                completed_at: now,
                required_by_policy: Some(false),
                artifact_digests: Vec::new(),
                previous_receipt_id: None,
            });
        }

        Ok((findings, receipts))
    }
}

impl AnalyzerAdapter for CodeQlAdapter {
    fn engine_id(&self) -> &str {
        &self.engine_id
    }

    fn engine_version(&self) -> &str {
        &self.engine_version
    }

    fn supported_profiles(&self) -> &[ScanProfile] {
        &[ScanProfile::Deep, ScanProfile::Research, ScanProfile::Ci]
    }

    fn supported_languages(&self) -> &[&str] {
        &[
            "javascript",
            "typescript",
            "python",
            "go",
            "java",
            "cpp",
            "csharp",
            "ruby",
            "rust",
        ]
    }

    fn supported_target_kinds(&self) -> &[TargetKind] {
        &[TargetKind::GenericSourceFile, TargetKind::GenericConfigFile]
    }

    fn capabilities(&self) -> AdapterCapabilities {
        AdapterCapabilities {
            requires_network: false,
            requires_mutation: false,
            is_isolated: true,
            supports_cancellation: true,
        }
    }

    fn analyze(
        &self,
        request: &AnalysisRequest,
        cancel_token: &CancellationToken,
    ) -> Result<AnalysisResponse, AnalysisError> {
        let start = Instant::now();
        let now = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

        // 1. Missing engine check
        if !self.is_installed() {
            let receipt_id = format!(
                "codeql-receipt-missing-{}",
                &request.snapshot_sha256[..8.min(request.snapshot_sha256.len())]
            );

            let receipt = CoverageReceiptV1 {
                schema_version: "1.0".to_string(),
                receipt_id,
                run_id: request.run_id.clone(),
                engine_id: self.engine_id().to_string(),
                engine_version: self.engine_version().to_string(),
                check_id: request
                    .check_ids
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "ALL".to_string()),
                target_id: request
                    .target_ids
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "ALL".to_string()),
                snapshot_sha256: request.snapshot_sha256.clone(),
                status: CoverageReceiptStatus::NotRun,
                counts: ReceiptCounts::default(),
                reason_codes: vec![ReceiptReasonCode::EngineMissing],
                details: vec!["CodeQL binary not found in PATH or configured path".to_string()],
                started_at: now.clone(),
                completed_at: now.clone(),
                required_by_policy: Some(false),
                artifact_digests: Vec::new(),
                previous_receipt_id: None,
            };

            let diagnostic = DiagnosticV1 {
                code: REASON_ENGINE_MISSING.to_string(),
                message: "CodeQL binary is missing on host; scan not run".to_string(),
                target_id: None,
            };

            return Ok(AnalysisResponse {
                schema_version: "1.0".to_string(),
                run_id: request.run_id.clone(),
                engine_id: self.engine_id().to_string(),
                engine_version: self.engine_version().to_string(),
                snapshot_sha256: request.snapshot_sha256.clone(),
                status: EngineStatus::Blocked,
                findings: Vec::new(),
                receipts: vec![receipt],
                diagnostics: vec![diagnostic],
                resources: ResourceUsage {
                    duration_ms: start.elapsed().as_millis() as u64,
                    peak_memory_bytes: 0,
                },
                completed_at: now,
            });
        }

        // 2. Strict license / entitlement check (FAIL CLOSED IF UNLICENSED)
        if !self.is_licensed() {
            let receipt_id = format!(
                "codeql-receipt-unlicensed-{}",
                &request.snapshot_sha256[..8.min(request.snapshot_sha256.len())]
            );

            let receipt = CoverageReceiptV1 {
                schema_version: "1.0".to_string(),
                receipt_id,
                run_id: request.run_id.clone(),
                engine_id: self.engine_id().to_string(),
                engine_version: self.engine_version().to_string(),
                check_id: request
                    .check_ids
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "ALL".to_string()),
                target_id: request
                    .target_ids
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "ALL".to_string()),
                snapshot_sha256: request.snapshot_sha256.clone(),
                status: CoverageReceiptStatus::NotRun,
                counts: ReceiptCounts::default(),
                reason_codes: vec![ReceiptReasonCode::AuthBlocked],
                details: vec![format!(
                    "CodeQL execution blocked: unlicensed environment or unverified open-source entitlement (reason_code: {})",
                    REASON_UNLICENSED_ENVIRONMENT
                )],
                started_at: now.clone(),
                completed_at: now.clone(),
                required_by_policy: Some(false),
                artifact_digests: Vec::new(),
                previous_receipt_id: None,
            };

            let diagnostic = DiagnosticV1 {
                code: REASON_UNLICENSED_ENVIRONMENT.to_string(),
                message: "CodeQL requires verified license entitlement or approved open-source status; execution blocked".to_string(),
                target_id: None,
            };

            return Ok(AnalysisResponse {
                schema_version: "1.0".to_string(),
                run_id: request.run_id.clone(),
                engine_id: self.engine_id().to_string(),
                engine_version: self.engine_version().to_string(),
                snapshot_sha256: request.snapshot_sha256.clone(),
                status: EngineStatus::Blocked,
                findings: Vec::new(),
                receipts: vec![receipt],
                diagnostics: vec![diagnostic],
                resources: ResourceUsage {
                    duration_ms: start.elapsed().as_millis() as u64,
                    peak_memory_bytes: 0,
                },
                completed_at: now,
            });
        }

        if cancel_token.is_cancelled() {
            return Err(AnalysisError::Cancelled);
        }

        // Licensed execution: invoke codeql CLI
        let binary = self.binary_path.as_ref().unwrap();
        let target_path = Path::new(&request.snapshot_ref);

        let mut cmd = Command::new(binary);
        cmd.arg("database")
            .arg("analyze")
            .arg("--format=sarif-latest")
            .arg(target_path);

        let output = cmd.output().map_err(|e| {
            AnalysisError::ExecutionFailed(format!("Failed to execute codeql binary: {}", e))
        })?;

        if cancel_token.is_cancelled() {
            return Err(AnalysisError::Cancelled);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let (findings, receipts) = Self::parse_sarif(&stdout, request).map_err(|e| {
            AnalysisError::MalformedOutput(format!("Failed to parse CodeQL SARIF: {}", e))
        })?;

        let duration_ms = start.elapsed().as_millis() as u64;
        let completed_at = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

        Ok(AnalysisResponse {
            schema_version: "1.0".to_string(),
            run_id: request.run_id.clone(),
            engine_id: self.engine_id().to_string(),
            engine_version: self.engine_version().to_string(),
            snapshot_sha256: request.snapshot_sha256.clone(),
            status: EngineStatus::Completed,
            findings,
            receipts,
            diagnostics: Vec::new(),
            resources: ResourceUsage {
                duration_ms,
                peak_memory_bytes: 0,
            },
            completed_at,
        })
    }
}
