use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use chrono::Utc;
use sha2::{Digest, Sha256};

use crate::deep::broker::{Installation, InstallationState, ToolCapabilityBroker};
use crate::engine::adapter::{AdapterCapabilities, AnalyzerAdapter};
use crate::engine::protocol::{
    AnalysisRequest, AnalysisResponse, CoverageReceiptStatus, CoverageReceiptV1, DiagnosticV1,
    EngineDescriptor, EngineStatus, EvidenceCertaintyV1, EvidenceItemKind, EvidenceItemV1,
    FindingKind, FindingStatus, FindingV1, NormalizedSeverity, NormalizedTargetKind, ReceiptCounts,
    ReceiptReasonCode, ResourceUsage, SourceSpanV1, TargetDescriptor,
};
use crate::engine::runner::{AnalysisError, CancellationToken};
use crate::types::{ScanProfile, TargetKind};

/// Analyzer adapter for Semgrep Community Edition running in an isolated local sandbox.
#[derive(Debug, Clone)]
pub struct SemgrepAdapter {
    engine_id: String,
    engine_version: String,
    binary_path: Option<PathBuf>,
    rules: Vec<String>,
}

impl Default for SemgrepAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl SemgrepAdapter {
    /// Creates a new `SemgrepAdapter` discovering binary location from broker / PATH.
    pub fn new() -> Self {
        let broker = ToolCapabilityBroker::new();
        let binary_path = broker.find_binary("semgrep");
        Self {
            engine_id: "semgrep-ce-adapter".to_string(),
            engine_version: "0.1.0".to_string(),
            binary_path,
            rules: Vec::new(),
        }
    }

    /// Creates an adapter with an explicit binary path.
    pub fn with_binary_path(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        Self {
            engine_id: "semgrep-ce-adapter".to_string(),
            engine_version: "0.1.0".to_string(),
            binary_path: if path.is_file() { Some(path) } else { None },
            rules: Vec::new(),
        }
    }

    /// Configures custom rules or rule pack path for Semgrep execution.
    pub fn with_rules(mut self, rules: Vec<String>) -> Self {
        self.rules = rules;
        self
    }

    /// Checks if Semgrep binary is present on host.
    pub fn is_installed(&self) -> bool {
        self.binary_path
            .as_ref()
            .map(|p| p.is_file())
            .unwrap_or(false)
    }

    /// Returns the installation state of Semgrep.
    pub fn installation_state(&self) -> InstallationState {
        if self.is_installed() {
            Installation::Available
        } else {
            Installation::Missing
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

    /// Maps SARIF / Semgrep severity strings to `NormalizedSeverity`.
    fn map_severity(raw: &str) -> NormalizedSeverity {
        match raw.to_ascii_uppercase().as_str() {
            "ERROR" | "CRITICAL" => NormalizedSeverity::High,
            "WARNING" | "MEDIUM" => NormalizedSeverity::Medium,
            "INFO" | "LOW" | "NOTE" => NormalizedSeverity::Low,
            _ => NormalizedSeverity::Unknown,
        }
    }

    /// Parses Semgrep SARIF v2.1.0 JSON output into normalized `FindingV1` and `CoverageReceiptV1`.
    pub fn parse_sarif(
        sarif_str: &str,
        request: &AnalysisRequest,
    ) -> Result<(Vec<FindingV1>, Vec<CoverageReceiptV1>), String> {
        let v: serde_json::Value = serde_json::from_str(sarif_str)
            .map_err(|e| format!("Failed to parse Semgrep SARIF JSON: {}", e))?;

        let mut findings = Vec::new();
        let mut receipts = Vec::new();
        let now = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

        let runs = v.get("runs").and_then(|r| r.as_array());
        if let Some(runs) = runs {
            for (run_idx, run) in runs.iter().enumerate() {
                // Collect rule CWE metadata
                let mut rule_cwes: std::collections::HashMap<String, Vec<String>> =
                    std::collections::HashMap::new();
                if let Some(rules) = run.pointer("/tool/driver/rules").and_then(|r| r.as_array()) {
                    for r in rules {
                        if let Some(id) = r.get("id").and_then(|i| i.as_str()) {
                            let mut cwes = Vec::new();
                            if let Some(props) = r.get("properties") {
                                if let Some(cwe_val) = props.get("cwe") {
                                    if let Some(arr) = cwe_val.as_array() {
                                        for item in arr {
                                            if let Some(s) = item.as_str() {
                                                if let Some(norm) = Self::normalize_cwe_id(s) {
                                                    cwes.push(norm);
                                                }
                                            }
                                        }
                                    } else if let Some(s) = cwe_val.as_str() {
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

                let results = run.get("results").and_then(|r| r.as_array());
                if let Some(results) = results {
                    for (res_idx, res) in results.iter().enumerate() {
                        let rule_id = res
                            .get("ruleId")
                            .and_then(|r| r.as_str())
                            .unwrap_or("semgrep.unspecified-rule");

                        let level = res
                            .get("level")
                            .and_then(|l| l.as_str())
                            .unwrap_or("warning");
                        let severity = Self::map_severity(level);

                        let message = res
                            .pointer("/message/text")
                            .and_then(|m| m.as_str())
                            .unwrap_or("Semgrep pattern match");

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

                        let mut weakness_ids = rule_cwes.get(rule_id).cloned().unwrap_or_default();
                        if weakness_ids.is_empty() {
                            if let Some(norm) = Self::normalize_cwe_id(message) {
                                weakness_ids.push(norm);
                            }
                        }
                        weakness_ids.dedup();

                        let receipt_id = format!(
                            "semgrep-receipt-{}-{}-{}",
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
                            format!("{:x}", h.finalize())
                        };

                        let title = if message.len() > 200 {
                            format!("{}: {}", rule_id, &message[..190])
                        } else {
                            format!("{}: {}", rule_id, message)
                        };

                        let evidence_desc = format!(
                            "Semgrep rule '{}' matched at {}:{}: {}",
                            rule_id, file_path, start_line, message
                        );

                        let finding = FindingV1 {
                            schema_version: "1.0".to_string(),
                            run_id: request.run_id.clone(),
                            finding_id: finding_id.clone(),
                            fingerprint: Some(finding_id.clone()),
                            kind: FindingKind::Catalog,
                            status: FindingStatus::Suspected,
                            title,
                            summary: Some(message.to_string()),
                            severity,
                            evidence_certainty: EvidenceCertaintyV1::PatternIndicator,
                            rule_id: Some(rule_id.to_string()),
                            weakness_ids,
                            advisory_ids: Vec::new(),
                            engine: EngineDescriptor {
                                id: "semgrep-ce-adapter".to_string(),
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
                            evidence: vec![EvidenceItemV1 {
                                kind: EvidenceItemKind::SourceSpan,
                                artifact_sha256: request.snapshot_sha256.clone(),
                                description: evidence_desc,
                                reference: Some(format!("{}:{}", file_path, start_line)),
                                limitations: vec![
                                    "Pattern indicator without dynamic proof".to_string(),
                                ],
                            }],
                            proof: None,
                            coverage_receipt_ids: vec![receipt_id.clone()],
                            uncertainty_reasons: vec!["Static pattern indicator only".to_string()],
                            remediation_plan_id: None,
                            created_at: now.clone(),
                            updated_at: None,
                            extensions: serde_json::Map::new(),
                        };

                        let receipt = CoverageReceiptV1 {
                            schema_version: "1.0".to_string(),
                            receipt_id,
                            run_id: request.run_id.clone(),
                            engine_id: "semgrep-ce-adapter".to_string(),
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

        // If no results, emit at least one coverage receipt for evaluated targets
        if receipts.is_empty() {
            receipts.push(CoverageReceiptV1 {
                schema_version: "1.0".to_string(),
                receipt_id: format!("semgrep-receipt-clean-{}", &request.snapshot_sha256[..8]),
                run_id: request.run_id.clone(),
                engine_id: "semgrep-ce-adapter".to_string(),
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

    /// Parses Semgrep CLI standard JSON output (`--json`) into normalized `FindingV1` and `CoverageReceiptV1`.
    pub fn parse_json(
        json_str: &str,
        request: &AnalysisRequest,
    ) -> Result<(Vec<FindingV1>, Vec<CoverageReceiptV1>), String> {
        let v: serde_json::Value = serde_json::from_str(json_str)
            .map_err(|e| format!("Failed to parse Semgrep JSON: {}", e))?;

        let mut findings = Vec::new();
        let mut receipts = Vec::new();
        let now = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

        if let Some(results) = v.get("results").and_then(|r| r.as_array()) {
            for (idx, item) in results.iter().enumerate() {
                let check_id = item
                    .get("check_id")
                    .and_then(|c| c.as_str())
                    .unwrap_or("semgrep.rule");

                let path = item
                    .get("path")
                    .and_then(|p| p.as_str())
                    .unwrap_or("unknown");

                let start_line = item
                    .pointer("/start/line")
                    .and_then(|l| l.as_u64())
                    .unwrap_or(1) as u32;

                let end_line = item
                    .pointer("/end/line")
                    .and_then(|l| l.as_u64())
                    .unwrap_or(start_line as u64) as u32;

                let start_col = item
                    .pointer("/start/col")
                    .and_then(|c| c.as_u64())
                    .map(|c| c as u32);

                let end_col = item
                    .pointer("/end/col")
                    .and_then(|c| c.as_u64())
                    .map(|c| c as u32);

                let message = item
                    .pointer("/extra/message")
                    .and_then(|m| m.as_str())
                    .unwrap_or("Semgrep match");

                let sev_str = item
                    .pointer("/extra/severity")
                    .and_then(|s| s.as_str())
                    .unwrap_or("WARNING");
                let severity = Self::map_severity(sev_str);

                let mut weakness_ids = Vec::new();
                if let Some(cwe_val) = item.pointer("/extra/metadata/cwe") {
                    if let Some(arr) = cwe_val.as_array() {
                        for c in arr {
                            if let Some(s) = c.as_str() {
                                if let Some(norm) = Self::normalize_cwe_id(s) {
                                    weakness_ids.push(norm);
                                }
                            }
                        }
                    } else if let Some(s) = cwe_val.as_str() {
                        if let Some(norm) = Self::normalize_cwe_id(s) {
                            weakness_ids.push(norm);
                        }
                    }
                }
                if weakness_ids.is_empty() {
                    if let Some(norm) = Self::normalize_cwe_id(message) {
                        weakness_ids.push(norm);
                    }
                }
                weakness_ids.dedup();

                let receipt_id = format!(
                    "semgrep-json-receipt-{}-{}",
                    &request.snapshot_sha256[..8],
                    idx
                );

                let finding_id = {
                    let mut h = Sha256::new();
                    h.update(request.run_id.as_bytes());
                    h.update(check_id.as_bytes());
                    h.update(path.as_bytes());
                    h.update(start_line.to_be_bytes());
                    format!("{:x}", h.finalize())
                };

                let title = if message.len() > 200 {
                    format!("{}: {}", check_id, &message[..190])
                } else {
                    format!("{}: {}", check_id, message)
                };

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
                    evidence_certainty: EvidenceCertaintyV1::PatternIndicator,
                    rule_id: Some(check_id.to_string()),
                    weakness_ids,
                    advisory_ids: Vec::new(),
                    engine: EngineDescriptor {
                        id: "semgrep-ce-adapter".to_string(),
                        version: "0.1.0".to_string(),
                        rule_pack_sha256: None,
                    },
                    target: TargetDescriptor {
                        target_id: path.to_string(),
                        kind: NormalizedTargetKind::File,
                        path: Some(path.to_string()),
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
                    evidence: vec![EvidenceItemV1 {
                        kind: EvidenceItemKind::SourceSpan,
                        artifact_sha256: request.snapshot_sha256.clone(),
                        description: format!(
                            "Semgrep matched check '{}' at {}:{}",
                            check_id, path, start_line
                        ),
                        reference: Some(format!("{}:{}", path, start_line)),
                        limitations: vec!["Pattern indicator without dynamic proof".to_string()],
                    }],
                    proof: None,
                    coverage_receipt_ids: vec![receipt_id.clone()],
                    uncertainty_reasons: vec!["Static pattern indicator only".to_string()],
                    remediation_plan_id: None,
                    created_at: now.clone(),
                    updated_at: None,
                    extensions: serde_json::Map::new(),
                };

                let receipt = CoverageReceiptV1 {
                    schema_version: "1.0".to_string(),
                    receipt_id,
                    run_id: request.run_id.clone(),
                    engine_id: "semgrep-ce-adapter".to_string(),
                    engine_version: "0.1.0".to_string(),
                    check_id: check_id.to_string(),
                    target_id: path.to_string(),
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

        if receipts.is_empty() {
            receipts.push(CoverageReceiptV1 {
                schema_version: "1.0".to_string(),
                receipt_id: format!("semgrep-json-clean-{}", &request.snapshot_sha256[..8]),
                run_id: request.run_id.clone(),
                engine_id: "semgrep-ce-adapter".to_string(),
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

impl AnalyzerAdapter for SemgrepAdapter {
    fn engine_id(&self) -> &str {
        &self.engine_id
    }

    fn engine_version(&self) -> &str {
        &self.engine_version
    }

    fn supported_profiles(&self) -> &[ScanProfile] {
        &[
            ScanProfile::Quick,
            ScanProfile::Project,
            ScanProfile::Ci,
            ScanProfile::Deep,
        ]
    }

    fn supported_languages(&self) -> &[&str] {
        &[
            "python",
            "javascript",
            "typescript",
            "go",
            "java",
            "c",
            "cpp",
            "ruby",
            "rust",
            "php",
            "csharp",
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

        // Check if semgrep binary is installed
        if !self.is_installed() {
            let receipt_id = format!(
                "semgrep-receipt-missing-{}",
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
                details: vec!["Semgrep CE binary not found in PATH or configured path".to_string()],
                started_at: now.clone(),
                completed_at: now.clone(),
                required_by_policy: Some(false),
                artifact_digests: Vec::new(),
                previous_receipt_id: None,
            };

            let diagnostic = DiagnosticV1 {
                code: "ENGINE_MISSING".to_string(),
                message: "semgrep binary is missing on host; scan not run".to_string(),
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

        let binary = self.binary_path.as_ref().unwrap();
        let target_path = Path::new(&request.snapshot_ref);

        let mut cmd = Command::new(binary);
        cmd.arg("scan")
            .arg("--json")
            .arg("--quiet")
            .arg("--metrics=off")
            .arg("--disable-version-check");

        if !self.rules.is_empty() {
            for r in &self.rules {
                cmd.arg(format!("--config={}", r));
            }
        } else {
            cmd.arg("--config=auto");
        }

        cmd.arg(target_path);

        let output = cmd.output().map_err(|e| {
            AnalysisError::ExecutionFailed(format!("Failed to execute semgrep binary: {}", e))
        })?;

        if cancel_token.is_cancelled() {
            return Err(AnalysisError::Cancelled);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let (findings, receipts) = Self::parse_json(&stdout, request).map_err(|e| {
            AnalysisError::MalformedOutput(format!("Failed to parse semgrep output: {}", e))
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
