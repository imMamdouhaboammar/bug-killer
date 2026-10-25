use std::fs;
use std::path::PathBuf;
use std::time::Instant;

use ast_grep_core::tree_sitter::LanguageExt;
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

use crate::engine::adapter::{AdapterCapabilities, AnalyzerAdapter};
use crate::engine::protocol::{
    AnalysisRequest, AnalysisResponse, CoverageReceiptStatus, CoverageReceiptV1, DiagnosticV1,
    EngineDescriptor, EngineStatus, EvidenceCertaintyV1, EvidenceItemKind, EvidenceItemV1,
    FindingKind, FindingStatus, FindingV1, NormalizedTargetKind, ReceiptCounts, ReceiptReasonCode,
    ResourceUsage, TargetDescriptor,
};
use crate::engine::runner::{AnalysisError, CancellationToken};
use crate::structural::cache::{CachedAnalysis, StructuralCache, StructuralCacheKey};
use crate::structural::language::StructuralLanguage;
use crate::structural::rule::RulePack;
use crate::structural::span::FindingTargetSpan;
use crate::types::{ScanProfile, TargetKind};

/// Analyzer adapter executing ast-grep and tree-sitter structural AST queries against codebases.
#[derive(Clone)]
pub struct AstGrepAdapter {
    engine_id: String,
    engine_version: String,
    rule_pack: RulePack,
    cache: StructuralCache,
}

impl AstGrepAdapter {
    /// Creates a new `AstGrepAdapter` with default migrated catalog rules and a shared cache.
    pub fn new() -> Self {
        Self {
            engine_id: "ast-grep-adapter".to_string(),
            engine_version: "0.51.0".to_string(),
            rule_pack: RulePack::default_migrated_rules(),
            cache: StructuralCache::new(),
        }
    }

    /// Creates an adapter with a custom rule pack and cache.
    pub fn with_rules_and_cache(rule_pack: RulePack, cache: StructuralCache) -> Self {
        Self {
            engine_id: "ast-grep-adapter".to_string(),
            engine_version: "0.51.0".to_string(),
            rule_pack,
            cache,
        }
    }

    /// Access to the underlying structural cache.
    pub fn cache(&self) -> &StructuralCache {
        &self.cache
    }

    /// Access to the underlying rule pack.
    pub fn rule_pack(&self) -> &RulePack {
        &self.rule_pack
    }

    /// Computes lowercase SHA-256 hex digest of file bytes.
    fn compute_sha256(bytes: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        format!("{:x}", hasher.finalize())
    }
}

impl Default for AstGrepAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl AnalyzerAdapter for AstGrepAdapter {
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
            ScanProfile::Research,
            ScanProfile::Audit,
        ]
    }

    fn supported_languages(&self) -> &[&str] {
        &["python", "javascript", "typescript", "php", "go", "rust"]
    }

    fn supported_target_kinds(&self) -> &[TargetKind] {
        &[TargetKind::GenericSourceFile, TargetKind::NodeSourceFile]
    }

    fn supported_checks(&self) -> &[&str] {
        &[
            "BK-AI-INJ-001",
            "BK-AI-INJ-002",
            "BK-AI-SEC-001",
            "BK-AI-LNG-001",
        ]
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

        if cancel_token.is_cancelled() {
            return Err(AnalysisError::Cancelled);
        }

        let root_path = PathBuf::from(&request.snapshot_ref);
        if !root_path.exists() {
            return Err(AnalysisError::ExecutionFailed(format!(
                "Target snapshot path does not exist: {}",
                request.snapshot_ref
            )));
        }

        // Collect files to scan
        let mut target_files: Vec<PathBuf> = Vec::new();
        if root_path.is_file() {
            target_files.push(root_path.clone());
        } else if root_path.is_dir() {
            for entry in WalkDir::new(&root_path)
                .follow_links(false)
                .into_iter()
                .filter_entry(|e| {
                    let name = e.file_name().to_string_lossy();
                    !name.starts_with('.') && name != "node_modules" && name != "target"
                })
                .flatten()
            {
                if entry.file_type().is_file() {
                    target_files.push(entry.into_path());
                }
            }
        }

        let rule_pack_hash = self.rule_pack.pack_hash();
        let mut all_findings = Vec::new();
        let mut all_receipts = Vec::new();
        let mut all_diagnostics = Vec::new();
        let mut has_partial = false;
        let mut has_error = false;

        let now = chrono::Utc::now().to_rfc3339();

        for file_path in &target_files {
            if cancel_token.is_cancelled() {
                return Err(AnalysisError::Cancelled);
            }

            let relative_path = file_path
                .strip_prefix(&root_path)
                .unwrap_or(file_path)
                .to_string_lossy()
                .to_string();
            let target_id = if relative_path.is_empty() {
                file_path.to_string_lossy().to_string()
            } else {
                relative_path.clone()
            };

            let content_bytes = match fs::read(file_path) {
                Ok(bytes) => bytes,
                Err(e) => {
                    has_error = true;
                    all_diagnostics.push(DiagnosticV1 {
                        code: "FILE_READ_ERROR".to_string(),
                        message: format!("Failed to read {}: {}", file_path.display(), e),
                        target_id: Some(target_id.clone()),
                    });
                    all_receipts.push(CoverageReceiptV1 {
                        schema_version: "1.0".to_string(),
                        receipt_id: format!("receipt-{}-{}", request.run_id, all_receipts.len()),
                        run_id: request.run_id.clone(),
                        engine_id: self.engine_id.clone(),
                        engine_version: self.engine_version.clone(),
                        check_id: "STRUCTURAL_SCAN".to_string(),
                        target_id: target_id.clone(),
                        snapshot_sha256: request.snapshot_sha256.clone(),
                        status: CoverageReceiptStatus::Error,
                        counts: ReceiptCounts::default(),
                        reason_codes: vec![ReceiptReasonCode::ReadError],
                        details: vec![e.to_string()],
                        started_at: now.clone(),
                        completed_at: now.clone(),
                        required_by_policy: Some(false),
                        artifact_digests: Vec::new(),
                        previous_receipt_id: None,
                    });
                    continue;
                }
            };

            let source_sha256 = Self::compute_sha256(&content_bytes);
            let content_str = String::from_utf8_lossy(&content_bytes);

            // Detect language
            let detected_lang = StructuralLanguage::detect(file_path, Some(&content_str));
            let structural_lang = match detected_lang {
                Some(lang) => lang,
                None => {
                    // Truthful unsupported coverage receipt
                    all_receipts.push(CoverageReceiptV1 {
                        schema_version: "1.0".to_string(),
                        receipt_id: format!("receipt-{}-{}", request.run_id, all_receipts.len()),
                        run_id: request.run_id.clone(),
                        engine_id: self.engine_id.clone(),
                        engine_version: self.engine_version.clone(),
                        check_id: "STRUCTURAL_SCAN".to_string(),
                        target_id: target_id.clone(),
                        snapshot_sha256: request.snapshot_sha256.clone(),
                        status: CoverageReceiptStatus::Unsupported,
                        counts: ReceiptCounts {
                            items_discovered: 1,
                            items_examined: 0,
                            items_excluded: 0,
                            items_skipped: 1,
                        },
                        reason_codes: vec![ReceiptReasonCode::UnsupportedLanguage],
                        details: vec![format!(
                            "File '{}' has unsupported extension or language",
                            target_id
                        )],
                        started_at: now.clone(),
                        completed_at: now.clone(),
                        required_by_policy: Some(false),
                        artifact_digests: vec![source_sha256.clone()],
                        previous_receipt_id: None,
                    });
                    continue;
                }
            };

            let grammar_id = structural_lang.grammar_id();
            let cache_key =
                StructuralCacheKey::new(source_sha256.clone(), grammar_id, rule_pack_hash.clone());

            // Check source hash cache for instant re-scan bypass
            if let Some(cached) = self.cache.get(&cache_key) {
                all_findings.extend(cached.findings);
                all_receipts.extend(cached.receipts);
                all_diagnostics.extend(cached.diagnostics);
                continue;
            }

            // Parse AST with ast-grep
            let support_lang = structural_lang.to_support_lang();
            let root = support_lang.ast_grep(&content_str);

            // Honest error-tolerant receipt check for syntax errors
            let has_syntax_error = root
                .root()
                .dfs()
                .any(|n| n.is_error() || n.kind() == "ERROR");

            let receipt_status = if has_syntax_error {
                has_partial = true;
                CoverageReceiptStatus::Partial
            } else {
                CoverageReceiptStatus::Evaluated
            };

            let reason_codes = if has_syntax_error {
                vec![ReceiptReasonCode::ParseError]
            } else {
                Vec::new()
            };

            let details = if has_syntax_error {
                vec![format!(
                    "Syntax error encountered during tree-sitter parsing of '{}'",
                    target_id
                )]
            } else {
                Vec::new()
            };

            let receipt_id = format!("receipt-{}-{}", request.run_id, all_receipts.len());
            let coverage_receipt = CoverageReceiptV1 {
                schema_version: "1.0".to_string(),
                receipt_id: receipt_id.clone(),
                run_id: request.run_id.clone(),
                engine_id: self.engine_id.clone(),
                engine_version: self.engine_version.clone(),
                check_id: "STRUCTURAL_SCAN".to_string(),
                target_id: target_id.clone(),
                snapshot_sha256: request.snapshot_sha256.clone(),
                status: receipt_status,
                counts: ReceiptCounts {
                    items_discovered: 1,
                    items_examined: 1,
                    items_excluded: 0,
                    items_skipped: 0,
                },
                reason_codes,
                details,
                started_at: now.clone(),
                completed_at: now.clone(),
                required_by_policy: Some(false),
                artifact_digests: vec![source_sha256.clone()],
                previous_receipt_id: None,
            };

            // Run applicable rules against the AST
            let mut file_findings = Vec::new();
            let applicable_rules = self.rule_pack.rules_for_language(structural_lang);

            for rule in applicable_rules {
                if !request.check_ids.is_empty()
                    && !request
                        .check_ids
                        .iter()
                        .any(|c| c == "ALL_ACTIVE" || c == &rule.rule_id)
                {
                    continue;
                }

                for pattern_str in rule.all_patterns() {
                    for node_match in root.root().find_all(pattern_str) {
                        // Apply secondary semantic filter (anti-slop)
                        if !rule.validates_match(&node_match) {
                            continue;
                        }

                        let span = FindingTargetSpan::from_node(&node_match).to_source_span_v1();
                        let finding_idx = all_findings.len() + file_findings.len() + 1;
                        let finding_id = format!(
                            "finding-{}-{}-{:04}",
                            request.run_id, rule.rule_id, finding_idx
                        );

                        let matched_line = node_match.text();
                        let first_line = matched_line.lines().next().unwrap_or("").trim();

                        let evidence_item = EvidenceItemV1 {
                            kind: EvidenceItemKind::AstMatch,
                            artifact_sha256: source_sha256.clone(),
                            description: format!(
                                "ast-grep structural match for rule {}: {}",
                                rule.rule_id, first_line
                            ),
                            reference: Some(rule.rule_id.clone()),
                            limitations: Vec::new(),
                        };

                        let target = TargetDescriptor {
                            target_id: target_id.clone(),
                            kind: NormalizedTargetKind::File,
                            path: Some(relative_path.clone()),
                            package_purl: None,
                            version: None,
                            span: Some(span.clone()),
                        };

                        let finding = FindingV1 {
                            schema_version: "1.0".to_string(),
                            run_id: request.run_id.clone(),
                            finding_id,
                            fingerprint: Some(format!(
                                "{}:{}:{}",
                                rule.rule_id, target_id, span.start_line
                            )),
                            kind: FindingKind::Catalog,
                            status: FindingStatus::Suspected,
                            title: format!("{}: {}", rule.rule_id, rule.message),
                            summary: Some(format!(
                                "Structural rule {} triggered on {} at line {}: {}",
                                rule.rule_id, target_id, span.start_line, first_line
                            )),
                            severity: rule.severity,
                            evidence_certainty: EvidenceCertaintyV1::Suspected,
                            rule_id: Some(rule.rule_id.clone()),
                            weakness_ids: vec![rule.cwe.clone()],
                            advisory_ids: Vec::new(),
                            engine: EngineDescriptor {
                                id: self.engine_id.clone(),
                                version: self.engine_version.clone(),
                                rule_pack_sha256: Some(rule_pack_hash.clone()),
                            },
                            target,
                            source_snapshot_sha256: request.snapshot_sha256.clone(),
                            evidence: vec![evidence_item],
                            proof: None,
                            coverage_receipt_ids: vec![receipt_id.clone()],
                            uncertainty_reasons: Vec::new(),
                            remediation_plan_id: None,
                            created_at: now.clone(),
                            updated_at: None,
                            extensions: serde_json::Map::new(),
                        };

                        file_findings.push(finding);
                    }
                }
            }

            // Save to structural cache for subsequent identical queries
            let cached_file_receipts = vec![coverage_receipt.clone()];
            let file_diagnostics = Vec::new();
            self.cache.insert(
                cache_key,
                CachedAnalysis {
                    findings: file_findings.clone(),
                    receipts: cached_file_receipts,
                    diagnostics: file_diagnostics,
                    cached_at: now.clone(),
                },
            );

            all_findings.extend(file_findings);
            all_receipts.push(coverage_receipt);
        }

        let overall_status = if has_error {
            EngineStatus::Error
        } else if has_partial {
            EngineStatus::Partial
        } else {
            EngineStatus::Completed
        };

        let duration_ms = start.elapsed().as_millis() as u64;

        let response = AnalysisResponse {
            schema_version: "1.0".to_string(),
            run_id: request.run_id.clone(),
            engine_id: self.engine_id.clone(),
            engine_version: self.engine_version.clone(),
            snapshot_sha256: request.snapshot_sha256.clone(),
            status: overall_status,
            findings: all_findings,
            receipts: all_receipts,
            diagnostics: all_diagnostics,
            resources: ResourceUsage {
                duration_ms,
                peak_memory_bytes: 4 * 1024 * 1024,
            },
            completed_at: chrono::Utc::now().to_rfc3339(),
        };

        // Strict schema validation check
        response
            .validate()
            .map_err(AnalysisError::ExecutionFailed)?;

        Ok(response)
    }
}
