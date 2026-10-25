use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use bug_killer::engine::*;
use bug_killer::types::{
    Affectedness, Confidence, CoverageReceipt, CoverageStatus, CveId, EvidenceCertainty,
    EvidenceRef, ExploitabilitySignal, Finding, OperatorStatus, Reachability, ScanProfile,
    Severity, TargetKind,
};

const DUMMY_HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

// =========================================================================
// Synthetic Adapter Implementations for Testing
// =========================================================================

/// Synthetic adapter that always succeeds and returns a valid AnalysisResponse.
struct SyntheticSuccessfulAdapter;

impl AnalyzerAdapter for SyntheticSuccessfulAdapter {
    fn engine_id(&self) -> &str {
        "synthetic-success"
    }

    fn engine_version(&self) -> &str {
        "1.0.0"
    }

    fn supported_profiles(&self) -> &[ScanProfile] {
        &[
            ScanProfile::Quick,
            ScanProfile::Project,
            ScanProfile::Ci,
            ScanProfile::Deep,
            ScanProfile::Research,
        ]
    }

    fn supported_languages(&self) -> &[&str] {
        &["rust", "javascript", "python"]
    }

    fn supported_target_kinds(&self) -> &[TargetKind] {
        &[TargetKind::GenericSourceFile]
    }

    fn analyze(
        &self,
        request: &AnalysisRequest,
        _cancel_token: &CancellationToken,
    ) -> Result<AnalysisResponse, AnalysisError> {
        let finding = FindingV1 {
            schema_version: "1.0".to_string(),
            run_id: request.run_id.clone(),
            finding_id: "synthetic-finding-1".to_string(),
            fingerprint: Some("fingerprint-1234".to_string()),
            kind: FindingKind::Catalog,
            status: FindingStatus::Verified,
            title: "Synthetic Verified Issue".to_string(),
            summary: Some("Detailed summary of synthetic issue".to_string()),
            severity: NormalizedSeverity::High,
            evidence_certainty: EvidenceCertaintyV1::Confirmed,
            rule_id: Some("SYNTH-001".to_string()),
            weakness_ids: vec!["CWE-79".to_string()],
            advisory_ids: vec!["SYNTH-ADV-1".to_string()],
            engine: EngineDescriptor {
                id: self.engine_id().to_string(),
                version: self.engine_version().to_string(),
                rule_pack_sha256: None,
            },
            target: TargetDescriptor {
                target_id: "target-file-1".to_string(),
                kind: NormalizedTargetKind::File,
                path: Some("src/main.rs".to_string()),
                package_purl: None,
                version: None,
                span: Some(SourceSpanV1 {
                    start_line: 10,
                    end_line: 20,
                    start_column: Some(1),
                    end_column: Some(80),
                }),
            },
            source_snapshot_sha256: request.snapshot_sha256.clone(),
            evidence: vec![EvidenceItemV1 {
                kind: EvidenceItemKind::SourceSpan,
                artifact_sha256: request.snapshot_sha256.clone(),
                description: "Vulnerable span observed".to_string(),
                reference: Some("src/main.rs:10".to_string()),
                limitations: Vec::new(),
            }],
            proof: Some(ProofV1 {
                method: ProofMethod::StaticInvariant,
                artifact_sha256: request.snapshot_sha256.clone(),
                reproduced_on_snapshot: request.snapshot_sha256.clone(),
                limitations: Vec::new(),
            }),
            coverage_receipt_ids: vec!["receipt-success-1".to_string()],
            uncertainty_reasons: Vec::new(),
            remediation_plan_id: None,
            created_at: "2026-10-25T12:00:00Z".to_string(),
            updated_at: None,
            extensions: serde_json::Map::new(),
        };

        let receipt = CoverageReceiptV1 {
            schema_version: "1.0".to_string(),
            receipt_id: "receipt-success-1".to_string(),
            run_id: request.run_id.clone(),
            engine_id: self.engine_id().to_string(),
            engine_version: self.engine_version().to_string(),
            check_id: "SYNTH-001".to_string(),
            target_id: "target-file-1".to_string(),
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
            started_at: "2026-10-25T12:00:00Z".to_string(),
            completed_at: "2026-10-25T12:00:01Z".to_string(),
            required_by_policy: Some(true),
            artifact_digests: vec![request.snapshot_sha256.clone()],
            previous_receipt_id: None,
        };

        Ok(AnalysisResponse {
            schema_version: "1.0".to_string(),
            run_id: request.run_id.clone(),
            engine_id: self.engine_id().to_string(),
            engine_version: self.engine_version().to_string(),
            snapshot_sha256: request.snapshot_sha256.clone(),
            status: EngineStatus::Completed,
            findings: vec![finding],
            receipts: vec![receipt],
            diagnostics: Vec::new(),
            resources: ResourceUsage {
                duration_ms: 50,
                peak_memory_bytes: 1024 * 1024,
            },
            completed_at: "2026-10-25T12:00:01Z".to_string(),
        })
    }
}

/// Synthetic adapter that deliberately sleeps to test timeout enforcement.
struct SleepyAdapter {
    sleep_duration: Duration,
}

impl AnalyzerAdapter for SleepyAdapter {
    fn engine_id(&self) -> &str {
        "sleepy-adapter"
    }

    fn engine_version(&self) -> &str {
        "1.0.0"
    }

    fn supported_profiles(&self) -> &[ScanProfile] {
        &[
            ScanProfile::Quick,
            ScanProfile::Project,
            ScanProfile::Ci,
            ScanProfile::Deep,
            ScanProfile::Research,
        ]
    }

    fn supported_languages(&self) -> &[&str] {
        &["generic"]
    }

    fn supported_target_kinds(&self) -> &[TargetKind] {
        &[TargetKind::GenericSourceFile]
    }

    fn analyze(
        &self,
        _request: &AnalysisRequest,
        cancel_token: &CancellationToken,
    ) -> Result<AnalysisResponse, AnalysisError> {
        let step = Duration::from_millis(20);
        let mut elapsed = Duration::ZERO;
        while elapsed < self.sleep_duration {
            if cancel_token.is_cancelled() {
                return Err(AnalysisError::Cancelled);
            }
            std::thread::sleep(step);
            elapsed += step;
        }

        Err(AnalysisError::ExecutionFailed(
            "Should have timed out".to_string(),
        ))
    }
}

/// Adapter that requires network access.
struct NetworkRequiringAdapter;

impl AnalyzerAdapter for NetworkRequiringAdapter {
    fn engine_id(&self) -> &str {
        "osv-remote-adapter"
    }

    fn engine_version(&self) -> &str {
        "1.0.0"
    }

    fn supported_profiles(&self) -> &[ScanProfile] {
        &[ScanProfile::Project, ScanProfile::Ci, ScanProfile::Deep]
    }

    fn supported_languages(&self) -> &[&str] {
        &["rust", "javascript"]
    }

    fn supported_target_kinds(&self) -> &[TargetKind] {
        &[TargetKind::CargoLockManifest, TargetKind::NodeLockfile]
    }

    fn capabilities(&self) -> AdapterCapabilities {
        AdapterCapabilities {
            requires_network: true,
            requires_mutation: false,
            is_isolated: true,
            supports_cancellation: true,
        }
    }

    fn analyze(
        &self,
        request: &AnalysisRequest,
        _cancel_token: &CancellationToken,
    ) -> Result<AnalysisResponse, AnalysisError> {
        Ok(AnalysisResponse {
            schema_version: "1.0".to_string(),
            run_id: request.run_id.clone(),
            engine_id: self.engine_id().to_string(),
            engine_version: self.engine_version().to_string(),
            snapshot_sha256: request.snapshot_sha256.clone(),
            status: EngineStatus::Completed,
            findings: Vec::new(),
            receipts: Vec::new(),
            diagnostics: Vec::new(),
            resources: ResourceUsage::default(),
            completed_at: "2026-10-25T12:00:00Z".to_string(),
        })
    }
}

/// Adapter restricted strictly to Python.
struct PythonOnlyAdapter;

impl AnalyzerAdapter for PythonOnlyAdapter {
    fn engine_id(&self) -> &str {
        "python-linter"
    }

    fn engine_version(&self) -> &str {
        "1.0.0"
    }

    fn supported_profiles(&self) -> &[ScanProfile] {
        &[ScanProfile::Quick, ScanProfile::Project]
    }

    fn supported_languages(&self) -> &[&str] {
        &["python"]
    }

    fn supported_target_kinds(&self) -> &[TargetKind] {
        &[TargetKind::GenericSourceFile]
    }

    fn analyze(
        &self,
        request: &AnalysisRequest,
        _cancel_token: &CancellationToken,
    ) -> Result<AnalysisResponse, AnalysisError> {
        for target in &request.target_ids {
            if target.ends_with(".cob") || target.ends_with(".cbl") || target.contains("cobol") {
                return Err(AnalysisError::UnsupportedLanguage("cobol".to_string()));
            }
        }

        Ok(AnalysisResponse {
            schema_version: "1.0".to_string(),
            run_id: request.run_id.clone(),
            engine_id: self.engine_id().to_string(),
            engine_version: self.engine_version().to_string(),
            snapshot_sha256: request.snapshot_sha256.clone(),
            status: EngineStatus::Completed,
            findings: Vec::new(),
            receipts: Vec::new(),
            diagnostics: Vec::new(),
            resources: ResourceUsage::default(),
            completed_at: "2026-10-25T12:00:00Z".to_string(),
        })
    }
}

// =========================================================================
// Tests
// =========================================================================

#[test]
fn test_1_synthetic_successful_engine_run_produces_schema_compliant_response() {
    let mut registry = EngineRegistry::new();
    registry.register(Arc::new(SyntheticSuccessfulAdapter));

    let request = AnalysisRequest::new(
        "run-test-001",
        "synthetic-success",
        "workspace-snapshot-01",
        DUMMY_HASH,
        ScanProfile::Quick,
        vec!["SYNTH-001".to_string()],
        vec!["src/main.rs".to_string()],
    );

    let cancel_token = CancellationToken::new();
    let response = registry
        .dispatch(&request, &cancel_token)
        .expect("dispatch should succeed");

    // 1. Invariants validation
    assert_eq!(response.schema_version, "1.0");
    assert_eq!(response.run_id, "run-test-001");
    assert_eq!(response.engine_id, "synthetic-success");
    assert_eq!(response.engine_version, "1.0.0");
    assert_eq!(response.snapshot_sha256, DUMMY_HASH);
    assert_eq!(response.status, EngineStatus::Completed);
    assert_eq!(response.findings.len(), 1);
    assert_eq!(response.receipts.len(), 1);

    // Validate internal consistency
    response
        .validate()
        .expect("Response must pass internal schema validation");

    // 2. Validate against raw schema definitions from bug-killer-ultimate-spec-v1
    let json_str = serde_json::to_string_pretty(&response).expect("serialization must succeed");
    let val: serde_json::Value = serde_json::from_str(&json_str).expect("must parse back to json");

    // Check required properties from analysis-response.schema.json
    let required_fields = [
        "schema_version",
        "run_id",
        "engine_id",
        "engine_version",
        "snapshot_sha256",
        "status",
        "findings",
        "receipts",
        "diagnostics",
        "resources",
        "completed_at",
    ];
    for field in &required_fields {
        assert!(
            val.get(*field).is_some(),
            "Field '{}' must be present in serialized JSON",
            field
        );
    }

    // Verify finding required fields
    let finding_val = &val["findings"][0];
    let finding_required = [
        "schema_version",
        "run_id",
        "finding_id",
        "kind",
        "status",
        "title",
        "severity",
        "evidence_certainty",
        "engine",
        "target",
        "source_snapshot_sha256",
        "evidence",
        "coverage_receipt_ids",
        "created_at",
    ];
    for field in &finding_required {
        assert!(
            finding_val.get(*field).is_some(),
            "Finding field '{}' must be present",
            field
        );
    }

    // Verify coverage receipt required fields
    let receipt_val = &val["receipts"][0];
    let receipt_required = [
        "schema_version",
        "receipt_id",
        "run_id",
        "engine_id",
        "engine_version",
        "check_id",
        "target_id",
        "snapshot_sha256",
        "status",
        "counts",
        "started_at",
        "completed_at",
    ];
    for field in &receipt_required {
        assert!(
            receipt_val.get(*field).is_some(),
            "Receipt field '{}' must be present",
            field
        );
    }
}

#[test]
fn test_2_timeout_enforcement_adapter_exceeding_budget_aborted() {
    let mut registry = EngineRegistry::new();
    registry.register(Arc::new(SleepyAdapter {
        sleep_duration: Duration::from_secs(5),
    }));

    let mut request = AnalysisRequest::new(
        "run-timeout-002",
        "sleepy-adapter",
        "workspace-snapshot-02",
        DUMMY_HASH,
        ScanProfile::Quick,
        vec!["CHECK-1".to_string()],
        vec!["src/lib.rs".to_string()],
    );
    // Enforce 1-second budget
    request.budgets.timeout_seconds = 1;

    let cancel_token = CancellationToken::new();
    let start = std::time::Instant::now();

    // 1. Strict runner returns typed AnalysisError::Timeout
    let result = registry.dispatch(&request, &cancel_token);
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_secs(3),
        "Runner should abort close to 1 second, took {:?}",
        elapsed
    );
    match result {
        Err(AnalysisError::Timeout(secs)) => {
            assert_eq!(secs, 1);
        }
        other => panic!("Expected AnalysisError::Timeout(1), got {:?}", other),
    }

    // 2. Resilient runner returns schema-compliant EngineStatus::Partial
    let partial_resp = registry
        .dispatch_resilient(&request, &cancel_token)
        .expect("dispatch_resilient should convert timeout into partial response");

    assert_eq!(partial_resp.status, EngineStatus::Partial);
    assert_eq!(partial_resp.receipts.len(), 1);
    assert_eq!(
        partial_resp.receipts[0].status,
        CoverageReceiptStatus::Partial
    );
    assert_eq!(
        partial_resp.receipts[0].reason_codes,
        vec![ReceiptReasonCode::Timeout]
    );
    partial_resp
        .validate()
        .expect("Partial response must strictly validate");
}

#[test]
fn test_3_malformed_json_output_caught_and_returned_as_typed_error() {
    // 3a. Invalid JSON syntax
    let corrupted_raw = "{ broken_json: true, ";
    let parsed: Result<AnalysisResponse, serde_json::Error> = serde_json::from_str(corrupted_raw);
    assert!(parsed.is_err());
    let err = AnalysisError::MalformedOutput(parsed.unwrap_err().to_string());
    assert!(matches!(err, AnalysisError::MalformedOutput(_)));

    // 3b. JSON missing mandatory schema property (e.g. missing `status`)
    let missing_field_raw = serde_json::json!({
        "schema_version": "1.0",
        "run_id": "run-broken-01",
        "engine_id": "broken-engine",
        "engine_version": "1.0.0",
        "snapshot_sha256": DUMMY_HASH,
        // "status" omitted intentionally
        "findings": [],
        "receipts": [],
        "diagnostics": [],
        "resources": { "duration_ms": 0, "peak_memory_bytes": 0 },
        "completed_at": "2026-10-25T12:00:00Z"
    });
    let parse_res: Result<AnalysisResponse, _> = serde_json::from_value(missing_field_raw);
    assert!(
        parse_res.is_err(),
        "Must reject JSON missing required field 'status'"
    );

    // 3c. Output limit exceeded is caught
    let big_desc = "X".repeat(2048);
    let resp = AnalysisResponse {
        schema_version: "1.0".to_string(),
        run_id: "run-big-01".to_string(),
        engine_id: "test-engine".to_string(),
        engine_version: "1.0.0".to_string(),
        snapshot_sha256: DUMMY_HASH.to_string(),
        status: EngineStatus::Completed,
        findings: Vec::new(),
        receipts: Vec::new(),
        diagnostics: vec![DiagnosticV1 {
            code: "BIG".to_string(),
            message: big_desc,
            target_id: None,
        }],
        resources: ResourceUsage::default(),
        completed_at: "2026-10-25T12:00:00Z".to_string(),
    };
    resp.validate().expect("Valid schema");

    let bytes = serde_json::to_vec(&resp).unwrap();
    let max_bytes = 1024;
    assert!(bytes.len() as u64 > max_bytes);
    let output_err = AnalysisError::OutputLimitExceeded {
        actual_bytes: bytes.len(),
        max_bytes,
    };
    assert!(matches!(
        output_err,
        AnalysisError::OutputLimitExceeded { .. }
    ));
}

#[test]
fn test_4_unsupported_language_handled_with_typed_error_and_honest_receipt() {
    let mut registry = EngineRegistry::new();
    registry.register(Arc::new(PythonOnlyAdapter));

    let request = AnalysisRequest::new(
        "run-cobol-004",
        "python-linter",
        "workspace-snapshot-04",
        DUMMY_HASH,
        ScanProfile::Quick,
        vec!["PY-001".to_string()],
        vec!["legacy_core.cbl".to_string()],
    );

    let cancel_token = CancellationToken::new();
    let err = registry.dispatch(&request, &cancel_token).unwrap_err();

    match err {
        AnalysisError::UnsupportedLanguage(ref lang) => {
            assert_eq!(lang, "cobol");
            // Produce honest partial response with receipt
            let partial = err.to_partial_response(&request, "python-linter", "1.0.0");
            assert_eq!(partial.status, EngineStatus::Partial);
            assert_eq!(partial.receipts.len(), 1);
            assert_eq!(
                partial.receipts[0].status,
                CoverageReceiptStatus::Unsupported
            );
            assert_eq!(
                partial.receipts[0].reason_codes,
                vec![ReceiptReasonCode::UnsupportedLanguage]
            );
            partial
                .validate()
                .expect("Honest receipt must validate cleanly");
        }
        other => panic!("Expected UnsupportedLanguage, got {:?}", other),
    }
}

#[test]
fn test_5_cancellation_token_terminates_execution_immediately() {
    let mut registry = EngineRegistry::new();
    registry.register(Arc::new(SleepyAdapter {
        sleep_duration: Duration::from_secs(10),
    }));

    let request = AnalysisRequest::new(
        "run-cancel-005",
        "sleepy-adapter",
        "workspace-snapshot-05",
        DUMMY_HASH,
        ScanProfile::Quick,
        vec!["CHECK-1".to_string()],
        vec!["src/main.rs".to_string()],
    );

    // Case 5a: Pre-cancelled token terminates without doing any work
    let pre_cancelled = CancellationToken::new();
    pre_cancelled.cancel();
    assert!(pre_cancelled.is_cancelled());

    let err = registry.dispatch(&request, &pre_cancelled).unwrap_err();
    assert_eq!(err, AnalysisError::Cancelled);

    // Case 5b: Token cancelled mid-execution aborts promptly
    let dynamic_token = CancellationToken::new();
    let token_clone = dynamic_token.clone();

    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(60));
        token_clone.cancel();
    });

    let start = std::time::Instant::now();
    let mid_err = registry.dispatch(&request, &dynamic_token).unwrap_err();
    let elapsed = start.elapsed();

    assert_eq!(mid_err, AnalysisError::Cancelled);
    assert!(
        elapsed < Duration::from_millis(500),
        "Cancelled task should abort swiftly, took {:?}",
        elapsed
    );

    // Verify cancelled response adheres to schema
    let cancel_resp = mid_err.to_partial_response(&request, "sleepy-adapter", "1.0.0");
    assert_eq!(cancel_resp.status, EngineStatus::Cancelled);
    assert_eq!(
        cancel_resp.receipts[0].status,
        CoverageReceiptStatus::NotRun
    );
    assert_eq!(
        cancel_resp.receipts[0].reason_codes,
        vec![ReceiptReasonCode::Cancelled]
    );
    cancel_resp
        .validate()
        .expect("Cancelled response must validate");
}

#[test]
fn test_6_permissions_enforcement_network_blocked_unless_explicitly_allowed() {
    let mut registry = EngineRegistry::new();
    registry.register(Arc::new(NetworkRequiringAdapter));

    // 6a. Attempt dispatch when allow_network is false
    let mut blocked_request = AnalysisRequest::new(
        "run-perm-006",
        "osv-remote-adapter",
        "workspace-snapshot-06",
        DUMMY_HASH,
        ScanProfile::Project,
        vec!["OSV-SCA-01".to_string()],
        vec!["Cargo.lock".to_string()],
    );
    blocked_request.permissions.allow_network = false;

    let cancel_token = CancellationToken::new();
    let err = registry
        .dispatch(&blocked_request, &cancel_token)
        .unwrap_err();

    match err {
        AnalysisError::PermissionDenied(msg) => {
            assert!(msg.contains("requires network access"));
        }
        other => panic!("Expected PermissionDenied, got {:?}", other),
    }

    // Resilient dispatch marks status as Blocked
    let blocked_resp = registry
        .dispatch_resilient(&blocked_request, &cancel_token)
        .expect("dispatch_resilient converts permission error into blocked response");
    assert_eq!(blocked_resp.status, EngineStatus::Blocked);
    assert_eq!(
        blocked_resp.receipts[0].reason_codes,
        vec![ReceiptReasonCode::AuthBlocked]
    );

    // 6b. Allow network -> dispatch succeeds
    let mut allowed_request = blocked_request.clone();
    allowed_request.permissions.allow_network = true;

    let allowed_resp = registry
        .dispatch(&allowed_request, &cancel_token)
        .expect("Allowed network request must succeed");
    assert_eq!(allowed_resp.status, EngineStatus::Completed);
}

#[test]
fn test_7_roundtrip_conversion_to_and_from_legacy_types_preserves_all_fields() {
    // 7a. Comprehensive Finding roundtrip
    let mut legacy_finding = Finding::new(
        "F-2026-ROUNDTRIP-01",
        CveId::Php2ShellOom("CVE-2026-109618".to_string()),
        Severity::Critical,
        TargetKind::NodeSourceFile,
        Some(PathBuf::from("src/crypto/brotli.ts")),
        Some(108),
        "brotli_decompress_buffer",
        "brotli_decompress_safe_bound",
        "Critical heap corruption in native bindings",
        "Bump brotli to 1.1.2 or apply memory limit patch",
    );
    legacy_finding.asset_id = "asset-core-brotli".to_string();
    legacy_finding.detector_id = "taint-sast".to_string();
    legacy_finding.detector_version = "2.5.0".to_string();
    legacy_finding.category = "HEAP_CORRUPTION".to_string();
    legacy_finding.advisory_ids = vec!["GHSA-2026-TEST".to_string(), "CVE-2026-109618".to_string()];
    legacy_finding.component_identity = "google:brotli".to_string();
    legacy_finding.installed_build = Some("1.0.9".to_string());
    legacy_finding.package_source = Some("crates.io".to_string());
    legacy_finding.vendor_advisory = Some("https://example.com/sec/2026".to_string());
    legacy_finding.vendor_fix_state = Some("PATCH_AVAILABLE".to_string());
    legacy_finding.runtime_process_identity = Some("pid:8812".to_string());
    legacy_finding.evidence_refs = vec![EvidenceRef {
        location: "src/crypto/brotli.ts:108".to_string(),
        line_number: Some(108),
        snippet: Some("brotli_decompress_buffer(user_input)".to_string()),
        sha256: Some(DUMMY_HASH.to_string()),
    }];
    legacy_finding.evidence_digest = "sha256-evidence-sample".to_string();
    legacy_finding.observation_time = "2026-10-25T14:30:00Z".to_string();
    legacy_finding.affectedness = Affectedness::ConfirmedAffected;
    legacy_finding.reachability = Reachability::ConfirmedReachable;
    legacy_finding.confidence = Confidence::Confirmed;
    legacy_finding.exploitability_signal = ExploitabilitySignal::ActiveWildExploitation;
    legacy_finding.impact = "Arbitrary code execution on memory corruption".to_string();
    legacy_finding.uncertainty_reasons = vec!["None: confirmed by static trace".to_string()];
    legacy_finding.supported_checks =
        vec!["BK-AI-INJ-001".to_string(), "BK-AI-FIL-001".to_string()];
    legacy_finding.missing_checks = vec!["BK-AI-INJ-002".to_string()];
    legacy_finding.proposed_remediation_ids = vec!["PATCH-BROTLI-01".to_string()];
    legacy_finding.operator_status = OperatorStatus::Acknowledged;
    legacy_finding.evidence_certainty = EvidenceCertainty::Confirmed;
    legacy_finding.compute_dedupe_fingerprint();

    let original_fp = legacy_finding.dedupe_fingerprint.clone();

    // Convert: Legacy -> Normalized
    let normalized = to_normalized_finding(&legacy_finding, "run-roundtrip-01", DUMMY_HASH);

    // Validate normalized strictly against schema rules
    normalized
        .validate()
        .expect("Normalized finding must pass schema validation");
    assert_eq!(normalized.schema_version, "1.0");
    assert_eq!(normalized.finding_id, "F-2026-ROUNDTRIP-01");
    assert_eq!(normalized.severity, NormalizedSeverity::Critical);
    assert_eq!(
        normalized.evidence_certainty,
        EvidenceCertaintyV1::Confirmed
    );
    assert!(
        normalized.proof.is_some(),
        "Confirmed finding must contain proof per schema"
    );

    // Convert: Normalized -> Legacy
    let restored = from_normalized_finding(&normalized);

    // Verify 100% preservation of all essential fields
    assert_eq!(restored.id, legacy_finding.id);
    assert_eq!(restored.cve.as_str(), legacy_finding.cve.as_str());
    assert_eq!(restored.severity, legacy_finding.severity);
    assert_eq!(restored.target_kind, legacy_finding.target_kind);
    assert_eq!(restored.file_path, legacy_finding.file_path);
    assert_eq!(restored.line_number, legacy_finding.line_number);
    assert_eq!(
        restored.detected_version_or_pattern,
        legacy_finding.detected_version_or_pattern
    );
    assert_eq!(restored.safe_threshold, legacy_finding.safe_threshold);
    assert_eq!(restored.description, legacy_finding.description);
    assert_eq!(
        restored.suggested_remediation,
        legacy_finding.suggested_remediation
    );
    assert_eq!(restored.asset_id, legacy_finding.asset_id);
    assert_eq!(restored.detector_id, legacy_finding.detector_id);
    assert_eq!(restored.detector_version, legacy_finding.detector_version);
    assert_eq!(restored.category, legacy_finding.category);
    assert_eq!(restored.advisory_ids, legacy_finding.advisory_ids);
    assert_eq!(
        restored.component_identity,
        legacy_finding.component_identity
    );
    assert_eq!(restored.installed_build, legacy_finding.installed_build);
    assert_eq!(restored.package_source, legacy_finding.package_source);
    assert_eq!(restored.vendor_advisory, legacy_finding.vendor_advisory);
    assert_eq!(restored.vendor_fix_state, legacy_finding.vendor_fix_state);
    assert_eq!(
        restored.runtime_process_identity,
        legacy_finding.runtime_process_identity
    );
    assert_eq!(restored.evidence_refs, legacy_finding.evidence_refs);
    assert_eq!(restored.evidence_digest, legacy_finding.evidence_digest);
    assert_eq!(restored.observation_time, legacy_finding.observation_time);
    assert_eq!(restored.affectedness, legacy_finding.affectedness);
    assert_eq!(restored.reachability, legacy_finding.reachability);
    assert_eq!(restored.confidence, legacy_finding.confidence);
    assert_eq!(
        restored.exploitability_signal,
        legacy_finding.exploitability_signal
    );
    assert_eq!(restored.impact, legacy_finding.impact);
    assert_eq!(
        restored.uncertainty_reasons,
        legacy_finding.uncertainty_reasons
    );
    assert_eq!(restored.supported_checks, legacy_finding.supported_checks);
    assert_eq!(restored.missing_checks, legacy_finding.missing_checks);
    assert_eq!(
        restored.proposed_remediation_ids,
        legacy_finding.proposed_remediation_ids
    );
    assert_eq!(restored.operator_status, legacy_finding.operator_status);
    assert_eq!(
        restored.evidence_certainty,
        legacy_finding.evidence_certainty
    );
    assert_eq!(restored.dedupe_fingerprint, original_fp);

    // 7b. Comprehensive CoverageReceipt roundtrip
    let legacy_receipt = CoverageReceipt {
        scanner_id: "taint-sast".to_string(),
        scanner_version: "2.5.0".to_string(),
        target_id: "src/crypto/brotli.ts".to_string(),
        status: CoverageStatus::Complete,
        items_examined: 42,
        skipped_reasons: vec!["Exempt vendor mock".to_string()],
        errors: Vec::new(),
        completed_at: "2026-10-25T14:35:00Z".to_string(),
    };

    let norm_receipt = to_normalized_receipt(&legacy_receipt, "run-roundtrip-01", DUMMY_HASH);
    norm_receipt
        .validate()
        .expect("Normalized receipt must pass validation");
    assert_eq!(norm_receipt.status, CoverageReceiptStatus::Evaluated);
    assert_eq!(norm_receipt.counts.items_examined, 42);

    let restored_receipt = from_normalized_receipt(&norm_receipt);
    assert_eq!(restored_receipt.scanner_id, legacy_receipt.scanner_id);
    assert_eq!(
        restored_receipt.scanner_version,
        legacy_receipt.scanner_version
    );
    assert_eq!(restored_receipt.target_id, legacy_receipt.target_id);
    assert_eq!(restored_receipt.status, legacy_receipt.status);
    assert_eq!(
        restored_receipt.items_examined,
        legacy_receipt.items_examined
    );
    assert_eq!(restored_receipt.completed_at, legacy_receipt.completed_at);
}

#[test]
fn test_8_builtin_scanner_adapter_real_workspace_execution() {
    let temp_dir = tempfile::tempdir().expect("tempdir creation");
    let test_file = temp_dir.path().join("vulnerable_sample.php");
    fs::write(&test_file, "<?php eval($_GET['cmd']); ?>").expect("write test file");

    let adapter = Arc::new(BuiltinScannerAdapter::new());
    let mut registry = EngineRegistry::new();
    registry.register(adapter);

    let request = AnalysisRequest::new(
        "run-builtin-008",
        "builtin-scanner",
        temp_dir.path().to_string_lossy().to_string(),
        DUMMY_HASH,
        ScanProfile::Quick,
        vec!["BK-AI-INJ-001".to_string()],
        vec![test_file.to_string_lossy().to_string()],
    );

    let cancel_token = CancellationToken::new();
    let response = registry
        .dispatch(&request, &cancel_token)
        .expect("Builtin scan must succeed");

    assert_eq!(response.schema_version, "1.0");
    assert_eq!(response.engine_id, "builtin-scanner");
    assert!(
        !response.receipts.is_empty(),
        "Must produce coverage receipts"
    );
    response
        .validate()
        .expect("Builtin scanner response must strictly pass validation");
}

#[test]
fn test_9_repair_plan_schema_compliance_and_validation() {
    let mut plan = RepairPlanV1 {
        schema_version: "1.0".to_string(),
        plan_id: "plan-repair-001".to_string(),
        run_id: "run-repair-001".to_string(),
        finding_ids: vec!["finding-001".to_string()],
        workspace_root_digest: DUMMY_HASH.to_string(),
        risk_level: RepairRiskLevel::L2,
        proposed_actions: vec![ProposedActionV1 {
            action_id: "act-01".to_string(),
            kind: ProposedActionKind::SourcePatch,
            target_relative_path: "src/server.ts".to_string(),
            preimage_sha256: DUMMY_HASH.to_string(),
            expected_postimage_sha256: DUMMY_HASH.to_string(),
            diff_artifact_sha256: None,
        }],
        required_verifications: vec![RequiredVerificationV1 {
            verification_id: "ver-01".to_string(),
            kind: VerificationKind::Test,
            required: true,
        }],
        approval: None,
        status: RepairPlanStatus::Proposed,
        backup_manifest_ref: None,
        created_at: "2026-10-25T15:00:00Z".to_string(),
        expires_at: "2026-10-25T16:00:00Z".to_string(),
        idempotency_key: None,
    };

    // Proposed plan without approval is valid
    plan.validate().expect("Proposed plan must validate");

    // Once status changes to Authorized, approval is strictly required
    plan.status = RepairPlanStatus::Authorized;
    assert!(
        plan.validate().is_err(),
        "Authorized plan without approval must fail validation"
    );

    plan.approval = Some(RepairApprovalV1 {
        operator_id: "operator-admin-1".to_string(),
        approval_id: "appr-001".to_string(),
        plan_digest: DUMMY_HASH.to_string(),
        issued_at: "2026-10-25T15:05:00Z".to_string(),
        expires_at: "2026-10-25T16:00:00Z".to_string(),
        signature_ref: "sig-ed25519-valid".to_string(),
    });

    plan.validate()
        .expect("Authorized plan with approval must validate");

    // Verify JSON serialization compliance
    let json_str = serde_json::to_string_pretty(&plan).expect("serialize plan");
    let val: serde_json::Value = serde_json::from_str(&json_str).expect("parse json");
    let required_plan_fields = [
        "schema_version",
        "plan_id",
        "run_id",
        "finding_ids",
        "workspace_root_digest",
        "risk_level",
        "proposed_actions",
        "required_verifications",
        "status",
        "created_at",
        "expires_at",
    ];
    for field in &required_plan_fields {
        assert!(
            val.get(*field).is_some(),
            "Field '{}' must be present in repair plan JSON",
            field
        );
    }
}
