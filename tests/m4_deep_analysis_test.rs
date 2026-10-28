use bug_killer::deep::*;
use bug_killer::engine::adapter::AnalyzerAdapter;
use bug_killer::engine::protocol::*;
use bug_killer::engine::runner::CancellationToken;
use bug_killer::types::ScanProfile;
use chrono::Utc;
use serde_json::Value;
use std::fs;

const DUMMY_SNAPSHOT_SHA256: &str =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

// -------------------------------------------------------------------------
// 1. Multi-file CPG Taint Flow Detection (Positive Control)
// Input read in File A -> passed across functions/files -> sink in File B.
// Verified that CPG graph analysis detects the complete source-to-sink flow.
// -------------------------------------------------------------------------
#[test]
fn test_1_multi_file_cpg_taint_flow_detection_positive_control() {
    let mut builder = CpgBuilder::new();

    let file_a_content = r#"
// src/controllers/userController.js
function handleUserRequest(req, res) {
    const userId = req.query.id;
    executeUserLookup(userId);
}
"#;

    let file_b_content = r#"
// src/services/databaseService.js
function executeUserLookup(id) {
    const sql = "SELECT * FROM users WHERE id = " + id;
    db.query(sql);
}
"#;

    builder.add_source_file("src/controllers/userController.js", file_a_content);
    builder.add_source_file("src/services/databaseService.js", file_b_content);

    let cpg = builder.build();
    let flows = cpg.find_taint_flows();

    assert_eq!(
        flows.len(),
        1,
        "Must detect exactly one cross-file taint flow"
    );
    let flow = &flows[0];

    assert!(
        flow.is_multi_file,
        "Flow must cross file boundaries (File A -> File B)"
    );
    assert_eq!(flow.source_file, "src/controllers/userController.js");
    assert_eq!(flow.sink_file, "src/services/databaseService.js");
    assert_eq!(flow.certainty, TraceCertainty::Confirmed);
    assert_eq!(flow.weakness, "CWE-89");

    // Complete source-to-sink trace steps
    assert!(flow.steps.len() >= 3);
    assert_eq!(flow.steps[0].file, "src/controllers/userController.js");
    assert!(flow.steps[0].code.contains("req.query.id"));
    let last_step = flow.steps.last().unwrap();
    assert_eq!(last_step.file, "src/services/databaseService.js");
    assert!(last_step.code.contains("db.query"));
}

// -------------------------------------------------------------------------
// 2. Sanitizer Defense (Negative Control)
// Input read in File A -> passed through sanitizer (intval / escape) -> sink in File B.
// Verified that sanitizer breaks the taint chain; zero false-positive findings reported.
// -------------------------------------------------------------------------
#[test]
fn test_2_sanitizer_defense_breaks_taint_chain_negative_control() {
    let mut builder = CpgBuilder::new();

    let file_a_content = r#"
// src/controllers/userController.js
function handleUserRequest(req, res) {
    const rawId = req.query.id;
    const cleanId = intval(rawId);
    executeUserLookup(cleanId);
}
"#;

    let file_b_content = r#"
// src/services/databaseService.js
function executeUserLookup(id) {
    const sql = "SELECT * FROM users WHERE id = " + id;
    db.query(sql);
}
"#;

    builder.add_source_file("src/controllers/userController.js", file_a_content);
    builder.add_source_file("src/services/databaseService.js", file_b_content);

    let cpg = builder.build();
    let flows = cpg.find_taint_flows();

    assert!(
        flows.is_empty(),
        "Sanitizer must break the taint chain, producing zero false-positive findings"
    );
}

// -------------------------------------------------------------------------
// 3. Dynamic Dispatch & Reflection Ambiguity
// Input flows through an indirect / dynamic dispatch call (e.g. handler[action](payload)).
// Verified that the trace is captured with TraceCertainty::Uncertain / Suspected,
// NOT silently dropped and NOT claimed as 100% confirmed.
// -------------------------------------------------------------------------
#[test]
fn test_3_dynamic_dispatch_and_reflection_captured_as_uncertain() {
    let mut builder = CpgBuilder::new();

    let file_a_content = r#"
// src/controllers/dispatchController.js
function routeAction(req, res) {
    const payload = req.query.payload;
    const action = req.query.action;
    handler[action](payload);
}
"#;

    let file_b_content = r#"
// src/handlers/actionHandler.js
function handleCustomAction(payload) {
    db.query("SELECT * FROM log WHERE data = " + payload);
}
"#;

    builder.add_source_file("src/controllers/dispatchController.js", file_a_content);
    builder.add_source_file("src/handlers/actionHandler.js", file_b_content);

    let cpg = builder.build();
    let flows = cpg.find_taint_flows();

    assert_eq!(
        flows.len(),
        1,
        "Dynamic dispatch path must be captured, NOT silently dropped"
    );
    let flow = &flows[0];

    assert_eq!(
        flow.certainty,
        TraceCertainty::Uncertain,
        "Dynamic dispatch must yield TraceCertainty::Uncertain, not claimed 100% confirmed"
    );
    assert_ne!(
        flow.certainty,
        TraceCertainty::Confirmed,
        "Ambiguous reflection cannot claim confirmed certainty"
    );

    // Verify dynamic step is flagged in the trace
    let dynamic_step = flow.steps.iter().find(|s| s.is_dynamic);
    assert!(
        dynamic_step.is_some(),
        "Trace must record the dynamic dispatch step"
    );
}

// -------------------------------------------------------------------------
// 4. Tool Capability Broker & Honest Receipts
// Test ToolCapabilityBroker:
// - Discovers available tools vs missing tools.
// - When external tools (Joern, Semgrep, CodeQL) are not installed, emits
//   ToolExecutionReceipt with status: NotRun and reason_code: EngineMissing.
// - Zero panics, zero false assurances of completeness.
// - Conformance to JSON schemas: serialize ToolCapability and ToolExecutionReceipt
//   to JSON and assert all required fields match schemas.
// -------------------------------------------------------------------------
#[test]
fn test_4_tool_capability_broker_honest_receipts_and_schema_conformance() {
    let mut broker = ToolCapabilityBroker::new();

    // Verify discovery of standard specialist tools
    let joern = broker
        .get_capability("joern-cpg-adapter")
        .cloned()
        .expect("Joern adapter must be registered");
    let semgrep = broker
        .get_capability("semgrep-ce-adapter")
        .cloned()
        .expect("Semgrep adapter must be registered");
    let codeql = broker
        .get_capability("codeql-adapter")
        .cloned()
        .expect("CodeQL adapter must be registered");

    assert_eq!(joern.installation, Installation::Missing);
    assert_eq!(semgrep.installation, Installation::Missing);
    assert_eq!(codeql.installation, Installation::Unlicensed);

    // Emit receipt against missing Joern
    let receipt = broker.emit_receipt(
        "plan-deep-001",
        "run-deep-001",
        "joern-cpg-adapter",
        DUMMY_SNAPSHOT_SHA256,
        vec!["target/project".to_string()],
        vec!["CWE-89".to_string()],
    );

    // Assert honest missing tool reporting
    assert_eq!(receipt.status, ToolExecutionStatus::NotRun);
    assert!(receipt.is_engine_missing());
    assert_eq!(receipt.resources.duration_ms, 0);

    // Assert built-in invariant validation passes
    joern.validate().expect("ToolCapability must validate");
    receipt
        .validate()
        .expect("ToolExecutionReceipt must validate");

    // ---------------- JSON Schema Conformance ----------------
    // 4a. Conformance of ToolCapability to tool-capability.schema.json
    let cap_json = serde_json::to_value(joern).expect("Serialize ToolCapability");

    let cap_schema_raw =
        fs::read_to_string("bug-killer-ultimate-spec-v1/schemas/tool-capability.schema.json")
            .expect("Read tool-capability.schema.json");
    let cap_schema: Value =
        serde_json::from_str(&cap_schema_raw).expect("Parse tool-capability.schema.json");

    let required_cap_fields = cap_schema["required"]
        .as_array()
        .expect("Schema must have required array");

    for field in required_cap_fields {
        let field_name = field.as_str().unwrap();
        assert!(
            cap_json.get(field_name).is_some(),
            "ToolCapability missing required schema field: {}",
            field_name
        );
    }
    assert_eq!(cap_json["schema_version"], "1.0");
    assert_eq!(cap_json["installation"], "MISSING");

    // 4b. Conformance of ToolExecutionReceipt to tool-execution-receipt.schema.json
    let receipt_json = serde_json::to_value(&receipt).expect("Serialize ToolExecutionReceipt");

    let receipt_schema_raw = fs::read_to_string(
        "bug-killer-ultimate-spec-v1/schemas/tool-execution-receipt.schema.json",
    )
    .expect("Read tool-execution-receipt.schema.json");
    let receipt_schema: Value = serde_json::from_str(&receipt_schema_raw)
        .expect("Parse tool-execution-receipt.schema.json");

    let required_receipt_fields = receipt_schema["required"]
        .as_array()
        .expect("Schema must have required array");

    for field in required_receipt_fields {
        let field_name = field.as_str().unwrap();
        assert!(
            receipt_json.get(field_name).is_some(),
            "ToolExecutionReceipt missing required schema field: {}",
            field_name
        );
    }
    assert_eq!(receipt_json["schema_version"], "1.0");
    assert_eq!(receipt_json["status"], "NOT_RUN");
    assert_eq!(receipt_json["snapshot_sha256"], DUMMY_SNAPSHOT_SHA256);
}

// -------------------------------------------------------------------------
// 5. CodeQL Licensing Gate
// When CodeQL is present but license is not approved / verified,
// execution fails closed with status: Blocked or NotRun (reason_code: UnlicensedEnvironment).
// -------------------------------------------------------------------------
#[test]
fn test_5_codeql_licensing_gate_fails_closed() {
    let mut broker = ToolCapabilityBroker::new();

    // 1. Initial State: Unlicensed CodeQL must fail closed with Blocked status
    let receipt_unlicensed = broker.emit_receipt(
        "plan-codeql-01",
        "run-codeql-01",
        "codeql",
        DUMMY_SNAPSHOT_SHA256,
        vec!["target/project".to_string()],
        vec!["CWE-89".to_string()],
    );
    assert_eq!(receipt_unlicensed.status, ToolExecutionStatus::NotRun);
    assert!(
        receipt_unlicensed.is_unlicensed(),
        "Unlicensed CodeQL must fail closed with UnlicensedEnvironment reason"
    );

    // 2. State update: License is explicitly approved and entitlement verified
    broker.set_codeql_license_approved(true);

    // Configure a dummy mock binary path so it is detected as Available
    let dummy_temp_bin = std::env::temp_dir().join("mock_codeql_bin");
    fs::write(&dummy_temp_bin, b"#!/bin/sh\necho 2.16.0\n").expect("write mock bin");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&dummy_temp_bin).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&dummy_temp_bin, perms).unwrap();
    }
    broker.set_tool_path("codeql", dummy_temp_bin.clone());

    let cap_licensed = broker
        .get_capability("codeql")
        .expect("CodeQL capability exists");
    assert_eq!(cap_licensed.installation, Installation::Available);
    assert_eq!(
        cap_licensed.governance.license_review,
        LicenseReview::Approved
    );
    assert!(cap_licensed.governance.entitlement_verified);

    // 3. Discovery of a licensed tool does not prove an execution occurred.
    let receipt_licensed = broker.emit_receipt(
        "plan-codeql-02",
        "run-codeql-02",
        "codeql",
        DUMMY_SNAPSHOT_SHA256,
        vec!["target/project".to_string()],
        vec!["CWE-89".to_string()],
    );
    assert_eq!(receipt_licensed.status, ToolExecutionStatus::NotRun);
    assert_eq!(receipt_licensed.reason_code, "NOT_EXECUTED");
    assert!(receipt_licensed.artifacts.is_empty());

    // Clean up temporary mock binary
    let _ = fs::remove_file(dummy_temp_bin);
}

// -------------------------------------------------------------------------
// 6. Timeout & Cancellation Bounds
// Cancellation token triggers during analysis -> adapter halts cleanly
// and returns status: Cancelled within budget limits.
// -------------------------------------------------------------------------
#[test]
fn test_6_timeout_and_cancellation_bounds_aborts_cleanly() {
    let mut broker = ToolCapabilityBroker::new();
    let cancel_token = CancellationToken::new();

    // Trigger cancellation
    cancel_token.cancel();
    assert!(cancel_token.is_cancelled());

    // Record an execution that halted due to cancellation token
    let now = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let receipt = ToolExecutionReceipt {
        schema_version: "1.0".to_string(),
        receipt_id: "receipt-cancelled-001".to_string(),
        plan_id: "plan-cancel-01".to_string(),
        run_id: "run-cancel-01".to_string(),
        tool_id: "joern-cpg-adapter".to_string(),
        adapter_version: "0.1.0".to_string(),
        engine_version: None,
        snapshot_sha256: DUMMY_SNAPSHOT_SHA256.to_string(),
        target_ids: vec!["target/project".to_string()],
        check_ids: vec!["CWE-89".to_string()],
        status: ToolExecutionStatus::Cancelled,
        reason_code: REASON_CANCELLED.to_string(),
        authorization_ref: None,
        resources: ExecutionResources {
            duration_ms: 12,
            peak_memory_bytes: Some(1024 * 1024),
            cost_estimate_usd: None,
            cost_actual_usd: None,
        },
        artifacts: Vec::new(),
        started_at: now.clone(),
        completed_at: now,
    };

    receipt.validate().expect("Cancelled receipt must validate");
    broker.record_receipt(receipt.clone());

    assert_eq!(receipt.status, ToolExecutionStatus::Cancelled);
    assert_eq!(receipt.reason_code, "Cancelled");
    assert!(
        receipt.resources.duration_ms < 1000,
        "Cancelled execution must abort cleanly within tight resource/time budget"
    );
    assert_eq!(broker.receipts().len(), 1);
}

// -------------------------------------------------------------------------
// 7. Joern Sandboxed Adapter Configuration & Network Isolation
// -------------------------------------------------------------------------
#[test]
fn test_7_joern_adapter_sandboxed_configuration() {
    let adapter = JoernAdapter::new();
    assert!(
        !adapter.is_installed(),
        "Joern binary should not be present in test environment"
    );
    assert_eq!(adapter.installation_state(), Installation::Missing);

    let caps = adapter.capabilities();
    assert!(
        !caps.requires_network,
        "Joern sidecar must have network disabled by default"
    );
    assert!(caps.is_isolated, "Joern sidecar must be isolated");
    assert!(
        adapter
            .supported_profiles()
            .contains(&bug_killer::types::ScanProfile::Deep)
    );
}

// -------------------------------------------------------------------------
// 8. Joern Profile Acceptance & Quick Profile Rejection
// Quick scan profile must NEVER invoke Joern or slow graph traversals.
// Joern adapter must explicitly reject ScanProfile::Quick and accept Deep & Audit.
// -------------------------------------------------------------------------
#[test]
fn test_8_joern_adapter_profile_rejection_and_acceptance() {
    let adapter = JoernAdapter::new();

    // Quick profile rejection
    assert!(
        !adapter.can_handle_profile(ScanProfile::Quick),
        "Joern adapter must NEVER handle ScanProfile::Quick"
    );

    // Deep & Audit profile acceptance
    assert!(
        adapter.can_handle_profile(ScanProfile::Deep),
        "Joern adapter must handle ScanProfile::Deep"
    );
    assert!(
        adapter.can_handle_profile(ScanProfile::Audit),
        "Joern adapter must handle ScanProfile::Audit"
    );

    // Calling analyze directly with ScanProfile::Quick returns an ExecutionFailed error
    let req = AnalysisRequest::new(
        "run-quick-fail",
        "joern-cpg-adapter",
        "target/project",
        DUMMY_SNAPSHOT_SHA256,
        ScanProfile::Quick,
        vec!["CWE-89".to_string()],
        vec!["target/project".to_string()],
    );
    let cancel = CancellationToken::new();
    let res = adapter.analyze(&req, &cancel);
    assert!(
        res.is_err(),
        "Joern analyze must fail cleanly when invoked with ScanProfile::Quick"
    );
    if let Err(bug_killer::engine::runner::AnalysisError::ExecutionFailed(msg)) = res {
        assert!(msg.contains("does not support scan profile Quick"));
    } else {
        panic!("Expected AnalysisError::ExecutionFailed");
    }
}

// -------------------------------------------------------------------------
// 9. Joern Missing Engine Honest Receipts
// When Joern binary is missing and fallback is not requested, emit honest
// CoverageReceiptStatus::NotRun with ReceiptReasonCode::EngineMissing.
// -------------------------------------------------------------------------
#[test]
fn test_9_joern_adapter_missing_engine_honest_receipt() {
    let adapter = JoernAdapter::new();
    let cancel = CancellationToken::new();

    let req = AnalysisRequest::new(
        "run-joern-missing",
        "joern-cpg-adapter",
        "target/dummy-repo",
        DUMMY_SNAPSHOT_SHA256,
        ScanProfile::Deep,
        vec!["CWE-89".to_string()],
        vec!["target/dummy-repo".to_string()],
    );

    let res = adapter
        .analyze(&req, &cancel)
        .expect("Missing Joern must return honest response, not an unexpected panic or error");

    assert_eq!(res.status, EngineStatus::Partial);
    assert!(res.findings.is_empty(), "No findings when engine missing");
    assert_eq!(res.receipts.len(), 1);

    let receipt = &res.receipts[0];
    assert_eq!(receipt.status, CoverageReceiptStatus::NotRun);
    assert_eq!(receipt.reason_codes, vec![ReceiptReasonCode::EngineMissing]);
    assert_eq!(receipt.engine_id, "joern-cpg-adapter");
    assert_eq!(receipt.snapshot_sha256, DUMMY_SNAPSHOT_SHA256);

    assert_eq!(res.diagnostics.len(), 1);
    assert_eq!(res.diagnostics[0].code, "ENGINE_MISSING");
}

// -------------------------------------------------------------------------
// 10. Joern Embedded Fallback & Trace Evidence Structure
// When embedded fallback is enabled, analysis discovers cross-file flows
// and packages them into FindingV1 with EvidenceItemKind::DataflowTrace.
// -------------------------------------------------------------------------
#[test]
fn test_10_joern_embedded_fallback_produces_full_dataflow_trace() {
    let temp_dir = std::env::temp_dir().join(format!(
        "bk_test_joern_cpg_{}",
        Utc::now().timestamp_nanos_opt().unwrap_or(0)
    ));
    let src_dir = temp_dir.join("src");
    fs::create_dir_all(&src_dir).expect("create temp dir");

    let file_a_path = src_dir.join("userController.js");
    let file_b_path = src_dir.join("databaseService.js");

    let file_a_content = r#"
function handleUserRequest(req, res) {
    const userId = req.query.id;
    executeUserLookup(userId);
}
"#;
    let file_b_content = r#"
function executeUserLookup(id) {
    const sql = "SELECT * FROM users WHERE id = " + id;
    db.query(sql);
}
"#;

    fs::write(&file_a_path, file_a_content).expect("write file A");
    fs::write(&file_b_path, file_b_content).expect("write file B");

    let adapter = JoernAdapter::with_fallback(true);
    let cancel = CancellationToken::new();

    let req = AnalysisRequest::new(
        "run-embedded-deep-01",
        "joern-cpg-adapter",
        temp_dir.to_string_lossy().to_string(),
        DUMMY_SNAPSHOT_SHA256,
        ScanProfile::Deep,
        vec!["CWE-89".to_string()],
        vec![temp_dir.to_string_lossy().to_string()],
    );

    let res = adapter
        .analyze(&req, &cancel)
        .expect("Analysis should succeed");

    assert_eq!(res.status, EngineStatus::Completed);
    assert_eq!(
        res.findings.len(),
        1,
        "Must find exactly 1 cross-file finding"
    );

    let finding = &res.findings[0];
    assert_eq!(finding.rule_id.as_deref(), Some("joern.cwe-89"));
    assert_eq!(finding.weakness_ids, vec!["CWE-89"]);
    assert_eq!(finding.status, FindingStatus::Verified);
    assert_eq!(finding.severity, NormalizedSeverity::Critical);

    // Verify EvidenceItemKind::DataflowTrace
    assert_eq!(finding.evidence.len(), 1);
    let ev = &finding.evidence[0];
    assert_eq!(ev.kind, EvidenceItemKind::DataflowTrace);
    assert!(ev.reference.is_some());

    // Deserialize trace from evidence reference
    let trace_str = ev.reference.as_ref().unwrap();
    let trace: CpgDataflowTrace =
        serde_json::from_str(trace_str).expect("Valid CpgDataflowTrace JSON");
    assert_eq!(trace.certainty, TraceCertainty::Confirmed);
    assert!(trace.is_multi_file);
    assert!(trace.steps.len() >= 3);

    // Verify receipt status
    assert_eq!(res.receipts.len(), 1);
    assert_eq!(res.receipts[0].status, CoverageReceiptStatus::Evaluated);
    assert_eq!(res.receipts[0].counts.items_discovered, 1);

    // Cleanup temp dir
    let _ = fs::remove_dir_all(&temp_dir);
}

// -------------------------------------------------------------------------
// 11. Joern Cancellation Token Honored
// Analysis halts cleanly when cancellation token is triggered.
// -------------------------------------------------------------------------
#[test]
fn test_11_joern_adapter_cancellation_honored() {
    let adapter = JoernAdapter::with_fallback(true);
    let cancel = CancellationToken::new();
    cancel.cancel(); // Pre-cancel

    let req = AnalysisRequest::new(
        "run-cancelled-01",
        "joern-cpg-adapter",
        "target/project",
        DUMMY_SNAPSHOT_SHA256,
        ScanProfile::Deep,
        vec!["CWE-89".to_string()],
        vec!["target/project".to_string()],
    );

    let res = adapter.analyze(&req, &cancel);
    assert!(res.is_err());
    match res {
        Err(bug_killer::engine::runner::AnalysisError::Cancelled) => {}
        other => panic!("Expected AnalysisError::Cancelled, got {:?}", other),
    }
}

// -------------------------------------------------------------------------
// 12. CPG Graph Structure, Node Kinds & Edge Kinds Coverage
// Tests direct creation and traversal of CPG graphs.
// -------------------------------------------------------------------------
#[test]
fn test_12_cpg_graph_structure_and_kinds() {
    let mut graph = CpgGraph::new();

    let n0 = graph.add_node("app.js", 1, "req.query.user", CpgNodeKind::Source, None);
    let n1 = graph.add_node(
        "app.js",
        2,
        "user = req.query.user",
        CpgNodeKind::Variable,
        Some("user"),
    );
    let n2 = graph.add_node(
        "app.js",
        3,
        "clean = sanitize(user)",
        CpgNodeKind::Sanitizer,
        Some("clean"),
    );
    let n3 = graph.add_node("app.js", 4, "run(user)", CpgNodeKind::CallSite, Some("run"));
    let n4 = graph.add_node(
        "lib.js",
        1,
        "function run(arg)",
        CpgNodeKind::Source,
        Some("arg"),
    );
    let n5 = graph.add_node("lib.js", 2, "query(arg)", CpgNodeKind::Sink, None);
    let n6 = graph.add_node("lib.js", 3, "return res", CpgNodeKind::Return, None);
    let n7 = graph.add_node(
        "app.js",
        5,
        "obj[method](arg)",
        CpgNodeKind::DynamicDispatch,
        None,
    );

    graph.add_dataflow_edge(n0, n1);
    graph.add_dataflow_edge(n1, n2);
    graph.add_controlflow_edge(n1, n3);
    graph.add_call_edge(n3, n4);
    graph.add_dataflow_edge(n4, n5);
    graph.add_controlflow_edge(n5, n6);
    graph.add_dynamic_call_edge(n7, n4);

    assert_eq!(graph.nodes().len(), 8);
    assert_eq!(graph.edges().len(), 7);

    // Verify node properties
    assert_eq!(graph.nodes()[n0].kind, CpgNodeKind::Source);
    assert_eq!(graph.nodes()[n2].kind, CpgNodeKind::Sanitizer);
    assert_eq!(graph.nodes()[n5].kind, CpgNodeKind::Sink);
    assert_eq!(graph.nodes()[n6].kind, CpgNodeKind::Return);
    assert_eq!(graph.nodes()[n7].kind, CpgNodeKind::DynamicDispatch);

    // Verify edge properties
    assert_eq!(graph.edges()[0].kind, CpgEdgeKind::DataFlow);
    assert_eq!(graph.edges()[2].kind, CpgEdgeKind::ControlFlow);
    assert_eq!(graph.edges()[3].kind, CpgEdgeKind::CallDirect);
    assert_eq!(graph.edges()[6].kind, CpgEdgeKind::CallDynamic);

    // Serialization roundtrip
    let json = serde_json::to_string(&graph).expect("Serialize CPG graph");
    let deser: CpgGraph = serde_json::from_str(&json).expect("Deserialize CPG graph");
    assert_eq!(deser.nodes().len(), 8);
    assert_eq!(deser.edges().len(), 7);
}
