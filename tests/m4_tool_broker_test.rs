use std::fs;
use std::path::PathBuf;

use bug_killer::deep::*;
use bug_killer::engine::adapter::AnalyzerAdapter;
use bug_killer::engine::protocol::{
    AnalysisRequest, CoverageReceiptStatus, EngineStatus, EvidenceCertaintyV1, EvidenceItemKind,
    ReceiptReasonCode,
};
use bug_killer::engine::runner::CancellationToken;
use bug_killer::types::ScanProfile;

const DUMMY_HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn create_sample_request() -> AnalysisRequest {
    AnalysisRequest::new(
        "run-m4-test-001",
        "semgrep-ce-adapter",
        "/tmp/snapshot",
        DUMMY_HASH,
        ScanProfile::Quick,
        vec!["CHECK-001".to_string()],
        vec!["src/main.py".to_string()],
    )
}

// =========================================================================
// 1. Schema Round-Trip and Validation Tests
// =========================================================================

#[test]
fn test_tool_capability_schema_example_conformance() {
    let example_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("bug-killer-ultimate-spec-v1/examples/tool-capability.json");
    let json_text = fs::read_to_string(&example_path)
        .expect("Failed to read tool-capability.json example fixture");

    let capability: ToolCapability = serde_json::from_str(&json_text)
        .expect("ToolCapability must parse from canonical example JSON");

    assert_eq!(capability.schema_version, "1.0");
    assert_eq!(capability.tool_id, "example-local-sast-adapter");
    assert_eq!(capability.adapter_version, "0.1-test");
    assert_eq!(capability.engine_version, None);
    assert_eq!(capability.binary_sha256, None);
    assert_eq!(capability.installation, Installation::Missing);
    assert_eq!(capability.capabilities.kinds, vec![CapabilityKind::Sast]);
    assert_eq!(
        capability.capabilities.output_formats,
        vec![OutputFormat::Json]
    );
    assert_eq!(
        capability.capabilities.evidence_limit,
        EvidenceLimit::Unknown
    );
    assert_eq!(capability.execution.transport, ExecutionTransport::Cli);
    assert_eq!(
        capability.execution.platforms,
        vec!["linux-amd64".to_string()]
    );
    assert!(capability.execution.local);
    assert!(!capability.execution.network_required);
    assert_eq!(capability.governance.license_review, LicenseReview::Pending);
    assert!(!capability.governance.entitlement_verified);
    assert_eq!(capability.governance.cost_model, CostModel::LocalResources);
    assert_eq!(
        capability.governance.restrictions,
        vec!["Fixture only; not installed or benchmarked".to_string()]
    );
    assert_eq!(
        capability.notes,
        vec!["Demonstrates honest missing-tool reporting; no engine was executed".to_string()]
    );

    assert!(capability.validate().is_ok());

    // Serialize back and re-deserialize
    let serialized = serde_json::to_string_pretty(&capability)
        .expect("Must serialize ToolCapability back to JSON");
    let roundtrip: ToolCapability =
        serde_json::from_str(&serialized).expect("Must deserialize round-tripped ToolCapability");
    assert_eq!(capability, roundtrip);
}

#[test]
fn test_tool_execution_receipt_schema_example_conformance() {
    let example_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("bug-killer-ultimate-spec-v1/examples/tool-execution-receipt.json");
    let json_text = fs::read_to_string(&example_path)
        .expect("Failed to read tool-execution-receipt.json example fixture");

    let receipt: ToolExecutionReceipt = serde_json::from_str(&json_text)
        .expect("ToolExecutionReceipt must parse from canonical example JSON");

    assert_eq!(receipt.schema_version, "1.0");
    assert_eq!(receipt.receipt_id, "sample-missing-1");
    assert_eq!(receipt.plan_id, "sample-plan-1");
    assert_eq!(receipt.run_id, "sample-run-1");
    assert_eq!(receipt.tool_id, "example-local-sast-adapter");
    assert_eq!(receipt.adapter_version, "0.1-test");
    assert_eq!(receipt.engine_version, None);
    assert_eq!(
        receipt.snapshot_sha256,
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );
    assert_eq!(receipt.status, ToolExecutionStatus::NotRun);
    assert_eq!(receipt.reason_code, "ENGINE_MISSING");
    assert!(receipt.is_engine_missing());
    assert_eq!(receipt.authorization_ref, None);
    assert_eq!(receipt.resources.duration_ms, 0);
    assert_eq!(receipt.resources.peak_memory_bytes, None);
    assert_eq!(receipt.artifacts.len(), 0);

    assert!(receipt.validate().is_ok());

    let serialized = serde_json::to_string_pretty(&receipt)
        .expect("Must serialize ToolExecutionReceipt back to JSON");
    let roundtrip: ToolExecutionReceipt = serde_json::from_str(&serialized)
        .expect("Must deserialize round-tripped ToolExecutionReceipt");
    assert_eq!(receipt, roundtrip);
}

// =========================================================================
// 2. Tool Capability Broker Discovery and Honest Receipts
// =========================================================================

#[test]
fn test_broker_discovery_on_host_uninstalled_tools() {
    let mut broker = ToolCapabilityBroker::new();
    let capabilities = broker.discover_all();

    assert!(capabilities.len() >= 4);

    // On standard test machine where external tools are not in PATH,
    // they must report Missing honestly, never claiming false Available.
    let semgrep_cap = broker
        .get_capability("semgrep")
        .expect("semgrep capability registered");
    if broker.find_binary("semgrep").is_none() {
        assert_eq!(semgrep_cap.installation, Installation::Missing);
        assert_eq!(semgrep_cap.engine_version, None);
        assert_eq!(semgrep_cap.binary_sha256, None);
    }

    let codeql_cap = broker
        .get_capability("codeql")
        .expect("codeql capability registered");
    if broker.find_binary("codeql").is_none() {
        assert_eq!(codeql_cap.installation, Installation::Unlicensed);
    }
}

#[test]
fn test_broker_honest_not_run_receipt_emission() {
    let mut broker = ToolCapabilityBroker::new();
    // Non-existent tool binary path
    broker.set_tool_path("semgrep", PathBuf::from("/nonexistent/bin/semgrep"));

    let receipt = broker.emit_receipt(
        "plan-123",
        "run-456",
        "semgrep",
        DUMMY_HASH,
        vec!["target/project".to_string()],
        vec!["RULE-001".to_string()],
    );

    assert_eq!(receipt.schema_version, "1.0");
    assert_eq!(receipt.status, ToolExecutionStatus::NotRun);
    assert_eq!(receipt.reason_code, REASON_ENGINE_MISSING);
    assert!(receipt.is_engine_missing());
    assert_eq!(receipt.resources.duration_ms, 0);
    assert!(receipt.artifacts.is_empty());
    assert!(receipt.validate().is_ok());

    assert_eq!(broker.receipts().len(), 1);
}

#[test]
fn test_broker_configured_binary_hash_and_discovery() {
    let temp_dir = tempfile::tempdir().expect("temp dir");
    let fake_binary = temp_dir.path().join("semgrep");
    fs::write(&fake_binary, b"#!/bin/sh\necho 1.80.0\n").expect("write fake script");

    let mut broker = ToolCapabilityBroker::new();
    broker.set_tool_path("semgrep", fake_binary.clone());

    let cap = broker
        .get_capability("semgrep")
        .expect("semgrep capability");
    assert_eq!(cap.installation, Installation::Available);
    assert!(cap.binary_sha256.is_some());
    assert_eq!(cap.binary_sha256.as_ref().unwrap().len(), 64);
    assert!(cap.validate().is_ok());

    let receipt = broker.emit_receipt(
        "plan-mock",
        "run-mock",
        "semgrep",
        DUMMY_HASH,
        vec!["target/1".to_string()],
        vec!["CHECK-1".to_string()],
    );
    assert_eq!(receipt.status, ToolExecutionStatus::NotRun);
    assert_eq!(receipt.reason_code, "NOT_EXECUTED");
    assert!(receipt.artifacts.is_empty());
    assert!(receipt.validate().is_ok());
}

// =========================================================================
// 3. Semgrep CE Adapter Tests
// =========================================================================

#[test]
fn test_semgrep_adapter_missing_binary_fails_closed_with_honest_receipt() {
    let adapter = SemgrepAdapter::with_binary_path(PathBuf::from("/path/to/missing/semgrep"));
    assert!(!adapter.is_installed());
    assert_eq!(adapter.installation_state(), Installation::Missing);
    assert_eq!(adapter.engine_id(), "semgrep-ce-adapter");
    assert_eq!(adapter.engine_version(), "0.1.0");

    let mut request = create_sample_request();
    request.profile = ScanProfile::Deep;
    let cancel_token = CancellationToken::new();

    let response = adapter
        .analyze(&request, &cancel_token)
        .expect("analyze must return response");

    assert!(matches!(
        response.status,
        EngineStatus::Blocked | EngineStatus::Partial
    ));
    assert!(response.findings.is_empty());
    assert_eq!(response.receipts.len(), 1);

    let receipt = &response.receipts[0];
    assert_eq!(receipt.status, CoverageReceiptStatus::NotRun);
    assert!(
        receipt
            .reason_codes
            .contains(&ReceiptReasonCode::EngineMissing)
    );
    assert!(receipt.validate().is_ok());

    assert_eq!(response.diagnostics.len(), 1);
    assert_eq!(response.diagnostics[0].code, "ENGINE_MISSING");
    assert!(response.validate().is_ok());
}

#[test]
fn test_semgrep_sarif_output_parsing_and_normalization() {
    let sarif_json = r#"{
      "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
      "version": "2.1.0",
      "runs": [
        {
          "tool": {
            "driver": {
              "name": "semgrep",
              "rules": [
                {
                  "id": "rules.python.sql-injection",
                  "properties": {
                    "cwe": ["CWE-89: Improper Neutralization of Special Elements used in an SQL Command"]
                  }
                }
              ]
            }
          },
          "results": [
            {
              "ruleId": "rules.python.sql-injection",
              "level": "error",
              "message": { "text": "Detected raw SQL query concatenation" },
              "locations": [
                {
                  "physicalLocation": {
                    "artifactLocation": { "uri": "app/db.py" },
                    "region": {
                      "startLine": 45,
                      "startColumn": 8,
                      "endLine": 45,
                      "endColumn": 48
                    }
                  }
                }
              ]
            }
          ]
        }
      ]
    }"#;

    let mut request = create_sample_request();
    request.profile = ScanProfile::Deep;
    let (findings, receipts) = SemgrepAdapter::parse_sarif(sarif_json, &request)
        .expect("Semgrep SARIF must parse successfully");

    assert_eq!(findings.len(), 1);
    assert_eq!(receipts.len(), 1);

    let f = &findings[0];
    assert_eq!(f.engine.id, "semgrep-ce-adapter");
    assert_eq!(f.rule_id, Some("rules.python.sql-injection".to_string()));
    assert_eq!(f.weakness_ids, vec!["CWE-89".to_string()]);
    assert_eq!(f.evidence_certainty, EvidenceCertaintyV1::PatternIndicator);
    assert_eq!(f.target.path, Some("app/db.py".to_string()));
    assert_eq!(f.target.span.as_ref().unwrap().start_line, 45);
    assert_eq!(f.target.span.as_ref().unwrap().start_column, Some(8));
    assert_eq!(f.evidence.len(), 1);
    assert_eq!(f.evidence[0].kind, EvidenceItemKind::SourceSpan);

    assert!(f.validate().is_ok());
    assert!(receipts[0].validate().is_ok());
}

#[test]
fn test_semgrep_json_output_parsing_and_normalization() {
    let semgrep_json = r#"{
      "results": [
        {
          "check_id": "rules.javascript.eval-injection",
          "path": "src/evaluator.js",
          "start": { "line": 12, "col": 4 },
          "end": { "line": 12, "col": 25 },
          "extra": {
            "message": "Use of dangerous eval function",
            "severity": "ERROR",
            "metadata": {
              "cwe": ["CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code"]
            }
          }
        }
      ],
      "paths": {
        "scanned": ["src/evaluator.js"],
        "skipped": []
      }
    }"#;

    let mut request = create_sample_request();
    request.profile = ScanProfile::Deep;
    let (findings, receipts) = SemgrepAdapter::parse_json(semgrep_json, &request)
        .expect("Semgrep JSON must parse successfully");

    assert_eq!(findings.len(), 1);
    assert_eq!(receipts.len(), 1);

    let f = &findings[0];
    assert_eq!(
        f.rule_id,
        Some("rules.javascript.eval-injection".to_string())
    );
    assert_eq!(f.weakness_ids, vec!["CWE-95".to_string()]);
    assert_eq!(f.target.path, Some("src/evaluator.js".to_string()));
    assert_eq!(f.target.span.as_ref().unwrap().start_line, 12);

    assert!(f.validate().is_ok());
    assert!(receipts[0].validate().is_ok());
}

// =========================================================================
// 4. CodeQL Adapter and Strict License Verification Tests
// =========================================================================

#[test]
fn test_codeql_missing_binary_reporting() {
    let adapter = CodeQlAdapter::new().with_binary_path("/missing/codeql");
    assert!(!adapter.is_installed());
    assert_eq!(adapter.installation_state(), Installation::Missing);

    let mut request = create_sample_request();
    request.profile = ScanProfile::Deep;
    let cancel = CancellationToken::new();
    let response = adapter
        .analyze(&request, &cancel)
        .expect("analyze response");

    assert!(matches!(
        response.status,
        EngineStatus::Blocked | EngineStatus::Partial
    ));
    assert_eq!(response.receipts.len(), 1);
    assert_eq!(response.receipts[0].status, CoverageReceiptStatus::NotRun);
    assert!(
        response.receipts[0]
            .reason_codes
            .contains(&ReceiptReasonCode::EngineMissing)
    );
}

#[test]
fn test_codeql_unlicensed_environment_fails_closed() {
    let temp_dir = tempfile::tempdir().expect("temp dir");
    let fake_binary = temp_dir.path().join("codeql");
    fs::write(&fake_binary, b"#!/bin/sh\necho 2.15.0\n").expect("write fake script");

    // Binary exists, but license is unverified / pending
    let adapter = CodeQlAdapter::new()
        .with_binary_path(fake_binary)
        .with_license(CodeQlLicenseConfig::unlicensed());

    assert!(adapter.is_installed());
    assert!(!adapter.is_licensed());
    assert_eq!(adapter.installation_state(), Installation::Unlicensed);

    let mut request = create_sample_request();
    request.profile = ScanProfile::Deep;
    let cancel = CancellationToken::new();

    let response = adapter
        .analyze(&request, &cancel)
        .expect("analyze must return response");

    // Fail closed! Status must be Blocked with AuthBlocked reason
    assert!(matches!(
        response.status,
        EngineStatus::Blocked | EngineStatus::Partial
    ));
    assert!(response.findings.is_empty());
    assert_eq!(response.receipts.len(), 1);

    let receipt = &response.receipts[0];
    assert_eq!(receipt.status, CoverageReceiptStatus::NotRun);
    assert!(
        receipt
            .reason_codes
            .contains(&ReceiptReasonCode::AuthBlocked)
    );
    assert!(receipt.details[0].contains("UnlicensedEnvironment"));
    assert!(receipt.validate().is_ok());

    assert_eq!(response.diagnostics.len(), 1);
    assert_eq!(response.diagnostics[0].code, REASON_UNLICENSED_ENVIRONMENT);
}

#[test]
fn test_codeql_licensed_and_open_source_entitlement_verified() {
    let temp_dir = tempfile::tempdir().expect("temp dir");
    let fake_binary = temp_dir.path().join("codeql");
    fs::write(&fake_binary, b"#!/bin/sh\necho 2.15.0\n").expect("write fake script");

    let adapter = CodeQlAdapter::new()
        .with_binary_path(fake_binary)
        .with_license(CodeQlLicenseConfig::open_source_eligible());

    assert!(adapter.is_installed());
    assert!(adapter.is_licensed());
    assert_eq!(adapter.installation_state(), Installation::Available);
}

#[test]
fn test_codeql_sarif_dataflow_parsing() {
    let codeql_sarif = r#"{
      "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
      "version": "2.1.0",
      "runs": [
        {
          "tool": {
            "driver": {
              "name": "CodeQL",
              "rules": [
                {
                  "id": "js/sql-injection",
                  "properties": {
                    "tags": ["security", "external/cwe/cwe-089"]
                  }
                }
              ]
            }
          },
          "results": [
            {
              "ruleId": "js/sql-injection",
              "level": "error",
              "message": { "text": "Database query depends on untrusted input" },
              "locations": [
                {
                  "physicalLocation": {
                    "artifactLocation": { "uri": "server/handlers.js" },
                    "region": { "startLine": 88, "startColumn": 5, "endLine": 88, "endColumn": 50 }
                  }
                }
              ],
              "codeFlows": [
                {
                  "threadFlows": [
                    {
                      "locations": [
                        {
                          "location": {
                            "physicalLocation": {
                              "artifactLocation": { "uri": "server/handlers.js" },
                              "region": { "startLine": 10 }
                            },
                            "message": { "text": "req.params.id (source)" }
                          }
                        },
                        {
                          "location": {
                            "physicalLocation": {
                              "artifactLocation": { "uri": "server/handlers.js" },
                              "region": { "startLine": 88 }
                            },
                            "message": { "text": "query(sql) (sink)" }
                          }
                        }
                      ]
                    }
                  ]
                }
              ]
            }
          ]
        }
      ]
    }"#;

    let mut request = create_sample_request();
    request.profile = ScanProfile::Deep;
    let (findings, receipts) = CodeQlAdapter::parse_sarif(codeql_sarif, &request)
        .expect("CodeQL SARIF parsing must succeed");

    assert_eq!(findings.len(), 1);
    assert_eq!(receipts.len(), 1);

    let f = &findings[0];
    assert_eq!(f.engine.id, "codeql-adapter");
    assert_eq!(f.weakness_ids, vec!["CWE-089".to_string()]);
    assert_eq!(f.evidence_certainty, EvidenceCertaintyV1::StronglySupported);
    assert_eq!(f.target.path, Some("server/handlers.js".to_string()));
    assert_eq!(f.evidence.len(), 2);
    assert_eq!(f.evidence[0].kind, EvidenceItemKind::SourceSpan);
    assert_eq!(f.evidence[1].kind, EvidenceItemKind::DataflowTrace);
    assert!(
        f.evidence[1]
            .description
            .contains("interprocedural taint flow")
    );

    assert!(f.validate().is_ok());
    assert!(receipts[0].validate().is_ok());
}

// =========================================================================
// 5. Code Property Graph and Joern Adapter Tests
// =========================================================================

#[test]
fn test_cpg_dataflow_path_traversal() {
    let mut builder = CpgBuilder::new();

    let code = r#"
    function process(req, res) {
        const input = req.query.id;
        db.query("SELECT * FROM users WHERE id = " + input);
    }
    "#;

    builder.add_source_file("app.js", code);
    let cpg = builder.build();
    let flows = cpg.find_taint_flows();

    assert_eq!(flows.len(), 1);
    assert_eq!(flows[0].weakness, "CWE-89");
    assert_eq!(flows[0].certainty, TraceCertainty::Confirmed);
    assert!(!flows[0].is_multi_file);
}

#[test]
fn test_joern_adapter_missing_binary() {
    let adapter = JoernAdapter::with_binary_path("/missing/joern");
    assert!(!adapter.is_installed());
    assert_eq!(adapter.installation_state(), Installation::Missing);

    let mut request = create_sample_request();
    request.profile = ScanProfile::Deep;
    let cancel = CancellationToken::new();
    let response = adapter
        .analyze(&request, &cancel)
        .expect("analyze response");

    assert!(matches!(
        response.status,
        EngineStatus::Blocked | EngineStatus::Partial
    ));
    assert_eq!(response.receipts.len(), 1);
    assert_eq!(response.receipts[0].status, CoverageReceiptStatus::NotRun);
    assert!(
        response.receipts[0]
            .reason_codes
            .contains(&ReceiptReasonCode::EngineMissing)
    );
}
