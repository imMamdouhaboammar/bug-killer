use std::path::PathBuf;

use bug_killer::deep::broker::{
    CapabilityKind, ExecutionTransport, Installation, ToolCapabilityBroker,
};
use bug_killer::deep::cve_mcp::CveMcpAdapter;
use bug_killer::engine::adapter::AnalyzerAdapter;
use bug_killer::engine::protocol::{
    AnalysisRequest, CoverageReceiptStatus, EngineStatus, NormalizedSeverity,
};
use bug_killer::engine::runner::CancellationToken;
use bug_killer::mcp::server::McpServer;
use bug_killer::types::ScanProfile;
use serde_json::Value;

const DUMMY_HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

#[test]
fn test_cve_mcp_adapter_initialization_and_discovery() {
    let adapter = CveMcpAdapter::new();

    assert_eq!(adapter.engine_id(), "cve-mcp-adapter");
    assert_eq!(adapter.engine_version(), "0.2.0");
    assert!(
        adapter.is_installed(),
        "cve-mcp-server service must be discoverable in services/"
    );
    assert_eq!(adapter.installation_state(), Installation::Available);
    assert!(adapter.can_handle_profile(ScanProfile::Deep));
    assert!(adapter.can_handle_profile(ScanProfile::Quick));
    assert!(adapter.can_handle_language("python"));
    assert!(adapter.can_handle_language("rust"));
    assert!(adapter.can_handle_language("php"));
}

#[test]
fn test_broker_cve_mcp_capability_discovery_and_registration() {
    let mut broker = ToolCapabilityBroker::new();
    let cap = broker.discover_tool("cve-mcp");

    assert_eq!(cap.tool_id, "cve-mcp-adapter");
    assert_eq!(cap.adapter_version, "0.2.0");
    assert_eq!(cap.execution.transport, ExecutionTransport::Mcp);
    assert!(cap.capabilities.kinds.contains(&CapabilityKind::Advisory));
    assert!(cap.capabilities.kinds.contains(&CapabilityKind::Context));
    assert!(cap.capabilities.kinds.contains(&CapabilityKind::Sca));
    assert!(
        cap.validate().is_ok(),
        "Discovered capability must satisfy schema v1.0"
    );

    // All tools discovery includes cve-mcp
    let all = broker.discover_all();
    assert!(
        all.iter().any(|c| c.tool_id == "cve-mcp-adapter"),
        "discover_all() must include cve-mcp-adapter"
    );

    // Aliases resolve properly
    assert!(broker.get_capability("cve-mcp").is_some());
    assert!(broker.get_capability("cve-mcp-adapter").is_some());
    assert!(broker.get_capability("cve-mcp-server").is_some());
}

#[test]
fn test_cve_mcp_risk_score_deterministic_formula() {
    // 1. KEV Hard Override: Even with low CVSS and low EPSS, KEV membership sets floor to 76.0 and CRITICAL
    let (score_kev, label_kev, urgency_kev, _) =
        CveMcpAdapter::calculate_risk_score(Some(4.0), Some(0.05), true, "NONE", None);
    assert!(score_kev >= 76.0);
    assert_eq!(label_kev, "CRITICAL");
    assert_eq!(urgency_kev, "PATCH WITHIN 24 HOURS");

    // 2. Maximum Threat: Critical CVSS + High EPSS + KEV + Weaponized PoC + Recent Disclosure
    let (score_max, label_max, urgency_max, boosters) =
        CveMcpAdapter::calculate_risk_score(Some(9.8), Some(0.92), true, "WEAPONIZED", Some(2));
    assert_eq!(score_max, 100.0);
    assert_eq!(label_max, "CRITICAL");
    assert_eq!(urgency_max, "PATCH IMMEDIATELY");
    assert!(boosters.contains(&"KEV+PoC".to_string()));
    assert!(boosters.contains(&"CVSS>=9+EPSS>0.7".to_string()));
    assert!(boosters.contains(&"Published<7days".to_string()));

    // 3. Low Risk Vulnerability: No KEV, No PoC, Low CVSS, Low EPSS
    let (score_low, label_low, urgency_low, _) =
        CveMcpAdapter::calculate_risk_score(Some(3.5), Some(0.01), false, "NONE", Some(180));
    assert!(score_low <= 25.0);
    assert_eq!(label_low, "LOW");
    assert_eq!(urgency_low, "SCHEDULE FOR NEXT CYCLE");
}

#[test]
fn test_cve_triage_and_intelligence_endpoints() {
    let adapter = CveMcpAdapter::new();

    // PHP2Shell Triage
    let triage_php = adapter
        .triage_cve("CVE-2026-109618")
        .expect("Triage must succeed");
    assert_eq!(triage_php.cve_id, "CVE-2026-109618");
    assert!(triage_php.in_kev);
    assert_eq!(triage_php.risk_label, "CRITICAL");
    assert!(triage_php.risk_score >= 76.0);
    assert!(triage_php.recommendation.contains("CISA KEV"));

    // Node2Shell Triage
    let triage_node = adapter
        .triage_cve("CVE-2026-111497")
        .expect("Triage must succeed");
    assert_eq!(triage_node.cve_id, "CVE-2026-111497");
    assert!(triage_node.risk_score >= 50.0);

    // KEV Catalog Check
    let kev_positive = adapter
        .check_kev("CVE-2026-109618")
        .expect("KEV check must succeed");
    assert!(kev_positive.in_kev);
    assert!(kev_positive.due_date.is_some());

    let kev_negative = adapter
        .check_kev("CVE-2020-000000")
        .expect("KEV check must succeed");
    assert!(!kev_negative.in_kev);
    assert!(kev_negative.due_date.is_none());

    // EPSS Scoring
    let epss = adapter
        .get_epss("CVE-2026-109618")
        .expect("EPSS must succeed");
    assert_eq!(epss.cve_id, "CVE-2026-109618");
    assert!(epss.probability > 0.8);
    assert!(epss.percentile > 0.9);
}

#[test]
fn test_cve_mcp_analyzer_adapter_execution_receipt() {
    let adapter = CveMcpAdapter::new();
    let request = AnalysisRequest::new(
        "run-cve-triage-101",
        "cve-mcp-adapter",
        "/tmp/snapshot",
        DUMMY_HASH,
        ScanProfile::Deep,
        vec!["CVE-2026-109618".to_string()],
        vec!["src/index.php".to_string()],
    );

    let cancel = CancellationToken::new();
    let response = adapter
        .analyze(&request, &cancel)
        .expect("analyze must succeed");

    assert_eq!(response.status, EngineStatus::Completed);
    assert_eq!(response.findings.len(), 1);
    assert_eq!(response.findings[0].advisory_ids[0], "CVE-2026-109618");
    assert_eq!(response.findings[0].severity, NormalizedSeverity::Critical);
    assert!(
        response.findings[0]
            .title
            .contains("Threat Intelligence Triage")
    );

    assert_eq!(response.receipts.len(), 1);
    let receipt = &response.receipts[0];
    assert_eq!(receipt.status, CoverageReceiptStatus::Evaluated);
    assert_eq!(receipt.counts.items_examined, 1);
    assert!(receipt.validate().is_ok());

    // Cancellation test
    cancel.cancel();
    let cancelled_response = adapter
        .analyze(&request, &cancel)
        .expect("cancelled analyze must return response");
    assert_eq!(cancelled_response.status, EngineStatus::Cancelled);
    assert_eq!(
        cancelled_response.receipts[0].status,
        CoverageReceiptStatus::NotRun
    );
}

#[test]
fn test_mcp_server_cve_tools_json_rpc_integration() {
    let mut server = McpServer::new(PathBuf::from("."), true);

    // 1. Tool catalog contains the 3 new CVE tools
    let tools = server.list_tools();
    assert!(tools.iter().any(|t| t.name == "bk.cve_triage"));
    assert!(tools.iter().any(|t| t.name == "bk.cve_lookup"));
    assert!(tools.iter().any(|t| t.name == "bk.cve_kev_check"));

    // 2. Call bk.cve_triage via JSON-RPC
    let triage_req = r#"{
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "bk.cve_triage",
            "arguments": {
                "cve_id": "CVE-2026-109618"
            }
        }
    }"#;

    let res_str = server
        .handle_json_rpc_line(triage_req)
        .expect("Server must reply");
    let res: Value = serde_json::from_str(&res_str).expect("Valid JSON-RPC response");
    assert_eq!(res["id"], 1);
    assert_eq!(res["result"]["isError"], false);
    let content_text = res["result"]["content"][0]["text"].as_str().unwrap();
    assert!(content_text.contains("CVE-2026-109618"));
    assert!(content_text.contains("CRITICAL"));

    // 3. Call bk.cve_kev_check via JSON-RPC
    let kev_req = r#"{
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "bk.cve_kev_check",
            "arguments": {
                "cve_id": "CVE-2026-109618"
            }
        }
    }"#;

    let res_kev_str = server
        .handle_json_rpc_line(kev_req)
        .expect("Server must reply");
    let res_kev: Value = serde_json::from_str(&res_kev_str).expect("Valid JSON-RPC response");
    assert_eq!(res_kev["id"], 2);
    assert_eq!(res_kev["result"]["isError"], false);
    let kev_content = res_kev["result"]["content"][0]["text"].as_str().unwrap();
    assert!(kev_content.contains("\"in_kev\": true") || kev_content.contains("\"in_kev\":true"));
}
