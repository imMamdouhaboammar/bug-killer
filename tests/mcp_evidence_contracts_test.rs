use bug_killer::mcp::McpServer;
use serde_json::json;
use std::path::PathBuf;

#[test]
fn test_mcp_scan_and_findings_with_evidence_certainty() {
    let workspace = PathBuf::from(".");
    let mut server = McpServer::new(workspace, true);

    // Test bk.scan with taint: true
    let scan_res = server
        .handle_json_rpc_line(
            &json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "bk.scan",
                    "arguments": {
                        "path": "tests/fixtures/sast",
                        "taint": true
                    }
                }
            })
            .to_string(),
        )
        .expect("Should get JSON-RPC response");

    let val: serde_json::Value = serde_json::from_str(&scan_res).unwrap();
    assert!(val.get("error").is_none());

    let content = val["result"]["content"][0]["text"].as_str().unwrap();
    let report: serde_json::Value = serde_json::from_str(content).unwrap();

    // Verify scan report contains findings and receipts
    assert!(report["is_vulnerable"].as_bool().unwrap());
    let receipts = report["coverage"]["receipts"].as_array().unwrap();
    assert!(
        receipts.iter().any(|r| r["scanner_id"] == "taint-sast"),
        "Scan coverage must include taint-sast receipt"
    );

    // Test bk.findings filtering by evidence_certainty
    let findings_res = server
        .handle_json_rpc_line(
            &json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "bk.findings",
                    "arguments": {
                        "path": "tests/fixtures/sast",
                        "evidence_certainty": "PatternIndicator"
                    }
                }
            })
            .to_string(),
        )
        .expect("Should get JSON-RPC response");

    let findings_val: serde_json::Value = serde_json::from_str(&findings_res).unwrap();
    let findings_content = findings_val["result"]["content"][0]["text"]
        .as_str()
        .unwrap();
    let findings_report: serde_json::Value = serde_json::from_str(findings_content).unwrap();

    assert!(findings_report["total_matches"].as_u64().unwrap() >= 4);
    for finding in findings_report["findings"].as_array().unwrap() {
        assert_eq!(
            finding["evidence_certainty"].as_str().unwrap(),
            "PatternIndicator"
        );
    }
}

#[test]
fn test_mcp_read_only_mode_prevents_mutating_actions() {
    let workspace = PathBuf::from(".");
    let mut server = McpServer::new(workspace, true); // read_only = true

    let apply_res = server
        .handle_json_rpc_line(
            &json!({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "bk.apply_plan",
                    "arguments": {
                        "plan_id": "test-plan",
                        "approval_receipt": "receipt"
                    }
                }
            })
            .to_string(),
        )
        .expect("Should get response");

    let val: serde_json::Value = serde_json::from_str(&apply_res).unwrap();
    let is_err = val["result"]["isError"].as_bool().unwrap_or(false);
    assert!(
        is_err,
        "Mutating operations in read-only MCP server must return isError = true"
    );
}
