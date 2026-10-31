use bug_killer::mcp::McpServer;
use serde_json::json;
use tempfile::tempdir;

// @lat: [[tests#Test Suite Specifications#MCP Tool Registry Specifications#MCP Tool Registry Parity Tests]]
#[test]
fn test_tool_list_and_dispatch_parity() {
    let dir = tempdir().unwrap();
    let mut server = McpServer::new(dir.path().to_path_buf(), true);

    let tools = server.list_tools();
    assert_eq!(
        tools.len(),
        32,
        "Expected exactly 32 registered MCP tools across all domains"
    );

    for tool in &tools {
        assert!(!tool.name.trim().is_empty(), "Tool name must not be empty");
        assert!(
            !tool.description.trim().is_empty(),
            "Tool description must not be empty for {}",
            tool.name
        );
        assert_eq!(
            tool.input_schema.get("type").and_then(|v| v.as_str()),
            Some("object"),
            "Tool schema must be an object for {}",
            tool.name
        );

        // Call every tool through JSON-RPC tools/call and verify it is recognized (never returns "Unknown tool")
        let call_req = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": tool.name,
                "arguments": {}
            }
        });

        let resp_str = server
            .handle_json_rpc_line(&serde_json::to_string(&call_req).unwrap())
            .expect("Server must reply to tool call");
        let resp: serde_json::Value = serde_json::from_str(&resp_str).unwrap();

        let result = resp.get("result").expect("Must contain result");
        let content = result.get("content").and_then(|c| c.as_array()).unwrap();
        let first_text = content
            .first()
            .and_then(|item| item.get("text"))
            .and_then(|t| t.as_str())
            .unwrap_or("");

        assert!(
            !first_text.contains("Unknown tool"),
            "Tool '{}' in list_tools was not recognized by dispatch: {}",
            tool.name,
            first_text
        );
    }
}

#[test]
fn test_unknown_tool_handling() {
    let dir = tempdir().unwrap();
    let mut server = McpServer::new(dir.path().to_path_buf(), true);

    let call_req = json!({
        "jsonrpc": "2.0",
        "id": 42,
        "method": "tools/call",
        "params": {
            "name": "nonexistent_tool_id",
            "arguments": {}
        }
    });

    let resp_str = server
        .handle_json_rpc_line(&serde_json::to_string(&call_req).unwrap())
        .expect("Server must reply to tool call");
    let resp: serde_json::Value = serde_json::from_str(&resp_str).unwrap();

    let result = resp.get("result").unwrap();
    assert_eq!(result.get("isError").and_then(|v| v.as_bool()), Some(true));
    let text = result["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("Unknown tool: nonexistent_tool_id"));
}

#[test]
fn test_read_only_mode_rejection() {
    let dir = tempdir().unwrap();
    let mut server = McpServer::new(dir.path().to_path_buf(), true);

    // bk.apply_plan
    let apply_req = json!({
        "jsonrpc": "2.0",
        "id": 100,
        "method": "tools/call",
        "params": {
            "name": "bk.apply_plan",
            "arguments": {
                "plan_id": "test-plan",
                "approval_receipt": "receipt-tok"
            }
        }
    });
    let resp_str = server
        .handle_json_rpc_line(&serde_json::to_string(&apply_req).unwrap())
        .unwrap();
    let resp: serde_json::Value = serde_json::from_str(&resp_str).unwrap();
    let text = resp["result"]["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("operating in read-only mode"));

    // bk.rollback
    let rollback_req = json!({
        "jsonrpc": "2.0",
        "id": 101,
        "method": "tools/call",
        "params": {
            "name": "bk.rollback",
            "arguments": {
                "backup_id": "test-backup"
            }
        }
    });
    let resp_str = server
        .handle_json_rpc_line(&serde_json::to_string(&rollback_req).unwrap())
        .unwrap();
    let resp: serde_json::Value = serde_json::from_str(&resp_str).unwrap();
    let text = resp["result"]["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("operating in read-only mode"));
}

#[test]
fn test_workspace_traversal_rejection() {
    let dir = tempdir().unwrap();
    let mut server = McpServer::new(dir.path().to_path_buf(), true);

    let traversal_req = json!({
        "jsonrpc": "2.0",
        "id": 200,
        "method": "tools/call",
        "params": {
            "name": "bk.scan",
            "arguments": {
                "path": "../../etc/passwd"
            }
        }
    });

    let resp_str = server
        .handle_json_rpc_line(&serde_json::to_string(&traversal_req).unwrap())
        .unwrap();
    let resp: serde_json::Value = serde_json::from_str(&resp_str).unwrap();
    let text = resp["result"]["content"][0]["text"].as_str().unwrap();
    assert!(
        text.contains("Security Boundary Violation")
            || text.contains("escapes MCP workspace")
            || text.contains("Scan path is unavailable"),
        "Unexpected error text: {}",
        text
    );
}

#[test]
fn test_missing_and_invalid_arguments() {
    let dir = tempdir().unwrap();
    let mut server = McpServer::new(dir.path().to_path_buf(), true);

    // bk.cve_triage requires cve_id
    let req = json!({
        "jsonrpc": "2.0",
        "id": 300,
        "method": "tools/call",
        "params": { "name": "bk.cve_triage", "arguments": {} }
    });
    let resp: serde_json::Value = serde_json::from_str(
        &server
            .handle_json_rpc_line(&serde_json::to_string(&req).unwrap())
            .unwrap(),
    )
    .unwrap();
    assert!(
        resp["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("Missing required argument 'cve_id'")
    );

    // bugkiller_probe_authorized requires authorized=true
    let req = json!({
        "jsonrpc": "2.0",
        "id": 301,
        "method": "tools/call",
        "params": { "name": "bugkiller_probe_authorized", "arguments": { "url": "http://localhost:8080" } }
    });
    let resp: serde_json::Value = serde_json::from_str(
        &server
            .handle_json_rpc_line(&serde_json::to_string(&req).unwrap())
            .unwrap(),
    )
    .unwrap();
    assert!(
        resp["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("Authorization Required")
    );

    // bugkiller_propose_fix requires finding_id
    let req = json!({
        "jsonrpc": "2.0",
        "id": 302,
        "method": "tools/call",
        "params": { "name": "bugkiller_propose_fix", "arguments": {} }
    });
    let resp: serde_json::Value = serde_json::from_str(
        &server
            .handle_json_rpc_line(&serde_json::to_string(&req).unwrap())
            .unwrap(),
    )
    .unwrap();
    assert!(
        resp["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("finding_id is required")
    );

    // bugkiller_room_status requires run_id
    let req = json!({
        "jsonrpc": "2.0",
        "id": 303,
        "method": "tools/call",
        "params": { "name": "bugkiller_room_status", "arguments": {} }
    });
    let resp: serde_json::Value = serde_json::from_str(
        &server
            .handle_json_rpc_line(&serde_json::to_string(&req).unwrap())
            .unwrap(),
    )
    .unwrap();
    assert!(
        resp["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("run_id is required")
    );
}

#[test]
fn test_notification_and_protocol_methods() {
    let dir = tempdir().unwrap();
    let mut server = McpServer::new(dir.path().to_path_buf(), true);

    // Notification: no id and method starts with notifications/ -> returns None
    let notif = json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized"
    });
    assert!(
        server
            .handle_json_rpc_line(&serde_json::to_string(&notif).unwrap())
            .is_none(),
        "Notifications must not generate responses"
    );

    // Initialize method
    let init = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {}
    });
    let resp: serde_json::Value = serde_json::from_str(
        &server
            .handle_json_rpc_line(&serde_json::to_string(&init).unwrap())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(resp["result"]["serverInfo"]["name"], "bug-killer");

    // Ping method
    let ping = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "ping"
    });
    let resp: serde_json::Value = serde_json::from_str(
        &server
            .handle_json_rpc_line(&serde_json::to_string(&ping).unwrap())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(resp["result"], json!({}));

    // Method not found
    let unknown = json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "unknown/method"
    });
    let resp: serde_json::Value = serde_json::from_str(
        &server
            .handle_json_rpc_line(&serde_json::to_string(&unknown).unwrap())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(resp["error"]["code"], -32601);
}
