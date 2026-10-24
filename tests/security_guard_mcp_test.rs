use bug_killer::mcp::McpServer;
use bug_killer::security_guard::SecurityGuard;
use serde_json::{Value, json};
use std::fs;
use tempfile::tempdir;

#[test]
fn test_mcp_tools_list_includes_all_bugkiller_tools() {
    let dir = tempdir().unwrap();
    let mut server = McpServer::new(dir.path().to_path_buf(), true);

    let list_req = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list"
    });

    let resp_str = server
        .handle_json_rpc_line(&list_req.to_string())
        .expect("tools/list response");
    let resp: Value = serde_json::from_str(&resp_str).unwrap();

    let tools = resp["result"]["tools"].as_array().expect("tools array");
    let tool_names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();

    let expected_tools = [
        "bugkiller_security_status",
        "bugkiller_scan_project",
        "bugkiller_scan_changed_files",
        "bugkiller_list_findings",
        "bugkiller_explain_finding",
        "bugkiller_get_rule",
        "bugkiller_propose_fix",
        "bugkiller_verify_fix",
        "bugkiller_get_coverage",
        "bugkiller_security_guidance",
    ];

    for expected in &expected_tools {
        assert!(
            tool_names.contains(expected),
            "Expected tool '{}' not found in tools/list: {:?}",
            expected,
            tool_names
        );
    }
}

#[test]
fn test_mcp_security_guard_tools_workflow() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    // 1. Initialize project via SecurityGuard
    SecurityGuard::init(root, false).unwrap();

    // Create a vulnerable Dockerfile (BK-AI-INF-001)
    let dockerfile_path = root.join("Dockerfile");
    fs::write(
        &dockerfile_path,
        "FROM alpine:3.18\nUSER root\nCMD [\"sh\"]\n",
    )
    .unwrap();

    let mut server = McpServer::new(root.to_path_buf(), false);

    // 2. Test bugkiller_security_status
    let status_req = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "bugkiller_security_status",
            "arguments": { "path": "." }
        }
    });
    let resp_str = server
        .handle_json_rpc_line(&status_req.to_string())
        .unwrap();
    let resp: Value = serde_json::from_str(&resp_str).unwrap();
    assert_eq!(resp["result"]["isError"], false);
    let status_val: Value =
        serde_json::from_str(resp["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(status_val["is_initialized"], true);

    // 3. Test bugkiller_scan_project
    let scan_req = json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "bugkiller_scan_project",
            "arguments": { "path": "." }
        }
    });
    let resp_str = server.handle_json_rpc_line(&scan_req.to_string()).unwrap();
    let resp: Value = serde_json::from_str(&resp_str).unwrap();
    assert_eq!(resp["result"]["isError"], false);
    let scan_val: Value =
        serde_json::from_str(resp["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    let findings = scan_val["findings"].as_array().expect("findings array");
    assert!(
        !findings.is_empty(),
        "Scan should detect Dockerfile finding"
    );
    let finding_id = findings[0]["id"].as_str().unwrap().to_string();

    // 4. Test bugkiller_list_findings with filter
    let list_findings_req = json!({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {
            "name": "bugkiller_list_findings",
            "arguments": {
                "path": ".",
                "severity": "high"
            }
        }
    });
    let resp_str = server
        .handle_json_rpc_line(&list_findings_req.to_string())
        .unwrap();
    let resp: Value = serde_json::from_str(&resp_str).unwrap();
    assert_eq!(resp["result"]["isError"], false);
    let list_val: Value =
        serde_json::from_str(resp["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert!(list_val["total_findings"].as_u64().unwrap() >= 1);

    // 5. Test bugkiller_explain_finding
    let explain_req = json!({
        "jsonrpc": "2.0",
        "id": 5,
        "method": "tools/call",
        "params": {
            "name": "bugkiller_explain_finding",
            "arguments": {
                "path": ".",
                "finding_id": finding_id
            }
        }
    });
    let resp_str = server
        .handle_json_rpc_line(&explain_req.to_string())
        .unwrap();
    let resp: Value = serde_json::from_str(&resp_str).unwrap();
    assert_eq!(resp["result"]["isError"], false);
    let explain_val: Value =
        serde_json::from_str(resp["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(explain_val["finding_id"], finding_id);
    assert!(
        !explain_val["remediation_guidance"]
            .as_str()
            .unwrap()
            .is_empty()
    );

    // 6. Test bugkiller_get_rule
    let rule_req = json!({
        "jsonrpc": "2.0",
        "id": 6,
        "method": "tools/call",
        "params": {
            "name": "bugkiller_get_rule",
            "arguments": {
                "rule_id": "BK-AI-INJ-001"
            }
        }
    });
    let resp_str = server.handle_json_rpc_line(&rule_req.to_string()).unwrap();
    let resp: Value = serde_json::from_str(&resp_str).unwrap();
    assert_eq!(resp["result"]["isError"], false);
    let rule_val: Value =
        serde_json::from_str(resp["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(rule_val["rule_id"], "BK-AI-INJ-001");
    assert_eq!(
        rule_val["category"],
        "2.1 Injection and interpreter boundaries"
    );

    // 7. Test bugkiller_propose_fix
    let propose_req = json!({
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": {
            "name": "bugkiller_propose_fix",
            "arguments": {
                "path": ".",
                "finding_id": finding_id
            }
        }
    });
    let resp_str = server
        .handle_json_rpc_line(&propose_req.to_string())
        .unwrap();
    let resp: Value = serde_json::from_str(&resp_str).unwrap();
    assert_eq!(resp["result"]["isError"], false);
    let proposal_val: Value =
        serde_json::from_str(resp["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert!(
        proposal_val["replacement_content"]
            .as_str()
            .unwrap()
            .contains("USER node")
    );

    // 8. Test bugkiller_verify_fix
    let verify_req = json!({
        "jsonrpc": "2.0",
        "id": 8,
        "method": "tools/call",
        "params": {
            "name": "bugkiller_verify_fix",
            "arguments": { "path": "." }
        }
    });
    let resp_str = server
        .handle_json_rpc_line(&verify_req.to_string())
        .unwrap();
    let resp: Value = serde_json::from_str(&resp_str).unwrap();
    assert_eq!(resp["result"]["isError"], false);
    let verify_val: Value =
        serde_json::from_str(resp["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(verify_val["is_clean"], false); // still vulnerable before patch applied

    // 9. Test bugkiller_get_coverage
    let coverage_req = json!({
        "jsonrpc": "2.0",
        "id": 9,
        "method": "tools/call",
        "params": {
            "name": "bugkiller_get_coverage",
            "arguments": { "path": "." }
        }
    });
    let resp_str = server
        .handle_json_rpc_line(&coverage_req.to_string())
        .unwrap();
    let resp: Value = serde_json::from_str(&resp_str).unwrap();
    assert_eq!(resp["result"]["isError"], false);
    let cov_val: Value =
        serde_json::from_str(resp["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert!(cov_val["files_assessed"].as_u64().unwrap() >= 1);
    assert!(!cov_val["rules_evaluated"].as_array().unwrap().is_empty());

    // 10. Test bugkiller_security_guidance
    let guidance_req = json!({
        "jsonrpc": "2.0",
        "id": 10,
        "method": "tools/call",
        "params": {
            "name": "bugkiller_security_guidance",
            "arguments": {
                "task": "file_upload_handler",
                "language": "typescript"
            }
        }
    });
    let resp_str = server
        .handle_json_rpc_line(&guidance_req.to_string())
        .unwrap();
    let resp: Value = serde_json::from_str(&resp_str).unwrap();
    assert_eq!(resp["result"]["isError"], false);
    let guid_val: Value =
        serde_json::from_str(resp["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(guid_val["task_query"], "file_upload_handler");
    assert!(
        !guid_val["recommended_safe_patterns"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn test_mcp_read_only_mode_blocks_mutating_actions() {
    let dir = tempdir().unwrap();
    let root = dir.path();
    let mut server = McpServer::new(root.to_path_buf(), true); // Read-only server

    let apply_req = json!({
        "jsonrpc": "2.0",
        "id": 20,
        "method": "tools/call",
        "params": {
            "name": "bk.apply_plan",
            "arguments": {
                "plan_id": "PLAN-001",
                "approval_receipt": "{}"
            }
        }
    });

    let resp_str = server.handle_json_rpc_line(&apply_req.to_string()).unwrap();
    let resp: Value = serde_json::from_str(&resp_str).unwrap();
    assert_eq!(resp["result"]["isError"], true);
    assert!(
        resp["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("read-only mode"),
        "Mutating call must fail with read-only error"
    );
}
