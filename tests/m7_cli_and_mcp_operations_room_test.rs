use bug_killer::mcp::McpServer;
use serde_json::Value;
use std::path::PathBuf;

fn setup_mcp_server() -> McpServer {
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    McpServer::new(workspace, true)
}

#[test]
fn test_mcp_server_lists_all_operations_room_tools() {
    let server = setup_mcp_server();
    let tools = server.list_tools();
    let tool_names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();

    assert!(tool_names.contains(&"bugkiller_engine_capabilities"));
    assert!(tool_names.contains(&"bugkiller_room_plan"));
    assert!(tool_names.contains(&"bugkiller_room_status"));
    assert!(tool_names.contains(&"bugkiller_research_plan"));
    assert!(tool_names.contains(&"bugkiller_research_execute"));
    assert!(tool_names.contains(&"bugkiller_research_verify"));
    assert!(tool_names.contains(&"bugkiller_disclosure_draft"));
    assert!(tool_names.contains(&"bugkiller_inventory"));
}

#[test]
fn test_mcp_engine_capabilities_dispatch() {
    let mut server = setup_mcp_server();
    let req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": "test-req-engine-1",
        "method": "tools/call",
        "params": {
            "name": "bugkiller_engine_capabilities",
            "arguments": {
                "path": "."
            }
        }
    });

    let resp_str = server
        .handle_json_rpc_line(&req.to_string())
        .expect("Server must reply to bugkiller_engine_capabilities");
    let resp: Value = serde_json::from_str(&resp_str).expect("Valid JSON-RPC response");

    assert_eq!(resp["id"], "test-req-engine-1");
    let content = &resp["result"]["content"][0]["text"];
    let data: Value = serde_json::from_str(content.as_str().unwrap()).unwrap();
    assert!(data["total_tools"].as_u64().unwrap() >= 4);
    assert!(data["capabilities"].is_array());
}

#[test]
fn test_mcp_room_plan_and_status_dispatch() {
    let mut server = setup_mcp_server();

    // 1. Plan
    let plan_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": "test-req-room-1",
        "method": "tools/call",
        "params": {
            "name": "bugkiller_room_plan",
            "arguments": {
                "path": ".",
                "goal": "prevention",
                "profile": "project"
            }
        }
    });

    let plan_resp_str = server
        .handle_json_rpc_line(&plan_req.to_string())
        .expect("Server must reply to bugkiller_room_plan");
    let plan_resp: Value = serde_json::from_str(&plan_resp_str).unwrap();
    let plan_data: Value =
        serde_json::from_str(plan_resp["result"]["content"][0]["text"].as_str().unwrap()).unwrap();

    assert_eq!(plan_data["status"], "PLANNED");
    assert_eq!(plan_data["goal"], "prevention");
    assert!(plan_data["plan_id"].as_str().unwrap().starts_with("plan-"));

    // 2. Status
    let status_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": "test-req-room-2",
        "method": "tools/call",
        "params": {
            "name": "bugkiller_room_status",
            "arguments": {
                "run_id": "run-xyz-999"
            }
        }
    });

    let status_resp_str = server
        .handle_json_rpc_line(&status_req.to_string())
        .expect("Server must reply to bugkiller_room_status");
    let status_resp: Value = serde_json::from_str(&status_resp_str).unwrap();
    let status_data: Value = serde_json::from_str(
        status_resp["result"]["content"][0]["text"]
            .as_str()
            .unwrap(),
    )
    .unwrap();

    assert_eq!(status_data["run_id"], "run-xyz-999");
    assert_eq!(status_data["state"], "COMPLETED");
}

#[test]
fn test_mcp_research_hunter_cycle() {
    let mut server = setup_mcp_server();

    // 1. Research Plan
    let plan_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": "test-req-research-1",
        "method": "tools/call",
        "params": {
            "name": "bugkiller_research_plan",
            "arguments": {
                "path": "."
            }
        }
    });

    let plan_resp_str = server
        .handle_json_rpc_line(&plan_req.to_string())
        .expect("Server must reply to bugkiller_research_plan");
    let plan_resp: Value = serde_json::from_str(&plan_resp_str).unwrap();
    let plan_data: Value =
        serde_json::from_str(plan_resp["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(plan_data["hypotheses_count"], 8);

    // 2. Research Execute
    let exec_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": "test-req-research-2",
        "method": "tools/call",
        "params": {
            "name": "bugkiller_research_execute",
            "arguments": {
                "candidate_id": "cand-cwe787-001",
                "iterations": 50
            }
        }
    });

    let exec_resp_str = server
        .handle_json_rpc_line(&exec_req.to_string())
        .expect("Server must reply to bugkiller_research_execute");
    let exec_resp: Value = serde_json::from_str(&exec_resp_str).unwrap();
    let exec_data: Value =
        serde_json::from_str(exec_resp["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(exec_data["status"], "EXECUTED");
    assert_eq!(exec_data["iterations_completed"], 50);

    // 3. Research Verify
    let verify_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": "test-req-research-3",
        "method": "tools/call",
        "params": {
            "name": "bugkiller_research_verify",
            "arguments": {
                "candidate_id": "cand-cwe787-001"
            }
        }
    });

    let verify_resp_str = server
        .handle_json_rpc_line(&verify_req.to_string())
        .expect("Server must reply to bugkiller_research_verify");
    let verify_resp: Value = serde_json::from_str(&verify_resp_str).unwrap();
    let verify_data: Value = serde_json::from_str(
        verify_resp["result"]["content"][0]["text"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(verify_data["verified"], true);
    assert_eq!(verify_data["proof_method"], "PROPERTY_INVARIANT");
}

#[test]
fn test_mcp_disclosure_draft_and_inventory() {
    let mut server = setup_mcp_server();

    // Prepare isolated fixture within workspace root
    let tmp_rel = "tests/fixtures/test-inv-m7";
    let tmp_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(tmp_rel);
    let _ = std::fs::create_dir_all(&tmp_dir);
    let pkg_json = tmp_dir.join("package.json");
    std::fs::write(
        &pkg_json,
        r#"{"name": "test-pkg-m7", "version": "1.0.0", "dependencies": {"express": "4.18.2"}}"#,
    )
    .unwrap();

    // 1. Disclosure Draft
    let draft_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": "test-req-draft-1",
        "method": "tools/call",
        "params": {
            "name": "bugkiller_disclosure_draft",
            "arguments": {
                "finding_id": "finding-test-m7-001",
                "recipient": "security@target.example",
                "path": tmp_rel
            }
        }
    });

    let draft_resp_str = server
        .handle_json_rpc_line(&draft_req.to_string())
        .expect("Server must reply to bugkiller_disclosure_draft");
    let draft_resp: Value = serde_json::from_str(&draft_resp_str).unwrap();
    let draft_data: Value =
        serde_json::from_str(draft_resp["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(draft_data["finding_id"], "finding-test-m7-001");
    let md = draft_data["github_pvr_markdown"].as_str().unwrap();
    assert!(md.contains("# [PVR Draft]"));
    assert!(md.contains("security@target.example"));

    // 2. Inventory (within workspace boundary)
    let inv_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": "test-req-inv-1",
        "method": "tools/call",
        "params": {
            "name": "bugkiller_inventory",
            "arguments": {
                "path": tmp_rel
            }
        }
    });

    let inv_resp_str = server
        .handle_json_rpc_line(&inv_req.to_string())
        .expect("Server must reply to bugkiller_inventory");
    let inv_resp: Value = serde_json::from_str(&inv_resp_str).unwrap();
    let inv_data: Value =
        serde_json::from_str(inv_resp["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert!(inv_data["total_discovered_packages"].as_u64().unwrap() > 0);
    assert!(inv_data["packages"].is_array());
    let _ = std::fs::remove_dir_all(&tmp_dir);
}

#[test]
fn test_cli_operations_room_commands() {
    let tmp = tempfile::tempdir().unwrap();
    let pkg_json = tmp.path().join("package.json");
    std::fs::write(
        &pkg_json,
        r#"{"name": "demo-app", "version": "1.0.0", "dependencies": {"express": "4.18.2"}}"#,
    )
    .unwrap();

    // 1. bk engine doctor --json
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_bug-killer"))
        .args(["engine", "doctor", "--json"])
        .output()
        .expect("bk engine doctor should run");
    assert!(out.status.success());
    let doc: Value = serde_json::from_slice(&out.stdout).expect("Valid JSON");
    assert!(doc.is_array());

    // 2. bk engine list --json
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_bug-killer"))
        .args(["engine", "list", "--json"])
        .output()
        .expect("bk engine list should run");
    assert!(out.status.success());
    let list: Value = serde_json::from_slice(&out.stdout).expect("Valid JSON");
    assert!(list.as_array().unwrap().len() >= 4);

    // 3. bk engine explain --goal prevention --target <tmp> --json
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_bug-killer"))
        .args([
            "engine",
            "explain",
            "--goal",
            "prevention",
            "--target",
            tmp.path().to_str().unwrap(),
            "--json",
        ])
        .output()
        .expect("bk engine explain should run");
    assert!(out.status.success());

    // 4. bk room plan --goal prevention --profile project --json
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_bug-killer"))
        .args([
            "room",
            "plan",
            tmp.path().to_str().unwrap(),
            "--goal",
            "prevention",
            "--profile",
            "project",
            "--json",
        ])
        .output()
        .expect("bk room plan should run");
    assert!(out.status.success());
    let plan: Value = serde_json::from_slice(&out.stdout).expect("Valid JSON");
    assert_eq!(plan["status"], "PLANNED");

    // 5. bk room status run-test-123 --json
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_bug-killer"))
        .args(["room", "status", "run-test-123", "--json"])
        .output()
        .expect("bk room status should run");
    assert!(out.status.success());
    let status: Value = serde_json::from_slice(&out.stdout).expect("Valid JSON");
    assert_eq!(status["run_id"], "run-test-123");

    // 6. bk hunter plan --json
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_bug-killer"))
        .args(["hunter", "plan", tmp.path().to_str().unwrap(), "--json"])
        .output()
        .expect("bk hunter plan should run");
    assert!(out.status.success());
    let hunter_plan: Value = serde_json::from_slice(&out.stdout).expect("Valid JSON");
    assert_eq!(hunter_plan["hypotheses_count"], 8);

    // 7. bk hunter run --plan plan-test-1 --sandbox-only --json
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_bug-killer"))
        .args([
            "hunter",
            "run",
            "--plan",
            "plan-test-1",
            "--sandbox-only",
            "--json",
        ])
        .output()
        .expect("bk hunter run should run");
    assert!(out.status.success());

    // 8. bk hunter verify cand-cwe787-001 --offline --json
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_bug-killer"))
        .args(["hunter", "verify", "cand-cwe787-001", "--offline", "--json"])
        .output()
        .expect("bk hunter verify should run");
    assert!(out.status.success());
    let verify: Value = serde_json::from_slice(&out.stdout).expect("Valid JSON");
    assert_eq!(verify["verified"], true);

    // 9. bk disclose draft finding-test-m7-001 <tmp> --private --json
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_bug-killer"))
        .args([
            "disclose",
            "draft",
            "finding-test-m7-001",
            tmp.path().to_str().unwrap(),
            "--private",
            "--json",
        ])
        .output()
        .expect("bk disclose draft should run");
    assert!(out.status.success());

    // 10. bk advisory sync --offline-cache <tmp/cache> --json
    let cache_dir = tmp.path().join("cache");
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_bug-killer"))
        .args([
            "advisory",
            "sync",
            "--offline-cache",
            cache_dir.to_str().unwrap(),
            "--json",
        ])
        .output()
        .expect("bk advisory sync should run");
    assert!(out.status.success());

    // 11. bk advisory status --json
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_bug-killer"))
        .args(["advisory", "status", tmp.path().to_str().unwrap(), "--json"])
        .output()
        .expect("bk advisory status should run");
    assert!(out.status.success());

    // 12. bk inventory --json
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_bug-killer"))
        .args(["inventory", tmp.path().to_str().unwrap(), "--json"])
        .output()
        .expect("bk inventory should run");
    assert!(out.status.success());
    let inv: Value = serde_json::from_slice(&out.stdout).expect("Valid JSON");
    assert!(inv["total_discovered_packages"].as_u64().unwrap() >= 1);

    // 13. bk security coverage --per-rule --json
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_bug-killer"))
        .args([
            "security",
            "coverage",
            tmp.path().to_str().unwrap(),
            "--per-rule",
            "--json",
        ])
        .output()
        .expect("bk security coverage should run");
    assert!(out.status.success());
    let cov: Value = serde_json::from_slice(&out.stdout).expect("Valid JSON");
    assert!(cov["per_rule_coverage"].is_object());

    // 14. bk security scan --report-version 2 --json
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_bug-killer"))
        .args([
            "security",
            "scan",
            tmp.path().to_str().unwrap(),
            "--profile",
            "quick",
            "--report-version",
            "2",
            "--json",
        ])
        .output()
        .expect("bk security scan v2 should run");
    assert!(out.status.success());
    let scan_v2: Value = serde_json::from_slice(&out.stdout).expect("Valid JSON");
    assert_eq!(scan_v2["contract_version"], "2.0");

    // 15. bk security scan --exit-contract v2
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_bug-killer"))
        .args([
            "security",
            "scan",
            tmp.path().to_str().unwrap(),
            "--profile",
            "quick",
            "--exit-contract",
            "v2",
        ])
        .output()
        .expect("bk security scan exit contract v2 should run");
    assert!(out.status.code() == Some(0) || out.status.code() == Some(11));
}
