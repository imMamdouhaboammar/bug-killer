use bug_killer_inspector::agent::{
    AgentModelConfig, AgenticSecuritySupervisor, BinaryAuditArgs, BinaryAuditTool, IncidentContext,
    ModelProvider, ProcessMemoryArgs, ProcessMemoryAuditTool, VirtualPatchAdvisorTool,
    VirtualPatchArgs,
};
use rig::tool::{Tool, ToolContext};
use serde_json::json;

#[tokio::test]
async fn test_binary_audit_tool_execution() {
    let tool = BinaryAuditTool;
    let mut ctx = ToolContext::new();

    // Audit /bin/ls on mac/linux
    let ls_path = if std::path::Path::new("/bin/ls").exists() {
        "/bin/ls".to_string()
    } else {
        std::env::current_exe()
            .unwrap()
            .to_string_lossy()
            .to_string()
    };

    let args = BinaryAuditArgs {
        path: ls_path.clone(),
    };

    let result = tool
        .call(&mut ctx, args)
        .await
        .expect("Binary audit call failed");
    assert_eq!(result.path, ls_path);
    assert!(!result.format.is_empty());
    println!(
        "[✓] BinaryAuditTool verified format: {}, risk_score: {}",
        result.format, result.risk_score
    );
}

#[tokio::test]
async fn test_process_memory_audit_tool_execution() {
    let tool = ProcessMemoryAuditTool;
    let mut ctx = ToolContext::new();

    // Inspect current process PID
    let current_pid = std::process::id() as i32;
    let args = ProcessMemoryArgs { pid: current_pid };

    let result = tool
        .call(&mut ctx, args)
        .await
        .expect("Memory audit call failed");
    assert_eq!(result.pid, current_pid);
    assert!(!result.risk_summary.is_empty());
    println!(
        "[✓] ProcessMemoryAuditTool verified PID: {}, is_exposed: {}",
        result.pid, result.is_exposed
    );
}

#[tokio::test]
async fn test_virtual_patch_advisor_tool_php2shell() {
    let tool = VirtualPatchAdvisorTool;
    let mut ctx = ToolContext::new();

    let args = VirtualPatchArgs {
        vulnerability_id: "CVE-2026-109618".to_string(),
        target_component: "php-fpm".to_string(),
        environment: Some("debian".to_string()),
    };

    let result = tool
        .call(&mut ctx, args)
        .await
        .expect("Patch advisor call failed");
    assert_eq!(result.target_proxy, "nginx");
    assert!(result.patch_strategy.contains("Brotli"));
    assert!(
        result
            .recommended_directives
            .iter()
            .any(|d| d.contains("brotli off;"))
    );
    assert!(result.package_upgrade_command.contains("apt-get"));
    assert!(result.safe_rollback_procedure.contains("Ed25519"));
    println!("[✓] VirtualPatchAdvisorTool verified PHP2Shell virtual patch");
}

#[tokio::test]
async fn test_virtual_patch_advisor_tool_node2shell() {
    let tool = VirtualPatchAdvisorTool;
    let mut ctx = ToolContext::new();

    let args = VirtualPatchArgs {
        vulnerability_id: "CVE-2026-111497".to_string(),
        target_component: "nodejs".to_string(),
        environment: Some("ubuntu".to_string()),
    };

    let result = tool
        .call(&mut ctx, args)
        .await
        .expect("Patch advisor call failed");
    assert_eq!(result.target_proxy, "haproxy");
    assert!(result.patch_strategy.contains("Node.js"));
    assert!(
        result
            .recommended_directives
            .iter()
            .any(|d| d.contains("__proto__"))
    );
    assert!(result.package_upgrade_command.contains("node"));
    println!("[✓] VirtualPatchAdvisorTool verified Node2Shell virtual patch");
}

#[tokio::test]
async fn test_supervisor_dispatch_tool_dynamically() {
    let config = AgentModelConfig {
        provider: ModelProvider::DeterministicHeuristic,
        model_name: "heuristic-v1".to_string(),
        base_url: None,
        api_key: None,
        temperature: 0.1,
    };
    let supervisor = AgenticSecuritySupervisor::new(config);

    // Dynamic dispatch of virtual_patch_advisor
    let patch_json = json!({
        "vulnerability_id": "CVE-2026-109618",
        "target_component": "libphp.so",
        "environment": "linux"
    });

    let value = supervisor
        .dispatch_tool("virtual_patch_advisor", patch_json)
        .await
        .expect("Dispatch virtual_patch_advisor failed");

    assert_eq!(value["target_proxy"], "nginx");
    assert!(value["patch_strategy"].as_str().unwrap().contains("Brotli"));
    println!("[✓] Dynamic tool dispatch verified");
}

#[test]
fn test_multi_model_provider_resolution() {
    assert_eq!(ModelProvider::from_str_loose("kimi"), ModelProvider::Kimi);
    assert_eq!(
        ModelProvider::from_str_loose("moonshot"),
        ModelProvider::Kimi
    );
    assert_eq!(
        ModelProvider::from_str_loose("deepseek"),
        ModelProvider::DeepSeek
    );
    assert_eq!(
        ModelProvider::from_str_loose("minimax"),
        ModelProvider::MiniMax
    );
    assert_eq!(
        ModelProvider::from_str_loose("claude"),
        ModelProvider::Claude
    );
    assert_eq!(
        ModelProvider::from_str_loose("gemini"),
        ModelProvider::Gemini
    );
    assert_eq!(
        ModelProvider::from_str_loose("openai"),
        ModelProvider::OpenAi
    );
    assert_eq!(
        ModelProvider::from_str_loose("ollama"),
        ModelProvider::Ollama
    );
    assert_eq!(
        ModelProvider::from_str_loose("vllm"),
        ModelProvider::OpenWeightsCompatible
    );
    assert_eq!(
        ModelProvider::from_str_loose("unknown"),
        ModelProvider::DeterministicHeuristic
    );
}

#[tokio::test]
async fn test_autonomous_incident_investigation_workflow() {
    let config = AgentModelConfig {
        provider: ModelProvider::DeterministicHeuristic,
        model_name: "heuristic-v1".to_string(),
        base_url: None,
        api_key: None,
        temperature: 0.1,
    };
    let supervisor = AgenticSecuritySupervisor::new(config);

    let ls_path = if std::path::Path::new("/bin/ls").exists() {
        "/bin/ls".to_string()
    } else {
        std::env::current_exe()
            .unwrap()
            .to_string_lossy()
            .to_string()
    };

    let incident = IncidentContext {
        incident_id: "INC-TEST-001".to_string(),
        alert_source: "Sniffer-GoPacket".to_string(),
        target_binary: Some(ls_path),
        target_pid: Some(std::process::id() as i32),
        anomaly_description: "Anomalous compressed stream payload matched CVE-2026-109618 pattern"
            .to_string(),
        cve_hint: Some("CVE-2026-109618".to_string()),
    };

    let report = supervisor
        .investigate_incident(&incident)
        .await
        .expect("Autonomous investigation failed");

    assert_eq!(report.incident_id, "INC-TEST-001");
    assert!(report.binary_audit.is_some());
    assert!(report.memory_audit.is_some());
    assert!(report.virtual_patch.is_some());
    assert!(report.synthesized_remediation.contains("IMMEDIATE ACTION"));
    assert_eq!(report.provider_used, "DeterministicHeuristic");

    println!(
        "[✓] Agentic incident investigation report:\n{}",
        serde_json::to_string_pretty(&report).unwrap()
    );
}
