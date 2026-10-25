use bug_killer::scanner::ai_agent::AgentSecurityScanner;
use bug_killer::types::*;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_bk_ai_llm_004_model_output_passed_to_eval_exec_subprocess() {
    let dir = tempdir().unwrap();

    // 1. Python eval with model response content
    let eval_py = dir.path().join("eval_vuln.py");
    let eval_code = r#"
import openai

response = openai.ChatCompletion.create(model="gpt-4", messages=[{"role": "user", "content": "gen code"}])
code_to_run = response.choices[0].message.content
eval(code_to_run)
"#;
    fs::write(&eval_py, eval_code).unwrap();
    let findings_eval = AgentSecurityScanner::scan_model_output_execution(&eval_py, eval_code);
    assert!(
        !findings_eval.is_empty(),
        "Must detect model output passed to eval"
    );
    let f_eval = findings_eval
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-LLM-004")
        .unwrap();
    assert_eq!(f_eval.severity, Severity::Critical);
    assert_eq!(f_eval.target_kind, TargetKind::GenericSourceFile);
    assert!(f_eval.description.contains("Model output"));

    // 2. Python exec with direct model output
    let exec_py = dir.path().join("exec_vuln.py");
    let exec_code = r#"
def execute_model_script(ai_response):
    exec(ai_response)
"#;
    fs::write(&exec_py, exec_code).unwrap();
    let findings_exec = AgentSecurityScanner::scan_source_code(&exec_py);
    assert!(
        !findings_exec.is_empty(),
        "Must detect ai_response passed to exec"
    );
    let f_exec = findings_exec
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-LLM-004")
        .unwrap();
    assert_eq!(f_exec.severity, Severity::Critical);

    // 3. Subprocess run with llm_output shell execution
    let subproc_py = dir.path().join("subprocess_vuln.py");
    let subproc_code = r#"
import subprocess

def run_command(llm_output):
    subprocess.run(llm_output, shell=True)
"#;
    fs::write(&subproc_py, subproc_code).unwrap();
    let findings_sub = AgentSecurityScanner::scan_source_code(&subproc_py);
    assert!(
        !findings_sub.is_empty(),
        "Must detect llm_output passed to subprocess.run"
    );
    let f_sub = findings_sub
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-LLM-004")
        .unwrap();
    assert_eq!(f_sub.severity, Severity::Critical);

    // 4. Node.js child_process.exec with model completion
    let node_js = dir.path().join("runner.js");
    let node_code = r#"
const { exec } = require('child_process');
async function handlePrompt(completion) {
    exec(completion);
}
"#;
    fs::write(&node_js, node_code).unwrap();
    let findings_node = AgentSecurityScanner::scan_model_output_execution(&node_js, node_code);
    assert!(
        !findings_node.is_empty(),
        "Must detect completion passed to child_process exec"
    );
    let f_node = findings_node
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-LLM-004")
        .unwrap();
    assert_eq!(f_node.severity, Severity::Critical);

    // 5. Safe code should not trigger BK-AI-LLM-004
    let safe_py = dir.path().join("safe.py");
    let safe_code = r#"
import json

response = {"text": "hello"}
print(response["text"])
data = json.loads(response["text"])
subprocess.run(["ls", "-la"])
"#;
    fs::write(&safe_py, safe_code).unwrap();
    let safe_findings = AgentSecurityScanner::scan_source_code(&safe_py);
    assert!(
        !safe_findings
            .iter()
            .any(|f| f.cve.as_str() == "BK-AI-LLM-004"),
        "Safe code must not trigger BK-AI-LLM-004"
    );
}

#[test]
fn test_bk_ai_llm_017_agent_config_missing_token_or_cost_budget() {
    let dir = tempdir().unwrap();

    // 1. Agent config completely missing token/cost budget
    let unbudgeted_path = dir.path().join("unbudgeted_agent.json");
    let unbudgeted_json = r#"{
  "name": "autonomous-researcher",
  "model": "claude-3-7-sonnet",
  "tools": ["web-search", "code-interpreter", "bash"],
  "system_prompt": "You are an autonomous research agent."
}"#;
    fs::write(&unbudgeted_path, unbudgeted_json).unwrap();
    let findings = AgentSecurityScanner::scan_agent_config(&unbudgeted_path);
    assert!(
        !findings.is_empty(),
        "Must detect agent config missing budget"
    );
    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-LLM-017")
        .unwrap();
    assert_eq!(f.severity, Severity::High);
    assert_eq!(f.target_kind, TargetKind::GenericConfigFile);
    assert!(f.description.contains("budget"));

    // 2. Agent config with empty budget object
    let empty_budget_path = dir.path().join("empty_budget_agent.json");
    let empty_budget_json = r#"{
  "name": "helper-agent",
  "model": "gpt-4o",
  "tools": ["eval-tool"],
  "budget": {}
}"#;
    let findings_empty =
        AgentSecurityScanner::scan_agent_config_str(&empty_budget_path, empty_budget_json);
    assert!(
        !findings_empty.is_empty(),
        "Empty budget object must trigger BK-AI-LLM-017"
    );
    assert!(
        findings_empty
            .iter()
            .any(|f| f.cve.as_str() == "BK-AI-LLM-017")
    );

    // 3. Safe agent config with explicit max_tokens and cost_budget
    let safe_path = dir.path().join("safe_agent.json");
    let safe_json = r#"{
  "name": "budgeted-agent",
  "model": "gpt-4o",
  "tools": ["web-search"],
  "budget": {
    "max_tokens": 50000,
    "cost_budget": 5.0
  }
}"#;
    fs::write(&safe_path, safe_json).unwrap();
    let safe_findings = AgentSecurityScanner::scan_agent_config(&safe_path);
    assert!(
        !safe_findings
            .iter()
            .any(|f| f.cve.as_str() == "BK-AI-LLM-017"),
        "Config with valid budget must not trigger BK-AI-LLM-017"
    );

    // 4. Safe agent config with top-level budget fields
    let safe_flat_path = dir.path().join("safe_flat_agent.json");
    let safe_flat_json = r#"{
  "name": "flat-budgeted-agent",
  "model": "claude-3-5-sonnet",
  "tools": ["bash"],
  "max_tokens": 100000,
  "max_cost": 2.50
}"#;
    let safe_flat_findings =
        AgentSecurityScanner::scan_agent_config_str(&safe_flat_path, safe_flat_json);
    assert!(
        !safe_flat_findings
            .iter()
            .any(|f| f.cve.as_str() == "BK-AI-LLM-017"),
        "Config with top-level max_tokens/max_cost must not trigger BK-AI-LLM-017"
    );

    // 5. Non-agent config JSON (e.g. general app config) without agent fields should not be flagged
    let generic_path = dir.path().join("app_settings.json");
    let generic_json = r#"{
  "appName": "my-service",
  "port": 8080,
  "debug": false
}"#;
    let generic_findings = AgentSecurityScanner::scan_agent_config_str(&generic_path, generic_json);
    assert!(
        generic_findings.is_empty(),
        "Non-agent configs should not be falsely flagged"
    );
}
