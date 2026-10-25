use crate::types::*;
use regex::Regex;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::sync::LazyLock;

static PROMPT_INJECTION_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(ignore\s+(all\s+)?(previous|prior)\s+instructions|disregard\s+(all\s+)?(prior\s+)?(guidelines|rules|constraints)|you\s+are\s+now\s+in\s+developer\s+mode|system\s+override\s+mode|bypass\s+all\s+safety\s+filters)").unwrap()
});

static EXFILTRATION_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(curl|wget|fetch|nc|ncat)\s+.*(\$(AWS_|OPENAI_|ANTHROPIC_|GEMINI_|KIMI_|MINIMAX_|DEEPSEEK_)|[A-Za-z0-9_\-\.]+\.(space|com|io|xyz|ru|cn)/.*(\.env|credentials|agent_identity))").unwrap()
});

#[allow(dead_code)]
static MODEL_OUTPUT_ASSIGN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)^\s*(?:let\s+|const\s+|var\s+)?([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*.*(?:response\s*\.\s*(?:choices|text|content|data)|(?:openai|anthropic|client|llm|model)\s*\.\s*(?:chat|complete|generate|create|invoke|predict)|model_output|llm_output|ai_output|ai_response|llm_response|completion|generation)"#).unwrap()
});

#[allow(dead_code)]
static FUNC_PARAM_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(?:def\s+[a-zA-Z0-9_]+\s*\(|function\s+[a-zA-Z0-9_]*\s*\(|\basync\s+function\s+[a-zA-Z0-9_]*\s*\(|\(\s*)([^)]*)\)"#).unwrap()
});

#[allow(dead_code)]
static MODEL_OUTPUT_PATTERNS_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(response\s*\.\s*(?:choices|text|content|data)|model_output|llm_output|ai_output|agent_output|model_response|llm_response|ai_response|completion|generation)\b"#).unwrap()
});

#[allow(dead_code)]
static SINK_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(eval|exec|os\.system|os\.popen|subprocess\.(?:run|Popen|call|check_output|check_call)|child_process\.(?:exec|execSync|spawn|spawnSync)|system|shell_exec)\s*\((.*)"#).unwrap()
});

pub struct AgentSecurityScanner;

impl AgentSecurityScanner {
    /// Scans an MCP server configuration file (.mcp.json, claude_desktop_config.json, etc.) for supply-chain and privilege risks.
    pub fn scan_mcp_config(path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => return findings,
        };

        let val: Value = match serde_json::from_str(&content) {
            Ok(v) => v,
            Err(_) => return findings,
        };

        let servers = val
            .get("mcpServers")
            .or_else(|| val.get("servers"))
            .and_then(|s| s.as_object());

        if let Some(servers_obj) = servers {
            for (srv_name, srv_val) in servers_obj {
                // 1. Uncontained shell tool execution
                if let Some(cmd) = srv_val.get("command").and_then(|c| c.as_str()) {
                    let cmd_lower = cmd.to_lowercase();
                    let is_dangerous_shell = cmd_lower == "bash"
                        || cmd_lower == "sh"
                        || cmd_lower == "zsh"
                        || cmd_lower == "powershell"
                        || cmd_lower == "cmd.exe"
                        || cmd_lower.ends_with("/bash")
                        || cmd_lower.ends_with("/sh")
                        || cmd_lower.ends_with("/zsh");

                    if is_dangerous_shell {
                        let mut finding = Finding::new(
                            format!("ai-mcp-unrestricted-shell-{}", srv_name),
                            CveId::Custom {
                                id: "BK-AGENT-001".to_string(),
                                title: format!("Unrestricted Shell Tool Execution in MCP Server '{}'", srv_name),
                            },
                            Severity::Critical,
                            TargetKind::McpServerConfig,
                            Some(path.to_path_buf()),
                            None,
                            format!("Server '{}' executes command '{}'", srv_name, cmd),
                            "Wrap tools in dedicated single-purpose binaries with rigid schemas rather than raw shell interpreters".to_string(),
                            format!("MCP server '{}' exposes an unconstrained shell interpreter ('{}') directly to autonomous agent execution, creating arbitrary command execution vulnerability if prompt injected.", srv_name, cmd),
                            format!("Replace raw shell command in MCP server '{}' with a sandboxed CLI binary declaring strict input schemas and parameter allowlists.", srv_name),
                        );
                        finding.detector_id = "agent-mcp-scanner".to_string();
                        finding.category = "ai-agent-security".to_string();
                        finding.affectedness = Affectedness::ConfirmedAffected;
                        finding.reachability = Reachability::ConfirmedReachable;
                        finding.confidence = Confidence::High;
                        finding.supported_checks = vec!["mcp_command_allowlist_check".to_string()];
                        finding.compute_dedupe_fingerprint();
                        findings.push(finding);
                    }
                }

                // 2. Hardcoded API secrets in env block
                if let Some(env_obj) = srv_val.get("env").and_then(|e| e.as_object()) {
                    for (k, v) in env_obj {
                        let k_upper = k.to_uppercase();
                        if k_upper.contains("KEY")
                            || k_upper.contains("SECRET")
                            || k_upper.contains("TOKEN")
                            || k_upper.contains("PASSWORD")
                        {
                            if let Some(val_str) = v.as_str() {
                                let is_env_ref =
                                    val_str.starts_with('$') || val_str.starts_with("${");
                                let is_placeholder = val_str.is_empty()
                                    || val_str == "your_api_key_here"
                                    || val_str == "changeme";

                                if !is_env_ref && !is_placeholder && val_str.len() >= 8 {
                                    let mut finding = Finding::new(
                                        format!("ai-mcp-hardcoded-secret-{}-{}", srv_name, k),
                                        CveId::Custom {
                                            id: "BK-AGENT-002".to_string(),
                                            title: format!("Hardcoded Secret in MCP Server '{}' Environment", srv_name),
                                        },
                                        Severity::High,
                                        TargetKind::McpServerConfig,
                                        Some(path.to_path_buf()),
                                        None,
                                        format!("Server '{}' defines hardcoded credential for key '{}'", srv_name, k),
                                        "Reference secrets via environment variables ('$ENV_VAR') or external secret vault".to_string(),
                                        format!("MCP server configuration '{}' hardcodes plain-text secret '{}' in cleartext configuration file.", srv_name, k),
                                        format!("Replace cleartext value of '{}' with environment reference '${{{}}}' in {}.", k, k, path.display()),
                                    );
                                    finding.detector_id = "agent-mcp-scanner".to_string();
                                    finding.category = "credential-leakage".to_string();
                                    finding.affectedness = Affectedness::ConfirmedAffected;
                                    finding.reachability = Reachability::ConfirmedReachable;
                                    finding.confidence = Confidence::High;
                                    finding.supported_checks =
                                        vec!["mcp_env_secret_check".to_string()];
                                    finding.compute_dedupe_fingerprint();
                                    findings.push(finding);
                                }
                            }
                        }
                    }
                }
            }
        }

        findings
    }

    /// Scans agent skill files (SKILL.md, *.skill) for prompt injection and credential exfiltration primitives.
    pub fn scan_agent_skill(path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => return findings,
        };

        let file_digest = format!("{:x}", Sha256::digest(path.to_string_lossy().as_bytes()));

        for (idx, line) in content.lines().enumerate() {
            let line_num = idx + 1;
            let trimmed = line.trim();

            if trimmed.is_empty() || trimmed.starts_with("<!--") {
                continue;
            }

            // 1. Adversarial prompt injection signatures
            if let Some(mat) = PROMPT_INJECTION_RE.find(trimmed) {
                let matched_text = mat.as_str();
                let mut finding = Finding::new(
                    format!("ai-skill-prompt-injection-{}-L{}", &file_digest[..8], line_num),
                    CveId::Custom {
                        id: "BK-AGENT-003".to_string(),
                        title: "Adversarial Prompt Injection Signature in Agent Skill".to_string(),
                    },
                    Severity::High,
                    TargetKind::AgentSkillManifest,
                    Some(path.to_path_buf()),
                    Some(line_num),
                    format!("Matches prompt injection pattern: '{}'", matched_text),
                    "Remove adversarial override instructions; keep security boundaries deterministic".to_string(),
                    "Agent skill instructions contain prompt injection patterns designed to hijack LLM behavior, override system guardrails, or disable safety constraints.".to_string(),
                    "Audit and sanitize agent skill instructions. Enforce capability boundaries in deterministic host runtime code rather than prompt-level text.".to_string(),
                );
                finding.detector_id = "agent-skill-scanner".to_string();
                finding.category = "prompt-injection-risk".to_string();
                finding.affectedness = Affectedness::LikelyAffected;
                finding.reachability = Reachability::PotentiallyReachable;
                finding.confidence = Confidence::Medium;
                finding.supported_checks = vec!["skill_prompt_injection_regex_check".to_string()];
                finding.compute_dedupe_fingerprint();
                findings.push(finding);
            }

            // 2. Data / Credential exfiltration signatures
            if let Some(mat) = EXFILTRATION_RE.find(trimmed) {
                let matched_text = mat.as_str();
                let mut finding = Finding::new(
                    format!("ai-skill-data-exfiltration-{}-L{}", &file_digest[..8], line_num),
                    CveId::Custom {
                        id: "BK-AGENT-004".to_string(),
                        title: "Credential / Data Exfiltration Signature in Agent Skill".to_string(),
                    },
                    Severity::Critical,
                    TargetKind::AgentSkillManifest,
                    Some(path.to_path_buf()),
                    Some(line_num),
                    format!("Matches network exfiltration pattern: '{}'", matched_text),
                    "Quarantine and remove unauthorized outbound credential transmission hooks".to_string(),
                    "Agent skill instructions contain explicit instructions to curl/fetch/exfiltrate environment variables, API tokens, or sensitive credentials to external endpoints.".to_string(),
                    "Immediately quarantine and remove this agent skill. Restrict external outbound network egress in agent runner environments.".to_string(),
                );
                finding.detector_id = "agent-skill-scanner".to_string();
                finding.category = "data-exfiltration-risk".to_string();
                finding.affectedness = Affectedness::ConfirmedAffected;
                finding.reachability = Reachability::ConfirmedReachable;
                finding.confidence = Confidence::High;
                finding.supported_checks = vec!["skill_exfiltration_regex_check".to_string()];
                finding.compute_dedupe_fingerprint();
                findings.push(finding);
            }
        }

        findings
    }

    /// Scans source code file on disk for model output passed directly into execution sinks (BK-AI-LLM-004).
    #[allow(dead_code)]
    pub fn scan_source_code(path: &Path) -> Vec<Finding> {
        match fs::read_to_string(path) {
            Ok(content) => Self::scan_model_output_execution(path, &content),
            Err(_) => Vec::new(),
        }
    }

    /// Scans model output execution patterns in source text (BK-AI-LLM-004).
    #[allow(dead_code)]
    pub fn scan_model_output(path: &Path, content: &str) -> Vec<Finding> {
        Self::scan_model_output_execution(path, content)
    }

    /// Inspects source code content for model outputs passed into exec/eval/subprocess sinks (BK-AI-LLM-004).
    #[allow(dead_code)]
    pub fn scan_model_output_execution(path: &Path, content: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let file_digest = format!("{:x}", Sha256::digest(path.to_string_lossy().as_bytes()));
        let mut tainted_vars = HashSet::new();

        for (idx, line) in content.lines().enumerate() {
            let line_num = idx + 1;
            let trimmed = line.trim();

            if trimmed.is_empty()
                || trimmed.starts_with("//")
                || trimmed.starts_with('#')
                || trimmed.starts_with('*')
                || trimmed.starts_with("/*")
            {
                continue;
            }

            // 1. Identify function parameters that carry model outputs
            if let Some(caps) = FUNC_PARAM_RE.captures(trimmed) {
                if let Some(params_str) = caps.get(1) {
                    for param in params_str.as_str().split(',') {
                        let param_name = param
                            .split(':')
                            .next()
                            .unwrap_or(param)
                            .split('=')
                            .next()
                            .unwrap_or(param)
                            .trim();
                        if MODEL_OUTPUT_PATTERNS_RE.is_match(param_name) {
                            tainted_vars.insert(param_name.to_string());
                        }
                    }
                }
            }

            // 2. Identify variables assigned from model output expressions
            if let Some(caps) = MODEL_OUTPUT_ASSIGN_RE.captures(trimmed) {
                if let Some(var_cap) = caps.get(1) {
                    let var_name = var_cap.as_str().trim();
                    tainted_vars.insert(var_name.to_string());
                }
            }

            // 3. Inspect execution sinks for untrusted model output input
            if let Some(sink_cap) = SINK_RE.captures(trimmed) {
                let sink_func = sink_cap.get(1).map(|m| m.as_str()).unwrap_or("");
                let args_str = sink_cap.get(2).map(|m| m.as_str()).unwrap_or("");

                let has_direct_model_pattern = MODEL_OUTPUT_PATTERNS_RE.is_match(args_str);
                let has_tainted_var = tainted_vars.iter().any(|v| {
                    if let Ok(var_re) = Regex::new(&format!(r"\b{}\b", regex::escape(v))) {
                        var_re.is_match(args_str)
                    } else {
                        args_str.contains(v)
                    }
                });

                if has_direct_model_pattern || has_tainted_var {
                    let mut finding = Finding::new(
                        format!("ai-llm-004-output-injection-{}-L{}", &file_digest[..8], line_num),
                        CveId::Custom {
                            id: "BK-AI-LLM-004".to_string(),
                            title: format!("Model Output Injected into Execution Sink ('{}')", sink_func),
                        },
                        Severity::Critical,
                        TargetKind::GenericSourceFile,
                        Some(path.to_path_buf()),
                        Some(line_num),
                        format!("Execution sink '{}' invoked with untrusted model output", sink_func),
                        "Sanitize model output and execute via strictly validated non-shell APIs with hardcoded schemas".to_string(),
                        "Model output is passed directly into code execution or system command sink (eval/exec/subprocess) without strict validation, risking arbitrary remote code execution via prompt injection.".to_string(),
                        "Restore invariant: output treated as untrusted data. Validate, sanitize, or parse model output into structured data instead of passing directly to execution sinks.".to_string(),
                    );
                    finding.detector_id = "agent-security-scanner".to_string();
                    finding.category =
                        "2.22 LLM, RAG, autonomous agent and MCP application flaws".to_string();
                    finding.affectedness = Affectedness::ConfirmedAffected;
                    finding.reachability = Reachability::ConfirmedReachable;
                    finding.confidence = Confidence::Confirmed;
                    finding.evidence_certainty = EvidenceCertainty::Confirmed;
                    finding.supported_checks =
                        vec!["model_output_execution_sink_check".to_string()];
                    finding.compute_dedupe_fingerprint();
                    findings.push(finding);
                }
            }
        }

        findings
    }

    /// Scans an agent configuration JSON file for missing resource, token, or cost budgets (BK-AI-LLM-017).
    #[allow(dead_code)]
    pub fn scan_agent_config(path: &Path) -> Vec<Finding> {
        match fs::read_to_string(path) {
            Ok(content) => Self::scan_agent_config_str(path, &content),
            Err(_) => Vec::new(),
        }
    }

    /// Scans an agent configuration JSON string for missing resource, token, or cost budgets (BK-AI-LLM-017).
    #[allow(dead_code)]
    pub fn scan_agent_config_str(path: &Path, content: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let val: Value = match serde_json::from_str(content) {
            Ok(v) => v,
            Err(_) => return findings,
        };

        let file_digest = format!("{:x}", Sha256::digest(path.to_string_lossy().as_bytes()));

        let agent_objs: Vec<&serde_json::Map<String, Value>> =
            if let Some(agents_arr) = val.get("agents").and_then(|a| a.as_array()) {
                agents_arr.iter().filter_map(|v| v.as_object()).collect()
            } else if let Some(subagents_arr) = val.get("subagents").and_then(|a| a.as_array()) {
                subagents_arr.iter().filter_map(|v| v.as_object()).collect()
            } else if let Some(obj) = val.as_object() {
                let is_agent = obj.contains_key("agent")
                    || obj.contains_key("agent_id")
                    || obj.contains_key("tools")
                    || obj.contains_key("system_prompt")
                    || obj.contains_key("model")
                    || obj.contains_key("budget")
                    || obj.contains_key("max_tokens")
                    || obj.contains_key("cost_budget")
                    || path.to_string_lossy().to_lowercase().contains("agent");

                if is_agent { vec![obj] } else { Vec::new() }
            } else {
                Vec::new()
            };

        for obj in agent_objs {
            let name = obj
                .get("name")
                .or_else(|| obj.get("id"))
                .or_else(|| obj.get("agent_id"))
                .and_then(|n| n.as_str())
                .unwrap_or("agent");

            // Check for token budget
            let has_token_budget = obj
                .get("max_tokens")
                .is_some_and(|v| !v.is_null() && v != 0)
                || obj
                    .get("token_budget")
                    .is_some_and(|v| !v.is_null() && v != 0)
                || obj
                    .get("token_limit")
                    .is_some_and(|v| !v.is_null() && v != 0)
                || obj
                    .get("max_total_tokens")
                    .is_some_and(|v| !v.is_null() && v != 0)
                || obj
                    .get("budget")
                    .and_then(|b| b.as_object())
                    .is_some_and(|b| {
                        b.get("max_tokens").is_some_and(|v| !v.is_null() && v != 0)
                            || b.get("tokens").is_some_and(|v| !v.is_null() && v != 0)
                            || b.get("token_budget")
                                .is_some_and(|v| !v.is_null() && v != 0)
                    });

            // Check for cost budget
            let has_cost_budget = obj
                .get("max_cost")
                .is_some_and(|v| !v.is_null() && v != 0 && v != 0.0)
                || obj
                    .get("cost_budget")
                    .is_some_and(|v| !v.is_null() && v != 0 && v != 0.0)
                || obj
                    .get("cost_limit")
                    .is_some_and(|v| !v.is_null() && v != 0 && v != 0.0)
                || obj
                    .get("budget_usd")
                    .is_some_and(|v| !v.is_null() && v != 0 && v != 0.0)
                || obj
                    .get("max_spend")
                    .is_some_and(|v| !v.is_null() && v != 0 && v != 0.0)
                || obj.get("budget").is_some_and(|b| {
                    if let Some(num) = b.as_f64() {
                        num > 0.0
                    } else if let Some(b_obj) = b.as_object() {
                        b_obj
                            .get("max_cost")
                            .is_some_and(|v| !v.is_null() && v != 0 && v != 0.0)
                            || b_obj
                                .get("cost_budget")
                                .is_some_and(|v| !v.is_null() && v != 0 && v != 0.0)
                            || b_obj
                                .get("cost_limit")
                                .is_some_and(|v| !v.is_null() && v != 0 && v != 0.0)
                            || b_obj
                                .get("budget_usd")
                                .is_some_and(|v| !v.is_null() && v != 0 && v != 0.0)
                            || b_obj
                                .get("max_spend")
                                .is_some_and(|v| !v.is_null() && v != 0 && v != 0.0)
                            || b_obj
                                .get("cost")
                                .is_some_and(|v| !v.is_null() && v != 0 && v != 0.0)
                    } else {
                        false
                    }
                });

            let has_budget = has_token_budget || has_cost_budget;

            if !has_budget {
                let mut finding = Finding::new(
                    format!("ai-agent-no-budget-{}-{}", &file_digest[..8], name),
                    CveId::Custom {
                        id: "BK-AI-LLM-017".to_string(),
                        title: format!("Agent '{}' Tool Calls Lack Resource or Cost Budget", name),
                    },
                    Severity::High,
                    TargetKind::GenericConfigFile,
                    Some(path.to_path_buf()),
                    Some(1),
                    format!(
                        "Agent '{}' defines execution capabilities with no token or cost budget limit",
                        name
                    ),
                    "Define explicit max_tokens, cost_budget, or timeout limits in agent configuration"
                        .to_string(),
                    format!(
                        "Agent '{}' permits unbounded autonomous execution and tool calls without specifying token count, cost budget, or wall-clock limits, risking denial of service and cost exhaustion.",
                        name
                    ),
                    format!(
                        "Restore invariant: bounded work and cancellation. Add 'budget' specification with 'max_tokens' and 'cost_budget' to agent '{}' configuration.",
                        name
                    ),
                );
                finding.detector_id = "agent-security-scanner".to_string();
                finding.category =
                    "2.22 LLM, RAG, autonomous agent and MCP application flaws".to_string();
                finding.affectedness = Affectedness::ConfirmedAffected;
                finding.reachability = Reachability::ConfirmedReachable;
                finding.confidence = Confidence::High;
                finding.evidence_certainty = EvidenceCertainty::Confirmed;
                finding.supported_checks = vec!["agent_budget_boundary_check".to_string()];
                finding.compute_dedupe_fingerprint();
                findings.push(finding);
            }
        }

        findings
    }
}
