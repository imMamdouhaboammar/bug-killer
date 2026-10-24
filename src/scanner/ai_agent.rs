use crate::types::*;
use regex::Regex;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use std::sync::LazyLock;

static PROMPT_INJECTION_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(ignore\s+(all\s+)?(previous|prior)\s+instructions|disregard\s+(all\s+)?(prior\s+)?(guidelines|rules|constraints)|you\s+are\s+now\s+in\s+developer\s+mode|system\s+override\s+mode|bypass\s+all\s+safety\s+filters)").unwrap()
});

static EXFILTRATION_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(curl|wget|fetch|nc|ncat)\s+.*(\$(AWS_|OPENAI_|ANTHROPIC_|GEMINI_|KIMI_|MINIMAX_|DEEPSEEK_)|[A-Za-z0-9_\-\.]+\.(space|com|io|xyz|ru|cn)/.*(\.env|credentials|agent_identity))").unwrap()
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
}
