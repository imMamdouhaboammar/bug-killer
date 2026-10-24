use serde::{Deserialize, Serialize};
use serde_json::json;
use std::path::Path;
use thiserror::Error;

use rig::completion::{CompletionRequest, ToolDefinition};
use rig::tool::{Tool, ToolContext, tool_definition};

use crate::binary_audit::BinaryAuditor;
use crate::mem_audit::ProcessMemoryAuditor;
use crate::omni_proto::{BinaryInspectionRequest, SecurityHardeningFlags};

#[derive(Debug, Error)]
pub enum AgentSecurityError {
    #[error("Tool execution failed: {0}")]
    ToolExecution(String),
    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Unknown tool requested: {0}")]
    UnknownTool(String),
    #[error("Provider error: {0}")]
    Provider(String),
    #[error("Investigation error: {0}")]
    Investigation(String),
}

// ============================================================================
// 1. TOOL A: BINARY AUDIT TOOL (Goblin Zero-Copy Parser & Checksec)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryAuditArgs {
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChecksecSummary {
    pub pie_enabled: bool,
    pub nx_stack_enabled: bool,
    pub relro_full: bool,
    pub stack_canary_present: bool,
    pub fortified_source: bool,
}

impl From<SecurityHardeningFlags> for ChecksecSummary {
    fn from(flags: SecurityHardeningFlags) -> Self {
        Self {
            pie_enabled: flags.pie_enabled,
            nx_stack_enabled: flags.nx_stack_enabled,
            relro_full: flags.relro_full,
            stack_canary_present: flags.stack_canary_present,
            fortified_source: flags.fortified_source,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryAuditOutput {
    pub path: String,
    pub format: String,
    pub architecture_id: i32,
    pub checksec: ChecksecSummary,
    pub unsafe_symbols_found: Vec<String>,
    pub missing_cleanups: Vec<String>,
    pub is_vulnerable: bool,
    pub risk_score: u32,
    pub risk_summary: String,
}

pub struct BinaryAuditTool;

impl Tool for BinaryAuditTool {
    const NAME: &'static str = "binary_audit";
    type Args = BinaryAuditArgs;
    type Output = BinaryAuditOutput;
    type Error = AgentSecurityError;

    fn description(&self) -> String {
        "Statically audits an ELF, Mach-O, or PE binary file using zero-copy Goblin parsing. \
         Extracts checksec hardening flags (PIE, Stack Canary, NX/DEP, RELRO), locates unsafe legacy \
         C calls (strcpy, strcat, longjmp stack cleanup bypass), and evaluates known CVE vulnerability signatures."
            .to_string()
    }

    fn parameters(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Absolute filesystem path to the target binary or shared library."
                }
            },
            "required": ["path"]
        })
    }

    async fn call(
        &self,
        _context: &mut ToolContext,
        args: Self::Args,
    ) -> Result<Self::Output, Self::Error> {
        let p = Path::new(&args.path);
        if !p.exists() {
            return Err(AgentSecurityError::ToolExecution(format!(
                "Target binary path does not exist: {}",
                args.path
            )));
        }

        let req = BinaryInspectionRequest {
            request_id: "agent_audit".to_string(),
            file_path: args.path.clone(),
            binary_payload: Vec::new(),
            expected_arch: 0,
            extract_symbols: true,
            verify_hardening_flags: true,
        };

        let resp = BinaryAuditor::audit_binary_proto(&req);

        let checksec = resp
            .hardening_flags
            .map(ChecksecSummary::from)
            .unwrap_or(ChecksecSummary {
                pie_enabled: false,
                nx_stack_enabled: false,
                relro_full: false,
                stack_canary_present: false,
                fortified_source: false,
            });

        let unsafe_symbols: Vec<String> = resp
            .unsafe_symbols
            .into_iter()
            .map(|s| format!("{}: risk_category={}", s.symbol_name, s.risk_category))
            .collect();

        let risk_score = if resp.is_vulnerable {
            95
        } else if !unsafe_symbols.is_empty() || !checksec.nx_stack_enabled {
            65
        } else {
            10
        };

        Ok(BinaryAuditOutput {
            path: args.path,
            format: resp.binary_format,
            architecture_id: resp.detected_arch,
            checksec,
            unsafe_symbols_found: unsafe_symbols,
            missing_cleanups: resp.missing_cleanups,
            is_vulnerable: resp.is_vulnerable,
            risk_score,
            risk_summary: resp.diagnostic_summary,
        })
    }
}

// ============================================================================
// 2. TOOL B: PROCESS MEMORY AUDIT TOOL (/proc/[PID]/maps Inspector)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessMemoryArgs {
    pub pid: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessMemoryOutput {
    pub pid: i32,
    pub is_exposed: bool,
    pub mapped_vulnerable_libraries: Vec<String>,
    pub execution_regions_count: usize,
    pub risk_summary: String,
}

pub struct ProcessMemoryAuditTool;

impl Tool for ProcessMemoryAuditTool {
    const NAME: &'static str = "process_memory_audit";
    type Args = ProcessMemoryArgs;
    type Output = ProcessMemoryOutput;
    type Error = AgentSecurityError;

    fn description(&self) -> String {
        "Inspects a running Linux process's virtual memory map via /proc/[PID]/maps without \
         blocking or crashing the target process. Discovers unpatched shared libraries (e.g. libphp.so) \
         mapped into executable segments."
            .to_string()
    }

    fn parameters(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "pid": {
                    "type": "integer",
                    "description": "Process identifier (PID) of the target runtime process."
                }
            },
            "required": ["pid"]
        })
    }

    async fn call(
        &self,
        _context: &mut ToolContext,
        args: Self::Args,
    ) -> Result<Self::Output, Self::Error> {
        let finding = ProcessMemoryAuditor::audit_process(args.pid).map_err(|e| {
            AgentSecurityError::ToolExecution(format!(
                "Memory audit failed for PID {}: {}",
                args.pid, e
            ))
        })?;

        Ok(ProcessMemoryOutput {
            pid: finding.pid,
            is_exposed: finding.is_exposed,
            mapped_vulnerable_libraries: finding.mapped_vulnerable_libraries,
            execution_regions_count: finding.execution_regions_count,
            risk_summary: finding.risk_summary,
        })
    }
}

// ============================================================================
// 3. TOOL C: VIRTUAL PATCH ADVISOR TOOL (WAF / System Hardening Engine)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtualPatchArgs {
    pub vulnerability_id: String,
    pub target_component: String,
    pub environment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtualPatchOutput {
    pub vulnerability_id: String,
    pub patch_strategy: String,
    pub target_proxy: String,
    pub recommended_directives: Vec<String>,
    pub package_upgrade_command: String,
    pub safe_rollback_procedure: String,
}

pub struct VirtualPatchAdvisorTool;

impl Tool for VirtualPatchAdvisorTool {
    const NAME: &'static str = "virtual_patch_advisor";
    type Args = VirtualPatchArgs;
    type Output = VirtualPatchOutput;
    type Error = AgentSecurityError;

    fn description(&self) -> String {
        "Synthesizes actionable, non-breaking virtual patch directives (WAF rules for Nginx, HAProxy, Apache) \
         and package upgrade reconciliation sequences for identified vulnerabilities (such as CVE-2026-109618 PHP2Shell \
         or CVE-2026-111497 Node2Shell) with cryptographic rollback safety."
            .to_string()
    }

    fn parameters(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "vulnerability_id": {
                    "type": "string",
                    "description": "Identifier of vulnerability or CVE (e.g., CVE-2026-109618, CVE-2026-111497, generic_oob)."
                },
                "target_component": {
                    "type": "string",
                    "description": "Target component (e.g. php-fpm, nodejs, bun, nginx)."
                },
                "environment": {
                    "type": "string",
                    "description": "Optional deployment environment (e.g. debian, alpine, kubernetes)."
                }
            },
            "required": ["vulnerability_id", "target_component"]
        })
    }

    async fn call(
        &self,
        _context: &mut ToolContext,
        args: Self::Args,
    ) -> Result<Self::Output, Self::Error> {
        let (strategy, proxy, directives, pkg_cmd, rollback) = match args.vulnerability_id.to_uppercase().as_str() {
            v if v.contains("109618") || v.contains("PHP2SHELL") || args.target_component.to_lowercase().contains("php") => {
                (
                    "WAF Brotli Decompression Stripping & FastCGI Buffer Clamp".to_string(),
                    "nginx".to_string(),
                    vec![
                        "# Virtual Patch for PHP2Shell CVE-2026-109618 / CVE-2026-109619".to_string(),
                        "brotli off;".to_string(),
                        "client_max_body_size 2M;".to_string(),
                        "client_body_buffer_size 128k;".to_string(),
                        "fastcgi_buffers 16 16k;".to_string(),
                        "fastcgi_buffer_size 32k;".to_string(),
                    ],
                    "apt-get update && apt-get --only-upgrade install -y php8.3-fpm libphp8.3-embed".to_string(),
                    "Restore signed backup from ~/.bug-killer/backups/nginx.conf.bak and verify Ed25519 signature before nginx -s reload".to_string(),
                )
            }
            v if v.contains("111497") || v.contains("NODE2SHELL") || args.target_component.to_lowercase().contains("node") => {
                (
                    "Node.js HTTP Header Boundary Clamp & Prototype Hardening".to_string(),
                    "haproxy".to_string(),
                    vec![
                        "# Virtual Patch for Node2Shell CVE-2026-111497".to_string(),
                        "http-request deny if { req.hdr_cnt() gt 50 }".to_string(),
                        "http-request deny if { req.hdrs_bin -m sub __proto__ }".to_string(),
                        "tune.maxrewrite 16384".to_string(),
                    ],
                    "npm update -g node || apt-get --only-upgrade install -y nodejs".to_string(),
                    "Restore haproxy.cfg from signed backup manifest and restart haproxy service".to_string(),
                )
            }
            _ => {
                (
                    "Generic Runtime Boundary Hardening".to_string(),
                    "nginx".to_string(),
                    vec![
                        "# Generic Virtual Patch: Request sanitization".to_string(),
                        "client_max_body_size 8M;".to_string(),
                        "proxy_hide_header X-Powered-By;".to_string(),
                    ],
                    format!("apt-get --only-upgrade install -y {}", args.target_component),
                    "Revert configuration from Ed25519-signed manifest and reload service".to_string(),
                )
            }
        };

        Ok(VirtualPatchOutput {
            vulnerability_id: args.vulnerability_id,
            patch_strategy: strategy,
            target_proxy: proxy,
            recommended_directives: directives,
            package_upgrade_command: pkg_cmd,
            safe_rollback_procedure: rollback,
        })
    }
}

// ============================================================================
// 4. MODEL BACKEND & PROVIDER INTEGRATION ABSTRACTION
// ============================================================================

/// Supported LLM Provider Families
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ModelProvider {
    OpenAi,
    DeepSeek,
    Kimi,
    MiniMax,
    Claude,
    Gemini,
    Ollama,
    OpenWeightsCompatible,
    DeterministicHeuristic,
}

impl ModelProvider {
    pub fn from_str_loose(s: &str) -> Self {
        match s.to_lowercase().trim() {
            "openai" | "codex" | "chatgpt" => ModelProvider::OpenAi,
            "deepseek" | "deepseek-r1" | "deepseek-chat" => ModelProvider::DeepSeek,
            "kimi" | "moonshot" => ModelProvider::Kimi,
            "minimax" => ModelProvider::MiniMax,
            "claude" | "anthropic" => ModelProvider::Claude,
            "gemini" | "google" => ModelProvider::Gemini,
            "ollama" | "local" => ModelProvider::Ollama,
            "openweights" | "vllm" | "lmstudio" | "custom" => ModelProvider::OpenWeightsCompatible,
            _ => ModelProvider::DeterministicHeuristic,
        }
    }
}

/// Dynamic Configuration for Multi-Model Security Brain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentModelConfig {
    pub provider: ModelProvider,
    pub model_name: String,
    pub base_url: Option<String>,
    pub api_key: Option<String>,
    pub temperature: f64,
}

impl Default for AgentModelConfig {
    fn default() -> Self {
        // Automatically check environment variables
        let (provider, model, base_url, key) = if let Ok(k) = std::env::var("DEEPSEEK_API_KEY") {
            (
                ModelProvider::DeepSeek,
                "deepseek-chat".to_string(),
                None,
                Some(k),
            )
        } else if let Ok(k) = std::env::var("MOONSHOT_API_KEY") {
            (ModelProvider::Kimi, "kimi-k3".to_string(), None, Some(k))
        } else if let Ok(k) = std::env::var("MINIMAX_API_KEY") {
            (
                ModelProvider::MiniMax,
                "MiniMax-M3".to_string(),
                None,
                Some(k),
            )
        } else if let Ok(k) = std::env::var("ANTHROPIC_API_KEY") {
            (
                ModelProvider::Claude,
                "claude-3-5-sonnet-20241022".to_string(),
                None,
                Some(k),
            )
        } else if let Ok(k) = std::env::var("GEMINI_API_KEY") {
            (
                ModelProvider::Gemini,
                "gemini-2.5-flash".to_string(),
                None,
                Some(k),
            )
        } else if let Ok(k) = std::env::var("OPENAI_API_KEY") {
            (ModelProvider::OpenAi, "gpt-4o".to_string(), None, Some(k))
        } else if let Ok(url) = std::env::var("OLLAMA_API_BASE_URL") {
            (
                ModelProvider::Ollama,
                "llama3.3".to_string(),
                Some(url),
                None,
            )
        } else {
            (
                ModelProvider::DeterministicHeuristic,
                "heuristic-v1".to_string(),
                None,
                None,
            )
        };

        Self {
            provider,
            model_name: model,
            base_url,
            api_key: key,
            temperature: 0.1,
        }
    }
}

// ============================================================================
// 5. INCIDENT & REMEDIATION REPORT SCHEMAS
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentContext {
    pub incident_id: String,
    pub alert_source: String,
    pub target_binary: Option<String>,
    pub target_pid: Option<i32>,
    pub anomaly_description: String,
    pub cve_hint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgenticIncidentReport {
    pub incident_id: String,
    pub severity: String,
    pub root_cause: String,
    pub binary_audit: Option<BinaryAuditOutput>,
    pub memory_audit: Option<ProcessMemoryOutput>,
    pub virtual_patch: Option<VirtualPatchOutput>,
    pub synthesized_remediation: String,
    pub provider_used: String,
    pub model_used: String,
}

// ============================================================================
// 6. THE AGENTIC SECURITY SUPERVISOR
// ============================================================================

pub struct AgenticSecuritySupervisor {
    pub config: AgentModelConfig,
    binary_tool: BinaryAuditTool,
    mem_tool: ProcessMemoryAuditTool,
    patch_tool: VirtualPatchAdvisorTool,
}

impl AgenticSecuritySupervisor {
    pub fn new(config: AgentModelConfig) -> Self {
        Self {
            config,
            binary_tool: BinaryAuditTool,
            mem_tool: ProcessMemoryAuditTool,
            patch_tool: VirtualPatchAdvisorTool,
        }
    }

    /// Returns definitions of all tools registered with this agent.
    pub fn tool_definitions(&self) -> Vec<ToolDefinition> {
        vec![
            tool_definition(&self.binary_tool),
            tool_definition(&self.mem_tool),
            tool_definition(&self.patch_tool),
        ]
    }

    /// Dispatches a tool by its exact name with arbitrary JSON arguments.
    pub async fn dispatch_tool(
        &self,
        name: &str,
        arguments: serde_json::Value,
    ) -> Result<serde_json::Value, AgentSecurityError> {
        let mut ctx = ToolContext::new();
        match name {
            BinaryAuditTool::NAME => {
                let args: BinaryAuditArgs = serde_json::from_value(arguments)?;
                let output = self.binary_tool.call(&mut ctx, args).await?;
                Ok(serde_json::to_value(output)?)
            }
            ProcessMemoryAuditTool::NAME => {
                let args: ProcessMemoryArgs = serde_json::from_value(arguments)?;
                let output = self.mem_tool.call(&mut ctx, args).await?;
                Ok(serde_json::to_value(output)?)
            }
            VirtualPatchAdvisorTool::NAME => {
                let args: VirtualPatchArgs = serde_json::from_value(arguments)?;
                let output = self.patch_tool.call(&mut ctx, args).await?;
                Ok(serde_json::to_value(output)?)
            }
            other => Err(AgentSecurityError::UnknownTool(other.to_string())),
        }
    }

    /// Invokes the configured LLM provider (Kimi, MiniMax, DeepSeek, Claude, Gemini, OpenAI, Ollama, Open-Weights)
    /// to reason dynamically about complex multi-stage attack chains or incident forensics.
    pub async fn run_model_reasoning(&self, prompt: &str) -> Result<String, AgentSecurityError> {
        let key = self.config.api_key.clone().unwrap_or_default();
        let model = &self.config.model_name;
        let req = CompletionRequest::new(prompt);

        match self.config.provider {
            ModelProvider::DeepSeek => {
                let client = if !key.is_empty() {
                    rig::providers::deepseek::new(key)
                } else {
                    rig::providers::deepseek::from_env().map_err(|e| {
                        AgentSecurityError::Provider(format!("DeepSeek config error: {}", e))
                    })?
                };
                let resp = client.chat(model).call(req).await.map_err(|e| {
                    AgentSecurityError::Provider(format!("DeepSeek call error: {}", e))
                })?;
                Ok(resp.text())
            }
            ModelProvider::Kimi => {
                let client = if !key.is_empty() {
                    rig::providers::moonshot::new(key)
                } else {
                    rig::providers::moonshot::from_env().map_err(|e| {
                        AgentSecurityError::Provider(format!("Kimi/Moonshot config error: {}", e))
                    })?
                };
                let resp =
                    client.chat(model).call(req).await.map_err(|e| {
                        AgentSecurityError::Provider(format!("Kimi call error: {}", e))
                    })?;
                Ok(resp.text())
            }
            ModelProvider::MiniMax => {
                let client = if !key.is_empty() {
                    rig::providers::minimax::new(key)
                } else {
                    rig::providers::minimax::from_env().map_err(|e| {
                        AgentSecurityError::Provider(format!("MiniMax config error: {}", e))
                    })?
                };
                let resp = client.chat(model).call(req).await.map_err(|e| {
                    AgentSecurityError::Provider(format!("MiniMax call error: {}", e))
                })?;
                Ok(resp.text())
            }
            ModelProvider::Claude => {
                let client = if !key.is_empty() {
                    rig::providers::anthropic::Anthropic::new(key)
                } else {
                    rig::providers::anthropic::Anthropic::from_env().map_err(|e| {
                        AgentSecurityError::Provider(format!("Anthropic config error: {}", e))
                    })?
                };
                let resp = client.completion(model).call(req).await.map_err(|e| {
                    AgentSecurityError::Provider(format!("Anthropic call error: {}", e))
                })?;
                Ok(resp.text())
            }
            ModelProvider::Gemini => {
                let client = if !key.is_empty() {
                    rig::providers::gemini::Gemini::new(key)
                } else {
                    rig::providers::gemini::Gemini::from_env().map_err(|e| {
                        AgentSecurityError::Provider(format!("Gemini config error: {}", e))
                    })?
                };
                let resp = client.completion(model).call(req).await.map_err(|e| {
                    AgentSecurityError::Provider(format!("Gemini call error: {}", e))
                })?;
                Ok(resp.text())
            }
            ModelProvider::Ollama => {
                let client = rig::providers::ollama::Ollama::new();
                let resp = client.completion(model).call(req).await.map_err(|e| {
                    AgentSecurityError::Provider(format!("Ollama call error: {}", e))
                })?;
                Ok(resp.text())
            }
            ModelProvider::OpenAi | ModelProvider::OpenWeightsCompatible => {
                let mut config = rig::providers::openai::wire::OpenAIConfig::new(key);
                if let Some(ref base_url) = self.config.base_url {
                    config = config.with_base_url(base_url);
                }
                let client = config.client();
                let resp = client.chat(model).call(req).await.map_err(|e| {
                    AgentSecurityError::Provider(format!("OpenAI/Compatible call error: {}", e))
                })?;
                Ok(resp.text())
            }
            ModelProvider::DeterministicHeuristic => Ok(
                "Deterministic Heuristic Engine active: Zero-latency air-gapped evaluation."
                    .to_string(),
            ),
        }
    }

    /// Orchestrates an autonomous end-to-end investigation workflow across the registered tools
    /// and synthesizes a high-integrity incident response report.
    pub async fn investigate_incident(
        &self,
        context: &IncidentContext,
    ) -> Result<AgenticIncidentReport, AgentSecurityError> {
        let mut mut_ctx = ToolContext::new();

        // 1. Execute Binary Audit if target binary path was specified
        let binary_res = if let Some(ref path) = context.target_binary {
            let args = BinaryAuditArgs { path: path.clone() };
            match self.binary_tool.call(&mut mut_ctx, args).await {
                Ok(out) => Some(out),
                Err(e) => {
                    eprintln!("[AgenticSupervisor] Warning: Binary audit error: {}", e);
                    None
                }
            }
        } else {
            None
        };

        // 2. Execute Process Memory Audit if target PID was specified
        let mem_res = if let Some(pid) = context.target_pid {
            let args = ProcessMemoryArgs { pid };
            match self.mem_tool.call(&mut mut_ctx, args).await {
                Ok(out) => Some(out),
                Err(e) => {
                    eprintln!("[AgenticSupervisor] Warning: Memory audit error: {}", e);
                    None
                }
            }
        } else {
            None
        };

        // 3. Determine vulnerability tag from binary/memory findings or incident context
        let vuln_id = if let Some(ref b) = binary_res {
            if !b.unsafe_symbols_found.is_empty() {
                b.unsafe_symbols_found[0]
                    .split(':')
                    .next()
                    .unwrap_or("CVE-2026-109618")
                    .trim()
                    .to_string()
            } else {
                context
                    .cve_hint
                    .clone()
                    .unwrap_or_else(|| "GENERIC_ANOMALY".to_string())
            }
        } else if let Some(ref m) = mem_res {
            if m.is_exposed {
                "CVE-2026-109618".to_string()
            } else {
                context
                    .cve_hint
                    .clone()
                    .unwrap_or_else(|| "GENERIC_ANOMALY".to_string())
            }
        } else {
            context
                .cve_hint
                .clone()
                .unwrap_or_else(|| "GENERIC_ANOMALY".to_string())
        };

        let target_comp = if let Some(ref b) = binary_res {
            if b.path.contains("php") {
                "php-fpm".to_string()
            } else if b.path.contains("node") || b.path.contains("bun") {
                "nodejs".to_string()
            } else {
                "native-binary".to_string()
            }
        } else {
            "web-runtime".to_string()
        };

        // 4. Execute Virtual Patch Advisor Tool
        let patch_args = VirtualPatchArgs {
            vulnerability_id: vuln_id.clone(),
            target_component: target_comp,
            environment: Some("linux".to_string()),
        };
        let patch_res = match self.patch_tool.call(&mut mut_ctx, patch_args).await {
            Ok(out) => Some(out),
            Err(e) => {
                eprintln!("[AgenticSupervisor] Warning: Patch advisor error: {}", e);
                None
            }
        };

        // 5. Severity determination
        let is_critical = binary_res.as_ref().is_some_and(|b| b.risk_score >= 80)
            || mem_res.as_ref().is_some_and(|m| m.is_exposed);
        let severity = if is_critical { "CRITICAL" } else { "MEDIUM" }.to_string();

        // 6. Synthesis Narrative (Dynamic multi-model reasoning with deterministic air-gapped fallback)
        let root_cause = format!(
            "Incident {} alerted by {}: {}. Vulnerability classification: {}.",
            context.incident_id, context.alert_source, context.anomaly_description, vuln_id
        );

        let synthesized_remediation = if self.config.provider
            != ModelProvider::DeterministicHeuristic
        {
            let prompt = format!(
                "You are an Autonomous Cyber Security Principal Architect and Systems Engineer.\n\
                 Incident Context: ID={}, Source={}, Anomaly={}, Classification={}.\n\
                 Binary Findings: {:?}\n\
                 Memory Findings: {:?}\n\
                 Virtual Patch Proposal: {:?}\n\
                 Provide an authoritative, technical, zero-fluff incident response diagnosis and remediation directives.",
                context.incident_id,
                context.alert_source,
                context.anomaly_description,
                vuln_id,
                binary_res,
                mem_res,
                patch_res
            );
            match self.run_model_reasoning(&prompt).await {
                Ok(reasoning) if !reasoning.trim().is_empty() => reasoning,
                _ => {
                    if let Some(ref p) = patch_res {
                        format!(
                            "IMMEDIATE ACTION: Apply {} on {}. Directives: {:?}. Package Upgrade: '{}'. Rollback: '{}'.",
                            p.patch_strategy,
                            p.target_proxy,
                            p.recommended_directives,
                            p.package_upgrade_command,
                            p.safe_rollback_procedure
                        )
                    } else {
                        "Apply safe system quarantine and review system process integrity."
                            .to_string()
                    }
                }
            }
        } else if let Some(ref p) = patch_res {
            format!(
                "IMMEDIATE ACTION: Apply {} on {}. Directives: {:?}. Package Upgrade: '{}'. Rollback: '{}'.",
                p.patch_strategy,
                p.target_proxy,
                p.recommended_directives,
                p.package_upgrade_command,
                p.safe_rollback_procedure
            )
        } else {
            "Apply safe system quarantine and review system process integrity.".to_string()
        };

        Ok(AgenticIncidentReport {
            incident_id: context.incident_id.clone(),
            severity,
            root_cause,
            binary_audit: binary_res,
            memory_audit: mem_res,
            virtual_patch: patch_res,
            synthesized_remediation,
            provider_used: format!("{:?}", self.config.provider),
            model_used: self.config.model_name.clone(),
        })
    }
}
