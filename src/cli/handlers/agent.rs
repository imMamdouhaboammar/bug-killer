use crate::agent::investigation::InvestigationSupervisor;
use crate::agent::privacy::PrivacyPolicy;
use crate::agent::provider::{AgentModelConfig, ModelProvider, ProviderAdapter};
use crate::cli::{AgentCommands, McpCommands};
use crate::mcp::{HostConfigGenerator, McpServer};

pub fn handle_agent(cmd: AgentCommands) -> i32 {
    match cmd {
        AgentCommands::Doctor { provider, json } => {
            let model_provider = ModelProvider::from_str_loose(&provider);
            let config = AgentModelConfig {
                provider: model_provider,
                model_name: "default".into(),
                ..Default::default()
            };
            let adapter = ProviderAdapter::new(config);
            let health = adapter.check_health();
            if json {
                println!("{}", serde_json::to_string_pretty(&health).unwrap());
                return 0;
            }
            println!("\n=======================================================");
            println!("  🤖  BUG KILLER AGENT PROVIDER HEALTH & CAPABILITY");
            println!("=======================================================");
            println!("Provider:          {}", health.provider);
            println!("Model:             {}", health.model);
            println!(
                "Available:         {}",
                if health.is_available {
                    "READY ✅"
                } else {
                    "NOT READY ⚠️"
                }
            );
            println!(
                "Local / Offline:   {}",
                if health.is_local {
                    "YES (Air-gapped)"
                } else {
                    "NO (Remote Network)"
                }
            );
            println!("Endpoint:          {}", health.endpoint);
            println!(
                "Requires Key:      {}",
                if health.requires_key { "YES" } else { "NO" }
            );
            println!(
                "Key Configured:    {}",
                if health.key_configured {
                    "YES (Set in environment)"
                } else {
                    "NO (Unset)"
                }
            );
            println!(
                "Function Calling:  {}",
                if health.capability.supports_function_calling {
                    "YES"
                } else {
                    "NO"
                }
            );
            println!(
                "Structured Output: {}",
                if health.capability.supports_structured_output {
                    "YES"
                } else {
                    "NO"
                }
            );
            println!(
                "Max Context:       {} tokens",
                health.capability.max_context_tokens
            );
            println!(
                "Max Output:        {} tokens\n",
                health.capability.max_output_tokens
            );
            0
        }

        AgentCommands::Investigate {
            path,
            provider,
            model,
            mode: _mode,
            max_steps,
            export_profile,
            json,
        } => {
            let model_prov = ModelProvider::from_str_loose(&provider);
            let model_name = model.unwrap_or_else(|| "default".into());
            let privacy_policy = if let Some(ref _profile) = export_profile {
                PrivacyPolicy::new_approved_export(vec![provider.clone()])
            } else {
                PrivacyPolicy::default()
            };

            let config = AgentModelConfig {
                provider: model_prov,
                model_name,
                privacy_policy,
                ..Default::default()
            };

            let adapter = ProviderAdapter::new(config);
            let mut supervisor = InvestigationSupervisor::new(adapter, max_steps);
            match supervisor.run_investigation(&path) {
                Ok(report) => {
                    if json {
                        println!("{}", serde_json::to_string_pretty(&report).unwrap());
                        return 0;
                    }
                    println!("\n=======================================================");
                    println!("  🔍  AUTONOMOUS AGENT INVESTIGATION REPORT");
                    println!("=======================================================");
                    println!("Investigation ID:  {}", report.investigation_id);
                    println!("Target Directory:  {}", report.target_dir.display());
                    println!("Terminal State:    {:?}", report.state);
                    println!(
                        "Steps Executed:    {}/{}",
                        report.total_steps, report.max_steps_allowed
                    );
                    println!("Findings Found:    {}", report.findings.len());
                    println!("Plans Proposed:    {}", report.proposed_plans.len());
                    println!("Vetoes Triggered:  {}", report.vetoes.len());
                    println!("Audit Digest:      {}\n", report.audit_digest);

                    for step in &report.steps_history {
                        println!(
                            "Step {}: [{:?}] {} -> {}",
                            step.step_index, step.state, step.action, step.outcome_summary
                        );
                    }
                    println!();
                    0
                }
                Err(e) => {
                    eprintln!("Investigation failed: {}", e);
                    4
                }
            }
        }
    }
}

pub fn handle_mcp(cmd: McpCommands) -> i32 {
    match cmd {
        McpCommands::Serve {
            transport,
            read_only,
            path,
        } => {
            if transport != "stdio" {
                eprintln!(
                    "Unsupported transport: '{}'. Only 'stdio' is currently supported.",
                    transport
                );
                return 5;
            }
            let mut server = McpServer::new(path, read_only);
            if let Err(e) = server.run_stdio() {
                eprintln!("MCP server error: {}", e);
                return 5;
            }
            0
        }
        McpCommands::Config { host, binary } => {
            let bin_ref = binary.as_deref();
            match host.to_lowercase().as_str() {
                "claude" | "claude-code" => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&HostConfigGenerator::claude_code_config(
                            bin_ref
                        ))
                        .unwrap()
                    );
                }
                "codex" => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&HostConfigGenerator::codex_config(bin_ref))
                            .unwrap()
                    );
                }
                "gemini" | "gemini-cli" => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&HostConfigGenerator::gemini_cli_config(
                            bin_ref
                        ))
                        .unwrap()
                    );
                }
                _ => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&HostConfigGenerator::generate_all(bin_ref))
                            .unwrap()
                    );
                }
            }
            0
        }
    }
}
