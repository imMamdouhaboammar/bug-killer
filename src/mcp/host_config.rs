use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostConfigGenerator;

impl HostConfigGenerator {
    /// Generates Claude Code MCP configuration
    pub fn claude_code_config(binary_path: Option<&str>) -> Value {
        let cmd = binary_path.unwrap_or("bug-killer");
        json!({
            "mcpServers": {
                "bug-killer": {
                    "command": cmd,
                    "args": ["mcp", "serve", "--transport", "stdio", "--read-only"],
                    "description": "Bug Killer: Autonomous Vulnerability Finder & Virtual Healer (Read-Only MCP Server)"
                }
            }
        })
    }

    /// Generates Codex MCP configuration
    pub fn codex_config(binary_path: Option<&str>) -> Value {
        let cmd = binary_path.unwrap_or("bug-killer");
        json!({
            "mcpServers": {
                "bug-killer": {
                    "command": cmd,
                    "args": ["mcp", "serve", "--transport", "stdio", "--read-only"],
                    "description": "Bug Killer MCP Integration for Codex Agents"
                }
            }
        })
    }

    /// Generates Gemini CLI MCP configuration
    pub fn gemini_cli_config(binary_path: Option<&str>) -> Value {
        let cmd = binary_path.unwrap_or("bug-killer");
        json!({
            "mcpServers": {
                "bug-killer": {
                    "command": cmd,
                    "args": ["mcp", "serve", "--transport", "stdio", "--read-only"],
                    "description": "Bug Killer Security MCP Server for Gemini CLI"
                }
            }
        })
    }

    /// Generates CVE MCP Server configuration snippet
    pub fn cve_mcp_config(server_dir: Option<&str>) -> Value {
        let dir = server_dir.unwrap_or("services/cve-mcp-server");
        json!({
            "command": "uv",
            "args": ["run", "--directory", dir, "cve-mcp"],
            "description": "CVE MCP Server: Correlated Vulnerability Triage, EPSS & CISA KEV Intelligence"
        })
    }

    /// Generates combined multi-host configuration manifest
    pub fn generate_all(binary_path: Option<&str>) -> Value {
        json!({
            "claude_code": Self::claude_code_config(binary_path),
            "codex": Self::codex_config(binary_path),
            "gemini_cli": Self::gemini_cli_config(binary_path),
        })
    }
}
