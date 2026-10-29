use crate::mcp::protocol::*;
use crate::mcp::registry;
use serde_json::{Value, json};
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

pub struct McpServer {
    pub read_only: bool,
    pub workspace_root: PathBuf,
}

// @lat: [[mcp#Stdio Protocol Server]]
impl McpServer {
    pub fn new(workspace_root: PathBuf, read_only: bool) -> Self {
        Self {
            read_only,
            workspace_root,
        }
    }

    /// Returns the schema of all tools exposed by the Bug Killer MCP server.
    pub fn list_tools(&self) -> Vec<McpTool> {
        registry::all_tools()
    }

    /// Handles a single incoming JSON-RPC line and returns the response string if one is required.
    pub fn handle_json_rpc_line(&mut self, line: &str) -> Option<String> {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return None;
        }

        let req: JsonRpcRequest = match serde_json::from_str(trimmed) {
            Ok(r) => r,
            Err(e) => {
                let err_resp = JsonRpcResponse::error(None, -32700, format!("Parse error: {}", e));
                return serde_json::to_string(&err_resp).ok();
            }
        };

        let id = req.id.clone();
        let method = req.method.as_str();

        // Notifications do not return responses
        if id.is_none() && method.starts_with("notifications/") {
            return None;
        }

        match method {
            "initialize" => {
                let result = InitializeResult {
                    protocol_version: "2024-11-05".into(),
                    capabilities: ServerCapabilities {
                        tools: ToolsCapability {
                            list_changed: Some(false),
                        },
                    },
                    server_info: ServerInfo {
                        name: "bug-killer".into(),
                        version: env!("CARGO_PKG_VERSION").into(),
                    },
                };
                let resp = JsonRpcResponse::success(id, serde_json::to_value(result).unwrap());
                serde_json::to_string(&resp).ok()
            }

            "ping" => {
                let resp = JsonRpcResponse::success(id, json!({}));
                serde_json::to_string(&resp).ok()
            }

            "tools/list" => {
                let tools = self.list_tools();
                let resp = JsonRpcResponse::success(id, json!({ "tools": tools }));
                serde_json::to_string(&resp).ok()
            }

            "tools/call" => {
                let params = req.params.unwrap_or(Value::Null);
                let tool_name = params.get("name").and_then(Value::as_str).unwrap_or("");
                let arguments = params.get("arguments").cloned().unwrap_or(json!({}));

                let tool_result = self.execute_tool(tool_name, &arguments);
                let resp = JsonRpcResponse::success(id, serde_json::to_value(tool_result).unwrap());
                serde_json::to_string(&resp).ok()
            }

            _ => {
                let resp = JsonRpcResponse::method_not_found(id, method);
                serde_json::to_string(&resp).ok()
            }
        }
    }

    fn execute_tool(&mut self, tool_name: &str, args: &Value) -> CallToolResult {
        let path_str = args.get("path").and_then(Value::as_str).unwrap_or(".");
        let target_path = match self.resolve_path(path_str) {
            Ok(path) => path,
            Err(error) => return CallToolResult::error_text(error),
        };

        registry::dispatch(self, tool_name, args, &target_path)
    }

    fn resolve_path(&self, raw: &str) -> Result<PathBuf, String> {
        let root = self
            .workspace_root
            .canonicalize()
            .map_err(|e| format!("Workspace root is unavailable: {e}"))?;
        let p = Path::new(raw);
        let candidate = if p.is_absolute() {
            p.to_path_buf()
        } else {
            root.join(p)
        };
        let path = candidate
            .canonicalize()
            .map_err(|e| format!("Scan path is unavailable: {e}"))?;
        if !path.starts_with(&root) {
            return Err(
                "Security Boundary Violation: requested path escapes MCP workspace".to_string(),
            );
        }
        Ok(path)
    }

    /// Runs the MCP server reading from standard input and writing to standard output.
    pub fn run_stdio(&mut self) -> Result<(), std::io::Error> {
        let stdin = std::io::stdin();
        let mut stdout = std::io::stdout();

        for line in stdin.lock().lines() {
            let line = line?;
            if let Some(resp) = self.handle_json_rpc_line(&line) {
                writeln!(stdout, "{}", resp)?;
                stdout.flush()?;
            }
        }
        Ok(())
    }
}
