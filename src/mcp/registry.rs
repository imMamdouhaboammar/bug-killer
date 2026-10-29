use crate::mcp::protocol::{CallToolResult, McpTool};
use crate::mcp::server::McpServer;
use crate::mcp::tools;
use serde_json::Value;
use std::path::Path;

pub struct McpToolRegistration {
    pub name: &'static str,
    pub description: &'static str,
    pub schema: fn() -> Value,
    pub handler: fn(&McpServer, &Value, &Path) -> CallToolResult,
}

pub static ALL_TOOL_GROUPS: &[&[McpToolRegistration]] = &[
    tools::core::TOOLS,
    tools::cve::TOOLS,
    tools::probe::TOOLS,
    tools::guard::TOOLS,
    tools::operations::TOOLS,
];

/// Returns the schema of all tools exposed by the Bug Killer MCP server.
pub fn all_tools() -> Vec<McpTool> {
    let mut tools = Vec::with_capacity(32);
    for group in ALL_TOOL_GROUPS {
        for reg in *group {
            tools.push(McpTool {
                name: reg.name.to_string(),
                description: reg.description.to_string(),
                input_schema: (reg.schema)(),
            });
        }
    }
    tools
}

/// Dispatches an incoming MCP tool invocation to its registered handler.
pub fn dispatch(
    server: &McpServer,
    tool_name: &str,
    args: &Value,
    target_path: &Path,
) -> CallToolResult {
    for group in ALL_TOOL_GROUPS {
        for reg in *group {
            if reg.name == tool_name {
                return (reg.handler)(server, args, target_path);
            }
        }
    }
    CallToolResult::error_text(format!("Unknown tool: {}", tool_name))
}

/// Retrieves a specific tool definition by its registered identifier.
pub fn get_tool(tool_name: &str) -> Option<&'static McpToolRegistration> {
    for group in ALL_TOOL_GROUPS {
        for reg in *group {
            if reg.name == tool_name {
                return Some(reg);
            }
        }
    }
    None
}

/// Returns the list of all registered tool names.
pub fn registered_tool_names() -> Vec<&'static str> {
    let mut names = Vec::with_capacity(32);
    for group in ALL_TOOL_GROUPS {
        for reg in *group {
            names.push(reg.name);
        }
    }
    names
}
