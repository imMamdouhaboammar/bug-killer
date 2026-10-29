use crate::dast::{DastProber, DastScopeConfig};
use crate::mcp::protocol::CallToolResult;
use crate::mcp::registry::McpToolRegistration;
use crate::mcp::server::McpServer;
use serde_json::{Value, json};
use std::path::Path;

fn probe_authorized_schema() -> Value {
    json!({
        "type": "object",
        "required": ["url", "authorized"],
        "properties": {
            "url": {"type": "string", "description": "Exact authorized HTTP(S) target URL"},
            "authorized": {"type": "boolean", "description": "Explicit user approval for this URL and host; must be true"},
            "allow_private_targets": {"type": "boolean", "default": false, "description": "Also permit authorized internal-network targets"},
            "allow_sensitive_paths": {"type": "boolean", "default": false, "description": "Permit probing sensitive paths within the same authorized origin"},
            "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": 30, "default": 10}
        }
    })
}

fn handle_probe_authorized(
    _server: &McpServer,
    args: &Value,
    _target_path: &Path,
) -> CallToolResult {
    if args.get("authorized").and_then(Value::as_bool) != Some(true) {
        return CallToolResult::error_text(
            "Authorization Required: explicit user approval for the exact target URL is mandatory",
        );
    }
    let Some(url) = args.get("url").and_then(Value::as_str) else {
        return CallToolResult::error_text("Missing required argument 'url'");
    };
    let Some(timeout_seconds) = args
        .get("timeout_seconds")
        .map(Value::as_u64)
        .unwrap_or(Some(10))
        .filter(|seconds| (1..=30).contains(seconds))
    else {
        return CallToolResult::error_text(
            "Invalid timeout_seconds: expected an integer between 1 and 30",
        );
    };
    let config = DastScopeConfig {
        authorized: true,
        allow_private_targets: args
            .get("allow_private_targets")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        allow_sensitive_paths: args
            .get("allow_sensitive_paths")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        timeout_seconds,
        ..DastScopeConfig::default()
    };
    match DastProber::probe_with_config(url, &config) {
        Ok(report) => CallToolResult::ok_json(&report)
            .unwrap_or_else(|error| CallToolResult::error_text(error.to_string())),
        Err(error) => CallToolResult::error_text(error),
    }
}

pub static TOOLS: &[McpToolRegistration] = &[McpToolRegistration {
    name: "bugkiller_probe_authorized",
    description: "Perform a bounded, read-only DAST probe of an explicitly authorized URL and host. Redirects and out-of-scope destinations are denied.",
    schema: probe_authorized_schema,
    handler: handle_probe_authorized,
}];
