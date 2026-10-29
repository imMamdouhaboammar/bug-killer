use crate::mcp::protocol::CallToolResult;
use crate::mcp::registry::McpToolRegistration;
use crate::mcp::server::McpServer;
use serde_json::{Value, json};
use std::path::Path;

fn cve_triage_schema() -> Value {
    json!({
        "type": "object",
        "required": ["cve_id"],
        "properties": {
            "cve_id": {
                "type": "string",
                "description": "CVE identifier to triage (e.g. CVE-2026-109618)"
            }
        }
    })
}

fn handle_cve_triage(_server: &McpServer, args: &Value, _target_path: &Path) -> CallToolResult {
    let Some(cve_id) = args.get("cve_id").and_then(Value::as_str) else {
        return CallToolResult::error_text("Missing required argument 'cve_id'");
    };
    let adapter = crate::deep::cve_mcp::CveMcpAdapter::new();
    match adapter.triage_cve(cve_id) {
        Ok(triage) => CallToolResult::ok_json(&triage)
            .unwrap_or_else(|e| CallToolResult::error_text(e.to_string())),
        Err(e) => CallToolResult::error_text(e),
    }
}

fn cve_lookup_schema() -> Value {
    json!({
        "type": "object",
        "required": ["cve_id"],
        "properties": {
            "cve_id": {
                "type": "string",
                "description": "CVE identifier (e.g. CVE-2026-109618)"
            }
        }
    })
}

fn handle_cve_lookup(_server: &McpServer, args: &Value, _target_path: &Path) -> CallToolResult {
    let Some(cve_id) = args.get("cve_id").and_then(Value::as_str) else {
        return CallToolResult::error_text("Missing required argument 'cve_id'");
    };
    let adapter = crate::deep::cve_mcp::CveMcpAdapter::new();
    let triage = adapter.triage_cve(cve_id);
    let kev = adapter.check_kev(cve_id);
    let epss = adapter.get_epss(cve_id);
    let lookup = json!({
        "cve_id": cve_id,
        "triage": triage.ok(),
        "kev": kev.ok(),
        "epss": epss.ok(),
    });
    CallToolResult::ok_json(&lookup).unwrap_or_else(|e| CallToolResult::error_text(e.to_string()))
}

fn cve_kev_check_schema() -> Value {
    json!({
        "type": "object",
        "required": ["cve_id"],
        "properties": {
            "cve_id": {
                "type": "string",
                "description": "CVE identifier to check in KEV"
            }
        }
    })
}

fn handle_cve_kev_check(_server: &McpServer, args: &Value, _target_path: &Path) -> CallToolResult {
    let Some(cve_id) = args.get("cve_id").and_then(Value::as_str) else {
        return CallToolResult::error_text("Missing required argument 'cve_id'");
    };
    let adapter = crate::deep::cve_mcp::CveMcpAdapter::new();
    match adapter.check_kev(cve_id) {
        Ok(kev) => CallToolResult::ok_json(&kev)
            .unwrap_or_else(|e| CallToolResult::error_text(e.to_string())),
        Err(e) => CallToolResult::error_text(e),
    }
}

pub static TOOLS: &[McpToolRegistration] = &[
    McpToolRegistration {
        name: "bk.cve_triage",
        description: "Triage a CVE with composite risk scoring (0-100), CISA KEV priority override, EPSS exploitation probability, and actionable remediation SLA.",
        schema: cve_triage_schema,
        handler: handle_cve_triage,
    },
    McpToolRegistration {
        name: "bk.cve_lookup",
        description: "Look up vulnerability details, EPSS score, and CISA KEV status for a CVE identifier.",
        schema: cve_lookup_schema,
        handler: handle_cve_lookup,
    },
    McpToolRegistration {
        name: "bk.cve_kev_check",
        description: "Check if a CVE is in the CISA Known Exploited Vulnerabilities (KEV) catalog with due dates.",
        schema: cve_kev_check_schema,
        handler: handle_cve_kev_check,
    },
];
