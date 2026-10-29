use crate::catalog::SecurityCatalog;
use crate::mcp::protocol::CallToolResult;
use crate::mcp::registry::McpToolRegistration;
use crate::mcp::server::McpServer;
use crate::security_guard::SecurityGuard;
use crate::types::*;
use serde_json::{Value, json};
use std::path::Path;

fn security_status_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "path": { "type": "string", "default": "." }
        }
    })
}

fn handle_security_status(
    _server: &McpServer,
    _args: &Value,
    target_path: &Path,
) -> CallToolResult {
    let status = SecurityGuard::status(target_path);
    CallToolResult::ok_json(&status).unwrap_or_else(|e| CallToolResult::error_text(e.to_string()))
}

fn scan_project_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "path": { "type": "string", "default": "." },
            "osv": { "type": "boolean", "default": false }
        }
    })
}

fn handle_scan_project(_server: &McpServer, args: &Value, target_path: &Path) -> CallToolResult {
    let osv = args.get("osv").and_then(Value::as_bool).unwrap_or(false);
    let report = SecurityGuard::scan(target_path, ScanProfile::Project, false, osv);
    CallToolResult::ok_json(&report).unwrap_or_else(|e| CallToolResult::error_text(e.to_string()))
}

fn scan_changed_files_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "path": { "type": "string", "default": "." }
        }
    })
}

fn handle_scan_changed_files(
    _server: &McpServer,
    _args: &Value,
    target_path: &Path,
) -> CallToolResult {
    let report = SecurityGuard::scan(target_path, ScanProfile::Quick, true, false);
    CallToolResult::ok_json(&report).unwrap_or_else(|e| CallToolResult::error_text(e.to_string()))
}

fn list_findings_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "path": { "type": "string", "default": "." },
            "severity": { "type": "string" },
            "rule_id": { "type": "string" }
        }
    })
}

fn handle_list_findings(_server: &McpServer, args: &Value, target_path: &Path) -> CallToolResult {
    let report = SecurityGuard::scan(target_path, ScanProfile::Quick, false, false);
    let sev_filter = args
        .get("severity")
        .and_then(Value::as_str)
        .map(|s| s.to_lowercase());
    let rule_filter = args
        .get("rule_id")
        .and_then(Value::as_str)
        .map(|s| s.to_lowercase());

    let filtered: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|f| {
            if let Some(ref sev) = sev_filter {
                if !format!("{:?}", f.severity).to_lowercase().contains(sev) {
                    return false;
                }
            }
            if let Some(ref r) = rule_filter {
                if !f.cve.as_str().to_lowercase().contains(r) {
                    return false;
                }
            }
            true
        })
        .collect();

    let out = json!({
        "total_findings": filtered.len(),
        "findings": filtered,
    });
    CallToolResult::ok_json(&out).unwrap_or_else(|e| CallToolResult::error_text(e.to_string()))
}

fn explain_finding_schema() -> Value {
    json!({
        "type": "object",
        "required": ["finding_id"],
        "properties": {
            "finding_id": { "type": "string" },
            "path": { "type": "string", "default": "." }
        }
    })
}

fn handle_explain_finding(_server: &McpServer, args: &Value, target_path: &Path) -> CallToolResult {
    let finding_id = args.get("finding_id").and_then(Value::as_str).unwrap_or("");
    if finding_id.is_empty() {
        return CallToolResult::error_text("finding_id is required".to_string());
    }
    match SecurityGuard::explain(finding_id, target_path) {
        Some(explanation) => CallToolResult::ok_json(&explanation)
            .unwrap_or_else(|e| CallToolResult::error_text(e.to_string())),
        None => CallToolResult::error_text(format!("Finding '{}' not found", finding_id)),
    }
}

fn get_rule_schema() -> Value {
    json!({
        "type": "object",
        "required": ["rule_id"],
        "properties": {
            "rule_id": { "type": "string" }
        }
    })
}

fn handle_get_rule(_server: &McpServer, args: &Value, _target_path: &Path) -> CallToolResult {
    let rule_id = args.get("rule_id").and_then(Value::as_str).unwrap_or("");
    let catalog = SecurityCatalog::global();
    match catalog.get_rule(rule_id) {
        Some(rule) => CallToolResult::ok_json(rule)
            .unwrap_or_else(|e| CallToolResult::error_text(e.to_string())),
        None => {
            CallToolResult::error_text(format!("Rule '{}' not found in security catalog", rule_id))
        }
    }
}

fn propose_fix_schema() -> Value {
    json!({
        "type": "object",
        "required": ["finding_id"],
        "properties": {
            "finding_id": { "type": "string" },
            "path": { "type": "string", "default": "." }
        }
    })
}

fn handle_propose_fix(_server: &McpServer, args: &Value, target_path: &Path) -> CallToolResult {
    let finding_id = args.get("finding_id").and_then(Value::as_str).unwrap_or("");
    if finding_id.is_empty() {
        return CallToolResult::error_text("finding_id is required".to_string());
    }
    match SecurityGuard::plan_fix(finding_id, target_path) {
        Ok(plan) => CallToolResult::ok_json(&plan)
            .unwrap_or_else(|e| CallToolResult::error_text(e.to_string())),
        Err(e) => CallToolResult::error_text(e),
    }
}

fn verify_fix_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "path": { "type": "string", "default": "." }
        }
    })
}

fn handle_verify_fix(_server: &McpServer, _args: &Value, target_path: &Path) -> CallToolResult {
    let report = SecurityGuard::scan(target_path, ScanProfile::Quick, false, false);
    let is_clean = report.is_clean();
    let out = json!({
        "is_clean": is_clean,
        "status": report.status,
        "result_classification": report.result_classification,
        "unresolved_findings": report.findings.len(),
        "coverage_complete": report.coverage.is_complete(),
    });
    CallToolResult::ok_json(&out).unwrap_or_else(|e| CallToolResult::error_text(e.to_string()))
}

fn get_coverage_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "path": { "type": "string", "default": "." }
        }
    })
}

fn handle_get_coverage(_server: &McpServer, _args: &Value, target_path: &Path) -> CallToolResult {
    let report = SecurityGuard::scan(target_path, ScanProfile::Quick, false, false);
    let out = json!({
        "coverage_status": report.coverage.coverage_status,
        "files_assessed": report.files_assessed,
        "rules_evaluated": report.rules_evaluated,
        "applicable_rules": report.applicable_rules,
        "unsupported_rules": report.unsupported_rules,
        "receipts": report.receipts,
        "unexamined_reasons": report.unexamined_reasons,
    });
    CallToolResult::ok_json(&out).unwrap_or_else(|e| CallToolResult::error_text(e.to_string()))
}

fn security_guidance_schema() -> Value {
    json!({
        "type": "object",
        "required": ["task"],
        "properties": {
            "task": { "type": "string" },
            "language": { "type": "string", "default": "generic" }
        }
    })
}

fn handle_security_guidance(
    _server: &McpServer,
    args: &Value,
    _target_path: &Path,
) -> CallToolResult {
    let task = args.get("task").and_then(Value::as_str).unwrap_or("");
    let lang = args
        .get("language")
        .and_then(Value::as_str)
        .unwrap_or("generic");
    let guidance = SecurityGuard::guidance(task, lang);
    CallToolResult::ok_json(&guidance).unwrap_or_else(|e| CallToolResult::error_text(e.to_string()))
}

pub static TOOLS: &[McpToolRegistration] = &[
    McpToolRegistration {
        name: "bugkiller_security_status",
        description: "Query project initialization state, baseline findings, and security guard status.",
        schema: security_status_schema,
        handler: handle_security_status,
    },
    McpToolRegistration {
        name: "bugkiller_scan_project",
        description: "Execute full project security guard scan across all applicable catalog rules.",
        schema: scan_project_schema,
        handler: handle_scan_project,
    },
    McpToolRegistration {
        name: "bugkiller_scan_changed_files",
        description: "Execute fast incremental scan on changed or git-modified files only.",
        schema: scan_changed_files_schema,
        handler: handle_scan_changed_files,
    },
    McpToolRegistration {
        name: "bugkiller_list_findings",
        description: "List detected security findings filtered by rule, severity, or affectedness.",
        schema: list_findings_schema,
        handler: handle_list_findings,
    },
    McpToolRegistration {
        name: "bugkiller_explain_finding",
        description: "Retrieve comprehensive security catalog explanation, CWE reference, and remediation requirements for a finding.",
        schema: explain_finding_schema,
        handler: handle_explain_finding,
    },
    McpToolRegistration {
        name: "bugkiller_get_rule",
        description: "Look up a rule in the 373-rule AI-Generated Code Security Catalog by rule ID (e.g. BK-AI-INJ-001 or INJ-001).",
        schema: get_rule_schema,
        handler: handle_get_rule,
    },
    McpToolRegistration {
        name: "bugkiller_propose_fix",
        description: "Generate a bounded, non-mutating repair proposal and diff preview for a detected security issue.",
        schema: propose_fix_schema,
        handler: handle_propose_fix,
    },
    McpToolRegistration {
        name: "bugkiller_verify_fix",
        description: "Independently verify whether a security failure still occurs and check coverage completeness.",
        schema: verify_fix_schema,
        handler: handle_verify_fix,
    },
    McpToolRegistration {
        name: "bugkiller_get_coverage",
        description: "Retrieve truthful coverage receipt, evaluated rules, and list of unexamined/unsupported catalog rules.",
        schema: get_coverage_schema,
        handler: handle_get_coverage,
    },
    McpToolRegistration {
        name: "bugkiller_security_guidance",
        description: "Request pre-generation task-scoped security guidance, safe patterns, and banned anti-patterns before coding.",
        schema: security_guidance_schema,
        handler: handle_security_guidance,
    },
];
