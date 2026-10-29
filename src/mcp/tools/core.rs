use crate::healer::AutopilotHealer;
use crate::mcp::protocol::CallToolResult;
use crate::mcp::registry::McpToolRegistration;
use crate::mcp::server::McpServer;
use crate::osv::OsvClient;
use crate::scanner::FleetScanner;
use crate::scanner::ai_agent::AgentSecurityScanner;
use crate::scanner::host::HostProcessScanner;
use crate::types::*;
use serde_json::{Value, json};
use std::path::Path;

fn asset_inventory_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "path": {
                "type": "string",
                "description": "Path to inspect (default: workspace root)",
                "default": "."
            }
        }
    })
}

fn handle_asset_inventory(
    _server: &McpServer,
    _args: &Value,
    target_path: &Path,
) -> CallToolResult {
    let packages = OsvClient::discover_packages(target_path);
    let processes = HostProcessScanner::discover_running_processes();
    let inventory = json!({
        "workspace": target_path.display().to_string(),
        "discovered_packages_count": packages.len(),
        "packages": packages,
        "host_processes_running": processes.len(),
        "processes": processes,
    });
    CallToolResult::ok_json(&inventory)
        .unwrap_or_else(|e| CallToolResult::error_text(e.to_string()))
}

fn scan_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "path": {
                "type": "string",
                "description": "Workspace or file path to scan",
                "default": "."
            },
            "taint": {
                "type": "boolean",
                "description": "Enable AST taint analysis dataflow checking",
                "default": false
            }
        }
    })
}

fn handle_scan(_server: &McpServer, args: &Value, target_path: &Path) -> CallToolResult {
    let taint = args.get("taint").and_then(Value::as_bool).unwrap_or(false);
    let scan_report =
        FleetScanner::scan_directory_with_rules_and_taint(target_path, true, &[], taint);
    CallToolResult::ok_json(&scan_report)
        .unwrap_or_else(|e| CallToolResult::error_text(e.to_string()))
}

fn findings_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "path": {
                "type": "string",
                "description": "Path to query findings for",
                "default": "."
            },
            "cve": {
                "type": "string",
                "description": "Filter by CVE ID (e.g. CVE-2026-109618, CVE-2026-111497)"
            },
            "severity": {
                "type": "string",
                "description": "Filter by severity (CRITICAL, HIGH, MEDIUM, LOW)"
            },
            "affectedness": {
                "type": "string",
                "description": "Filter by affectedness (CONFIRMED_AFFECTED, POTENTIALLY_AFFECTED, NOT_AFFECTED_WITH_EVIDENCE)"
            },
            "reachability": {
                "type": "string",
                "description": "Filter by reachability (REACHABLE, UNREACHABLE, UNKNOWN)"
            },
            "evidence_certainty": {
                "type": "string",
                "description": "Filter by evidence certainty (Confirmed, StronglySupported, Suspected, PatternIndicator, Unknown)"
            },
            "taint": {
                "type": "boolean",
                "description": "Include AST taint analysis dataflow checking (default: true)",
                "default": true
            }
        }
    })
}

fn handle_findings(_server: &McpServer, args: &Value, target_path: &Path) -> CallToolResult {
    let taint = args.get("taint").and_then(Value::as_bool).unwrap_or(true);
    let scan_report =
        FleetScanner::scan_directory_with_rules_and_taint(target_path, true, &[], taint);
    let cve_filter = args
        .get("cve")
        .and_then(Value::as_str)
        .map(|s| s.to_lowercase());
    let sev_filter = args
        .get("severity")
        .and_then(Value::as_str)
        .map(|s| s.to_lowercase());
    let aff_filter = args
        .get("affectedness")
        .and_then(Value::as_str)
        .map(|s| s.to_lowercase());
    let reach_filter = args
        .get("reachability")
        .and_then(Value::as_str)
        .map(|s| s.to_lowercase());
    let certainty_filter = args
        .get("evidence_certainty")
        .and_then(Value::as_str)
        .map(|s| s.to_lowercase());

    let filtered: Vec<&Finding> = scan_report
        .findings
        .iter()
        .filter(|f| {
            if let Some(ref c) = cve_filter {
                if !f.cve.as_str().to_lowercase().contains(c) {
                    return false;
                }
            }
            if let Some(ref s) = sev_filter {
                let f_sev = format!("{:?}", f.severity).to_lowercase();
                if !f_sev.contains(s) {
                    return false;
                }
            }
            if let Some(ref a) = aff_filter {
                if !f.affectedness.as_str().to_lowercase().contains(a) {
                    return false;
                }
            }
            if let Some(ref r) = reach_filter {
                if !f.reachability.as_str().to_lowercase().contains(r) {
                    return false;
                }
            }
            if let Some(ref cert) = certainty_filter {
                let f_cert = format!("{:?}", f.evidence_certainty).to_lowercase();
                if !f_cert.contains(cert) {
                    return false;
                }
            }
            true
        })
        .collect();

    let out = json!({
        "total_matches": filtered.len(),
        "findings": filtered,
        "coverage": scan_report.coverage,
    });
    CallToolResult::ok_json(&out).unwrap_or_else(|e| CallToolResult::error_text(e.to_string()))
}

fn evidence_schema() -> Value {
    json!({
        "type": "object",
        "required": ["finding_id"],
        "properties": {
            "finding_id": {
                "type": "string",
                "description": "Finding identifier or deduplication hash prefix"
            },
            "path": {
                "type": "string",
                "description": "Workspace path (default: .)",
                "default": "."
            }
        }
    })
}

fn handle_evidence(_server: &McpServer, args: &Value, target_path: &Path) -> CallToolResult {
    let finding_id = match args.get("finding_id").and_then(Value::as_str) {
        Some(id) => id,
        None => {
            return CallToolResult::error_text("Missing required argument 'finding_id'");
        }
    };
    let scan_report = FleetScanner::scan_directory(target_path, true);
    let target = scan_report
        .findings
        .iter()
        .find(|f| f.id == finding_id || f.dedupe_fingerprint.starts_with(finding_id));

    match target {
        Some(f) => {
            CallToolResult::ok_json(f).unwrap_or_else(|e| CallToolResult::error_text(e.to_string()))
        }
        None => {
            CallToolResult::error_text(format!("Finding '{}' not found in workspace", finding_id))
        }
    }
}

fn plan_schema() -> Value {
    json!({
        "type": "object",
        "required": ["finding_id"],
        "properties": {
            "finding_id": {
                "type": "string",
                "description": "Finding identifier or deduplication hash prefix"
            },
            "path": {
                "type": "string",
                "description": "Workspace path (default: .)",
                "default": "."
            }
        }
    })
}

fn handle_plan(_server: &McpServer, args: &Value, target_path: &Path) -> CallToolResult {
    let finding_id = match args.get("finding_id").and_then(Value::as_str) {
        Some(id) => id,
        None => {
            return CallToolResult::error_text("Missing required argument 'finding_id'");
        }
    };
    let scan_report = FleetScanner::scan_directory(target_path, true);
    let target = scan_report
        .findings
        .iter()
        .find(|f| f.id == finding_id || f.dedupe_fingerprint.starts_with(finding_id));

    match target {
        Some(f) => {
            let single_report = ScanReport {
                findings: vec![f.clone()],
                ..scan_report
            };
            let plan = AutopilotHealer::plan_healing(&single_report);
            let plan_dto = json!({
                "finding_id": f.id,
                "cve": f.cve.as_str(),
                "patches_planned": plan.len(),
                "actions": plan,
                "mode": "PROSPECTIVE_PLAN_ONLY",
                "non_mutating": true,
            });
            CallToolResult::ok_json(&plan_dto)
                .unwrap_or_else(|e| CallToolResult::error_text(e.to_string()))
        }
        None => {
            CallToolResult::error_text(format!("Finding '{}' not found in workspace", finding_id))
        }
    }
}

fn verify_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "path": {
                "type": "string",
                "description": "Workspace path to verify",
                "default": "."
            }
        }
    })
}

fn handle_verify(_server: &McpServer, _args: &Value, target_path: &Path) -> CallToolResult {
    let scan_report = FleetScanner::scan_directory(target_path, true);
    let is_clean = scan_report.is_clean();
    let out = json!({
        "is_clean": is_clean,
        "coverage_status": scan_report.coverage.coverage_status,
        "total_files_scanned": scan_report.total_files_scanned,
        "unresolved_findings_count": scan_report.findings.len(),
        "parser_failures": scan_report.coverage.parser_failures,
        "verified": is_clean,
    });
    CallToolResult::ok_json(&out).unwrap_or_else(|e| CallToolResult::error_text(e.to_string()))
}

fn skill_scan_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "path": {
                "type": "string",
                "description": "Workspace or skill file path to scan",
                "default": "."
            }
        }
    })
}

fn handle_skill_scan(_server: &McpServer, _args: &Value, target_path: &Path) -> CallToolResult {
    let mut findings = Vec::new();
    if target_path.is_file() {
        let name = target_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");
        if name.ends_with(".md") {
            findings.extend(AgentSecurityScanner::scan_agent_skill(target_path));
        } else if name.ends_with(".json") {
            findings.extend(AgentSecurityScanner::scan_mcp_config(target_path));
        }
    } else if target_path.is_dir() {
        for entry in walkdir::WalkDir::new(target_path).into_iter().flatten() {
            let p = entry.path();
            if p.file_name().is_some_and(|n| n == "SKILL.md") {
                findings.extend(AgentSecurityScanner::scan_agent_skill(p));
            } else if p.file_name().is_some_and(|n| n == ".mcp.json") {
                findings.extend(AgentSecurityScanner::scan_mcp_config(p));
            }
        }
    }
    let out = json!({
        "skills_scanned_path": target_path.display().to_string(),
        "risks_found": findings.len(),
        "findings": findings,
    });
    CallToolResult::ok_json(&out).unwrap_or_else(|e| CallToolResult::error_text(e.to_string()))
}

fn status_schema() -> Value {
    json!({
        "type": "object"
    })
}

fn handle_status(server: &McpServer, _args: &Value, _target_path: &Path) -> CallToolResult {
    let status = json!({
        "service": "bug-killer",
        "version": env!("CARGO_PKG_VERSION"),
        "read_only_mode": server.read_only,
        "workspace_root": server.workspace_root.display().to_string(),
        "agent_identity_configured": server.workspace_root.join(".aegis/agent_identity.key").is_file(),
        "trust_anchor": "Ed25519 Project Key (.aegis/agent_identity.key)",
        "transport": "stdio",
    });
    CallToolResult::ok_json(&status).unwrap_or_else(|e| CallToolResult::error_text(e.to_string()))
}

fn apply_plan_schema() -> Value {
    json!({
        "type": "object",
        "required": ["plan_id", "approval_receipt"],
        "properties": {
            "plan_id": {
                "type": "string",
                "description": "Deterministic ID of plan to apply"
            },
            "approval_receipt": {
                "type": "string",
                "description": "Operator approval token or cryptographic receipt path"
            },
            "path": {
                "type": "string",
                "description": "Target workspace path",
                "default": "."
            }
        }
    })
}

fn handle_apply_plan(server: &McpServer, args: &Value, _target_path: &Path) -> CallToolResult {
    if server.read_only {
        return CallToolResult::error_text(
            "Policy Denied: MCP server is operating in read-only mode (--read-only). File mutations are strictly prohibited.",
        );
    }
    let receipt = args
        .get("approval_receipt")
        .and_then(Value::as_str)
        .unwrap_or("");
    if receipt.is_empty() {
        return CallToolResult::error_text(
            "Policy Denied: Operator approval receipt is mandatory for plan execution.",
        );
    }
    CallToolResult::error_text(
        "Policy Denied: Operator approval receipt signature verification pending (L4 execution required).",
    )
}

fn rollback_schema() -> Value {
    json!({
        "type": "object",
        "required": ["backup_id"],
        "properties": {
            "backup_id": {
                "type": "string",
                "description": "Backup snapshot ID"
            },
            "approval_receipt": {
                "type": "string",
                "description": "Operator approval token"
            },
            "path": {
                "type": "string",
                "description": "Target workspace path",
                "default": "."
            }
        }
    })
}

fn handle_rollback(server: &McpServer, _args: &Value, _target_path: &Path) -> CallToolResult {
    if server.read_only {
        return CallToolResult::error_text(
            "Policy Denied: MCP server is operating in read-only mode (--read-only). Rollback mutations are strictly prohibited.",
        );
    }
    CallToolResult::error_text(
        "Policy Denied: Operator approval receipt is mandatory for rollback.",
    )
}

pub static TOOLS: &[McpToolRegistration] = &[
    McpToolRegistration {
        name: "bk.asset_inventory",
        description: "Catalog all software assets, SBOMs, package manifests, containers, host processes, and AI skills within a workspace.",
        schema: asset_inventory_schema,
        handler: handle_asset_inventory,
    },
    McpToolRegistration {
        name: "bk.scan",
        description: "Run deterministic multi-engine vulnerability scan over target workspace (PHP2Shell, Node2Shell, YARA, OSV, Containers).",
        schema: scan_schema,
        handler: handle_scan,
    },
    McpToolRegistration {
        name: "bk.findings",
        description: "Query and filter security findings by CVE, severity, affectedness, or reachability.",
        schema: findings_schema,
        handler: handle_findings,
    },
    McpToolRegistration {
        name: "bk.evidence",
        description: "Retrieve complete cryptographic evidence, taint traces, and AST location records for a specific finding.",
        schema: evidence_schema,
        handler: handle_evidence,
    },
    McpToolRegistration {
        name: "bk.plan",
        description: "Synthesize prospective, non-mutating virtual patches or remediation plans for a finding without altering disk.",
        schema: plan_schema,
        handler: handle_plan,
    },
    McpToolRegistration {
        name: "bk.verify",
        description: "Verify workspace security state, check coverage completeness, and audit backup integrity.",
        schema: verify_schema,
        handler: handle_verify,
    },
    McpToolRegistration {
        name: "bk.skill_scan",
        description: "Scan AI agent skills, prompts, and MCP server configuration files for supply-chain risks, prompt injections, and shell privilege escapes.",
        schema: skill_scan_schema,
        handler: handle_skill_scan,
    },
    McpToolRegistration {
        name: "bk.status",
        description: "Inspect Bug Killer server operational status, read-only mode, and agent identity cryptographic trust anchor.",
        schema: status_schema,
        handler: handle_status,
    },
    McpToolRegistration {
        name: "bk.apply_plan",
        description: "Privileged mutating operation: apply prospective healing plan to files. Strictly gated by operator approval receipt.",
        schema: apply_plan_schema,
        handler: handle_apply_plan,
    },
    McpToolRegistration {
        name: "bk.rollback",
        description: "Privileged mutating operation: cryptographically verify Ed25519 signature and rollback files from backup snapshot.",
        schema: rollback_schema,
        handler: handle_rollback,
    },
];
