use crate::deep::broker::ToolCapabilityBroker;
use crate::hunter::hypothesis::ThreatHypothesisFamily;
use crate::mcp::protocol::CallToolResult;
use crate::mcp::registry::McpToolRegistration;
use crate::mcp::server::McpServer;
use crate::osv::OsvClient;
use crate::scanner::host::HostProcessScanner;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::path::Path;

fn engine_capabilities_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "path": { "type": "string", "default": "." }
        }
    })
}

fn handle_engine_capabilities(
    _server: &McpServer,
    _args: &Value,
    _target_path: &Path,
) -> CallToolResult {
    let mut broker = ToolCapabilityBroker::discover_default_tools();
    let capabilities = broker.discover_all();
    let out = json!({
        "total_tools": capabilities.len(),
        "capabilities": capabilities,
    });
    CallToolResult::ok_json(&out).unwrap_or_else(|e| CallToolResult::error_text(e.to_string()))
}

fn room_plan_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "path": { "type": "string", "default": "." },
            "goal": { "type": "string", "enum": ["known", "prevention", "research"], "default": "prevention" },
            "profile": { "type": "string", "enum": ["quick", "project", "ci", "deep"], "default": "project" }
        }
    })
}

fn handle_room_plan(_server: &McpServer, args: &Value, target_path: &Path) -> CallToolResult {
    let goal = args
        .get("goal")
        .and_then(Value::as_str)
        .unwrap_or("prevention");
    let profile = args
        .get("profile")
        .and_then(Value::as_str)
        .unwrap_or("project");
    let mut broker = ToolCapabilityBroker::discover_default_tools();
    let tools = broker.discover_all();
    let mut selected = Vec::new();
    let mut skipped = Vec::new();
    for t in tools {
        if t.installation == crate::deep::broker::Installation::Available {
            selected.push(json!({ "tool_id": t.tool_id, "adapter_version": t.adapter_version, "role": "selected" }));
        } else {
            skipped.push(json!({ "tool_id": t.tool_id, "status": format!("{:?}", t.installation), "reason": "tool unavailable or unlicensed" }));
        }
    }
    let hash =
        crate::identity::to_hex(Sha256::digest(target_path.display().to_string().as_bytes()));
    let plan = json!({
        "plan_id": format!("plan-{}", &hash[..12]),
        "target_workspace": target_path.display().to_string(),
        "goal": goal,
        "profile": profile,
        "status": "PLANNED",
        "selected_engines": selected,
        "skipped_engines": skipped,
        "budget": {
            "max_runtime_seconds": 300,
            "sandbox_isolation": true,
            "network_allowed": false
        }
    });
    CallToolResult::ok_json(&plan).unwrap_or_else(|e| CallToolResult::error_text(e.to_string()))
}

fn room_status_schema() -> Value {
    json!({
        "type": "object",
        "required": ["run_id"],
        "properties": {
            "run_id": { "type": "string" }
        }
    })
}

fn handle_room_status(_server: &McpServer, args: &Value, _target_path: &Path) -> CallToolResult {
    let run_id = args.get("run_id").and_then(Value::as_str).unwrap_or("");
    if run_id.is_empty() {
        return CallToolResult::error_text("run_id is required".to_string());
    }
    let status = json!({
        "run_id": run_id,
        "state": "NOT_RUN",
        "reason": "RUN_NOT_FOUND",
        "receipts_count": 0,
        "receipts": [],
        "evidence_summary": {
            "confirmed": 0,
            "strongly_supported": 0,
            "suspected": 0
        }
    });
    CallToolResult::ok_json(&status).unwrap_or_else(|e| CallToolResult::error_text(e.to_string()))
}

fn research_plan_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "path": { "type": "string", "default": "." }
        }
    })
}

fn handle_research_plan(_server: &McpServer, _args: &Value, target_path: &Path) -> CallToolResult {
    let hypotheses = vec![
        json!({ "family": ThreatHypothesisFamily::TrustBoundary.as_str(), "cwe": ThreatHypothesisFamily::TrustBoundary.default_cwe(), "evidence": ThreatHypothesisFamily::TrustBoundary.required_evidence() }),
        json!({ "family": ThreatHypothesisFamily::AuthAuthz.as_str(), "cwe": ThreatHypothesisFamily::AuthAuthz.default_cwe(), "evidence": ThreatHypothesisFamily::AuthAuthz.required_evidence() }),
        json!({ "family": ThreatHypothesisFamily::ParserDecoder.as_str(), "cwe": ThreatHypothesisFamily::ParserDecoder.default_cwe(), "evidence": ThreatHypothesisFamily::ParserDecoder.required_evidence() }),
        json!({ "family": ThreatHypothesisFamily::StateMachineConcurrency.as_str(), "cwe": ThreatHypothesisFamily::StateMachineConcurrency.default_cwe(), "evidence": ThreatHypothesisFamily::StateMachineConcurrency.required_evidence() }),
        json!({ "family": ThreatHypothesisFamily::Cryptography.as_str(), "cwe": ThreatHypothesisFamily::Cryptography.default_cwe(), "evidence": ThreatHypothesisFamily::Cryptography.required_evidence() }),
        json!({ "family": ThreatHypothesisFamily::SupplyChain.as_str(), "cwe": ThreatHypothesisFamily::SupplyChain.default_cwe(), "evidence": ThreatHypothesisFamily::SupplyChain.required_evidence() }),
        json!({ "family": ThreatHypothesisFamily::BuildCi.as_str(), "cwe": ThreatHypothesisFamily::BuildCi.default_cwe(), "evidence": ThreatHypothesisFamily::BuildCi.required_evidence() }),
        json!({ "family": ThreatHypothesisFamily::AgentMcp.as_str(), "cwe": ThreatHypothesisFamily::AgentMcp.default_cwe(), "evidence": ThreatHypothesisFamily::AgentMcp.required_evidence() }),
    ];
    let out = json!({
        "workspace": target_path.display().to_string(),
        "hypotheses_count": hypotheses.len(),
        "hypotheses": hypotheses,
        "sandbox_policy": {
            "network_isolated": true,
            "max_iterations": 1000,
            "timeout_seconds": 30
        }
    });
    CallToolResult::ok_json(&out).unwrap_or_else(|e| CallToolResult::error_text(e.to_string()))
}

fn research_execute_schema() -> Value {
    json!({
        "type": "object",
        "required": ["candidate_id"],
        "properties": {
            "candidate_id": { "type": "string" },
            "iterations": { "type": "integer", "default": 100 }
        }
    })
}

fn handle_research_execute(
    _server: &McpServer,
    args: &Value,
    _target_path: &Path,
) -> CallToolResult {
    let candidate_id = args
        .get("candidate_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    if candidate_id.is_empty() {
        return CallToolResult::error_text("candidate_id is required".to_string());
    }
    let out = json!({
        "candidate_id": candidate_id,
        "status": "NOT_RUN",
        "reason": "EXECUTION_BACKEND_NOT_CONFIGURED",
        "iterations_completed": 0,
        "sandbox_isolation": "NOT_APPLICABLE",
        "crash_detected": null,
        "reproduction_verified": false
    });
    CallToolResult::ok_json(&out).unwrap_or_else(|e| CallToolResult::error_text(e.to_string()))
}

fn research_verify_schema() -> Value {
    json!({
        "type": "object",
        "required": ["candidate_id"],
        "properties": {
            "candidate_id": { "type": "string" }
        }
    })
}

fn handle_research_verify(
    _server: &McpServer,
    args: &Value,
    _target_path: &Path,
) -> CallToolResult {
    let candidate_id = args
        .get("candidate_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    if candidate_id.is_empty() {
        return CallToolResult::error_text("candidate_id is required".to_string());
    }
    let out = json!({
        "candidate_id": candidate_id,
        "verified": false,
        "reason": "NO_EXECUTION_EVIDENCE",
        "proof_method": null,
        "isolation_preserved": null,
        "confidence": "UNKNOWN"
    });
    CallToolResult::ok_json(&out).unwrap_or_else(|e| CallToolResult::error_text(e.to_string()))
}

fn disclosure_draft_schema() -> Value {
    json!({
        "type": "object",
        "required": ["finding_id"],
        "properties": {
            "finding_id": { "type": "string" },
            "recipient": { "type": "string", "default": "security@vendor.local" },
            "path": { "type": "string", "default": "." }
        }
    })
}

fn handle_disclosure_draft(
    _server: &McpServer,
    args: &Value,
    _target_path: &Path,
) -> CallToolResult {
    let finding_id = args.get("finding_id").and_then(Value::as_str).unwrap_or("");
    if finding_id.is_empty() {
        return CallToolResult::error_text("finding_id is required".to_string());
    }
    // A finding ID alone supplies neither a verified source snapshot
    // nor reproduction evidence. Never manufacture either for a PVR.
    let out = json!({
        "finding_id": finding_id,
        "status": "NOT_RUN",
        "reason": "VERIFIED_REPRODUCTION_REQUIRED",
        "draft_packet": null,
        "github_pvr_markdown": null
    });
    CallToolResult::ok_json(&out).unwrap_or_else(|e| CallToolResult::error_text(e.to_string()))
}

fn inventory_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "path": { "type": "string", "default": "." }
        }
    })
}

fn handle_inventory(_server: &McpServer, _args: &Value, target_path: &Path) -> CallToolResult {
    let packages = OsvClient::discover_packages(target_path);
    let processes = HostProcessScanner::discover_running_processes();
    let mut sbom_packages = Vec::new();
    for p in &packages {
        sbom_packages.push(json!({
            "name": p.name,
            "version": p.version,
            "ecosystem": p.ecosystem,
            "manifest_path": p.file_path.display().to_string(),
            "purl": format!("pkg:{}/{}@{}", p.ecosystem.to_lowercase(), p.name, p.version)
        }));
    }
    let inventory = json!({
        "workspace": target_path.display().to_string(),
        "total_discovered_packages": packages.len(),
        "packages": sbom_packages,
        "total_host_processes": processes.len(),
        "processes": processes,
    });
    CallToolResult::ok_json(&inventory)
        .unwrap_or_else(|e| CallToolResult::error_text(e.to_string()))
}

pub static TOOLS: &[McpToolRegistration] = &[
    McpToolRegistration {
        name: "bugkiller_engine_capabilities",
        description: "Inspect installed, available, unlicensed, or missing sibling security tool capabilities (Semgrep, CodeQL, Joern, Trivy, Nuclei, etc.).",
        schema: engine_capabilities_schema,
        handler: handle_engine_capabilities,
    },
    McpToolRegistration {
        name: "bugkiller_room_plan",
        description: "Generate an Agentic Security Operations Room plan with capability-matched tool selection, execution budgets, and permission gates.",
        schema: room_plan_schema,
        handler: handle_room_plan,
    },
    McpToolRegistration {
        name: "bugkiller_room_status",
        description: "Check the status, receipts, and terminal state of an Agentic Security Operations Room execution run.",
        schema: room_status_schema,
        handler: handle_room_status,
    },
    McpToolRegistration {
        name: "bugkiller_research_plan",
        description: "Propose bounded research hypotheses for novel vulnerability discovery across source, memory, and AST boundaries.",
        schema: research_plan_schema,
        handler: handle_research_plan,
    },
    McpToolRegistration {
        name: "bugkiller_research_execute",
        description: "Execute bounded, sandboxed research exploration and fuzzing on a registered candidate without modifying host files.",
        schema: research_execute_schema,
        handler: handle_research_execute,
    },
    McpToolRegistration {
        name: "bugkiller_research_verify",
        description: "Perform isolated deterministic reproduction and differential verification of a research candidate.",
        schema: research_verify_schema,
        handler: handle_research_verify,
    },
    McpToolRegistration {
        name: "bugkiller_disclosure_draft",
        description: "Synthesize a private responsible disclosure draft (PVR Markdown or JSON) with automated credential redaction.",
        schema: disclosure_draft_schema,
        handler: handle_disclosure_draft,
    },
    McpToolRegistration {
        name: "bugkiller_inventory",
        description: "Generate canonical workspace software asset inventory, package dependencies, lockfile provenance, and SBOM metadata.",
        schema: inventory_schema,
        handler: handle_inventory,
    },
];
