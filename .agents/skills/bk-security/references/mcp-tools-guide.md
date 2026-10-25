# Bug Killer Model Context Protocol (MCP) Tools Specification

External AI agents (such as Claude Code, Cursor, Google Antigravity, and OpenAI Codex) can invoke Bug Killer directly through its native stdio Model Context Protocol (MCP) server.

---

## 1. Launching and Configuring the MCP Server

### Stdio Server Execution
```bash
bk mcp serve --transport stdio
```

### Automatic Configuration Snippet Generation
To produce configuration blocks for client applications:
```bash
# Generate configuration for all supported clients
bk mcp config --host all

# Or specific host: claude, cursor, codex, gemini
bk mcp config --host claude
```

Example `claude_desktop_config.json` snippet:
```json
{
  "mcpServers": {
    "bug-killer": {
      "command": "bk",
      "args": ["mcp", "serve"],
      "env": {
        "BK_LOG": "info"
      }
    }
  }
}
```

---

## 2. MCP Tools Inventory

Bug Killer exposes two complementary sets of MCP tools:

### Suite A: Low-Level Core Tools (`bk.*`)

| Tool Name | Parameters | Description |
|---|---|---|
| `bk.asset_inventory` | `path: string` | Enumerate software components, package manifests, and services. |
| `bk.scan` | `path: string`, `profile: string`, `check_runtime: bool` | Execute vulnerability scan returning structured findings. |
| `bk.findings` | `path: string`, `severity: string` | Query findings filtered by severity or status. |
| `bk.evidence` | `path: string`, `finding_id: string` | Fetch cryptographic evidence hashes and code excerpts for a finding. |
| `bk.plan` | `path: string`, `finding_id: string` | Create prospective non-mutating repair plan with diff hash. |
| `bk.apply_plan` | `path: string`, `receipt_id: string` | Apply approved remediation plan with Ed25519 signature. |
| `bk.verify` | `path: string` | Re-scan and verify that findings were resolved. |
| `bk.rollback` | `backup_id: string` | Restore original files from backup snapshot. |
| `bk.skill_scan` | `path: string` | Audit AI agent skills and prompts for security risks. |
| `bk.status` | `path: string` | Report identity status and backup inventory. |

### Suite B: High-Level Security Guard Tools (`bugkiller_*`)

| Tool Name | Parameters | Description |
|---|---|---|
| `bugkiller_security_status` | `path: string` | Complete security posture report (initialized, languages, baseline count). |
| `bugkiller_scan_project` | `path: string`, `profile: string` | Run comprehensive project scan against 373+ catalog rules. |
| `bugkiller_scan_changed_files` | `path: string`, `files: string[]` | Targeted scan on git diff or uncommitted files for fast PR review. |
| `bugkiller_list_findings` | `path: string`, `severity: string` | List active findings with certainty and reachability ratings. |
| `bugkiller_explain_finding` | `finding_id: string` | In-depth technical explanation, root cause analysis, and remediation options. |
| `bugkiller_get_rule` | `rule_id: string` | Detailed catalog rule specification and CWE references. |
| `bugkiller_propose_fix` | `path: string`, `finding_id: string` | Generate proposed fix diff and explanation without modifying files. |
| `bugkiller_verify_fix` | `path: string`, `finding_id: string` | Verify whether a specific finding is eliminated after editing. |
| `bugkiller_get_coverage` | `path: string` | Inspect SCA, SAST, DAST, Container, and Secret coverage metrics. |
| `bugkiller_security_guidance` | `task_description: string` | Shift-left guidance before authoring code: lists dangerous patterns to avoid. |

---

## 3. Best Practices for AI Agents Using MCP Tools

1. **Shift-Left First**: Call `bugkiller_security_guidance` with the task description *before* writing code.
2. **Scan Changed Files Fast**: During coding iterations, call `bugkiller_scan_changed_files` with only the modified files to get instant feedback (< 1s).
3. **Verify Before Declaring Done**: Never tell the user a security issue is fixed until `bugkiller_verify_fix` confirms zero remaining findings.
