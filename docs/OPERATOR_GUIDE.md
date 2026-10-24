# Bug Killer (`bk`) — Operator & Security Governance Guide

This document defines the operational procedures, trust boundaries, and execution controls for the Bug Killer autonomous vulnerability finder and virtual healing platform.

---

## 1. Architectural Scope & Governance

Bug Killer operates strictly on a **defensive-only perimeter**. Its sole authorized purpose is vulnerability detection, prospective patch planning, virtual hardening, and cryptographic rollback. Exploit generation, weaponized payload authoring, and unconstrained command execution are prohibited by deterministic safety vetoes.

### Core Governance Rules

1. **Plan-Only Default:** All mutation operations (`heal`, `apply`, `rollback`) default to non-mutating preview modes. Disk mutation requires explicit operator authorization.
2. **Cryptographic Non-Repudiation:** Every state mutation records a SHA-256 digest and Ed25519 signature in an immutable backup manifest before applying modifications.
3. **Fail-Closed Verification:** Rollback, healing execution, and remote data export fail closed if signatures, digests, or policies do not match exact expected values.

---

## 2. Autonomous Healing Ladder (L0 — L4)

Bug Killer implements graduated operational levels to prevent unintended systemic drift:

| Level | Classification | Execution Constraint | Rollback Guarantee |
|---|---|---|---|
| **L0** | Asset Discovery & Inventory | Read-only. Always permitted. | N/A (Zero mutation) |
| **L1** | Vulnerability Scan & Triage | Read-only. Always permitted. | N/A (Zero mutation) |
| **L2** | Prospective Remediation Planning | Read-only. Diff synthesis. Always permitted. | N/A (Zero mutation) |
| **L3** | Supervised Remediation | Requires explicit operator `--apply` flag. | Ed25519-signed backup manifest |
| **L4** | Autonomous Supervised Healing | Requires operator approval receipt with Ed25519 signature + post-verification gate. | Automatic rollback on post-execution failure |

---

## 3. Operator Approval Receipt Workflow (L4)

Autonomous agents must submit prospective plans to human operators for cryptographic receipt signing before applying changes.

### Step 1: Formulate Prospective Plan
```bash
bug-killer plan <finding-id> --path /path/to/repo --json
```

### Step 2: Issue Cryptographic Approval Receipt
```bash
bug-killer approve <plan-id> \
  --path /path/to/repo \
  --approver "secops-lead@enterprise.corp" \
  --validity-mins 60
```
This computes the deterministic SHA-256 checksum of the prospective patch actions, signs the receipt using the root identity key (`~/.bug-killer/identity/agent.key`), and stores the receipt at `.bug-killer/approvals/<plan-id>.receipt.json`.

### Step 3: Supervised Execution
```bash
bug-killer apply <plan-id> \
  --path /path/to/repo \
  --approval-file .bug-killer/approvals/<plan-id>.receipt.json
```
Execution gate checks:
1. Receipt timestamp is within validity period.
2. Cryptographic signature validates against local root identity key.
3. Current plan checksum matches receipt's `plan_checksum`.
4. Multi-file transaction creates safety backup before touching disk.
5. Post-execution scan automatically runs. If any unresolved critical/high vulnerabilities or parser corruptions remain, the platform **automatically triggers atomic rollback**.

---

## 4. Model Context Protocol (MCP) Integration

Bug Killer exposes a local standard input/output (stdio) MCP server for external coding agents (Claude Code, OpenAI Codex, Gemini CLI).

### Server Startup
```bash
bug-killer mcp serve --transport stdio --read-only
```

### Supported Tools Matrix

| Tool | Mode | Description |
|---|---|---|
| `bk.asset_inventory` | Read-Only | Enumerate packages, containers, processes, SBOMs |
| `bk.scan` | Read-Only | Run deterministic scanner engines over workspace |
| `bk.findings` | Read-Only | Query and filter findings by CVE, severity, affectedness |
| `bk.evidence` | Read-Only | Extract full cryptographic evidence records for finding |
| `bk.plan` | Read-Only | Synthesize prospective patch diff without disk mutation |
| `bk.verify` | Read-Only | Audit workspace security and coverage integrity |
| `bk.skill_scan` | Read-Only | Inspect AI agent skills and MCP server configs for risks |
| `bk.status` | Read-Only | Query server operational health and Ed25519 trust anchor |
| `bk.apply_plan` | Gated | Apply prospective plan (requires operator approval receipt) |
| `bk.rollback` | Gated | Restore files from backup snapshot (requires approval) |

### Host Configuration Snippets

#### Claude Code (`~/.claude/mcp.json` or `claude.json`)
```json
{
  "mcpServers": {
    "bug-killer": {
      "command": "bug-killer",
      "args": ["mcp", "serve", "--transport", "stdio", "--read-only"],
      "description": "Bug Killer: Autonomous Vulnerability Finder & Virtual Healer"
    }
  }
}
```

#### OpenAI Codex (`~/.codex/config.json`)
```json
{
  "mcpServers": {
    "bug-killer": {
      "command": "bug-killer",
      "args": ["mcp", "serve", "--transport", "stdio", "--read-only"]
    }
  }
}
```

#### Gemini CLI (`~/.gemini/mcp.json`)
```json
{
  "mcpServers": {
    "bug-killer": {
      "command": "bug-killer",
      "args": ["mcp", "serve", "--transport", "stdio", "--read-only"]
    }
  }
}
```

Generate these dynamically with:
```bash
bug-killer mcp config --host all
```

---

## 5. Machine-Readable Structured CLI & Exit Codes

All query commands support `--json` output for automated pipeline integration.

### Deterministic Exit Codes

| Exit Code | Meaning | Condition |
|---|---|---|
| `0` | Clean / Success | Zero vulnerabilities, scan complete, or operation succeeded |
| `1` | Confirmed Affected | At least one confirmed vulnerable finding detected |
| `2` | Potentially Affected | Uncertainty / potentially affected findings detected |
| `3` | Partial Coverage | Parser or I/O failure prevented complete file coverage |
| `4` | Policy / Safety Denial | Deterministic veto, expired approval, or signature mismatch |
| `5` | Operational Error | Missing required dependency or invalid transport argument |

---

## 6. Recovery Drills & Manual Rollback

If an operator wishes to manually roll back any healing operation:

```bash
# List available backup snapshots
ls -la .aegis/backups/

# Cryptographically verify and restore snapshot
bug-killer rollback <backup-id> --path /path/to/repo
```
The rollback engine verifies the Ed25519 signature on `.aegis/backups/<backup-id>/manifest.json`, validates that backup files match original SHA-256 digests, and atomically writes the original contents back to their target paths.
