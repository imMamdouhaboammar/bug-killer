---
name: bk-security
description: >
  Autonomous vulnerability discovery, multi-surface security inspection, and virtual healing engine
  powered by Bug Killer (bk). Guides agents on auditing production codebases across SAST, SCA, DAST,
  secrets, Docker containers, reverse proxies, and AI agent MCP configurations. Use when asked to
  scan a repository with bk, audit production code for security vulnerabilities, run bug-killer
  security checks, inspect runtime exploit exposure (e.g. PHP2Shell, Node2Shell), fix vulnerabilities
  with cryptographic rollback, or integrate bk into CI/CD pipelines, even if they don't explicitly
  say 'bug killer' or 'bk'. Do NOT use for general non-security refactoring, generating weaponized
  exploit payloads, or configuring unrelated linters like eslint or clippy.
---

# Bug Killer Security: Autonomous Vulnerability Finder & Virtual Healer

Autonomous multi-surface security auditor, virtual patcher, and cryptographic rollback engine.

```
+-----------------------------------------------------------------------------------+
|                               BUG KILLER (bk) ENGINE                             |
+-----------------------------------------------------------------------------------+
| Pre-Flight        | Verify binary handle ($BK_BIN) and Ed25519 identity key.      |
| Shift-Left        | Fetch task guidance before modifying code.                    |
| Scan Surfaces     | SAST (Taint) | SCA (OSV) | DAST | Secrets | Containers | MCP |
| Finding Triage    | Classify by Severity, Certainty, and Reachability.            |
| Remediation       | Plan (L2) -> Approve (L3) -> Apply (Ed25519) -> Verify Gate.  |
| Failsafe          | Bit-for-bit cryptographic restoration via rollback backup ID.  |
+-----------------------------------------------------------------------------------+
```

---

## Runtime Requirements (Pre-Flight)

Before executing any commands, verify that the environment meets the pre-flight conditions:
- **Bug Killer executable**: Available via `bk`, `bug-killer`, or locally in `./target/release/bug-killer`.
- **Ed25519 keypair**: Present at `<project>/.aegis/agent_identity.key` for signed mutations.
- **Detailed setup & fallback instructions** -> **`references/runtime-setup.md`**.

If the binary is missing, compile locally via `cargo build --release` or use the cargo runner:
```bash
cargo run --release --bin bug-killer -- <COMMAND>
```

---

## Core Operational Workflow

### Phase 1: Shift-Left Security Guidance (Pre-Task)
Before writing or refactoring production code, fetch active security catalog rules and banned sinks:
```bash
bk security guidance "implement file upload and stream processing"
```
Or via MCP: call `bugkiller_security_guidance(task_description="...")`.

### Phase 2: Production Codebase Inspection
Select the scan profile based on operational budget (see **`references/production-scan-playbook.md`**):

```bash
# 1. Fast pre-commit or quick audit (< 5s)
bk security scan . --profile quick

# 2. Comprehensive repository audit with JSON report (SCA, SAST, Secrets, Docker, MCP)
bk security scan . --profile deep --json

# 3. Defensive DAST probe against staging endpoint (denies localhost/cloud metadata)
bk probe https://staging.example.com --json

# 4. Direct OSV vulnerability check on a third-party dependency
bk osv . --json
```

### Phase 3: Finding Triage & Decision Matrix
Map findings against Certainty and Reachability (see **`references/security-catalog-rubric.md`**):

| Classification | Action | SLA |
|---|---|---|
| **`ConfirmedAffected` + `Reachable`** | Mandatory blocker; generate patch plan immediately. | P0 (Block Deploy) |
| **`PotentiallyAffected` + `Reachable`** | Audit call site and verify if untrusted input reaches sink. | P1 (Same Sprint) |
| **`Unreachable` / Guarded Sink** | Document existing sanitizer; record in baseline if expected. | P3 (Monitor) |

### Phase 4: Supervised Virtual Patching & Remediation
Never mutate production code directly without cryptographic tracking. Execute the 4-step loop (see **`references/remediation-and-rollback.md`**):

1. **Plan Non-Mutating Diff**:
   ```bash
   bk plan <FINDING_ID> .
   ```
   *Inspect output unified diff and verify diff hash.*

2. **Operator Sign-Off**:
   ```bash
   bk approve <FINDING_ID> .
   ```

3. **Apply with Cryptographic Snapshot**:
   ```bash
   bk apply <FINDING_ID> .
   ```
   *Creates snapshot in `.aegis/backups/<backup_id>` signed with Ed25519.*

4. **Verify Fix**:
   ```bash
   bk security verify .
   ```

### Phase 5: Failsafe Cryptographic Rollback
If application tests fail or regression occurs post-patch, revert bit-for-bit:
```bash
bk rollback <BACKUP_ID>
```

---

## Architectural & Security Invariants

1. **Strictly Defensive Perimeter**: Zero offensive exploit payload generation or weaponized shellcode authoring. Only detection, virtual patching, and hardening.
2. **Read-Only Scans**: `bk scan` and `bk security scan` must never mutate files, alter timestamps, or modify git state.
3. **Cryptographic Non-Repudiation**: All filesystem mutations must generate a SHA-256 digest manifest signed via Ed25519. Rollbacks fail closed on signature mismatch.
4. **SSRF Guardrails**: DAST probing strictly denies IP `169.254.169.254`, loopback subnets, and non-HTTP protocols.

---

## External Agent Integration (MCP)

To connect Claude Code, Cursor, or Gemini CLI to Bug Killer via MCP:
```bash
# 1. Output MCP host configuration
bk mcp config --host all

# 2. Run stdio MCP server daemon
bk mcp serve
```
Full MCP tool definitions and calling patterns -> **`references/mcp-tools-guide.md`**.

---

## Reference Map

| Document | Purpose |
|---|---|
| `references/runtime-setup.md` | Pre-flight checks, binary discovery, environment variables |
| `references/cli-reference.md` | Complete CLI syntax, flags, subcommands, and exit codes |
| `references/production-scan-playbook.md` | Detailed multi-surface scanning guide and CI/CD pipelines |
| `references/remediation-and-rollback.md` | Graduated patch levels, operator receipts, and Ed25519 rollback |
| `references/mcp-tools-guide.md` | `bk.*` and `bugkiller_*` MCP server tool documentation |
| `references/security-catalog-rubric.md` | The 27 rule categories, certainty levels, and reachability |
