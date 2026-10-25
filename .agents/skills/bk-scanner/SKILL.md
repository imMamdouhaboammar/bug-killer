---
name: bk-scanner
description: >
  Zero-side-effect, strictly read-only vulnerability scanner and security auditor powered by
  Bug Killer (bk). Guides agents on inspecting production codebases across SCA, SAST, taint analysis,
  high-entropy secrets, Docker containers, reverse proxies, and defensive DAST endpoints. Use when
  asked to scan code for CVEs with bk, run a non-destructive security audit, detect taint injection
  sinks, inspect dependencies against OSV, audit Dockerfiles, or probe staging endpoints defensively,
  even if they don't explicitly say 'bk scan'. Do NOT use when the task requires modifying code,
  applying virtual patches, executing rollbacks, or running non-security linters.
---

# Bug Killer Scanner: Non-Destructive Production Security Auditor

Strictly read-only vulnerability discovery and multi-surface security inspection lens.

```
+-----------------------------------------------------------------------------------+
|                            BUG KILLER SCANNER WORKFLOW                            |
+-----------------------------------------------------------------------------------+
| 1. Profile Budget | Quick (< 3s) | Project (10-25s) | CI (30-60s) | Deep (1-5m)   |
| 2. Read-Only Scan | Scans AST, manifests, secrets, containers, and agent configs.  |
| 3. Taint Tracking | Traces untrusted inputs to SQL, shell, path, and XSS sinks.   |
| 4. Findings Class | Maps findings to Certainty, Reachability, and Severity.       |
| 5. Output Report  | Outputs structured JSON or SARIF for CI/CD integration.       |
+-----------------------------------------------------------------------------------+
```

---

## Runtime Requirements (Pre-Flight)

Before running scans, verify runtime dependencies:
- **Bug Killer executable**: Available via `bk`, `bug-killer`, or `./target/release/bug-killer`.
- **Read-Only Invariant**: Scanning operations never mutate source files, touch timestamps, or alter git status.
- **Detailed setup & offline mode** -> **`references/runtime-setup.md`**.

```bash
# Check binary availability
which bk || which bug-killer || ls -la ./target/release/bug-killer
```

---

## Scanner Execution Protocol

### Step 1: Select Scan Profile
Choose the profile matching the execution budget (see **`references/scan-profiles-matrix.md`**):

- **Pre-commit / Fast Loop**: `--profile quick` (< 3s)
- **Feature Branch / PR**: `--profile project` (10-25s)
- **CI / Deployment Gate**: `--profile ci --fail-on high` (30-60s)
- **Comprehensive Audit**: `--profile deep --json` (1-5m)

### Step 2: Execute Multi-Surface Scan
Run the scan command across workspace targets:

```bash
# General multi-surface scan with JSON output
bk security scan . --profile deep --json

# Scan only changed git files during rapid code edits
bk security scan . --profile quick --changed-only

# Defensive live endpoint probe (SSRF-protected)
bk probe https://preview.example.com --json
```

### Step 3: Taint & Reachability Analysis
For each reported finding, evaluate the taint graph (see **`references/surface-taxonomy.md`**):
1. **Source**: Entry point of user-controlled data (`req.body`, `req.query`, URL parameters).
2. **Propagator**: Variable passing, transformations, or stream chunks.
3. **Sink**: Target API (`child_process.exec`, raw SQL formatting, `fs.readFile`, `eval`).
4. **Sanitizer Check**: Confirm whether an existing sanitizer or parameterized call neutralizes the taint.

### Step 4: Classify and Report Findings
Group findings according to the decision rubric:

| Finding Type | Criteria | Action |
|---|---|---|
| **Critical Blocker** | `Severity: Critical` + `ConfirmedAffected` + `Reachable` | Halt pipeline; require remediation plan before merge. |
| **High Priority** | `Severity: High` + `PotentiallyAffected` | Investigate reachability and verify active callsites. |
| **Informational / Baseline** | Low severity or unreachable guarded sink | Record in `.bugkiller/baseline.json`. |

---

## Invariants & Guardrails

1. **Zero Filesystem Mutation**: `bk scan` is strictly read-only. If file changes are needed, transition to the `bk-healer` skill.
2. **SSRF Denial**: `bk probe` automatically rejects cloud metadata IP `169.254.169.254`, loopback addresses, and non-HTTP protocols.
3. **Incomplete Coverage Fails Closed**: Unreadable files or parser errors cause coverage accounting to fail closed; never classify an incomplete scan as clean.

---

## Reference Map

| Document | Purpose |
|---|---|
| `references/runtime-setup.md` | Pre-flight checks, binary discovery, offline OSV configuration |
| `references/scan-profiles-matrix.md` | Profile comparisons, timing benchmarks, CI/CD integration |
| `references/surface-taxonomy.md` | SCA, SAST taint, secrets, container, and DAST surface details |
