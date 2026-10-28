# deepsec

> Autonomous DeepSec security review and triage skill for AI agents.

[![CI](https://github.com/imMamdouhaboammar/deepsec/actions/workflows/ci.yml/badge.svg)](https://github.com/imMamdouhaboammar/deepsec/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

`deepsec` is a production-grade agentic skill providing deterministic repository candidate scanning, LLM-powered investigation, two-pass false positive elimination, and priority triage (`P0`/`P1`/`P2`) for AI agents across Google Antigravity, Claude Code, Cursor, Codex, and Windsurf.

---

## Capabilities

- **Multi-Runtime Execution:** Automatically detects and operates with high-performance native compiled binaries (`bk deepsec`) or upstream Node.js CLI (`npx deepsec`).
- **Two-Pass Verification:** Pre-filter regex candidate matches are rigorously evaluated and revalidated before inclusion in findings.
- **Budget & Concurrency Fences:** Hard caps prevent runaway recursive LLM API billing and thread starvation.
- **Resumable State Machine:** Persists scan progress in `.deepsec/data/<project>/` with atomic file locking.

---

## Quick Start & Installation

### Option 1: Automatic Installer
```bash
curl -fsSL https://raw.githubusercontent.com/imMamdouhaboammar/deepsec/main/install.sh | bash
```

### Option 2: Clone to Agent Skills Directory
```bash
# For Google Antigravity / Claude Code / Codex
git clone https://github.com/imMamdouhaboammar/deepsec.git ~/.gemini/config/skills/deepsec
```

---

## Invariants

1. **Strictly Defensive Perimeter:** Zero exploit generation, weaponized payload creation, or offensive shellcode generation.
2. **Budget & Concurrency Fences:** Worker concurrency must not exceed `8`. Maximum spend threshold must be enforced before batch processing.
3. **Two-Pass Verification:** Unvalidated regex matches must never be reported as confirmed vulnerabilities.
4. **Non-Destructive Scanning:** Target repository files must remain strictly read-only during scanning and triage.

---

## Workflow Steps

```text
+-------------------+      +----------------------+      +----------------------+
| 1. Detect Runner  | ---> | 2. Configure Engine  | ---> | 3. Candidate Scan    |
| (Native vs Node)  |      | (.deepsec/config.json)|      | (.deepsec/data/)     |
+-------------------+      +----------------------+      +----------------------+
                                                                    |
+-------------------+      +----------------------+                 v
| 5. Triage Findings| <--- | 4. AI Revalidation   | <---------------+
| (P0/P1/P2 Reports)|      | (Filter False Pos)   |
+-------------------+      +----------------------+
```

| Step | Freedom | Action |
|---|---|---|
| `detect-runner` | low | Execute `scripts/detect-runtime.sh` to select execution engine. |
| `configure-engine` | low | Generate or validate `.deepsec/config.json` schema and budget. |
| `execute-scan` | low | Run regex matchers to populate candidate records in storage. |
| `process-and-revalidate` | medium | Dispatch batched LLM investigation and secondary revalidation. |
| `triage-and-report` | medium | Compute priority tiers (`P0`, `P1`, `P2`) and emit audit reports. |

---

## Configuration Example

```json
{
  "version": "1.0.0",
  "runner": "auto",
  "project_id": "auto",
  "storage_dir": ".deepsec/data",
  "model": "gemini-2.5-flash",
  "concurrency": 4,
  "max_cost_usd": 5.0,
  "max_tokens": 500000,
  "rules": {
    "sql_injection": true,
    "rce": true,
    "ssrf": true,
    "path_traversal": true,
    "hardcoded_secrets": true,
    "xss": true,
    "auth_bypass": true
  },
  "revalidation": {
    "enabled": true,
    "filter_false_positives": true
  }
}
```

---

## Verification & Testing

Run the deterministic evaluation test suite:

```bash
python3 scripts/eval_deepsec_skill.py
```

Run Layer 0 static security audit:

```bash
python3 ~/.gemini/config/skills/omni-skill/scripts/scan_skill_security.py . --format terminal --strict
```

---

## License

MIT © 2026 Mamdouh Aboammar
