---
name: deepsec
description: Configure, execute, and triage DeepSec deep security reviews on codebases. Use when asked to setup deepsec, run deepsec scans, audit a repository for vulnerabilities, triage security candidates, or configure findings storage.
user-invocable: true
---

# DeepSec Agentic Skill

Security review harness for deterministic candidate scanning, configured LLM investigation, uncertain-by-default revalidation, and priority triage. Do not represent model or regex output as independently verified.

## Invariants

1. **Strictly Defensive Perimeter:**
   Zero exploit generation, weaponized payload creation, or offensive shellcode generation. The agent's sole purpose is detection, vulnerability characterization, and remediation guidance.
   *Why this rule exists:* Prevents autonomous execution engines from authoring malicious software or violating safety policies.

2. **Budget & Concurrency Fences:**
   Do not dispatch investigation when a hard spending limit is required: the native processor cannot yet verify provider billing telemetry. Keep worker concurrency bounded.
   *Why this rule exists:* A stated limit without enforceable metering gives a false safety guarantee.

3. **Evidence Integrity:**
   Regex matches and LLM explanations are not confirmed vulnerabilities. Revalidation currently returns uncertainty without an independent proof step.
   *Why this rule exists:* Static patterns and model output alone cannot establish exploitability or remediation success.

4. **Non-Destructive Scanning:**
   Target repository files must remain strictly read-only during scanning and triage. Scans must never alter user source code.
   *Why this rule exists:* Guarantees reproducibility and prevents corruption of application state.

---

## Mode Router

Classify user intent into one of four execution modes:

| Mode | Trigger Phrases | Action | Output |
|---|---|---|---|
| `SETUP` | "setup deepsec", "configure deepsec settings" | Detect runtime, generate `.deepsec/config.json` | Validated config file |
| `SCAN` | "run deepsec scan", "scan repository" | Execute regex pre-filter to populate storage | Candidate inventory in `.deepsec/data/<project>/` |
| `INVESTIGATE` | "investigate candidates", "process and revalidate" | Run configured AI analysis, mark revalidation uncertainty | Unverified findings in `.deepsec/data/<project>/` |
| `REPORT` | "triage findings", "export deepsec report" | Compute P0/P1/P2 scores, render markdown table | `REPORT.md` and terminal summary |

---

## Workflow Steps

### Step 1: Detect Runner (`freedom: low`)

Execute runtime detection to select native binary vs Node.js fallback:

```bash
skills/deepsec/scripts/detect-runtime.sh
```

- If `native` (`bug-killer deepsec`): Use the compiled binary.
- If `node` (`npx deepsec`): Verify that the external package implements the intended commands before use; the bundled `bin/cli.js` is a placeholder.
- If no runner detected: Offer automated native compilation (`cargo build --release`) or inform the user.
- Reference: [Runner Comparison](references/runner-comparison.md)

### Step 2: Configure Engine (`freedom: low`)

Ensure `.deepsec/config.json` exists and satisfies budget constraints:

```bash
skills/deepsec/scripts/validate-config.sh .deepsec/config.json
```

- If missing, copy template from `assets/config.template.json` to `.deepsec/config.json`.
- Set `concurrency` between `1` and `8` (default: `4`).
- Do not treat `max_cost_usd` in the template as an enforced backend limit.
- Reference: [Configuration Reference](references/configuration.md)

### Step 3: Candidate Scanning (`freedom: low`)

Run the pre-filter candidate extraction over target repository paths:

- Native: `bug-killer deepsec scan . --project-id <project_id>`
- External Node runner: use only after verifying its actual implementation.

Validates that `.deepsec/data/<project>/` contains populated `FileRecord` JSON objects with discovered candidate regex matches.

### Step 4: Batched AI Investigation & Revalidation (`freedom: medium`)

Dispatch candidate batches to the configured LLM:

- Native: `bug-killer deepsec process . --project-id <project_id> && bug-killer deepsec revalidate . --project-id <project_id>`
- Requires `DEEPSEC_AI_ENDPOINT` (HTTPS) and `DEEPSEC_AI_KEY` in the trusted environment.

Workers evaluate candidates through the configured provider. The processor rejects a requested hard budget until verifiable usage accounting exists. Revalidation does not certify false positives or fixes.

### Step 5: Triage & Report Generation (`freedom: medium`)

Compute deterministic priority tiers (`P0`, `P1`, `P2`) and emit structured findings:

- Native: `bug-killer deepsec triage . --project-id <project_id> && bug-killer deepsec report . --project-id <project_id>`
- Do not use the bundled Node placeholder as evidence of a report.

Report format:
- Summary table categorized by Priority (`P0` / `P1` / `P2`).
- Detailed finding cards containing available evidence, affected file and line number, an explicitly unverified risk scenario, and suggested review.
- Reference: [Triage Matrix](references/triage-matrix.md)

---

## Stop Conditions & Fallback Behavior

1. **Missing Backend:** If `DEEPSEC_AI_ENDPOINT` or `DEEPSEC_AI_KEY` is absent, halt rather than use mock findings.
2. **Required Spending Cap:** If a hard limit is requested, stop; billing telemetry and enforcement are not implemented.
3. **Concurrent Workers:** File-claim checks and writes are serialized across processes with an OS advisory mutex; avoid multiple processors on the same project until the whole processing lifecycle, stale-lock expiry, and crash recovery are verified.
