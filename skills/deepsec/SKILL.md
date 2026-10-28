---
name: deepsec
description: Configure, execute, and triage DeepSec deep security reviews on codebases. Use when asked to setup deepsec, run deepsec scans, audit a repository for vulnerabilities, triage security candidates, or configure findings storage.
user-invocable: true
---

# DeepSec Agentic Skill

Autonomous security review orchestrator providing deterministic candidate scanning, LLM-powered investigation, second-pass false positive revalidation, and priority triage.

## Invariants

1. **Strictly Defensive Perimeter:**
   Zero exploit generation, weaponized payload creation, or offensive shellcode generation. The agent's sole purpose is detection, vulnerability characterization, and remediation guidance.
   *Why this rule exists:* Prevents autonomous execution engines from authoring malicious software or violating safety policies.

2. **Budget & Concurrency Fences:**
   Worker concurrency must not exceed `8`. Maximum expenditure (`max_cost_usd`) must be asserted prior to dispatching AI investigation batches.
   *Why this rule exists:* Prevents runaway recursive AI calls from consuming excessive API tokens or overwhelming local resources.

3. **Two-Pass Verification:**
   Unvalidated regex matches must never be reported as confirmed vulnerabilities. Every candidate must pass through the LLM investigation and secondary revalidation stages before inclusion in the final report.
   *Why this rule exists:* Static regex matchers exhibit high false-positive rates on common variable names and comments.

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
| `INVESTIGATE` | "investigate candidates", "process and revalidate" | Run batched AI analysis and false-positive filter | Confirmed findings in `.deepsec/data/<project>/` |
| `REPORT` | "triage findings", "export deepsec report" | Compute P0/P1/P2 scores, render markdown table | `REPORT.md` and terminal summary |

---

## Workflow Steps

### Step 1: Detect Runner (`freedom: low`)

Execute runtime detection to select native binary vs Node.js fallback:

```bash
skills/deepsec/scripts/detect-runtime.sh
```

- If `native` (`bk deepsec`): Use zero-dependency compiled binary.
- If `node` (`npx deepsec`): Use Node.js runtime.
- If no runner detected: Offer automated native compilation (`cargo build --release`) or inform the user.
- Reference: [Runner Comparison](references/runner-comparison.md)

### Step 2: Configure Engine (`freedom: low`)

Ensure `.deepsec/config.json` exists and satisfies budget constraints:

```bash
skills/deepsec/scripts/validate-config.sh .deepsec/config.json
```

- If missing, copy template from `assets/config.template.json` to `.deepsec/config.json`.
- Set `concurrency` between `1` and `8` (default: `4`).
- Assert `max_cost_usd` is positive (default: `5.0`).
- Reference: [Configuration Reference](references/configuration.md)

### Step 3: Candidate Scanning (`freedom: low`)

Run the pre-filter candidate extraction over target repository paths:

- Native: `bk deepsec scan --dir .`
- Node fallback: `npx deepsec scan`

Validates that `.deepsec/data/<project>/` contains populated `FileRecord` JSON objects with discovered candidate regex matches.

### Step 4: Batched AI Investigation & Revalidation (`freedom: medium`)

Dispatch candidate batches to the configured LLM:

- Native: `bk deepsec process --project <project_id> && bk deepsec revalidate --project <project_id>`
- Node fallback: `npx deepsec process`

Workers evaluate source context, rule criteria, and sanitize false positives. If the spend limit is reached, workers halt immediately with status saved to disk.

### Step 5: Triage & Report Generation (`freedom: medium`)

Compute deterministic priority tiers (`P0`, `P1`, `P2`) and emit structured findings:

- Native: `bk deepsec triage --project <project_id> && bk deepsec report --project <project_id>`
- Node fallback: `npx deepsec report`

Report format:
- Summary table categorized by Priority (`P0` / `P1` / `P2`).
- Detailed finding cards containing: Finding ID, CWE, affected file and line number, verified risk scenario, and recommended fix.
- Reference: [Triage Matrix](references/triage-matrix.md)

---

## Stop Conditions & Fallback Behavior

1. **Missing API Keys:** If neither `GEMINI_API_KEY`, `OPENAI_API_KEY`, nor `ANTHROPIC_API_KEY` is present in the environment, halt before Step 4 and prompt the user to provide API credentials.
2. **Budget Exhaustion:** If current spend exceeds `max_cost_usd`, pause execution, persist completed records to `.deepsec/data/<project>/`, and inform the user of partial progress.
3. **Lock Contention:** If `.deepsec/data/<project>/` contains an active worker lock from a running PID, wait or confirm whether the process is defunct before claiming.
