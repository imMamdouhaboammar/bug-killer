# Agentic Repository Discovery: DeepSec Architecture & Workflows

Identification of reusable agentic capabilities, prompts, and workflows in `vercel-labs/deepsec`.
Conducted per the `/agentic-repo-discovery` protocol.

---

## 1. Candidate Disposition Table

| Candidate Capability | Source Reference | Disposition | Clean-Room Integration Plan |
|---|---|---|---|
| Core Security Review Prompt | `packages/processor/src/prompt/core.ts` | `preserve_skill` | Embed into Rust `deepsec::prompt` module as canonical static system prompt. |
| Framework Threat Highlights | `packages/processor/src/prompt/highlights.ts` | `preserve_skill` | Inject conditionally based on detected framework tags. |
| Candidate Noise Scoring | `packages/scanner/src/index.ts` | `compile_skill` | Sort files before batching: precise matchers take priority over noisy ones. |
| Atomic File Locking | `packages/core/src/run.ts` | `compile_skill` | Implement `lockedByRunId` and `lockedAt` with PID liveness recovery. |
| Revalidation Prompt & Deduplication | `packages/processor/src/reconcile.ts` | `compile_skill` | Re-evaluate findings, resolve duplicates, and update verdicts. |
| P0-P2 Triage Classifier | `packages/processor/src/triage.ts` | `compile_skill` | Fast scoring pass assessing exploitability and blast radius. |
| Git Committer Attribution | `packages/processor/src/enrich.ts` | `compile_skill` | Extract author metadata from local git log without network roundtrips. |
| Vercel AI Gateway Broker | `packages/deepsec/src/auth/model-route.ts` | `reference_only` | Generalize into universal LLM HTTP adapter supporting Gateway, OpenAI, Anthropic, Gemini, and Ollama. |

---

## 2. Reusable Jobs Discovered

1. **Job 1: Zero-Shot Fast Repo Surface Inventory:** Scans the repo for entry points (HTTP routes, queues, crons, webhooks, CLI commands) and outputs a structured inventory (`surface-inventory.json`).
2. **Job 2: Gated Regex & AST Pattern Matching:** Evaluates fast heuristics without invoking AI, identifying candidate security sites in seconds.
3. **Job 3: Batched Reasoning-Model Security Review:** Passes small batches of candidate files (1-5 files) with targeted threat notes to a reasoning model, capturing structured findings.
4. **Job 4: False Positive Elimination & Git History Audit:** Audits surfaced findings against git commits to check if the code was already patched or mitigated.
5. **Job 5: Remediation Gate:** Feeds confirmed findings directly into Bug-Killer's virtual healing engine.
