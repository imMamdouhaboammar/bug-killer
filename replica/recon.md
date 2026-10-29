# Reconnaissance Map: Vercel Labs DeepSec

Reconnaissance map for clean-room reconstruction of `vercel-labs/deepsec`.
Target Source: `https://github.com/vercel-labs/deepsec`
Evidence Digest: Commit hash verified from upstream clone.

---

## 1. Executive Overview & Scope

`deepsec` is an agent-powered vulnerability scanner designed to review entire codebases on-demand.
It combines fast pattern matching with AI agent investigations to find security issues.
The workflow moves through six stages: scan, process, revalidate, triage, enrich, and export.
All state is stored on disk in `.deepsec/data/<projectId>/` in JSON format.

---

## 2. Public Sources & Reference Inventory

| Source | Target / File Reference | Evidence Description |
|---|---|---|
| README.md | `/tmp/deepsec_target/README.md` | Core CLI lifecycle, pricing model, architecture overview. |
| Docs | `/tmp/deepsec_target/docs/architecture.md` | Pipeline stages, setup coordinator, concurrency model. |
| Data Layout | `/tmp/deepsec_target/docs/data-layout.md` | Schemas for `FileRecord`, `RunMeta`, `Finding`, `SetupState`. |
| Core Types | `/tmp/deepsec_target/packages/core/src/types.ts` | Complete TypeScript domain models and enums. |
| Scanner Engine | `/tmp/deepsec_target/packages/scanner/src/index.ts` | Multi-file scanning, tech detection, matcher evaluation. |
| Matcher Rules | `/tmp/deepsec_target/packages/scanner/src/matchers/` | 50+ built-in vulnerability matchers across ecosystems. |
| Processor Engine | `/tmp/deepsec_target/packages/processor/src/index.ts` | File batching, AI prompt assembly, JSON output extraction. |
| Core Prompt | `/tmp/deepsec_target/packages/processor/src/prompt/core.ts` | System prompt, severity levels, vulnerability categories. |
| Revalidation | `/tmp/deepsec_target/packages/processor/src/reconcile.ts` | Deduplication, verdict resolution, git fix validation. |
| CLI Commands | `/tmp/deepsec_target/packages/deepsec/src/commands/` | CLI command implementations and lifecycle hooks. |

---

## 3. Screen & CLI Interface Inventory

| ID | Command / Surface | Input Flags | Purpose | Key Outputs / State Changes |
|---|---|---|---|---|
| C01 | `deepsec init` | `--max-cost-usd`, `--max-duration`, `--model-auth` | Onboards repository, detects tech, writes `INFO.md`, runs baseline scan. | `.deepsec/data/<id>/project.json`, `setup/`, `INFO.md`. |
| C02 | `deepsec scan` | `--root`, `--only-slugs`, `--skip-slugs` | Fast pattern scan across source tree without invoking AI. | `data/<id>/files/**/*.json` with `candidates` populated. |
| C03 | `deepsec process` | `--concurrency`, `--batch-size`, `--agent`, `--model` | Investigates pending candidate files with AI model. | `data/<id>/files/**/*.json` with `findings` and `analysisHistory`. |
| C04 | `deepsec process --diff` | `--diff <ref>`, `--diff-working` | PR mode: scans and investigates only files changed in git diff. | Gating exit code: 0 if no net-new findings, 1 if net-new findings exist. |
| C05 | `deepsec revalidate` | `--force`, `--model` | Re-evaluates findings to filter false positives and check git fixes. | `finding.revalidation` with verdicts (`true-positive`, `false-positive`, `fixed`). |
| C06 | `deepsec triage` | `--model` | Classifies findings into priority buckets (`P0`, `P1`, `P2`, `skip`). | `finding.triage` with priority, exploitability, and impact. |
| C07 | `deepsec enrich` | `--git` | Attaches git committers and code ownership to files with findings. | `fileRecord.gitInfo` populated. |
| C08 | `deepsec report` | `--format <summary\|detail>` | Renders terminal and markdown summary for project. | Formatted Markdown and stdout metrics table. |
| C09 | `deepsec export` | `--format <json\|md-dir>`, `--out <path>` | Exports findings into structured files for downstream tools. | JSON file or directory of markdown files per finding. |
| C10 | `deepsec status` | None | Displays mirror state, file counts, and lock status. | Terminal snapshot table. |

---

## 4. User Flows

### F01: Repository Onboarding (`init`)
1. Detect repository root and remote GitHub URL.
2. Analyze repository structure and technologies (Next.js, FastAPI, Django, Rails, Go, Rust).
3. Generate structured `surface-inventory.json` and human-readable `INFO.md`.
4. Run baseline regex scan across repository.
5. Create `.deepsec/data/<projectId>/` directory structure.

### F02: Fast Pattern Scan (`scan`)
1. Expand globs against source root while excluding `IGNORE_DIRS`.
2. Evaluate gate conditions for matchers based on detected technologies.
3. Compute SHA-256 `fileHash` for each candidate file.
4. Execute regex patterns and extract line numbers and surrounding snippets.
5. Write or update `FileRecord` on disk with `status: "pending"`.

### F03: AI Investigation (`process`)
1. Query pending files and sort by noise score (precise matchers first).
2. Group files into batches (default 1 to 5 files per batch).
3. Atomically acquire lock per file with `lockedByRunId` and `lockedAt`.
4. Assemble system prompt combining `CORE_PROMPT`, tech highlights, and `INFO.md`.
5. Call AI agent backend with structured JSON schema constraint.
6. Parse agent response into `Finding` records with severity and recommendation.
7. Append entry to `analysisHistory` and transition `status` to `analyzed`.
8. Clear file lock.

### F04: False-Positive Revalidation (`revalidate`)
1. Select analyzed files containing findings without revalidation.
2. Read source code and inspect git commit log for potential fixes.
3. Ask model to re-evaluate finding validity and check for existing mitigations.
4. Record verdict (`true-positive`, `false-positive`, `fixed`, `uncertain`, `duplicate`).

### F05: Git & Ownership Enrichment (`enrich`)
1. Locate files with confirmed findings.
2. Query git blame and commit log for top recent authors.
3. Attach committer metadata to `FileRecord.gitInfo`.

### F06: Reporting & Export (`export`)
1. Read all `FileRecord`s for project.
2. Filter by status, severity, or revalidation verdict.
3. Write formatted report to terminal or export as JSON / markdown directory.

---

## 5. Inferred Data Model & Entities

### ProjectConfig
- `projectId`: String matching project directory name.
- `rootPath`: Absolute path to scanned codebase.
- `createdAt`: ISO 8601 creation timestamp.
- `githubUrl`: Optional repository URL for link generation.

### FileRecord
- `filePath`: Relative path within repository.
- `projectId`: Project identifier.
- `candidates`: Array of `CandidateMatch` objects.
- `lastScannedAt`: ISO 8601 timestamp.
- `lastScannedRunId`: ID of scan run.
- `fileHash`: SHA-256 hash of file content.
- `findings`: Array of `Finding` objects.
- `analysisHistory`: Append-only array of `AnalysisEntry` records.
- `gitInfo`: Optional git committer and ownership metadata.
- `status`: Lifecycle state (`pending`, `processing`, `analyzed`, `error`).
- `lockedByRunId`: Optional run ID holding active lock.
- `lockedAt`: Optional ISO 8601 timestamp of lock acquisition.

### Finding
- `findingId`: Deterministic ID (`finding_` + SHA-256 prefix of project, path, and title).
- `severity`: Enum (`CRITICAL`, `HIGH`, `MEDIUM`, `HIGH_BUG`, `BUG`, `LOW`).
- `vulnSlug`: Category slug (e.g. `sql-injection`, `rce`, `ssrf`).
- `title`: Single-sentence summary.
- `description`: Detailed explanation of vulnerability.
- `lineNumbers`: 1-indexed line numbers.
- `recommendation`: Concrete remediation advice.
- `confidence`: Enum (`high`, `medium`, `low`).
- `triage`: Optional `Triage` classification.
- `revalidation`: Optional `Revalidation` assessment.
- `producedByRunId`: Run ID that discovered finding.

---

## 6. What Cannot Be Cloned & Clean-Room Substitutions

| Target Dependency | Original Implementation | Clean-Room Rust / Go Replacement |
|---|---|---|
| Runtime Host | Node.js / TypeScript runtime (`node_modules`) | Pure compiled native Rust binary (`bk deepsec`) + Go orchestrator service. |
| AI Client | `@openai/codex-sdk`, `@anthropic-ai/claude-agent-sdk` | Native HTTP client (`ureq` in Rust, `net/http` in Go) with support for Vercel AI Gateway, OpenAI, Anthropic, Gemini, and Ollama. |
| Cloud VMs | Vercel Sandbox microVMs | Go orchestrator with Afero sandboxed isolation and local worker pools. |
| Git Provider | GitHub API via octokit | Local `git` CLI invocation via `std::process::Command` with zero network overhead. |
