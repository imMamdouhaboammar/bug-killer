# System Architecture: Bug-Killer DeepSec Rust/Go Harness

Architecture blueprint for the clean-room reconstruction of DeepSec into a native Rust engine and Go orchestrator.

---

## 1. System Stack & Design Rationale

| Layer | Component | Language / Tooling | Rationale |
|---|---|---|---|
| Core Engine | Scanning, Parsing, Matchers, Storage | Rust 2024 | Zero-copy performance, thread safety, memory safety, DFA linear-time regex execution. |
| Orchestrator | Worker pool, sandboxing, task scheduling | Go 1.24 | Concurrency via goroutines, lightweight sandboxed filesystem via Afero. |
| Storage & State | Append-only on-disk state mirror | Serde JSON (`.deepsec/data/`) | Compatible with standard DeepSec layout; human-readable and git-friendly. |
| AI Integration | LLM Gateway / Direct Client | Rust `ureq` + Go `net/http` | Uniform JSON streaming/HTTP client with zero external SDK bloat. |
| CLI Interface | Unified `bk deepsec` commands | Clap v4 (`derive`) | Robust CLI with tab completion, ANSI colors, and structured JSON outputs. |

---

## 2. On-Disk State Architecture

The storage layout mirrors the DeepSec specification:

```text
.deepsec/data/<projectId>/
├── project.json              # Project identity and root path
├── INFO.md                   # Repository threat context for AI prompt
├── setup/
│   ├── setup-state.json      # Phase checkpoints and digests
│   └── surface-inventory.json# Structured ingress and entry point inventory
├── files/                    # One FileRecord JSON per scanned source file
│   └── src/api/auth.rs.json
├── runs/                     # One RunMeta JSON per execution run
│   └── 20261028-103000-abcd.json
└── reports/                  # Generated markdown and JSON reports
```

### Atomic Locking & State Transition Invariants
- Each `FileRecord` transitions through four states: `pending` -> `processing` -> `analyzed` -> `error`.
- File claims are atomic: a worker sets `lockedByRunId` and `lockedAt` timestamp during `processing`.
- Stale lock recovery: if a lock is older than 3600 seconds or the owning PID is no longer alive on the current host (`libc::kill(pid, 0)`), another worker may safely reclaim the record.
- Additive updates: candidates are merged, analysis history is appended, findings are deduped by finding ID.

---

## 3. Data Schemas

### `FileRecord`
- `file_path`: Path relative to repository root.
- `project_id`: Project identifier.
- `candidates`: List of `CandidateMatch` records.
- `last_scanned_at`: ISO timestamp.
- `last_scanned_run_id`: Run ID.
- `file_hash`: SHA-256 hash of file content.
- `findings`: List of `Finding` records.
- `analysis_history`: List of `AnalysisEntry` records.
- `git_info`: Committer and author attribution.
- `status`: Enum (`pending`, `processing`, `analyzed`, `error`).
- `locked_by_run_id`: Active locking run.
- `locked_at`: Lock acquisition timestamp.

### `Finding`
- `finding_id`: Stable deterministic hash `finding_<sha256(projectId + path + title)>[..16]`.
- `severity`: Enum (`CRITICAL`, `HIGH`, `MEDIUM`, `HIGH_BUG`, `BUG`, `LOW`).
- `vuln_slug`: Category identifier (e.g. `sql-injection`, `rce`, `ssrf`).
- `title`: Short summary.
- `description`: Full vulnerability explanation.
- `line_numbers`: 1-indexed line numbers.
- `recommendation`: Remediation guidance.
- `confidence`: Enum (`high`, `medium`, `low`).
- `triage`: Optional `Triage` classification.
- `revalidation`: Optional `Revalidation` assessment.
- `produced_by_run_id`: Discovery run ID.

---

## 4. CLI Subcommands & Flows

| Subcommand | Purpose | Engine Layer |
|---|---|---|
| `bk deepsec init` | Onboard repo, detect frameworks, write `INFO.md`, run baseline scan | Rust Coordinator |
| `bk deepsec scan` | Execute fast regex matchers across codebase | Rust Scanner |
| `bk deepsec process` | Batched AI investigation of candidate files | Rust Processor |
| `bk deepsec revalidate` | Filter false positives and verify git fixes | Rust Revalidate |
| `bk deepsec triage` | Classify findings into P0/P1/P2 priorities | Rust Triage |
| `bk deepsec enrich` | Attach git blame author history to findings | Rust Enrich |
| `bk deepsec report` | Render markdown report and terminal summary table | Rust Export |
| `bk deepsec export` | Export findings to JSON or markdown directory | Rust Export |
| `bk deepsec status` | Inspect data directory mirror and lock states | Rust Storage |

---

## 5. Potential Failure Modes & Hardening

1. **ReDoS / Infinite Regex Loops:** Handled by Rust `regex` crate, which guarantees $O(mn)$ linear time execution and cannot suffer catastrophic backtracking.
2. **Race Conditions in Concurrent Workers:** Addressed through atomic file replacement (write to temp file in same directory followed by atomic rename) and PID liveness validation.
3. **Runaway LLM Spend:** Enforced through `--max-cost-usd`, `--max-duration`, and batch token limits before every request.
4. **False Positive Fatigue:** Addressed through two-pass architecture (investigation followed by explicit revalidation) and noise score prioritization.
