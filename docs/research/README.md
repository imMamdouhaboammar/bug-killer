# Research & Clean-Room Provenance

Archival research, clean-room audits, and technical specifications informing Bug Killer's native architecture.

> [!NOTE]
> Operational documentation for end users and operators is maintained in [[docs/OPERATOR_GUIDE.md]] and [[docs/AEGIS_PLATFORM_SPECIFICATION.md]]. The documents in this directory represent background clean-room research and provenance studies of upstream systems; they do **not** reflect live Bug Killer implementation metrics.

---

## DeepSec Clean-Room Research (`docs/research/deepsec/`)

This collection contains clean-room engineering research conducted during the evaluation and native reimplementation of `vercel-labs/deepsec` into Bug Killer's compiled Rust scanner and Go orchestrator.

| Artifact | Source / Scope | Status | Purpose & Rationale |
|---|---|---|---|
| [`upstream-scan-report.md`](file:///Users/mamdouhaboammar/Documents/antigravity/silly-kepler/docs/research/deepsec/upstream-scan-report.md) | `vercel-labs/deepsec` upstream clone | Archived Reference | External code audit and asset inventory of upstream TypeScript packages (`@deepsec/*`). Relocated from `docs/repo-scan-report.md` to prevent confusing upstream metrics with Bug Killer. |
| [`recon.md`](file:///Users/mamdouhaboammar/Documents/antigravity/silly-kepler/docs/research/deepsec/recon.md) | Clean-room reconnaissance | Archived Reference | Pipeline stage breakdown (scan, process, revalidate, triage, enrich, export) and public reference inventory. |
| [`architecture.md`](file:///Users/mamdouhaboammar/Documents/antigravity/silly-kepler/docs/research/deepsec/architecture.md) | Clean-room architectural plan | Archived Reference | Architectural comparison between Node.js/V8 upstream and Bug Killer's zero-copy Rust DFA engine and Go Afero sandbox. |
| [`feedback.md`](file:///Users/mamdouhaboammar/Documents/antigravity/silly-kepler/docs/research/deepsec/feedback.md) | User sentiment analysis | Archived Reference | Analysis of friction points in upstream scanners (heavyweight Node.js footprint, runaway token costs, ReDoS fragility). |
| [`fixes.md`](file:///Users/mamdouhaboammar/Documents/antigravity/silly-kepler/docs/research/deepsec/fixes.md) | Strategic positioning | Archived Reference | The "Three Lists" defining clean-room advantages: native binary compilation, multi-provider LLM support, and virtual healing seam. |
| [`features.csv`](file:///Users/mamdouhaboammar/Documents/antigravity/silly-kepler/docs/research/deepsec/features.csv) | Parity traceability matrix | Archived Reference | Mapping of 18 core scanner and CLI features from original to clean-room implementation. |
| [`design/components.md`](file:///Users/mamdouhaboammar/Documents/antigravity/silly-kepler/docs/research/deepsec/design/components.md) | Terminal UI design specs | Archived Reference | Console table formatting, finding pill banners, and ANSI color hierarchy. |
| [`design/tokens.css`](file:///Users/mamdouhaboammar/Documents/antigravity/silly-kepler/docs/research/deepsec/design/tokens.css) | Report theme styling | Archived Reference | CSS custom properties for finding severity and verdict styling in HTML reports. |
| [`design/tokens.json`](file:///Users/mamdouhaboammar/Documents/antigravity/silly-kepler/docs/research/deepsec/design/tokens.json) | Design token definitions | Archived Reference | Machine-readable color definitions for terminal and web presentation. |

---

## Operational Skill Separation

The operational DeepSec agent skill is maintained under `skills/deepsec/` with its test suite in `scripts/eval_deepsec_skill.py`. Research artifacts do not interfere with skill execution, and test suites verify that skill packaging remains independent.
