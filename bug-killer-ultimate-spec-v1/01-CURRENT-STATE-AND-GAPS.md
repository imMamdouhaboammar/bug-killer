# 01. Source-grounded current state and change surface

## Inspection baseline

- Repository: https://github.com/imMamdouhaboammar/bug-killer
- Observed PR: https://github.com/imMamdouhaboammar/bug-killer/pull/25, merged 2026-10-25
- Baseline merge SHA: `636887a76dc1654d51005af6210c605b7e556ecb`
- Audit is a **snapshot**, not a promise of permanent file layout.

Current modules inspected: `src/types.rs`, `src/main.rs`, `src/lib.rs`, `src/osv/mod.rs`, `src/taint/mod.rs`, `src/detectors/mod.rs`, `src/dast/mod.rs`, `services/orchestrator/ledger/ledger.go`, and repository `AGENTS.md`.

## Present foundations to preserve

| Area | Existing element | Consequence |
|---|---|---|
| Core implementation | Rust CLI/library, Go orchestrator/healer, Rust Inspector | Add adapters rather than replace binaries |
| CLI | `scan`, `probe`, `osv`, `heal`, `security scan/status/explain/fix/verify/guidance/catalog`, `init`, `watch`, `mcp` | Extend without reinterpreting existing command flags |
| Known advisories | `OsvClient`, lockfile/manifest discovery, exact vs declared version distinction | Extend to durable feed cache/SBOM/correlation instead of a fresh rewrite |
| Catalog | `SecurityCatalog`, `DetectorRegistry`, 373 catalog IDs, `supported_rule_ids` | Existing declared support is not per-target execution evidence |
| Findings | `EvidenceCertainty`, `Finding`, `CoverageReceipt`, `ScanCoverage`, `SecurityGuardReport` | Implement versioned adapters and preserve serialization compatibility |
| Taint | `src/taint/mod.rs` uses Regex-based detection | Introduce AST/dataflow engines, do not claim its present output proves cross-file reachability |
| DAST | `probe --authorized`, `--allow-private-targets` and sensitive-path controls | Preserve host/scope restrictions; add explicit research sandbox policy |
| Healing | plan/approve/apply, backup signatures and rollback code | Keep safe transactional core, strengthen authorization separation and test invariants |
| Agent support | MCP stdio server and hook/config utilities | Evolve within least-privilege grants and stable tool contracts |

## Confirmed architectural gaps

1. Runtime coverage is insufficiently tied to a **rule-target execution receipt**. A registered detector ID must never count as executed without a completed check.
2. Structural analysis is regex-heavy and has no confirmed shared Tree-sitter AST/typed CPG layer. Cross-function or cross-file evidence cannot be inferred from text adjacency alone.
3. OSV functionality is present, but the roadmap needs trusted feed refresh, cross-source deduplication, transitive SBOM provenance, commit-range matching, and patch validation.
4. There is no evidence of a production-grade local novelty research workflow with deterministic hypothesis triage, isolated fuzzing and private disclosure lifecycle.
5. Privileged healer authorization and identity, partial crawler coverage, WAF staging, and repair rule provenance are tracked as separate open hardening issues.
6. Optional engine discovery, license gating, per-engine versioning and SARIF normalization need defined contracts.

Do not automatically assume these gaps remain unchanged: implementation agents must re-read current main before any PR.

## Open issue coordination, 2026-10-25 snapshot

| Current issue | Topic | Plan dependency |
|---|---|---|
| [#22](https://github.com/imMamdouhaboammar/bug-killer/issues/22) | Dependency-aware safety tracker | Master sequencing / integration gate |
| [#10](https://github.com/imMamdouhaboammar/bug-killer/issues/10), [#11](https://github.com/imMamdouhaboammar/bug-killer/issues/11), [#12](https://github.com/imMamdouhaboammar/bug-killer/issues/12) | Go auth, scoped heal, cross-file rollback | R-004/R-005/R-014 |
| [#15](https://github.com/imMamdouhaboammar/bug-killer/issues/15), [#23](https://github.com/imMamdouhaboammar/bug-killer/issues/23) | Operator identity and untrusted rules | R-004/R-005 |
| [#13](https://github.com/imMamdouhaboammar/bug-killer/issues/13), [#20](https://github.com/imMamdouhaboammar/bug-killer/issues/20), [#24](https://github.com/imMamdouhaboammar/bug-killer/issues/24) | Staged index, coverage receipts, crawler partiality | R-002/R-003/R-013 |
| [#14](https://github.com/imMamdouhaboammar/bug-killer/issues/14), [#16](https://github.com/imMamdouhaboammar/bug-killer/issues/16), [#17](https://github.com/imMamdouhaboammar/bug-killer/issues/17) | DAST scopes, upgrade and WAF safety | R-005/R-007 |
| [#19](https://github.com/imMamdouhaboammar/bug-killer/issues/19), [#21](https://github.com/imMamdouhaboammar/bug-killer/issues/21) | Finding certainty and bounded fuzz/property tests | R-002/R-010 |

Some issues predate PR #25 and may be partly addressed. **Never close or rewrite them merely because a nearby fix merged.** Compare acceptance tests against current master and mark implemented, partial and remaining acceptance explicitly.

## Migration approach

1. Introduce new envelopes, adapters and receipts alongside old fields.
2. Keep the original Rust `Finding` / `SecurityGuardReport` JSON readable through a compatibility layer.
3. Version all new public JSON with major version, reject unknown required semantics and preserve unknown optional extension fields.
4. During transition, old scanners supply `PATTERN_INDICATOR` or `UNKNOWN` certainty where reachability has not been proven.
5. Promote a detector to structural/dataflow status only after a language-specific precision/recall regression corpus is checked.
6. Remove or deprecate old fields only in a documented major contract migration.

## Critical caution

AGENTS.md declares a project-specific source-available/business-attribution license for Bug Killer. Do not describe the entire repository as unconditionally MIT/Apache/open-source, and do not assume permission to relicense existing code. The references in Section 09 have separate upstream licenses that require normal compliance review.
