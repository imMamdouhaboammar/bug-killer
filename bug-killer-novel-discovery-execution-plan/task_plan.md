# Bug Killer — Novel Discovery Engine: Task Plan

**Project:** https://github.com/imMamdouhaboammar/bug-killer  
**Baseline commit:** `06b24f2d9328de4d55868519f59e8591afbe9781`  
**Plan version:** 1.0.0  
**Started:** 2026-10-28  
**Goal:** All phases Status: complete with independently verified acceptance evidence per card.

## Next Step

**BK-ND-00** — Run `cargo fmt --all` on `src/scanner/mem_temp.rs` + `tests/mem_temp_test.rs`, confirm CI green, open PR.

---

## Phases

### Phase 0: BK-ND-00 — Restore CI Baseline
**Status:** `pending`  
**Branch:** `bk-nd-00-restore-ci-baseline`  
**Files:** `src/scanner/mem_temp.rs`, `tests/mem_temp_test.rs`  
**Acceptance:**
- [ ] `cargo fmt --all -- --check` → exit 0
- [ ] `cargo clippy --all-targets -- -D warnings` → 0 warnings
- [ ] `cargo test --workspace` → all pass
- [ ] `cd services/orchestrator && go test -v ./... && go vet ./...`
- [ ] `cd services/healer && go test -v ./... && go vet ./...`

**Rollback:** `git revert` formatting commit; no behavior risk.

---

### Phase 1: BK-ND-01 — Quarantine Simulated Research Proof
**Status:** `blocked_on: Phase 0`  
**Branch:** `bk-nd-01-quarantine-simulated-proof`  
**Files:** `src/hunter/orchestrator.rs`, `src/hunter/hypothesis.rs`  
**Acceptance:**
- [ ] RED test `test_hunt_simulation_cannot_yield_verified` fails on current master (document this)
- [ ] PASSES after fix: `test_simulated_experiment_status_is_simulation_only`
- [ ] PASSES: `test_simulation_blocked_from_verified_transition`
- [ ] PASSES: `test_scan_unaffected_by_research_quarantine`

**Rollback:** Feature flag `RESEARCH_REAL_EXECUTION=false`.

---

### Phase 2: BK-ND-02 — OS-Backed Research Sandbox
**Status:** `blocked_on: Phase 1`  
**Branch:** `bk-nd-02-os-sandbox-isolation`  
**Files:** `src/hunter/sandbox.rs`, execution host adapter  
**Acceptance:**
- [ ] `test_sandbox_raw_socket_denied`
- [ ] `test_sandbox_filesystem_escape_denied`
- [ ] `test_sandbox_child_process_contained`
- [ ] `test_sandbox_memory_ceiling_enforced`
- [ ] `test_sandbox_unsupported_platform_blocks`
- [ ] `test_sandbox_receipt_truthful_measurements`

**Open question:** CI runner OS (Linux = seccomp / macOS = Docker --network=none)?

---

### Phase 3: BK-ND-03 — Immutable Target Snapshot and Research Scope
**Status:** `blocked_on: Phase 2`  
**Branch:** `bk-nd-03-immutable-target-snapshot`  
**Files:** `src/engine` (new research protocol), `src/hunter` scope enforcer  
**Acceptance:**
- [ ] `test_snapshot_symlink_escape_blocked`
- [ ] `test_snapshot_tool_binary_substitution_blocked`
- [ ] `test_scope_cannot_expand_from_llm_output`
- [ ] `test_unauthorized_target_blocked`

---

### Phase 4: BK-ND-04 — Real Tool Broker and Execution Ledger
**Status:** `blocked_on: Phase 3`  
**Branch:** `bk-nd-04-real-tool-broker`  
**Files:** `src/deep/broker.rs`, adapter contracts, ledger  
**Acceptance:**
- [ ] `test_semgrep_real_execution_receipt`
- [ ] `test_cargo_audit_real_execution_receipt`
- [ ] `test_missing_tool_yields_not_run`
- [ ] `test_tool_timeout_cleans_child_process`

**Open question:** Semgrep + cargo-audit OR cargo-audit + clippy if Semgrep has CI constraints?

---

### Phase 5: BK-ND-05 — Node/TS Attack-Surface Map with Honest Confidence
**Status:** `blocked_on: Phase 3`  
**Branch:** `bk-nd-05-node-ts-attack-surface`  
**Files:** `src/hunter/orchestrator.rs` (surface analysis), AST/dataflow, framework adapters  
**Acceptance:**
- [ ] `test_comment_only_match_not_confirmed_reachable`
- [ ] `test_cross_file_auth_trace_express`
- [ ] `test_unsupported_router_partial_coverage`
- [ ] `test_confidence_calibration_structural_vs_dataflow`

**Parallel-safe with:** Phase 4

---

### Phase 6: BK-ND-06 — Target-Bound Authorization Test Harness
**Status:** `blocked_on: Phase 4, Phase 5`  
**Branch:** `bk-nd-06-target-bound-authz-harness`  
**Files:** New harness adapter, `tests/fixtures/node-authz-harness/`  
**Acceptance:**
- [ ] `test_harness_cross_tenant_authz_bypass_detected`
- [ ] `test_harness_safe_case_not_flagged`
- [ ] `test_harness_no_external_traffic`
- [ ] `test_harness_replay_evidence_complete`

---

### Phase 7: BK-ND-07 — LLM Hypothesis Planner with Bounded Structured Tools
**Status:** `blocked_on: Phase 5, Phase 6`  
**Branch:** `bk-nd-07-llm-hypothesis-planner`  
**Files:** `src/agent`, `src/hunter` hypothesis planner  
**Acceptance:**
- [ ] `test_llm_cannot_execute_arbitrary_shell`
- [ ] `test_llm_cannot_expand_scope`
- [ ] `test_offline_fallback_hypothesis_generator`
- [ ] `test_hypothesis_record_provenance_required`

---

### Phase 8: BK-ND-08 — Independent Replay and Security Consequence Gate
**Status:** `blocked_on: Phase 6, Phase 7`  
**Branch:** `bk-nd-08-independent-replay-gate`  
**Files:** `src/hunter` reproduction engine, `src/disclosure` receipt gate, evidence schemas  
**Acceptance:**
- [ ] `test_replay_requires_fresh_snapshot`
- [ ] `test_verified_requires_consequence_proof_not_crash_alone`
- [ ] `test_tampered_receipt_rejected`
- [ ] `test_three_passes_same_predicate_not_independent_proof`

---

### Phase 9: BK-ND-09 — Novelty Triage and Private Disclosure
**Status:** `blocked_on: Phase 8`  
**Branch:** `bk-nd-09-novelty-triage-disclosure`  
**Files:** `src/advisory`, `src/hunter/novelty.rs`, `src/disclosure`  
**Acceptance:**
- [ ] `test_empty_advisory_not_novel`
- [ ] `test_known_cve_classified_known`
- [ ] `test_novel_candidate_requires_human_review`
- [ ] `test_zero_auto_disclosure`

---

### Phase 10: BK-ND-10 — Blind Evaluation and Differential Baseline
**Status:** `blocked_on: Phase 6, Phase 8`  
**Human dependency:** Independent maintainers must prepare sealed holdout corpus — start coordinating during Batch 2.  
**Branch:** `bk-nd-10-blind-evaluation`  
**Files:** `src/benchmark`, sealed holdout corpus, `scripts/run-benchmark.sh`  
**Acceptance:**
- [ ] `test_benchmark_holdout_sealed_during_development`
- [ ] `test_benchmark_publishes_denominators`
- [ ] `test_benchmark_comparison_against_component_tools`
- [ ] `scripts/run-benchmark.sh --corpus=holdout --output=results.json` produces valid JSON

**Parallel-safe with:** Phase 9

---

### Phase 11: BK-ND-11 — External Pilot and Experimental Release
**Status:** `blocked_on: Phase 9, Phase 10`  
**Human dependency:** Written permission from 5-10 pilot repo owners — start collecting during Batch 3.  
**Branch:** `bk-nd-11-external-pilot-release`  
**Files:** Release scripts, docs, public CLI, pilot evidence artifacts  
**Acceptance:**
- [ ] `scripts/release-build.sh --verify-signature` → signed artifact
- [ ] `test_pilot_finding_requires_written_permission`
- [ ] `test_release_disclaimer_present`
- [ ] Independent reviewer sign-off on at least one confirmed finding (manual gate)

---

## Decisions Made

| Decision | Rationale | Date |
|---|---|---|
| Batch 1 (BK-ND-00..03) before any research code | CI must be green; simulated findings must be quarantined before any real execution code is added | 2026-10-28 |
| Feature flag `RESEARCH_REAL_EXECUTION=false` default | Fail-closed; scan mode unaffected; research mode gated | 2026-10-28 |
| Ponytail full mode | Minimum correct fix per card; no speculative abstractions | 2026-10-28 |
| One PR per card | No combined unrelated PRs; each card must pass its own acceptance gate | 2026-10-28 |

## Errors Encountered

| Error | Attempt | Resolution |
|---|---|---|
| — | — | — |
