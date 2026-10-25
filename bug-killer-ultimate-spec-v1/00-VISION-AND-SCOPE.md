# 00. Vision, users, requirements and scope

## Problem and final outcome

Bug Killer evolves from a predominantly pattern-based developer security scanner into a **local-first, evidence-driven, agentic cybersecurity operations room** for known vulnerability response, code security prevention, and novel vulnerability research. **Its core product is the orchestrator over trustworthy, mature security tools**, rather than a mandate to recreate every scanner, fuzzer, dataflow engine or repair engine. Its outputs must help a user determine what is affected, what is known, what is merely suspected, what was actually assessed, which repair can be safely applied, and whether a resulting fix was verified. See the governing product architecture in [Section 14](14-AGENTIC-SECURITY-OPERATIONS-ROOM.md).

User segments: (a) beginners and vibe coders who need guided findings and safe defaults, (b) professional software developers who need precise machine-readable CI/MCP output, (c) AppSec engineers needing traces and proof, and (d) authorized vulnerability researchers needing reproducible, bounded experiments and private reporting.

## Three product missions, one orchestration room

The three `BK-*` domains are **workflows** composed from existing engines and targeted native capabilities, not three independent reimplementations. Every workflow uses shared capability discovery, scoped execution, provenance, correlation, approval and verification.

### BK-1: Known Vulnerability Response

- Discover direct and transitive dependencies and their exact resolved versions.
- Consume trustworthy advisory feeds for new and updated disclosures, correlate package identities, version/commit ranges, and optional patch signatures.
- Differentiate an **affected dependency** from a **confirmed reachable vulnerable code path**.
- Offer version upgrades, surgical source fixes, mitigation advice, regression tests, and policy-scoped apply with verification.
- Operate with cached signed/validated intelligence while offline; expose freshness as evidence rather than silently presenting stale data.

### BK-2: Security Catalog & Prevention

- Preserve the existing 373-entry security catalog as a taxonomy, not an accuracy claim.
- For each rule: executable detector implementation, applicability conditions, required evidence, target languages, precision tests and coverage receipts.
- Run fast at project initialization, before commits, in CI, with agents via MCP, and on demand.
- Support AST/structural matching for simple rules, dataflow and cross-file analysis for complex ones, and runtime tests only when authorized.
- Use fail-closed policy where mandatory coverage is incomplete; do not call an unassessed target secure.

### BK-3: Novel Vulnerability Research

- Generate bounded security hypotheses about code paths, third-party packages, cross-component trust boundaries and missing invariants.
- Test hypotheses in isolated copies of approved local source or explicit researcher-controlled environments using deterministic checks, property tests, fuzzing and differential testing.
- Preserve crash/violation reproduction artifacts without weaponizing or publishing attack payloads.
- Confirm that evidence is not explained by an existing advisory before classifying as a potentially unreported issue.
- Permit user-reviewed private disclosure bundles, with no autonomous public posting.

## Cross-cutting outcomes

| ID | Requirement | Priority |
|---|---|---|
| R-001 | Local-first operation, no mandatory cloud or LLM for ordinary scans | P0 |
| R-002 | Every result has machine-readable provenance and certainty | P0 |
| R-003 | Complete/partial/error/not-run coverage is explicit per relevant target and rule | P0 |
| R-004 | Operator authorization is separate from agent cryptographic identity | P0 |
| R-005 | No privileged mutation before policy/approval, backup and rollback gates | P0 |
| R-006 | Catalog checks use real evidence, not only declared supported IDs | P1 |
| R-007 | Advisory feed ingestion and exact dependency correlation | P1 |
| R-008 | Incremental AST and structural rule engine | P1 |
| R-009 | Optional cross-function and cross-file dataflow analysis | P1 |
| R-010 | Bounded hypothesis and fuzz execution with reproducible proofs | P2 |
| R-011 | Private disclosure, provenance and explicit publishing consent | P2 |
| R-012 | Benchmarked recall/precision/false-positive and coverage rates | P1 |
| R-013 | Backwards-compatible CLI/MCP schemas and migration tooling | P0 |
| R-014 | Deterministic supervised patch, test, re-scan, rollback lifecycle | P0 |
| R-015 | Orchestration-first engine selection: reuse validated mature tools before building new detection algorithms | P0 |
| R-016 | Tool capability discovery, availability/license/entitlement preflight and explicit required-vs-optional policy | P0 |
| R-017 | Agentic security-room plan, auditable execution lifecycle, resource/cost caps and execution receipts | P0 |
| R-018 | Cross-tool evidence correlation, independent verification, disagreement and shared-signal detection | P1 |
| R-019 | Replaceable external tool adapters that cannot expand permissions or silently export source/evidence | P0 |

## Modes

- **Quick:** bounded local pattern/AST scan, pre-commit; fast and offline.
- **Project:** full source/dependency inventory with known advisories when enabled; on demand/init.
- **CI:** deterministic pinned engines and fail-closed mandatory controls.
- **Deep:** Joern and other licensed/installed engines, broader cross-file analysis and approved runtime tests.
- **Research (PROPOSED):** privileged only within a designated sandbox and research policy; higher time/memory budgets with separate receipts.

Agent-facing guidance may recommend new security checks, but cannot self-approve privileged mutations, expand host scope, or silently ship research outputs.

## Success criteria

Success is not "373/373" alone. Report (1) applicable supported rules, (2) actually evaluated rule-target pairs, (3) files/assets enumerated vs excluded, (4) source-reachability evidence, (5) recalled/false-positive measured benchmark cases, (6) reproduced issues, (7) repair verification passes, (8) rollback successes, and (9) advisory freshness. Expose metric denominators and dataset versions; do not invent an assurance percentage.

## Explicit non-goals

- Mathematical proof of absence of all vulnerabilities.
- Universal zero-day discovery, automated CVE assignment, exploit kits, or unapproved internet-wide probing.
- Recreating Tree-sitter, a compiler frontend, or general-purpose graph search from scratch.
- Cloning mature SAST, SCA, fuzzers, AIxCC research systems or vendor platforms without a measured functional gap and legally viable basis.
- Replacing existing Rust/Go services in a single breaking migration.
- Calling LLM-generated text a verified vulnerability, approved rule or successful fix without deterministic evidence.
- Making every optional engine, Python service, JVM or Node runtime mandatory for an ordinary installation.
- Claiming to prevent every coding agent mistake or discover unknown vulnerabilities universally just because multiple tools are connected.

## Constraints and scope

The user may authorize deep assessment of their own systems, including selected private IPs, but authorization must be explicit, scoped, logged and bound to operation identity. Authorization to inspect a local dependency does not grant permission to probe its upstream maintainers' production infrastructure. Research external targets requires separately documented authorization.

## Documentation acceptance

Implementations must show a reproducible failure on old behavior, then a passing regression, versioned output schema, compatible CLI/MCP behavior, and a reverse path. Unsupported and experimental features remain visibly labelled.
