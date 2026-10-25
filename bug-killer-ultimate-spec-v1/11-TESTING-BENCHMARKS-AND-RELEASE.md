# 11. Verification strategy, benchmarks and release criteria

## Principles

- Red/green falsification: a regression test must fail on the pre-fix source for the reason claimed, pass after fix, and remain stable without live network.
- Independent evidence: a classifier does not get credit for predicting its own generated ground truth.
- Coverage and measurement must be reproducible and honestly scoped.
- Separate code-quality green from AppSec correctness and from privileged deployment safety.

## Test layers

| Layer | Purpose | Tooling / fixtures |
|---|---|---|
| Unit | Deterministic rule and parser behavior | Rust `cargo test`, Go `go test`; good/bad/evasion |
| Contract | Schema versioning, errors and receipts | JSON Schema + compatibility golden files |
| Integration | Rust/Go/MCP/adapter interoperability | Temp projects, fake OSV, offline tools |
| Adversarial | Parser and trust boundary resilience | Property-based tests, fuzz input, symlink/permission fixtures |
| End-to-end | Authorization → repair → verify/rollback | Ephemeral workspace, controlled fake services |
| Benchmark | Detection precision/recall and speed | OWASP Benchmark, NIST SARD, internal labelled real-world fixtures |
| Release | Distribution/CI across OS/CPU | Signed bundles, Docker build where supported, SBOM, smoke tests |

Benchmark sources: https://owasp.org/www-project-benchmark/ and https://samate.nist.gov/SARD

## Golden corpus specification

Each case manifest:

```yaml
case_id: BK-INJECTION-SQL-0001
language: python
weakness: CWE-89
expected_vulnerable: true
expected_certainty_cap: STRONGLY_SUPPORTED
expected_rule_ids: ["BK-AI-EXAMPLE"]
source_sha256: "<digest>"
scenario:
  type: source-to-sink
  execution: offline
provenance:
  class: synthetic
  source: tests/fixtures/security
```

Fixtures must include matched safe neighbors, dead code, comments, nested declarations, Unicode, alternate formatting, async flows, parameterized sanitizers, cross-file source/sink chains, dynamic dispatch unknowns, partial parse, module import failure, dependency ambiguity and permission boundary cases.

No secret-shaped live keys, executable exploit payloads or external target URLs are required. Fixture data stays synthetic.

## Required benchmark metrics

`Recall = TP / (TP + FN)`  
`Precision = TP / (TP + FP)`  
`FPR = FP / (FP + TN)`

Report per CWE, language and engine, plus totals weighted by transparent test mix. Include CI run ID, commit, corpus digest, ruleset digest, engine version, parser and system metadata, sample count and confidence intervals. Never use only "zero false positives in our own repo" as a product accuracy claim.

### Benchmark promotion rule

An AST/CPG detector may replace a legacy detector when its labelled fixture performance is no worse on critical seeded cases, the new false-positive behavior is justified, and the engine's unavailable/partial statuses are honest. Targets for precision/recall are set after baseline measurement, not made up in this spec.

## CI pipeline plan

1. `fmt`: Rust fmt, Go fmt, JSON/YAML schema and docs lint.
2. `static`: Rust clippy warnings denied, Go vet, dependency/license check.
3. `unit`: deterministic unit suites plus contract schemas.
4. `integration`: Rust/Go/MCP/adapter offline end-to-end.
5. `security`: negative auth/rule provenance, SSRF/rebinding, secrets redaction, symlink/rollback.
6. `benchmark`: pinned small representative suite and metric regression check.
7. `fuzz-smoke`: deterministic bounded seed corpus, no network and no privileged host.
8. `release`: build reproducible images/binaries for supported hosts, SBOM and provenance.
9. `nightly`: extended benchmark and fuzz jobs, resource-capped, results triaged.

### Current required commands as checked in AGENTS.md

```bash
cargo test --workspace
cargo clippy --all-targets -- -D warnings
# Separately under services/orchestrator and services/healer:
go test -v ./...
go vet ./...
```

Also execute `cargo fmt --all -- --check` and Inspector checks as appropriate. This spec does not claim that all optional adapters exist or their tests currently pass.

## Critical negative tests

- Scan never claims `PASS_IN_SCOPE` with a failed crawler subtree.
- Expired, forged, replayed, wrong-root, wrong-plan approvals all denied.
- AI-generated rules cannot run arbitrary shell or bypass trust/provenance.
- DAST denies non-authorized private targets and metadata endpoints even when other private networks are authorized.
- Trusted scoped DNS resolution resists rebinding and redirects on actual connection.
- Partial OSV inventory with no findings is not complete security assurance.
- Joern absence or crash reports `NOT_RUN/ERROR` when required, not silent success.
- Property-based scanner/parser input cannot cause uncontrolled panic, hang, OOM or host write.
- All repair verification failures leave an honest failed/partial state and rollback proof.
- Disclosure draft contains no secrets, and no external report is sent without fresh user approval.

## Performance budgets

Establish baseline on fixed repositories of 1k, 10k and 100k files; pin machine/OS; measure cold and incremental paths. Acceptance thresholds are data-driven. Quick mode must not require Java, Python, Node, network or graph DB and must remain viable in local pre-commit. Deep and Research may be more expensive, but must enforce user-configured maximum time, RAM and concurrency.

## Release channels

- `experimental`: behind feature flag, limited fixtures and labelled uncertainty.
- `preview`: tested adapters and documented limits, disabled privileged research by default.
- `stable`: passing gates A–G appropriate to included features, complete docs and rollback.

A release can ship Quick improvements without claiming Novel Hunter stable. Stable status applies per capability, not to the entire vision.

## Definition of done

No feature is "done" until: code merged, tests red/green proven, schema/API compatible, safety coverage receipts complete, docs accurate, license constraints met, independent review completed, and CI/release artifacts verified. Do not infer deployment readiness from successful `docker compose config` alone: a real container build and non-production smoke test are separate checks.
