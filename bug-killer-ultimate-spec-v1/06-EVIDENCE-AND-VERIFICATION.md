# 06. Evidence, completeness, verification and measurement contracts

## Main invariant

**No finding does not mean no vulnerability.** A scan may report `NO_FINDING_IN_COVERAGE` only for an explicitly enumerated and completed scope. `VERIFIED` always means a particular proposition was checked under recorded assumptions, never that the entire system is safe.

The current code already has `Finding`, `EvidenceCertainty`, `CoverageReceipt`, `ScanCoverage`, `ScanStatus` and `SecurityGuardReport` in `src/types.rs`. Extend these with an additive v1 envelope and compatibility transformer rather than replacing public structs in one PR.

## Evidence model

Every normalized result contains:

- Finding ID + stable fingerprint independent of line-number jitter, linked source revision.
- Source type: `KNOWN_ADVISORY`, `CATALOG` or `RESEARCH_CANDIDATE`.
- Rule/advisory IDs with correct namespace: CWE is weakness category, CVE is disclosure ID; do not use CWE strings as CVE values.
- Engine identity/version, rulepack hash and data source provenance.
- Affected package, target, normalized paths, source/commit/content digests.
- Evidence items: source spans, AST IDs, dataflow path, runtime test proof, advisory version match, reproducible test hash.
- Evidence certainty with explicit reason and counterevidence.
- Associated coverage receipts, scan status, policy decision and remediation/verification references.
- Redaction metadata: no secrets, tokens, private vulnerability content or raw sensitive HTTP responses in standard logs.
- Correlation metadata: per-engine raw IDs, shared rule/feed lineage, disagreements, evidence independence classification and linked actual `ToolExecutionReceipt` IDs.

See `schemas/finding.schema.json`.

## Evidence certainty

| Level | When permitted | Not sufficient on its own |
|---|---|---|
| `UNKNOWN` | Missing, broken or untrusted evidence | Any positive assurance |
| `PATTERN_INDICATOR` | Regex/AST syntactic signal | Runtime reachability claims |
| `SUSPECTED` | Coherent model but path/preconditions uncertain | Exploitability or "confirmed" |
| `STRONGLY_SUPPORTED` | Relevant static dataflow and applicable contextual facts | Full dynamic proof if required |
| `CONFIRMED` | Rule-specific decisive deterministic proof, isolated reproducibility or authoritative affectedness **for the precise claim** | Universal absence of risk |

Conflicting evidence lowers certainty, never silently increases it. Advisory affected version can confirm `VERSION_AFFECTED` without confirming reachable exploitability.

## Coverage model

`CoverageReceipt v1` tracks actual `(run, engine, target, rule/check)` work and carries:

`status = EVALUATED | PARTIAL | NOT_RUN | UNSUPPORTED | NOT_APPLICABLE | ERROR`

with counts and reasons. This proposed schema differs from legacy `COMPLETE/PARTIAL/SCAN_INCOMPLETE` and must be mapped explicitly:

| Legacy | New mapping |
|---|---|
| `Complete` | `EVALUATED` only when rule-target execution evidence exists; else `PARTIAL` |
| `Partial` / `ScanIncomplete` | `PARTIAL` with detailed reason |
| `NotRun` | `NOT_RUN` |
| `Unsupported` | `UNSUPPORTED` |
| `Error` | `ERROR` |
| Not applicable | explicit `NOT_APPLICABLE`, never counted as assessed |

Receipts are append-only per run and reference input snapshot hash; a resumed task creates new receipt IDs and links to its predecessor. Counts must reconcile: discovered = assessed + excluded + skipped/error as appropriate without double counting. The aggregate status is the worst required status under policy, not the most favorable engine result.

**Three distinct claims:** `ToolCapability` says an engine *could* be applicable; `ToolExecutionReceipt` says it *was attempted or skipped* under recorded policy; `CoverageReceipt` says a particular check/target *was actually evaluated* or why it was not. Only the third counts towards checked coverage. A completed tool process without rule-target evidence is not completed assessment. An unlicensed/absent required tool stays a coverage blocker.

See `schemas/coverage-receipt.schema.json`.

## Gate algebra

Let `M` be mandatory rule-target checks, `E` be successfully evaluated relevant checks, `F` be threshold findings, and `X` be errors/partial/not-run/unsupported among mandatory checks.

- `PASS_IN_SCOPE` iff `F = 0` and `X = 0` and the target enumeration was complete under policy.
- `FAIL_FINDINGS` iff a verified or sufficiently supported finding exceeds configured severity/evidence threshold.
- `BLOCKED_INCOMPLETE` iff `X > 0` or inventory could not establish complete mandatory scope.
- `BLOCKED_AUTHORIZATION` iff required activity is outside signed operator grant.
- `ERROR` iff engine protocol, verification integrity, or internal invariant failed.
- `NOT_ASSESSED` where no meaningful security assessment was actually performed.

These are mutually exclusive aggregate outcomes. Evaluate in strict precedence order:
`ERROR > BLOCKED_AUTHORIZATION > BLOCKED_INCOMPLETE > FAIL_FINDINGS > NOT_ASSESSED > PASS_IN_SCOPE`.
`ERROR` is reserved for an engine/protocol/integrity fault, not ordinary incomplete source coverage. If verified findings coexist with missing mandatory checks, return `BLOCKED_INCOMPLETE` while still including all findings in the report and blocking CI. If no rule-target work ran, return `NOT_ASSESSED`, never `PASS_IN_SCOPE`. This precedence applies identically to CLI exit codes, MCP responses and CI policy.

CI cannot succeed because there are no findings if mandatory source files were unreadable or required engines were absent.

## Compatibility and machine outputs

- Preserve legacy exit behavior until a documented versioned interface changes it.
- A proposed `--exit-contract=v2` opts into stable distinct result codes: `0 PASS_IN_SCOPE`, `10 FAIL_FINDINGS`, `11 BLOCKED_INCOMPLETE`, `12 ERROR`, `13 BLOCKED_AUTHORIZATION`, `64 INVALID_REQUEST`. Values are **proposed**, not existing implementation.
- Include `schema_version` and `contract_version` in machine output.
- MCP and JSON consumers receive typed result codes, not text parsing of human summary.
- SARIF import/export retains original engine result IDs, source locations, flow edges, severities, fingerprints and coverage extension records; SARIF absence of a finding is not proof of full coverage.

## Evidence integrity

An audit record binds `run_id`, source snapshot, tool versions, policy version, approval ID (if any), and artifact SHA-256. Sign final audit envelopes with a designated system signing identity but do **not** treat an agent-held signing key as an operator approval authority. Never make a model-supplied string the material to be signed without trusted canonicalization and validation.

Secrets are redacted before logs, export, model inference and disclosure drafts. Content-addressed evidence references have retention and access policies. Hashes attest to bytes, not to correctness or completeness of analysis.

## Metrics

| Metric | Definition | Common pitfall |
|---|---|---|
| Rule registration | Registered catalog IDs / catalog IDs | Does not imply execution |
| Evaluated coverage | Evaluated mandatory rule-target checks / applicable mandatory checks | Cannot exclude errors from denominator |
| Asset inventory coverage | Fully enumerated assets / expected scoped assets | Expected set needs crawl receipts |
| Recall / TPR | TP / (TP + FN) on labelled cases | Inflated if only easy synthetic positives |
| Precision | TP / (TP + FP) | Poor if no safe negative fixtures |
| FPR | FP / (FP + TN) | Depends on negative corpus |
| Fix verified rate | Repaired and rechecked issues / attempted repairs | Cannot count unrun tests |
| Novel proof yield | Independently reproducible unique violations / bounded experiments | Never label all as CVEs |
| Advisory freshness | Age of immutable provider snapshot | Online vs offline comparison |

Disaggregate by language, weakness class, engine version, project size and execution profile. Confidence intervals and dataset version are required before any headline accuracy assertion.

## Acceptance tests

1. Partial filesystem crawl plus zero findings returns `BLOCKED_INCOMPLETE` for mandatory CI, not pass.
2. Unavailable Joern does not block Quick when not mandatory, but blocks Deep policy if Joern is explicitly required.
3. Rule marked supported without run receipt contributes zero to evaluated count.
4. A verified benign path avoids false confirmed vulnerability.
5. No claim of corrected issue before post-fix tests and rescan complete.
6. Signature verification fails after tampering with scope, preimage, plan ID, result or evidence digests.
7. Replaying old JSON through compatibility adapter preserves old meaning, including explicit unknown uncertainty.
