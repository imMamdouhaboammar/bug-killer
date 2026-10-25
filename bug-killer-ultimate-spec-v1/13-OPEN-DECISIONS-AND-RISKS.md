# 13. Decision log, risks, assumptions and open questions

## Decisions locked for this specification

1. Three product missions are **orchestrated workflows** in a shared agentic cybersecurity operations room, **not three scanners to rebuild**. Bug Killer owns coordination, trust, evidence and verification.
2. Rust remains the authoritative local orchestrator and CLI.
3. Tree-sitter + ast-grep are the initial structural baseline.
4. Joern is optional deep-analysis sidecar, not a mandatory installer dependency.
5. Semgrep CE is an independent adapter; CodeQL usage must pass separate licensing checks.
6. Babel is a JS/TS specialist only.
7. Probe/Graphify/Code-Graph-RAG/CocoIndex/tensor-grep are evaluation candidates or context providers, not security proof engines by default.
8. A registered catalog rule is not counted as evaluated without actual rule-target proof.
9. Unknown candidates are not automatically CVEs or "zero-days".
10. No unattended high-risk mutation or public vulnerability publication without explicit scoped authority.
11. Offline-first Quick and stable legacy CLI/MCP compatibility precede deeper functionality.
12. Prefer mature proven SAST/SCA/fuzz/research/repair tools via versioned adapters before building new analyzer algorithms; native code requires a measured gap.
13. Engine availability, license, entitlement, privacy, platform and cost eligibility are mandatory preflight dimensions, never inferred from marketing or model text.
14. A tool's successful run is not automatically completed assessment; execution, coverage and confirmation are distinct evidence classes.

## Unresolved but non-blocking choices

| ID | Question | Decision point | Default until resolved |
|---|---|---|---|
| O-01 | Which exact Tree-sitter grammar crates and versions per language? | M2 spike | Pin each grammar with test matrix |
| O-02 | ast-grep Rust API vs CLI subprocess? | M2 benchmark | Rust API where mature, CLI adapter fallback |
| O-03 | Joern container or JVM binary process? | M4 spike | Isolated process with network disabled |
| O-04 | Which graph/context retrieval tool adds measurable value? | M4 optional evaluation | Do not bundle any |
| O-05 | Specific CodeQL licensed use cases? | Before shipping adapter | Disabled |
| O-06 | Benchmark suite selection and benchmark targets? | After M1 baseline | No artificial accuracy claims |
| O-07 | How to store audit artifacts on Windows/macOS/Linux? | M0/M1 design | Project-relative secure local store, no hidden global mutation |
| O-08 | Default feed refresh cadence and cache TTL? | M3 tests | Offline-safe and user-configurable |
| O-09 | Supported dependency ecosystem priority? | M3 inventory | Start where existing OsvClient already parses reliably |
| O-10 | Runtime deep target consent UI? | M4/M5 | Disabled by default |
| O-11 | Research model provider or local LLM? | M5 privacy/quality tests | No LLM requirement; model opt-in |
| O-12 | Report recipient/authentication transport? | M6 | Draft locally only |
| O-13 | Pricing/distribution of proprietary optional engines? | Release/legal review | External adapter only |
| O-14 | Which first two independent local external analyzers prove real composed value? | M1.4 benchmark and license review | Evaluate Semgrep CE/Trivy; no automatic bundled engines |
| O-15 | Which external fuzzers and specialized research workflows work for which target families? | M5 spike | Language-native fuzzers first; no universal research engine assumption |
| O-16 | User-facing agentic room: terminal-first or optional local UI? | M1.3 persona usability test | CLI/MCP/CI remain authoritative; dashboard optional |
| O-17 | How to identify tools sharing rule/feed/model lineage? | M1.4 fixtures | Treat unknown independence as **not independent** |
| O-18 | Which commercial tools expose consented APIs and allowable data transfer? | Adapter-specific legal/privacy review | No integration or source upload by default |

## Risk register

| Risk | Likelihood/impact | Control and owner |
|---|---|---|
| False assurance: no findings reported as safe | High/high | Mandatory coverage receipts and policy gates; core security owner |
| Automatic repair deletes/corrupts user data | Medium/critical | Signed plan+operator grant, atomic backup, drift test, rollback; healer owner |
| Prompt injection or malicious workspace rule | High/high | Untrusted data boundary, signed rule provenance, typed tool protocol; policy owner |
| Sandbox escape or harmful research side effect | Low/critical | Ephemeral containment, no network, quotas, no privileged host; research owner |
| Licensing breach by bundling CodeQL/Semgrep | Medium/high | Separate adapters, license audit and release gate; legal/release owner |
| Slow pre-commit due heavy engine | High/medium | Quick minimal Rust only, warm cache, opt-in Deep; performance owner |
| Missing transitive dependency creates false negative | High/high | SBOM/crawler completeness and explicit `INCONCLUSIVE`; inventory owner |
| Hypothesis falsely disclosed as new CVE | Medium/high | Independent proof, dedup, private disclosure approval; research owner |
| AST grammar mismatch gives wrong lines | Medium/medium | Grammar pinning, Unicode/source map fixtures; AST owner |
| Incorrect dataflow edge treated as confirmed | High/high | Evidence class caps and extracted-vs-inferred provenance; deep analysis owner |
| External feed poisoned or stale | Medium/high | Trusted providers, digests, cache TTL and no executable feed content; advisory owner |
| Schema change breaks agents or existing CLI | Medium/high | Versioned envelopes, compatibility adapters and golden tests; integration owner |
| Unavailable/unlicensed engine is silently reported as clean | High/high | Capability preflight, mandatory policy and host execution/coverage receipts; orchestration owner |
| Agent chooses inappropriate tool or self-approves costly plan | High/high | Deterministic suitability, signed operator grants and enforced budgets; policy owner |
| External tool or vendor exfiltrates private source / vulnerability proof | Medium/critical | Deny network by default; data-sharing approval, scoped credentials, redaction and isolation; privacy owner |
| Shared scanner database or duplicated rule inflates certainty | High/high | Provenance lineage, de-duplication and independent revalidation; evidence owner |
| Over-engineering duplicates mature scanners and delays useful product | High/medium | Build-vs-orchestrate decision record, comparative benchmark and adapter-first gates; architecture owner |

## Stop conditions

- Any failure of auth, scope validation, signature or isolation while attempting privileged mutation.
- Unavailable mandatory parser/advisory/engine, with no way to report partiality honestly.
- Undisclosed legal restriction on redistribution or use.
- New research plan requiring third-party live system access without specific owner permission.
- A test suite passes while the required negative control demonstrably fails to detect the underlying bug.
- An agent proposes silently publishing a private proof or treating advisory text as executable instructions.
- A required engine lacks verified license/entitlement/health, or the selected external service would export data outside an approved boundary.
- The plan requires more cost, time or privileged operations than the operator granted.

## Future improvements excluded from the initial program

- Native coverage-guided fuzzing as a universal built-in service for every language.
- Full formal verification of arbitrary business logic or distributed systems.
- Autonomous vendor vulnerability management without human involvement.
- SaaS multi-tenant processing of private code before privacy/threat review.
- Universal cross-language interprocedural analysis for every supported syntax.

## Completion decision

Only after M0–M6 acceptance is verified should public product descriptions claim the corresponding new capabilities. The phrase "373 rules supported" must always be accompanied by actual evaluated coverage and benchmark measurement.
