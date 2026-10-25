# 13. Decision log, risks, assumptions and open questions

## Decisions locked for this specification

1. Three product engines share evidence, policy and repair components.
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

## Stop conditions

- Any failure of auth, scope validation, signature or isolation while attempting privileged mutation.
- Unavailable mandatory parser/advisory/engine, with no way to report partiality honestly.
- Undisclosed legal restriction on redistribution or use.
- New research plan requiring third-party live system access without specific owner permission.
- A test suite passes while the required negative control demonstrably fails to detect the underlying bug.
- An agent proposes silently publishing a private proof or treating advisory text as executable instructions.

## Future improvements excluded from the initial program

- Native coverage-guided fuzzing as a universal built-in service for every language.
- Full formal verification of arbitrary business logic or distributed systems.
- Autonomous vendor vulnerability management without human involvement.
- SaaS multi-tenant processing of private code before privacy/threat review.
- Universal cross-language interprocedural analysis for every supported syntax.

## Completion decision

Only after M0–M6 acceptance is verified should public product descriptions claim the corresponding new capabilities. The phrase "373 rules supported" must always be accompanied by actual evaluated coverage and benchmark measurement.
