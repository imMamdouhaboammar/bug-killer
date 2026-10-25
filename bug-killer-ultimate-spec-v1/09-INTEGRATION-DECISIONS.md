# 09. External engine decisions, licensing and validation spikes

## Integration principle

**Use proven security engines as the primary execution arsenal; Bug Killer owns coordination, trust and evidence.** Embed small stable primitives only where appropriate; execute large or restricted engines behind versioned adapters. Never require every user to install all research dependencies. Prefer source and behavior evidence over popularity or badges. Use the engine acceptance process in [Section 14](14-AGENTIC-SECURITY-OPERATIONS-ROOM.md) before proposing a new native detector.

The following is based on upstream README and available root LICENSE files checked on 2026-10-25. It is not a complete legal audit of transitive dependencies or linked commercial services.

## Core engines

| Upstream | Role | Observed license | Packaging decision | Risk |
|---|---|---|---|---|
| [tree-sitter/tree-sitter](https://github.com/tree-sitter/tree-sitter) | Incremental CST/AST parser | MIT | Embed Rust bindings/pinned grammar packages | Grammar version drift, syntax failures |
| [ast-grep/ast-grep](https://github.com/ast-grep/ast-grep) | Structural search/rewrite | MIT | Embed suitable Rust API where practical; CLI adapter fallback | Not interprocedural proof |
| [joernio/joern](https://github.com/joernio/joern) | Code Property Graph, dataflow | Apache-2.0 | Optional isolated sidecar, pinned binary/container | JVM/runtime cost, language models/precision |
| [semgrep/semgrep](https://github.com/semgrep/semgrep) | Independent SAST and community rules | LGPL-2.1 | External CLI adapter; review redistribution terms and rule licenses | CE interfile restrictions, rule drift |
| [github/codeql](https://github.com/github/codeql) | Additional dataflow queries | Query/library repo MIT; **CLI engine licensed separately** | Optional external adapter enabled only when terms permit | Commercial/private repo eligibility |
| [babel/babel](https://github.com/babel/babel) | Rich JS/TS parser/transforms | MIT | Optional Node subprocess for JS/TS-specific cases | Node runtime, AST divergence, plugin drift |

Official docs:

- Tree-sitter: https://tree-sitter.github.io/tree-sitter/
- ast-grep: https://ast-grep.github.io/
- Joern: https://docs.joern.io/
- Semgrep CE: https://semgrep.dev/products/community-edition/
- CodeQL license: https://docs.github.com/en/code-security/concepts/code-scanning/codeql/codeql-cli
- Babel parser: https://babeljs.io/docs/babel-parser

## Supporting research tools

| Upstream | Observed license | Decision | Why |
|---|---|---|---|
| [probelabs/probe](https://github.com/probelabs/probe) | Apache-2.0 | Optional on-demand code context/retrieval adapter | Fast AST-aware search; no deep taint guarantee |
| [Graphify-Labs/graphify](https://github.com/Graphify-Labs/graphify) | Apache-2.0 | Research spike only | Cross-file extracted/inferred relation graph, inferred edges not proofs |
| [vitali87/code-graph-rag](https://github.com/vitali87/code-graph-rag) | MIT | Research spike only | Graph/query, compiler frontends and trace overlays; Python runtime overhead |
| [cocoindex-io/cocoindex-code](https://github.com/cocoindex-io/cocoindex-code) | Apache-2.0 | Optional developer context provider | Semantic search/indexing, overlaps retrieval tools |
| [oimiragieo/tensor-grep](https://github.com/oimiragieo/tensor-grep) | Apache-2.0 | Comparator to Probe, not mandatory | Context search and structural patterns, similar value area |
| [imohitseth/AST-Healer](https://github.com/imohitseth/AST-Healer) | MIT | Reference workflow only | Python exception repair loop, not security verification engine |
| [consolascionw/prompt-to-pattern-design](https://github.com/consolascionw/prompt-to-pattern-design) | No root LICENSE verified | Do not vendor; conceptual reference only | Intent/outline consistency is different from code AST/taint |

Observed upstream claims are used as starting hypotheses; independently measure performance, output fidelity and security before production adoption.

## Additional mature engine and research candidates

These are **integration evaluations**, not installed adapters. Reference links and roles are inventoried in Section 14; exact compatible versions, licenses, entitlements and maintenance state must be checked at the moment of adoption.

| Candidate | Proposed capability | Decision gate |
|---|---|---|
| Trivy | Dependency/container/IaC/SBOM assessments | Compare with current OSV path, pin database and CLI version, measure distinct value |
| OSV-Scanner | Dependency evidence and inventory comparison | Avoid duplicating existing OSV fetches without evidence gain |
| AFL++ / libFuzzer / language-native fuzzers | Harness-specific vulnerability research | Existing executables, safe target/harness and bounded reproducible proof required |
| OSS-Fuzz / ClusterFuzzLite | External fuzzing infrastructure and CI patterns | Infrastructure/eligibility evaluation; not assumed to be a local engine |
| Buttercup / Team Atlanta Atlantis / FuzzingBrain | AI-assisted specialist discovery and repair research | Experimental only; confirm licenses, target constraints, runtime, model/data costs and defense boundaries |
| Big Sleep | AI-discovery research reference | **Not offered as an assumed installable/public-API integration** |
| XBOW | Commercial agentic security testing comparator | Entitlement/API/authorization/privacy feasibility must be verified before adding an adapter |

**Integration hazards verified from upstream documentation:** Buttercup's repository is AGPL-3.0, while Atlantis' root repository states MIT; neither observation substitutes for a complete dependency/image and use-case license review. FuzzingBrain's example workflow mounts the host Docker socket and requires API credentials, so **its documented Docker command must never be copied into an unprivileged Bug Killer job**. A secure nested-runtime alternative would need separate design, permission and escape tests. OSS-Fuzz is a hosted continuous fuzzing program for eligible open-source projects; private/unqualified projects require separately managed infrastructure (such as ClusterFuzz/ClusterFuzzLite) and cannot be silently submitted to OSS-Fuzz. References: [Buttercup](https://github.com/trailofbits/buttercup), [Atlantis](https://github.com/Team-Atlanta/aixcc-afc-atlantis), [FuzzingBrain](https://github.com/o2lab/afc-crs-all-you-need-is-a-fuzzing-brain), [OSS-Fuzz FAQ](https://github.com/google/oss-fuzz/blob/master/docs/faq.md).

Classify every candidate as `SELECTED`, `PILOT`, `REFERENCE_ONLY`, `DECLINED` or `BLOCKED` **with dated validation evidence**. Selection changes require an explicit decision record, not a silent replacement.

## Engine adapter ABI (PROPOSED)

The JSON below is a **legacy illustrative shape**, not the authoritative capability registry contract. New adapters must also implement `schemas/tool-capability.schema.json` and produce host-issued `schemas/tool-execution-receipt.schema.json` records. Advertised metadata cannot bypass health, entitlement, license or policy preflight.

```json
{
  "adapter_version": "1.0",
  "engine": {
    "id": "joern",
    "version": "<pinned>",
    "binary_sha256": "<digest>"
  },
  "capabilities": {
    "languages": ["c", "cpp", "javascript", "python"],
    "features": ["cpg", "dataflow"],
    "evidence_max": "STRONGLY_SUPPORTED"
  },
  "requirements": {
    "runtime": "jvm",
    "network": false,
    "privileges": ["workspace:read"]
  },
  "resource_limits": {
    "memory_mb": 4096,
    "timeout_seconds": 600
  }
}
```

This is an illustrative example; values must be measured/declared by a real adapter, not assumed. The sidecar receives a manifest with content-addressed workspace snapshot and emits validated JSON/SARIF, not an LLM narrative.

## Integration spike protocol

For each core engine integration:

1. Pin exact upstream release, checksum, license, supported target platform and grammar/dataflow version.
2. Build/test offline with representative Rust, JS/TS, Python, Go and PHP snippets as appropriate.
3. Prove parser and engine errors yield `PARTIAL/ERROR` receipts and fail correctly.
4. Evaluate precision and recall on labelled safe/unsafe fixtures, plus an intentionally missing-grammar case.
5. Benchmark cold startup, warm incremental rerun, memory peak, wall time, output bytes and cancellation.
6. Verify source hashes and file spans survive SARIF/JSON normalization without truncating flows.
7. Test untrusted code/comments cannot execute commands, set config or escape sandbox through the adapter.
8. Verify deployment on macOS Apple Silicon, Linux amd64/arm64 and Windows where claimed.
9. Demonstrate availability, incompatible platform, missing/unlicensed tool, false capability declaration, API quota exhaustion and denial of unauthorized source upload.
10. Correlate findings from two deliberately overlapping tools without counting shared rules as independent proof; preserve conflicting conclusions and original IDs.
11. Verify a timed-out engine still produces a host-issued execution receipt, and mandatory-tool absence blocks CI instead of falling back silently.

### Keep/remove criteria

An adapter is accepted only if it adds a measured detection capability or significant developer value absent from the already-selected stack. Two overlapping search engines are not both bundled absent clear benchmark benefit. Decline engines that materially degrade Quick path latency, require cloud login, cannot run within policy, have unacceptable license terms or cannot provide truthful coverage receipts.

## Default build matrix

- `minimal`: Rust core + Tree-sitter/ast-grep modules only (offline-first).
- `standard`: minimal + OSV connectivity (explicit network policy) + healer.
- `deep`: standard + discovered Semgrep/Joern adapters; installed separately.
- `research`: deep + sandbox/fuzz runners and optional context tools.
- `codeql`: manually enabled only with documented license eligibility.

No machine downloads an untrusted analyzer based solely on repository-provided config.
