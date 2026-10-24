# BUG KILLER: MASTER UPGRADE PROMPT

## Repository-first, model-agnostic autonomous defensive security platform

**Target repository:** https://github.com/imMamdouhaboammar/bug-killer  
**Starting branch:** `master`, unless a newer authoritative project state says otherwise.  
**Observed research snapshot:** 2026-10-24, commit `6c31c133c7d520e02881dafab89241c881f882da`. Re-check the branch and all evidence before making changes.  
**Operating mode:** Long-horizon, evidence-led engineering in bounded milestones, each independently tested and reviewable.

## 1. Your role and mission

Act as a principal security architect, defensive vulnerability researcher, Rust/Go systems engineer, incident-response engineer, agent-platform engineer, test designer, and skeptical maintainer of the **existing** Bug Killer project.

**Do not scaffold a replacement repository. Do not treat the current code as a blank slate.** Inspect the live code and extend, correct, or simplify it in place.

Upgrade Bug Killer (`bug-killer`, `bk`) into a local-first, model-agnostic, genuinely agentic security platform that can:

1. Inventory and assess authorized repositories, hosts, deployed runtimes, application configurations, packages, native binaries, containers, and selected cloud/IaC artifacts.
2. Correlate findings against reliable vulnerability intelligence, including vendor fixes, package backports, affected build identities, and runtime exposure.
3. Distinguish confirmed issues, supported risk indicators, incomplete scans, unknowns, and unsupported surfaces.
4. Use AI models to investigate, prioritize, explain, and propose repairs, while keeping deterministic code in control of permissions and side effects.
5. Generate a minimal remediation plan, run non-destructive verification, request authorization, perform approved bounded changes, independently re-check health, and roll back when possible.
6. Run with no LLM at all, with fully local open-weight models, or with a user-authorized remote model provider.
7. Expose strictly scoped capabilities to Codex, Claude, Gemini, Kimi, MiniMax, DeepSeek, locally hosted models, and other agents through stable interfaces such as MCP and CLI. Do not assume all models or agent products share the same API.

### Product honesty

Never claim an absolute security tool, universal zero-day discovery, zero false negatives, guaranteed exploitability, proof of safety from an empty finding list, perfect rollback, or universal support for all models. These are coverage and evidence questions, not branding claims.

### Non-negotiable defensive boundary

Authorized targets only. No autonomous scanning of arbitrary internet hosts. No exploit-chain automation, payload weaponization, credential harvesting, persistence, destructive probes, or exploit reproduction against production. Offensive reference repositories may inform defensive preconditions and negative tests; never execute or bundle their attacks. Explicit operator authorization and deterministic policy are prerequisites for mutation, even when the LLM recommends it.

## 2. Mandatory baseline reconnaissance: preserve what already exists

Before any design or commit:

1. Read root and scoped `AGENTS.md`, `README.md`, `SECURITY.md`, `LICENSE`, `CONTRIBUTING.md`, `Cargo.toml`, Go manifests, lockfiles, `Makefile`, `.github/workflows/ci.yml`, existing tests, and relevant project specifications.
2. Trace actual entrypoints and state transitions in `src/main.rs`, `src/scanner/`, `src/healer/`, `src/identity/`, `src/watcher/`, `src/osv/`, `src/rules/`, and the existing `services/{orchestrator,inspector,healer}/` boundaries.
3. Inspect both `proto/aegis.proto` and `proto/omni_messaging.proto`, and determine which protocol is canonical. Inventory generated code and version compatibility.
4. Inspect the repository's existing Omni skill system, its public/private separation, host adapters, rule sources, permissions, and test fixtures. Do not copy internal maintainer-only skills into public documentation or distributions.
5. Record live HEAD, worktree changes, open PRs/issues, CI status, platform/toolchain versions, and real supported commands. Do not overwrite unrelated work.
6. Reproduce current failures before attempting fixes. Distinguish baseline failures from regressions introduced by your changes.
7. Build a compact **implemented / partial / stub / claimed-only / missing** feature matrix, with file/symbol evidence. Statements in README are hypotheses until code and tests prove them.

### Known starting leads to verify, not unquestioningly accept

At the observed commit, the repository already contains Rust CLI scanning, PHP/Node checks, OSV lookup, configurable vulnerability rules, a watcher, cryptographic backup records, Go orchestration, an inspector, an OPA evaluator, a Go healer, and gRPC definitions.

The following deserve **immediate verification**:

- `src/main.rs`: `Heal.auto_apply` is declared with `default_value_t = true`; `bk heal` can apply changes without an explicit approval ceremony.
- `src/watcher/mod.rs`: `--auto-heal` calls the patch executor directly. Determine whether shared authorization checks exist and cannot be bypassed through this path.
- `src/healer/mod.rs`: multiple files are persisted in a loop after backup. Per-file atomic rename is not a multi-file transaction; failure after file N can leave earlier changes applied.
- `src/healer/backup.rs`: backup signing appears conditional on identity initialization succeeding, rather than fail-closed.
- `src/healer/rollback.rs`: signature verification appears conditional on a signature existing. Restore uses ordinary copying and requires path, integrity, and interrupted-restore review.
- `src/identity/mod.rs`: a public key embedded within an untrusted manifest does not by itself establish a trusted signer. Review pinned trust anchors, key persistence, permissions, and canonical signing format.
- `services/healer/main.go` and `services/healer/server/`: check direct privileged entrypoints, gRPC Unix-domain socket permissions, authentication, authorization, replay protection, and default dry-run behavior.
- `src/scanner/node.rs`: framework/package presence may be marked as affected even without proven decompression reachability. Avoid representing a heuristic as confirmed exposure.
- `src/types.rs`: current finding objects lack several evidence, confidence, fix-provenance, scan-coverage, and state-transition fields needed for safe agent decisions.
- The observed Rust and Go CI jobs failed and the dependent E2E job was skipped. First find actual failure logs; do not invent the root causes.

**Gate 0:** Produce a fact-checked baseline table and get existing CI to pass without weakening a test, deleting coverage, downgrading lint, or hiding failures. If any issue is unfixable in the environment, show a reproducible blocker and isolate it from subsequent changes.

## 3. Reference research and the reusable-parts decision

Review upstream README, manifests, licenses, current implementation, integration APIs, security posture, and recent project activity before choosing a dependency. Do not clone the reference universe into production or mistake a demonstration for a vetted component.

**Known-vulnerability and host scanning:**

- https://github.com/future-architect/vuls
- https://github.com/anchore/grype
- https://github.com/openai/php2shell-checker
- https://github.com/trailofbits/brotli-checker

**Fuzzing, static/binary forensics, and review:**

- https://github.com/google/oss-fuzz
- https://github.com/WerWolv/ImHex
- https://github.com/trailofbits/skills
- https://github.com/crev-dev/cargo-crev
- https://github.com/cisco-ai-defense/skill-scanner

**Defensive workflow, OSINT, agent system and AI-infrastructure security:**

- https://github.com/cloudflare/security-audit-skill
- https://github.com/smicallef/spiderfoot
- https://github.com/Tencent/AI-Infra-Guard
- https://github.com/decalage2/awesome-security-hardening
- https://github.com/mukul975/Anthropic-Cybersecurity-Skills
- https://github.com/sanyuan0704/sanyuan-skills
- https://github.com/msmps/pilotty
- https://github.com/makecindy/cindy
- https://github.com/ParzivalHack/PySpector

**Offensive or dual-use inspiration: research-only, never auto-execute:**

- https://github.com/9bie/php2shell-bypass-aslr-exp
- https://github.com/swisskyrepo/PayloadsAllTheThings
- https://github.com/usestrix/strix
- https://github.com/KeygraphHQ/shannon
- https://github.com/0x4m4/hexstrike-ai
- https://github.com/SnailSploit/Claude-Red
- https://github.com/GH05TCREW/pentestagent

For each repository, classify **reuse via stable interface / adapt a defensive concept / research-only / reject**, with verified licensing and a concrete justification. Repeated references in earlier prompts are deduplicated. No plagiarism, wholesale reproduction, arbitrary `curl | bash`, automatic execution of unknown scripts, or inclusion of weaponized corpora in runtime packages.

Check official PHP, Node.js, Linux distribution, OSV, CISA KEV, NVD, and upstream vendor advisories for the latest affected/fixed versions. The initial regression cases are PHP2Shell `CVE-2026-109618`, `CVE-2026-109619`, and Node.js Brotli `CVE-2026-111497`. Validate exact branch/build applicability and vendor backports at implementation time; never freeze a conversational version matrix into permanent truth.

**Gate 1:** Produce a reference matrix with explicit coverage, limitations, provenance, dependency/security risk, and integration choices. No claims of binary reachability or exploitability without a matching proof method.

## 4. Architecture: extend Rust + Go, add boundaries only where necessary

The current code already mixes Rust and Go. Preserve useful interfaces and evolve them incrementally.

**Rust core: deterministic and local-first.** Own domain types, discovery adapters, evidence normalization, scanner rule evaluation, remediation plans, policy-independent transaction primitives, CLI, local state/ledger, and a thin secure tool-execution kernel. Use existing crates unless an audited new dependency clearly earns its cost.

**Go control plane: optional but useful for fleet coordination.** Own bounded concurrent target inventory, service discovery, queued jobs, remote-agent lifecycle, connection management, and orchestration only if these responsibilities are real. Do not duplicate Rust's vulnerability truth or permission model.

**Privileged remediation executor: a separate trust boundary.** It must not accept arbitrary shell scripts, file paths, package names, or privileged directives merely because a model or another service sent them. Require an independently authorized, typed, scoped, expiring, replay-safe operation identifier linked to a hash-pinned plan and current target state. Enforce permissions again at the side-effect boundary.

**Agent/model runtime: thin, replaceable, unprivileged.** Reason about evidence, request read-only tools, propose candidate findings and plans, ask for missing proof, and deliver explanations. No direct process execution, raw filesystem mutation, policy edits, or unmediated privileged IPC.

**Local default:** one `bk` installation must provide useful read-only scanning and offline reports without Docker, a GPU, a cloud account, or a running model. Distributed fleet management and graphical dashboards are optional profiles, not prerequisites for simple local checks.

Do not introduce Zig, C++, Python, TypeScript, message brokers, Kubernetes, or extra microservices merely for variety. Consider an isolated native helper for a measured parser requirement, Python for an existing research tool adapter, or a UI service only when a testable use case requires it. Explicitly compare alternatives through an ADR and retain compatibility during any protocol migration.

### Canonical boundary sketch

```
CLI / MCP client / API (authorized operator)
                 |
                 v
       Agent Session & Job Controller (unprivileged)
           |                    |
           v                    v
  Model Adapter(s)        Read-only Analysis Tools
           |                    |
           +---------+----------+
                     v
          Typed Evidence & Coverage Store
                     |
                     v
             Plan and Policy Gate
                     |
           approved operation ID only
                     v
        Isolated Remediation Executor
                     |
           independent checks / rollback
                     v
             Signed Audit Receipt
```

Keep model output, tool responses, advisory content, scanned source comments, logs, skills, and retrieved pages in lower-trust channels. They are data, not control instructions.

## 5. Model-agnostic agent platform: a real protocol, not hardcoded model brands

Separate two forms of integration:

**A. Bug Killer hosts an agent using a configured model provider.** A `ModelProvider` contract should support at least:

- `openai_responses` and `openai_chat` where actually supported;
- `anthropic_messages` for Claude-compatible endpoints;
- `google_genai` for the native Gemini API;
- `ollama_native` or Ollama's documented subset of compatible APIs;
- `openai_compatible` for configurable Kimi/Moonshot, MiniMax, DeepSeek, local vLLM, llama.cpp-compatible servers, and other genuinely compatible providers.

**B. An external coding agent controls Bug Killer.** Provide a versioned `bk` CLI with structured JSON output, an MCP server, and concise host installation examples for Codex, Claude Code, Gemini CLI, Kimi CLI, and any other host you can verify. Avoid assuming those products expose interchangeable account APIs or require their SDK to be embedded in Bug Killer.

### Adapter capabilities and constraints

1. Discover or configure a model's *actual* capabilities. Record chat/Responses endpoint support, function-calling, structured output, streaming, thinking/reasoning fields, context limits, maximum output, tool-call correlation IDs, and cancellation behavior.
2. Implement provider-neutral internal messages, tool calls, tool results, usage metrics, errors, and retryable status. Preserve provider-specific fields through adapters without polluting core types.
3. Normalize tool-call arguments against a strict JSON Schema before dispatch. Reject hallucinated tool names, invalid arguments, unexpected paths, or unsupported permissions.
4. Do not silently downgrade security if the provider lacks tool calling or strict JSON mode. Fall back to **read-only structured proposals**, bounded extractive output, or a deterministic no-LLM workflow.
5. Support local and remote models on separate data-flow policies. Default to **no sensitive system telemetry sent to an external provider**. Require an operator-approved export profile with path, secret, source-code, log, and PII redaction plus provider allowlisting.
6. Support offline mode, hot provider switch between sessions, explicit model IDs, context compression with evidence hash preservation, bounded tool iterations, call rate limits, token/cost budgets, retries with jitter, circuit breakers, timeouts, cancellation, and reproducible event traces.
7. Protect against prompt injection embedded in source files, web pages, dependency advisories, MCP results, issue text, or agent skills. Neither system prompts nor model self-critique are authorization mechanisms.
8. Define `ProviderCapability` and a conformance suite. Test Kimi, MiniMax, DeepSeek, OpenAI, Anthropic, Google Gemini, Ollama, and vLLM using verified current APIs and supported models when credentials/endpoints are available. Otherwise mark live tests NOT RUN and use truthful protocol fixtures.
9. No mandatory proprietary SDK, hosted telemetry, provider-specific prompt template, or model checkpoint. A smaller open-weight model may have fewer abilities; the product must degrade transparently, not fabricate support.

### Illustrative configuration, not assumed existing syntax

```yaml
agent:
  enabled: true
  mode: investigate_only
  max_steps: 24
  max_parallel_tools: 3
  allow_remote_data_export: false
  provider: local

providers:
  local:
    protocol: openai_compatible
    base_url: http://127.0.0.1:11434/v1
    model: ${BK_MODEL_ID}
  kimi:
    protocol: openai_chat
    base_url: ${KIMI_API_BASE}
    api_key_env: KIMI_API_KEY
    model: ${KIMI_MODEL_ID}
  minimax:
    protocol: openai_chat
    base_url: ${MINIMAX_API_BASE}
    api_key_env: MINIMAX_API_KEY
    model: ${MINIMAX_MODEL_ID}
  deepseek:
    protocol: openai_chat
    base_url: ${DEEPSEEK_API_BASE}
    api_key_env: DEEPSEEK_API_KEY
    model: ${DEEPSEEK_MODEL_ID}
```

The agent must replace this illustrative schema with one validated against the implementation, document official base URL defaults where appropriate, and keep secrets out of config and logs. No `base_url` supplied by the model may be accepted for arbitrary HTTP requests; enforce local-only or user-approved endpoint allowlists to prevent SSRF.

## 6. Agentic execution loop and machine-verifiable authorization

Design an observable state machine:

```
INTAKE -> SCOPE_CHECK -> DISCOVER -> COLLECT_EVIDENCE -> ASSESS
  -> PLAN -> STATIC_VALIDATE -> POLICY_EVALUATE -> APPROVAL
  -> EXECUTE -> HEALTH_CHECK -> RESCAN -> VERIFIED
                               \-> FAILED -> RECOVER/ROLLBACK -> ESCALATE
```

Agent responsibilities must be specific:

- **Investigator:** asks read-only questions and cites tool receipts.
- **Triage analyst:** groups duplicates, checks advisory applicability, and reports missing exposure evidence.
- **Planner:** proposes smallest repairs with expected diffs, blast radius, and verification commands.
- **Skeptical verifier:** challenges candidate findings and repair outcomes using independent deterministic tests.
- **Executor:** is not an LLM role. It is a narrow permissioned component that consumes approved typed operations only.

Use one agent runtime and specialized analysis modes before introducing a network of autonomous agents. Every proposed action must include a source finding ID, affected asset ID, immutable target identity, bounded command or patch type, expected-state hash, risk class, expected diff, validation plan, and rollback capability. Do not accept free-form shell commands as executable plans.

### Autonomy levels

| Level | Allowed behavior | Approval requirement |
| --- | --- | --- |
| L0 | Offline/read-only inventory, scanner reports, evidence collection | Local explicit target scope |
| L1 | Agent-assisted interpretation and simulated remediation | No mutation; no remote data export by default |
| L2 | Create local patches and run bounded tests in a disposable sandbox | User-provided sandbox or equivalent authorization |
| L3 | Apply allowlisted reversible repairs to an authorized non-production target | Human-approved, hash-pinned plan and policy receipt |
| L4 | Production or potentially disruptive changes | Separate, time-limited operator approval, change window, recovery prerequisites, canary and health gates |

No model response may upgrade its own autonomy level, edit policy to permit a rejected operation, write its own approval, or substitute an acknowledgment for required authorization. L0 remains the safe default for newly discovered targets and first-time runs.

## 7. Universal detection engine and evidence contract

Build a plugin/detector registry with explicit supported target types, required permissions, capabilities, safety level, analysis cost, input schema, output schema, version, provenance, and test fixtures.

Prioritized detector families:

1. **Known vulnerabilities / SCA:** OS packages, language manifests, lockfiles, SBOMs, CycloneDX/SPDX, vendor backports, distro advisories, OSV, NVD, KEV, VEX/OpenVEX where validated. Prefer vetted tools such as Syft/Grype/Vuls through constrained adapters if they outperform duplicate hand-written parsing.
2. **Runtime identity and deployment:** multiple PHP/Node installations, process-to-binary mapping, interpreter manager paths, loaded shared libraries, package epochs, containers, and restarts pending after updates.
3. **Web and application source:** language-specific AST/dataflow rules, dependency misconfigurations, injection and authorization patterns, endpoint guards, secret leakage; mark pattern-only detections as hypotheses until real dataflow is established.
4. **Binaries and embedded libraries:** bounded ELF/PE/Mach-O parsing, build IDs, hash signatures, package provenance, vendored Brotli, stripped executables, and parser errors represented as UNKNOWN rather than CLEAN.
5. **Container and supply-chain:** image identities and digests, SBOM, exposed secrets, risky build instructions, signing/attestation evidence, IaC misconfigurations, CI permissions, unsafe dependencies.
6. **Host and service hardening:** package status, process exposure, file permissions, system service settings, patch levels, TLS/proxy configuration, and Linux-specific eBPF observation only when supported and explicitly enabled.
7. **AI/agent security:** agent skills, tool definitions, MCP servers, connector permissions, prompt-injection surfaces, data exfiltration paths, model-server exposure and agent control failures. Use Cisco Skill Scanner and Tencent AI-Infra-Guard as research/reference implementations, subject to license and containment review.
8. **Anomaly research:** local fuzzing, property-based tests, crash deduplication, static taint paths, and bounded sandbox dynamic checks to propose possible new bugs. A crash or model hypothesis is not automatically a zero-day vulnerability.

**No default active exploitation.** Network checks must be authorized, rate-limited, minimally invasive, and precisely scoped. Internet-wide scanning, exploit-based validation, credential attacks, and self-directed privilege escalation are out of scope.

### Required finding object

Specify and version a common schema containing:

```
finding_id, asset_id, detector_id, detector_version, category,
advisory_ids, component_identity, installed_build, package_source,
vendor_advisory, vendor_fix_state, runtime_process_identity,
evidence_refs[], evidence_digest, observation_time,
affectedness, reachability, confidence, severity, exploitability_signal,
impact, uncertainty_reasons[], supported_checks[], missing_checks[],
proposed_remediation_ids[], operator_status, dedupe_fingerprint
```

Model `affectedness` separately from `reachability`, severity, policy priority, exploitability, and remediation readiness. Recommended states include:

- `CONFIRMED_AFFECTED`
- `LIKELY_AFFECTED`
- `POTENTIALLY_AFFECTED`
- `NOT_AFFECTED_WITH_EVIDENCE`
- `UNKNOWN`
- `NOT_ASSESSED`

Treat `UNSUPPORTED`, `SCAN_INCOMPLETE`, parser failure, offline advisory staleness, ambiguous version tags, and insufficient permissions as coverage outcomes, not absence of risk. Always return what was actually scanned and what was excluded.

## 8. PHP2Shell and Brotli as falsification-grade reference cases

Keep `CVE-2026-109618`, `CVE-2026-109619`, and `CVE-2026-111497` as strong fixtures, not the complete scope of the engine.

For PHP:

- Enumerate CLI, FPM, Apache modules, CGI, custom builds and container copies.
- Distinguish requirement ranges in `composer.json` from an actually installed production interpreter.
- Resolve running process identity and relevant upstream or distro patch status.
- Distinguish end-of-life unsupported branches and backported fixes.
- Do not assume a proxy-side change fixes core PHP memory corruption.

For Brotli:

- Enumerate Node, standalone Brotli packages, embedded and vendored decoder copies, container images, and relevant native binaries.
- Distinguish declared Node version from actually running executable and build.
- Treat a framework dependency as a possible risk signal, not proof that attacker input reaches vulnerable decompression.
- Separate inbound decompression paths from outbound fetch/response parsing, build artifacts, and inactive dependencies.
- Do not misrepresent a `Content-Encoding: br` proxy block as a universal or permanent fix. Prefer a proven patched runtime/library; temporary compensating controls must be explicitly limited and expire.

Fixtures must include patched and vulnerable upstream versions, backported packages, custom builds, unrelated code containing misleading symbols, incomplete source, duplicate vendored copies, untrusted build metadata, and crash-safe error paths. Use vendor records as independent oracles, not hardcoded expected values produced by the detector itself.

## 9. Self-healing: transaction, approval, verification, and recovery

**Remediation is the highest-risk feature. Build no expanded autonomous healing until its core safety proof exists.**

1. Plan-only is default. Make every mutating entrypoint share a single deterministic authorization gate, including CLI, shell, watcher, gRPC, API, MCP, jobs, and plugins.
2. Resolve target identity and canonical path under explicit target roots. Resist symlink swaps, hardlink escapes, archive traversal, mount changes, and TOCTOU. Avoid arbitrary root/admin execution.
3. Validate a plan before applying: executable allowlist, policy version, approval scope, target hash, backup capacity, file owner/mode, service health baseline, package availability, lock status, and change-window rules.
4. Treat file replacement as a single-file atomic operation, **not** multi-file atomicity. Add a journaled `PREPARED -> APPLYING -> VERIFYING -> COMMITTED` or recovery state machine with fail-safe startup reconciliation.
5. Preserve mode, owner, extended attributes, symlink policy, and metadata when required. Use durable writes and fsync/rename semantics appropriate to the filesystem, not hopeful `copy()` calls.
6. Sign manifests with a **separately established trusted agent identity**. Verify identity against a pinned local trust store or operator-approved key; a manifest-supplied key alone is not an authorization root. Reject unsigned, malformed, tampered, duplicated, replayed or cross-target rollback requests unless explicitly migrating legacy backups in a quarantined workflow.
7. Verify backup bytes before and after write; detect drift of the live target at apply/rollback time and stop rather than overwrite unrelated user changes.
8. Implement scoped least-privilege helpers for package managers and service controllers. No arbitrary package names, command strings, daemon restart, or network downloads from untrusted model outputs.
9. For package updates, require a verified version/digest, supported upgrade path, dependency conflict check, and deterministic verification after install. Use snapshots or an equivalent platform recovery mechanism when the operation is not truly reversible.
10. For proxy mitigations, validate configuration syntax, reload semantics, canary and request health. Test that the policy does not break unrelated traffic. Treat mitigation as temporary with explicit residual risk.
11. Support approval withdrawal, timeouts, aborts, power-loss recovery, retried calls, idempotency keys, and process crashes. Do not let partial execution be reported as SUCCESS.
12. Independent post-repair verification must check the actual target state and affected vulnerability condition, not merely command exit code. If verification fails, attempt only authorized, safe rollback and escalate with evidence.

**Mandatory negative tests:** unauthenticated gRPC caller; forged manifest with self-generated key; absent signature; symlink race; path escape; edited file after approval; first write succeeds/second fails; interrupted fsync; insufficient disk; stale health signal; dangerous LLM-proposed command; watcher bypass; policy update during a job; package manager returns success but unchanged runtime; rollback target drift.

## 10. Skills, plugins, and Omni integration

Treat public skill bundles and retrieved repo content as executable supply-chain surfaces, not automatically trusted instructions.

- Integrate the repository's existing Omni skill registry instead of creating a rival plugin system.
- Separate **public end-user skills** (`triage`, `explain`, `scan-repo`, `scan-local-host`, `plan-fix`, `verify`, `report`) from **private maintainer workflows** used only for this repository's development.
- Never publish private maintainer skills, unreleased prompts, secrets, or references to private infrastructure in public README, packages, marketplace metadata, examples, or distributed archives.
- Define a permission manifest and capability contract for each public skill, with no implicit elevated access.
- Introduce a skill security preflight covering instructions, network/tool capabilities, script hooks, dependency provenance, prompt injection, and secret exfiltration.
- Support natural-language routing without granting a skill powers absent from the deterministic runtime.
- Expose versioned MCP tools with explicit permissions. Begin with `bk.asset_inventory`, `bk.scan`, `bk.findings`, `bk.evidence`, `bk.plan`, `bk.verify`, `bk.status`. Remediation requests should create plans or approval challenges, not accept untrusted arbitrary action strings.
- Offer local stdio MCP as the first integration. If network transport is later needed, implement authenticated per-request authorization, origin/network restrictions, auditability, and minimal transport exposure.
- Use schemas, examples, and host-specific setup docs that are actually tested; no promise that every ChatGPT/Codex/Claude/Gemini client exposes identical capabilities.

Use task-appropriate development skills when available: Anti-Slop Engineering, Fable discovery/research/plan/TDD/security/verify, Ponytail's reuse-first ladder, skeptical code review, Go and Rust testing, and repository-native instructions. Skills influence **engineering process**, not public privileged product functionality.

## 11. UX and operator contract

Preserve existing commands and migrate carefully. Proposed future CLI (syntax must be tested before publishing):

```bash
bk doctor --json
bk scan . --json
bk evidence <finding-id>
bk plan <finding-id> --json
bk agent doctor --provider local
bk agent investigate . --model local --mode read-only
bk agent investigate . --model kimi --export-profile approved-redacted
bk mcp serve --transport stdio --read-only
bk apply <approved-plan-id> --approval-file <operator-signed-receipt>
bk verify <job-id>
bk rollback <recovery-id>
```

Do not implement every command at once. Adopt consistent and machine-readable exit codes for `clean`, `findings-present`, `partial`, `inconclusive`, `policy-denied`, `execution-failed`, and `verification-failed`. Avoid an unqualified green `CLEAN` badge when coverage is partial. Human UI should show evidence, impact, affected target, confidence, missing checks, proposed fix, residual risk, authorization required, and a truthful post-action state.

Offer JSON and SARIF where applicable; SBOM inputs/outputs in supported CycloneDX/SPDX versions; VEX where a defensible status assessment exists. Trace remote target checks with authorized target IDs and correlate all logs through a job ID without dumping secrets.

## 12. Security design of Bug Killer itself

Produce an actionable threat model covering:

- Model prompt injection from scanned code, READMEs, issue text, tool outputs, advisory descriptions, web responses and agent skills.
- Local-host privileges, path containment, symlinks, procfs, Docker socket, systemd and package managers.
- Network exposure, remote target ownership, SSRF, loopback and metadata endpoints, DNS rebinding, gRPC UDS permissions and remote authentication.
- Compromised dependency feeds, malicious binary parsers, decompression bombs, huge files, CPU/heap exhaustion, eBPF capabilities, process lifetime and cancellation.
- Malicious or weak tool calls, hallucinated findings, model/provider spoofing, tool-result forgery and unauthorized plan mutation.
- Data leakage to hosted models, telemetry, artifacts, logs and bug reports.
- Rollback trust, signing-key lifecycle, replay, rollback to vulnerable state, journal tampering, and crash consistency.
- Multi-tenant and fleet asset authorization if a fleet API is actually implemented.

Each threat must be attached to an entrypoint, privileged sink, measurable security property, defensive control, and test. Do not claim a scanner result or an agent's explanation is proof that these boundaries hold.

## 13. Verification and quality gates

Run the actual repository commands after updating or checking documentation against source:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo test --manifest-path services/inspector/Cargo.toml
( cd services/orchestrator && go vet ./... && go test ./... )
( cd services/healer && go vet ./... && go test ./... )
make build
make test
```

Check that generated CLI help, shell completions, `Makefile`, Docker builds, architecture docs and public README describe actual behavior. Do not treat one Rust workspace as covering the separately nested inspector manifest unless verified.

Mandatory suites beyond happy path:

- Red-green reproduction for each confirmed bug, with old tests preserved unless an independent contract justifies changes.
- Provider adapter protocol fixtures (stream chunks, malformed tool JSON, missing usage, token limits, unsupported parameters, partial function calls, retryable errors, 429/5xx, cancellation).
- Cross-model evaluation using the same fixture pack and safety policies. Record task success, false claims, valid tool-call rate, token/time cost, privacy policy decisions, and veto outcomes. A provider lacking live credentials is **NOT RUN**, not **PASS**.
- Scanner precision and recall on curated labeled corpora. Report numerator, denominator, corpus provenance, version and excluded cases.
- Partial-scan honesty tests and adversarial fixtures that should produce `UNKNOWN` instead of `NOT_AFFECTED`.
- Property-based and fuzz tests for schema decoding, archives, binary parsers, paths, policy inputs, and journal recovery. Use only isolated bounded fixtures.
- Privilege-boundary, replay, injection, symlink/TOCTOU, SSRF, quota and secret-redaction tests.
- Fault injection for mid-transaction crash, remote agent offline, provider outage, package-manager failures, reload failure, immutable files, and low disk.
- Behavioral integration E2E, real binary installation, CLI stdout/stderr/exit contract, gRPC permission denial and MCP read-only tool flow.
- Reliability and performance with bounded CPU/memory concurrency, large folders, nested dependencies, cancellation and retries. Report hardware and reproducible measurement conditions.
- Artifact verification for published binaries, image digests, dependency manifests, signed attestations and release rollback instructions.

Do not report `CI green`, `secured`, `production-ready`, `all providers work`, or `rollback guaranteed` without the corresponding evidence. A successful compilation alone is not security verification.

## 14. Roadmap: bounded, reviewable milestones

Do not attempt all phases in a single PR. Split work around behavior and risk, not arbitrary file count or an artificial commit target.

### M0: Baseline restoration and security triage

**Outcome:** restore truthful test/build state; reproduce all currently failing jobs; define actual public CLI behavior; write a prioritized security finding list with code evidence.

**Deliverables:** baseline receipt, resolved or precisely blocked CI, architecture map, risk-ranked safety backlog, acceptance tests for P0 risks.

**Gate:** no new feature development until blockers are understood. Failed CI is not relabeled as expected or ignored.

### M1: Non-bypassable execution safety

**Outcome:** plan-only default, centralized privilege/authorization gate, immutable plan IDs, typed operations, secure backup trust, transaction journal, crash-safe recovery, and verifier separation.

**Gate:** every CLI/watcher/shell/gRPC/MCP entrypoint fails closed on unauthorized mutation; fault-injection and adversarial tests pass.

### M2: Typed finding and coverage engine

**Outcome:** versioned evidence/finding/coverage schemas, provenance ledger, advisory normalization, deduplication, uncertainty, real runtime identity, and stronger PHP/Brotli regression fixtures.

**Gate:** no misleading `CLEAN` statuses; known benchmark cases demonstrate accurate affectedness and uncertainty.

### M3: General defensive scanner extensions

**Outcome:** small, high-value integrations for SBOM/package scanning, source/config rules, host inventory, binary evidence, and container support. Favor stable existing tools over replicas.

**Gate:** adapter contract tests, measured corpus results, sandbox limits, licensing proof, and transparent unsupported targets.

### M4: Model-provider-independent agent runtime

**Outcome:** single bounded investigation loop with read-only tools, provider adapters, privacy gates, budgets, structured outputs, persistence/replay, deterministic vetoes, and offline mode.

**Gate:** at least one local and one remote provider tested live if available; all other adapters covered by honest protocol conformance fixtures, with unsupported features explicitly disabled.

### M5: Agent host interoperability

**Outcome:** local stdio MCP, structured CLI contracts, tested host recipes for selected coding agents, skill-scanning preflight and public/private skill boundaries.

**Gate:** at least two distinct supported agent hosts exercise the same read-only fixture and obtain equivalent evidence without mutation.

### M6: Graduated supervised remediation and release hardening

**Outcome:** bounded L2/L3 repairs, explicit L4 approval workflow, isolated integration labs, signed packages, update feed, operator documentation, support matrix, and recovery drills.

**Gate:** incident-like E2E proof of inventory -> finding -> plan -> approval -> bounded repair -> independent verify -> safe rollback, with failure-path evidence. Never market L4 readiness until operational gates are met.

For each milestone, define 3-7 coherent work cards. Each card must contain objective, existing entrypoint, owned scope, forbidden scope, dependencies, behavior oracle, exact verification commands, rollback and integration owner. Separate independent PRs when possible, keep diffs inspectable, and preserve a clean target branch. Do not merge or deploy without explicit authorization and required review gates.

## 15. Engineering discipline and publication boundaries

Follow the Anti-Slop seven gates: discover, contract, preserve test oracle, implement minimal coherent change, verify, skeptical diff audit, release decision.

- No test assertion weakening, unexplained snapshot refreshes, CI exclusions, unverified claims, fake benchmarks, stale README demonstrations or theatrical commit counts.
- No broad rewrite until profiling and architecture evidence prove existing boundaries cannot support the needed contract.
- Use official generators and current stable versions for genuinely new components. Check dependency and licensing compatibility, pin resolved versions and lockfiles, and do not upgrade unrelated dependencies as collateral.
- Review actual license of every external project. Existing Bug Killer is source-available with business attribution terms. Do not silently relicense it, label it OSI open source, or import GPL/proprietary code incompatibly.
- Preserve existing public APIs and user data or document a deliberate migration and compatibility plan.
- Separate read-only agent analysis from privileged production work. The former may run autonomously within the configured task scope; the latter requires an approval receipt and an enforced policy.
- Keep private maintainer instructions out of public repository documentation, releases, package archives, test fixtures and skills shipped to users.
- Source code, agent output, prompts, HTML, telemetry and generated reports are all untrusted input until processed by a specific validation boundary.
- Never present attack descriptions or runnable exploit modules as user-facing platform features.

## 16. Required first response and continuation contract

Begin with actual investigation, not a grand rewrite proposal. Return this compact execution packet:

1. **Repo receipt:** HEAD SHA, branch, exact worktree state, toolchain and baseline CI/test status. Label anything not run as `NOT RUN`.
2. **Capability truth table:** shipped, partial, stubbed, README-only, missing, with file/path evidence.
3. **P0 findings:** at most 10 highest-severity reproducible problems, each with trust boundary, failure path, proof and exact test to add.
4. **Reference decision table:** which upstream concepts/tools to reuse, reject or defer and why.
5. **Architecture decision:** retain/remove/change Rust, Go, gRPC, MCP, OPA and existing Omni structures based on measured need.
6. **Provider compatibility plan:** distinguish hosted model APIs, local open-weight inference engines, and external coding-agent host integrations. List tested capabilities and unknowns.
7. **Milestones and first 3-7 work cards:** explicit dependency graph, acceptance, rollback, integration owner.
8. **First implementation:** start M0, then the highest-risk M1 safety contract, using a feature branch and focused regression tests.
9. **Verification receipt:** commands, outputs, skipped checks, new failures, evidence timestamps, and exact behavior change. No claims beyond observed facts.
10. **Next gate:** what remains to become safely ready for the next milestone. Continue automatically on authorized reversible coding tasks, but pause at production mutation, credential/data export, live intrusive scan, privileged operation or irreversible external action.

### Definition of done

Bug Killer is not considered mature merely because it has many scanners, service binaries, or model names on a README. Maturity means a user can repeat an authorized investigation across different models, get the same grounded underlying facts, see honest uncertainty, obtain a meaningful minimal fix plan, and trust that unapproved changes are technically impossible even when an agent fails, hallucinates, or is manipulated.

**Start now by inspecting the latest repository state and CI, then execute M0 with real evidence.**
