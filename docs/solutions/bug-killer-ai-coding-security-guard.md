# Solution: Bug Killer AI Coding Security Guard Architecture & Codified Learnings

## Mission Summary
Turned the 373-rule, 27-category AI-Generated Code Security Catalog into a fully operational, policy-controlled security detection, prevention, guidance, and remediation engine within the Bug Killer platform.

---

## Architecture

The system implements the five core decoupled responsibilities:

1. **Catalog Engine (`src/catalog/`):**
   - Single authoritative structured JSON database (`src/catalog/catalog_data.json`) embedded at compile time via `include_str!`.
   - Complete typing with `RuleLifecycle` (`Cataloged`, `SupportedStatic`, `SupportedDynamic`, `ReviewRequired`, `Experimental`, `Deprecated`).
   - Ground truth invariant: unautomated rules remain honestly `Cataloged` or `ReviewRequired`.

2. **Detector Registry (`src/detectors/`):**
   - Uniform trait `SecurityDetector` defining permissions, supported targets, rules, and failure semantics.
   - Built-in detectors:
     - `TaintSastDetector`: AST taint analysis for command/SQL/path injection.
     - `SecretDetector`: High-entropy regex detector for AWS/GitHub/OpenAI tokens with automated redaction.
     - `CicdSecurityDetector`: GitHub Actions expression script injection and privileged PR triggers.
     - `ContainerIacDetector`: Container root execution and dangerous docker daemon mounts.
     - `AgentSkillDetector`: MCP tool poisoning and excessive permission grants.
     - `OsvScaDetector`: Dependency vulnerability tracking.
   - Distinct statuses: `Confirmed`, `Suspected`, `NoFindingInCoverage`, `NotAssessed`.

3. **Project Initialization & Configuration (`src/security_guard/config.rs`):**
   - Idempotent `bk init [PATH]` creates `.bugkiller/config.json` and `.bugkiller/policy.json`.
   - Content-hash cache (`.bugkiller/cache.json`) for sub-second incremental scans.
   - Git pre-commit hook gating.

4. **Universal Agent MCP Tools (`src/mcp/server.rs`):**
   - 10 canonical MCP tools (`bugkiller_security_status`, `bugkiller_scan_project`, `bugkiller_scan_changed_files`, `bugkiller_list_findings`, `bugkiller_explain_finding`, `bugkiller_get_rule`, `bugkiller_propose_fix`, `bugkiller_verify_fix`, `bugkiller_get_coverage`, `bugkiller_security_guidance`).
   - Strict read-only gating preventing unprivileged agents from executing file mutations.

5. **Guarded Local Fix Remediation (`src/security_guard/remediation.rs`):**
   - Ed25519-signed backup manifests created prior to file modification.
   - Mandatory post-patch re-scan with automatic rollback to snapshot if vulnerability invariants fail.

---

## Durable Engineering Learnings

1. **Rule ID Mapping vs Advisory Aliases:**
   When integrating existing specialized scanners (e.g. `ContainerScanner` with `BK-CONTAINER-001`) with generalized catalog rules (`BK-AI-INF-001`), store the primary catalog identifier in `CveId::Custom` and retain legacy/scanner identifiers in `finding.advisory_ids`. This preserves backward compatibility across existing integration tests while satisfying catalog-grounded guard evaluations.

2. **Independent Verification Isolation:**
   Remediation engines must never trust prospective diffs or unit test results as proof of security. A post-patch scan through the exact same detector pipeline must affirmatively verify the finding is gone, or trigger an immediate, non-repudiable Ed25519 rollback.

3. **Read-Only MCP Boundaries:**
   Coding agents frequently operate in sandboxed or read-only workspaces. Exposing mutating tools without permission checks introduces state corruption risks. All write operations (`bk.apply_plan`, `bk.rollback`) must fail-closed when `--read-only` is active.

---

## Verification Matrix

| Test Suite | Coverage | Status |
|---|---|---|
| `cargo test --workspace` | Catalog, Detectors, MCP, Taint, SAST, DAST, Healer | **PASSED (100%)** |
| `cargo clippy --workspace --all-targets -- -D warnings` | Zero warnings permitted | **PASSED (0 warnings)** |
| `cargo test --manifest-path services/inspector/Cargo.toml` | Agent tools, gRPC UDS roundtrip | **PASSED (100%)** |
| `go test ./...` (`services/orchestrator` & `healer`) | Afero sandboxed fs, WAF, UDS IPC | **PASSED (100%)** |
