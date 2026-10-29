# Bug Killer Documentation Map & Architecture Hierarchy

## Purpose & Authority
Bug Killer documentation is organized into three distinct tiers to ensure clarity between **implemented/shipped runtime behavior**, **accepted architectural specifications/schemas**, and **historical milestone execution archives**.

### The Three-Tier Hierarchy

| Tier | Classification | Directory / Files | Purpose & Lifecycle | Precedence |
| --- | --- | --- | --- | --- |
| **Tier 1** | **Live Operational Documentation** | [`README.md`](../README.md)<br>[`docs/OPERATOR_GUIDE.md`](OPERATOR_GUIDE.md)<br>[`docs/OPERATOR-APPROVAL.md`](OPERATOR-APPROVAL.md)<br>[`docs/AEGIS_PLATFORM_SPECIFICATION.md`](AEGIS_PLATFORM_SPECIFICATION.md)<br>[`docs/SIBLING_TOOLS.md`](SIBLING_TOOLS.md)<br>[`lat.md/`](../lat.md/) | Authoritative for currently implemented and released CLI commands, daemon flags, security guard workflows, and operator actions. | **Highest (1)** |
| **Tier 2** | **Accepted Specifications & Active Schemas** | [`bug-killer-ultimate-spec-v1/`](../bug-killer-ultimate-spec-v1/README.md) (`00-` through `14-`)<br>[`schemas/`](../bug-killer-ultimate-spec-v1/schemas/)<br>[`examples/`](../bug-killer-ultimate-spec-v1/examples/) | Authoritative architectural target contracts, data interchange formats, JSON Schemas, and integration fixtures validated by workspace tests (`tests/m1_*.rs`, `tests/m4_*.rs`, etc.). | **Authoritative Contract (2)** |
| **Tier 3** | **Historical Plans, Research & Milestone Archives** | [`plan/`](../plan/README.md)<br>[`bug-killer-novel-discovery-execution-plan/`](../bug-killer-novel-discovery-execution-plan/README.md)<br>[`docs/research/`](research/README.md) | Historical point-in-time plans, sprint logs, research retrospectives, and upstream teardowns. Non-authoritative for current runtime behavior. | **Informational / Historical (3)** |

### Precedence Rule
When a statement in a Tier 3 planning document conflicts with a Tier 2 contract or Tier 1 live behavior, **Tier 1 and Tier 2 strictly govern**. Planning documents capture the intent and deliberations of specific development iterations (such as October 2026 milestones) and do not represent verified runtime functionality until proven by test suites.

---

## Detailed Directory Breakdown

### 1. Live Operational Documentation (Tier 1)
- **`README.md`**: Main operator landing page, fast-start instructions, CLI reference, and architecture summary.
- **`docs/OPERATOR_GUIDE.md`**: Runbooks for defensive memory inspections, AST scanning, taint analysis, and remediation workflows.
- **`docs/OPERATOR-APPROVAL.md`**: Human-in-the-loop security protocol governing state mutations, authorization tokens, and rollback manifests.
- **`docs/AEGIS_PLATFORM_SPECIFICATION.md`**: Security perimeter invariants, safe defensive sandboxing, and non-repudiation guarantees.
- **`docs/SIBLING_TOOLS.md`**: The external scanner and tool broker integration matrix (Semgrep, CodeQL, Trivy, OSV, etc.) and execution receipt contracts.
- **`lat.md/`**: The active, machine-checked Lat knowledge graph containing formal section IDs, architecture mappings, and `@lat:` test traces.

### 2. Accepted Specifications & Active Schemas (Tier 2)
Located in `bug-killer-ultimate-spec-v1/`:
- **`00-VISION-AND-SCOPE.md`** through **`14-AGENTIC-SECURITY-OPERATIONS-ROOM.md`**: Deep domain architecture and protocol definitions.
- **`schemas/`**: Formal JSON Schema definitions used for runtime deserialization and integration testing:
  - `finding.schema.json`: Unified vulnerability finding contract.
  - `tool-capability.schema.json`: External tool descriptor contract.
  - `tool-execution-receipt.schema.json`: Cryptographically verifiable execution receipt.
  - `disclosure-packet.schema.json`: Coordinated vulnerability disclosure bundle.
- **`examples/`**: Machine-validated golden fixtures used in automated regression tests.

### 3. Historical Plans, Research & Milestone Logs (Tier 3)
- **`plan/`**:
  - `Bug-Killer-Agentic-Master-Prompt.md`: Initial multi-agent role prompts and design principles (October 2026).
  - `Bug-Killer-Full-Security-Coverage-Implementation-Plan.md`: M0-M6 implementation plan drafted during early development.
  - `Bug-Killer-AI-Generated-Code-Security-Catalog.md`: 373-rule AI vulnerability classification blueprint.
- **`bug-killer-novel-discovery-execution-plan/`**:
  - `bug-killer-novel-discovery-execution-plan-2026-10-26.md`: Milestone roadmap for novel discovery engine.
  - `task_plan.md`, `findings.md`, `progress.md`: Execution logs and initial triage records from the October 28, 2026 sprint.
- **`docs/research/`**:
  - `deepsec/`: Reverse-engineering and architectural audit of `vercel-labs/deepsec` clean-room baseline.
