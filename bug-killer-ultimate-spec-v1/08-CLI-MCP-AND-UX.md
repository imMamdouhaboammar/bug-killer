# 08. Public CLI, MCP contracts and user journeys

## Existing interface inventory (2026-10-25)

Existing Rust CLI commands include `bk scan`, `bk probe`, `bk osv`, `bk heal`, `bk rollback`, `bk init`, `bk watch`, `bk evidence`, `bk plan`, `bk approve`, `bk apply`, `bk security scan/status/explain/fix/verify/guidance/catalog` and `bk mcp serve/config`. Do not accidentally document these as newly implemented features. Keep existing flags behavior unless a versioned migration is announced.

## Proposed additions (NOT implemented)

```text
bk advisory sync [--offline-cache PATH] [--sources osv,ghsa]
bk advisory status [--json]
bk inventory . [--sbom cyclonedx-json] [--json]
bk security scan . --profile quick|project|ci|deep --report-version 2
bk security scan . --engine tree-sitter,ast-grep,joern --json
bk security coverage . --per-rule --json
bk hunter plan . --policy .bug-killer/policy.yaml --json
bk hunter run --plan <id> --sandbox-only --json
bk hunter candidate <id> --evidence
bk hunter verify <id> --offline --json
bk disclose draft <finding-id> --private --output ./report.md
bk engine doctor --json
bk engine list --capabilities --availability --json
bk engine explain --goal known|prevention|research --target . --json
bk room plan . --goal known|prevention|research --profile project --json
bk room status <run-id> --receipts --json
bk room evidence <run-id> --include-gaps --json
```

Avoid using `bk hunt` synonymously with live network probing; `hunter` operates on local/sandbox targets unless a separate target-specific authorization exists.

`room` commands are **PROPOSED** unified orchestration-room interactions, not existing CLI features. `room plan` is read-only, shows chosen/skipped engines and resource/cost estimates; `room run` (if later added) must request authorization for any privileged action. Never imply a command's existence before implementation or invent an external engine's flags.

### User persona: vibe coder

`bk init` configures light checks and runs a baseline. The user sees "issues found", "coverage partial", "recommended safe fix", and a diff preview in plain language. The user is never told "completely secure". Autoapply is off until explicit allowed policy and regression gates are proven.

### User persona: software developer

`bk security scan --profile ci` returns deterministic exit-contract v2 and SARIF/JSON with stable fingerprints. Pre-commit checks exact staged blob contents and only mandatory gates. Full Project mode can refresh advisories using explicit network opt-in and pinned snapshots.

### User persona: security engineer

Deep mode discovers optional engine capabilities, captures call/dataflow traces, correlates findings and supports authorized DAST with exact target permissions. Every engine log and skipped target is traceable.

### User persona: vulnerability researcher

`hunter plan` shows requested resources and scope; `hunter run` uses isolated worker; `hunter verify` reproduces in fresh sandbox; `disclose draft` produces private report. Sending the draft externally is a separately approved action, never a side effect of "run".

## MCP API extension (PROPOSED)

Do not rename existing tools. Add names only after auditing current MCP server:

| Tool | Side effects | Returned evidence |
|---|---|---|
| `bugkiller_inventory` | Local read only | Assets, SBOM refs, inventory receipts |
| `bugkiller_scan_v2` | Local read, optional approved feed refresh | Findings and coverage envelopes |
| `bugkiller_engine_capabilities` | Read only | Installed/pinned engines and limitations |
| `bugkiller_room_plan` | Read only | Planned tasks, tool selection reasons, cost/permission requirements and gaps |
| `bugkiller_room_status` | Read only | Run state, per-tool execution receipts, partial coverage and budget consumption |
| `bugkiller_research_plan` | Read only | Hypotheses, sandbox budgets and consent requirements |
| `bugkiller_research_execute` | Sandbox-only bounded execution | Reproduction status, artifacts and receipts |
| `bugkiller_research_verify` | Isolated deterministic test | Independent verification and uncertainty |
| `bugkiller_repair_plan` | Read only | Bound patch diff and preimages |
| `bugkiller_repair_apply` | Privileged write, separately approved | Transaction/verification receipts |
| `bugkiller_disclosure_draft` | Local read/write draft only | Redacted private report |

Tool schemas must reject unexpected fields, non-canonical target paths and authorization IDs from another run. Default MCP transport remains read-only. The client agent may propose work but cannot create a trusted approval token through its own invocation.

## UI model

Each issue card contains:

- **What:** clearly bounded alleged weakness.
- **Where:** source/package/file span and version.
- **Why it matters:** impact under stated assumptions, without overstated exploitability.
- **Evidence:** indicator/static trace/reproduced behavior/official advisory and confidence.
- **What was checked:** assessed targets, missing checks, engine versions.
- **What can be fixed:** diff, test plan, risk/approval requirement.
- **Result:** fixed, blocked, partial, failed or independently verified.

Research candidates are visually separate from confirmed vulnerabilities to avoid pressure to publish unsupported reports.

The agentic room view also presents a **tool availability board**, an explicit **chosen/not-run/blocked** plan, bounded run timeline and cross-tool evidence trail. Human consent is a separate host/operator action, not an agent-generated MCP token. A vendor's clean status cannot suppress a mandatory-check gap.

## JSON and exit contracts

Use `schemas/finding.schema.json`, `schemas/coverage-receipt.schema.json` and `schemas/repair-plan.schema.json`. Envelope contains `contract_version`. Existing `--json` stays compatible until explicit major migration. Proposed `--report-version=2` selects the machine-readable report schema; separately, proposed `--exit-contract=v2` opts into Section 06 exit codes. Selecting a report version **must not** implicitly change exit-code behavior. CLI help and machine docs must explicitly mark optional engines unavailable/missing license rather than silently skipping.

## Accessibility and usability

Terminal output has plain-text equivalents for color. Critical states include text label, not color alone. Links to affected code don't expose private path data in remote telemetry. JSON key names remain English and stable; human messaging can be localized (Arabic RTL/English).

## Acceptance

1. Existing CLI golden snapshots preserve semantics when new engine absent.
2. MCP read-only endpoint cannot indirectly trigger package manager, service restart, Docker privileged calls or external disclosure.
3. V2 reports distinguish empty finding set from partial scan.
4. Research candidate remains draft until verified; no fake "CVE" label.
5. User can inspect exact scope and deny high-risk operation without side effect.
6. Full CLI help and examples mark proposed commands only after implementation lands.
