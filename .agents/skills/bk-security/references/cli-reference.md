# Bug Killer CLI Specification & Contract

Current command-line arguments and output contracts for Bug Killer (`bk`).

---

## 1. Core Command Index

| Command | Category | Purpose | Typical Run |
|---|---|---|---|
| `bk init [PATH]` | Setup | Initialize project security baseline, policy, and git hooks | `bk init . --hooks` |
| `bk doctor [PATH]` | Health | Audit environment, tools, and identity key health | `bk doctor . --json` |
| `bk scan [PATH]` | Inspection | Execute multi-surface vulnerability scan across targets | `bk scan . --taint --json` |
| `bk security scan [PATH]` | Inspection | Catalog-driven security audit with severity gating | `bk security scan . --fail-on high` |
| `bk security status [PATH]` | Audit | Report project security posture and active policies | `bk security status . --json` |
| `bk security guidance [TASK]` | Shift-Left | Obtain contextual security guardrails for planned changes | `bk security guidance "add file upload"` |
| `bk security catalog [QUERY]` | Rules | Browse rule catalog, CWE mappings, and remediation guides | `bk security catalog sql-injection` |
| `bk probe <URL>` | DAST | Defensively probe running web service headers & disclosures | `bk probe https://staging.internal` |
| `bk osv [PATH]` | SCA | Query OSV for vulnerable dependencies in a workspace | `bk osv . --json` |
| `bk cve-info <CVE_ID>` | Intelligence | Fetch teardown and virtual patch blueprint for specific CVE | `bk cve-info CVE-2026-111497` |
| `bk plan <ID> [PATH]` | Remediation | Generate prospective, non-mutating repair plan | `bk plan BK-2026-0042 .` |
| `bk approve <ID> [PATH]` | Remediation | Issue operator approval receipt | `bk approve BK-2026-0042 .` |
| `bk apply <ID> [PATH]` | Remediation | Apply approved remediation | `bk apply BK-2026-0042 . --approval-file approval.json` |
| `bk heal [PATH]` | Remediation | Execute autonomous virtual patching with safety snapshots | `bk heal . --dry-run` |
| `bk rollback <BACKUP_ID>` | Safety | Bit-for-bit restoration from cryptographically signed backup | `bk rollback bkp_20261024_01` |
| `bk history [PATH]` | Audit | List historical backup manifests and rollback snapshots | `bk history .` |
| `bk evidence [PATH] <ID>` | Forensics | Retrieve cryptographic evidence hashes for finding | `bk evidence . BK-2026-0042` |
| `bk security verify [PATH]` | Validation | Verify scan coverage and remaining findings | `bk security verify .` |
| `bk watch [PATH]` | Surveillance | Live filesystem daemon monitoring for security regressions | `bk watch . -i 2` |
| `bk mcp serve` | Integration | Launch stdio MCP server for agent tool calls | `bk mcp serve` |
| `bk mcp config` | Integration | Generate host agent configuration snippets (Claude, Cursor) | `bk mcp config --host all` |

---

## 2. Command Details & Flag Signatures

### `bk init`
Initializes `.bugkiller/config.json`, computes the baseline finding inventory, and installs git pre-commit hooks.
- `--hooks`: Install git pre-commit hook (default: true). Set `--hooks=false` to skip hook installation.
- `--json`: Output receipt as JSON (`InitReceipt`).

### `bk scan`
Multi-surface scanning engine.
- `--profile <PROFILE>`: Scan profile (`quick`, `project`, `deep`, `ci`).
- `--check-runtime`: Inspect running Node.js and PHP processes on host for memory vulnerabilities.
- `--json`: Output full findings array with certainty, reachability, and evidence receipts.
- `--taint`: Enable source-level taint checks.
- `--osv`: Query OSV for dependency vulnerabilities.

### `bk security scan`
Policy-enforcing security guard scan.
- `--profile <PROFILE>`: Scan depth (`quick`, `project`, `deep`, `ci`).
- `--fail-on <SEVERITY>`: Exit with code 1 if findings meet or exceed severity (`critical`, `high`, `medium`, `low`).
- `--changed-only`: Restrict reported findings to Git-changed files.
- `--json`: Output `SecurityGuardReport` JSON (exit status still indicates a severity breach).

### `bk probe`
Strictly defensive DAST prober.
- Safe perimeter rules: Automatically denies cloud metadata IPs (`169.254.169.254`), embedded HTTP credentials, and non-HTTP schemes.
- `--timeout <SECS>`: Request timeout in seconds (default: 10).
- `--header <K:V>`: Pass custom authorization or identification header.
- `--json`: Output raw probe findings, CSP evaluations, and missing headers.

### `bk plan`, `approve`, `apply`
Supervised graduated remediation workflow.
1. `bk security fix <FINDING_ID> [PATH] --plan`: Generates an advisory proposal or a bounded supported repair.
2. `bk security fix <FINDING_ID> [PATH] --apply`: Requires `config.json` to allow guarded fixes and `policy.json` to set `allow_guarded_local_fix: true`.
3. Supported guarded changes snapshot files in `.aegis/backups/<id>`; unsupported image, secret, and workflow transformations remain advisory only.

---

## 3. Exit Code Conventions

| Exit Code | Meaning | Action for AI Agent |
|---|---|---|
| `0` | Success / Clean workspace | Proceed to next workflow step. |
| `1` | Security threshold breach | Vulnerabilities found meeting `--fail-on` criteria. Inspect findings and formulate remediation plan. |
| `2` | CLI argument error | Clap rejects invalid flags or missing required arguments. |
| `1` | Other command failure | Fix or rollback failed, including integrity or filesystem errors. Inspect stderr. |
