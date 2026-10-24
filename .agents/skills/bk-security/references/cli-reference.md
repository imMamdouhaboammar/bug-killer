# Bug Killer CLI Specification & Contract

Exhaustive command-line syntax, arguments, flags, exit codes, and machine-readable output schemas for Bug Killer (`bk`).

---

## 1. Core Command Index

| Command | Category | Purpose | Typical Run |
|---|---|---|---|
| `bk init [PATH]` | Setup | Initialize project security baseline, policy, and git hooks | `bk init . --hooks` |
| `bk doctor [PATH]` | Health | Audit environment, tools, and identity key health | `bk doctor . --json` |
| `bk scan [PATH]` | Inspection | Execute multi-surface vulnerability scan across targets | `bk scan . --profile deep --json` |
| `bk security scan [PATH]` | Inspection | Catalog-driven security audit with baseline gating | `bk security scan . --fail-on high` |
| `bk security status [PATH]` | Audit | Report project security posture and active policies | `bk security status . --json` |
| `bk security guidance [TASK]` | Shift-Left | Obtain contextual security guardrails for planned changes | `bk security guidance "add file upload"` |
| `bk security catalog [QUERY]` | Rules | Browse rule catalog, CWE mappings, and remediation guides | `bk security catalog sql-injection` |
| `bk probe <URL>` | DAST | Defensively probe running web service headers & disclosures | `bk probe https://staging.internal` |
| `bk osv <ECO> <PKG> [VER]` | SCA | Query OSV database directly for known vulnerabilities | `bk osv npm express 4.17.1` |
| `bk cve-info <CVE_ID>` | Intelligence | Fetch teardown and virtual patch blueprint for specific CVE | `bk cve-info CVE-2026-111497` |
| `bk plan [PATH] <ID>` | Remediation | Generate prospective, non-mutating repair plan with diff | `bk plan . BK-2026-0042` |
| `bk approve [PATH] <ID>` | Remediation | Record operator approval receipt for a planned fix | `bk approve . REC-9871` |
| `bk apply [PATH] <ID>` | Remediation | Apply approved prospective plan with Ed25519 signature | `bk apply . REC-9871` |
| `bk heal [PATH]` | Remediation | Execute autonomous virtual patching with safety snapshots | `bk heal . --dry-run` |
| `bk rollback <BACKUP_ID>` | Safety | Bit-for-bit restoration from cryptographically signed backup | `bk rollback bkp_20261024_01` |
| `bk history [PATH]` | Audit | List historical backup manifests and rollback snapshots | `bk history .` |
| `bk evidence [PATH] <ID>` | Forensics | Retrieve cryptographic evidence hashes for finding | `bk evidence . BK-2026-0042` |
| `bk verify [PATH]` | Validation | Verify that previously detected findings are eliminated | `bk verify .` |
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
- `--sarif`: Output report in standard SARIF format for GitHub Advanced Security.

### `bk security scan`
Policy-enforcing security guard scan.
- `--profile <PROFILE>`: Scan depth (`quick`, `project`, `deep`, `ci`).
- `--baseline`: Evaluate findings delta against `.bugkiller/baseline.json`.
- `--fail-on <SEVERITY>`: Exit with code 1 if findings meet or exceed severity (`critical`, `high`, `medium`, `low`).
- `--json`: Output `SecurityScanResult` JSON.

### `bk probe`
Strictly defensive DAST prober.
- Safe perimeter rules: Automatically denies cloud metadata IPs (`169.254.169.254`), embedded HTTP credentials, and non-HTTP schemes.
- `--timeout <SECS>`: Request timeout in seconds (default: 10).
- `--header <K:V>`: Pass custom authorization or identification header.
- `--json`: Output raw probe findings, CSP evaluations, and missing headers.

### `bk plan`, `approve`, `apply`
Supervised graduated remediation workflow.
1. `bk plan <PATH> <FINDING_ID>`: Computes minimal unified diff, generates unique `receipt_id`, and calculates SHA-256 diff hash.
2. `bk approve <PATH> <RECEIPT_ID>`: Prompts operator or reads automated CI sign-off; writes signature to `.bugkiller/approvals/`.
3. `bk apply <PATH> <RECEIPT_ID>`: Verifies signature, creates snapshot in `.bugkiller/backups/<id>`, applies diff atomically, and validates syntax.

---

## 3. Exit Code Conventions

| Exit Code | Meaning | Action for AI Agent |
|---|---|---|
| `0` | Success / Clean workspace | Proceed to next workflow step. |
| `1` | Security threshold breach | Vulnerabilities found meeting `--fail-on` criteria. Inspect findings and formulate remediation plan. |
| `2` | Configuration / Input error | Invalid arguments, missing file path, or malformed config. Correct flags before retrying. |
| `3` | Runtime environment failure | Compiler missing, unreadable file permissions, or network failure on mandatory check. Fails closed. |
| `4` | Signature / Integrity violation | Rollback aborted due to Ed25519 signature mismatch or tampered backup manifest. Halt immediately. |
