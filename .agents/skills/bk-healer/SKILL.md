---
name: bk-healer
description: >
  Autonomous virtual patcher, supervised remediation engine, and cryptographic rollback controller
  powered by Bug Killer (bk). Guides agents on planning non-mutating diffs, collecting operator
  approval receipts, executing atomic Ed25519-signed patches, and restoring bit-for-bit backups. Use
  when asked to heal vulnerabilities with bk, apply virtual patches for CVEs (e.g. PHP2Shell,
  Node2Shell), approve remediation plans, execute safe emergency WAF injection, or rollback a healing
  session, even if they don't explicitly say 'bk heal'. Do NOT use for discovering new vulnerabilities
  (use bk-scanner instead), generating exploit code, or performing unbacked manual file edits.
---

# Bug Killer Healer: Supervised Virtual Patcher & Rollback Controller

Autonomous remediation engine, prospective diff planner, and cryptographic rollback orchestrator.

```
+-----------------------------------------------------------------------------------+
|                            BUG KILLER HEALER WORKFLOW                             |
+-----------------------------------------------------------------------------------+
| 1. Prospective Plan | bk plan <finding_id> -> produces non-mutating diff & receipt |
| 2. Operator Sign-Off| bk approve <receipt_id> -> records cryptographic approval    |
| 3. Atomic Patch     | bk apply <receipt_id> -> creates Ed25519-signed backup       |
| 4. Verification Gate| bk security verify . -> confirms fix eliminates flaw         |
| 5. Rollback Failsafe| bk rollback <backup_id> -> bit-for-bit restoration on error  |
+-----------------------------------------------------------------------------------+
```

---

## Runtime Requirements (Pre-Flight)

Before applying patches, verify runtime invariants:
- **Bug Killer executable**: Available via `bk`, `bug-killer`, or `./target/release/bug-killer`.
- **Agent Identity**: Ed25519 keypair exists at `<project>/.aegis/agent_identity.key` for manifest signing.
- **Detailed pre-flight checks** -> **`references/runtime-setup.md`**.

```bash
# Check identity key existence
test -f .aegis/agent_identity.key || bk init . --hooks=false
```

---

## Supervised Remediation Protocol

### Step 1: Prospective Non-Mutating Plan
Never apply unverified mutations. Generate a prospective patch with a cryptographic diff hash:
```bash
bk plan <FINDING_ID> .
```
This generates a unique `receipt_id` and writes the candidate diff without touching source files.

### Step 2: Operator Review & Approval
Present the diff and blast radius to the operator. Obtain cryptographic approval:
```bash
bk approve <FINDING_ID> .
```
See **`references/cryptographic-receipts.md`** for receipt structure and token validation.

### Step 3: Apply Patch with Signed Backup Snapshot
Apply the approved remediation:
```bash
bk apply <FINDING_ID> .
```
Or for emergency autonomous virtual patching:
```bash
bk heal . --dry-run   # Preview first
bk heal .             # Apply with automated backup
```
Every applied patch:
1. Snapshots target files to `.aegis/backups/<backup_id>/`.
2. Computes SHA-256 digests and signs the manifest with Ed25519.
3. Applies changes atomically.

### Step 4: Verification Gate
Re-scan the workspace to confirm that the vulnerability is eliminated and no regressions occurred:
```bash
bk security verify .
```

### Step 5: Rollback on Verification Failure
If post-patch tests fail or regressions are detected, restore bit-for-bit:
```bash
# 1. View backup history
bk history .

# 2. Execute cryptographic rollback
bk rollback <BACKUP_ID>
```

---

## Remediation Strategies by Surface

| Surface | Remediation Strategy | Action Reference |
|---|---|---|
| **Reverse Proxy (Nginx/Apache)** | HTTP 415 rejection blocks for malicious compressed payloads. | **`references/patching-strategies.md`** |
| **Package Manifests** | Version pinning to patched releases in `package.json`, `composer.json`. | **`references/patching-strategies.md`** |
| **Containers (Dockerfile)** | Base image bumping to security tags; non-root user insertion. | **`references/patching-strategies.md`** |
| **Application Middleware** | Express/Fastify/Koa request body decompression guards. | **`references/patching-strategies.md`** |

---

## Invariants & Guardrails

1. **Non-Repudiation**: All filesystem modifications must be signed using Ed25519.
2. **Fail-Closed Rollback**: If an Ed25519 signature is missing, invalid, or any backup file hash has been tampered with, `bk rollback` aborts immediately with Exit Code `4`.
3. **Atomicity**: Multi-file patches apply as a single atomic transaction; any write error triggers automatic reversion.

---

## Reference Map

| Document | Purpose |
|---|---|
| `references/runtime-setup.md` | Pre-flight identity checks and filesystem write invariants |
| `references/patching-strategies.md` | WAF virtual patches, manifest pinning, and container fixes |
| `references/cryptographic-receipts.md` | Receipt schema, operator approval, and rollback verification |
