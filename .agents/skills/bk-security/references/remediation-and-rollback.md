# Supervised Remediation & Cryptographic Rollback Protocol

This reference defines how Bug Killer (`bk`) executes safe, graduated virtual patching, atomic file transactions, cryptographic backup manifests, and bit-for-bit rollbacks without risking production stability.

---

## 1. The 4-Step Remediation Loop

```mermaid
sequenceDiagram
    participant Agent as AI Agent
    participant BK as Bug Killer (bk)
    participant Operator as Operator / CI Approval Gate
    participant FS as Production Filesystem

    Agent->>BK: 1. bk plan <finding_id>
    BK-->>Agent: Prospective Diff + Receipt ID (SHA-256 hash)
    
    Agent->>Operator: Present diff & blast-radius analysis
    Operator->>BK: 2. bk approve <receipt_id>
    BK-->>Operator: Cryptographic Approval Token
    
    Agent->>BK: 3. bk apply <receipt_id>
    BK->>FS: Snapshot targets to .bugkiller/backups/<backup_id>
    BK->>FS: Sign manifest with Ed25519 identity key
    BK->>FS: Apply unified diff atomically
    BK-->>Agent: Application Confirmation + Backup ID
    
    Agent->>BK: 4. bk verify .
    BK-->>Agent: Vulnerability Eliminated (Pass) OR Regression Detected (Fail)
    
    opt Regression Detected
        Agent->>BK: bk rollback <backup_id>
        BK->>FS: Verify Ed25519 signature & restore bit-for-bit
    end
```

---

## 2. Graduated Remediation Levels

| Level | Name | Behavior | Permitted Actions |
|---|---|---|---|
| **L1** | Advisory | Report vulnerabilities only. Zero filesystem mutations. | Generate patch recommendations, code snippets, guidance. |
| **L2** | Supervised Plan | Produce non-mutating unified diff and generate receipt ID. | `bk plan <finding_id>`. Filesystem remains untouched. |
| **L3** | Approved Apply | Apply planned patch after verifying cryptographic operator sign-off. | `bk apply <receipt_id>`. Enforces atomic backup & Ed25519 sign. |
| **L4** | Autonomous Virtual Patch | Apply reversible virtual patches (WAF rules, HTTP 415 drops) in emergency mode. | `bk heal --level L4`. Snapshot created before any write. |

---

## 3. Cryptographic Backup & Manifest Verification

Whenever `bk apply` or `bk heal` mutates a file:

1. **Snapshot Creation**: The original target file is copied bit-for-bit into `.bugkiller/backups/<backup_id>/`.
2. **Digest Computation**: SHA-256 hashes are calculated for every original file.
3. **Ed25519 Non-Repudiation**: The manifest containing file paths, timestamps, and SHA-256 hashes is signed using the autonomous agent identity key located at `~/.bug-killer/identity/agent.key`.
4. **Failure-Closed Rollback Policy**:
   - Before executing `bk rollback <backup_id>`, `bk` verifies the Ed25519 signature against the agent public key.
   - If any backup file was modified, tampered with, or the signature does not match, rollback aborts immediately with Exit Code `4` (`Signature / Integrity violation`).

---

## 4. Remediation Strategies by Target Type

### Manifest Pinning (`package.json`, `composer.json`, `Cargo.toml`)
- Pins vulnerable dependency versions to patched upstream versions (e.g. updating Node runtime engines or PHP packages).
- Preserves formatting, indent spacing, and existing package constraints.

### Virtual Patching (Reverse Proxy & Middleware)
- Injects HTTP 415 `Unsupported Media Type` rejection rules into Nginx or Apache configuration to drop attack payloads (such as Brotli chunked decompression exploits) before reaching vulnerable runtimes.
- Idempotent: Never duplicates rules if already present.

### Container Hardening (`Dockerfile`)
- Replaces vulnerable base image tags with patched versions.
- Injects non-root user directives (`USER 10001:10001`) to mitigate container breakout risks.

---

## 5. Instant Rollback Procedure

If a test fails or production behaves unexpectedly following a patch:

```bash
# 1. Identify the backup ID
bk history .

# 2. Revert the patch bit-for-bit
bk rollback <backup_id>

# 3. Verify original baseline is restored
bk doctor .
```
