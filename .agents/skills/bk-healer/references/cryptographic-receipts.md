# Cryptographic Receipts & Rollback Verification

This reference defines the schema, verification protocol, and failure-closed semantics for Bug Killer (`bk`) operator approval receipts and rollback snapshots.

---

## 1. Approval Receipt Schema

`bk approve` signs an approved plan checksum with these fields:

```json
{
  "plan_id": "FINDING-ID",
  "plan_checksum": "64-character SHA-256 hex digest",
  "approver": "operator@example.com",
  "timestamp": "2026-10-24T15:00:00Z",
  "valid_until": "2026-10-24T16:00:00Z",
  "signature": "Ed25519 signature hex"
}
```

---

## 2. Operator Approval Workflow

1. **Review Diff**: The agent presents the unified diff and risk score to the human operator or automated pipeline.
2. **Issue Approval**:
   ```bash
   bk approve <FINDING_ID> .
   ```
   This generates an approval receipt signed with the project identity and records it in `.bug-killer/approvals/`.
3. **Application Verification**:
   ```bash
   bk apply <FINDING_ID> .
   ```
   `bk apply` verifies that:
   - The approval signature is valid.
   - Target files on disk have not been modified since the diff was generated (SHA-256 match).
   - An Ed25519-signed backup manifest is written before touching files.

---

## 3. Rollback Manifest Structure & Tamper Detection

Snapshots are stored in `.aegis/backups/<backup_id>/manifest.json`:

```json
{
  "backup_id": "20261024_150210",
  "created_at": "2026-10-24T15:02:10Z",
  "root_dir": "/project/path",
  "signer_public_key": "64-character Ed25519 public key hex",
  "signature": "Ed25519 signature hex",
  "records": [
    {
      "relative_target_path": "nginx.conf",
      "backup_file_name": "0_nginx.conf",
      "original_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    }
  ]
}
```

### Failure-Closed Verification Rules
When `bk rollback <backup_id>` is invoked:
1. It validates the manifest signature against the locally trusted `.aegis/agent_identity.key`.
2. If the signature is invalid or tampered with, execution returns an error.
3. It computes the SHA-256 hash of every stored file in `.aegis/backups/<backup_id>/` before restoring any file.
4. If any stored file hash does not match `manifest.json`, restoration does not begin.
5. Only upon full verification are files restored bit-for-bit to their original locations.
