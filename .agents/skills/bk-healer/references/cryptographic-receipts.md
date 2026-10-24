# Cryptographic Receipts & Rollback Verification

This reference defines the schema, verification protocol, and failure-closed semantics for Bug Killer (`bk`) operator approval receipts and rollback snapshots.

---

## 1. Approval Receipt Schema

When `bk plan` produces a prospective patch, it outputs a structured receipt:

```json
{
  "receipt_id": "REC-20261024-8842",
  "finding_id": "RULE-NODE-BROTLI-001",
  "created_at": "2026-10-24T15:00:00Z",
  "target_files": [
    {
      "path": "nginx.conf",
      "original_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "diff_sha256": "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a"
    }
  ],
  "patch_level": "L2_SUPERVISED",
  "operator_signature": null
}
```

---

## 2. Operator Approval Workflow

1. **Review Diff**: The agent presents the unified diff and risk score to the human operator or automated pipeline.
2. **Issue Approval**:
   ```bash
   bk approve . REC-20261024-8842
   ```
   This generates an approval token signed by the operator identity and records it in `.bugkiller/approvals/`.
3. **Application Verification**:
   ```bash
   bk apply . REC-20261024-8842
   ```
   `bk apply` verifies that:
   - The approval signature is valid.
   - Target files on disk have not been modified since the diff was generated (SHA-256 match).
   - An Ed25519-signed backup manifest is written before touching files.

---

## 3. Rollback Manifest Structure & Tamper Detection

Snapshots are stored in `.bugkiller/backups/<backup_id>/manifest.json`:

```json
{
  "backup_id": "bkp_20261024_01",
  "timestamp": "2026-10-24T15:02:10Z",
  "agent_public_key": "4a7f23...",
  "ed25519_signature": "9b12e4...",
  "entries": [
    {
      "relative_path": "nginx.conf",
      "stored_filename": "nginx.conf.orig",
      "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    }
  ]
}
```

### Failure-Closed Verification Rules
When `bk rollback <backup_id>` is invoked:
1. It reads `manifest.json` and computes the Ed25519 signature over its payload using `agent_public_key`.
2. If the signature is invalid or tampered with, execution aborts with exit code `4`.
3. It computes the SHA-256 hash of each stored file in `.bugkiller/backups/<backup_id>/`.
4. If any stored file hash does not match `manifest.json`, execution aborts with exit code `4`.
5. Only upon full verification are files restored bit-for-bit to their original locations.
