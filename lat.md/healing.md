# Virtual Healing and Rollback

Bug Killer implements atomic self-healing remediation paired with bit-for-bit cryptographic rollback.

Mutations require cryptographic manifests, operator approvals, and isolated backup snapshots.

## Supervised Remediation Protocol

Healing operations are planned as discrete patch actions that require explicit operator approval receipts.

The workflow coordinates through [[src/healer/mod.rs#AutopilotHealer]] and requires valid receipts validated by [[src/healer/approval.rs#ApprovalManager]].

## Cryptographic Non-Repudiation

State mutations calculate SHA-256 digests and produce signed manifests before touching disk.

Manifest generation is handled by [[src/healer/backup.rs#BackupManager]], while Ed25519 signatures are verified via [[src/identity/mod.rs#AgentIdentity]] and [[src/identity/mod.rs#OperatorIdentity]].

## Bit-for-Bit Rollback

Rollback restores modified target files to their exact pre-remediation byte state.

The restoration engine is implemented in [[src/healer/rollback.rs#RollbackManager]], which validates SHA-256 digests and cryptographic signatures before restoring snapshots.
