# Bug Killer Healer Runtime Setup & Pre-Flight

This reference defines the pre-flight checks and cryptographic invariants required before applying any remediation or rollback with Bug Killer (`bk`).

---

## 1. Pre-Flight Verification

Verify the following invariants prior to executing any file mutation:

| Check | Target | Requirement | Remediation |
|---|---|---|---|
| **Binary Handle** | `which bk` or local path | Executable binary present | Check `target/release/bug-killer` or compile via `cargo build --release`. |
| **Agent Keypair** | `~/.bug-killer/identity/agent.key` | Ed25519 keypair exists and permissions are `0600` | Run `bk init .` or `bk doctor .` to generate default identity. |
| **Workspace Write** | `.bugkiller/backups` | Writable directory for snapshots | Verify filesystem permissions; never mutate without snapshot capability. |
| **Git Working Tree** | `git status --porcelain` | Clean or known working tree | Recommended to avoid mixing uncommitted edits with security patches. |

---

## 2. Cryptographic Non-Repudiation Invariant

Every mutation performed by `bk heal` or `bk apply`:
1. Computes SHA-256 digests of all target files before modification.
2. Writes original contents into `.bugkiller/backups/<backup_id>/`.
3. Creates an Ed25519 signature over the backup manifest using the agent private key.
4. If signature generation fails, the entire transaction aborts without modifying target files.
