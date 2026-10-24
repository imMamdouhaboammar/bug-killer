# FL-004: Agent Identity & Cryptographic Trust

## Problem Statement

When the healing engine (`bk heal`) modifies configuration files (e.g. `php.ini`, `Dockerfile`, `package.json`), it writes backup copies and an index manifest (`backup_manifest.json`) allowing the user to restore original system state via `bk rollback`.

Without integrity protections, an attacker or compromised local process with file write access could alter `backup_manifest.json`:
1. Modify `original_path` to point to `/etc/shadow` or other sensitive system files.
2. Alter `backup_path` to inject a malicious replacement payload during restoration.
3. Forge rollback instructions that trick the autonomous agent into overwriting production secrets.

## Root Cause Analysis

Unsigned state transitions in autonomous agent architectures violate the zero-trust boundary. An agent cannot assume local disk contents remain unmolested between execution runs. Backup manifests require cryptographic provenance and content commitment.

## Resolution & Implementation

Integrated `ed25519-dalek = "2.1"` to establish a durable Agent Identity and cryptographic trust perimeter:

1. **Autonomous Key Management (`src/identity/mod.rs`):**
   - Automatically generates a 32-byte Ed25519 signing keypair at `~/.bug-killer/identity/agent.key` with strict permissions (`0600`).
   - Exposes the agent's hex-encoded public key as its verifiable identity.

2. **Tamper-Evident Manifest Signing:**
   - For every backed-up file, the engine calculates the SHA-256 digest of the backup content.
   - Signs the canonical JSON serialization of the manifest using the agent's private key.
   - Embeds both the signature (`agent_signature_hex`) and public key (`agent_pubkey_hex`) directly into the manifest.

3. **Fail-Closed Verification on Rollback:**
   - Before restoring any file, `bk rollback` recalculates SHA-256 hashes of the stored backups and verifies the Ed25519 signature against the embedded public key.
   - If any byte of the manifest or backup payload has been altered, rollback aborts immediately with an authentication error:

```text
[ERROR] Security Violation: Backup manifest signature verification failed! Manifest has been tampered with. Aborting rollback.
```

## Verification

The test `test_agent_identity_signature_and_tamper_detection` validates both affirmative verification and intentional bit-flip rejection:

```bash
cargo test test_agent_identity_signature_and_tamper_detection
```

## Durable Invariant

```text
[LEARN] Security: Cryptographically sign all backup manifests with Ed25519 and fail closed on signature mismatch before rollback.
```
