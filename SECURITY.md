# Security Policy: Bug Killer

Bug Killer is committed to responsible vulnerability discovery, proof-backed reachability validation, and safe, deterministic remediation.

## Supported Versions

| Version | Supported | Security Patch SLA |
|---|---|---|
| `v0.1.x` (Current) | Yes | Immediate hot-patch within 24 hours |
| `< v0.1.0` | No | Upgrade required |

## Reporting a Vulnerability

If you discover a vulnerability or security defect within Bug Killer itself (such as a parser boundary bypass, archive handling flaw, or privilege escalation issue):

1. **Do NOT open a public GitHub issue.**
2. Send an encrypted advisory report to: `mamdouhfces1997@gmail.com`.
3. Include:
   - Reproduction environment and exact OS/architecture.
   - Proof-of-concept target files (e.g. malformed ELF or container manifest).
   - Expected behavior versus observed behavior.
4. You will receive an initial response within 24 hours acknowledging receipt.

## Defensive Non-Exploitation Guarantee

Bug Killer is strictly a defensive auditing, static verification, and auto-remediation engine:
- It does **not** generate weaponized exploit payloads.
- It does **not** bypass ASLR or execute arbitrary shellcode against targets.
- It validates reachability through static binary disassembling, symbol presence, and `/proc` memory mapping.
- All live mutations require explicit policy authorization and are backed by SHA-256 rollback ledgers.
