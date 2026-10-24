---
name: aegis-healer
description: >
  Autopilot vulnerability finder and safe auto-healer for critical runtime exploits,
  specifically PHP2Shell (CVE-2026-109618, CVE-2026-109619) and Node2Shell (CVE-2026-111497).
  Scans PHP/Node.js runtimes, package manifests, Dockerfiles, Nginx/Apache configurations,
  and source code. Executes deterministic, atomic healing with automated cryptographic backups
  and instant zero-loss rollback.
---

# Aegis Healer: Autopilot Vulnerability Finder & Healer

Autonomous, zero-downtime security auditor and patcher built in high-performance Rust (`bug-killer` / `bk`, formerly `aegis`).

> [!NOTE]
> Aegis has evolved into **Bug Killer (`bk`)**. For new implementations, prefer **`bk-security`**, **`bk-scanner`**, or **`bk-healer`**. `bk` CLI commands are fully compatible.

## Trigger Conditions

Use this skill when:
- Asked to scan, detect, or remediate PHP vulnerabilities, especially **PHP2Shell** (`CVE-2026-109618`, `CVE-2026-109619`).
- Asked to audit or heal Node.js applications against the Brotli memory corruption flaw **Node2Shell** (`CVE-2026-111497`).
- Asked to audit Dockerfiles, `package.json`, `composer.json`, Nginx configs, or Apache reverse proxies for runtime exploit exposure.
- Running autonomous security hardening with atomic rollback guarantees.

## Core Capabilities

1. **Deterministic Multi-Surface Scanning:**
   - Detects unpatched host PHP (< 8.2.35, < 8.3.36, < 8.4.27, < 8.5.12) and Node.js (< 22.23.4, < 24.22.1, < 26.12.1).
   - Audits Dockerfile base image tags across fleets.
   - Discovers unguarded Express/Fastify request body decompression pipelines.
   - Flags missing reverse-proxy WAF rules.

2. **Automated Atomic Healing:**
   - **Virtual Patching:** Injects HTTP 415 rejection blocks for Brotli payloads into Nginx reverse proxies before requests hit Node.js.
   - **Manifest Pinning:** Updates `package.json` engines and `composer.json` requirements to safe branches.
   - **Container Remediation:** Bumps Dockerfile base images to patched upstream releases.
   - **Middleware Guarding:** Injects Express middleware rejecting `Content-Encoding: br` bodies pending binary updates.

3. **Safety & Zero-Loss Rollback:**
   - Pre-computation of SHA-256 hashes for all modified targets.
   - Snapshot archived in `.bugkiller/backups/<backup_id>/` (or legacy `.aegis/backups/<backup_id>/`).
   - Instant cryptographic rollback restoring files bit-for-bit: `bk rollback <backup_id>`.

## CLI Usage

```bash
# 1. Audit entire workspace or server root
bk scan . [--check-runtime] [--json]

# 2. Preview automated remediation without touching files
bk heal . --dry-run

# 3. Apply atomic healing patches (creates automatic safety snapshot)
bk heal .

# 4. View backup snapshot history
bk history

# 5. Rollback changes if needed
bk rollback <BACKUP_ID>

# 6. Deep CVE vulnerability breakdown
bk cve-info <CVE_ID>
```
aegis cve-info CVE-2026-109618
```
