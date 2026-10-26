---
name: bk-threatswarm
description: Autonomous defensive threat modeling, deterministic scope boundary enforcement, MITRE ATT&CK mapping, and CVSS 3.1 base scoring engine for Bug Killer.
triggers:
  - "threatswarm"
  - "scope check"
  - "scope enforcement"
  - "cvss scoring"
  - "mitre attack mapping"
  - "defensive perimeter audit"
  - "egress verification"
---

# ThreatSwarm Defensive Intelligence Engine

## Overview & Scope Boundary

The `bk-threatswarm` engine provides autonomous defensive security orchestration, strict scope boundary containment, MITRE ATT&CK enterprise mapping, and CVSS v3.1 mathematical scoring within Bug Killer (`bk`).

> [!IMPORTANT]
> **Strictly Defensive Perimeter Invariant:**
> In accordance with the repository constitution ([AGENTS.md](file:///Users/mamdouhaboammar/Documents/antigravity/silly-kepler/AGENTS.md)), all offensive tooling, weaponized exploit generators, payload encoders, and command-and-control (C2) frameworks have been systematically excised. The engine operates exclusively in detection, boundary enforcement, risk scoring, and virtual patching modes.

---

## Capabilities

| Capability | Engine Component | Contract / Standard |
|---|---|---|
| **Deterministic Scope Enforcer** | [`ThreatswarmScopeEnforcer`](file:///Users/mamdouhaboammar/Documents/antigravity/silly-kepler/src/deep/threatswarm.rs#L91-L325) | CIDR (`10.0.0.0/8`, `192.168.1.0/24`), FQDN globbing, zero unauthorized egress |
| **CVSS 3.1 Scoring Engine** | [`CvssVector`](file:///Users/mamdouhaboammar/Documents/antigravity/silly-kepler/src/deep/threatswarm.rs#L375-L670), [`ThreatswarmCvssEngine`](file:///Users/mamdouhaboammar/Documents/antigravity/silly-kepler/src/deep/threatswarm.rs#L674-L715) | FIRST.org CVSS 3.1 Specification, ceiling roundup to 0.1, automated remediation SLAs |
| **MITRE ATT&CK Catalog** | [`ThreatswarmMitreCatalog`](file:///Users/mamdouhaboammar/Documents/antigravity/silly-kepler/src/deep/threatswarm.rs#L724-L800) | MITRE Enterprise ATT&CK tactics (TA0001–TA0040) and top techniques, automated CWE-to-TTP mapping |
| **Finding Synchronizer** | [`ThreatswarmFindingSync`](file:///Users/mamdouhaboammar/Documents/antigravity/silly-kepler/src/deep/threatswarm.rs#L806-L915) | Cross-subsystem deduplication of Critical/High findings, consolidated `FINDINGS_SUMMARY.md` |
| **Deep Engine Analyzer Adapter** | [`ThreatswarmAdapter`](file:///Users/mamdouhaboammar/Documents/antigravity/silly-kepler/src/deep/threatswarm.rs#L920-L1370) | [`AnalyzerAdapter`](file:///Users/mamdouhaboammar/Documents/antigravity/silly-kepler/src/engine/adapter.rs) schema v1.0, strongly-supported evidence receipts |

---

## 4-Phase Operational Workflow

### Phase 1: Scope Verification Preflight

Before initiating scans, external probes, or command evaluations, load the authorized boundaries:

```bash
# Load boundaries from standard scope.txt
bk engine run --goal threatswarm --profile deep --path .
```

The scope enforcer evaluates targets against:
1. **Loopback & Localhost:** Automatically permitted (`127.0.0.1`, `::1`, `localhost`, `0.0.0.0`).
2. **Explicit CIDR Ranges:** Bitmasked IPv4 subnets (e.g. `10.10.10.0/24`, `172.16.0.0/12`).
3. **Explicit FQDN & Wildcard Domains:** Exact host matches and authorized subdomains (e.g. `*.internal.corp`).
4. **Command Interception:** Evaluates CLI invocations for network tools (`curl`, `nmap`, `httpx`, `nc`) and halts execution if targets are out-of-scope.

### Phase 2: Deep Threat Analysis & ATT&CK Mapping

Static source files and configurations are inspected for boundary breaches and defensive degradations:
- **Rule `threatswarm.scope.unauthorized_egress`:** Flags hardcoded or dynamic outbound network calls to unauthorized IPs or external domain targets outside the allowlist.
- **Rule `threatswarm.defense.disabled_tls_validation`:** Flags disabled peer certificate validation (`rejectUnauthorized: false`, `verify=False`, `InsecureSkipVerify: true`).
- Each finding is correlated to MITRE ATT&CK techniques:
  - `CWE-78` / `CWE-77` $\to$ **T1059** (Command and Scripting Interpreter)
  - `CWE-89` / `CWE-943` $\to$ **T1190** (Exploit Public-Facing Application)
  - `CWE-918` $\to$ **T1190** & **T1046** (Network Service Discovery)
  - `CWE-295` $\to$ **T1562** (Impair Defenses)
  - `CWE-22` $\to$ **T1083** (File and Directory Discovery)

### Phase 3: CVSS 3.1 Base Scoring & SLA Triage

Findings are assigned standard CVSS 3.1 vectors with automated severity tiering and remediation SLA timers:

$$\text{BaseScore} = \text{roundup}\left(\min(\text{Impact} + \text{Exploitability}, 10.0)\right)$$

| Severity Tier | CVSS 3.1 Range | Remediation SLA | Escalation Target |
|---|---|---|---|
| **CRITICAL** | $9.0 - 10.0$ | **24 hours** | Immediate emergency patch, killswitch activation |
| **HIGH** | $7.0 - 8.9$ | **72 hours** | Sprint hotfix, virtual patch staging |
| **MEDIUM** | $4.0 - 6.9$ | **7 days** | Next scheduled release cycle |
| **LOW** | $0.1 - 3.9$ | **30 days** | Backlog remediation |

### Phase 4: Virtual Patch & Remediation Guidance

Virtual patches are authored and registered into the virtual patching pipeline:
1. Cryptographic SHA-256 digests computed for affected source spans.
2. Ed25519-signed rollback manifests recorded prior to mutation.
3. Remediation verification executed via red-green falsification testing.

---

## References & Documentation

- [MITRE ATT&CK Catalog Specification](file:///Users/mamdouhaboammar/Documents/antigravity/silly-kepler/.agents/skills/bk-threatswarm/references/mitre-attack.md)
- [CVSS 3.1 Scoring Reference & Formulas](file:///Users/mamdouhaboammar/Documents/antigravity/silly-kepler/.agents/skills/bk-threatswarm/references/cvss-reference.md)
- [Scope Enforcement Specification](file:///Users/mamdouhaboammar/Documents/antigravity/silly-kepler/.agents/skills/bk-threatswarm/references/scope-enforcement.md)
