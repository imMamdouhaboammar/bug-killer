# MITRE ATT&CK Enterprise Catalog Reference

This document catalogs the defensive TTP mappings enforced by the `bk-threatswarm` engine.

## Tactic & Technique Matrix

| Technique ID | Technique Name | Tactic | CWE Mapping | Detection Rule |
|---|---|---|---|---|
| **T1190** | Exploit Public-Facing Application | Initial Access | CWE-89, CWE-943, CWE-120, CWE-787 | `threatswarm.scope.unauthorized_egress` |
| **T1059** | Command and Scripting Interpreter | Execution | CWE-78, CWE-77, CWE-88 | `threatswarm.scope.unauthorized_egress` |
| **T1078** | Valid Accounts | Initial Access / Defense Evasion | CWE-798, CWE-259 | `threatswarm.identity.hardcoded_credential` |
| **T1003** | OS Credential Dumping | Credential Access | CWE-522, CWE-312 | `threatswarm.credential.dumping` |
| **T1021** | Remote Services | Lateral Movement | CWE-284, CWE-306 | `threatswarm.scope.unauthorized_egress` |
| **T1068** | Exploitation for Privilege Escalation | Privilege Escalation | CWE-269, CWE-732 | `threatswarm.privilege.escalation` |
| **T1055** | Process Injection | Defense Evasion / Privilege Escalation | CWE-119, CWE-787 | `threatswarm.process.injection` |
| **T1027** | Obfuscated Files or Information | Defense Evasion | CWE-116, CWE-117 | `threatswarm.payload.obfuscation` |
| **T1562** | Impair Defenses | Defense Evasion | CWE-295, CWE-778 | `threatswarm.defense.disabled_tls_validation` |
| **T1486** | Data Encrypted for Impact | Impact | CWE-732, CWE-284 | `threatswarm.ransomware.indicator` |
| **T1110** | Brute Force | Credential Access | CWE-307 | `threatswarm.auth.rate_limiting` |
| **T1046** | Network Service Discovery | Discovery | CWE-918 | `threatswarm.scope.unauthorized_egress` |
| **T1071** | Application Layer Protocol | Command and Control | CWE-918 | `threatswarm.scope.unauthorized_egress` |
| **T1083** | File and Directory Discovery | Discovery | CWE-22, CWE-23 | `threatswarm.traversal.directory` |
| **T1005** | Data from Local System | Collection | CWE-200, CWE-209 | `threatswarm.data.leakage` |

## Mapping Implementation

The mapping logic is implemented in [`ThreatswarmMitreCatalog::map_cwe`](file:///Users/mamdouhaboammar/Documents/antigravity/silly-kepler/src/deep/threatswarm.rs#L779-L800).
Findings automatically inherit TTP identifiers in their `extensions` metadata for SIEM/SOAR export.
