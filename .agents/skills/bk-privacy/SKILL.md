---
name: bk-privacy
description: >
  Autonomous privacy compliance, data protection audit, and LINDDUN threat modeling engine powered by Bug Killer (bk).
  Guides agents on auditing codebases for GDPR, CCPA/CPRA, HIPAA, EU AI Act, LINDDUN, ISO 27701, and NIST Privacy Framework
  compliance. References 282 embedded privacy procedures in src/deep/privacy_skills_data.json and authoritative cross-reference matrices
  in docs/privacy/. Use when evaluating privacy risks, auditing PII ingestion into AI models, verifying DSAR routes,
  validating storage limitations, or applying cryptographic virtual patches for privacy deficiencies.
---

# Bug Killer Privacy: Autonomous Privacy & Data Protection Engine

Autonomous privacy compliance auditor, LINDDUN threat modeler, and data protection virtual healer.

```
+-----------------------------------------------------------------------------------+
|                        BUG KILLER (bk) PRIVACY ENGINE                             |
+-----------------------------------------------------------------------------------+
| Pre-Flight        | Verify binary handle ($BK_BIN) and PrivacySkillsRegistry.     |
| Regulations       | GDPR | CCPA/CPRA | HIPAA | EU AI Act | ISO 27701 | NIST PF     |
| Threat Modeling   | LINDDUN (Linkability, Identifiability, Non-repudiation, etc.) |
| Deep Analysis     | CPG Inter-procedural Taint Flow + AST Regulatory Matchers      |
| Privacy Catalog   | 282 Embedded Procedures across OWASP Privacy Risks P1-P10      |
| Remediation       | PII Redaction, Field Encryption, DSAR Guards, HITL Oversight   |
+-----------------------------------------------------------------------------------+
```

---

## 1. Architectural Scope & Framework Mappings

The Bug Killer Deep Privacy Engine incorporates 282 canonical privacy procedures embedded in `src/deep/privacy_skills_data.json` (the `skills/privacy/` source directory has been retired; `src/deep/privacy.rs` embeds the JSON at compile time) and mapped to international standards in `docs/privacy/`:

| Framework | Scope & Focus Areas | Authoritative Reference |
|---|---|---|
| **OWASP Privacy Risks** | P1 (Web Telemetry) to P10 (AI Dark Patterns) | [`docs/privacy/owasp-privacy-risks-mapping.md`](file:///Users/mamdouhaboammar/Documents/antigravity/silly-kepler/docs/privacy/owasp-privacy-risks-mapping.md) |
| **NIST Privacy Framework** | Identify-P, Govern-P, Control-P, Communicate-P, Protect-P | [`docs/privacy/nist-privacy-framework-mapping.md`](file:///Users/mamdouhaboammar/Documents/antigravity/silly-kepler/docs/privacy/nist-privacy-framework-mapping.md) |
| **ISO/IEC 27701:2019** | PIMS Controllers (Clause 7) & Processors (Clause 8) | [`docs/privacy/iso-27701-mapping.md`](file:///Users/mamdouhaboammar/Documents/antigravity/silly-kepler/docs/privacy/iso-27701-mapping.md) |
| **LINDDUN GO** | Unlinkability, Anonymity, Plausible Deniability, Confidentiality | Embedded LINDDUN index in `PrivacySkillsRegistry` |
| **EU AI Act & GDPR** | High-risk AI human oversight (Art. 14), Automated decisions (Art. 22) | Automated decision AST matchers in `PrivacyEngineAdapter` |

---

## 2. Core Operational Workflow

### Phase 1: Privacy Guidance & Threat Modeling
Before developing or modifying code handling personal data, query the registry for applicable privacy procedures:

```bash
# Query privacy skills for specific regulatory checks or topics
bk privacy search "LLM prompt data minimization"
bk privacy search "DSAR deletion route"
bk privacy search "HIPAA Safe Harbor"
```

Or programmatically query the Rust API:
```rust
use bug_killer::deep::PrivacySkillsRegistry;

let registry = PrivacySkillsRegistry::default_embedded();
let matches = registry.search_by_keyword("anonymization");
let skills_for_check = registry.recommend_for_check("BK-AI-PRIV-002");
```

### Phase 2: Deep Privacy Codebase Scan
Execute deep analysis combining static regulatory pattern checks and Code Property Graph (CPG) dataflow taint tracing:

```bash
# Full deep privacy audit
bk scan --profile deep --target .

# JSON output for automated CI/CD gating
bk scan --profile deep --format json > privacy-report.json
```

The Deep Privacy Engine runs through `EngineRegistry` under `ScanProfile::Deep` (isolated from fast pre-commit checks) to perform comprehensive inter-procedural flow analysis.

### Phase 3: Rule Catalog & Detection Matrix

The engine enforces 10 primary automated privacy checks:

| Check ID | Regulatory Citation | Description | Severity |
|---|---|---|---|
| `BK-AI-PRIV-001` | GDPR Art. 32 / PCI DSS | Direct PII in Unencrypted Database Column / Model | High |
| `BK-AI-PRIV-002` | EU AI Act Art. 10 / GDPR Art. 5 | Unredacted PII Ingestion into LLM / External AI Service | High |
| `BK-AI-PRIV-003` | GDPR Art. 5(1)(c) | Sensitive Data Infiltration via Telemetry / Log Dumps | Medium |
| `BK-AI-PRIV-004` | GDPR Art. 5(1)(e) | Indefinite Storage Limitation / Missing Retention Expiration | High |
| `BK-AI-PRIV-005` | GDPR Art. 17 / CCPA § 1798.105 | DSAR Export or Erasure Route Authorization Bypass | High |
| `BK-AI-PRIV-006` | GDPR Art. 7(3) | Consent Revocation Mechanism Omission | Medium |
| `BK-AI-PRIV-007` | GDPR Art. 44 / Schrems II | Cross-Border Transfer without Adequate Safeguards (SCC) | High |
| `BK-AI-PRIV-008` | HIPAA 45 CFR § 164.514 | HIPAA Un-Deidentified Protected Health Information Exposure | Critical |
| `BK-AI-PRIV-009` | EU AI Act Art. 14 / GDPR Art. 22 | Autonomous High-Risk Decision Without Human Oversight | Critical |
| `BK-AI-PRIV-010` | GDPR Art. 33 | Security Incident Response Lacks 72-Hour Regulatory Notification | High |

---

## 3. Dataflow Taint Tracking & Sanitizers

The CPG engine tracks untrusted sensitive PII from source ingestion points to external sinks (e.g. OpenAI/Anthropic APIs, telemetry loggers, remote endpoints). 

Taint chains are marked **Confirmed** only when sanitizers are absent. The following functions act as approved sanitizers that obstruct taint flow:
- Cryptographic hashing: `sha256`, `sha512`, `bcrypt`, `argon2`, `hashSync`
- Encryption: `encrypt`, `aesEncrypt`, `encryptField`, `crypto.subtle.encrypt`
- Redaction / Masking: `redact`, `redactPii`, `maskSsn`, `maskCreditCard`, `anonymize`
- Privacy Preserving: `differentialPrivacy`, `laplaceNoise`, `tokenize`, `deidentify_hipaa`

---

## 4. Remediation & Virtual Patching

All privacy findings contain machine-actionable remediation recipes registered in `rules/vulnerabilities.json` and `src/catalog/catalog_data.json`. Virtual patches are cryptographically signed with the agent's Ed25519 identity key and can be rolled back bit-for-bit at zero risk.
