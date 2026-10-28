# DeepSec Triage & Severity Matrix

Every candidate finding processed by DeepSec undergoes deterministic triage scoring mapping into priority tiers: `P0`, `P1`, or `P2`.

## Severity Scoring Formula

The base priority score $S \in [0, 100]$ is computed deterministically:

$$S = 0.45 \cdot \text{Impact} + 0.35 \cdot \text{Exploitability} + 0.20 \cdot \text{Confidence} + \text{ExposureModifier}$$

Where:
- $\text{Impact} \in [0, 100]$: Severity of breach (RCE = 100, SQLi = 90, SSRF = 80, Auth Bypass = 85, Secrets = 75, XSS = 50).
- $\text{Exploitability} \in [0, 100]$: Unauthenticated remote network surface = 90; Authenticated admin-only = 40; Internal CLI = 20.
- $\text{Confidence} \in [0, 100]$: Model assessment score confirmed by secondary revalidation.
- $\text{ExposureModifier} \in [-20, +15]$: $+15$ if route is public Internet facing; $-20$ if test mock or fixture directory.

## Priority Thresholds

| Priority | Score Range | Action SLA | Description |
|---|---|---|---|
| **P0** | $S \ge 80$ | Immediate (24 hours) | Confirmed critical vulnerability directly exploitable on unauthenticated attack surface. |
| **P1** | $60 \le S < 80$ | Sprint (7 days) | High-severity issue requiring authenticated access or complex preconditions. |
| **P2** | $S < 60$ | Backlog (30 days) | Medium or low-severity hygiene finding, defense-in-depth weakness, or hardening opportunity. |

## Defensive Reporting Invariant

Every triage report must state:
1. Vulnerability classification (CWE identifier).
2. Exact source file and line span.
3. Verified failure scenario.
4. Remediation guidance.

Weaponized shellcode, exploitation scripts, or payload delivery instructions are strictly prohibited.
