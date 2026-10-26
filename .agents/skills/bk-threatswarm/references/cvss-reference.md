# CVSS v3.1 Scoring Engine Reference

## Mathematical Formulation

The base score calculation strictly implements the FIRST.org CVSS 3.1 specification.

### Exploitability Metric Subscore

$$\text{Exploitability} = 8.22 \times \text{AV} \times \text{AC} \times \text{PR} \times \text{UI}$$

Where numerical coefficients are assigned as follows:

| Metric | Level | Numerical Value |
|---|---|---|
| **Attack Vector (AV)** | Network | $0.85$ |
| | Adjacent | $0.62$ |
| | Local | $0.55$ |
| | Physical | $0.20$ |
| **Attack Complexity (AC)** | Low | $0.77$ |
| | High | $0.44$ |
| **Privileges Required (PR) [Scope Unchanged]** | None | $0.85$ |
| | Low | $0.62$ |
| | High | $0.27$ |
| **Privileges Required (PR) [Scope Changed]** | None | $0.85$ |
| | Low | $0.68$ |
| | High | $0.50$ |
| **User Interaction (UI)** | None | $0.85$ |
| | Required | $0.62$ |

### Impact Metric Subscore

$$\text{ISS} = 1 - (1 - \text{Impact}_C) \times (1 - \text{Impact}_I) \times (1 - \text{Impact}_A)$$

- For Scope Unchanged:
  $$\text{Impact} = 6.42 \times \text{ISS}$$
- For Scope Changed:
  $$\text{Impact} = 7.52 \times (\text{ISS} - 0.029) - 3.25 \times (\text{ISS} - 0.02)^{15}$$

### Base Score & Ceiling Roundup

$$\text{BaseScore} = \begin{cases}
0.0 & \text{if } \text{Impact} \le 0 \\
\text{roundup}\left(\min(\text{Impact} + \text{Exploitability}, 10.0)\right) & \text{if Scope Unchanged} \\
\text{roundup}\left(\min(1.08 \times (\text{Impact} + \text{Exploitability}), 10.0)\right) & \text{if Scope Changed}
\end{cases}$$

The `roundup` function computes the smallest decimal number with one decimal place greater than or equal to its input:

```rust
fn roundup(val: f64) -> f64 {
    let int_val = (val * 100_000.0).round() as i64;
    if int_val % 10_000 == 0 {
        (int_val as f64) / 100_000.0
    } else {
        (((int_val / 10_000) + 1) as f64) / 10.0
    }
}
```

## Canonical Prebuilt Weakness Vectors

| Weakness Pattern | Vector String | Score | Tier | SLA |
|---|---|---|---|---|
| **Pre-Auth RCE / PHP2Shell** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | **9.8** | Critical | 24h |
| **Changed Scope SSRF** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` | **10.0** | Critical | 24h |
| **SQL Injection (Authenticated)** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` | **8.1** | High | 72h |
| **Post-Auth RCE / Deserialization** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` | **8.8** | High | 72h |
| **IDOR / Object Reference** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` | **6.5** | Medium | 7d |
| **Local Privilege Escalation (LPE)** | `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` | **7.8** | High | 72h |
