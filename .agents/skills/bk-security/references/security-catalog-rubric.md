# Security Catalog & Vulnerability Classification Rubric

This reference defines the 27 rule categories, evidence certainty taxonomy, and reachability classifications enforced by Bug Killer (`bk`).

---

## 1. The 27 Security Rule Categories

Bug Killer indexes 373+ static and dynamic security rules across 27 distinct categories:

| Category ID | Category Name | Primary Sinks / Target Vectors |
|---|---|---|
| `CAT-01` | **Memory Corruption & Runtime** | Brotli decompression buffer overflows, stream corruption, unaligned pointers (`PHP2Shell`, `Node2Shell`). |
| `CAT-02` | **Command Injection** | `child_process.exec`, `system()`, `popen()`, `execve` with unsanitized arguments. |
| `CAT-03` | **SQL & NoSQL Injection** | String concatenation in raw SQL queries, unescaped ORM raw clauses, MongoDB operator injection. |
| `CAT-04` | **Path Traversal & LFI** | `fs.readFile`, `include`, `require` with untrusted file paths lacking directory canonicalization. |
| `CAT-05` | **Server-Side Request Forgery (SSRF)**| Unvalidated outgoing HTTP calls, access to link-local/cloud metadata (`169.254.169.254`). |
| `CAT-06` | **Cross-Site Scripting (XSS)** | Direct HTML echoing, `dangerouslySetInnerHTML`, unescaped template variables. |
| `CAT-07` | **Insecure Deserialization** | `unserialize()`, `pickle.loads()`, `yaml.load()` without safe loader schemas. |
| `CAT-08` | **Cryptographic Flaws** | Hardcoded IVs, ECB cipher mode, weak hashing (`MD5`, `SHA1` for passwords), small RSA keys. |
| `CAT-09` | **Hardcoded Secrets & Tokens** | High-entropy AWS, GitHub, Stripe, OpenAI, Resend tokens embedded in source. |
| `CAT-10` | **Authentication & Session Flaws** | Missing JWT expiration, `alg: none` acceptance, insecure session cookies without `HttpOnly`/`Secure`. |
| `CAT-11` | **Authorization & IDOR** | Missing tenancy checks, horizontal privilege escalation on entity lookups. |
| `CAT-12` | **XML External Entity (XXE)** | XML parsers with external entity resolution enabled. |
| `CAT-13` | **Container & Dockerfile Flaws** | Running as root user, unpinned base images, sensitive env leakage, `curl ... \| bash`. |
| `CAT-14` | **Reverse Proxy & WAF Gaps** | Nginx/Apache missing body size limits, disabled security headers, unmitigated chunked Brotli. |
| `CAT-15` | **SCA Vulnerable Dependencies** | Known CVEs in npm, Composer, PyPI, Cargo, Go modules matched via OSV.dev. |
| `CAT-16` | **Open Redirects** | Redirection based on unvalidated `?next=` or `?redirect=` query parameters. |
| `CAT-17` | **Denial of Service (ReDoS / Slowloris)**| Catastrophic backtracking in regular expressions, unbounded memory allocation in request handlers. |
| `CAT-18` | **CORS Misconfiguration** | Wildcard `Access-Control-Allow-Origin: *` paired with `Access-Control-Allow-Credentials: true`. |
| `CAT-19` | **Insecure File Uploads** | Missing MIME type validation, unauthenticated file upload endpoints, executable extensions. |
| `CAT-20` | **Template Injection (SSTI)** | Untrusted user input rendered directly into Jinja2, Twig, or Handlebars templates. |
| `CAT-21` | **AI Agent & Prompt Security** | MCP servers with unconstrained bash execution, unpinned agent skills, prompt injection. |
| `CAT-22` | **CI/CD Pipeline Security** | Untrusted PR triggers, script injection in GitHub Actions workflows, unpinned actions. |
| `CAT-23` | **Sensitive Data Exposure** | PII/credit card numbers logged in plain text, missing masking in error responses. |
| `CAT-24` | **Missing Security Headers** | Missing CSP, HSTS, X-Frame-Options, or X-Content-Type-Options. |
| `CAT-25` | **Race Conditions (TOCTOU)** | Time-of-check to time-of-use filesystem or database concurrency flaws. |
| `CAT-26` | **Mass Assignment / Parameter Tampering**| Direct request payload binding to database ORM models without field filtering. |
| `CAT-27` | **Insecure Direct Object Reference** | Resource fetching without checking caller ownership or organizational boundary. |

---

## 2. Classification Matrix: Certainty x Reachability

```
                       REACHABILITY
                 Reachable    Unknown    Unreachable
             +-------------+-----------+-------------+
 Confirmed   |  ACTION: P0 | ACTION: P1|  ACTION: P3 |
  Affected   |  Immediate  | Prioritize|  Deprecate  |
             +-------------+-----------+-------------+
CERTAINTY    |  ACTION: P1 | ACTION: P2|  ACTION: P4 |
 Potentially |  Investigate| Audit AST |  Monitor    |
  Affected   +-------------+-----------+-------------+
             |  ACTION: P3 | ACTION: P4|  ACTION: P5 |
  Unknown    |  Fuzz/Taint | Backlog   |  Ignore     |
             +-------------+-----------+-------------+
```

- **P0 Findings (`ConfirmedAffected` + `Reachable`)**: Must be resolved immediately before deploying.
- **P1 Findings**: High priority investigation.
- **P3-P5 Findings**: Informational or guarded sinks.
