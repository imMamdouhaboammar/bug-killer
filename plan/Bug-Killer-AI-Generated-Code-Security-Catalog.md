# Bug Killer: AI-Generated Code Security Issues Catalog

> [!NOTE]
> **Historical Planning Artifact (Tier 3):** This catalog represents an initial October 2026 taxonomy planning document. For active implementation and runtime architecture, consult the [Documentation Map](../docs/DOCUMENTATION_MAP.md) and [lat.md Knowledge Graph](../lat.md/architecture.md).

**Version:** 1.0 | **Date:** 2026-10-24 | **Type:** Defensive detection requirements / living test catalog  
**Target:** [bug-killer](https://github.com/imMamdouhaboammar/bug-killer) | **Audience:** Rust/Go scanner implementers, reviewers, CI maintainers, model-agnostic security agents.

> **Core rule:** This is a prioritized inventory of security failure modes frequently possible in AI-assisted development, **not** a statement that only AI writes these bugs, a statistical ranking of their occurrence, or proof that every class can be detected by automation. A passing scan means that specified checks completed within declared scope. It never means a system is free from all vulnerabilities.

## 1. The security verification contract

For each applicable item in this catalog, Bug Killer should produce a verifiable rule/result record, not a generic AI judgment:

```yaml
rule_id: "BK-AI-INJ-001"
rule_version: "1.0"
category: "Injection"
cwe: "CWE-89"
target: "repository-relative-path-or-authorized-asset-id"
applicability: "APPLICABLE | NOT_APPLICABLE | UNKNOWN"
execution: "NOT_RUN | RUNNING | COMPLETED | PARTIAL | FAILED | BLOCKED"
verdict: "CONFIRMED | SUSPECTED | NO_FINDING_IN_COVERAGE | NOT_ASSESSED"
evidence_kind: "FLOW | AST | CONFIG | SCA | SECRET | TEST | DAST | FUZZ | REVIEW | AGENT"
evidence: "redacted source->sink trace, test receipt, or authoritative configuration location"
limitations: "unexamined paths, dynamic language features, missing dependencies, unavailable network"
severity: "case-specific; never inferred from keyword alone"
remediation: "bounded invariant to restore"
verification: "security negative test plus functional regression proof"
```

### Evidence method legend

| Code | Meaning | What it can and cannot prove |
| --- | --- | --- |
| `FLOW` | Syntax/semantic source-to-sink dataflow | Shows possible tainted reachability in supported language/framework subset; not by itself a working exploit |
| `AST` | Language-aware source/pattern/config analysis | Detects constructs or missing local controls; can miss indirect flows and business context |
| `CONFIG` | Configuration/IaC/workflow policy checks | Proves configuration state in inspected files, not deployed drift |
| `SCA` | SBOM/lockfile inventory + vendor/OSV advisories | Requires accurate installed version, platform, advisory range and complete lookup |
| `SECRET` | Secret/PII and credential hygiene with redaction | Matches possible secrets, never prints values; must check exposure/rotation separately |
| `TEST` | Offline executable positive/negative security fixture | Proves the property under tested conditions and tenant/role variants only |
| `DAST` | Explicitly authorized, low-impact endpoint observation | Verifies live behavior for scoped hosts only; remote targets are not auto-authorized |
| `FUZZ` | Sandboxed local parser/component fuzzing | Finds crash/logic issues in the exercised harness, not comprehensive safety |
| `REVIEW` | Human threat model, design and business-rule review | Required when roles, asset value or threat prerequisites cannot be inferred |
| `AGENT` | Tool graph, privilege policy, approval-state and prompt-boundary validation | Checks actual tool permissions and denied-action fixtures, not model promises |

**Priority semantics:** `P0` means start with this family for a security gate; it does not mean every instance is automatically critical. `P1` is next implementation wave; `P2` requires additional platform/context. The per-finding severity is assigned after reachability, attacker control, mitigations and impact are evaluated. `N/A`, `UNKNOWN`, `PARTIAL` and `ERROR` must never silently become a PASS.

**Rule ID:** Add `BK-AI-` before each table ID below. Stable IDs permit one-to-one tests, suppression with expiry, and evidence tracking. Methods are recommended detection routes; every row needs a true-positive fixture, a near-miss false-positive fixture, and a failure/unsupported receipt before shipping as a claimed rule.

## 2. Master issue inventory

### 2.1 Injection and interpreter boundaries [P0]

| ID | AI-generated code failure to check | CWE | Method / security proof target |
| --- | --- | --- | --- |
| INJ-001 | SQL constructed by string concatenation/interpolation of untrusted values | CWE-89 | FLOW+TEST: query values are parameterized |
| INJ-002 | Dynamic SQL identifiers, ordering, or table names without a finite allowlist | CWE-89 | FLOW+REVIEW: identifier selection cannot become arbitrary SQL |
| INJ-003 | Shell command built from user-controlled data | CWE-78 | FLOW+TEST: no shell interpreter or argument injection |
| INJ-004 | Command-line argument injection despite use of a subprocess argument array | CWE-88 | FLOW+TEST: untrusted input cannot become a command option |
| INJ-005 | OS command execution via helper/wrapper/library omitted from basic grep rules | CWE-78 | FLOW: all configured sink aliases included |
| INJ-006 | JavaScript `eval`, `new Function`, dynamic `vm` execution of untrusted content | CWE-94 | FLOW+REVIEW: no untrusted code execution path |
| INJ-007 | Python `eval`/`exec` or generated Python script from untrusted input | CWE-94 | FLOW+TEST: no execution of attacker-controlled code |
| INJ-008 | Server-side template expressions compiled from user data | CWE-1336 | FLOW+TEST: template is fixed; data stays data |
| INJ-009 | Template escape bypass (`safe`, raw output) applied to untrusted values | CWE-79 | FLOW+TEST: context-appropriate encoding at sink |
| INJ-010 | XPath/XQuery expression assembled from inputs | CWE-643 | FLOW+TEST: untrusted values cannot change query structure |
| INJ-011 | LDAP filter/DN assembled without context-specific escaping | CWE-90 | FLOW+TEST: LDAP grammar preserved |
| INJ-012 | NoSQL query/operator injection from user-controlled objects | CWE-943 | FLOW+TEST: inputs cannot introduce operators or predicates |
| INJ-013 | CRLF injection into HTTP response headers or logs | CWE-113 | FLOW+TEST: line terminators rejected or safely encoded |
| INJ-014 | YAML/config/CI expression interpreted from uncontrolled strings | CWE-94 | FLOW+CONFIG: data not evaluated as executable expression |
| INJ-015 | Untrusted regular expression or unsafe pattern susceptible to ReDoS | CWE-1333 | AST+FUZZ: regex source and worst-case input bounds verified |
| INJ-016 | Trusting generic `sanitize()` or `escape()` without checking target context | CWE-116 | FLOW+TEST: sanitizer appropriate to exact sink, charset and decoding order |

### 2.2 Authentication and account lifecycle [P0]

| ID | Failure to check | CWE | Method / proof |
| --- | --- | --- | --- |
| AUT-001 | Protected route lacks server-side authentication | CWE-306 | AST+TEST: unauthenticated requests denied |
| AUT-002 | Middleware bypass through alternate HTTP method, path or transport | CWE-288 | TEST+REVIEW: all equivalent entrypoints enforce identity |
| AUT-003 | `isAuthenticated` stub, always-true mock or demo login remains in release | CWE-287 | AST+TEST: production auth cannot be bypassed |
| AUT-004 | Passwords stored in plaintext, reversible encryption or fast unsalted hashes | CWE-256 | AST+REVIEW: approved password KDF with unique salt used |
| AUT-005 | Password reset token is guessable, reusable, not expiring or not bound to user | CWE-640 | TEST: randomness, expiry, one-time use and binding proven |
| AUT-006 | Email/phone change does not require appropriate fresh verification | CWE-620 | TEST+REVIEW: sensitive account changes revalidated |
| AUT-007 | No abuse throttling for sign-in, recovery, OTP or invite issuance | CWE-307 | CONFIG+TEST: bounded attempts without easy bypass |
| AUT-008 | MFA disabled for sensitive administrative actions or weak step-up logic | CWE-308 | REVIEW+TEST: privilege transitions require approved factors |
| AUT-009 | Fail-open login/auth service timeout or exception | CWE-754 | AST+TEST: identity denied when verifier unavailable |
| AUT-010 | Authentication relies on client-side JS, hidden button or route guard alone | CWE-602 | AST+TEST: backend independently rejects unauthorized calls |
| AUT-011 | Untrusted JWT claims used before signature/issuer/audience/expiry verification | CWE-347 | AST+TEST: all verification prerequisites enforced |
| AUT-012 | OAuth/OIDC state, nonce, PKCE or callback/redirect checks omitted where required | CWE-346 | AST+TEST: replay, substitution and redirect binding blocked |

### 2.3 Authorization, tenant isolation and privilege [P0]

| ID | Failure to check | CWE | Method / proof |
| --- | --- | --- | --- |
| AZ-001 | IDOR/BOLA: object ID accepted without per-object ownership check | CWE-639 | FLOW+TEST: cross-user access denied |
| AZ-002 | Tenant ID read from body/query/header and trusted without session-bound scope | CWE-863 | FLOW+TEST: tenant scope derived from trusted identity |
| AZ-003 | User can edit server-owned fields (`role`, `owner`, `isAdmin`, `price`) via mass assignment | CWE-915 | AST+TEST: writable field allowlist enforced |
| AZ-004 | Backend function/admin route lacks role/capability enforcement | CWE-862 | AST+TEST: lower roles denied every privileged operation |
| AZ-005 | Authorization checked only in UI, gateway or frontend cache | CWE-602 | REVIEW+TEST: enforcement exists at sensitive side effect |
| AZ-006 | GraphQL nested resolver bypasses parent object/field-level policy | CWE-863 | AST+TEST: nested fields respect caller scope |
| AZ-007 | Batch APIs authorize first object but not each element | CWE-863 | TEST: unauthorized list members denied or redacted |
| AZ-008 | Background job/queue trusts caller-provided role instead of rechecking | CWE-863 | REVIEW+TEST: revalidation at worker execution time |
| AZ-009 | Webhook/event handler assumes event payload identity implies permission | CWE-862 | REVIEW+TEST: resource ownership checked after authenticity |
| AZ-010 | Export/report/download endpoint omits tenancy filtering | CWE-200 | FLOW+TEST: tenant-isolated output verified |
| AZ-011 | Admin service token reused for normal user request path | CWE-250 | CONFIG+REVIEW: least-privileged caller-specific capability |
| AZ-012 | Default role includes privileged permissions or deny rule omitted | CWE-276 | CONFIG+TEST: deny-by-default policy |
| AZ-013 | Check-then-act privilege check races with ownership/role changes | CWE-367 | REVIEW+TEST: atomic or revalidated authorization |
| AZ-014 | Search, cache, vector index or metrics layer leaks cross-tenant objects | CWE-200 | TEST+REVIEW: tenant scope bound to every read path |

### 2.4 Sessions, tokens, cookies and browser login [P0]

| ID | Failure to check | CWE | Method / proof |
| --- | --- | --- | --- |
| SES-001 | Session ID predictable or generated with non-cryptographic randomness | CWE-330 | AST+TEST: CSPRNG and entropy policy verified |
| SES-002 | Session not rotated after authentication or privilege change | CWE-384 | TEST: fixation state invalidated |
| SES-003 | Logout/password reset fails to invalidate server-side session/refresh token | CWE-613 | TEST: old token rejected after revocation |
| SES-004 | Cookie carrying session lacks `Secure` where HTTPS is required | CWE-614 | CONFIG+DAST: observed attributes correct |
| SES-005 | Cookie carrying session lacks `HttpOnly` without justified JS access | CWE-1004 | CONFIG+DAST: observed attributes correct |
| SES-006 | `SameSite`/CSRF defense missing on relevant browser-driven state changes | CWE-352 | CONFIG+TEST: cross-site request rejected |
| SES-007 | Token lifetime too long or unlimited reusable refresh token | CWE-613 | AST+REVIEW: expiry/rotation/replay properties defined |
| SES-008 | JWT algorithm confusion, `none`, or attacker-controlled key locator | CWE-347 | AST+TEST: accepted algorithms/keys pinned |
| SES-009 | Token logged, embedded in URL/query, analytics, referrer or browser history | CWE-598 | FLOW+SECRET: credentials do not enter exposed channels |
| SES-010 | LocalStorage/sessionStorage holds long-lived sensitive credentials without threat review | CWE-922 | AST+REVIEW: browser compromise model and storage choice reviewed |
| SES-011 | Session not scoped by environment, domain, audience or device policy | CWE-284 | REVIEW+TEST: session scope enforced |
| SES-012 | Concurrent refresh calls permit token reuse/race or stale session resurrection | CWE-362 | TEST: replay and concurrent transition safe |

### 2.5 Browser, UI and frontend code [P0/P1]

| ID | Failure to check | CWE | Method / proof |
| --- | --- | --- | --- |
| WEB-001 | DOM XSS through `innerHTML`, `dangerouslySetInnerHTML` or equivalent | CWE-79 | FLOW+TEST: untrusted text cannot become markup/code |
| WEB-002 | Stored or reflected XSS on server-rendered HTML without contextual escaping | CWE-79 | FLOW+TEST: sink context is encoded |
| WEB-003 | HTML sanitization relies only on regex/blacklist | CWE-79 | AST+TEST: vetted sanitizer and policy used when rich HTML required |
| WEB-004 | Client-side URL navigation/open redirects to attacker-controlled hosts | CWE-601 | FLOW+TEST: destination allowlist and normalization |
| WEB-005 | `postMessage` handlers lack origin/source and schema validation | CWE-346 | AST+TEST: untrusted origins cannot issue privileged actions |
| WEB-006 | Sensitive data placed into frontend bundle/source map/runtime config | CWE-200 | SECRET+CONFIG: public artifacts contain no protected data |
| WEB-007 | CSRF-sensitive mutations are exposed via unsafe GET routes | CWE-352 | AST+TEST: state mutations require protected method + CSRF policy |
| WEB-008 | CSP absent/over-permissive on relevant HTML application contexts | CWE-693 | CONFIG+DAST: policy covers target sinks; false positives context-aware |
| WEB-009 | Third-party JS included without provenance, pinning or integrity review | CWE-829 | SCA+CONFIG: external scripts governed |
| WEB-010 | Unsafe iframe embedding/clickjacking protection omitted where relevant | CWE-1021 | CONFIG+DAST: framing policy matches product embedding requirements |
| WEB-011 | CORS reflects any origin while allowing credentials | CWE-942 | CONFIG+TEST: allowlist and credential semantics verified |
| WEB-012 | Credentials/tokens passed through client telemetry and error tracking | CWE-532 | FLOW+SECRET: redaction at event source |
| WEB-013 | File download URL/object link exposes private content without authz | CWE-200 | TEST: access to download resource independently checked |
| WEB-014 | Service worker/cache stores private responses accessible across accounts | CWE-525 | REVIEW+TEST: user/logout and cache partitions safe |
| WEB-015 | SSR/hydration payload serializes PII or privileged server state | CWE-200 | FLOW+TEST: public page content redacted |

### 2.6 HTTP APIs, GraphQL, gRPC and realtime [P0/P1]

| ID | Failure to check | CWE | Method / proof |
| --- | --- | --- | --- |
| API-001 | Request body/field validation only occurs in UI | CWE-20 | AST+TEST: server enforces type, length, shape, enum |
| API-002 | Unknown/extra fields accepted into privileged model without allowlist | CWE-915 | AST+TEST: reject or strip unauthorized fields |
| API-003 | No per-actor rate/size limit on expensive API operations | CWE-770 | CONFIG+TEST: bounded usage by identity/tenant |
| API-004 | GraphQL depth, complexity or introspection exposure lacks threat-appropriate control | CWE-400 | CONFIG+TEST: bounded query cost; deliberate schema exposure |
| API-005 | WebSocket upgrade/authentication checked once, not per message or room | CWE-862 | REVIEW+TEST: membership and operations rechecked |
| API-006 | gRPC metadata/auth interceptors omit service or streaming methods | CWE-306 | AST+TEST: all privileged RPC paths gated |
| API-007 | Pagination/filtering can enumerate data outside tenant/user scope | CWE-200 | FLOW+TEST: scoped query enforced |
| API-008 | Webhook request lacks sender authentication, replay controls or trusted event mapping | CWE-345 | CONFIG+TEST: signature, timestamp and replay as applicable |
| API-009 | Third-party API credentials forwarded to clients or wrong upstream | CWE-201 | FLOW+TEST: tokens restricted to intended backend |
| API-010 | HTTP method override or content-type ambiguity bypasses validation | CWE-20 | TEST: equivalent encodings and verbs protected |
| API-011 | Cached privileged API response served across users or tenants | CWE-524 | CONFIG+TEST: cache key/scope and `Cache-Control` correct |
| API-012 | Remote service errors returned with sensitive traces, connection strings or headers | CWE-209 | FLOW+TEST: caller sees bounded error details |
| API-013 | Server-to-server trust relies only on obscurity/private network | CWE-306 | REVIEW+TEST: explicit service authentication/authorization |
| API-014 | Subscription/event stream can consume other principals' updates | CWE-200 | TEST: per-topic/channel permission enforced |

### 2.7 Filesystem, uploads, archives and path traversal [P0]

| ID | Failure to check | CWE | Method / proof |
| --- | --- | --- | --- |
| FIL-001 | User-controlled path escapes permitted root after normalization | CWE-22 | FLOW+TEST: canonical containment checked |
| FIL-002 | Symlink or hardlink bypasses path restriction | CWE-59 | TEST: no traversal after link resolution |
| FIL-003 | Zip/Tar extraction writes outside destination (Zip Slip) | CWE-22 | AST+TEST: archive members independently constrained |
| FIL-004 | Unsafe archive decompression creates resource exhaustion (zip bomb) | CWE-400 | FUZZ+TEST: decompressed size/item/time limits enforced |
| FIL-005 | Uploaded file extension trusted as content type or executable disposition | CWE-434 | FLOW+TEST: content/magic/storage policy validated |
| FIL-006 | User upload stored in executable/public directory with unsafe permissions | CWE-434 | CONFIG+TEST: isolated non-executable storage |
| FIL-007 | Filename allows path separators, control chars or Unicode normalization escape | CWE-22 | TEST: normalized safe generated storage identity |
| FIL-008 | Temporary file predictable or opened insecurely | CWE-377 | AST+TEST: secure creation/permissions |
| FIL-009 | Insecure temporary/backup files persist secrets or become publicly readable | CWE-552 | CONFIG+SECRET: permissions and lifecycle verified |
| FIL-010 | Unsafe file overwrite, truncation or deletion from arbitrary user-supplied path | CWE-73 | FLOW+TEST: explicit authorized target set |
| FIL-011 | TOCTOU between file validation and opening/replacement | CWE-367 | REVIEW+TEST: atomic or handle-based enforcement |
| FIL-012 | Files served/downloaded without proper per-object authorization | CWE-639 | TEST: tenant/user request isolation |
| FIL-013 | Uploaded SVG/HTML/PDF rendered inline without appropriate isolation | CWE-79 | CONFIG+TEST: response disposition/sandbox policy |
| FIL-014 | File parser accepts unbounded content/recursive structure | CWE-400 | FUZZ+TEST: byte, nesting, CPU and memory limits |

### 2.8 SSRF, outbound HTTP and network trust [P0]

| ID | Failure to check | CWE | Method / proof |
| --- | --- | --- | --- |
| NET-001 | Arbitrary user-provided URL used by server HTTP client | CWE-918 | FLOW+TEST: allowed scheme/host/port constrained |
| NET-002 | IP literals, alternate encoding, IPv6 or DNS result bypass destination policy | CWE-918 | TEST: resolved destination validated |
| NET-003 | Redirect follows from allowed host to disallowed private/metadata address | CWE-918 | TEST: every redirect hop reauthorized |
| NET-004 | DNS rebinding changes resolved address between check and connection | CWE-918 | TEST+REVIEW: connected peer constrained |
| NET-005 | Non-HTTP URL scheme or local file scheme accepted by fetcher | CWE-918 | AST+TEST: strict supported scheme list |
| NET-006 | Proxy settings or environment bypass network egress policy | CWE-918 | CONFIG+TEST: proxy route respects scope |
| NET-007 | TLS certificate verification disabled, including in debug fallback | CWE-295 | AST+TEST: certificate/hostname verification required |
| NET-008 | TLS trust pinned incorrectly, stale CA handling or hardcoded accept-all certificate callback | CWE-295 | AST+REVIEW: identity and certificate policy sound |
| NET-009 | Secret-bearing headers forwarded across redirect or unrelated origin | CWE-201 | FLOW+TEST: origin-bound credentials |
| NET-010 | Network calls have no deadline, response cap or concurrency bound | CWE-400 | AST+TEST: time/size/resource limits enforced |

### 2.9 Cryptography, randomness and key management [P0/P1]

| ID | Failure to check | CWE | Method / proof |
| --- | --- | --- | --- |
| CRY-001 | Password hashes use MD5/SHA1/plain SHA or reversible encryption | CWE-916 | AST+REVIEW: approved password KDF |
| CRY-002 | Predictable token/nonce/OTP/password reset values | CWE-330 | AST+TEST: cryptographic RNG used |
| CRY-003 | Custom invented crypto or homegrown cipher/protocol | CWE-327 | AST+REVIEW: vetted primitives/protocol |
| CRY-004 | ECB or unauthenticated encryption used where authenticity is required | CWE-327 | AST+REVIEW: AEAD or approved authenticated construction |
| CRY-005 | Static/duplicated nonce, IV misuse or key+nonce reuse | CWE-329 | AST+TEST: nonce uniqueness enforced |
| CRY-006 | Hard-coded private key, salt-as-secret or symmetric key | CWE-321 | SECRET+CONFIG: managed secret storage and rotation |
| CRY-007 | Key/certificate expiration, rotation, revocation not handled | CWE-324 | REVIEW+TEST: lifecycle proof |
| CRY-008 | Insecure deterministic equality/hash used to sign/authorize requests | CWE-347 | AST+TEST: authenticated signature/MAC with correct key |
| CRY-009 | Signature checked over different canonical bytes than consumed | CWE-345 | REVIEW+TEST: canonical binding to actual action/body |
| CRY-010 | Comparison of secret token/signature leaks through timing | CWE-208 | AST+TEST: constant-time compare on relevant secret bytes |
| CRY-011 | Unsafe TLS downgrade or obsolete protocol/cipher config | CWE-326 | CONFIG+DAST: deployed policy verified where authorized |
| CRY-012 | Sensitive data encrypted but associated metadata/tenant binding omitted | CWE-347 | REVIEW+TEST: tampering/cross-context misuse denied |

### 2.10 Secrets, privacy, PII and data exposure [P0]

| ID | Failure to check | CWE | Method / proof |
| --- | --- | --- | --- |
| SEC-001 | API key, bearer token, SSH key or password embedded in source | CWE-798 | SECRET: redact values; report location and credential class |
| SEC-002 | Secret present in `.env.example`, test fixtures, notebooks or screenshots | CWE-200 | SECRET: fingerprint only, no raw echo |
| SEC-003 | Secret already committed to Git history but removed from HEAD | CWE-200 | SECRET+REVIEW: historical exposure evaluated, rotation required if genuine |
| SEC-004 | `.env`, config, keys, dump, backup or private source shipped under public web root | CWE-552 | CONFIG+TEST: no public artifact exposure |
| SEC-005 | Environment variables, request/response payload or stack trace dumped verbatim | CWE-532 | FLOW+TEST: logging redaction by boundary |
| SEC-006 | Sensitive PII in metrics tags, trace spans, queue attributes or analytics | CWE-200 | FLOW+REVIEW: telemetry data minimized |
| SEC-007 | Unnecessary collection/storage/retention of sensitive user data | CWE-359 | REVIEW: data inventory, purpose, retention policy |
| SEC-008 | Data export/deletion workflows omit authorized ownership verification | CWE-639 | TEST: principal and object rights proven |
| SEC-009 | Encryption-at-rest missing for required regulated/sensitive datasets | CWE-311 | CONFIG+REVIEW: data classification determines control |
| SEC-010 | Secret appears in client bundle, image layer, IaC state or build cache | CWE-200 | SECRET+CONFIG: final artifacts and history checked |
| SEC-011 | Third-party analytics or AI provider receives confidential data without policy | CWE-201 | FLOW+REVIEW: consent/contract/data boundary defined |
| SEC-012 | Reports and AI-agent tool replies contain raw secrets/exploit payload material | CWE-532 | TEST+AGENT: redaction with bounded evidence preview |

### 2.11 Database, storage, search and persistence [P0/P1]

| ID | Failure to check | CWE | Method / proof |
| --- | --- | --- | --- |
| DAT-001 | Database connection uses superuser/owner credentials for normal app operations | CWE-250 | CONFIG+REVIEW: least-privilege roles |
| DAT-002 | Database row-level security configured but bypassed by service role | CWE-863 | CONFIG+TEST: server roles and every query path scoped |
| DAT-003 | Query returns all rows and filters tenant in application memory | CWE-200 | FLOW+TEST: tenant filter enforced before access |
| DAT-004 | DB schema/seed inserts default admin credentials | CWE-798 | AST+SECRET: credentials cannot ship in deployment |
| DAT-005 | Database backup/snapshot stored publicly or without access restrictions | CWE-552 | CONFIG: protection and retention audited |
| DAT-006 | Concurrent balance/state mutation without transaction/lock invariant | CWE-362 | TEST: atomic financial/ownership updates |
| DAT-007 | Search index, embedding retrieval or cache bypasses permissions | CWE-863 | TEST: read path enforces tenant and document ACL |
| DAT-008 | ORM raw query escaping assumed but interpolated fragments remain | CWE-89 | FLOW+TEST: raw fragments controlled |
| DAT-009 | Migration drops constraints, audit trigger or uniqueness required for security | CWE-284 | AST+TEST: invariants retained |
| DAT-010 | Unsafe dynamic table/collection chosen from caller input | CWE-89 | FLOW+REVIEW: finite allowed target set |
| DAT-011 | Storage object ACL/public bucket used for private content | CWE-732 | CONFIG+TEST: object-level rights enforced |
| DAT-012 | Sensitive records survive deletion/revocation through materialized views/caches | CWE-212 | REVIEW+TEST: lifecycle/cascade proof |

### 2.12 Parsers, serialization and content handling [P0/P1]

| ID | Failure to check | CWE | Method / proof |
| --- | --- | --- | --- |
| PAR-001 | Python pickle or other executable object deserialization from untrusted bytes | CWE-502 | FLOW+TEST: safe data-only decoder used |
| PAR-002 | YAML unsafe loader constructs arbitrary objects | CWE-502 | AST+TEST: safe loader and allowed types |
| PAR-003 | Java/.NET/Ruby/PHP object deserialization permits gadgets/unsafe types | CWE-502 | FLOW+REVIEW: untrusted object graph refused |
| PAR-004 | XML external entity resolution or entity expansion enabled for untrusted XML | CWE-611 | CONFIG+TEST: external entities/DTD appropriately disabled |
| PAR-005 | Untrusted JSON/object keys trigger prototype pollution or unsafe merge | CWE-1321 | FLOW+TEST: dangerous prototype keys refused |
| PAR-006 | Unsafe reflection/dynamic class construction from untrusted type name | CWE-470 | FLOW+TEST: class/type allowlist |
| PAR-007 | Parser consumes unbounded nesting, arrays, strings or recursive references | CWE-400 | FUZZ+TEST: bounded parsing |
| PAR-008 | MIME/content-type confusion processes HTML/script as safe media | CWE-436 | TEST: actual bytes checked and served safely |
| PAR-009 | CSV/spreadsheet export allows formula injection into operator's client | CWE-1236 | FLOW+TEST: spreadsheet-dangerous cells neutralized |
| PAR-010 | Untrusted Markdown/HTML conversion allows script or remote resource loading | CWE-79 | FLOW+TEST: safe render and URL policy |
| PAR-011 | Decoder normalizes/decodes twice after validation, changing meaning | CWE-174 | FLOW+TEST: validate final normalized bytes |
| PAR-012 | Files parsed through native plugins/codecs without memory/CPU containment | CWE-400 | FUZZ+REVIEW: isolated worker with limits |

### 2.13 Packages, dependency resolution and software supply chain [P0]

| ID | Failure to check | CWE | Method / proof |
| --- | --- | --- | --- |
| SCA-001 | Resolved package version affected by known advisory | CWE-1104 | SCA: exact name/ecosystem/version + source/advisory applicability |
| SCA-002 | Semver range (`^`, `~`, `>=`) misrepresented as actual installed version | n/a | SCA+TEST: declare unresolved instead of fabricating match |
| SCA-003 | Package name hallucinated by AI, nonexistent or typo-squatted | CWE-829 | SCA+REVIEW: registry, provenance and maintainer identity verified |
| SCA-004 | Dependency confusion via ambiguous public/private package source | CWE-427 | SCA+CONFIG: registry mapping and namespace trust verified |
| SCA-005 | Newly added package unnecessarily invokes privileged install/postinstall scripts | CWE-829 | SCA+CONFIG: script permissions and package origin reviewed |
| SCA-006 | Git URL, branch, floating tag or unpinned remote source used as dependency | CWE-829 | SCA+CONFIG: immutable trusted revision and provenance |
| SCA-007 | Lockfile missing/stale or differs from manifest resolution | CWE-1104 | SCA+TEST: deterministic tree/catalog reconciles |
| SCA-008 | Transitive dependency ignored or exact dependency graph unknown | CWE-1104 | SCA: transitive inventory and explicit unresolved nodes |
| SCA-009 | Advisory reported from the wrong OS/distro/library ecosystem | n/a | SCA+TEST: namespace/platform disambiguation |
| SCA-010 | Report assumes no CVEs after OSV/NVD/network lookup failure | n/a | SCA+TEST: `PARTIAL`/`ERROR` explicit, not green |
| SCA-011 | SBOM missing dependencies that appear in shipped binaries/images | CWE-1104 | SCA+CONFIG: build artifact and source inventory reconciled |
| SCA-012 | Vendored or copied code never checked because absent from manifest | CWE-1104 | SCA+REVIEW: vendored provenance or manual coverage |
| SCA-013 | Unreviewed model, dataset, prompt pack, IDE extension or MCP server dependency | CWE-829 | SCA+AGENT: external component trust inventory |
| SCA-014 | License/provenance/source integrity checks omitted for added security-critical dependency | CWE-829 | CONFIG+REVIEW: reproducible origin and licensing receipt |

### 2.14 CI/CD, build pipelines and repository automation [P0]

| ID | Failure to check | CWE | Method / proof |
| --- | --- | --- | --- |
| CIC-001 | `pull_request_target` executes untrusted PR code with secrets or write token | CWE-829 | CONFIG+TEST: hostile PR cannot reach elevated context |
| CIC-002 | GitHub/GitLab workflow token has unnecessary write/administrative permissions | CWE-250 | CONFIG: minimal permissions by job |
| CIC-003 | Unpinned third-party CI action or floating image used in release path | CWE-829 | CONFIG: immutable digest/SHA where appropriate |
| CIC-004 | Shell expression injects untrusted branch/title/PR/comment data into script | CWE-78 | FLOW+CONFIG: untrusted values passed as data |
| CIC-005 | Build/test executes downloaded untrusted shell script without verification | CWE-829 | CONFIG+REVIEW: digest, signature or vetted package flow |
| CIC-006 | CI secrets printed by debug trace, command echo, failure artifact | CWE-532 | SECRET+TEST: values redacted in job logs/artifacts |
| CIC-007 | Unsafe artifact/cache reuse between untrusted PR and release job | CWE-829 | CONFIG+TEST: provenance and cache isolation |
| CIC-008 | Deployment triggered without branch/environment approval controls | CWE-284 | CONFIG: required protected environment gates |
| CIC-009 | Release generated from a different commit than tested/reviewed | CWE-494 | CONFIG+TEST: immutable commit provenance bound |
| CIC-010 | Test/security jobs optional, skipped or configured with `continue-on-error` while reported green | n/a | CONFIG+TEST: required checks actually enforced |
| CIC-011 | Package scripts execute with privileged token, network and filesystem by default | CWE-250 | CONFIG: controlled untrusted build runner |
| CIC-012 | Artifact signing/attestation missing where project trust contract requires it | CWE-494 | CONFIG+REVIEW: verifiable artifact identity |
| CIC-013 | PR bot auto-merges without review of changed security boundaries | CWE-863 | AGENT+CONFIG: required independent checks before merge |
| CIC-014 | Workflow writes to repo based on arbitrary external issue/comment content | CWE-78 | FLOW+CONFIG: inputs constrained and authority scoped |

### 2.15 Containers, cloud, infrastructure and runtime defaults [P0/P1]

| ID | Failure to check | CWE | Method / proof |
| --- | --- | --- | --- |
| INF-001 | API/service exposed on `0.0.0.0` when only loopback/private access was intended | CWE-668 | CONFIG+REVIEW: intended exposure vs actual bind/firewall |
| INF-002 | Storage bucket/container/DB endpoint accidentally public | CWE-732 | CONFIG: public grants explicitly approved |
| INF-003 | Container runs as root without justified need | CWE-250 | CONFIG: non-root execution and capability limits |
| INF-004 | Privileged container, hostPID/network, hostPath or Docker socket mounted by default | CWE-250 | CONFIG: sensitive capabilities denied by default |
| INF-005 | IAM policy permits `*` actions/resources or broad role assumption | CWE-269 | CONFIG+REVIEW: least-privilege graph |
| INF-006 | Security group/network rule opens management/database port to the internet | CWE-284 | CONFIG: exposure consistent with policy |
| INF-007 | Secrets embedded in Dockerfile layer, image args or Terraform state | CWE-200 | SECRET+CONFIG: secret transport and artifact safety |
| INF-008 | Application disables TLS/auth to make local deployment easier, carries to production | CWE-306 | CONFIG+TEST: environment-safe production defaults |
| INF-009 | Database/queue/Redis/Elasticsearch has no authentication in reachable environment | CWE-306 | CONFIG+REVIEW: identity required for exposed service |
| INF-010 | Health/debug/admin/metrics endpoint exposes internals publicly | CWE-200 | CONFIG+DAST: routes scoped and data minimized |
| INF-011 | Default credentials, sample tokens or test users active after deployment | CWE-798 | SECRET+CONFIG: no shared demo accounts in production |
| INF-012 | Container image uses unverified base tag with stale vulnerable OS packages | CWE-1104 | SCA+CONFIG: resolved digest and image advisories |
| INF-013 | Infrastructure logs/audit disabled for security-critical asset | CWE-778 | CONFIG: monitored event delivery |
| INF-014 | K8s workloads lack required securityContext / privilege confinement | CWE-250 | CONFIG: workload policy enforced |
| INF-015 | Cloud metadata service accessible from untrusted fetch path | CWE-918 | CONFIG+TEST: egress/identity controls |
| INF-016 | Backups are unencrypted/public/unrestorable or deletion unsafe | CWE-552 | CONFIG+TEST: protection and actual restore drill |

### 2.16 Availability, denial of service and resource budgets [P1]

| ID | Failure to check | CWE | Method / proof |
| --- | --- | --- | --- |
| DOS-001 | User-defined recursion/depth/array size lacks bounds | CWE-674 | AST+FUZZ: depth cap under adversarial fixture |
| DOS-002 | Unbounded HTTP body, upload, compressed data or websocket frame | CWE-400 | CONFIG+TEST: streaming size ceiling |
| DOS-003 | Unlimited concurrency/task/thread/connection spawning per request | CWE-770 | AST+TEST: admission control |
| DOS-004 | Client/server IO operation has no timeout, cancellation or retry budget | CWE-400 | AST+TEST: operation terminates predictably |
| DOS-005 | Retry storm due to no backoff/jitter or maximum retries | CWE-400 | TEST: bounded failures and load |
| DOS-006 | Cache/pool grows without eviction, quota or per-tenant cap | CWE-400 | AST+TEST: maximum memory/resource envelope |
| DOS-007 | Database N+1 query or expensive predicate on attacker-controlled input | CWE-400 | TEST+REVIEW: bounded query cost |
| DOS-008 | Regex catastrophic backtracking on user input | CWE-1333 | FUZZ: worst-case execution cap |
| DOS-009 | AI/RAG generation lacks token, document, tool-call or spend quota | CWE-400 | AGENT+TEST: token/cost limits and cancellation |
| DOS-010 | Circuit breaker/queue backpressure absent for overloaded downstream | CWE-400 | TEST: controlled degradation under fault |
| DOS-011 | Unbounded file watching, process discovery or filesystem crawl by scanner | CWE-400 | TEST: path count/time/memory limits |
| DOS-012 | Error path repeatedly writes huge logs/reports causing disk exhaustion | CWE-400 | TEST: log/report caps and retention |

### 2.17 Concurrency, workflow state and race conditions [P1]

| ID | Failure to check | CWE | Method / proof |
| --- | --- | --- | --- |
| RAC-001 | TOCTOU on path, URL, credentials or permissions | CWE-367 | REVIEW+TEST: check and use bound atomically |
| RAC-002 | Double-submit/double-charge due to non-idempotent retries | CWE-362 | TEST: duplicate requests cause one side effect |
| RAC-003 | Token refresh/rotation race permits replay | CWE-362 | TEST: concurrent refresh invariants |
| RAC-004 | Shared mutable state used without synchronization | CWE-362 | AST+FUZZ: race-free under concurrent harness |
| RAC-005 | Queue message acknowledged before durable and authorized transaction | CWE-662 | REVIEW+TEST: failure cannot lose or duplicate protected action |
| RAC-006 | Stale cache permission survives user removal/role downgrade | CWE-613 | TEST: invalidation on revoke |
| RAC-007 | Optimistic update race bypasses inventory/limit/policy check | CWE-362 | TEST: atomic constraint enforced |
| RAC-008 | Distributed lease/lock expires during privileged operation | CWE-362 | REVIEW+TEST: stale worker cannot commit |
| RAC-009 | Background cleanup races with file upload or healing transaction | CWE-367 | TEST: cleanup cannot remove active/foreign resource |
| RAC-010 | Concurrent agents act on same target without serialization/ownership | CWE-362 | AGENT+TEST: conflict detection and exclusive action scope |

### 2.18 Native code, FFI and memory safety [P1/P2]

| ID | Failure to check | CWE | Method / proof |
| --- | --- | --- | --- |
| MEM-001 | Out-of-bounds read/write in C/C++/Zig/unsafe Rust or FFI | CWE-125 / CWE-787 | AST+FUZZ: bounds-safe access under harness |
| MEM-002 | Use-after-free, double-free or invalid lifetime across callbacks | CWE-416 / CWE-415 | AST+FUZZ: lifetime/ownership invariant |
| MEM-003 | Integer overflow/wraparound corrupts length/offset/allocation | CWE-190 | AST+FUZZ: checked arithmetic at size boundaries |
| MEM-004 | Null/dangling pointer dereference reachable from malformed input | CWE-476 | AST+FUZZ: non-null/valid handle proof |
| MEM-005 | Stack/heap buffer copy lacks verified bounds | CWE-120 | AST+FUZZ: no overflow under edge corpus |
| MEM-006 | `unsafe` Rust or FFI uses unchecked slice/pointer conversion | CWE-119 | AST+REVIEW: every safety precondition documented/tested |
| MEM-007 | C/C++ string encoding or truncation produces security control mismatch | CWE-170 | AST+FUZZ: termination and byte-count correct |
| MEM-008 | Untrusted native decoder or plugin runs in privileged host process | CWE-250 | CONFIG+FUZZ: isolation and privileges constrained |
| MEM-009 | Rust/Go panic or C++ exception crosses foreign function boundary unsafely | CWE-755 | REVIEW+TEST: ABI-safe error handling |
| MEM-010 | Compiler/hardening flags removed to silence warnings or fix build | CWE-693 | CONFIG: required hardening preserved |
| MEM-011 | Zig/C++ allocator mismatch or forgotten cleanup leaks secret-bearing memory | CWE-401 | FUZZ+REVIEW: memory lifetime clear |
| MEM-012 | Binary parser trusts declared lengths and integer casts | CWE-20 | FUZZ: size and signedness constraints validated |

### 2.19 Errors, observability and incident readiness [P1]

| ID | Failure to check | CWE | Method / proof |
| --- | --- | --- | --- |
| OPS-001 | Security exception swallowed with empty catch or `unwrap_or_default()` | CWE-754 | AST+TEST: failure visible and deny-by-default |
| OPS-002 | Authentication/authorization check returns allow after timeout/error | CWE-754 | TEST: verifier unavailable means deny |
| OPS-003 | Security-relevant events have no audit log or actor/resource identity | CWE-778 | REVIEW+TEST: accountable event emitted |
| OPS-004 | Raw secrets, authorization headers, PII or decrypted records logged | CWE-532 | FLOW+TEST: redaction enforced |
| OPS-005 | Detailed internal stack traces, SQL or file paths sent to untrusted clients | CWE-209 | TEST: safe bounded error response |
| OPS-006 | Alert threshold/recipient disabled without equivalent incident signal | CWE-778 | CONFIG: alert path verified |
| OPS-007 | Log forging through unsanitized multiline user fields | CWE-117 | FLOW+TEST: structured log fields safe |
| OPS-008 | Traces/audit lack correlation needed to reconstruct critical mutation | CWE-778 | REVIEW: event identity, ordering and provenance recorded |
| OPS-009 | Sensitive audit logs can be modified or deleted by same service account | CWE-284 | CONFIG+REVIEW: independent protected retention |
| OPS-010 | Recovery runbook promises rollback but no restorable backup is tested | CWE-693 | TEST: failure injection and restore receipt |
| OPS-011 | Healthcheck reports success when dependencies/scanners skipped or failed | CWE-754 | TEST: `PARTIAL`/`UNKNOWN` correctly surfaced |
| OPS-012 | Security fix suppresses test or warning rather than preserving invariant | n/a | TEST+REVIEW: independently failing regression retained |

### 2.20 Business logic, workflows and monetary/privileged effects [P0/P1]

| ID | Failure to check | CWE | Method / proof |
| --- | --- | --- | --- |
| BIZ-001 | Payment amount, discount, currency or recipient trusted from client | CWE-602 | TEST+REVIEW: server-derived authoritative values |
| BIZ-002 | User can reuse coupon/credit/refund/redeem token beyond permitted count | CWE-840 | TEST: state machine, one-time invariants |
| BIZ-003 | State-changing workflow can skip required step or approval | CWE-841 | REVIEW+TEST: valid transitions only |
| BIZ-004 | Role change/invite/ownership transfer lacks proper authorization and notice | CWE-862 | TEST: actor and target bound correctly |
| BIZ-005 | Idempotency key not actor-bound or expires incorrectly | CWE-362 | TEST: duplicate/cross-user effect denied |
| BIZ-006 | Order completion performed without verified settlement/fulfilment state | CWE-841 | REVIEW+TEST: external state reconciled |
| BIZ-007 | Reused webhook event alters account more than once | CWE-841 | TEST: event deduplicated and authentic |
| BIZ-008 | Account deletion/transfer misses shared resources or leaves active keys | CWE-613 | TEST: assets and credentials revoked |
| BIZ-009 | Multi-tenant report aggregates privileged records before access filtering | CWE-200 | TEST: aggregation preserves isolation |
| BIZ-010 | Feature flag/admin backdoor bypasses required policy in production | CWE-862 | CONFIG+TEST: bypass unavailable to untrusted actors |
| BIZ-011 | Sequence of individually permitted API calls defeats a global quota | CWE-840 | REVIEW+TEST: aggregate invariant across endpoints |
| BIZ-012 | Approval decision can be forged/reused for another action or target | CWE-345 | TEST: action hash, target and actor binding |

### 2.21 AI coding assistant-specific engineering traps [P0/P1]

These are failure patterns especially relevant when agents scaffold, complete or "repair" code quickly. Most are **process/design security checks**, not standalone CWE vulnerabilities.

| ID | Failure to check | CWE | Method / proof |
| --- | --- | --- | --- |
| AIC-001 | Agent removes access control, CSRF check, TLS verification or validation to make tests pass | CWE-693 | AST+REVIEW: security invariants preserved across diff |
| AIC-002 | Agent replaces real logic with hardcoded success response, dummy user, fixed token or no-op | CWE-693 | AST+TEST: negative tests independently fail when control disabled |
| AIC-003 | Generated tests only assert happy path and have no unauthorized/invalid inputs | n/a | TEST: explicit negative security test per critical path |
| AIC-004 | Tests are rewritten/weakened after a failure instead of diagnosing cause | n/a | REVIEW: original oracle retained; test diff separately inspected |
| AIC-005 | Agent invents nonexistent package/API/security option and assumes it works | n/a | SCA+TEST: dependency/API verified against installed implementation |
| AIC-006 | AI suggests outdated insecure code copied from old framework docs | CWE-1104 | SCA+REVIEW: pinned version and current official security model |
| AIC-007 | Generated migration/config changes break existing secure production defaults | CWE-16 | CONFIG+TEST: before/after security property delta |
| AIC-008 | Agent edits outside approved scope or unexpectedly changes permission-critical files | CWE-284 | AGENT+REVIEW: diff scope and permission boundary enforced |
| AIC-009 | Generated example secrets and `TODO: add authentication later` reach production | CWE-798 | SECRET+AST: no placeholder credential/security TODO in production path |
| AIC-010 | Generated comments claim "safe", "encrypted", "validated" without matching executable control | n/a | TEST+REVIEW: assertion traced to actual enforcement and failure test |
| AIC-011 | Agent silently bypasses failing scanner/CI or treats tool unavailable as zero issues | n/a | TEST+AGENT: unavailable checks produce blocked/partial verdict |
| AIC-012 | Agent uses broad `chmod 777`, wildcard IAM, open CORS or no sandbox to fix functional issue | CWE-732 | CONFIG+REVIEW: permissions remain minimal |
| AIC-013 | Agent adds broad exception handler that logs and continues privileged execution | CWE-754 | AST+TEST: fail-closed conditions still hold |
| AIC-014 | Generated fix changes data type, unit, signature, ownership or contract and breaks downstream enforcement | CWE-841 | TEST+REVIEW: integration contract tests and trust transition checks |
| AIC-015 | AI-produced security recommendation cites nonexistent advisory/CVE or mismatches package | n/a | SCA+REVIEW: advisory authority, package ID, affected range verified |
| AIC-016 | AI reports "fixed" based only on edited code without running functional and security tests | n/a | TEST+AGENT: proof receipts required before fixed status |

### 2.22 LLM, RAG, autonomous agent and MCP application flaws [P0/P1]

This category tracks the [OWASP LLM Top 10:2026](https://github.com/GenAI-Security-Project/GenAI-LLM-Top10/blob/main/2026/README.md) and [OWASP Agentic Top 10:2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) as *risk mappings*, not a guarantee that one static rule can verify every category.

| ID | Failure to check | Mapping | Method / proof |
| --- | --- | --- | --- |
| LLM-001 | Untrusted web/file/tool text treated as executable agent instruction | LLM01 / ASI01 | AGENT+TEST: instruction/data boundary enforced |
| LLM-002 | Prompt content alone used to authorize file, network, SQL, shell or deployment actions | LLM03 / ASI02 | AGENT+TEST: independent policy denies unapproved effect |
| LLM-003 | Model response directly executed as code or shell command | LLM10 / ASI05 | FLOW+AGENT: executable action requires trusted executor policy |
| LLM-004 | Model output put into SQL, HTML, Markdown, URL or command sink unchecked | LLM10 | FLOW+TEST: output treated as untrusted data |
| LLM-005 | External tool result carries injected instructions that can affect unrelated future tool calls | LLM01 / ASI01 | AGENT+TEST: lower-trust content cannot override goals |
| LLM-006 | Tool/MCP capability available to agent exceeds task identity and scope | LLM03 / ASI03 | AGENT+CONFIG: least-privileged tool permissions |
| LLM-007 | Agent with read-only user intent can invoke mutation-capable tool by prompt alone | ASI02 / ASI03 | AGENT+TEST: authorization enforced outside model |
| LLM-008 | MCP server/tool response hides exfiltration URL or secret in metadata | ASI04 / LLM02 | AGENT+SECRET: redacted output and egress policy |
| LLM-009 | Untrusted skill/plugin/agent instruction file gains precedence over system policy | ASI04 / LLM04 | AGENT+CONFIG: skill provenance and sandbox boundary |
| LLM-010 | Model/skill/tool update silently changes permissions or introduces new capability | ASI04 | AGENT+REVIEW: signed/pinned inventory and diff approval |
| LLM-011 | Retrieved RAG chunks cross tenant/user document ACL | LLM09 | TEST: retrieval scope enforced before and after ranking |
| LLM-012 | Vector index/embedding cache leaks another tenant's sensitive content | LLM09 / LLM02 | TEST+REVIEW: ACL and index isolation |
| LLM-013 | Model memory persists poisoned instruction or attacker-controlled long-term state | LLM05 / ASI06 | AGENT+TEST: integrity and expiry checks on memory writes |
| LLM-014 | Conversation/history/context gets silently included in another user's prompt | LLM02 / LLM08 | FLOW+TEST: context partitioning and redaction |
| LLM-015 | System prompts, API credentials or hidden context presented as authentication secret | LLM08 / LLM02 | REVIEW+AGENT: prompt secrecy not used as access control |
| LLM-016 | Model-supplied citation/source treated as verified fact or security patch evidence | LLM07 | AGENT+TEST: sources resolved and actual code verified |
| LLM-017 | Agent tool calls have no count, recursion, token, cost or wall-clock budget | LLM06 / ASI08 | AGENT+TEST: bounded work and cancellation |
| LLM-018 | Multi-agent messages lack trusted sender identity, authenticated channel or action scope | ASI07 | AGENT+TEST: signed/verified agent identity and scope |
| LLM-019 | Agent chain allows one agent's unchecked proposal to become another agent's privileged command | ASI07 / ASI08 | AGENT+TEST: reauthorization at each handoff |
| LLM-020 | Human approval prompt omits actual target, diff, impact or command being approved | ASI09 | AGENT+TEST: action-bound informed approval |
| LLM-021 | Agent continues acting after revocation, stop request, timeout or ownership change | ASI10 | AGENT+TEST: immediate cancellation/revocation enforced |
| LLM-022 | Model/tool endpoint sends proprietary code, secrets or PII to unapproved external provider | LLM02 | FLOW+CONFIG: outbound data policy and minimization |

### 2.23 Model, plugin and agent supply-chain integrity [P0/P1]

| ID | Failure to check | Mapping | Method / proof |
| --- | --- | --- | --- |
| AGS-001 | Model weights downloaded from unknown or mutable origin | LLM04 | SCA+CONFIG: model hash and trusted source |
| AGS-002 | Model format or loader can execute attacker-controlled code in trusted process | ASI05 | CONFIG+REVIEW: safe format/isolated loader |
| AGS-003 | Prompt templates from package/registry allowed to include tool-use instruction without review | ASI04 | AGENT+CONFIG: provenance and policy separation |
| AGS-004 | Skills/MCP tool descriptions embed instructions to overstep authority | ASI01 / ASI04 | AGENT+TEST: lower-trust metadata cannot grant privileges |
| AGS-005 | Remote tool endpoints/transport not authenticated or pinned to expected trust domain | ASI04 | CONFIG+TEST: identity and integrity verification |
| AGS-006 | Agent configuration hot reload widens tool grants without reapproval | ASI03 | AGENT+TEST: permission change audited and bound |
| AGS-007 | Credentials copied into agent prompts, state dumps or debugging traces | LLM02 | SECRET+TEST: no raw credential in model-visible logs |
| AGS-008 | Agent can use network fetcher to reach cloud metadata/internal-only systems | ASI02 / CWE-918 | AGENT+TEST: outbound scope and peer checks |
| AGS-009 | Unsigned/unreviewed policy files dynamically loaded from repository branch | ASI04 | CONFIG+TEST: trusted policy source and immutability |
| AGS-010 | Approval result can be fabricated by another agent/tool response | ASI09 | AGENT+TEST: approval cryptographically or server-state bound |
| AGS-011 | Retry after partial tool execution duplicates privileged action | ASI08 | AGENT+TEST: idempotency and rollback receipt |
| AGS-012 | Nested tool invocation delegates greater permissions than initiating actor owns | ASI03 | AGENT+TEST: delegated authority is subset only |

### 2.24 Language/runtime-specific red flags [P0/P1]

| ID | Failure to check | Stack / mapping | Method / proof |
| --- | --- | --- | --- |
| LNG-001 | PHP `include`, `require` or template path controlled by user | PHP / CWE-98 | FLOW+TEST: finite template set |
| LNG-002 | PHP `unserialize()` called on attacker-provided bytes | PHP / CWE-502 | FLOW: object injection path gated |
| LNG-003 | PHP `shell_exec`, `system`, `passthru` fed from request | PHP / CWE-78 | FLOW+TEST: no untrusted command path |
| LNG-004 | PHP upload/filename checks rely solely on extension or client MIME | PHP / CWE-434 | FLOW+TEST: actual content and non-exec storage |
| LNG-005 | PHP debug/errors exposed publicly or dangerous runtime settings enabled | PHP / CWE-209 | CONFIG+DAST: environment-aware settings |
| LNG-006 | Node.js `child_process.exec()` receives request data | Node / CWE-78 | FLOW+TEST: no shell injection |
| LNG-007 | Node/Bun `eval`, `vm`, dynamic import of untrusted strings | Node/Bun / CWE-94 | FLOW+REVIEW: trusted code modules only |
| LNG-008 | Node/Express prototype pollution via unsafe deep merge | Node / CWE-1321 | FLOW+TEST: hostile keys blocked |
| LNG-009 | Express/Fastify auth middleware omitted on one router/method | Node / CWE-306 | AST+TEST: route coverage matrix |
| LNG-010 | Node request/compression/decompression stream lacks size and CPU caps | Node / CWE-400 | TEST: decompression bomb and abort boundaries |
| LNG-011 | Bun/Node process runs postinstall or startup hook from untrusted package | Node/Bun / CWE-829 | SCA+CONFIG: hook provenance and privilege |
| LNG-012 | Python `subprocess(..., shell=True)`, `os.system()` with untrusted data | Python / CWE-78 | FLOW+TEST: safe argument boundary |
| LNG-013 | Python pickle, dill, joblib, unsafe YAML used for untrusted data | Python / CWE-502 | FLOW+TEST: safe data-only parsing |
| LNG-014 | Flask/Django/FastAPI debug, secret, route dependency/auth controls misconfigured | Python / CWE-16 | AST+CONFIG: environment-aware secure defaults |
| LNG-015 | Go `exec.Command` arguments accept attacker-controlled flags/subcommands | Go / CWE-88 | FLOW+TEST: argument grammar constrained |
| LNG-016 | Go HTTP clients follow redirects into forbidden origins or lack deadlines | Go / CWE-918 | TEST: controlled transport and redirect policy |
| LNG-017 | Go template uses `text/template` for user-controlled HTML where `html/template` expected | Go / CWE-79 | AST+TEST: context-aware HTML escaping |
| LNG-018 | Go path check uses `strings.HasPrefix` without symlink/segment safety | Go / CWE-22 | FLOW+TEST: canonical path containment |
| LNG-019 | Rust `unsafe`/FFI/parser code claims compiler guarantees for unchecked memory | Rust / CWE-119 | AST+REVIEW+FUZZ: unsafe invariants audited |
| LNG-020 | Rust `unwrap`/`expect` on attacker-controlled parser path causes service crash | Rust / CWE-248 | AST+FUZZ: untrusted input cannot panic process |
| LNG-021 | Rust error fallback returns empty findings/success after IO failure | Rust / CWE-754 | AST+TEST: partial/failed status preserved |
| LNG-022 | Java deserialization, expression language or unsafe JNDI lookup | Java / CWE-502 | FLOW+CONFIG: external values cannot select code |
| LNG-023 | .NET middleware/policy attribute omitted on controller/minimal API | .NET / CWE-862 | AST+TEST: endpoint authorization matrix |
| LNG-024 | Ruby `send`, ERB/Marshal/YAML loaders execute untrusted material | Ruby / CWE-94 | FLOW+TEST: no untrusted metaprogramming boundary |
| LNG-025 | C/C++/Zig generated code uses unchecked raw pointer/array copy | Native / CWE-787 | AST+FUZZ: size and lifetime bounds |
| LNG-026 | SQL/ORM integration treats string escape helper as replacement for bind parameters | Multi / CWE-89 | FLOW+TEST: binding at actual query sink |

### 2.25 Mobile, desktop, electron and local apps [P1/P2]

| ID | Failure to check | CWE | Method / proof |
| --- | --- | --- | --- |
| MOB-001 | Client mobile/desktop bundle contains long-lived cloud API/admin keys | CWE-798 | SECRET+CONFIG: shipped binary does not embed privileged keys |
| MOB-002 | Sensitive token stored in plaintext local preferences/file | CWE-922 | AST+REVIEW: OS secure storage used where required |
| MOB-003 | Android exported activity/service/provider reachable without intended permission | CWE-926 | CONFIG+TEST: component exposure constrained |
| MOB-004 | Deep-link or custom protocol handler accepts unsafe URL/command | CWE-939 | FLOW+TEST: recognized action and validated parameters |
| MOB-005 | Electron renderer has Node integration/unsafe context isolation policy | CWE-250 | CONFIG+TEST: renderer cannot gain host privileges |
| MOB-006 | Electron IPC main process blindly executes renderer-supplied command | CWE-78 | FLOW+TEST: typed command allowlist and auth |
| MOB-007 | Mobile/desktop TLS trust all certificates or disables hostname verification | CWE-295 | AST+TEST: expected origin identity authenticated |
| MOB-008 | Local database/files contain private content accessible to another user/process | CWE-922 | CONFIG+TEST: OS access permissions |
| MOB-009 | Untrusted app updates or executable plugins have no origin verification | CWE-494 | CONFIG+REVIEW: update signature/provenance |
| MOB-010 | Clipboard, screen capture, crash reports or notifications expose secret values | CWE-200 | AST+REVIEW: sensitive UI handling policy |

### 2.26 Bug Killer-specific scanner, reporter and healer safety [P0]

| ID | Failure to check | CWE | Method / proof |
| --- | --- | --- | --- |
| BKH-001 | Scanner reports "clean" after parser/network/tool failure | n/a | TEST: `PARTIAL`/`ERROR` status retained |
| BKH-002 | Scanner treats unresolved manifest constraint as installed vulnerable/safe version | n/a | SCA+TEST: exact/declared distinct |
| BKH-003 | Finding goes to healer solely because model believes it is exploitable | CWE-862 | AGENT+TEST: independent policy gate |
| BKH-004 | New analyzer runs arbitrary repository build/install hooks without consent | CWE-829 | CONFIG+TEST: sandbox or no execution |
| BKH-005 | DAST scanner follows redirect or DNS to out-of-scope network | CWE-918 | TEST: peer and per-hop scope enforcement |
| BKH-006 | External scanner tool/plugin inherits host secrets or admin credentials | CWE-250 | CONFIG+TEST: capability isolation |
| BKH-007 | Security report leaks credentials, environment or response body | CWE-532 | SECRET+TEST: evidence redaction |
| BKH-008 | Auto-fix edits wrong file because matching by basename or ambiguous path | CWE-73 | TEST: canonical target and content precondition |
| BKH-009 | Healing changes unapproved file, service or cloud asset | CWE-862 | TEST: immutable approval target scope |
| BKH-010 | Backup not independently authenticated or restorable | CWE-345 | TEST: tampering and restore negative tests |
| BKH-011 | Multi-file healing fails halfway without coherent rollback/state receipt | CWE-662 | TEST: fault injection at each phase |
| BKH-012 | Agent merges or releases a fix despite failing/skipped required tests | n/a | AGENT+CONFIG: gate blocks claim and merge |
| BKH-013 | Exclusion/suppression never expires or hides entire directory silently | n/a | CONFIG+TEST: expiry, owner, reason and coverage effect |
| BKH-014 | Scanner's source-to-sink claim is only a regex keyword hit | n/a | FLOW+TEST: downgraded to unconfirmed indicator |
| BKH-015 | CI checks Rust crate but skips Go services, nested Cargo workspace or installer | n/a | CONFIG+TEST: target/component matrix complete |
| BKH-016 | Remote target scan begins without asset authorization and rate/egress budgets | CWE-284 | AGENT+TEST: denied by default for live unknown target |
| BKH-017 | Parallel healers race on same manifest/config, overwriting each other's changes | CWE-362 | TEST: lock/precondition and conflict abort |
| BKH-018 | Public README claims support for checks not implemented, validated or enabled | n/a | TEST+REVIEW: docs tied to capability receipts |

### 2.27 Security-test integrity, human review and quality controls [P0/P1]

| ID | Failure to check | CWE | Method / proof |
| --- | --- | --- | --- |
| QAT-001 | Security test only checks existence of validator rather than rejection of malicious/unauthorized input | n/a | TEST: independent attacker-view negative case |
| QAT-002 | Fixture for each dangerous rule lacks safe lookalike, causing false positives | n/a | TEST: near-miss fixture retained |
| QAT-003 | Scanner detection relies on file extension while supported syntax is embedded/mixed | n/a | TEST: embedded templates, generated files and aliases covered |
| QAT-004 | Rule source/sink coverage not versioned per language/framework | n/a | TEST: explicitly supported runtime matrix |
| QAT-005 | A clean test run covers only one role, principal or tenant | n/a | TEST: matrix of unauthenticated, regular, elevated, foreign tenant |
| QAT-006 | Static scanner ignores indirect imports, aliases, callback/async entrypoints without disclosure | n/a | TEST: limitations emitted in report |
| QAT-007 | Security finding severity inferred from `CWE` alone rather than actual reachability and impact | n/a | REVIEW: asset, exposure, prerequisite, effect recorded |
| QAT-008 | "Mitigated" classification accepted without a test of the real guard | n/a | TEST: confirmed guard prevents effect |
| QAT-009 | Security test silently calls live external system or mutates production during CI | n/a | CONFIG+TEST: local fixtures and network containment |
| QAT-010 | Report hides unknown coverage or suppressions when producing summary/dashboard | n/a | TEST: coverage and exclusions visible in all exports |
| QAT-011 | Automatic repair writes without showing diff, impact, backup state or verification outcome | n/a | AGENT+TEST: action-bound receipt and rollback path |
| QAT-012 | One LLM reviews its own output and marks security as proven without independent evidence | n/a | REVIEW+TEST: deterministic corroboration or human security sign-off |

## 3. How Bug Killer should interpret the inventory

### 3.1 A required check is not automatically a supported detector

The catalog contains **373 rule candidates** across 27 categories. Do not claim `373 security checks supported` until all 373 have implementations and independently tested contracts. Each row can be in one of these lifecycle states:

1. `CATALOGED`: known failure mode, no implementation evidence.
2. `EXPERIMENTAL`: detection prototype with limitations and private fixtures; unavailable in stable default results.
3. `SUPPORTED_STATIC`: reproducible parser/flow/config evidence on listed languages/frameworks.
4. `SUPPORTED_DYNAMIC`: reproducible authorized fixture-based behavior on listed protocols/configurations.
5. `REVIEW_REQUIRED`: design or business control that scanner can inventory but cannot conclusively establish.
6. `DEPRECATED`: retired rule, with superseding ID and migration record.

For **every** scan, output a coverage receipt for the categories actually applicable to the target. `UNKNOWN`, `UNSUPPORTED`, `PARTIAL`, `ERROR`, `NOT_RUN`, `N/A` are distinct. For a valid `NO_FINDING_IN_COVERAGE`, the tool must prove the rule executed on the declared file/component scope. A review-only rule remains `REVIEW_REQUIRED` even if the agent's prose says it seems safe.

### 3.2 Source-backed finding packet

```yaml
finding_id: "stable fingerprint"
rule_id: "BK-AI-AZ-001"
target_type: "route|code|package|container|service|model|skill|agent"
affected_location: "path:line or typed resource ID"
attacker_preconditions: "who controls which input, role and environment"
trust_boundary: "principal/tenant/source -> sensitive resource or action"
evidence_trace:
  source: "user-controlled object ID"
  validation: "present/absent/unknown"
  authorization: "present/absent/unknown"
  sink: "object read/update"
  proof: "redacted non-destructive fixture receipt"
mitigations_checked: ["route middleware", "resource-level authorization", "storage policy"]
severity: "analyst-calibrated P0/P1/P2; justify by impact and reachability"
confidence: "CONFIRMED | HIGH | MEDIUM | LOW"
coverage: "COMPLETED | PARTIAL | ERROR"
safe_fix_plan: "enforce object authorization at data access boundary"
verification: "foreign-user and foreign-tenant negative tests, plus successful owner path"
```

**Do not infer confirmed vulnerability from** a banned-looking function name, a missing generic header on an API, a weak-looking string that is not a real secret, a declared dependency version range, a GitHub action name alone, or an LLM describing an attack. Trace the real input to an effect and account for existing controls.

### 3.3 Six mandatory kinds of counterexamples

Each detector ships with at least the following fixture classes, checked in an isolated repo or local test server:

| Fixture | Purpose | Expected detector behavior |
| --- | --- | --- |
| `positive_reachable` | Attacker-controlled input reaches dangerous effect without effective guard | Report with evidence; severity grounded |
| `negative_guarded` | Similar API pattern but effective authorization/validation/binding exists | No confirmed vulnerability |
| `negative_unreachable` | Dangerous helper exists but untrusted actor cannot reach it | No confirmed issue; optional review indicator |
| `partial_or_broken` | Network/advisory/parser/tool unavailable, timeout, truncated scope | Explicit partial/error status; no clean claim |
| `context_variant` | Different tenant, method, framework or runtime version | Applicability and specific limit correct |
| `repair_regression` | Security fix applied in staging, then tested for blocking and functional behavior | Security property restored without silently losing function |

For high-impact operations, add concurrency, replay, restart, path-symlink, redirect, DNS and rollback fixtures as applicable. Test corpora must use dummy data and local services; never require live exploit probes on third-party hosts.

## 4. Suggested implementation waves for the Rust/Go platform

| Wave | Rule families | Build sequence / release gate |
| --- | --- | --- |
| **W0: Trustworthy baseline** | BKH, QAT, AIC-011/016 | Fix CI, typed report coverage, scanning must not trigger unapproved healing, truthful failure output |
| **W1: Detectable high-priority source paths** | INJ, FIL, NET, SEC, AUT, AZ, SES | Integrate proven SAST/secret tools plus curated role/tenant fixture suites; start with supported PHP/Node and then Python/Go |
| **W2: Dependencies and build** | SCA, CIC, INF, CRY | Resolved lockfiles, advisory lookup with partial coverage, IaC/workflow policy checks; no automatic package upgrades |
| **W3: Endpoint and design context** | WEB, API, PAR, DAT, BIZ, RAC, DOS, OPS | Context-aware risk engine, local test harnesses, bounded authorized DAST; design gaps correctly marked review-required |
| **W4: Native and secondary runtimes** | MEM, LNG, MOB | Language-specific rule packs, sandboxed fuzzing where safe; identify unsupported platforms explicitly |
| **W5: AI agent application security** | LLM, AGS, AIC | Read-only MCP/agent audit, fixture-controlled denied actions, trust and capability graph, provenance and tool policy validation |

**Dependency rule:** W1/W2/W3/W4 can be implemented by separate owners after W0 freezes the result/evidence contract; they must not independently introduce alternative permissions, report verdicts or healers. W5 uses the same deny-by-default execution policy and evidence contracts.

### Recommended detection engine boundaries

- **Core Rust:** asset inventory, scope, report schema, policy decision, plugin isolation, CLI, resource caps, immutable rule IDs, no default mutation.
- **Existing Go services:** orchestration/transport only where already justified; they consume canonical findings and never reinterpret model confidence as permission.
- **SAST/dataflow:** evaluate vetted Semgrep and other verified analyzers on small falsifiable corpora; use language packs and document alias/cross-file limits. Regex heuristics stay *indicators*, not confirmed taint traces.
- **Dependency and binary inventory:** read lockfiles and SBOMs, distinguish direct/transitive/declared/resolved, use OSV and platform feeds with exact package and advisory provenance. Consider Syft/Grype reuse rather than hand-writing every ecosystem parser.
- **Secrets:** scan history, source, logs and artifacts with safe preview and provenance; known leaks require containment/rotation, not just deletion from HEAD.
- **HTTP posture:** authorized hosts only, low-impact metadata and cookie/header checks first. Sensitive paths, malformed inputs and stateful checks disabled by default; no unauthenticated broad scanning.
- **Agent/model layer:** interpretation and plan proposals only; filesystem/network/credential/deployment permissions come from external policy, signed operator grants and real runtime state, not prompts.

### Highest-priority adversarial scenarios to regression-test first

1. Anonymous request denied at every protected route (`AUT-001`, `API-006`).
2. User A cannot read/update user B or tenant B asset, including queues and caches (`AZ-001`, `AZ-008`, `DAT-007`).
3. Untrusted request/LLM text cannot reach shell, SQL or dynamic code sink (`INJ-001`, `INJ-003`, `LLM-003`).
4. Uploaded/archive/member path cannot escape intended root even through links (`FIL-001` through `FIL-004`).
5. User-supplied URL/redirect/DNS change cannot reach internal/cloud metadata or leak auth headers (`NET-001` through `NET-009`).
6. Credentials are absent from source/artifacts/logs and cannot be echoed in findings (`SEC-001`, `SEC-005`, `SEC-010`, `BKH-007`).
7. Untrusted PR code cannot execute with repo-write/production deployment context (`CIC-001` through `CIC-004`).
8. A failed OSV query/failed parser returns incomplete coverage, never `SAFE` (`SCA-010`, `BKH-001`).
9. An agent cannot mutate a file, host or cloud resource without action-bound permission (`LLM-002`, `BKH-003`, `BKH-009`).
10. Every staged repair can be tested, rejected and recovered without silently modifying out-of-scope resources (`BKH-008` through `BKH-011`).

## 5. Definition of done for a catalog-backed scan

Check each relevant statement before advertising a supported rule or package:

- [ ] Each emitted finding has rule ID, analyzed target, method, exact redacted evidence, limits and remediation invariant.
- [ ] Risk score is based on reachability, actor, scope, mitigations, impact and confidence, not a blanket CWE mapping.
- [ ] Every rule has positive, guarded, unreachable, partial, context and regression fixtures (or marked `REVIEW_REQUIRED` with rationale).
- [ ] Every detector names supported language versions, frameworks, file types, package ecosystems and platform bounds.
- [ ] Rule evaluation failure cannot masquerade as a clean application.
- [ ] Reports show `not analyzed`, exceptions, skip counts, suppressed items, unsupported features and evidence freshness.
- [ ] Test suite exercises permission-denial and no-side-effect assertions for sensitive operations.
- [ ] DAST targets are operator-owned/authorized, egress-constrained, budgeted and fixture-tested before any live use.
- [ ] No security scanner/model/skill response can independently authorize OS commands, installations or destructive healing.
- [ ] Redaction is verified before logs/reports, AI prompts, saved artifacts and telemetry leave their trust boundary.
- [ ] Security-specific and functional regressions both pass in CI; skipped required jobs block release.
- [ ] Release notes/README distinguish *cataloged*, *experimental*, *supported* and *human-review required* coverage.

## 6. Scope, limitations and maintenance

1. **AI authorship is not reliably detectable from source alone.** Apply these checks to all code, regardless of whether it was handwritten, generated or hybrid.
2. **No finite list covers every vulnerability.** New CVEs, framework versions, threats, architectures and business rules require continuous updates. Update this catalog quarterly and when major ecosystem security standards change.
3. **Absence is not proof.** Many classes (BOLA, business logic, token revocation, SSRF DNS rebinding, race conditions, agent agency, tenant leakage) need integration/runtime evidence or review. Static source scanning alone is insufficient.
4. **Scanning is not exploitation.** Use authorized local fixtures for payload-based proofs. Never probe public/live assets without explicit scope and permitted technique; never fetch known secret files by default.
5. **Fixing is a different security boundary.** A remediation agent can propose patch/diff and validate in a disposable environment. Actual changes require signed policy and preconditions, explicit target authority, independently restorable backup and verifiable no-side-effect controls.
6. **Never train the agent to return `ALL_SECURE`.** Show a bounded statement: `No findings in completed checks [X/Y] on targets [scope] at [snapshot]; remaining checks: ...`.
7. **Version the oracle.** Add/remove/change rule semantics only with explicit rationale, golden-fixture changes, changelog and backward compatibility plan.

## 7. Authoritative sources and research

Sources inform the category taxonomy and verification philosophy. **The individual BK-AI rules are design proposals** and are not verbatim entries or officially endorsed mappings from any named source.

### Standards and reference catalogs

- [MITRE CWE Top 25, 2025](https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25) and [CWE catalog](https://cwe.mitre.org/).
- [OWASP Top 10:2025 for Web Applications](https://top10.owasp.org/2025/0x00_2025-Introduction/).
- [OWASP API Security Top 10:2023](https://owasp.org/API-Security/editions/2023/en/0x11-t10/).
- [OWASP ASVS 5.0.0](https://asvs.owasp.org/) for testable web application security requirements.
- [OWASP LLM Top 10:2026 canonical source](https://github.com/GenAI-Security-Project/GenAI-LLM-Top10/blob/main/2026/README.md).
- [OWASP Top 10 for Agentic Applications:2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/).
- [NIST Secure Software Development Framework, SP 800-218](https://csrc.nist.gov/pubs/sp/800/218/final).
- [OpenSSF Security-Focused Guide for AI Code Assistant Instructions](https://best.openssf.org/Security-Focused-Guide-for-AI-Code-Assistant-Instructions.html).
- [GitHub guidance on securely using `pull_request_target`](https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target).

### Empirical studies specifically about AI-assisted code

- Fu et al., [Security Weaknesses of Copilot-Generated Code in GitHub Projects: An Empirical Study](https://doi.org/10.1145/3716848), *ACM TOSEM*, 2025. The authors examined 733 snippets and identified security weaknesses across 43 CWE categories. Their estimates apply to their studied dataset, not to every AI assistant or repository.
- Belozerov, Barclay and Sami, [Secure Coding with AI: From Detection to Repair](https://link.springer.com/article/10.1007/s10664-026-10812-8), *Empirical Software Engineering*, 2026. The study assessed 2,315 C/C++/C# snippets from a defined dataset, combining scanners and manual inspection; findings cannot be generalized to all generated code.

## 8. Maintainer instructions

When transforming this catalog into actual Bug Killer rules:

1. Start with **BKH-001, QAT-004, BKH-003, BKH-016**: truthful coverage, supported targets, permission barrier and scan authorization.
2. Create one owner-assigned issue per bounded rule family, not one issue per individual table row and not one giant PR covering all 373.
3. Record for each rule: `cataloged -> experimental -> supported` with fixture evidence and known false-positive/false-negative classes.
4. Map outputs to SARIF where applicable and preserve the canonical JSON report and privacy handling in every export.
5. Keep any private maintainer-only skills, prompts or credentials outside public release assets.
6. Re-evaluate official standards and dependency advisories on each quarterly revision; do not silently rename IDs.

**Status at publication:** Catalog design completed; **0/373 rules are claimed implemented by this document**. Actual Bug Killer support must be discovered and verified against source and CI before incrementing coverage counts.



