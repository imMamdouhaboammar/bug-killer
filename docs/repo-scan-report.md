# Cross-Stack Repository Scan: Vercel Labs DeepSec

Audit and asset classification of `https://github.com/vercel-labs/deepsec`.
Conducted per the `/repo-scan` cross-stack source asset audit protocol.

---

## 1. Executive Summary & Inventory

- **Total Source Files Analyzed:** 187 TypeScript / JavaScript source files.
- **Package Manager:** `pnpm` (pnpm-workspace monorepo with 5 packages).
- **License:** Apache 2.0 (commercial use permitted, attribution required).
- **Core Packages:**
  1. `@deepsec/core`: Data models, atomic locking, run tracking, path resolution.
  2. `@deepsec/scanner`: Fast regex matchers, technology detection, candidate generation.
  3. `@deepsec/processor`: Prompt engineering, batching, LLM agent integration, revalidation, triage, git enrichment.
  4. `deepsec`: Command line interface, setup coordinator, terminal UX.
  5. `@deepsec/website`: Documentation portal (Next.js App Router).

---

## 2. File & Asset Classification

| Layer / Subsystem | Asset Classification | Ownership Verdict | Clean-Room Strategy |
|---|---|---|---|
| Domain Types (`packages/core/src/types.ts`) | Core Asset | Rebuild in Rust | Map to idiomatic Rust structs with `serde::Serialize` and `serde::Deserialize`. |
| Regex Matchers (`packages/scanner/src/matchers/`) | Reusable Knowledge | Rebuild in Rust | Port regex patterns to Rust `regex::Regex` with pre-compiled static compilation. |
| Tech Detection (`packages/scanner/src/detect-tech.ts`) | Reusable Pattern | Rebuild in Rust | Inspect file existence and manifest keys using standard filesystem checks. |
| Processor Loop (`packages/processor/src/index.ts`) | Core Asset | Rebuild in Rust / Go | Concurrency worker pool using Rust channels / Go goroutines. |
| AI Prompt System (`packages/processor/src/prompt/`) | Reusable Knowledge | Preserve & Port | Port `CORE_PROMPT` and `TECH_HIGHLIGHTS` into embedded strings in Rust binary. |
| Website / Docs (`packages/website`) | Third-Party Wrapper | Deprecate | Not required for high-speed scanning and healing harness. |
| Cloud MicroVM Sandbox (`packages/deepsec/src/commands/sandbox*`) | Proprietary SaaS | Rebuild in Go | Rebuild using Go orchestrator with Afero sandboxed isolation. |

---

## 3. Vulnerability Matcher Coverage by Language

The original scanner implements 50+ matchers across ecosystems:

1. **Python:** Django views, Flask routes, FastAPI routes, raw SQL, Nosql injection, pickle deserialization.
2. **Ruby:** Rails controllers, Sinatra routes, Grape endpoints, ActiveRecord raw SQL.
3. **Go:** Gin routes, Chi routes, Echo handlers, Fiber handlers, raw SQL queries.
4. **Rust:** Actix routes, Axum handlers, Rocket routes, Warp filters, raw SQL strings.
5. **Node.js / TypeScript:** Express handlers, Fastify hooks, NestJS controllers, Hono routes, TRPC public procedures.
6. **Infrastructure / IaC:** Terraform unencrypted storage, IAM wildcards, public ingress security groups.
7. **Secrets:** Private keys, cloud tokens, database URIs, JWT hardcoded secrets.
