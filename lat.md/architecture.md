# Architecture

Bug Killer is an autonomous vulnerability discovery and self-healing engine engineered for critical runtime memory corruptions.

It operates through a polyglot system composed of a high-performance Rust core CLI, Go microservices, and MCP interfaces.

## Defensive Perimeter

All operations strictly adhere to a defensive posture focused on detection, virtual patching, and cryptographic rollback.

Weaponized payload authoring and exploit generation are prohibited across all execution paths.

## Polyglot System Boundaries

The system couples a Rust core CLI engine with Go microservices communicating via gRPC.

The Rust engine handles binary parsing and AST analysis, while Go microservices manage stateful orchestration in [[services/orchestrator/procmap/procmap.go#ProcessMapper]] and remediation in [[services/healer/server/healer_server.go#StatefulHealerServer]].

## Domain Model Taxonomy

The domain model separates affectedness, reachability, severity, and remediation readiness into type-safe enums.

Key domain models include [[src/types.rs#CveId]], [[src/types.rs#Severity]], and [[src/types.rs#Affectedness]].

## Vulnerability Evaluation Database

The CVE evaluation engine determines vulnerability status for runtime versions and package manifests.

Version matching rules are evaluated deterministically through [[src/cve_db.rs#CveDatabase]].

## Container and Orchestration Lifecycle

Orchestration sequences inventory and inspection deterministically via Compose dependency conditions.

The orchestrator publishes the coverage ledger atomically via [[services/orchestrator/ledger/ledger.go#CoverageLedger#WriteToFile]] and invalidates stale outputs before starting reconnaissance. The inspector coordinates startup via Docker Compose `service_completed_successfully` readiness.

## Docker Image Build and Smoke Verification

Container distribution builds the multi-stage image independently from native host toolchains.

The CI workflow verifies that the final container stage builds cleanly, entrypoints execute safely under an unprivileged user, and all runtime service binaries exist without requiring privileged Docker socket mounts.

## Python CVE MCP Quality Gate

The Python CVE intelligence sidecar enforces offline test isolation and linter standards in CI.

The root workflow defines a dedicated Python gate executing `ruff check`, `ruff format --check`, and `pytest` with the `not online` marker. This guarantees that external API dependencies (such as live NVD endpoints) are not required during pull request verification.

## Shell Completion Ownership

The CLI generates shell-specific completion scripts; generated files belong to ignored build outputs rather than the source tree.

The [[src/completion/mod.rs#CompletionGenerator]] implementation remains the source of completion syntax. The [[Makefile]] generates Bash, Zsh, and Fish completions under `target/completions/`; `install-completions` installs them to standard shell discovery directories only when explicitly requested. The build validates these outputs in GitHub Actions.
