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

## Shell Completions Ownership and Drift Gate

Shell completions for Bash, Zsh, and Fish are maintained as checked-in distribution assets in `completions/`.

Completions are generated dynamically via [[src/completion/mod.rs#CompletionGenerator#generate_completion]] and tested for drift against the committed scripts by `shell_completions_are_fresh_and_match_cli`. The `Makefile` installs them to standard `share` paths, and CI verifies zero uncommitted diff following `make build`.

## Canonical Skill Directory and Lat.md Packaging

Project-specific agent skills reside canonically within the `.agents/skills/` directory.

The `lat-md` skill is authored and maintained under `.agents/skills/lat-md`, with `skills/lat-md` linked directly to eliminate redundant tracked files while preserving discovery on external agent runtimes. Contract verification in `lat_md_skill_is_canonical_in_agents_directory` ensures content synchronization.

## Agent Skill Vendoring and Synchronization

Multi-package skills are vendored as self-contained directories with synchronized shared assets.

The `omni-skill` and `skill-conductor` packages are independently packaged skills upstream from `imMamdouhaboammar/omni-skill`. Because agent runtimes (such as Claude Code, Cursor, and Google Antigravity) expect self-contained directories when executing or packaging skills, cross-skill symlinks break standalone distribution. To prevent silent divergence between the 25 shared evaluation, benchmark, and prompt assets, [[tests/deployment_contract_test.rs]] enforces deterministic byte-for-byte synchronization in `omni_skill_and_skill_conductor_shared_assets_are_synchronized`.

## Research Provenance and Clean-Room Archive

Historical reverse-engineering and upstream research artifacts are archived under `docs/research/`.

Clean-room audits and design artifacts previously residing in `replica/` and `docs/repo-scan-report.md` are archived in `docs/research/deepsec/` with explicit upstream provenance labels. This physical separation prevents third-party source measurements (such as `vercel-labs/deepsec`) from being conflated with Bug Killer implementation metrics, while keeping operational skills in `skills/deepsec/` fully functional as enforced by `deepsec_research_artifacts_are_archived_and_skill_is_functional` in [[tests/deployment_contract_test.rs]].
