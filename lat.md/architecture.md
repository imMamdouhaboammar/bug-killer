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
