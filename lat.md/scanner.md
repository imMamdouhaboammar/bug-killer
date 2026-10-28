# Security Scanner Engine

Bug Killer features a multi-layer static and dynamic scanning engine tailored for vulnerability detection.

The scanner audits application source code, package manifests, runtime environments, and web server configurations.

## Fleet Scanning Architecture

The fleet scanner coordinates modular rule checkers and static analyzers across directory trees.

The core scanner entry point is [[src/scanner/mod.rs#FleetScanner#scan_directory]], which walks targets and aggregates findings into a unified report.

## Security Rule Catalog

The rule catalog establishes a comprehensive taxonomy of security checks with explicit lifecycles.

Catalog definitions in [[src/catalog/mod.rs#SecurityCatalog]] assign states via [[src/catalog/mod.rs#RuleLifecycle]] and require concrete [[src/catalog/mod.rs#EvidenceKind]].

## Specialized Detection Modules

Dedicated scanner modules inspect language runtimes, server configurations, and dependency manifests.

These checkers evaluate memory safety, authentication flows, secrets, and container isolation before remediation.
