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

The 26 security detectors are partitioned into domain submodules in `src/detectors/` (`sast`, `secrets`, `iac`, `agent`, `supply_chain`, `web`, `auth`, `quality`), all implementing [[src/detectors/mod.rs#SecurityDetector]]. The registry [[src/detectors/mod.rs#DetectorRegistry]] coordinates execution, catalog rule coverage accounting, and honest partial/completed scan status classification via [[src/detectors/mod.rs#DetectorRegistry#execute_guard_scan]]. Behavior and registration order parity are verified in `tests/detector_modular_dispatch_test.rs`.

## Consolidated Finding Construction

Standardized finding builder unifies finding instantiation, ID tagging, evidence references, and cryptographic fingerprints.

The consolidated [[src/scanner/finding_builder.rs#ScannerFindingBuilder]] constructs validated findings from [[src/scanner/finding_builder.rs#ScannerFindingSpec]]. It retains detector-specific reachability and advisory policies (such as `ScannerFindingBuilder::native_desktop` and `ScannerFindingBuilder::auth_security`) while eliminating broad parameter-count suppressions and redundant boilerplate across scanner modules. Parity is verified in `tests/scanner_finding_builder_test.rs`.

## Directory and Dependency Tree Exclusion

Non-source assets, build artifacts, and third-party dependencies are excluded from file tree traversal.

The centralized filter [[src/scanner/mod.rs#is_ignored_directory]] prunes virtual environments, lock directories, build outputs (`.venv`, `node_modules`, `target`, `dist`, `build`), and secret keys (`.aegis`, `.bugkiller`) during directory traversal. This bounds evaluation strictly to first-party source assets and prevents scanner hangs and false positive explosions.
