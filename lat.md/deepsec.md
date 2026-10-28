# DeepSec Agent Harness

The DeepSec harness provides an agent-powered vulnerability scanning and review pipeline.

It integrates high-speed Rust pattern scanning, atomic on-disk state tracking, and Go orchestrator worker pools to review codebases without Node.js dependencies.

## Scanning and Detection

Pattern matchers and technology detection identify candidate security vulnerabilities across multiple languages.

Deterministic regular expressions and technology gates in [[src/deepsec/scanner.rs#scan_repository]] populate [[src/deepsec/types.rs#CandidateMatch]] entries for investigation.

## Investigation and AI Processing

Candidate files are batched and reviewed by reasoning models with technology-specific prompt highlights.

The processor loop in [[src/deepsec/processor.rs#process_repository]] acquires atomic file locks and emits structured [[src/deepsec/types.rs#Finding]] records.

## Atomic State Storage

On-disk state is stored as append-only records with process-liveness and expiration checks.

State persistence and lock acquisition are handled by [[src/deepsec/storage.rs#StorageManager]] with atomic temporary file replacement.

## Revalidation and Triage

Findings undergo false-positive filtering, duplicate resolution, and priority triage.

The revalidation engine in [[src/deepsec/revalidate.rs#revalidate_findings]] assesses code mitigations and assigns [[src/deepsec/types.rs#RevalidationVerdict]] values.

## Orchestration and Sandboxing

The Go orchestrator coordinates distributed scan and process tasks in isolated filesystems.

Task scheduling and filesystem sandboxing are managed through [[services/orchestrator/deepsec/runner.go#Runner]] using Afero abstractions.
