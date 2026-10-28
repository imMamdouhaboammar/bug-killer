# DeepSec Agent Harness

The DeepSec harness provides an agent-powered vulnerability scanning and review pipeline.

It integrates Rust pattern scanning, JSON state records, and Go orchestrator workers. Results are preliminary until a real backend and independent verification are available.

## Scanning and Detection

Pattern matchers and technology detection identify candidate security vulnerabilities across multiple languages.

Deterministic regular expressions and technology gates in [[src/deepsec/scanner.rs#scan_repository]] populate [[src/deepsec/types.rs#CandidateMatch]] entries for investigation.

## Investigation and AI Processing

The Rust CLI requires an explicitly configured HTTPS AI endpoint and API key for investigation. The Go worker currently performs deterministic pattern classification only.

The processor in [[src/deepsec/processor.rs#process_repository]] updates structured [[src/deepsec/types.rs#Finding]] records. It rejects malformed responses and unknown file attributions. Per-file claims use a cross-process advisory mutex; the full lifecycle still lacks proven crash recovery.

## Atomic State Storage

On-disk state uses replaceable JSON files with process-liveness and expiration checks; it is not an append-only event log.

State writes in [[src/deepsec/storage.rs#StorageManager]] use temporary file replacement and validate project/file path components. File-claim operations serialize read/modify/write under an advisory mutex; filesystem durability and safe crash/stale-lock recovery are not guaranteed.

## Revalidation and Triage

Findings undergo duplicate grouping and severity-based priority triage. A pattern match or model explanation is not proof of exploitability.

The revalidation engine in [[src/deepsec/revalidate.rs#revalidate_findings]] reports `UNCERTAIN` without independent validation rather than claiming a true positive, fix, or false positive from source-file keywords.

## Orchestration and Sandboxing

The Go orchestrator coordinates distributed scan and process tasks in isolated filesystems.

Task scheduling and filesystem sandboxing are managed through [[services/orchestrator/deepsec/runner.go#Runner]] using Afero abstractions.
