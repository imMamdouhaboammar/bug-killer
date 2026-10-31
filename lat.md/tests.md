---
lat:
  require-code-mention: true
---
# Test Suite Specifications

Verification specifications for Bug Killer security invariants, remediation gates, and benchmark classifiers.

All leaf sections in this document are enforced and backed by code references in the test suite.

## Safety Boundaries

Architectural invariants ensuring scanning operations remain read-only and fail closed.

### Scan Is Strictly Read-Only

Security scans never mutate files on disk or corrupt cryptographic hashes during execution.

### Incomplete Coverage Is Not Clean

Scans with missing adapters or unassessed targets fail closed rather than falsely reporting clean status.

## Supervised Remediation

Remediation invariants ensuring cryptographic approval receipts, non-repudiation, and rollback.

### Plan Checksum Determinism

Healing plan checksums are strictly deterministic and immediately detect any in-flight mutation or tampering.

### Approval Receipt Verification

Operator approval receipts validate Ed25519 signatures, canonical roots, nonces, and expiration windows.

### Post-Verification Fault Triggers Automatic Rollback

Failed post-remediation verification triggers an immediate bit-for-bit rollback restoring original state.

## Benchmark Gates

Classifier evaluation benchmarks ensuring reproducible metrics and anti-tamper detection.

### Tamper Free Corpus Loading

Evaluation corpus manifests and targets are verified against cryptographically signed digests on loading.

### Repeated Runs Produce Identical Fingerprints

Successive benchmark execution runs produce byte-for-byte identical metrics and cryptographic fingerprints.

## DeepSec Harness Specifications

End-to-end verification of the agent-powered DeepSec scanning, processing, and locking harness.

### Full Pipeline Lifecycle Verification

Verifies scanning, candidate matching, AI processing, triage, revalidation, enrichment, and export across the full lifecycle.

### Atomic File Locking And Reclaim

Validates that concurrent workers cannot clobber active locks and stale locks are safely reclaimed.

## MCP Tool Registry Parity Tests

Every tool advertised by the MCP server's typed domain registry is listed with a non-empty name, description, and object input schema, and is recognized by JSON-RPC tools/call dispatch.
