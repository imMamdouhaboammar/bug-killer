# Failure Lessons & Engineering Memory

> *"Pay for an engineering mistake once. After that, the project should remember it."*

This directory contains durable, evidence-backed engineering failure lessons, architectural decisions, and prevention invariants captured from real implementation, debugging, and verification sessions across the **Bug Killer** platform.

## Directory Structure

```text
failure-lessons/
├── README.md                                             # This document: Purpose & governance
├── lessons-index.md                                      # Comprehensive index of lessons & rules
├── 001-walkdir-depth-zero-filtering-bug.md               # WalkDir root pruning defect & fix
├── 002-rust-edition-cadence-and-compiler-limits.md       # Rust 3-year edition epoch invariant
├── 003-battle-tested-crates-vs-hand-rolled-wheels.md     # Ponytail ladder & community security crates
├── 004-agent-identity-and-cryptographic-trust.md         # Ed25519 manifest signing & rollback security
└── 005-cargo-dual-target-module-scoping.md               # Lib/bin target module visibility in Rust
```

## Governance & Invariants

1. **Facts Over Speculation:** Every lesson records concrete reproductions, code diffs, and verification commands.
2. **Actionable Prevention:** Every lesson produces a single, unambiguous `[LEARN]` invariant for future agents and human engineers.
3. **Red-Green Falsification:** Lessons are tested against real test cases in `tests/`.
