# Failure Lessons Index

| ID | Title | Failure Class | Severity | Root Cause | Status | Rule Summary |
|---|---|---|---|---|---|---|
| `FL-001` | WalkDir Depth-0 Filtering Bug | Navigation / Filesystem | High | `!starts_with('.')` pruned hidden root directories | Verified | `[LEARN] Navigation: Always bypass hidden-file filters when WalkDir depth is 0 to avoid pruning hidden root directories.` |
| `FL-002` | Rust Edition Cadence & Compiler Limits | Architecture / Tooling | Medium | Assuming annual editions instead of 3-year epochs | Verified | `[LEARN] Architecture: Rust compiler editions strictly adhere to 3-year epochs (2015, 2018, 2021, 2024, 2027); annual editions do not exist.` |
| `FL-003` | Battle-Tested Crates vs Hand-Rolled Wheels | Architecture / Ponytail | High | Reinventing SemVer parsing, shell readline, and fs sandbox | Verified | `[LEARN] Architecture: Adopt battle-tested community standard crates (semver, rustyline, afero, ed25519) before hand-rolling custom primitives.` |
| `FL-004` | Agent Identity & Cryptographic Trust | Security / Identity | Critical | Unsigned backup manifests vulnerable to tamper & rollback attacks | Verified | `[LEARN] Security: Cryptographically sign all backup manifests with Ed25519 and fail closed on signature mismatch before rollback.` |
| `FL-005` | Cargo Dual-Target Module Scoping | Editing / Language | Low | Module declared in lib.rs not declared in main.rs | Verified | `[LEARN] Editing: When a Cargo package defines both lib and bin targets, ensure new submodules are declared in both roots or imported through the library name.` |

---

## Rules We Now Enforce

```text
[LEARN] Navigation: Always bypass hidden-file filters when WalkDir depth is 0 to avoid pruning hidden root directories.
[LEARN] Architecture: Rust compiler editions strictly adhere to 3-year epochs (2015, 2018, 2021, 2024, 2027); annual editions do not exist.
[LEARN] Architecture: Adopt battle-tested community standard crates (semver, rustyline, afero, ed25519) before hand-rolling custom primitives.
[LEARN] Security: Cryptographically sign all backup manifests with Ed25519 and fail closed on signature mismatch before rollback.
[LEARN] Editing: When a Cargo package defines both lib and bin targets, ensure new submodules are declared in both roots or imported through the library name.
```
