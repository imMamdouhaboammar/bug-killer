# FL-005: Cargo Dual-Target Module Scoping

## Problem Statement

When implementing the cryptographic agent identity submodule, `mod identity;` was declared in `src/lib.rs`.

However, executing `cargo build` or `cargo test --workspace` failed with a compilation error on the binary target:

```text
error[E0433]: failed to resolve: use of undeclared crate or module `identity`
  --> src/main.rs:25:9
   |
25 |     identity::verify_manifest_authenticity(&manifest)?;
   |     ^^^^^^^^ could not find `identity` in the crate root
```

## Root Cause Analysis

In Cargo, a package that defines both a library target (`src/lib.rs`) and a binary target (`src/main.rs`) compiles two separate compilation units (crate roots).

Declaring `mod identity;` inside `src/lib.rs` scopes the module to the library crate root (`bug_killer::identity`). It does **not** make `crate::identity` visible inside `src/main.rs`. Unless `src/main.rs` either:
1. Re-declares `mod identity;` (compiling the module twice), or
2. Imports the item from the library root (`use bug_killer::identity;`)

The symbol cannot be resolved inside the binary target.

## Resolution

In `src/main.rs`, the binary target was configured to import through the library root or declare the module root explicitly:

```rust
// In src/main.rs:
mod identity; // or: use bug_killer::identity;
```

This ensures both the standalone CLI binary (`bk`) and integration tests linking against `bug_killer` can access identity and cryptographic verification routines.

## Verification

```bash
cargo check --all-targets
cargo test --workspace
```

Both commands completed with zero errors and zero warnings under `-D warnings`.

## Durable Invariant

```text
[LEARN] Editing: When a Cargo package defines both lib and bin targets, ensure new submodules are declared in both roots or imported through the library name.
```
