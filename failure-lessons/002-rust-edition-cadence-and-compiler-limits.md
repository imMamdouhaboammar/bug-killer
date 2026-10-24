# FL-002: Rust Edition Cadence & Compiler Limits

## Problem Statement

During an architecture review, the question was raised:
> *"Why Rust (2024)? Why not Rust (2026)?"*

Attempting to configure `edition = "2026"` in a Cargo manifest results in an immediate compilation abort by the compiler:

```text
error: failed to parse manifest at `/path/to/Cargo.toml`

Caused by:
  supported edition values are `2015`, `2018`, `2021`, `2024`, or `future`, but `2026` was specified
```

## Root Cause Analysis

Rust compiler editions do not follow annual calendar release numbering. Instead, the Rust Project adheres to a formal 3-year edition epoch cadence governed by RFC 2052:

| Edition | Release Window | Minimum Rust Version | Primary Milestones |
|---|---|---|---|
| **`2015`** | May 2015 | `rustc 1.0` | Initial stable language definition |
| **`2018`** | December 2018 | `rustc 1.31` | Non-lexical lifetimes, module system overhaul, `async`/`await` |
| **`2021`** | October 2021 | `rustc 1.56` | Disjoint closure captures, `IntoIterator` for arrays, Cargo resolver v2 |
| **`2024`** | February 2025 | `rustc 1.85` | RPITIT, async closures, std prelude changes, gen blocks |
| **`2027`** | Expected Late 2027 | ~`rustc 1.109` | Next planned edition epoch |

There is no `2026` edition in the Rust language standard. While minor compiler releases occur every 6 weeks (e.g. `1.85`, `1.86`, `1.99`), edition boundaries introduce breaking syntactic changes and are reserved strictly for 3-year epochs.

## Resolution

All workspace packages in Bug Killer must declare the latest standardized edition:

```toml
[package]
name = "bug-killer"
version = "0.1.0"
edition = "2024"
```

## Durable Invariant

```text
[LEARN] Architecture: Rust compiler editions strictly adhere to 3-year epochs (2015, 2018, 2021, 2024, 2027); annual editions do not exist.
```
