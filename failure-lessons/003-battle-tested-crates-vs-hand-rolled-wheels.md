# FL-003: Battle-Tested Crates vs Hand-Rolled Wheels

## Problem Statement

Initial iterations of Bug Killer relied on hand-rolled primitives:
1. Version parsing used ad-hoc string splitting (`str.split('.')`), failing on semantic version suffixes (e.g. `8.2.0-fpm`, `20.18.1-alpine`).
2. Terminal input in the interactive shell used raw `std::io::stdin().read_line()`, offering no cursor navigation, line editing, or persistent command history.
3. The Go orchestrator traversed directories using standard `os.ReadDir` and `filepath.Walk`, lacking in-memory mocking and symlink loop protection.

## Root Cause Analysis

Violating Ponytail Ladder Rung 5: attempting to reinvent infrastructure primitives instead of leveraging verified, community-standard, high-assurance security and system libraries.

In security tooling, hand-rolled parsers introduce subtle bugs (e.g., parser differential vulnerabilities, buffer overruns, or infinite loops on cyclic symlinks).

## Resolution & Library Integration

The architecture was overhauled to adopt established, community-vetted frameworks:

| Hand-Rolled Primitive | Replaced With | Crate / Library | Justification |
|---|---|---|---|
| Ad-hoc version string split | `semver::Version` & `VersionReq` | `semver = "1.0"` | Full SemVer 2.0.0 compliance, pre-release tagging, range comparisons |
| Raw stdin loop | GNU Readline REPL | `rustyline = "15.0"` | History persistence (`~/.bk_history`), line editing, ANSI support |
| Raw Go `filepath.Walk` | Abstracted Virtual Filesystem | `github.com/spf13/afero` | Safe sandboxed traversal (`afero.NewMemMapFs`), symlink loop defense |
| Ad-hoc binary byte search | Zero-copy binary parser | `goblin = "0.9"` | Cross-platform ELF, Mach-O, and PE header & symbol inspection |
| Unsigned JSON rollback files | Ed25519 digital signatures | `ed25519-dalek = "2.1"` | Cryptographic agent identity & tamper-evident manifest verification |

## Verification

The test suites verified complete compatibility and robustness:
- `cargo test --workspace` (4 test suites green)
- `go test -v ./...` in `services/orchestrator` (`TestFileCrawlerAferoMemoryFs` passing)

## Durable Invariant

```text
[LEARN] Architecture: Adopt battle-tested community standard crates (semver, rustyline, afero, ed25519) before hand-rolling custom primitives.
```
