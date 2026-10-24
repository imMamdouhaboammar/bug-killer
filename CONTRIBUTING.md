# Contributing to Bug Killer

Thank you for contributing to Bug Killer. We enforce high engineering discipline, zero-slop code quality, strict defensive boundaries, and test verification.

## Development Prerequisites

- **Rust:** `cargo 1.85+` (2024 edition supported)
- **Go:** `go 1.22+`
- **Protobuf:** `protoc 3.x+` (optional for schema re-generation)

## Architecture Guidelines

1. **Memory Safety & Strict Bounded Slices:** The core analyzer in Rust prohibits unnecessary `unsafe` blocks. Memory parsing must use bounded slice abstractions.
2. **Deterministic Remediation:** Every patch action must be idempotent. Re-running a healer pass on an already-healed target must execute 0 mutations.
3. **Atomic Operations:** File modifications must use atomic write-and-replace (`NamedTempFile::persist`) with pre-calculated SHA-256 backup records.
4. **No Exploits in Repository:** Test fixtures must use synthetic version strings or non-weaponized symbol mocks. Never commit active shellcode.
5. **Attribution & License Compliance:** All contributions and forks remain under the Bug Killer Source-Available & Business Attribution License. Removing original author copyright notices is strictly forbidden.

## Quality Gates

Before opening a pull request, run:

```bash
# 1. Rust test & clippy pass
cargo clippy --all-targets -- -D warnings
cargo test --workspace

# 2. Go test & vet pass
cd services/orchestrator && go vet ./... && go test -v ./...
cd ../healer && go vet ./... && go test -v ./...

# 3. Microservices end-to-end integration pass
make test
```
