# Mission: Convert This Session Into Durable Project Learnings This session contains engineering knowledge that should not disappear

## Project Identity & Operational Governance

- **Repository:** `bug-killer` (`bk`)
- **Remote Origin:** `https://github.com/imMamdouhaboammar/bug-killer.git`
- **License:** Bug Killer Source-Available & Business Attribution License v1.0 ([`LICENSE`](file:///Users/mamdouhaboammar/Documents/antigravity/silly-kepler/LICENSE))
  - Author: `Mamdouh Aboammar` (Copyright (c) 2026)
  - Terms: Forking, inspection, and modification permitted with mandatory attribution retention. Commercial/business internal use permitted at zero cost. Prohibited: offering or packaging as a paid service, SaaS, or commercial managed service without prior explicit written permission.
- **Architectural Scope:** Autonomous Vulnerability Finder & Virtual Healer targeting critical runtime memory corruption and out-of-bounds execution (e.g. PHP2Shell `CVE-2026-109618` / `CVE-2026-109619`, Node2Shell `CVE-2026-111497`).

---

## The Ponytail Ladder & Engineering Standards

Every agent contributing to this repository must climb the Ponytail Ladder before authoring custom code:

1. **Rung 1 — Problem Definition:** Identify exact failure modes, CVE blast radius, and system boundaries before proposing solutions.
2. **Rung 2 — Prior Art & RFCs:** Ground architectures in official specifications (RFC 2052 for Rust editions, SemVer 2.0.0, POSIX signals).
3. **Rung 3 — Interface First:** Define type-safe domain models (`CveDatabase`, `ScanReport`, `Vulnerability`, `BackupManifest`) before engine mechanics.
4. **Rung 4 — Red-Green Falsification:** A test is not proven useful until shown to fail when the fix is removed. Never commit unverified assertions.
5. **Rung 5 — Battle-Tested Community Crates:** Prohibit hand-rolling primitives when audited, community-standard crates exist:
   - Rust: `semver = "1.0"`, `rustyline = "15.0"`, `goblin = "0.9"`, `ed25519-dalek = "2.1"`, `clap = "4.5"`.
   - Go: `github.com/spf13/afero v1.15.0` (sandboxed in-memory filesystem abstraction).

---

## Rules We Now Enforce

```text
[LEARN] Navigation: Always bypass hidden-file filters when WalkDir depth is 0 to avoid pruning hidden root directories.
[LEARN] Architecture: Rust compiler editions strictly adhere to 3-year epochs (2015, 2018, 2021, 2024, 2027); annual editions do not exist.
[LEARN] Architecture: Adopt battle-tested community standard crates (semver, rustyline, afero, ed25519) before hand-rolling custom primitives.
[LEARN] Security: Cryptographically sign all backup manifests with Ed25519 and fail closed on signature mismatch before rollback.
[LEARN] Editing: When a Cargo package defines both lib and bin targets, ensure new submodules are declared in both roots or imported through the library name.
```

---

## Architectural & Security Invariants

1. **Strictly Defensive Perimeter:**
   Zero exploit generation, weaponized payload authoring, or offensive shellcode generation. The engine's sole function is detection, virtual patching, runtime hardening, and cryptographic rollback.

2. **The Direct Payload & Zero Affordance Narration Invariant:**
   Transition directly from domain headers to technical payloads (tables, code, schemas) with zero transitional fluff. Ban affordance narration, conversational preambles, and mechanical hand-holding.

3. **Zero-Obviousness & Anti-Truism Doctrine:**
   High engineering discipline values silence over noise. Ban trivial play-by-play comments, tautological docstrings, and patronizing microcopy.

4. **Cryptographic Non-Repudiation on State Mutations:**
   All healing operations that write to disk must compute SHA-256 digests of modified files, generate an Ed25519 signature over the manifest using the autonomous agent identity key (`~/.bug-killer/identity/agent.key`), and verify this signature before executing rollback.

5. **Afero-Sandboxed Filesystem Operations (Go):**
   File discovery, directory traversal, and artifact extraction must be conducted through `afero.Fs` abstraction layers to ensure testability and prevent cyclic symlink or path traversal exploits.

6. **Zero-Copy Binary Parsing (Rust):**
   Inspection of ELF, Mach-O, and PE runtime binaries must execute via `goblin` over memory-mapped files (`memmap2`) with zero allocations in the parsing loop.

---

## Verification & CI Commands

Before pushing any commit or opening a pull request, the following gates must be green:

```bash
# 1. Rust workspace test suite
cargo test --workspace

# 2. Rust strict linter check (zero warnings permitted)
cargo clippy --all-targets -- -D warnings

# 3. Go microservices test suite
cd services/orchestrator && go test -v ./... && cd ../..
cd services/healer && go test -v ./... && cd ../..

# 4. Go strict vet check
cd services/orchestrator && go vet ./... && cd ../..
cd services/healer && go vet ./... && cd ../..

# 5. Git status cleanliness check
git status --porcelain
```
