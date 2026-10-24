# Bug Killer (`bug-killer` / `bk`) — Technical Stack & Dependency Declaration

This document specifies the authoritative catalog of runtimes, compilers, container images, frameworks, and third-party libraries across all components of the Bug Killer polyglot architecture.

---

## 1. Runtimes, Compilers & Systems Toolchain

| Technology / Tool | Version / Standard | Scope & Purpose |
|---|---|---|
| **Rust Compiler (`rustc` / `cargo`)** | Edition 2024 (`1.85+` minimum, `1.99.1` verified local) | Core CLI engine, AST patch planner, and zero-copy binary inspector. |
| **Go Toolchain (`go`)** | Go `1.23+` (CI/Container), `1.26.5` (darwin/arm64 local) | Concurrent filesystem crawler, Unix socket daemon orchestrator, and WAF healer. |
| **Bun Runtime (`bun`)** | `1.4.3` | Mandated JavaScript/TypeScript runtime and package analyzer. |
| **Node.js (`node`)** | `v24.14.1` (Diagnostic & Target Runtime) | Node2Shell vulnerability benchmark and dependency evaluation target. |
| **Protocol Buffers (`protoc`)** | Protocol Buffers v3 (`proto3`) | Service-to-service IPC contract definition (`proto/aegis.proto`, `proto/omni_messaging.proto`). |
| **Docker Engine & OCI** | API v1.40+ (`/var/run/docker.sock`) | Raw socket container discovery and image layer inspection. |
| **Linux Native Utilities** | `libpcap-dev`, `ca-certificates`, `tzdata` | Deep packet inspection and secure container runtime dependencies. |

---

## 2. Container Images & Build Environments

| Environment | Base Image | Purpose |
|---|---|---|
| **Rust Builder** | `rust:1.85-bookworm` | Multi-stage Docker build for `bug-killer` CLI and `bug-killer-inspector`. |
| **Go Builder** | `golang:1.23-bookworm` | Multi-stage Docker build for `bug-killer-orchestrator` and `bug-killer-healer`. |
| **Runtime Container** | `alpine:3.20` | Minimal, hardened final production container image. |
| **CI Runner** | `ubuntu-latest` | GitHub Actions workflow host (`clippy`, `rustfmt`, `go test`, `go vet`). |

---

## 3. Core CLI Engine (`bug-killer`) — Rust Workspace Root

- **Package Name:** `bug-killer`
- **Package Version:** `0.1.0`
- **Language Edition:** Rust 2024
- **Binary Targets:** `bug-killer`, symlinked as `bk`

| Crate | Declared Version | Resolved Lockfile Version | Architectural Role |
|---|---|---|---|
| [`clap`](https://crates.io/crates/clap) | `4.5` (derive) | `4.6.7` | Command-line argument parsing, subcommands, and flags. |
| [`clap_complete`](https://crates.io/crates/clap_complete) | `4.5` | `4.6.11` | Automated shell completion generation (Bash, Zsh, Fish). |
| [`semver`](https://crates.io/crates/semver) | `1.0` | `1.0.28` | Semantic Versioning (SemVer 2.0.0) range evaluation and comparisons. |
| [`thiserror`](https://crates.io/crates/thiserror) | `2.0` | `2.0.21` | Type-safe, ergonomic error enumeration and propagation. |
| [`anyhow`](https://crates.io/crates/anyhow) | `1.0` | `1.0.104` | Top-level application error reporting with contextual stacks. |
| [`rustyline`](https://crates.io/crates/rustyline) | `15.0` | `15.0.0` | Interactive REPL (`bk shell`) with command history and line editing. |
| [`colored`](https://crates.io/crates/colored) | `3.0` | `3.1.1` | ANSI color terminal formatting for vulnerability reports. |
| [`tabled`](https://crates.io/crates/tabled) | `0.17` | `0.17.0` | Tabular terminal layout rendering for scan summaries. |
| [`ed25519-dalek`](https://crates.io/crates/ed25519-dalek) | `2.1` (rand_core) | `2.2.0` | Cryptographic Ed25519 signing and verification of backup manifests. |
| [`rand`](https://crates.io/crates/rand) | `0.8` | `0.8.8` | CSPRNG key generation for agent identity and nonce tokens. |
| [`serde`](https://crates.io/crates/serde) | `1.0` (derive) | `1.0.229` | Zero-copy serialization and deserialization traits. |
| [`serde_json`](https://crates.io/crates/serde_json) | `1.0` | `1.0.154` | JSON structured parsing for findings, manifests, and reports. |
| [`walkdir`](https://crates.io/crates/walkdir) | `2.5` | `2.5.0` | Fast, recursive filesystem traversal with depth and root filtering. |
| [`regex`](https://crates.io/crates/regex) | `1.11` | `1.13.1` | DFA-based regex pattern matching for taint sinks and SAST rules. |
| [`sha2`](https://crates.io/crates/sha2) | `0.10` | `0.10.9` | Cryptographic SHA-256 digest computation for file state integrity. |
| [`chrono`](https://crates.io/crates/chrono) | `0.4` (serde) | `0.4.45` | ISO 8601 UTC timestamp generation and historical audit records. |
| [`tempfile`](https://crates.io/crates/tempfile) | `3.17` | `3.27.0` | Atomic transactional file writes via temporary paths and atomic rename. |
| [`ureq`](https://crates.io/crates/ureq) | `3.5.0` (json) | `3.5.0` | Minimal, synchronous HTTP client for OSV.dev and DAST probes. |

---

## 4. Deep Binary Inspector (`services/inspector`) — Rust Service

- **Package Name:** `bug-killer-inspector`
- **Package Version:** `0.1.0`
- **Language Edition:** Rust 2024
- **Binary Target:** `bug-killer-inspector`

| Crate | Declared Version | Resolved Lockfile Version | Architectural Role |
|---|---|---|---|
| [`goblin`](https://crates.io/crates/goblin) | `0.9` | `0.9.3` | Zero-allocation binary disassembler for ELF, Mach-O, and PE headers. |
| [`memmap2`](https://crates.io/crates/memmap2) | `0.9` | `0.9.12` | Memory-mapped I/O (`mmap`) for large binary and core dump inspection. |
| [`tokio`](https://crates.io/crates/tokio) | `1.40` (full) | `1.54.1` | Asynchronous runtime for high-throughput I/O and gRPC services. |
| [`tokio-stream`](https://crates.io/crates/tokio-stream) | `0.1` (sync) | `0.1.19` | Async stream primitives for continuous process telemetry. |
| [`tonic`](https://crates.io/crates/tonic) | `0.12` | `0.12.3` | High-performance gRPC server and client implementation over UDS. |
| [`prost`](https://crates.io/crates/prost) | `0.13` | `0.13.5` | Protocol Buffers v3 runtime implementation for Rust. |
| [`tonic-build`](https://crates.io/crates/tonic-build) | `0.12` | `0.12.3` | Build-time `.proto` code generator (`build.rs`). |
| [`tower`](https://crates.io/crates/tower) | `0.4` (util) | `0.4.13` | Composable transport and service middleware abstraction. |
| [`hyper-util`](https://crates.io/crates/hyper-util) | `0.1` (tokio) | `0.1.21` | Tokio-compatible HTTP/2 and gRPC socket connectors. |
| [`rig-core`](https://crates.io/crates/rig-core) | `0.45.0` (reqwest) | `0.45.0` | Multi-model agent orchestration for security investigation flows. |
| [`async-stream`](https://crates.io/crates/async-stream) | `0.3` | `0.3.6` | Ergonomic asynchronous stream generator macros. |
| [`clap`](https://crates.io/crates/clap) | `4.5` (derive) | `4.6.7` | Inspector standalone CLI arguments. |
| [`serde`](https://crates.io/crates/serde) | `1.0` (derive) | `1.0.229` | Serialization framework for inspector reports. |
| [`serde_json`](https://crates.io/crates/serde_json) | `1.0` | `1.0.154` | JSON generation for `findings.json`. |
| [`regex`](https://crates.io/crates/regex) | `1.11` | `1.13.1` | String and symbol token scanning. |
| [`sha2`](https://crates.io/crates/sha2) | `0.10` | `0.10.9` | Binary file hashing and signature matching. |
| [`walkdir`](https://crates.io/crates/walkdir) | `2.5` | `2.5.0` | Directory inspection for shared library mappings. |
| [`chrono`](https://crates.io/crates/chrono) | `0.4` | `0.4.45` | Audit timestamps. |
| [`thiserror`](https://crates.io/crates/thiserror) | `2.0` | `2.0.21` | Typed inspector errors. |

---

## 5. Autopilot Healer (`services/healer`) — Go Service

- **Go Module:** `github.com/aegis/healer`
- **Language Version:** Go `1.26.5` (Compatible with Go `1.23+`)
- **Binary Target:** `bug-killer-healer`

| Module / Library | Resolved Version | Architectural Role |
|---|---|---|
| [`google.golang.org/grpc`](https://pkg.go.dev/google.golang.org/grpc) | `v1.71.0` | gRPC server over Unix Domain Sockets (`omni_messaging_grpc.pb.go`). |
| [`google.golang.org/protobuf`](https://pkg.go.dev/google.golang.org/protobuf) | `v1.36.5` | Protobuf serialization runtime (`omni_messaging.pb.go`). |
| `crypto/ed25519` (Standard Library) | Go stdlib | Manifest signature verification before transactional rollbacks. |
| `crypto/sha256` (Standard Library) | Go stdlib | State digest generation for patched reverse proxies. |
| [`golang.org/x/net`](https://pkg.go.dev/golang.org/x/net) | `v0.34.0` | Network primitives and HTTP/2 support. |
| [`golang.org/x/sys`](https://pkg.go.dev/golang.org/x/sys) | `v0.29.0` | Low-level OS syscalls, file permissions, and signal interception. |
| [`golang.org/x/text`](https://pkg.go.dev/golang.org/x/text) | `v0.21.0` | Text encoding transformations for configuration patchers. |
| [`google.golang.org/genproto/googleapis/rpc`](https://pkg.go.dev/google.golang.org/genproto/googleapis/rpc) | `v0.0.0-20250115164207-1a7da9e5054f` | Standard Google RPC status and error envelope definitions. |

---

## 6. Orchestrator Service (`services/orchestrator`) — Go Service

- **Go Module:** `github.com/aegis/orchestrator`
- **Language Version:** Go `1.26.5` (Compatible with Go `1.23+`)
- **Binary Target:** `bug-killer-orchestrator`

| Module / Library | Resolved Version | Architectural Role |
|---|---|---|
| [`github.com/open-policy-agent/opa`](https://pkg.go.dev/github.com/open-policy-agent/opa) | `v1.21.4` | Embedded Open Policy Agent (Rego) policy evaluation engine. |
| [`github.com/spf13/afero`](https://pkg.go.dev/github.com/spf13/afero) | `v1.15.0` | Sandboxed filesystem abstraction for safe directory traversal. |
| [`github.com/spf13/cobra`](https://pkg.go.dev/github.com/spf13/cobra) | `v1.10.2` | Orchestrator CLI command structure and subcommands. |
| [`github.com/spf13/viper`](https://pkg.go.dev/github.com/spf13/viper) | `v1.21.0` | Layered configuration management (flags, environment variables, files). |
| [`github.com/google/gopacket`](https://pkg.go.dev/github.com/google/gopacket) | `v1.1.19` | Raw network packet capture and HTTP/2 stream decoding. |
| [`google.golang.org/grpc`](https://pkg.go.dev/google.golang.org/grpc) | `v1.83.2` | gRPC client communicating with Inspector and Healer UDS sockets. |
| [`google.golang.org/protobuf`](https://pkg.go.dev/google.golang.org/protobuf) | `v1.36.12` | Protobuf serialization runtime. |
| [`github.com/dgraph-io/badger/v4`](https://pkg.go.dev/github.com/dgraph-io/badger/v4) | `v4.9.6` | High-performance embedded key-value store for coverage tracking. |
| [`github.com/dgraph-io/ristretto/v2`](https://pkg.go.dev/github.com/dgraph-io/ristretto/v2) | `v2.2.0` | High-performance, concurrent memory cache for policy decisions. |
| [`github.com/tetratelabs/wazero`](https://pkg.go.dev/github.com/tetratelabs/wazero) | `v1.12.0` | Zero-dependency WebAssembly runtime for sandboxed security plugins. |
| [`github.com/lestrrat-go/jwx/v3`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v3) | `v3.3.0` | Cryptographic JWT, JWS, and JWE parsing and validation. |
| [`github.com/fsnotify/fsnotify`](https://pkg.go.dev/github.com/fsnotify/fsnotify) | `v1.10.1` | Cross-platform filesystem event monitoring. |
| [`github.com/prometheus/client_golang`](https://pkg.go.dev/github.com/prometheus/client_golang) | `v1.24.1` | Prometheus metric instrumentation and health reporting. |
| [`go.opentelemetry.io/otel`](https://pkg.go.dev/go.opentelemetry.io/otel) | `v1.46.0` | OpenTelemetry distributed tracing and metrics pipeline. |
| [`github.com/olekukonko/tablewriter`](https://pkg.go.dev/github.com/olekukonko/tablewriter) | `v1.1.5` | Formatted terminal table output for discovery ledgers. |
| [`github.com/sirupsen/logrus`](https://pkg.go.dev/github.com/sirupsen/logrus) | `v1.10.2` | Structured logging with level and field filtering. |
| [`github.com/sourcegraph/conc`](https://pkg.go.dev/github.com/sourcegraph/conc) | `v0.3.1-0.20240121214520-5f936abd7ae8` | Structured concurrency and panic-safe Goroutine pools. |
| [`oras.land/oras-go/v2`](https://pkg.go.dev/oras.land/oras-go/v2) | `v2.6.2` | OCI Registry client for policy package distribution. |
| [`golang.org/x/crypto`](https://pkg.go.dev/golang.org/x/crypto) | `v0.57.0` | Cryptographic utilities and key derivations. |
| [`golang.org/x/net`](https://pkg.go.dev/golang.org/x/net) | `v0.60.0` | Network protocol adapters. |
| [`golang.org/x/sync`](https://pkg.go.dev/golang.org/x/sync) | `v0.23.0` | Synchronous concurrency primitives (`errgroup.Group`). |
| [`golang.org/x/sys`](https://pkg.go.dev/golang.org/x/sys) | `v0.48.0` | UNIX operating system interfaces. |

---

## 7. Protocols, Schemas & Security Standards

| Standard / Protocol | Version / Reference | Usage |
|---|---|---|
| **gRPC over UDS** | HTTP/2 / Unix Domain Sockets | Local inter-process communication (`/tmp/omni_inspector.sock`, `/tmp/omni_healer.sock`). |
| **Protocol Buffers** | v3 (`proto3`) | Binary schema contracts (`proto/aegis.proto`, `proto/omni_messaging.proto`). |
| **OSV Schema** | OpenSSF Schema v1.6.0 | Live vulnerability vulnerability advisory query format (`https://api.osv.dev/v1/query`). |
| **Ed25519** | RFC 8032 | Cryptographic non-repudiation for snapshot backup manifests (`.aegis/backups/`). |
| **Rego Policy Language** | OPA v1.0+ | Runtime authorization and defensive ingress traffic gating rules. |
| **SemVer** | SemVer 2.0.0 | Version comparison across NPM, Composer, PyPI, Cargo, Go, and Ruby packages. |
