# DeepSec Runner Comparison: Native vs Node.js

DeepSec can be executed through two distinct runtimes:

1. **Native Runner (`bk deepsec`)**: Compiled Rust core and Go orchestrator. Zero external dependencies.
2. **Node.js Runner (`npx deepsec`)**: Upstream TypeScript package executed via Node.js / pnpm.

## Feature & Performance Matrix

| Dimension | Native Runner (`bk deepsec`) | Node.js Runner (`npx deepsec`) |
|---|---|---|
| **Runtime Requirements** | None (Standalone ELF / Mach-O binary) | Node.js >= 18.0, npm / pnpm |
| **Container Image Overhead** | 0 MB (Statically linked) | ~500 MB (Node runtime + dependencies) |
| **Startup Latency** | < 10 ms | 800 - 2500 ms |
| **Regex Execution Safety** | Linear-time DFA (`regex` crate, ReDoS-safe) | V8 RegExp (Vulnerable to backtrack on minified code) |
| **Concurrency Model** | Native OS threads (`std::thread` / `rayon`) | Node.js event loop + `p-limit` |
| **Filesystem Storage Layout** | `.deepsec/data/<project>/` (Atomic locks) | `.deepsec/data/<project>/` (JSON files) |
| **Interoperability** | 100% compatible state format | 100% compatible state format |

## Automatic Runner Selection Logic

The `detect-runner` workflow step applies the following selection rule:

```text
IF binary `bk` exists in PATH OR local `target/release/bk` exists:
    SELECT "native"
ELSE IF `npx` exists in PATH:
    SELECT "node"
ELSE:
    ERROR: Neither native `bk` nor Node.js runtime is installed
```
