# DeepSec Runner Comparison: Native vs Node.js

The current source tree has one implemented local CLI path:

1. **Native Runner (`bug-killer deepsec`)**: Compiled Rust CLI; requires an HTTPS AI backend and key for `process`.
2. **Node.js Runner (`npx deepsec`)**: Not implemented by the bundled `bin/cli.js`; the placeholder exits unsuccessfully.

## Feature & Performance Matrix

| Dimension | Native Runner (`bug-killer deepsec`) | Bundled Node placeholder |
|---|---|---|
| **Runtime Requirements** | Built Rust binary; configured backend for investigation | Node.js, but no implementation |
| **Candidate Scanner** | Rust deterministic regex matchers | Not available |
| **Filesystem Storage Layout** | `.deepsec/data/<project>/` (JSON replacement; locks not cross-process atomic) | Not available |
| **Interoperability** | Go and Rust record contracts require integration verification | Not established |

## Automatic Runner Selection Logic

The `detect-runner` workflow step applies the following selection rule:

```text
IF binary `bug-killer` exists in PATH OR local target/release/bug-killer exists:
    SELECT "native"
ELSE:
    ERROR: No verified native runner is installed; the Node placeholder is not a fallback
```
