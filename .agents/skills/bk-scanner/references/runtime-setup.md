# Bug Killer Scanner Runtime Setup & Pre-Flight

This reference defines the pre-flight checks required before executing read-only vulnerability inspections with Bug Killer (`bk`).

---

## 1. Pre-Flight Verification

Verify the following invariants prior to scanning:

| Check | Target | Requirement | Remediation |
|---|---|---|---|
| **Binary Handle** | `which bk` or local path | Executable binary present | Check `target/release/bug-killer` or compile via `cargo build --release`. |
| **Read Permissions** | Target workspace files | Read access to source files | Verify directory permissions; unreadable files cause coverage accounting to fail closed. |
| **Network (Optional)** | `osv.dev` API | Outbound HTTPS for live CVE resolution | If scanning in an isolated air-gapped environment, export `BK_OSV_OFFLINE=1`. |

---

## 2. Environment Variables

| Variable | Default | Purpose |
|---|---|---|
| `BK_LOG` | `info` | Control engine output verbosity (`error`, `warn`, `info`, `debug`). |
| `BK_OSV_OFFLINE` | `0` | When set to `1`, disables live HTTP lookups to OSV.dev and relies on local embedded CVE database. |
| `BK_CACHE_DIR` | `.bugkiller/cache` | Path for cached AST representations to accelerate re-scans. |

---

## 3. Read-Only Invariant Enforcement

The scanner engine is strictly non-destructive:
- It never touches file timestamps.
- It never writes modifications to scanned source files.
- It preserves SHA-256 file hashes across all scan operations.
