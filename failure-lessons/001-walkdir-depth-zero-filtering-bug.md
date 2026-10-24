# FL-001: WalkDir Depth-0 Filtering Bug

## Problem Statement

During the development of the filesystem surveillance engine (`src/watcher/mod.rs`), unit and integration tests executing in isolated temporary directories panicked with:

```text
assertion failed: !snapshot.is_empty()
thread 'watcher::tests::test_watcher_snapshot_mtimes' panicked at src/watcher/mod.rs:188:9
```

The watcher failed to register any files in the directory tree despite files being affirmatively created prior to snapshot invocation.

## Root Cause Analysis

The directory walker was implemented using `walkdir::WalkDir` with an entry filter designed to skip hidden dotfiles and hidden system directories:

```rust
// Faulty implementation:
WalkDir::new(root)
    .into_iter()
    .filter_entry(|entry| {
        let name = entry.file_name().to_string_lossy();
        !name.starts_with('.') && name != "node_modules" && name != "vendor"
    })
```

When tests create temporary working directories via `tempfile::tempdir()`, the host operating system (macOS / Linux) frequently provisions paths containing dot-prefixed directory names (e.g., `/var/folders/.../.tmpAbC123/`).

Because `WalkDir::filter_entry` evaluates the root path itself as depth `0`, the predicate `!name.starts_with('.')` evaluated to `false` for the root directory. Consequently, `WalkDir` pruned the root directory immediately, descending into zero subdirectories and discovering zero files.

## Resolution & Code Diff

The filter predicate was updated to explicitly bypass the dot-prefix check for the root entry at depth `0`:

```rust
// Corrected implementation:
WalkDir::new(root)
    .into_iter()
    .filter_entry(|entry| {
        // Depth 0 is the root path itself; never prune root even if its path contains a dot
        if entry.depth() == 0 {
            return true;
        }
        let name = entry.file_name().to_string_lossy();
        !name.starts_with('.') && name != "node_modules" && name != "vendor"
    })
```

## Verification

The test `test_watcher_snapshot_mtimes` was executed against temporary directories and confirmed passing:

```bash
cargo test test_watcher_snapshot_mtimes
```

## Durable Invariant

```text
[LEARN] Navigation: Always bypass hidden-file filters when WalkDir depth is 0 to avoid pruning hidden root directories.
```
