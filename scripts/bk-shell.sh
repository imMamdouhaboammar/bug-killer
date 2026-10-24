#!/usr/bin/env bash
# Bug Killer Interactive Shell Launcher
# Usage: ./scripts/bk-shell.sh [workspace_path]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Resolve binary
if command -v bk >/dev/null 2>&1; then
    BK_BIN="$(command -v bk)"
elif command -v bug-killer >/dev/null 2>&1; then
    BK_BIN="$(command -v bug-killer)"
elif [[ -f "${ROOT_DIR}/target/release/bug-killer" ]]; then
    BK_BIN="${ROOT_DIR}/target/release/bug-killer"
elif [[ -f "${ROOT_DIR}/target/debug/bug-killer" ]]; then
    BK_BIN="${ROOT_DIR}/target/debug/bug-killer"
else
    echo "==> Building bug-killer in release mode..."
    (cd "${ROOT_DIR}" && cargo build --release)
    BK_BIN="${ROOT_DIR}/target/release/bug-killer"
fi

TARGET_PATH="${1:-.}"

echo "==> Launching Bug Killer Shell via ${BK_BIN}..."
exec "${BK_BIN}" shell "${TARGET_PATH}"
