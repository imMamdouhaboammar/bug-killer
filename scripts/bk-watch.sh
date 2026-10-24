#!/usr/bin/env bash
# Bug Killer Surveillance Watcher Daemon Wrapper
# Usage: ./scripts/bk-watch.sh [target_dir] [interval_secs] [--auto-heal]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

if command -v bk >/dev/null 2>&1; then
    BK_BIN="$(command -v bk)"
elif command -v bug-killer >/dev/null 2>&1; then
    BK_BIN="$(command -v bug-killer)"
elif [[ -f "${ROOT_DIR}/target/release/bug-killer" ]]; then
    BK_BIN="${ROOT_DIR}/target/release/bug-killer"
else
    BK_BIN="${ROOT_DIR}/target/debug/bug-killer"
fi

TARGET_DIR="${1:-.}"
INTERVAL="${2:-3}"
AUTO_HEAL_FLAG="${3:-}"

ARGS=("watch" "${TARGET_DIR}" "--interval" "${INTERVAL}")
if [[ "${AUTO_HEAL_FLAG}" == "--auto-heal" ]]; then
    ARGS+=("--auto-heal")
fi

echo "==> Starting Bug Killer Surveillance Engine on ${TARGET_DIR} (interval: ${INTERVAL}s)..."
exec "${BK_BIN}" "${ARGS[@]}"
