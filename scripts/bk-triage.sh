#!/usr/bin/env bash
# Bug Killer Rapid Triage Utility
# Usage: ./scripts/bk-triage.sh [target_dir]

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
else
    BK_BIN="${ROOT_DIR}/target/debug/bug-killer"
fi

TARGET_DIR="${1:-.}"

echo "======================================================="
echo "  ⚡ BUG KILLER RAPID SECURITY TRIAGE"
echo "======================================================="
echo "Target: ${TARGET_DIR}"
echo

echo "==> Step 1: Running System Doctor..."
"${BK_BIN}" doctor "${TARGET_DIR}"

echo
echo "==> Step 2: Running Deep Vulnerability Audit..."
"${BK_BIN}" scan "${TARGET_DIR}" --check-runtime

echo
echo "==> Step 3: Checking Planned Remediation Actions..."
"${BK_BIN}" heal "${TARGET_DIR}" --dry-run

echo
echo "======================================================="
echo "  TRIAGE COMPLETE"
echo "  - To heal all safe targets:  bk heal ${TARGET_DIR} --auto-apply"
echo "  - To launch interactive REPL: bk shell ${TARGET_DIR}"
echo "======================================================="
