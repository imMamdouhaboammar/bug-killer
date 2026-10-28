#!/usr/bin/env bash
set -euo pipefail

# DeepSec Runtime Detector
# Identifies available execution environment (native vs node)

if command -v bk >/dev/null 2>&1; then
    echo "native:$(command -v bk)"
    exit 0
fi

if [[ -x "./target/release/bk" ]]; then
    echo "native:./target/release/bk"
    exit 0
fi

if [[ -x "./target/debug/bk" ]]; then
    echo "native:./target/debug/bk"
    exit 0
fi

if command -v npx >/dev/null 2>&1; then
    echo "node:$(command -v npx)"
    exit 0
fi

echo "error:no_runner_found" >&2
exit 1
