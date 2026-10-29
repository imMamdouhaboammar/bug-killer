#!/usr/bin/env bash
set -euo pipefail

# DeepSec Runtime Detector
# Identifies available execution environment (native vs node)

if command -v bug-killer >/dev/null 2>&1; then
    echo "native:$(command -v bug-killer)"
    exit 0
fi

if [[ -x "./target/release/bug-killer" ]]; then
    echo "native:./target/release/bug-killer"
    exit 0
fi

if [[ -x "./target/debug/bug-killer" ]]; then
    echo "native:./target/debug/bug-killer"
    exit 0
fi

echo "error:no_verified_native_runner (bundled Node CLI is a placeholder)" >&2
exit 1
