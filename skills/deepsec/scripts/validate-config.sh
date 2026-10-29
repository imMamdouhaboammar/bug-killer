#!/usr/bin/env bash
set -euo pipefail

# DeepSec Configuration Validator
# Asserts structure, concurrency bounds, and budget safety

CONFIG_PATH="${1:-.deepsec/config.json}"

if [[ ! -f "$CONFIG_PATH" ]]; then
    echo "ERROR: Configuration file not found at $CONFIG_PATH" >&2
    exit 1
fi

python3 - "$CONFIG_PATH" <<'PY'
import json
import sys

with open(sys.argv[1], encoding='utf-8') as f:
    cfg = json.load(f)

concurrency = cfg.get('concurrency', 4)
if not (1 <= concurrency <= 8):
    print(f'ERROR: Concurrency {concurrency} exceeds safe boundary [1, 8]', file=sys.stderr)
    sys.exit(1)

max_cost = cfg.get('max_cost_usd', 0.0)
if max_cost <= 0.0:
    print('ERROR: max_cost_usd must be greater than 0.0', file=sys.stderr)
    sys.exit(1)

max_tokens = cfg.get('max_tokens', 0)
if max_tokens <= 0:
    print('ERROR: max_tokens must be greater than 0', file=sys.stderr)
    sys.exit(1)

print('VALID: DeepSec configuration syntax and bounds checked; provider cost limits are not enforced by this validator')
PY
