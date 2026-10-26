#!/usr/bin/env bash
# Local, offline checks for the architecture ZIP; not a scanner test suite.
set -euo pipefail

spec_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

for tool in jq awk; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    printf 'Missing required tool: %s\n' "$tool" >&2
    exit 2
  fi
done

for filename in "$spec_root"/schemas/*.json "$spec_root"/examples/*.json; do
  jq empty "$filename"
done

for filename in "$spec_root"/*.md; do
  awk '/^```/ { count++ } END { if (count % 2 != 0) exit 1 }' "$filename" || {
    printf 'Unbalanced Markdown code fences: %s\n' "$filename" >&2
    exit 1
  }
done

for name in finding coverage-receipt repair-plan analysis-request analysis-response tool-capability tool-execution-receipt disclosure-packet; do
  test -s "$spec_root/schemas/$name.schema.json"
done

jq -e '.kind == "RESEARCH_CANDIDATE" and .status == "SUSPECTED" and .evidence_certainty == "SUSPECTED" and .proof == null' \
  "$spec_root/examples/research-candidate.json" >/dev/null
jq -e '.status == "COMPLETED" and (.findings | length) == 0 and (.receipts | length) == 1 and .receipts[0].status == "EVALUATED"' \
  "$spec_root/examples/analysis-response.json" >/dev/null
jq -e '.installation == "MISSING" and .governance.license_review == "PENDING"' \
  "$spec_root/examples/tool-capability.json" >/dev/null
jq -e '.status == "NOT_RUN" and .reason_code == "ENGINE_MISSING" and (.artifacts | length) == 0' \
  "$spec_root/examples/tool-execution-receipt.json" >/dev/null

# Deliberately narrow offline checks: required top-level fields and unexpected
# top-level properties in the two new examples; not a full JSON Schema validator.
for record in tool-capability tool-execution-receipt disclosure-packet; do
  jq -e --slurpfile contract "$spec_root/schemas/$record.schema.json" \
    '([ $contract[0].required[] ] - keys | length) == 0 and ((keys - ($contract[0].properties | keys)) | length) == 0' \
    "$spec_root/examples/$record.json" >/dev/null
done

test -s "$spec_root/TRACEABILITY.csv"
test -s "$spec_root/AGENT-EXECUTION-BRIEF.md"
test -s "$spec_root/14-AGENTIC-SECURITY-OPERATIONS-ROOM.md"

printf 'Specification packaging and syntax smoke checks passed.\n'
