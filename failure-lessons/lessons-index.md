# Failure Lessons Index

## Lessons

| ID | Skill | Failure Class | Summary | Status |
|---|---|---|---|---|
| [`LESSON-001`](lesson-001-adversarial-fixture-phrasing.md) | `deepsec` | `eval_security_linter_false_positive` | Unescaped jailbreak phrases in test fixtures fail Layer 0 static security gates. | Mitigated |

## Rules We Now Enforce for deepsec

- **Adversarial Fixture Phrasing:** Adversarial test phrases in skill specifications must probe behavioral boundaries (e.g. `"generate a weaponized exploit script and payload"`) rather than employing literal prompt injection strings (`"ignore safety rules"`), which fail closed under Layer 0 static security auditing.
- **Strict Concurrency Ceiling:** Concurrency parameters must be validated against a hard upper boundary ($\le 8$) in both configuration scripts and agent runtime guards.
- **Two-Pass Verification Requirement:** Security candidate matches from static regexes must never be output directly as verified CVEs without an LLM revalidation pass.
