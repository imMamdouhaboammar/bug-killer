# Implementation agent brief: Bug Killer ultimate roadmap

You are implementing the architecture in this ZIP against `https://github.com/imMamdouhaboammar/bug-killer`.

## Non-negotiable instructions

1. Read every document in this ZIP, the repository's current AGENTS.md, README, Cargo/Go manifests, test fixtures, open issues and current main source before writing code. Any discrepancy between the spec's 2026-10-25 baseline and current source must be documented, not hidden.
2. Follow `10-IMPLEMENTATION-PLAN.md` milestone dependency graph. First revalidate and finish the existing safety and coverage issues in [tracker #22](https://github.com/imMamdouhaboammar/bug-killer/issues/22); do not jump to autonomous research/privileged healing.
3. Use small scoped PRs with meaningful atomic commits. One coherent behavior contract per PR. Do not create artificial commit counts. Do not directly push to main; do not merge without required checks and review.
4. TDD for each behavior: demonstrate a failing regression on the old path, make it pass, add negative controls, run integration checks and show exact commands/results. Fix scanner and schema errors instead of suppressing errors or relaxing tests.
5. Use established engines according to ADRs. Avoid custom parser, crypto primitive, license bypass or broad framework rebuild. Keep optional engines optional and offline Quick usable.
6. Enforce strict defensive scope. No public exploit tools, real victim tests, remote unauthorized scanning, live secrets, arbitrary advisory scripts or unapproved external disclosure.
7. Keep operator approval distinct from agent identity; modifications restricted to exact authorized root, preimages and operation class. Fail closed and make rollback truthfully report failure.
8. Never label a detector's registered ID as an executed rule without rule-target receipt. Never call a candidate "zero-day", "confirmed", or "repaired" without corresponding reproducible proof.
9. Preserve legacy CLI/MCP behavior unless a versioned migration with compatibility tests is accepted.
10. Each PR must include a short implementation summary, risk analysis, regression evidence, measured performance where relevant, user-visible behavior, backward compatibility and rollback plan.

## First agent task

**M0 audit and work-order reconciliation:**

- Fetch the latest master and issue tracker.
- Validate issues #10–#24 against current implementation following PR #25. For each: `resolved/partial/open` with exact source and tests; do not close without explicit complete acceptance proof.
- List blocking trust boundaries for privileged healing and coverage.
- Produce a dependency-ordered worklist and select the smallest testable first PR.
- Implement that PR via red/green TDD, independent review and all relevant quality gates. Update issue status and link the PR.
- Do not begin M2 parser integration until M0 coverage envelope contract is stable.

## Standard work-card output

```text
Card ID / PR:
Source commit:
Requirement IDs:
Observed failure:
Negative test that failed before fix:
Owned behavior and shared contracts:
Out-of-scope:
Dependency:
Implementation and files:
Verification commands/results:
Security regression matrix:
Compatibility:
Rollback:
Review comments and resolutions:
Merge readiness:
```

## Exit conditions for each milestone

M0: no unapproved privileged write; true partial scan classification.  
M1: versioned adapters and benchmark reproducibility.  
M2: AST precision proven on representative migrated rules, Quick latency measured.  
M3: exact advisory correlation and tested repairs, no blind upgrades.  
M4: optional dataflow trace with uncertainty and sidecar isolation.  
M5: bounded research reproduction and no external effects.  
M6: private reporting drafts with fresh explicit approval to send.

## Reporting format

Every status update must separate `DONE`, `TESTED`, `NOT_RUN`, `BLOCKED`, `UNKNOWN` and `FOLLOW_UP`. Never claim merges or passing tests without tool evidence. If policy authorization, upstream license or runtime isolation remains unresolved, stop only the affected operation and continue safe, read-only tasks.
