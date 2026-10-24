---
name: karpathy-guidelines
description: Behavioral guidelines to reduce common LLM coding mistakes, overcomplication, and unintended edits. Use when writing, reviewing, debugging, or refactoring code, adding features, or fixing bugs — even if the user doesn't explicitly mention "karpathy guidelines". Do NOT use for non-coding tasks, creative writing, or general knowledge questions.
license: MIT
metadata:
  author: Andrej Karpathy & Multica AI
  version: 1.0.0
  source: https://github.com/multica-ai/andrej-karpathy-skills
compatibility: claude-code, gemini-cli, antigravity, codex, chatgpt, cursor, windsurf
---

# Karpathy Guidelines

Behavioral guidelines to reduce common LLM coding mistakes, derived from [Andrej Karpathy's observations](https://x.com/karpathy/status/2015883857489522876) on LLM coding pitfalls.

**Tradeoff:** These guidelines bias toward caution over speed. For trivial tasks, use judgment.

---

## Runtime Requirements (Pre-flight)

Before executing mutations, verify the target workspace and toolchain -> [`references/runtime-setup.md`](references/runtime-setup.md).

---

## 1. Think Before Coding

**Don't assume. Don't hide confusion. Surface tradeoffs.**

Before implementing:
- State your assumptions explicitly. If uncertain, ask.
- If multiple interpretations exist, present them - don't pick silently.
- If a simpler approach exists, say so. Push back when warranted.
- If something is unclear, stop. Name what's confusing. Ask.

Detailed before/after comparisons -> [`references/examples.md#1-think-before-coding`](references/examples.md).

---

## 2. Simplicity First

**Minimum code that solves the problem. Nothing speculative.**

- No features beyond what was asked.
- No abstractions for single-use code.
- No "flexibility" or "configurability" that wasn't requested.
- No error handling for impossible scenarios.
- If you write 200 lines and it could be 50, rewrite it.

Ask yourself: "Would a senior engineer say this is overcomplicated?" If yes, simplify.

Concrete overengineering examples -> [`references/examples.md#2-simplicity-first`](references/examples.md).

---

## 3. Surgical Changes

**Touch only what you must. Clean up only your own mess.**

When editing existing code:
- Don't "improve" adjacent code, comments, or formatting.
- Don't refactor things that aren't broken.
- Match existing style, even if you'd do it differently.
- If you notice unrelated dead code, mention it - don't delete it.

When your changes create orphans:
- Remove imports/variables/functions that YOUR changes made unused.
- Don't remove pre-existing dead code unless asked.

The test: Every changed line should trace directly to the user's request.

Surgical editing walkthrough -> [`references/examples.md#3-surgical-changes`](references/examples.md).

---

## 4. Goal-Driven Execution

**Define success criteria. Loop until verified.**

Transform tasks into verifiable goals:
- "Add validation" -> "Write tests for invalid inputs, then make them pass"
- "Fix the bug" -> "Write a test that reproduces it, then make it pass"
- "Refactor X" -> "Ensure tests pass before and after"

For multi-step tasks, state a brief plan:
```text
1. [Step] -> verify: [check]
2. [Step] -> verify: [check]
3. [Step] -> verify: [check]
```

Strong success criteria let you loop independently. Weak criteria ("make it work") require constant clarification.

Verification loops and test patterns -> [`references/examples.md#4-goal-driven-execution`](references/examples.md).

---

## Reference Map

| Resource | Purpose |
|---|---|
| [`references/examples.md`](references/examples.md) | Real-world before/after code walkthroughs across all 4 principles |
| [`references/anti-patterns.md`](references/anti-patterns.md) | High-frequency LLM failure modes and concrete remediation |
| [`references/runtime-setup.md`](references/runtime-setup.md) | Pre-flight environment, verification, and host capability profiles |
