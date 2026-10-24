# Anti-Patterns Summary

A catalog of high-frequency LLM coding mistakes, their underlying causes, and direct remediation tactics.

---

## 1. The Speculative Architect

- **Symptom:** The user asks for a simple utility function, and the LLM responds with a generic abstract base class, factory patterns, strategy interfaces, and configuration builders.
- **Root Cause:** Overfitting to enterprise design pattern training corpora without respecting Occam's razor.
- **Remediation:** Enforce the Rule of Three: write concrete code for the immediate requirement. Never introduce an abstraction until at least three distinct call sites demand it.

---

## 2. The Orthogonal Janitor

- **Symptom:** While fixing a one-line bug, the LLM re-formats whitespace, renames unrelated variables, updates comments in adjacent functions, and deletes unused imports across the whole file.
- **Root Cause:** Misguided helpfulness and token completion drift.
- **Remediation:** Strict surgical editing. Every line in the diff must trace directly to the user's explicit request. Leave existing code, style, and comments intact unless directly requested.

---

## 3. The Silent Guesser

- **Symptom:** When faced with an ambiguous requirement or multiple valid interpretations, the LLM silently picks one interpretation without notifying the user.
- **Root Cause:** Bias toward immediate generation over clarification.
- **Remediation:** Surface ambiguity immediately. List the interpretations and their tradeoffs, provide a recommended default, and confirm before writing code.

---

## 4. The Blind Implementer

- **Symptom:** The LLM implements complex logic without establishing a verification harness, writing code that looks plausible but fails silently on edge cases.
- **Root Cause:** Lack of goal-driven feedback loop.
- **Remediation:** Define success criteria upfront. Formulate verifiable assertions or reproduction tests before modifying production code. Loop until all checks pass green.
