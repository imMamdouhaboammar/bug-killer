# Runtime Setup & Agent Compatibility

This document provides runtime discovery and host compatibility mappings for `karpathy-guidelines`.

---

## 1. Runtime Requirements (Pre-flight)

**Core Invariants:**
- `karpathy-guidelines` is a portable behavioral skill requiring zero binary runtimes, native extensions, or remote network access.
- Works natively in headless and interactive environments across all major AI agent harnesses.
- Operates under strict progressive disclosure.

---

## 2. Host Capability Profile

| Agent Host | Discovery Channel | Installation Path | Behavioral Support Status |
|---|---|---|---|
| **Google Antigravity / Gemini CLI** | Native skill directory | `~/.gemini/config/skills/karpathy-guidelines/` | `SUPPORTED_TESTED` |
| **Universal Agent Kernel** | Agent Kernel registry | `~/.agents/skills/karpathy-guidelines/` | `SUPPORTED_TESTED` |
| **Claude Code & Desktop** | Claude skill / Plugin | `~/.claude/skills/karpathy-guidelines/` | `SUPPORTED_TESTED` |
| **OpenAI Codex & ChatGPT** | Codex skill / Plugin | `~/.codex/skills/karpathy-guidelines/` | `SUPPORTED_TESTED` |
| **Cursor & Windsurf** | Project & global rules | `.cursor/rules/karpathy-guidelines.mdc` | `SUPPORTED_TESTED` |
| **Skills.sh (Vercel)** | CLI installer | `.skills.json` / `npx skills add` | `SUPPORTED_TESTED` |

---

## 3. Verification Commands

```bash
# Verify SKILL.md structure and YAML frontmatter
python3 scripts/quick_validate.py .

# Evaluate discovery, triggers, and progressive disclosure
python3 scripts/eval_skill.py .
```
