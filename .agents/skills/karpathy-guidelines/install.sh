#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_NAME="karpathy-guidelines"
ALIAS_NAME="andrej-karpathy-skills"

echo "📦 Installing ${TARGET_NAME} across AI agent environments..."

# 1. Claude Code / Desktop
if [ -d "$HOME/.claude" ] || command -v claude >/dev/null 2>&1; then
  mkdir -p "$HOME/.claude/skills"
  rm -rf "$HOME/.claude/skills/${TARGET_NAME}"
  cp -r "$SCRIPT_DIR" "$HOME/.claude/skills/${TARGET_NAME}"
  ln -sfn "$HOME/.claude/skills/${TARGET_NAME}" "$HOME/.claude/skills/${ALIAS_NAME}"
  echo "  ✅ Installed for Claude Code -> $HOME/.claude/skills/${TARGET_NAME} (alias: ${ALIAS_NAME})"
fi

# 2. Antigravity / Gemini CLI
if [ -d "$HOME/.gemini" ]; then
  mkdir -p "$HOME/.gemini/config/skills"
  rm -rf "$HOME/.gemini/config/skills/${TARGET_NAME}"
  cp -r "$SCRIPT_DIR" "$HOME/.gemini/config/skills/${TARGET_NAME}"
  ln -sfn "$HOME/.gemini/config/skills/${TARGET_NAME}" "$HOME/.gemini/config/skills/${ALIAS_NAME}"
  echo "  ✅ Installed for Antigravity / Gemini CLI -> $HOME/.gemini/config/skills/${TARGET_NAME} (alias: ${ALIAS_NAME})"
fi

# 3. Codex / ChatGPT / OpenCode
if [ -d "$HOME/.codex" ]; then
  mkdir -p "$HOME/.codex/skills"
  rm -rf "$HOME/.codex/skills/${TARGET_NAME}"
  cp -r "$SCRIPT_DIR" "$HOME/.codex/skills/${TARGET_NAME}"
  ln -sfn "$HOME/.codex/skills/${TARGET_NAME}" "$HOME/.codex/skills/${ALIAS_NAME}"
  echo "  ✅ Installed for Codex / OpenCode -> $HOME/.codex/skills/${TARGET_NAME} (alias: ${ALIAS_NAME})"
fi

# 4. Universal Agent Kernel
mkdir -p "$HOME/.agents/skills"
rm -rf "$HOME/.agents/skills/${TARGET_NAME}"
cp -r "$SCRIPT_DIR" "$HOME/.agents/skills/${TARGET_NAME}"
ln -sfn "$HOME/.agents/skills/${TARGET_NAME}" "$HOME/.agents/skills/${ALIAS_NAME}"
echo "  ✅ Installed for Universal Agent Kernel -> $HOME/.agents/skills/${TARGET_NAME} (alias: ${ALIAS_NAME})"

# 5. Project-local .agents/skills if present in invocation path
CURRENT_DIR="$(pwd)"
if [ -d "$CURRENT_DIR/.agents/skills" ]; then
  rm -rf "$CURRENT_DIR/.agents/skills/${TARGET_NAME}"
  cp -r "$SCRIPT_DIR" "$CURRENT_DIR/.agents/skills/${TARGET_NAME}"
  ln -sfn "$CURRENT_DIR/.agents/skills/${TARGET_NAME}" "$CURRENT_DIR/.agents/skills/${ALIAS_NAME}"
  echo "  ✅ Installed into local project -> $CURRENT_DIR/.agents/skills/${TARGET_NAME} (alias: ${ALIAS_NAME})"
fi

# 6. Cursor IDE rules
if [ -d "$CURRENT_DIR" ]; then
  mkdir -p "$CURRENT_DIR/.cursor/rules"
  cp "$SCRIPT_DIR/.cursor/rules/karpathy-guidelines.mdc" "$CURRENT_DIR/.cursor/rules/karpathy-guidelines.mdc"
  echo "  ✅ Installed Cursor rule -> $CURRENT_DIR/.cursor/rules/karpathy-guidelines.mdc"
fi

echo ""
echo "🎉 Installation complete across all agent harnesses!"
