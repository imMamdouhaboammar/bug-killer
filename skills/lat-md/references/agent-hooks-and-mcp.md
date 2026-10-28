# Agent Hooks, MCP Server & CI Integration

Specifications for integrating `lat.md` into AI coding agents and automated CI pipelines.

## Model Context Protocol (MCP) Configuration

The MCP server runs over stdio via `lat mcp` and exposes:
- `lat_search`: Vector similarity search over sections.
- `lat_locate`: Exact and fuzzy section title finder.
- `lat_check`: Full graph validation engine.
- `lat_refs`: Graph reference and code backlink lookup.

### Universal / Antigravity (`.mcp.json`)
```json
{
  "mcpServers": {
    "lat": {
      "command": "lat",
      "args": ["mcp"]
    }
  }
}
```

### Cursor (`.cursor/mcp.json`)
```json
{
  "mcpServers": {
    "lat": {
      "command": "lat",
      "args": ["mcp"]
    }
  }
}
```

### VS Code (`.vscode/mcp.json`)
```json
{
  "servers": {
    "lat": {
      "command": "lat",
      "args": ["mcp"]
    }
  }
}
```

### Codex (`.codex/config.toml`)
```toml
[mcp_servers.lat]
command = "lat"
args = ["mcp"]
```

---

## Agent Lifecycle Hooks

Hooks automatically inject relevant search context into prompts and enforce that the graph is updated and checked before completing tasks.

### Claude Code (`.claude/settings.json`)
```json
{
  "hooks": {
    "UserPromptSubmit": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "lat hook claude UserPromptSubmit"
          }
        ]
      }
    ],
    "Stop": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "lat hook claude Stop"
          }
        ]
      }
    ]
  }
}
```

### Cursor Hooks (`.cursor/hooks.json`)
```json
{
  "version": 1,
  "hooks": {
    "stop": [
      {
        "command": "lat hook cursor stop"
      }
    ]
  }
}
```

### Codex Hooks (`.codex/hooks.json`)
```json
{
  "hooks": {
    "UserPromptSubmit": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "lat hook codex UserPromptSubmit"
          }
        ]
      }
    ],
    "Stop": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "lat hook codex Stop"
          }
        ]
      }
    ]
  }
}
```

---

## Shared Instruction Blocks (`AGENTS.md`)

Shared agent constitutions wrap lat instructions using delimiters:

```markdown
%% lat:begin %%
# Before starting work

Use Lat's knowledge graph to ground each task before changing code.

- Run `lat search` to find sections relevant to your task. Read them to understand the design intent before writing code.

# Post-task checklist (REQUIRED — do not skip)

After EVERY task, before responding to the user:

- [ ] Update `lat.md/` if you added or changed meaningful implemented functionality, architecture, tests, or behavior.
- [ ] Run `lat check` — all validations must pass
- [ ] Do not skip these steps. Do not consider your task done until both are complete.
%% lat:end %%
```

---

## GitHub Actions Continuous Integration

Enforce lattice consistency on every push and pull request without requiring Node or external build tools:

```yaml
name: Documentation & Knowledge Graph Verification

on:
  push:
    branches: [ master, main ]
  pull_request:
    branches: [ master, main ]

jobs:
  lat-check:
    name: Lat.md Knowledge Graph Check
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v4
      - name: Run Lat Check
        uses: vercel-labs/lat.md@action-v1
        with:
          working-directory: .
          profile: 'false'
```
