# lat.md CLI Commands Reference

Complete command-line interface documentation for `lat` (lat.md CLI).

## Global Options

| Option | Description |
|---|---|
| `-V, --version` | Output version number |
| `--dir <path>` | Project root containing `lat.md/` (default: current working directory) |
| `--no-color` | Disable ANSI color output |
| `--verbose` | Output deprecation warnings and extended diagnostics |
| `-h, --help` | Display command help |

---

## Command Catalog

### `lat init [dir]`
Scaffold a `lat.md/` directory and configure agent hooks and MCP servers.

```bash
lat init              # Initialize in current repository
lat init ./subproject # Initialize in target directory
```
- Creates `lat.md/` directory with `lat.md/lat.md` index placeholder.
- Generates `config.local.yaml` (machine-local overrides, gitignored).
- Prompts for agent selection (`claude`, `pi`, `cursor`, `copilot`, `opencode`, `codex`).
- Updates `AGENTS.md` using `%% lat:begin %%` / `%% lat:end %%` markers.
- Installs `.agents/skills/lat-md/SKILL.md`.
- Configures agent hooks (`UserPromptSubmit`, `Stop`).
- Writes `.mcp.json` / `.cursor/mcp.json` / `.vscode/mcp.json` / `.codex/config.toml`.
- Writes `.cache/lat_init.json` with `init_version` (v6) and content hashes.

---

### `lat check [subcommand] [-- <directory>]`
Validate the integrity of the knowledge graph and code references.

```bash
lat check             # Run all validation checks
lat check md          # Validate wiki links in markdown files
lat check links       # Validate relative markdown links
lat check code-refs   # Validate @lat code references and test coverage
lat check index       # Validate directory index files (lat.md, <subdir>.md)
lat check sections    # Validate section leading paragraphs (≤ 250 chars)
lat check diagrams    # Validate Mermaid readability and box count
```

Options:
- `--profile`: Show detailed execution timing per validation phase.

---

### `lat search [options] [query]`
Execute hybrid vector and BM25 lexical search across all markdown sections.

```bash
lat search "rollback memory corruption"
lat search --limit 5 "authentication flow"
```

Options:
- `--limit <n>`: Maximum number of search results to return (default: 5).
- Offline by default using local WebAssembly all-MiniLM-L6-v2 embeddings.
- Remote embeddings enabled via `LAT_LLM_KEY` (OpenAI `sk-...` or Vercel `vck_...`).

---

### `lat locate <query>`
Find sections by title or heading chain with exact and fuzzy matching.

```bash
lat locate "Rollback"
lat locate "Vulnerabilities#PHP2Shell"
```

---

### `lat section <query>`
Display full section text alongside incoming and outgoing graph references.

```bash
lat section "healing#Bit-for-Bit Rollback"
lat section "architecture#Defensive Perimeter"
```

---

### `lat refs [options] <query>`
Find incoming wiki links and `@lat:` source code references targeting a section.

```bash
lat refs "healing#Bit-for-Bit Rollback"
lat refs "vulnerabilities#PHP2Shell Vulnerabilities#OOM Heap Corruption"
```

---

### `lat expand [options] [text]`
Expand `[[refs]]` in a prompt into section locations and content for LLMs.

```bash
lat expand "Review [[architecture#Defensive Perimeter]] before patching"
```

---

### `lat ui [options]`
Launch or build the local interactive knowledge graph explorer.

```bash
lat ui                # Start local development UI server
lat ui build          # Build static UI assets to .lat-build/static
lat ui build server   # Build standalone Node server to .lat-build/server
```

---

### `lat mcp`
Start the stdio Model Context Protocol (MCP) server for IDEs and agents.

```bash
lat mcp
```
Exposes tools:
- `lat_search`: Vector search across sections.
- `lat_locate`: Exact/fuzzy section title finder.
- `lat_check`: Validation engine runner.
- `lat_refs`: Reference and backlink inspector.

---

### `lat reindex [options]`
Rebuild the local or remote embedding vector database.

```bash
lat reindex --local   # Force offline all-MiniLM-L6-v2 WASM embeddings
lat reindex --remote  # Build hosted embeddings using LAT_LLM_KEY
```

---

### `lat gen <target>`
Emit raw template files to standard output.

```bash
lat gen agents.md       # Output agents.md instruction block
lat gen cursor-rules.md # Output Cursor rules specification
```

---

### `lat paths [options]`
Inspect paths for configuration files, caches, and search databases.

```bash
lat paths
lat paths --config    # Show user configuration file path only
```
