# DeepSec Configuration Reference

The configuration file is stored at `.deepsec/config.json` relative to the repository root.

## Schema Fields

| Field | Type | Default | Description |
|---|---|---|---|
| `version` | string | `"1.0.0"` | Configuration schema version. |
| `runner` | string | `"auto"` | Execution engine: `"native"` (`bk deepsec`), `"node"` (`npx deepsec`), or `"auto"`. |
| `project_id` | string | `"auto"` | Unique identifier for data persistence. Defaults to repository folder name. |
| `storage_dir` | string | `".deepsec/data"` | Path to write atomic file records, findings, and run metadata. |
| `model` | string | `"gemini-2.5-flash"` | Target LLM model identifier for investigation and revalidation. |
| `concurrency` | integer | `4` | Number of concurrent file analysis workers. Range: `1` to `8`. |
| `max_cost_usd` | float | `5.0` | Maximum spend ceiling in USD before processing halts. |
| `max_tokens` | integer | `500000` | Maximum total prompt and completion token expenditure. |
| `ignore_paths` | array | `["**/node_modules/**", ...]` | Glob patterns excluded from directory crawlers. |
| `rules` | object | See below | Rule toggles for candidate matching. |
| `revalidation` | object | See below | Second-pass false positive filtering configuration. |

## Supported Environment Variables

| Variable | Description |
|---|---|
| `DEEPSEC_MODEL` | Overrides the LLM model defined in configuration. |
| `DEEPSEC_CONCURRENCY` | Overrides worker concurrency cap. |
| `DEEPSEC_MAX_COST` | Sets hard spend ceiling in USD. |
| `OPENAI_API_KEY` | Provider key when using OpenAI models. |
| `ANTHROPIC_API_KEY` | Provider key when using Anthropic Claude models. |
| `GEMINI_API_KEY` | Provider key when using Google Gemini models. |

## Budget Fence Invariant

Processing must halt immediately if token consumption or cost surpasses configured limits:

$$\text{Current Spend} \ge \text{max\_cost\_usd} \implies \text{HALT with exit code 75 (EX\_TEMPFAIL)}$$

Why this rule exists: Unbounded recursive AI calls on massive repositories risk runaway financial costs.
