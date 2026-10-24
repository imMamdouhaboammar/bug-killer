# Bug Killer Scan Profiles & Performance Matrix

This reference documents the runtime profile characteristics, analysis depth, and resource boundaries for Bug Killer (`bk`).

---

## 1. Profile Comparison Matrix

| Profile | Flag | Target Duration | Analysis Scope | Recommended Use Case |
|---|---|---|---|---|
| **Quick** | `--profile quick` | < 3 seconds | Fast AST regex heuristics, known critical CVE signatures, secret patterns | Pre-commit hooks, git staged changes, interactive editor save loops |
| **Project** | `--profile project` | 10 - 25 seconds | Multi-manifest SCA dependency resolution, single-file taint sinks, Dockerfile checks | Pull request review, pre-merge checks, local development audit |
| **CI** | `--profile ci` | 25 - 60 seconds | Policy enforcement, baseline regression diffing, SARIF report generation, fail-on threshold | GitHub Actions, GitLab CI, release pipelines |
| **Deep** | `--profile deep` | 1 - 5 minutes | Cross-file AST taint graphs, live OSV.dev querying, reverse proxy parsing, binary inspection | Pre-deployment compliance gates, security audits |

---

## 2. Invocation Examples

```bash
# Rapid check on current directory
bk scan . --profile quick

# Strict CI evaluation failing on High or Critical findings
bk security scan . --profile ci --fail-on high --json > scan-report.json

# Deep multi-surface audit with process inspection
bk scan . --profile deep --check-runtime --json
```

---

## 3. Exit Codes

| Code | Interpretation | Expected Action |
|---|---|---|
| `0` | No vulnerabilities found (or all findings below `--fail-on` threshold). | Allow build or merge to proceed. |
| `1` | One or more vulnerabilities found meeting or exceeding threshold. | Fail pipeline and report finding details. |
| `2` | Invalid configuration or CLI arguments. | Verify paths and profile names. |
| `3` | File I/O or parser error causing incomplete scan coverage. | Resolve unreadable files; never treat incomplete scans as clean. |
