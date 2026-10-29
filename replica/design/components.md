# Component Specifications: Bug-Killer DeepSec Harness

Component specifications for CLI terminal presentation, Markdown report rendering, and JSON export schema.

---

## 1. Terminal Findings Table

- **Type:** Console Table via `tabled` crate.
- **Columns:**
  1. `ID`: Short finding identifier (`finding_<hash:8>`).
  2. `Severity`: Formatted with terminal ANSI color (`colored` crate).
     - `CRITICAL`: Bright red bold.
     - `HIGH`: Bright yellow/orange bold.
     - `MEDIUM`: Yellow.
     - `BUG`: Magenta.
     - `LOW`: Cyan.
  3. `File`: Relative file path.
  4. `Lines`: Line span (e.g. `L42-L50`).
  5. `Category`: Vulnerability slug (e.g. `sql-injection`).
  6. `Title`: Single-line summary.

---

## 2. Scan Summary Pill Banner

- **Layout:** High-density header block with run metrics.
- **Tokens:**
  - Files Scanned: Numeric total.
  - Candidate Files: Count of files with regex hits.
  - Findings: Count of confirmed AI findings.
  - Duration: Wall clock time elapsed.
  - Cost USD: Modeled or actual API token expenditure.

---

## 3. Markdown Finding Detail Card

- **Section Template:**
  ```markdown
  ### [SEVERITY] Title of Vulnerability

  - **File:** `path/to/source.rs`
  - **Lines:** 102-115
  - **Category:** `rce`
  - **Confidence:** high
  - **Verdict:** true-positive

  #### Description
  Explanation of vulnerability and data flow.

  #### Recommendation
  Actionable remediation instructions.
  ```
