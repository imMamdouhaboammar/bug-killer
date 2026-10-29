# lat.md Knowledge Graph Authoring Specification

Standards and syntactic invariants for constructing and maintaining `lat.md/` files.

## Directory Structure & Index Registries

Knowledge graphs reside under `lat.md/` at the project root.

```
lat.md/
├── lat.md              # Root index registry (REQUIRED)
├── .gitignore          # Ignores config.local.yaml and .cache/
├── architecture.md     # System design & boundaries
├── auth.md             # Authentication logic
└── api/                # Subdirectory for API domain
    ├── api.md          # Subdirectory index registry (REQUIRED)
    ├── endpoints.md    # API endpoints
    └── payloads.md     # Request/response schemas
```

### Directory Index Invariant
Every directory inside `lat.md/` containing markdown files MUST have an index file matching the directory name:
- Root directory `lat.md/` $\rightarrow$ `lat.md/lat.md`
- Subdirectory `lat.md/api/` $\rightarrow$ `lat.md/api/api.md`

Every sibling file in that directory must be registered as an entry:
```markdown
# Directory Title

Overview paragraph under 250 characters.

## Registered Documents

Directory description under 250 characters.

- [[architecture]] — System design, polyglot boundaries, and defensive invariants.
- [[auth]] — Authentication protocols, token lifecycles, and session tokens.
```

---

## Section Structure & The Leading Paragraph Rule

Every heading (`#`, `##`, `###`) MUST have a leading paragraph immediately following it, before any child headings, bullet lists, or code blocks.

### Constraints
1. **Immediate Placement:** No child heading or list may precede the first paragraph.
2. **Length Limit:** The first paragraph must be $\le 250$ characters (excluding text inside `[[wiki links]]`).
3. **Identity Function:** This paragraph serves as the summary snippet in `lat search`, `lat locate`, and RAG expansions.

### Valid Section Example
```markdown
# Good Section Title

Clear overview summarizing the concept and why it matters in under 250 characters.

Subsequent paragraphs may include deeper technical details, code blocks, or tables.

## Child Subheading

Specific description of this child topic under 250 characters.
```

### Invalid Section Examples
```markdown
<!-- INVALID: Child heading immediately follows parent without leading paragraph -->
# Bad Section Title
## Child Subheading
Some description text.
```

```markdown
<!-- INVALID: Bullet list precedes leading paragraph -->
# Bad Section Title
- Item 1
- Item 2
```

---

## Wiki Links & Symbol References

### Section Cross-References
Connect concepts across the graph using stable headings:
```markdown
See [[architecture#Defensive Perimeter]] for runtime boundaries.
Refer to [[vulnerabilities#PHP2Shell Vulnerabilities|the PHP2Shell catalog]] for thresholds.
```

### Repository Path Links
Link to tracked files or directories without a `#` fragment:
```markdown
[[Cargo.toml]]
[[src/lib.rs]]
[[services/orchestrator]]
```

### Source Code Symbol Links
Target functions, classes, structs, enums, constants, or methods:
```markdown
[[src/cve_db.rs#CveDatabase]]                      — Rust struct
[[src/cve_db.rs#CveDatabase#check_php_version]]   — Rust method
[[services/healer/server.go#HealerServer]]         — Go struct
[[services/healer/server.go#HealerServer#Execute]] — Go method
[[src/auth.ts#validateSessionToken]]               — TypeScript function
[[lib/models.py#UserModel#verify_password]]        — Python method
```
`lat check` validates that all linked symbols physically exist in source code.

---

## Source Code Backlinks (`@lat:`)

Tie physical implementation files back to knowledge graph sections using inline comments:

| Language | Comment Syntax | Placement |
|---|---|---|
| Rust | `// @lat: [[section-id]]` | Directly above `struct`, `fn`, `impl`, or `enum` |
| Go | `// @lat: [[section-id]]` | Directly above `type`, `func`, or `const` |
| TypeScript / JS | `// @lat: [[section-id]]` | Directly above `class`, `function`, `export` |
| C / C++ | `// @lat: [[section-id]]` | Directly above declaration or definition |
| Python | `# @lat: [[section-id]]` | Directly above `def`, `class`, or block |
| PHP | `// @lat: [[section-id]]` | Directly above class, function, or block |

### Placement Rule
Place the comment directly adjacent to the relevant implementation. Never dump `@lat:` comments at the top of a file.

```rust
// @lat: [[healing#Bit-for-Bit Rollback]]
impl RollbackManager {
    pub fn rollback(root: &Path, backup_id: &str) -> Result<usize, String> { ... }
}
```

---

## Test Specification Enforcement

Formal test specs are declared in `lat.md/` with frontmatter:

```markdown
---
lat:
  require-code-mention: true
---
# Test Suite Specifications

Verification specifications for system invariants.

## User Authentication

Credential validation and session integrity assertions.

### Rejects Expired Tokens

Tokens past expiration timestamp return HTTP 401 even if cryptographically valid.

### Rejects Tampered Signatures

Requests with modified HMAC signatures return HTTP 403.
```

### Strict Enforcement Rules
1. Every leaf section under `require-code-mention: true` MUST have a descriptive paragraph.
2. Every leaf section MUST be referenced by exactly one `@lat:` comment in the test codebase:
   ```rust
   // @lat: [[tests#User Authentication#Rejects Expired Tokens]]
   #[test]
   fn test_rejects_expired_tokens() { ... }
   ```
3. `lat check code-refs` fails if a spec has no matching test or if a test references an unknown spec.
