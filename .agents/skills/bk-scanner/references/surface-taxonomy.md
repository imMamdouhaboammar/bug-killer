# Bug Killer Scanning Surface Taxonomy

This reference details the inspection mechanics, parser behavior, and detection criteria for the 6 primary surfaces scanned by Bug Killer (`bk`).

---

## 1. Surface 1: Software Composition Analysis (SCA) & OSV

### Supported Manifests & Lockfiles
- **Node.js**: `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`.
- **PHP**: `composer.json`, `composer.lock`.
- **Rust**: `Cargo.toml`, `Cargo.lock`.
- **Python**: `requirements.txt`, `Pipfile.lock`, `poetry.lock`.
- **Go**: `go.mod`, `go.sum`.
- **SBOM**: SPDX (JSON/tag-value) and CycloneDX (JSON/XML).

### Version Resolution Rules
- Direct dependencies are resolved against exact installed lockfile versions when available.
- Range constraints in manifests (e.g. `^1.2.0`) are evaluated against CVE advisory intervals; they are never queried as literal exact strings.
- In offline mode (`BK_OSV_OFFLINE=1`), lookups fall back to the embedded high-criticality CVE database.

---

## 2. Surface 2: Static Application Security Testing (SAST) & Taint

### Taint Analysis Pipeline
1. **Source Identification**: User inputs, HTTP query strings (`req.query`), body payloads (`req.body`), request headers, route params.
2. **Propagation**: Tracks variable assignments, function returns, string interpolations, and stream piping.
3. **Sink Verification**: Detects when unescaped tainted values enter:
   - Database query builders or raw SQL formatting strings (SQLi).
   - Shell process spawning (`exec`, `spawn`, `system`, `popen`) (Command Injection).
   - Filesystem path resolution (`fs.readFile`, `open`, `include`) (Path Traversal / LFI).
   - HTML DOM injection (`dangerouslySetInnerHTML`, `echo`) (XSS).
4. **Sanitizer Recognition**: Verifies if recognized escaping or parameter binding wrappers neutralize the taint.

---

## 3. Surface 3: High-Entropy Secrets & Credentials

### Detection Patterns
- High-entropy base64 and hex strings with Shannon entropy thresholding.
- Specific vendor tokens:
  - AWS access keys (`AKIA...`) and secret keys.
  - GitHub Personal Access Tokens (`ghp_...`, `github_pat_...`).
  - Stripe API keys (`sk_live_...`, `rk_live_...`).
  - OpenAI API keys (`sk-...`) and Anthropic keys (`sk-ant-...`).
  - Private Ed25519, RSA, and OpenSSH keys.

---

## 4. Surface 4: Containers & Reverse Proxies

### Dockerfile Audits
- Root execution detection (`USER root` or absent non-root user declaration).
- Insecure base images (unpinned tags, `latest`, outdated distributions).
- Sensitive environment variables (`ENV SECRET=...`).
- Dangerous inline scripts (`curl ... | bash`, `wget -O - ... | sh`).

### Reverse Proxies (Nginx / Apache / HAProxy)
- Missing client request body size limits (`client_max_body_size`).
- Unmitigated HTTP/2 chunked Brotli decompression vulnerabilities.
- Missing defensive HTTP security headers.

---

## 5. Surface 5: AI Agent & MCP Configuration

- Inspects `.cursor/`, `.agents/`, `.claude/`, and `mcp.json` files.
- Flags arbitrary bash execution tools granted to autonomous agents without approval gates.
- Detects unpinned external tool dependencies or vulnerable MCP package versions.

---

## 6. Surface 6: Defensive DAST Probing (`bk probe`)

- Executes non-destructive HTTP requests against live staging or preview URLs.
- Evaluates Content-Security-Policy (CSP), Strict-Transport-Security (HSTS), and server disclosures.
- **SSRF Safety Barrier**: Localhost loopback addresses, link-local addresses (`169.254.169.254`), and non-HTTP protocols are automatically rejected.
