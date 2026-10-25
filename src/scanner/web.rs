#![allow(dead_code, clippy::collapsible_if)]

use crate::types::*;
use regex::Regex;
use std::collections::HashSet;
use std::path::Path;
use std::sync::LazyLock;

// ----------------------------------------------------------------------------
// Static Regular Expressions for Category 5 (Web & Frontend Security) Rules
// ----------------------------------------------------------------------------

// BK-AI-WEB-001: DOM XSS Sinks
static RE_INNER_OUTER_HTML: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\.(?:innerHTML|outerHTML)\s*=\s*(.+)"#).unwrap()
});

static RE_DANGEROUSLY_SET_INNER_HTML: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is)dangerouslySetInnerHTML\s*=\s*\{\{\s*__html\s*:\s*([^}]+)\}\}"#).unwrap()
});

static RE_DOC_WRITE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\bdocument\.(?:write|writeln)\s*\(\s*([^)]+)\s*\)"#).unwrap()
});

static RE_JQUERY_HTML: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\$\([^)]+\)\.html\s*\(\s*([^)]+)\s*\)"#).unwrap()
});

// BK-AI-WEB-002: Stored/Reflected Server-Side Template XSS
static RE_RENDER_TEMPLATE_STRING: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\brender_template_string\s*\(\s*(?:f["']|["'].*?\+|[^"'\s\),]+)"#).unwrap()
});

static RE_MARKUP_SAFE_CALL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\b(?:markupsafe\.)?Markup\s*\(\s*(?:f["']|["'].*?\+|[^"'\s\),]+)|\bmark_safe\s*\(\s*(?:f["']|["'].*?\+|[^"'\s\),]+))"#).unwrap()
});

static RE_BLADE_RAW_ECHO: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\{!!\s*([^!]+?)\s*!!\}"#).unwrap()
});

static RE_TEMPLATE_SAFE_FILTER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\{\{\s*([^}]+?)\s*\|\s*safe\s*\}\}"#).unwrap()
});

// BK-AI-WEB-003: Naive Regex/Blacklist HTML Sanitization
static RE_REGEX_SANITIZATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\.replace(?:All)?\s*\(\s*/<[\\/?]*script(?:\\/|[^/])*>/[gims]*|\.replace(?:All)?\s*\(\s*/<[^>]*>/[gims]*|re\.sub\s*\(\s*r?['"]<[\\/?]*script|preg_replace\s*\(\s*['"]/<[\\/?]*script)"#).unwrap()
});

// BK-AI-WEB-004: Open Redirect
static RE_CLIENT_REDIRECT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:window\.)?location(?:\.href)?\s*=\s*([^;]+)|(?:window\.)?location\.(?:assign|replace)\s*\(\s*([^)]+)\s*\)"#).unwrap()
});

static RE_SERVER_REDIRECT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\bres\.redirect\s*\(\s*(?:30[1278]\s*,\s*)?(?:req\.query|req\.params|req\.body|url|targetUrl|redirectUrl|nextUrl|returnUrl)\b"#).unwrap()
});

// BK-AI-WEB-005: postMessage missing origin check
static RE_POSTMESSAGE_LISTENER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:window\.)?(?:addEventListener\s*\(\s*['"]message['"]|onmessage\s*=)"#).unwrap()
});

// BK-AI-WEB-006: Frontend sensitive data
static RE_FRONTEND_PUBLIC_SECRET_ENV: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\b(?:NEXT_PUBLIC_|REACT_APP_|VITE_|NUXT_PUBLIC_|GATSBY_)[A-Z0-9_]*(?:SECRET|PRIVATE_KEY|PASSWORD|TOKEN|AUTH_KEY|API_SECRET)[A-Z0-9_]*\b"#).unwrap()
});

static RE_FRONTEND_HARDCODED_SECRET: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(?:const|let|var)\s+[a-zA-Z0-9_]*(?:api_secret|apiKeySecret|secretKey|privateKey|jwtSecret)\s*=\s*['"][a-zA-Z0-9_\-]{8,}['"]"#).unwrap()
});

// BK-AI-WEB-007: CSRF-sensitive mutations exposed via unsafe GET routes
static RE_MUTATING_GET_ROUTE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\b(?:app|router|server)\.get\s*\(\s*['"]/(?:[a-zA-Z0-9_\-\/]*\/)?(?:delete|remove|destroy|update|edit|reset|clear|transfer|withdraw|cancel|purge|execute|promote|demote|change-password|logout)\b|@app\.route\s*\(\s*['"]/(?:[a-zA-Z0-9_\-\/]*\/)?(?:delete|remove|destroy|update|reset|transfer)\b[^)]*methods\s*=\s*\[[^\]]*['"]GET['"][^\]]*\])"#).unwrap()
});

// BK-AI-WEB-008: Over-permissive or absent CSP
static RE_OVERPERMISSIVE_CSP: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is)(?:default-src\s+[*][^;]*'(?:unsafe-inline|unsafe-eval)'|script-src\s+[*][^;]*'(?:unsafe-inline|unsafe-eval)'|contentSecurityPolicy\s*:\s*false)"#).unwrap()
});

// BK-AI-WEB-009: External third-party scripts missing SRI
static RE_SCRIPT_CDN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is)<script\b[^>]*\bsrc\s*=\s*['"](https?://(?:cdn\.|cdnjs\.|unpkg\.|code\.jquery\.|stackpath\.|cdn\.jsdelivr\.net|ajax\.googleapis\.com|maxcdn\.)[^'"]+)['"][^>]*>"#).unwrap()
});

// BK-AI-WEB-010: Unsafe iframe embedding / clickjacking
static RE_UNSAFE_FRAMING: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:X-Frame-Options\s*:\s*(?:ALLOWALL|ALLOW-FROM\s+\*)|['"]X-Frame-Options['"]\s*,\s*['"]ALLOWALL['"]|\bframeguard\s*:\s*false|frame-ancestors\s+[*])"#).unwrap()
});

// BK-AI-WEB-011: CORS reflects any origin with credentials
static RE_CORS_WILDCARD_CREDS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is)(?:cors\s*\(\s*\{[^}]*origin\s*:\s*(?:true|['"]\*['"])[^}]*credentials\s*:\s*true|cors\s*\(\s*\{[^}]*credentials\s*:\s*true[^}]*origin\s*:\s*(?:true|['"]\*['"])|origin\s*:\s*(?:true|['"]\*['"])\s*,\s*credentials\s*:\s*true|credentials\s*:\s*true\s*,\s*origin\s*:\s*(?:true|['"]\*['"]))"#).unwrap()
});

static RE_CORS_HEADER_ORIGIN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)Access-Control-Allow-Origin['"]\s*,\s*(?:req\.headers\.origin|req\.get\(['"]origin['"]\)|['"]\*['"])"#).unwrap()
});

static RE_CORS_HEADER_CREDS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)Access-Control-Allow-Credentials['"]\s*,\s*['"]true['"]"#).unwrap()
});

// BK-AI-WEB-012: Credentials in client telemetry
static RE_TELEMETRY_CREDENTIALS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\b(?:Sentry\.capture(?:Message|Exception)|mixpanel\.(?:track|identify)|datadogRum\.add(?:Action|Error)|analytics\.track)\s*\([^)]*(?:password|authToken|access_token|secret_key|apiKey|bearerToken|jwtToken)\b|console\.(?:log|warn|error)\s*\([^)]*(?:userPassword|apiSecret|privateKey|authToken|auth_token)\b)"#).unwrap()
});

// BK-AI-WEB-013: Unprotected file download URL without auth
static RE_UNAUTH_DOWNLOAD_ROUTE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is)(?:\b(?:app|router)\.get\s*\(\s*['"]/(?:api/)?(?:download|files|documents|export)/:?(?:fileId|filename|id)?['"]\s*,\s*(?:async\s*)?(?:\(req,\s*res\)|function\s*\(req,\s*res\))\s*=>?\s*\{[^}]*res\.(?:download|sendFile)|\bACL\s*:\s*['"]public-read['"][^}]*['"](?:invoices|receipts|documents|private|user-data)['"])"#).unwrap()
});

// BK-AI-WEB-014: Service worker caching private responses
static RE_SERVICE_WORKER_PRIVATE_CACHE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is)(?:caches\.open\s*\([^)]*\)\s*\.then\s*\([^)]*cache\s*=>\s*cache\.(?:add|addAll|put)\s*\(\s*[^)]*['"]\/api\/(?:user|account|profile|me|billing|auth|session|orders)['"]|cache\.(?:add|addAll)\s*\(\s*\[[^\]]*['"]\/api\/(?:user|account|profile|me|billing|auth|session|orders)['"]|if\s*\([^)]*(?:url\.includes\(['"]\/api\/(?:user|account|profile|me)['"]\)|url\.pathname\.startsWith\(['"]\/api\/(?:user|account)['"]\))\s*\)[^}]*cache\.put)"#).unwrap()
});

// BK-AI-WEB-015: SSR / Hydration payload serializing sensitive state or PII
static RE_SSR_SENSITIVE_STATE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is)window\.(?:__INITIAL_STATE__|__PRELOADED_STATE__|__APP_DATA__)\s*=\s*(?:\{[^;]{0,2000}(?:passwordHash|password_hash|ssn|social_security|apiKey|api_secret|secretKey|private_key|creditCard|secret_token)\b|JSON\.stringify\s*\(\s*(?:dbUser|rawUser|accountModel|adminUser)\s*\)|(?:dbUser|rawUser|accountModel|adminUser)\b|.*?(?:passwordHash|password_hash|ssn|social_security|apiKey|api_secret|secretKey|private_key|creditCard|secret_token)\b)"#).unwrap()
});

// ----------------------------------------------------------------------------
// Scanner Implementation
// ----------------------------------------------------------------------------

pub struct WebSecurityScanner;

impl WebSecurityScanner {
    /// Determines whether a string expression assigned to innerHTML / outerHTML / document.write is safe.
    fn is_safe_html_rhs(rhs: &str) -> bool {
        let trimmed = rhs.trim().trim_end_matches(';').trim();
        if trimmed.is_empty() || trimmed == "\"\"" || trimmed == "''" || trimmed == "``" {
            return true;
        }

        // Known safe sanitizers or encoders
        if trimmed.contains("DOMPurify.sanitize(")
            || trimmed.contains("sanitizeHtml(")
            || trimmed.contains("escapeHtml(")
            || trimmed.contains("encodeURIComponent(")
        {
            return true;
        }

        // String concatenation with '+' is dynamic
        if trimmed.contains('+') {
            return false;
        }

        // Static single- or double-quoted string literal without interpolation
        if (trimmed.starts_with('"') && trimmed.ends_with('"') && trimmed.len() >= 2 && !trimmed[1..trimmed.len() - 1].contains('"'))
            || (trimmed.starts_with('\'') && trimmed.ends_with('\'') && trimmed.len() >= 2 && !trimmed[1..trimmed.len() - 1].contains('\''))
        {
            return true;
        }

        // Static backtick literal without template interpolation
        if trimmed.starts_with('`') && trimmed.ends_with('`') && trimmed.len() >= 2 && !trimmed[1..trimmed.len() - 1].contains('`') && !trimmed.contains("${") {
            return true;
        }

        false
    }

    /// Primary entry point: scans source code content for Category 5 Web & Frontend security vulnerabilities.
    pub fn scan_source(path: &Path, content: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut seen = HashSet::new();

        let target_kind = match path.extension().and_then(|ext| ext.to_str()) {
            Some("js" | "mjs" | "cjs" | "ts" | "tsx" | "jsx") => TargetKind::NodeSourceFile,
            Some("json" | "yaml" | "yml") => TargetKind::GenericConfigFile,
            _ => {
                if path.to_string_lossy().contains(".env") {
                    TargetKind::EnvironmentFile
                } else {
                    TargetKind::GenericSourceFile
                }
            }
        };

        let file_tag = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("source");

        let lines: Vec<&str> = content.lines().collect();

        let byte_to_line = |byte_offset: usize| -> usize {
            content[..byte_offset].bytes().filter(|&b| b == b'\n').count() + 1
        };

        // --------------------------------------------------------------------
        // Pass 1: Line-by-Line Surface Analysis
        // --------------------------------------------------------------------
        for (idx, line) in lines.iter().enumerate() {
            let line_no = idx + 1;
            let trimmed = line.trim();

            if trimmed.is_empty()
                || trimmed.starts_with("//")
                || trimmed.starts_with('#')
                || trimmed.starts_with('*')
            {
                continue;
            }

            // 1. BK-AI-WEB-001: DOM XSS via innerHTML / outerHTML
            if let Some(rhs) = RE_INNER_OUTER_HTML.captures(trimmed).and_then(|c| c.get(1)) {
                if !Self::is_safe_html_rhs(rhs.as_str()) && seen.insert(("BK-AI-WEB-001".to_string(), line_no)) {
                    let mut finding = Finding::new(
                        format!("WEB-001-{}-{}", file_tag, line_no),
                        CveId::Custom {
                            id: "BK-AI-WEB-001".to_string(),
                            title: "DOM-Based Cross-Site Scripting (DOM XSS)".to_string(),
                        },
                        Severity::High,
                        target_kind.clone(),
                        Some(path.to_path_buf()),
                        Some(line_no),
                        trimmed,
                        "Use textContent/innerText, or sanitize markup with DOMPurify before assigning to innerHTML",
                        format!(
                            "Unsafe DOM assignment to innerHTML/outerHTML at line {}. Untrusted data may execute arbitrary script in user's browser context.",
                            line_no
                        ),
                        "Replace innerHTML/outerHTML with textContent, or sanitize untrusted HTML using DOMPurify.sanitize().",
                    );
                    finding.detector_id = "web-security".to_string();
                    finding.detector_version = "1.0.0".to_string();
                    finding.category = "2.5 Browser, UI and frontend code".to_string();
                    finding.advisory_ids = vec!["CWE-79".to_string()];
                    finding.affectedness = Affectedness::ConfirmedAffected;
                    finding.reachability = Reachability::ConfirmedReachable;
                    finding.confidence = Confidence::High;
                    finding.evidence_certainty = EvidenceCertainty::StronglySupported;
                    finding.evidence_refs.push(EvidenceRef {
                        location: format!("{}:{}", path.display(), line_no),
                        line_number: Some(line_no),
                        snippet: Some(trimmed.to_string()),
                        sha256: None,
                    });
                    finding.compute_dedupe_fingerprint();
                    findings.push(finding);
                }
            }

            // 1b. BK-AI-WEB-001: document.write / document.writeln
            if let Some(arg) = RE_DOC_WRITE.captures(trimmed).and_then(|c| c.get(1)) {
                if !Self::is_safe_html_rhs(arg.as_str()) && seen.insert(("BK-AI-WEB-001".to_string(), line_no)) {
                    let mut finding = Finding::new(
                        format!("WEB-001-{}-{}", file_tag, line_no),
                        CveId::Custom {
                            id: "BK-AI-WEB-001".to_string(),
                            title: "DOM-Based Cross-Site Scripting via document.write".to_string(),
                        },
                        Severity::High,
                        target_kind.clone(),
                        Some(path.to_path_buf()),
                        Some(line_no),
                        trimmed,
                        "Avoid document.write; use safe DOM element construction APIs",
                        format!(
                            "Unsafe invocation of document.write/writeln at line {}. Dynamic input can inject unescaped markup into document stream.",
                            line_no
                        ),
                        "Refactor away from document.write; construct DOM elements and use textContent or appendChild.",
                    );
                    finding.detector_id = "web-security".to_string();
                    finding.detector_version = "1.0.0".to_string();
                    finding.category = "2.5 Browser, UI and frontend code".to_string();
                    finding.advisory_ids = vec!["CWE-79".to_string()];
                    finding.affectedness = Affectedness::ConfirmedAffected;
                    finding.reachability = Reachability::ConfirmedReachable;
                    finding.confidence = Confidence::High;
                    finding.evidence_certainty = EvidenceCertainty::StronglySupported;
                    finding.evidence_refs.push(EvidenceRef {
                        location: format!("{}:{}", path.display(), line_no),
                        line_number: Some(line_no),
                        snippet: Some(trimmed.to_string()),
                        sha256: None,
                    });
                    finding.compute_dedupe_fingerprint();
                    findings.push(finding);
                }
            }

            // 1c. BK-AI-WEB-001: jQuery .html(...)
            if let Some(arg) = RE_JQUERY_HTML.captures(trimmed).and_then(|c| c.get(1)) {
                if !Self::is_safe_html_rhs(arg.as_str()) && seen.insert(("BK-AI-WEB-001".to_string(), line_no)) {
                    let mut finding = Finding::new(
                        format!("WEB-001-{}-{}", file_tag, line_no),
                        CveId::Custom {
                            id: "BK-AI-WEB-001".to_string(),
                            title: "DOM-Based Cross-Site Scripting via jQuery .html()".to_string(),
                        },
                        Severity::High,
                        target_kind.clone(),
                        Some(path.to_path_buf()),
                        Some(line_no),
                        trimmed,
                        "Use jQuery .text() or sanitize input with DOMPurify before calling .html()",
                        format!(
                            "Unsafe dynamic assignment via jQuery .html() at line {}.",
                            line_no
                        ),
                        "Replace .html() with .text() or sanitize user content prior to invocation.",
                    );
                    finding.detector_id = "web-security".to_string();
                    finding.detector_version = "1.0.0".to_string();
                    finding.category = "2.5 Browser, UI and frontend code".to_string();
                    finding.advisory_ids = vec!["CWE-79".to_string()];
                    finding.affectedness = Affectedness::ConfirmedAffected;
                    finding.reachability = Reachability::ConfirmedReachable;
                    finding.confidence = Confidence::High;
                    finding.evidence_certainty = EvidenceCertainty::StronglySupported;
                    finding.evidence_refs.push(EvidenceRef {
                        location: format!("{}:{}", path.display(), line_no),
                        line_number: Some(line_no),
                        snippet: Some(trimmed.to_string()),
                        sha256: None,
                    });
                    finding.compute_dedupe_fingerprint();
                    findings.push(finding);
                }
            }

            // 2. BK-AI-WEB-002: Server-Rendered Unescaped HTML
            let is_render_template = RE_RENDER_TEMPLATE_STRING.is_match(trimmed);
            let is_markup_call = RE_MARKUP_SAFE_CALL.is_match(trimmed);
            let is_blade_raw = RE_BLADE_RAW_ECHO.is_match(trimmed);
            let is_safe_filter = RE_TEMPLATE_SAFE_FILTER.is_match(trimmed);

            if is_render_template || is_markup_call || is_blade_raw || is_safe_filter {
                let cve_id = "BK-AI-WEB-002";
                if seen.insert((cve_id.to_string(), line_no)) {
                    let mut finding = Finding::new(
                        format!("WEB-002-{}-{}", file_tag, line_no),
                        CveId::Custom {
                            id: cve_id.to_string(),
                            title: "Unescaped HTML in Server-Rendered Output".to_string(),
                        },
                        Severity::High,
                        target_kind.clone(),
                        Some(path.to_path_buf()),
                        Some(line_no),
                        trimmed,
                        "Contextually escape untrusted variables or use template engines with automatic HTML entity encoding",
                        format!(
                            "Server template renders unescaped raw HTML at line {}. Untrusted data may inject malicious scripts.",
                            line_no
                        ),
                        "Use standard auto-escaping syntax (e.g. {{ }} in Blade/Jinja) and avoid raw unescaped template directives.",
                    );
                    finding.detector_id = "web-security".to_string();
                    finding.detector_version = "1.0.0".to_string();
                    finding.category = "2.5 Browser, UI and frontend code".to_string();
                    finding.advisory_ids = vec!["CWE-79".to_string()];
                    finding.affectedness = Affectedness::ConfirmedAffected;
                    finding.reachability = Reachability::ConfirmedReachable;
                    finding.confidence = Confidence::High;
                    finding.evidence_certainty = EvidenceCertainty::StronglySupported;
                    finding.evidence_refs.push(EvidenceRef {
                        location: format!("{}:{}", path.display(), line_no),
                        line_number: Some(line_no),
                        snippet: Some(trimmed.to_string()),
                        sha256: None,
                    });
                    finding.compute_dedupe_fingerprint();
                    findings.push(finding);
                }
            }

            // 3. BK-AI-WEB-003: Naive Regex/Blacklist Sanitization
            if RE_REGEX_SANITIZATION.is_match(trimmed) {
                let cve_id = "BK-AI-WEB-003";
                if seen.insert((cve_id.to_string(), line_no)) {
                    let mut finding = Finding::new(
                        format!("WEB-003-{}-{}", file_tag, line_no),
                        CveId::Custom {
                            id: cve_id.to_string(),
                            title: "Insecure HTML Sanitization via Naive Regular Expression".to_string(),
                        },
                        Severity::High,
                        target_kind.clone(),
                        Some(path.to_path_buf()),
                        Some(line_no),
                        trimmed,
                        "Use a robust, parser-based HTML sanitization library (such as DOMPurify, sanitize-html, or bleach)",
                        format!(
                            "HTML sanitization relies on regular expression replacement at line {}. Regex-based blacklists are easily bypassed.",
                            line_no
                        ),
                        "Replace regular expression tag stripping with an established HTML sanitizer like DOMPurify or bleach.",
                    );
                    finding.detector_id = "web-security".to_string();
                    finding.detector_version = "1.0.0".to_string();
                    finding.category = "2.5 Browser, UI and frontend code".to_string();
                    finding.advisory_ids = vec!["CWE-79".to_string()];
                    finding.affectedness = Affectedness::ConfirmedAffected;
                    finding.reachability = Reachability::ConfirmedReachable;
                    finding.confidence = Confidence::High;
                    finding.evidence_certainty = EvidenceCertainty::StronglySupported;
                    finding.evidence_refs.push(EvidenceRef {
                        location: format!("{}:{}", path.display(), line_no),
                        line_number: Some(line_no),
                        snippet: Some(trimmed.to_string()),
                        sha256: None,
                    });
                    finding.compute_dedupe_fingerprint();
                    findings.push(finding);
                }
            }

            // 4. BK-AI-WEB-004: Open Redirect
            let is_client_redirect = if let Some(caps) = RE_CLIENT_REDIRECT.captures(trimmed) {
                let target_expr = caps.get(1).or_else(|| caps.get(2)).map(|m| m.as_str().trim()).unwrap_or("");
                // Safe if it's a fixed relative path starting with '/'
                let is_static_relative = (target_expr.starts_with("\"/") && target_expr.ends_with('"'))
                    || (target_expr.starts_with("'/'") && target_expr.ends_with('\''))
                    || (target_expr.starts_with("`/") && target_expr.ends_with('`') && !target_expr.contains("${"));

                !is_static_relative && (target_expr.contains("url")
                    || target_expr.contains("redirect")
                    || target_expr.contains("target")
                    || target_expr.contains("query")
                    || target_expr.contains("params")
                    || target_expr.contains("search"))
            } else {
                false
            };

            let is_server_redirect = RE_SERVER_REDIRECT.is_match(trimmed);

            if is_client_redirect || is_server_redirect {
                let cve_id = "BK-AI-WEB-004";
                if seen.insert((cve_id.to_string(), line_no)) {
                    let mut finding = Finding::new(
                        format!("WEB-004-{}-{}", file_tag, line_no),
                        CveId::Custom {
                            id: cve_id.to_string(),
                            title: "Open URL Redirection to Attacker-Controlled Host".to_string(),
                        },
                        Severity::High,
                        target_kind.clone(),
                        Some(path.to_path_buf()),
                        Some(line_no),
                        trimmed,
                        "Validate target URLs against an explicit allowlist of trusted domains or enforce relative path navigation",
                        format!(
                            "Redirect target derived from untrusted input at line {}. Attackers can redirect users to arbitrary external domains.",
                            line_no
                        ),
                        "Validate destination URLs against an allowlist, or restrict redirects to relative paths starting with a single '/'.",
                    );
                    finding.detector_id = "web-security".to_string();
                    finding.detector_version = "1.0.0".to_string();
                    finding.category = "2.5 Browser, UI and frontend code".to_string();
                    finding.advisory_ids = vec!["CWE-601".to_string()];
                    finding.affectedness = Affectedness::ConfirmedAffected;
                    finding.reachability = Reachability::ConfirmedReachable;
                    finding.confidence = Confidence::High;
                    finding.evidence_certainty = EvidenceCertainty::StronglySupported;
                    finding.evidence_refs.push(EvidenceRef {
                        location: format!("{}:{}", path.display(), line_no),
                        line_number: Some(line_no),
                        snippet: Some(trimmed.to_string()),
                        sha256: None,
                    });
                    finding.compute_dedupe_fingerprint();
                    findings.push(finding);
                }
            }

            // 5. BK-AI-WEB-005: postMessage Origin Validation
            if RE_POSTMESSAGE_LISTENER.is_match(trimmed) {
                // Look ahead in the next 20 lines to verify if event.origin is checked
                let end_idx = (idx + 22).min(lines.len());
                let lookahead_block = lines[idx..end_idx].join("\n");
                let has_origin_check = lookahead_block.contains(".origin");
                let has_wildcard_origin = lookahead_block.contains("origin === '*'")
                    || lookahead_block.contains("origin == '*'")
                    || lookahead_block.contains("origin === \"*\"")
                    || lookahead_block.contains("origin == \"*\"");

                if !has_origin_check || has_wildcard_origin {
                    let cve_id = "BK-AI-WEB-005";
                    if seen.insert((cve_id.to_string(), line_no)) {
                        let mut finding = Finding::new(
                            format!("WEB-005-{}-{}", file_tag, line_no),
                            CveId::Custom {
                                id: cve_id.to_string(),
                                title: "Cross-Origin Communication (postMessage) Handler Lacks Origin Validation".to_string(),
                            },
                            Severity::High,
                            target_kind.clone(),
                            Some(path.to_path_buf()),
                            Some(line_no),
                            trimmed,
                            "Always verify event.origin matches expected trusted origin before processing message payload",
                            format!(
                                "Message event listener registered at line {} without verifying event.origin. Malicious frames can dispatch arbitrary messages.",
                                line_no
                            ),
                            "Add a strict check: if (event.origin !== 'https://trusted.example.com') return; at the beginning of the message handler.",
                        );
                        finding.detector_id = "web-security".to_string();
                        finding.detector_version = "1.0.0".to_string();
                        finding.category = "2.5 Browser, UI and frontend code".to_string();
                        finding.advisory_ids = vec!["CWE-346".to_string()];
                        finding.affectedness = Affectedness::ConfirmedAffected;
                        finding.reachability = Reachability::ConfirmedReachable;
                        finding.confidence = Confidence::High;
                        finding.evidence_certainty = EvidenceCertainty::StronglySupported;
                        finding.evidence_refs.push(EvidenceRef {
                            location: format!("{}:{}", path.display(), line_no),
                            line_number: Some(line_no),
                            snippet: Some(trimmed.to_string()),
                            sha256: None,
                        });
                        finding.compute_dedupe_fingerprint();
                        findings.push(finding);
                    }
                }
            }

            // 6. BK-AI-WEB-006: Sensitive data in frontend bundle
            let is_public_secret_env = RE_FRONTEND_PUBLIC_SECRET_ENV.is_match(trimmed);
            let is_hardcoded_secret = RE_FRONTEND_HARDCODED_SECRET.is_match(trimmed);

            if is_public_secret_env || is_hardcoded_secret {
                let cve_id = "BK-AI-WEB-006";
                if seen.insert((cve_id.to_string(), line_no)) {
                    let mut finding = Finding::new(
                        format!("WEB-006-{}-{}", file_tag, line_no),
                        CveId::Custom {
                            id: cve_id.to_string(),
                            title: "Sensitive Secret or Credential Exposed in Client-Side Frontend Bundle".to_string(),
                        },
                        Severity::High,
                        target_kind.clone(),
                        Some(path.to_path_buf()),
                        Some(line_no),
                        trimmed,
                        "Never prefix sensitive secrets with public build prefixes (e.g. NEXT_PUBLIC_) or hardcode credentials in frontend code",
                        format!(
                            "Client-exposed secret pattern detected at line {}. Publicly compiled assets expose this secret to all end-users.",
                            line_no
                        ),
                        "Move confidential API secrets, private keys, and credentials to server-side environment variables without public bundle prefixes.",
                    );
                    finding.detector_id = "web-security".to_string();
                    finding.detector_version = "1.0.0".to_string();
                    finding.category = "2.5 Browser, UI and frontend code".to_string();
                    finding.advisory_ids = vec!["CWE-200".to_string()];
                    finding.affectedness = Affectedness::ConfirmedAffected;
                    finding.reachability = Reachability::ConfirmedReachable;
                    finding.confidence = Confidence::High;
                    finding.evidence_certainty = EvidenceCertainty::StronglySupported;
                    finding.evidence_refs.push(EvidenceRef {
                        location: format!("{}:{}", path.display(), line_no),
                        line_number: Some(line_no),
                        snippet: Some(trimmed.to_string()),
                        sha256: None,
                    });
                    finding.compute_dedupe_fingerprint();
                    findings.push(finding);
                }
            }

            // 7. BK-AI-WEB-007: CSRF-sensitive mutations exposed via unsafe GET routes
            if RE_MUTATING_GET_ROUTE.is_match(trimmed) {
                let cve_id = "BK-AI-WEB-007";
                if seen.insert((cve_id.to_string(), line_no)) {
                    let mut finding = Finding::new(
                        format!("WEB-007-{}-{}", file_tag, line_no),
                        CveId::Custom {
                            id: cve_id.to_string(),
                            title: "State-Mutating Action Exposed via HTTP GET (CSRF Vulnerable)".to_string(),
                        },
                        Severity::High,
                        target_kind.clone(),
                        Some(path.to_path_buf()),
                        Some(line_no),
                        trimmed,
                        "Use HTTP POST, PUT, or DELETE with anti-CSRF token verification for all state-changing actions",
                        format!(
                            "State-mutating action defined as HTTP GET route at line {}. GET requests are easily triggered via <img>, <iframe>, or cross-site link clicks without CSRF defense.",
                            line_no
                        ),
                        "Convert route method to POST/DELETE and require valid CSRF tokens or SameSite=Strict cookies.",
                    );
                    finding.detector_id = "web-security".to_string();
                    finding.detector_version = "1.0.0".to_string();
                    finding.category = "2.5 Browser, UI and frontend code".to_string();
                    finding.advisory_ids = vec!["CWE-352".to_string()];
                    finding.affectedness = Affectedness::ConfirmedAffected;
                    finding.reachability = Reachability::ConfirmedReachable;
                    finding.confidence = Confidence::High;
                    finding.evidence_certainty = EvidenceCertainty::StronglySupported;
                    finding.evidence_refs.push(EvidenceRef {
                        location: format!("{}:{}", path.display(), line_no),
                        line_number: Some(line_no),
                        snippet: Some(trimmed.to_string()),
                        sha256: None,
                    });
                    finding.compute_dedupe_fingerprint();
                    findings.push(finding);
                }
            }

            // 8. BK-AI-WEB-008: Over-permissive or absent CSP (line-level)
            if RE_OVERPERMISSIVE_CSP.is_match(trimmed) {
                let cve_id = "BK-AI-WEB-008";
                if seen.insert((cve_id.to_string(), line_no)) {
                    let mut finding = Finding::new(
                        format!("WEB-008-{}-{}", file_tag, line_no),
                        CveId::Custom {
                            id: cve_id.to_string(),
                            title: "Over-Permissive or Disabled Content Security Policy".to_string(),
                        },
                        Severity::Medium,
                        target_kind.clone(),
                        Some(path.to_path_buf()),
                        Some(line_no),
                        trimmed,
                        "Configure a restrictive CSP policy without wildcard sources combined with 'unsafe-inline' or 'unsafe-eval'",
                        format!(
                            "Over-permissive CSP configuration detected at line {}. Using wildcard with unsafe-inline/unsafe-eval negates XSS mitigation.",
                            line_no
                        ),
                        "Define specific trusted origins, adopt cryptographic nonces or hashes for scripts, and eliminate 'unsafe-inline' and 'unsafe-eval'.",
                    );
                    finding.detector_id = "web-security".to_string();
                    finding.detector_version = "1.0.0".to_string();
                    finding.category = "2.5 Browser, UI and frontend code".to_string();
                    finding.advisory_ids = vec!["CWE-693".to_string()];
                    finding.affectedness = Affectedness::ConfirmedAffected;
                    finding.reachability = Reachability::PotentiallyReachable;
                    finding.confidence = Confidence::High;
                    finding.evidence_certainty = EvidenceCertainty::StronglySupported;
                    finding.evidence_refs.push(EvidenceRef {
                        location: format!("{}:{}", path.display(), line_no),
                        line_number: Some(line_no),
                        snippet: Some(trimmed.to_string()),
                        sha256: None,
                    });
                    finding.compute_dedupe_fingerprint();
                    findings.push(finding);
                }
            }

            // 9. BK-AI-WEB-009: External third-party scripts missing SRI (line-level)
            if let Some(caps) = RE_SCRIPT_CDN.captures(trimmed) {
                if !trimmed.contains("integrity=") && seen.insert(("BK-AI-WEB-009".to_string(), line_no)) {
                    let cdn_src = caps.get(1).map(|m| m.as_str()).unwrap_or("CDN script");
                    let mut finding = Finding::new(
                        format!("WEB-009-{}-{}", file_tag, line_no),
                        CveId::Custom {
                            id: "BK-AI-WEB-009".to_string(),
                            title: "External Script Missing Subresource Integrity (SRI)".to_string(),
                        },
                        Severity::Medium,
                        target_kind.clone(),
                        Some(path.to_path_buf()),
                        Some(line_no),
                        trimmed,
                        "Include cryptographic integrity attribute (e.g. integrity=\"sha384-...\") and crossorigin=\"anonymous\" on all CDN scripts",
                        format!(
                            "Third-party CDN script tag ('{}') included without 'integrity' attribute at line {}.",
                            cdn_src, line_no
                        ),
                        "Add subresource integrity (SRI) hash and crossorigin=\"anonymous\" attribute to the <script> element.",
                    );
                    finding.detector_id = "web-security".to_string();
                    finding.detector_version = "1.0.0".to_string();
                    finding.category = "2.5 Browser, UI and frontend code".to_string();
                    finding.advisory_ids = vec!["CWE-829".to_string()];
                    finding.affectedness = Affectedness::ConfirmedAffected;
                    finding.reachability = Reachability::PotentiallyReachable;
                    finding.confidence = Confidence::High;
                    finding.evidence_certainty = EvidenceCertainty::StronglySupported;
                    finding.evidence_refs.push(EvidenceRef {
                        location: format!("{}:{}", path.display(), line_no),
                        line_number: Some(line_no),
                        snippet: Some(trimmed.to_string()),
                        sha256: None,
                    });
                    finding.compute_dedupe_fingerprint();
                    findings.push(finding);
                }
            }

            // 10. BK-AI-WEB-010: Unsafe iframe embedding / clickjacking
            if RE_UNSAFE_FRAMING.is_match(trimmed) {
                let cve_id = "BK-AI-WEB-010";
                if seen.insert((cve_id.to_string(), line_no)) {
                    let mut finding = Finding::new(
                        format!("WEB-010-{}-{}", file_tag, line_no),
                        CveId::Custom {
                            id: cve_id.to_string(),
                            title: "Insecure Framing Policy Permitting Clickjacking".to_string(),
                        },
                        Severity::Medium,
                        target_kind.clone(),
                        Some(path.to_path_buf()),
                        Some(line_no),
                        trimmed,
                        "Set X-Frame-Options to DENY or SAMEORIGIN, or configure CSP frame-ancestors 'self'",
                        format!(
                            "Framing protection disabled or set to allow all origins at line {}. Application is vulnerable to clickjacking attacks.",
                            line_no
                        ),
                        "Enforce X-Frame-Options: DENY or SAMEORIGIN, and configure Content-Security-Policy with frame-ancestors 'self'.",
                    );
                    finding.detector_id = "web-security".to_string();
                    finding.detector_version = "1.0.0".to_string();
                    finding.category = "2.5 Browser, UI and frontend code".to_string();
                    finding.advisory_ids = vec!["CWE-1021".to_string()];
                    finding.affectedness = Affectedness::ConfirmedAffected;
                    finding.reachability = Reachability::PotentiallyReachable;
                    finding.confidence = Confidence::High;
                    finding.evidence_certainty = EvidenceCertainty::StronglySupported;
                    finding.evidence_refs.push(EvidenceRef {
                        location: format!("{}:{}", path.display(), line_no),
                        line_number: Some(line_no),
                        snippet: Some(trimmed.to_string()),
                        sha256: None,
                    });
                    finding.compute_dedupe_fingerprint();
                    findings.push(finding);
                }
            }

            // 12. BK-AI-WEB-012: Credentials in client telemetry
            if RE_TELEMETRY_CREDENTIALS.is_match(trimmed) {
                let cve_id = "BK-AI-WEB-012";
                if seen.insert((cve_id.to_string(), line_no)) {
                    let mut finding = Finding::new(
                        format!("WEB-012-{}-{}", file_tag, line_no),
                        CveId::Custom {
                            id: cve_id.to_string(),
                            title: "Credentials or Tokens Logged to Client Telemetry".to_string(),
                        },
                        Severity::High,
                        target_kind.clone(),
                        Some(path.to_path_buf()),
                        Some(line_no),
                        trimmed,
                        "Scrub credentials, tokens, and passwords at the event source before sending to third-party telemetry services",
                        format!(
                            "Client telemetry or error tracking records sensitive credential fields at line {}. Authentication secrets may be leaked to third-party logs.",
                            line_no
                        ),
                        "Scrub and redact passwords, session tokens, and secrets prior to dispatching telemetry events or error captures.",
                    );
                    finding.detector_id = "web-security".to_string();
                    finding.detector_version = "1.0.0".to_string();
                    finding.category = "2.5 Browser, UI and frontend code".to_string();
                    finding.advisory_ids = vec!["CWE-532".to_string()];
                    finding.affectedness = Affectedness::ConfirmedAffected;
                    finding.reachability = Reachability::ConfirmedReachable;
                    finding.confidence = Confidence::High;
                    finding.evidence_certainty = EvidenceCertainty::StronglySupported;
                    finding.evidence_refs.push(EvidenceRef {
                        location: format!("{}:{}", path.display(), line_no),
                        line_number: Some(line_no),
                        snippet: Some(trimmed.to_string()),
                        sha256: None,
                    });
                    finding.compute_dedupe_fingerprint();
                    findings.push(finding);
                }
            }
        }

        // --------------------------------------------------------------------
        // Pass 2: Multi-line and Block Construct Scanning
        // --------------------------------------------------------------------

        // 1d. BK-AI-WEB-001: dangerouslySetInnerHTML spanning across lines
        for m in RE_DANGEROUSLY_SET_INNER_HTML.find_iter(content) {
            let line_no = byte_to_line(m.start());
            let snippet = m.as_str().trim();
            if let Some(arg) = RE_DANGEROUSLY_SET_INNER_HTML.captures(snippet).and_then(|c| c.get(1)) {
                if !Self::is_safe_html_rhs(arg.as_str()) && seen.insert(("BK-AI-WEB-001".to_string(), line_no)) {
                    let mut finding = Finding::new(
                        format!("WEB-001-{}-{}", file_tag, line_no),
                        CveId::Custom {
                            id: "BK-AI-WEB-001".to_string(),
                            title: "DOM XSS via dangerouslySetInnerHTML".to_string(),
                        },
                        Severity::High,
                        target_kind.clone(),
                        Some(path.to_path_buf()),
                        Some(line_no),
                        snippet,
                        "Sanitize HTML using DOMPurify before passing to dangerouslySetInnerHTML",
                        format!(
                            "Unsanitized dangerouslySetInnerHTML markup at line {}.",
                            line_no
                        ),
                        "Wrap HTML payload with DOMPurify.sanitize().",
                    );
                    finding.detector_id = "web-security".to_string();
                    finding.detector_version = "1.0.0".to_string();
                    finding.category = "2.5 Browser, UI and frontend code".to_string();
                    finding.advisory_ids = vec!["CWE-79".to_string()];
                    finding.affectedness = Affectedness::ConfirmedAffected;
                    finding.reachability = Reachability::ConfirmedReachable;
                    finding.confidence = Confidence::High;
                    finding.evidence_certainty = EvidenceCertainty::StronglySupported;
                    finding.evidence_refs.push(EvidenceRef {
                        location: format!("{}:{}", path.display(), line_no),
                        line_number: Some(line_no),
                        snippet: Some(snippet.lines().next().unwrap_or(snippet).to_string()),
                        sha256: None,
                    });
                    finding.compute_dedupe_fingerprint();
                    findings.push(finding);
                }
            }
        }

        // 8b. BK-AI-WEB-008: Over-permissive CSP in multiline blocks
        for m in RE_OVERPERMISSIVE_CSP.find_iter(content) {
            let line_no = byte_to_line(m.start());
            let snippet = m.as_str().trim();
            let cve_id = "BK-AI-WEB-008";
            if seen.insert((cve_id.to_string(), line_no)) {
                let mut finding = Finding::new(
                    format!("WEB-008-{}-{}", file_tag, line_no),
                    CveId::Custom {
                        id: cve_id.to_string(),
                        title: "Over-Permissive or Disabled Content Security Policy".to_string(),
                    },
                    Severity::Medium,
                    target_kind.clone(),
                    Some(path.to_path_buf()),
                    Some(line_no),
                    snippet,
                    "Configure a restrictive CSP policy without wildcard sources combined with 'unsafe-inline' or 'unsafe-eval'",
                    format!(
                        "Over-permissive CSP configuration detected at line {}. Using wildcard with unsafe-inline/unsafe-eval negates XSS mitigation.",
                        line_no
                    ),
                    "Define specific trusted origins, adopt cryptographic nonces or hashes for scripts, and eliminate 'unsafe-inline' and 'unsafe-eval'.",
                );
                finding.detector_id = "web-security".to_string();
                finding.detector_version = "1.0.0".to_string();
                finding.category = "2.5 Browser, UI and frontend code".to_string();
                finding.advisory_ids = vec!["CWE-693".to_string()];
                finding.affectedness = Affectedness::ConfirmedAffected;
                finding.reachability = Reachability::PotentiallyReachable;
                finding.confidence = Confidence::High;
                finding.evidence_certainty = EvidenceCertainty::StronglySupported;
                finding.evidence_refs.push(EvidenceRef {
                    location: format!("{}:{}", path.display(), line_no),
                    line_number: Some(line_no),
                    snippet: Some(snippet.lines().next().unwrap_or(snippet).to_string()),
                    sha256: None,
                });
                finding.compute_dedupe_fingerprint();
                findings.push(finding);
            }
        }

        // 11. BK-AI-WEB-011: CORS reflects any origin with credentials
        // Check multiline cors configuration
        for m in RE_CORS_WILDCARD_CREDS.find_iter(content) {
            let line_no = byte_to_line(m.start());
            let snippet = m.as_str().trim();
            let cve_id = "BK-AI-WEB-011";
            if seen.insert((cve_id.to_string(), line_no)) {
                let mut finding = Finding::new(
                    format!("WEB-011-{}-{}", file_tag, line_no),
                    CveId::Custom {
                        id: cve_id.to_string(),
                        title: "CORS Allows Arbitrary Origin with Credentials".to_string(),
                    },
                    Severity::High,
                    target_kind.clone(),
                    Some(path.to_path_buf()),
                    Some(line_no),
                    snippet,
                    "Never reflect unvalidated Origin headers when Access-Control-Allow-Credentials is true; use strict whitelist",
                    format!(
                        "CORS configuration allows arbitrary origins with credentials enabled at line {}. Untrusted origins can read authenticated user responses.",
                        line_no
                    ),
                    "Validate incoming Origin against an explicit allowlist of authorized domain names before setting Access-Control-Allow-Origin with credentials.",
                );
                finding.detector_id = "web-security".to_string();
                finding.detector_version = "1.0.0".to_string();
                finding.category = "2.5 Browser, UI and frontend code".to_string();
                finding.advisory_ids = vec!["CWE-942".to_string()];
                finding.affectedness = Affectedness::ConfirmedAffected;
                finding.reachability = Reachability::ConfirmedReachable;
                finding.confidence = Confidence::High;
                finding.evidence_certainty = EvidenceCertainty::StronglySupported;
                finding.evidence_refs.push(EvidenceRef {
                    location: format!("{}:{}", path.display(), line_no),
                    line_number: Some(line_no),
                    snippet: Some(snippet.lines().next().unwrap_or(snippet).to_string()),
                    sha256: None,
                });
                finding.compute_dedupe_fingerprint();
                findings.push(finding);
            }
        }

        // Check Access-Control-Allow-Origin with Access-Control-Allow-Credentials headers
        if RE_CORS_HEADER_CREDS.is_match(content) {
            if let Some(m_orig) = RE_CORS_HEADER_ORIGIN.find(content) {
                let line_no = byte_to_line(m_orig.start());
                let cve_id = "BK-AI-WEB-011";
                if seen.insert((cve_id.to_string(), line_no)) {
                    let mut finding = Finding::new(
                        format!("WEB-011-{}-{}", file_tag, line_no),
                        CveId::Custom {
                            id: cve_id.to_string(),
                            title: "CORS Allows Arbitrary Origin with Credentials".to_string(),
                        },
                        Severity::High,
                        target_kind.clone(),
                        Some(path.to_path_buf()),
                        Some(line_no),
                        m_orig.as_str(),
                        "Never reflect unvalidated Origin headers when Access-Control-Allow-Credentials is true",
                        format!(
                            "Access-Control-Allow-Origin header reflects origin while Access-Control-Allow-Credentials is true near line {}.",
                            line_no
                        ),
                        "Validate Origin against an allowlist before returning credentials header.",
                    );
                    finding.detector_id = "web-security".to_string();
                    finding.detector_version = "1.0.0".to_string();
                    finding.category = "2.5 Browser, UI and frontend code".to_string();
                    finding.advisory_ids = vec!["CWE-942".to_string()];
                    finding.affectedness = Affectedness::ConfirmedAffected;
                    finding.reachability = Reachability::ConfirmedReachable;
                    finding.confidence = Confidence::High;
                    finding.evidence_certainty = EvidenceCertainty::StronglySupported;
                    finding.evidence_refs.push(EvidenceRef {
                        location: format!("{}:{}", path.display(), line_no),
                        line_number: Some(line_no),
                        snippet: Some(m_orig.as_str().to_string()),
                        sha256: None,
                    });
                    finding.compute_dedupe_fingerprint();
                    findings.push(finding);
                }
            }
        }

        // 13. BK-AI-WEB-013: Unprotected file download URL without auth
        for m in RE_UNAUTH_DOWNLOAD_ROUTE.find_iter(content) {
            let line_no = byte_to_line(m.start());
            let snippet = m.as_str().trim();
            let cve_id = "BK-AI-WEB-013";
            if seen.insert((cve_id.to_string(), line_no)) {
                let mut finding = Finding::new(
                    format!("WEB-013-{}-{}", file_tag, line_no),
                    CveId::Custom {
                        id: cve_id.to_string(),
                        title: "Unprotected File Download Endpoint Missing Authorization Check".to_string(),
                    },
                    Severity::Medium,
                    target_kind.clone(),
                    Some(path.to_path_buf()),
                    Some(line_no),
                    snippet,
                    "Require authenticated session and check resource access permissions before serving files or issuing download links",
                    format!(
                        "File download endpoint or public ACL exposes resources without authorization verification at line {}.",
                        line_no
                    ),
                    "Enforce authorization middleware on file download routes and avoid public-read ACLs for user data.",
                );
                finding.detector_id = "web-security".to_string();
                finding.detector_version = "1.0.0".to_string();
                finding.category = "2.5 Browser, UI and frontend code".to_string();
                finding.advisory_ids = vec!["CWE-200".to_string()];
                finding.affectedness = Affectedness::ConfirmedAffected;
                finding.reachability = Reachability::PotentiallyReachable;
                finding.confidence = Confidence::High;
                finding.evidence_certainty = EvidenceCertainty::StronglySupported;
                finding.evidence_refs.push(EvidenceRef {
                    location: format!("{}:{}", path.display(), line_no),
                    line_number: Some(line_no),
                    snippet: Some(snippet.lines().next().unwrap_or(snippet).to_string()),
                    sha256: None,
                });
                finding.compute_dedupe_fingerprint();
                findings.push(finding);
            }
        }

        // 14. BK-AI-WEB-014: Service worker caching private responses
        for m in RE_SERVICE_WORKER_PRIVATE_CACHE.find_iter(content) {
            let line_no = byte_to_line(m.start());
            let snippet = m.as_str().trim();
            let cve_id = "BK-AI-WEB-014";
            if seen.insert((cve_id.to_string(), line_no)) {
                let mut finding = Finding::new(
                    format!("WEB-014-{}-{}", file_tag, line_no),
                    CveId::Custom {
                        id: cve_id.to_string(),
                        title: "Service Worker / CacheStorage Caching User-Private API Responses".to_string(),
                    },
                    Severity::Medium,
                    target_kind.clone(),
                    Some(path.to_path_buf()),
                    Some(line_no),
                    snippet,
                    "Only cache public static assets in CacheStorage; never cache private or account-specific API responses",
                    format!(
                        "Service Worker CacheStorage stores private user endpoint at line {}. Caches persist across account logouts and shared browser profiles.",
                        line_no
                    ),
                    "Exclude authenticated user and account API endpoints from service worker caching strategies.",
                );
                finding.detector_id = "web-security".to_string();
                finding.detector_version = "1.0.0".to_string();
                finding.category = "2.5 Browser, UI and frontend code".to_string();
                finding.advisory_ids = vec!["CWE-525".to_string()];
                finding.affectedness = Affectedness::ConfirmedAffected;
                finding.reachability = Reachability::PotentiallyReachable;
                finding.confidence = Confidence::High;
                finding.evidence_certainty = EvidenceCertainty::StronglySupported;
                finding.evidence_refs.push(EvidenceRef {
                    location: format!("{}:{}", path.display(), line_no),
                    line_number: Some(line_no),
                    snippet: Some(snippet.lines().next().unwrap_or(snippet).to_string()),
                    sha256: None,
                });
                finding.compute_dedupe_fingerprint();
                findings.push(finding);
            }
        }

        // 15. BK-AI-WEB-015: SSR / Hydration payload serializing sensitive state or PII
        for m in RE_SSR_SENSITIVE_STATE.find_iter(content) {
            let line_no = byte_to_line(m.start());
            let snippet = m.as_str().trim();
            let cve_id = "BK-AI-WEB-015";
            if seen.insert((cve_id.to_string(), line_no)) {
                let mut finding = Finding::new(
                    format!("WEB-015-{}-{}", file_tag, line_no),
                    CveId::Custom {
                        id: cve_id.to_string(),
                        title: "SSR Hydration State Serializes Sensitive Credentials or PII".to_string(),
                    },
                    Severity::High,
                    target_kind.clone(),
                    Some(path.to_path_buf()),
                    Some(line_no),
                    snippet,
                    "Sanitize server state into public-safe DTOs before embedding into client hydration scripts",
                    format!(
                        "Hydration payload serialized to window object contains sensitive credential or PII fields at line {}.",
                        line_no
                    ),
                    "Project server models to safe public DTOs containing only non-sensitive presentation attributes before SSR serialization.",
                );
                finding.detector_id = "web-security".to_string();
                finding.detector_version = "1.0.0".to_string();
                finding.category = "2.5 Browser, UI and frontend code".to_string();
                finding.advisory_ids = vec!["CWE-200".to_string()];
                finding.affectedness = Affectedness::ConfirmedAffected;
                finding.reachability = Reachability::ConfirmedReachable;
                finding.confidence = Confidence::High;
                finding.evidence_certainty = EvidenceCertainty::StronglySupported;
                finding.evidence_refs.push(EvidenceRef {
                    location: format!("{}:{}", path.display(), line_no),
                    line_number: Some(line_no),
                    snippet: Some(snippet.lines().next().unwrap_or(snippet).to_string()),
                    sha256: None,
                });
                finding.compute_dedupe_fingerprint();
                findings.push(finding);
            }
        }

        findings
    }
}
