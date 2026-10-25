#![allow(dead_code)]

use crate::types::*;
use regex::Regex;
use std::path::Path;
use std::sync::LazyLock;

// ---------------------------------------------------------------------------
// Category 8: SSRF, Outbound HTTP & Network Trust (BK-AI-NET-001 through 010)
// ---------------------------------------------------------------------------

/// BK-AI-NET-001 (CWE-918): Arbitrary user-provided URL used by server HTTP client
static RE_NET_001_SSRF: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:(?:axios(?:\.(?:get|post|put|delete|patch|request))?|fetch|requests\.(?:get|post|put|delete|patch|request)|http\.(?:get|request)|https\.(?:get|request)|got(?:\.(?:get|post))?|superagent\.(?:get|post)|urllib\.request\.urlopen|client\.Get)\s*\(\s*(?:req\.(?:query|body|params)\.[a-zA-Z0-9_]*url|request\.(?:args|GET|POST|values|json)\.get\s*\(\s*['"][^'"]*url['"]\)|target_?url|user_?url|r\.URL\.Query\(\)\.Get\s*\(\s*['"][^'"]*url['"]\))|\burl\s*:\s*(?:req\.(?:query|body|params)\.[a-zA-Z0-9_]*url|request\.(?:args|GET|POST|values|json)\.get\s*\(\s*['"][^'"]*url['"]\)))"#).unwrap()
});

static RE_NET_001_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:isAllowedUrl|validateUrl|isSafeUrl|urlAllowlist|ALLOWED_DOMAINS|ALLOWLIST|parseAndValidateUrl|is_allowed_url|validate_url|is_safe_url|checkUrl)"#).unwrap()
});

/// BK-AI-NET-002 (CWE-918): IP literals, localhost, or cloud metadata address access
static RE_NET_002_METADATA_IP: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:(?:axios(?:\.(?:get|post|request))?|fetch|requests(?:\.(?:get|post|request))?|http\.(?:get|request)|https\.(?:get|request)|got(?:\.(?:get|post))?|urllib\.request\.urlopen|client\.Get)\s*\(\s*['"]https?://(?:169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200|127\.0\.0\.1|0\.0\.0\.0|localhost|\[::1\])|\b(?:METADATA_URL|IMDS_URL|INTERNAL_ENDPOINT)\s*=\s*['"]https?://(?:169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200|127\.0\.0\.1|0\.0\.0\.0|localhost)|//.*(?:metadata\s+service\s+access|ssrf\s+to\s+localhost|direct\s+metadata\s+request))"#).unwrap()
});

static RE_NET_002_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:isPrivateIp|blockPrivateIp|ipRangeCheck|isLoopback|is_private_ip|block_private_ip|validate_destination|filterPrivateRanges)"#).unwrap()
});

/// BK-AI-NET-003 (CWE-918): HTTP client follows redirects unconditionally to internal/private targets
static RE_NET_003_REDIRECTS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(?:maxRedirects\s*:\s*(?:[1-9]\d*)|followRedirects\s*:\s*true|follow_redirects\s*=\s*True|allow_redirects\s*=\s*True|redirect\s*:\s*['"]follow['"])\b"#).unwrap()
});

static RE_NET_003_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:beforeRedirect|validateRedirect|checkRedirect|recheckUrl|validateHop|validate_redirect|on_redirect|redirect_callback)"#).unwrap()
});

/// BK-AI-NET-004 (CWE-918): DNS rebinding / TOCTOU between IP check and request
static RE_NET_004_DNS_LOOKUP: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:dns\.(?:lookup|resolve(?:4|6)?)|socket\.gethostbyname|net\.LookupIP)\s*\("#).unwrap()
});

static RE_NET_004_HTTP_CALL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:fetch|axios\.(?:get|post|request)|requests\.(?:get|post)|http\.get)\s*\("#).unwrap()
});

static RE_NET_004_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:http\.Agent|https\.Agent|pinned_ip|direct_ip|custom_transport|lookup\s*:|Agent\s*\(|DialContext|pinnedAgent)"#).unwrap()
});

static RE_NET_004_COMMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)//.*(?:dns\s+rebinding|toctou\s+dns|dns\s+check\s+then\s+fetch|dns\s+time-of-check)"#).unwrap()
});

/// BK-AI-NET-005 (CWE-918): Non-HTTP URL schemes accepted by fetcher
static RE_NET_005_SCHEMES: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:CURLOPT_PROTOCOLS\s*,\s*CURLPROTO_ALL|CURLPROTO_FILE|CURLPROTO_GOPHER|protocols?\s*:\s*\[[^\]]*['"](?:file|gopher|ftp|dict|ldap)['"]|allowedSchemes\s*=\s*\[[^\]]*['"](?:file|gopher|ftp|dict|ldap)['"]|allowed_schemes\s*=\s*\[[^\]]*['"](?:file|gopher|ftp|dict|ldap)['"]|['"](?:file|gopher|ftp|dict|ldap)://['"]|url\.startsWith\s*\(\s*['"]file://['"]|protocol\s*===\s*['"]file:['"]|//.*(?:dangerous\s+url\s+scheme|accepts\s+file://|non-http\s+scheme\s+accepted))"#).unwrap()
});

/// BK-AI-NET-006 (CWE-918): Proxy settings or environment bypass network egress policy
static RE_NET_006_PROXY_BYPASS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:(?:NO_PROXY|no_proxy)\s*=\s*['"]\*['"]|env\.(?:NO_PROXY|no_proxy)\s*=\s*['"]\*['"]|os\.environ\[['"](?:NO_PROXY|no_proxy)['"]\]\s*=\s*['"]\*['"]|\bproxy\s*:\s*false\b|\bproxies\s*=\s*\{\s*\}|\bagent\s*:\s*false\b|CURLOPT_PROXY\s*,\s*['"]['"]|//.*(?:bypass\s+network\s+egress|egress\s+proxy\s+bypass|no_proxy\s+wildcard))"#).unwrap()
});

/// BK-AI-NET-007 (CWE-295): TLS certificate verification disabled
static RE_NET_007_TLS_DISABLE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(?:rejectUnauthorized\s*:\s*false|rejectUnauthorized\s*=\s*false|InsecureSkipVerify\s*:\s*true|InsecureSkipVerify\s*=\s*true|verify\s*=\s*False\b|verify\s*:\s*false\b|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]0['"]|CURLOPT_SSL_VERIFYPEER\s*,\s*(?:false|0)|CURLOPT_SSL_VERIFYHOST\s*,\s*0|ssl_verify\s*=\s*False\b|ssl_verify\s*:\s*false\b)\b"#).unwrap()
});

/// BK-AI-NET-008 (CWE-295): Hardcoded accept-all certificate callback
static RE_NET_008_ACCEPT_ALL_CERT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(?:checkServerIdentity\s*:\s*(?:\(\s*\)\s*=>\s*(?:null|undefined|\{\s*\})|function\s*\([^)]*\)\s*\{\s*(?:return\s*(?:null|undefined);?\s*)?\})|ServerCertificateValidationCallback\s*=\s*.*=>\s*true|VerifyPeerCertificate\s*:\s*func\([^)]*\)\s*error\s*\{\s*return\s+nil\s*\}|danger_accept_invalid_certs\s*\(\s*true\s*\)|danger_accept_invalid_hostnames\s*\(\s*true\s*\)|TrustAllStrategy\.INSTANCE|trustAllCertificates\s*=\s*true|//.*(?:accept-all\s+certificate|trust\s+all\s+certificates|disabled\s+server\s+identity\s+check))\b"#).unwrap()
});

/// BK-AI-NET-009 (CWE-201): Secret-bearing Authorization headers forwarded across redirects or cross-origin
static RE_NET_009_AUTH_FORWARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:headers\s*:\s*\{\s*\.\.\.req\.headers|headers\s*:\s*req\.headers|options\.headers\s*\[\s*['"]Authorization['"]\s*\]\s*=\s*(?:req|request)\.headers|headers\s*:\s*\{\s*['"]?Authorization['"]?\s*:\s*(?:req|request)\.headers\.(?:authorization|Authorization)|\bforwardAuthHeader\s*=\s*true\b|//.*(?:forward\s+auth(?:orization)?\s+header|auth\s+header\s+forwarded\s+cross-origin|forward\s+authorization\s+to\s+redirect))"#).unwrap()
});

/// BK-AI-NET-010 (CWE-400): Network calls have no deadline, timeout or response body cap
static RE_NET_010_TIMEOUT_DISABLED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\btimeout\s*:\s*0\b|\btimeout\s*=\s*(?:None|0)\b|//.*(?:missing\s+timeout|no\s+(?:deadline|timeout)\s+configured|network\s+call\s+without\s+timeout))"#).unwrap()
});

static RE_NET_010_REQUESTS_NO_TIMEOUT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\brequests\.(?:get|post|put|delete)\s*\([^)]+\)"#).unwrap()
});

// ---------------------------------------------------------------------------
// Category 16: Availability & Denial of Service (BK-AI-DOS-001 through 012)
// ---------------------------------------------------------------------------

/// BK-AI-DOS-001 (CWE-674): Unbounded recursion / tree depth without recursion limit
static RE_DOS_001_COMMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)//.*(?:unbounded\s+recursion|recursion\s+without\s+(?:depth\s+)?limit|unbounded\s+depth|no\s+recursion\s+limit)"#).unwrap()
});

static RE_DOS_001_FUNC: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:function\s+([a-zA-Z0-9_]+)\s*\(([^)]*)\)|def\s+([a-zA-Z0-9_]+)\s*\(([^)]*)\))"#).unwrap()
});

static RE_DOS_001_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(?:depth|maxDepth|max_depth|recursion_limit|depthLimit)\b"#).unwrap()
});

/// BK-AI-DOS-002 (CWE-400): Unbounded HTTP body, upload, or websocket frame size
static RE_DOS_002_BODY_LIMIT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\blimit\s*:\s*['"](?:[1-9]\d{2,}(?:mb|gb|tb)|Infinity)['"]|\blimit\s*:\s*Infinity\b|\bmaxPayload\s*:\s*0\b|\bclient_max_body_size\s+0\s*;|\bmaxHttpBufferSize\s*:\s*(?:1e9|Infinity|\d{10,})|express\.json\(\s*\{\s*limit\s*:\s*['"](?:100gb|50gb|10gb|1000mb)['"]\s*\}|//.*(?:unbounded\s+(?:http\s+)?body|missing\s+body\s+limit|infinite\s+payload\s+limit|unbounded\s+upload\s+size))"#).unwrap()
});

/// BK-AI-DOS-003 (CWE-770): Unlimited concurrency/thread/goroutine spawning per request
static RE_DOS_003_PROMISE_ALL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)Promise\.all\s*\(\s*(?:req\.[a-zA-Z0-9_.]+|items|records|tasks|entries|data|list)\.map\s*\(\s*async\b"#).unwrap()
});

static RE_DOS_003_FOR_EACH_ASYNC: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:items|records|tasks|req\.[a-zA-Z0-9_.]+)\.forEach\s*\(\s*async\s*\(?[a-zA-Z0-9_]+\)?\s*=>"#).unwrap()
});

static RE_DOS_003_THREAD_SPAWN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)for\s+[a-zA-Z0-9_]+\s+in\s+[a-zA-Z0-9_]+:\s*threading\.Thread\s*\("#).unwrap()
});

static RE_DOS_003_GOROUTINE_SPAWN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)for\s+.*:=\s*range\s+[a-zA-Z0-9_]+\s*\{\s*go\s+[a-zA-Z0-9_]+\s*\("#).unwrap()
});

static RE_DOS_003_COMMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)//.*(?:unlimited\s+concurrency|unbounded\s+concurrency|unlimited\s+(?:thread|goroutine)\s+spawning|concurrency\s+without\s+limit)"#).unwrap()
});

static RE_DOS_003_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:pLimit|p-limit|concurrency|Semaphore|ThreadPoolExecutor|workerPool|pool|sem\.Acquire|limit\s*\()"#).unwrap()
});

/// BK-AI-DOS-004 (CWE-400): IO operation has no timeout or cancellation budget
static RE_DOS_004_IO_NO_TIMEOUT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\b(?:socket|server|req|res|conn|connection)\.setTimeout\s*\(\s*0\s*\)|\b(?:server|connection)\.timeout\s*=\s*0\b|\bserver\.keepAliveTimeout\s*=\s*0\b|//.*(?:io\s+operation\s+has\s+no\s+timeout|socket\s+without\s+timeout|zero\s+timeout|timeout\s+disabled))"#).unwrap()
});

/// BK-AI-DOS-005 (CWE-400): Retry storm due to fixed retry loop without backoff or jitter
static RE_DOS_005_RETRY_STORM: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:for\s+[a-zA-Z0-9_]+\s+in\s+range\s*\(\s*(?:[5-9]\d|[1-9]\d{2,})\s*\)\s*:\s*(?:retry|fetch|call)\s*\(|retry\s*\(\s*\{\s*retries\s*:\s*[1-9]\d*,\s*delay\s*:\s*0\s*\}|//.*(?:retry\s+storm|without\s+backoff|no\s+backoff\s+or\s+jitter|fixed\s+retry\s+loop))"#).unwrap()
});

/// BK-AI-DOS-006 (CWE-400): Unbounded in-memory cache/map without eviction policy or max size
static RE_DOS_006_CACHE_INIT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:(?:const|let|var)\s+cache\s*=\s*(?:\{\}|new\s+Map\(\))\s*;|cache\s*=\s*\{\})"#).unwrap()
});

static RE_DOS_006_CACHE_SET: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:cache\[[a-zA-Z0-9_]+\]\s*=|cache\.set\s*\([a-zA-Z0-9_]+)"#).unwrap()
});

static RE_DOS_006_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:LRUCache|lru-cache|quick-lru|lru_cache|maxAge|maxSize|cache\.size\s*>|ttl:|prune\(|evict\(|max\s*:)"#).unwrap()
});

static RE_DOS_006_COMMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)//.*(?:unbounded\s+(?:in-memory\s+)?cache|cache\s+without\s+eviction|no\s+eviction\s+policy)"#).unwrap()
});

/// BK-AI-DOS-007 (CWE-400): Database query lacks pagination
static RE_DOS_007_RAW_QUERY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:await\s+)?(?:db\.(?:query|execute)|pool\.query)\s*\(\s*['"]SELECT\s+.*\s+FROM\s+[a-zA-Z0-9_]+(?:\s+WHERE\s+[^'"]*)?['"]\s*\)"#).unwrap()
});

static RE_DOS_007_ORM_FIND: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(?:Model|User|Item|Product|Post|Account|Order)\.(?:find|findAll)\s*\(\s*(?:\{\s*\})?\s*\)"#).unwrap()
});

static RE_DOS_007_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(?:LIMIT\s+\d+|limit\s*:|take\s*:|\.limit\s*\(|\.take\s*\()"#).unwrap()
});

static RE_DOS_007_COMMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)//.*(?:query\s+lacks\s+pagination|unpaginated\s+query|missing\s+pagination)"#).unwrap()
});

/// BK-AI-DOS-008 (CWE-1333): Regex catastrophic backtracking on user input
static RE_DOS_008_REDOS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:/(?:[^\n/]*\([^)]+\+[^\n/]*\)\+|[^\n/]*\([^)]+\*[^\n/]*\)\*)[^\n/]*/|RegExp\s*\(\s*['"][^'"]*\([^)]+\+[^\n'"]*\)\+[^'"]*['"]|re\.compile\s*\(\s*r?['"][^'"]*\([^)]+\+[^\n'"]*\)\+[^'"]*['"]|//.*(?:catastrophic\s+backtracking|redos\b))"#).unwrap()
});

/// BK-AI-DOS-009 (CWE-400): AI/LLM generation lacks token, document, or spend quota
static RE_DOS_009_LLM_CALL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:chat\.completions\.create|messages\.create|llm\.complete|llm\.generate|ai\.generateText)\s*\(\s*\{"#).unwrap()
});

static RE_DOS_009_TOKEN_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(?:max_tokens|max_completion_tokens|maxTokens)\s*:\s*[1-9]\d*"#).unwrap()
});

static RE_DOS_009_COMMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)//.*(?:lacks\s+token.*quota|missing\s+token\s+limit|ai.*without\s+quota|llm.*without\s+limit|missing\s+spend\s+quota)"#).unwrap()
});

/// BK-AI-DOS-010 (CWE-400): Circuit breaker / backpressure absent for overloaded downstream
static RE_DOS_010_CIRCUIT_BREAKER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:highWaterMark\s*:\s*Infinity\b|//.*(?:no\s+circuit\s+breaker|lacks?\s+backpressure|missing\s+circuit\s+breaker|unbounded\s+queue|queue\s+without\s+backpressure))"#).unwrap()
});

/// BK-AI-DOS-011 (CWE-400): Unbounded directory crawl / file reading without max depth or file limit
static RE_DOS_011_DIRECTORY_CRAWL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:fs\.readdir\w*\s*\([^)]*\{[^}]*recursive\s*:\s*true[^}]*\}\)|//.*(?:unbounded\s+(?:directory\s+crawl|filesystem\s+crawl|file\s+reading)|crawl\s+without\s+(?:max\s+)?depth|walk\s+without\s+limit))"#).unwrap()
});

static RE_DOS_011_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(?:maxDepth|max_depth|maxFiles|fileLimit|depthLimit)\b"#).unwrap()
});

/// BK-AI-DOS-012 (CWE-400): Error handler writes huge dumps / infinite error log loops causing disk exhaustion
static RE_DOS_012_DISK_EXHAUSTION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:(?:appendFileSync|writeFileSync|createWriteStream)\s*\([^)]*(?:error|log)[^)]*,\s*JSON\.stringify\s*\(\s*(?:req|request|process\.env)\s*\)|//.*(?:huge\s+dumps?|infinite\s+error\s+log|disk\s+exhaustion\s+log|dumps?\s+entire\s+req))"#).unwrap()
});

// ---------------------------------------------------------------------------
// NetworkDosScanner Implementation
// ---------------------------------------------------------------------------

pub struct NetworkDosScanner;

impl NetworkDosScanner {
    /// Scans source code content for Category 8 (SSRF & Outbound Network) and
    /// Category 16 (Availability & Denial of Service) rules.
    pub fn scan_source(path: &Path, content: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        let target_kind = match path.extension().and_then(|ext| ext.to_str()) {
            Some("js" | "mjs" | "cjs" | "ts" | "tsx" | "jsx") => TargetKind::NodeSourceFile,
            Some("json") => TargetKind::GenericConfigFile,
            Some("yaml" | "yml") => TargetKind::GenericConfigFile,
            _ => TargetKind::GenericSourceFile,
        };

        let lines: Vec<&str> = content.lines().collect();
        let total_lines = lines.len();

        for (idx, line) in lines.iter().enumerate() {
            let line_no = idx + 1;
            let trimmed = line.trim();

            if trimmed.is_empty() {
                continue;
            }

            // Window contexts for multi-line analysis (+/- 6 lines)
            let window_start = idx.saturating_sub(6);
            let window_end = (idx + 7).min(total_lines);
            let context_window = lines[window_start..window_end].join("\n");

            // Look-ahead window (next line to +10 lines)
            let ahead_start = (idx + 1).min(total_lines);
            let ahead_end = (idx + 11).min(total_lines);
            let lookahead_window = if ahead_start < total_lines {
                lines[ahead_start..ahead_end].join("\n")
            } else {
                String::new()
            };

            // ===============================================================
            // Category 8: SSRF & Outbound HTTP
            // ===============================================================

            // 1. BK-AI-NET-001 (CWE-918): Arbitrary user-provided URL used by server HTTP client
            if RE_NET_001_SSRF.is_match(trimmed) && !RE_NET_001_GUARD.is_match(&context_window) {
                findings.push(Self::create_finding(
                    "BK-AI-NET-001",
                    "CWE-918",
                    "Arbitrary user-provided URL used by server HTTP client",
                    Severity::High,
                    "2.8 SSRF, outbound HTTP and network trust",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Outbound HTTP requests must be constrained to an explicit allowlist of validated domains and protocols.",
                    "Server-side HTTP request made using unsanitized user-controlled input as destination URL without domain allowlist validation.",
                    "Validate destination URLs against a strict allowlist of allowed protocols, hostnames, and ports prior to dispatch.",
                ));
            }

            // 2. BK-AI-NET-002 (CWE-918): IP literals, localhost, or cloud metadata address access
            if RE_NET_002_METADATA_IP.is_match(trimmed) && !RE_NET_002_GUARD.is_match(&context_window) {
                findings.push(Self::create_finding(
                    "BK-AI-NET-002",
                    "CWE-918",
                    "IP literals, alternate encoding, IPv6 or DNS result bypass destination policy",
                    Severity::High,
                    "2.8 SSRF, outbound HTTP and network trust",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Private, loopback, link-local, and cloud metadata addresses (169.254.169.254, 127.0.0.1) must be rejected.",
                    "Outbound network request targets loopback, link-local, or cloud metadata IP addresses directly or via unvalidated host.",
                    "Enforce network destination policy that blocks private CIDR blocks, loopback addresses, and cloud provider metadata services.",
                ));
            }

            // 3. BK-AI-NET-003 (CWE-918): Redirect follows from allowed host to disallowed private/metadata address
            if RE_NET_003_REDIRECTS.is_match(trimmed) && !RE_NET_003_GUARD.is_match(&context_window) {
                findings.push(Self::create_finding(
                    "BK-AI-NET-003",
                    "CWE-918",
                    "Redirect follows from allowed host to disallowed private/metadata address",
                    Severity::Medium,
                    "2.8 SSRF, outbound HTTP and network trust",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "HTTP client redirect handling must be disabled or strictly re-validated at each redirect hop.",
                    "HTTP client configured to follow redirects unconditionally without re-verifying redirect target against network egress policy.",
                    "Disable automatic redirect following or implement a redirect callback hook that validates each target URL.",
                ));
            }

            // 4. BK-AI-NET-004 (CWE-918): DNS rebinding / TOCTOU between IP check and request
            let is_dns_toctou = RE_NET_004_COMMENT.is_match(trimmed)
                || (RE_NET_004_DNS_LOOKUP.is_match(trimmed)
                    && RE_NET_004_HTTP_CALL.is_match(&lookahead_window)
                    && !RE_NET_004_GUARD.is_match(&lookahead_window));

            if is_dns_toctou {
                findings.push(Self::create_finding(
                    "BK-AI-NET-004",
                    "CWE-918",
                    "DNS rebinding changes resolved address between check and connection",
                    Severity::High,
                    "2.8 SSRF, outbound HTTP and network trust",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Connection must be pinned to the validated IP address resolved during pre-request validation.",
                    "Host DNS lookup is performed separately from the HTTP request, allowing DNS rebinding TOCTOU between validation and connection.",
                    "Pin the resolved IP address directly in a custom HTTP agent / transport or perform socket-level validation on connect.",
                ));
            }

            // 5. BK-AI-NET-005 (CWE-918): Non-HTTP URL schemes accepted by fetcher
            if RE_NET_005_SCHEMES.is_match(trimmed) {
                findings.push(Self::create_finding(
                    "BK-AI-NET-005",
                    "CWE-918",
                    "Non-HTTP URL scheme or local file scheme accepted by fetcher",
                    Severity::High,
                    "2.8 SSRF, outbound HTTP and network trust",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "URL fetchers must strictly restrict allowed schemes to 'https' (and optionally 'http').",
                    "Fetcher configuration or protocol parser permits dangerous URL schemes (file://, gopher://, ftp://, dict://) enabling local resource access.",
                    "Constrain URL schemes to an explicit allowlist restricted to HTTP and HTTPS protocols only.",
                ));
            }

            // 6. BK-AI-NET-006 (CWE-918): Proxy settings or environment bypass network egress policy
            if RE_NET_006_PROXY_BYPASS.is_match(trimmed) {
                findings.push(Self::create_finding(
                    "BK-AI-NET-006",
                    "CWE-918",
                    "Proxy settings or environment bypass network egress policy",
                    Severity::Medium,
                    "2.8 SSRF, outbound HTTP and network trust",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Egress proxy configuration must be strictly enforced without wildcard NO_PROXY bypasses.",
                    "Network egress proxy disabled or bypassed via NO_PROXY wildcard configuration, circumventing egress inspection.",
                    "Remove blanket proxy bypasses and ensure all outbound network calls transit monitored egress gateway proxies.",
                ));
            }

            // 7. BK-AI-NET-007 (CWE-295): TLS certificate verification disabled
            if RE_NET_007_TLS_DISABLE.is_match(trimmed) {
                findings.push(Self::create_finding(
                    "BK-AI-NET-007",
                    "CWE-295",
                    "TLS certificate verification disabled, including in debug fallback",
                    Severity::High,
                    "2.8 SSRF, outbound HTTP and network trust",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "TLS certificate and hostname verification must be strictly enabled across all environments.",
                    "TLS verification explicitly disabled (e.g. rejectUnauthorized: false, verify=False, InsecureSkipVerify: true).",
                    "Enable strict TLS certificate validation and hostname verification across all network connections.",
                ));
            }

            // 8. BK-AI-NET-008 (CWE-295): Hardcoded accept-all certificate callback
            if RE_NET_008_ACCEPT_ALL_CERT.is_match(trimmed) {
                findings.push(Self::create_finding(
                    "BK-AI-NET-008",
                    "CWE-295",
                    "TLS trust pinned incorrectly, stale CA handling or hardcoded accept-all certificate callback",
                    Severity::High,
                    "2.8 SSRF, outbound HTTP and network trust",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Custom TLS validation callbacks must verify certificates against trusted root stores without accepting all certificates.",
                    "Hardcoded accept-all certificate validation callback detected, rendering TLS connections vulnerable to MITM interception.",
                    "Use standard system trust stores or pinned public key hashes instead of no-op validation stubs.",
                ));
            }

            // 9. BK-AI-NET-009 (CWE-201): Secret-bearing Authorization headers forwarded across redirects or cross-origin
            if RE_NET_009_AUTH_FORWARD.is_match(trimmed) {
                findings.push(Self::create_finding(
                    "BK-AI-NET-009",
                    "CWE-201",
                    "Secret-bearing headers forwarded across redirect or unrelated origin",
                    Severity::High,
                    "2.8 SSRF, outbound HTTP and network trust",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Authentication credentials and session tokens must be stripped before cross-origin redirects.",
                    "Sensitive Authorization or Cookie headers forwarded unconditionally across redirects or cross-origin requests.",
                    "Strip Authorization and authentication headers when following redirects to external or untrusted domains.",
                ));
            }

            // 10. BK-AI-NET-010 (CWE-400): Network calls have no deadline, timeout or response body cap
            let is_missing_timeout = RE_NET_010_TIMEOUT_DISABLED.is_match(trimmed)
                || (RE_NET_010_REQUESTS_NO_TIMEOUT.is_match(trimmed)
                    && !trimmed.to_lowercase().contains("timeout"));

            if is_missing_timeout {
                findings.push(Self::create_finding(
                    "BK-AI-NET-010",
                    "CWE-400",
                    "Network calls have no deadline, response cap or concurrency bound",
                    Severity::Medium,
                    "2.8 SSRF, outbound HTTP and network trust",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "All outbound network requests must declare explicit execution timeouts and response size limits.",
                    "Network request declared without timeout or with timeout disabled (timeout: 0), risking hanging connections and socket exhaustion.",
                    "Configure explicit connect and read timeouts (e.g., 5000ms) and maximum response body size limits.",
                ));
            }

            // ===============================================================
            // Category 16: Availability & Denial of Service
            // ===============================================================

            // 11. BK-AI-DOS-001 (CWE-674): Unbounded recursion / tree depth without recursion limit
            let is_unbounded_recursion = if RE_DOS_001_COMMENT.is_match(trimmed) {
                true
            } else if let Some(caps) = RE_DOS_001_FUNC.captures(trimmed) {
                let func_name = caps.get(1).or_else(|| caps.get(3)).map(|m| m.as_str()).unwrap_or("");
                let params = caps.get(2).or_else(|| caps.get(4)).map(|m| m.as_str()).unwrap_or("");
                if !func_name.is_empty() && !RE_DOS_001_GUARD.is_match(params) {
                    // Check if function name appears recursively in lookahead window without depth check
                    lookahead_window.contains(&format!("{}(", func_name)) && !RE_DOS_001_GUARD.is_match(&lookahead_window)
                } else {
                    false
                }
            } else {
                false
            };

            if is_unbounded_recursion {
                findings.push(Self::create_finding(
                    "BK-AI-DOS-001",
                    "CWE-674",
                    "User-defined recursion/depth/array size lacks bounds",
                    Severity::High,
                    "2.16 Availability, denial of service and resource budgets",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Recursive functions traversing user input must enforce a strict maximum depth limit.",
                    "Recursive function traversing tree or nested structures without explicit depth bounding, risking stack overflow.",
                    "Introduce an explicit recursion depth counter and fail or return gracefully when exceeding MAX_DEPTH.",
                ));
            }

            // 12. BK-AI-DOS-002 (CWE-400): Unbounded HTTP body, upload, or websocket frame size
            if RE_DOS_002_BODY_LIMIT.is_match(trimmed) {
                findings.push(Self::create_finding(
                    "BK-AI-DOS-002",
                    "CWE-400",
                    "Unbounded HTTP body, upload, compressed data or websocket frame",
                    Severity::High,
                    "2.16 Availability, denial of service and resource budgets",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "HTTP body parsers and upload limits must enforce restrictive size caps (e.g. 10MB or less).",
                    "HTTP body parser, file upload handler, or websocket buffer configured with unbounded or excessive size limit.",
                    "Configure reasonable body size limits (e.g. express.json({ limit: '10mb' })) to prevent memory exhaustion.",
                ));
            }

            // 13. BK-AI-DOS-003 (CWE-770): Unlimited concurrency/thread/goroutine spawning per request
            let is_unbounded_concurrency = RE_DOS_003_COMMENT.is_match(trimmed)
                || ((RE_DOS_003_PROMISE_ALL.is_match(trimmed)
                    || RE_DOS_003_FOR_EACH_ASYNC.is_match(trimmed)
                    || RE_DOS_003_THREAD_SPAWN.is_match(trimmed)
                    || RE_DOS_003_GOROUTINE_SPAWN.is_match(trimmed))
                    && !RE_DOS_003_GUARD.is_match(&context_window));

            if is_unbounded_concurrency {
                findings.push(Self::create_finding(
                    "BK-AI-DOS-003",
                    "CWE-770",
                    "Unlimited concurrency/task/thread/connection spawning per request",
                    Severity::High,
                    "2.16 Availability, denial of service and resource budgets",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Asynchronous task execution over user collections must enforce bounded concurrency.",
                    "Concurrent tasks, threads, or goroutines spawned over unbounded collections without concurrency pooling or rate limits.",
                    "Throttle parallel operations using concurrency-limiting primitives (e.g. p-limit, worker pools, semaphores).",
                ));
            }

            // 14. BK-AI-DOS-004 (CWE-400): IO operation has no timeout or cancellation budget
            if RE_DOS_004_IO_NO_TIMEOUT.is_match(trimmed) {
                findings.push(Self::create_finding(
                    "BK-AI-DOS-004",
                    "CWE-400",
                    "Client/server IO operation has no timeout, cancellation or retry budget",
                    Severity::Medium,
                    "2.16 Availability, denial of service and resource budgets",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Server sockets and IO streams must enforce non-zero idle and execution timeouts.",
                    "Socket or server timeout explicitly disabled (setTimeout(0) or timeout = 0), allowing slowloris and lingering open connections.",
                    "Configure non-zero timeouts on all sockets, HTTP servers, and stream connections.",
                ));
            }

            // 15. BK-AI-DOS-005 (CWE-400): Retry storm due to fixed retry loop without backoff or jitter
            if RE_DOS_005_RETRY_STORM.is_match(trimmed) {
                findings.push(Self::create_finding(
                    "BK-AI-DOS-005",
                    "CWE-400",
                    "Retry storm due to no backoff/jitter or maximum retries",
                    Severity::Medium,
                    "2.16 Availability, denial of service and resource budgets",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Retry loops must implement bounded retries with exponential backoff and randomized jitter.",
                    "Retry logic executes in an unthrottled loop or with zero delay, risking thundering herd and cascading system failure.",
                    "Implement exponential backoff with jitter and enforce a low maximum retry count (e.g. 3-5 attempts).",
                ));
            }

            // 16. BK-AI-DOS-006 (CWE-400): Unbounded in-memory cache/map without eviction policy or max size
            let is_unbounded_cache = RE_DOS_006_COMMENT.is_match(trimmed)
                || (RE_DOS_006_CACHE_INIT.is_match(trimmed)
                    && RE_DOS_006_CACHE_SET.is_match(&lookahead_window)
                    && !RE_DOS_006_GUARD.is_match(&lookahead_window));

            if is_unbounded_cache {
                findings.push(Self::create_finding(
                    "BK-AI-DOS-006",
                    "CWE-400",
                    "Cache/pool grows without eviction, quota or per-tenant cap",
                    Severity::High,
                    "2.16 Availability, denial of service and resource budgets",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "In-memory caches and object stores must enforce maximum size bounds and eviction policies (LRU/TTL).",
                    "Unbounded in-memory dictionary or map used as cache without size limits or eviction policy, leading to memory exhaustion.",
                    "Utilize bounded cache implementations (e.g. LRU cache) with maximum entry counts and TTL eviction.",
                ));
            }

            // 17. BK-AI-DOS-007 (CWE-400): Database query lacks pagination
            let is_unpaginated_query = RE_DOS_007_COMMENT.is_match(trimmed)
                || ((RE_DOS_007_RAW_QUERY.is_match(trimmed) || RE_DOS_007_ORM_FIND.is_match(trimmed))
                    && !RE_DOS_007_GUARD.is_match(trimmed)
                    && !RE_DOS_007_GUARD.is_match(&lookahead_window));

            if is_unpaginated_query {
                findings.push(Self::create_finding(
                    "BK-AI-DOS-007",
                    "CWE-400",
                    "Database query lacks pagination or bounded result set limit",
                    Severity::Medium,
                    "2.16 Availability, denial of service and resource budgets",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Database queries in request handlers must enforce pagination with explicit LIMIT/take clauses.",
                    "Database query executed in request handler without LIMIT or pagination, risking memory exhaustion on large tables.",
                    "Enforce mandatory pagination with a bounded maximum limit on all multi-record queries.",
                ));
            }

            // 18. BK-AI-DOS-008 (CWE-1333): Regex catastrophic backtracking on user input
            if RE_DOS_008_REDOS.is_match(trimmed) {
                findings.push(Self::create_finding(
                    "BK-AI-DOS-008",
                    "CWE-1333",
                    "Regex catastrophic backtracking on user input",
                    Severity::High,
                    "2.16 Availability, denial of service and resource budgets",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Regular expressions evaluated on untrusted input must not contain nested or ambiguous quantifiers.",
                    "Regular expression contains nested quantifiers or overlapping alternations vulnerable to catastrophic polynomial/exponential backtracking.",
                    "Refactor regular expression to eliminate nested repetitions, or evaluate using linear-time regex engines.",
                ));
            }

            // 19. BK-AI-DOS-009 (CWE-400): AI/LLM generation lacks token, document, or spend quota
            let is_llm_without_quota = RE_DOS_009_COMMENT.is_match(trimmed)
                || (RE_DOS_009_LLM_CALL.is_match(trimmed)
                    && !RE_DOS_009_TOKEN_GUARD.is_match(&lookahead_window));

            if is_llm_without_quota {
                findings.push(Self::create_finding(
                    "BK-AI-DOS-009",
                    "CWE-400",
                    "AI/RAG generation lacks token, document, tool-call or spend quota",
                    Severity::High,
                    "2.16 Availability, denial of service and resource budgets",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "LLM completions and agent iterations must enforce strict max_tokens and cost quotas.",
                    "Model completion or AI agent execution configured without max_tokens or iteration quotas, risking runaway costs and resource exhaustion.",
                    "Specify explicit max_tokens or max_completion_tokens on all LLM API invocations.",
                ));
            }

            // 20. BK-AI-DOS-010 (CWE-400): Circuit breaker / backpressure absent for overloaded downstream
            if RE_DOS_010_CIRCUIT_BREAKER.is_match(trimmed) {
                findings.push(Self::create_finding(
                    "BK-AI-DOS-010",
                    "CWE-400",
                    "Circuit breaker/queue backpressure absent for overloaded downstream",
                    Severity::Medium,
                    "2.16 Availability, denial of service and resource budgets",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "In-memory request queues and downstream dependencies must incorporate backpressure rejection and circuit breakers.",
                    "Unbounded in-memory queue or buffer accepts tasks without backpressure limits or circuit breaker protection.",
                    "Enforce maximum queue capacities with backpressure shedding and integrate circuit breakers for downstream services.",
                ));
            }

            // 21. BK-AI-DOS-011 (CWE-400): Unbounded directory crawl / file reading without max depth or file limit
            if RE_DOS_011_DIRECTORY_CRAWL.is_match(trimmed) && !RE_DOS_011_GUARD.is_match(&lookahead_window) {
                findings.push(Self::create_finding(
                    "BK-AI-DOS-011",
                    "CWE-400",
                    "Unbounded file watching, process discovery or filesystem crawl by scanner",
                    Severity::Medium,
                    "2.16 Availability, denial of service and resource budgets",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Filesystem traversal routines must enforce recursion depth and file count ceilings.",
                    "Recursive directory traversal or file reading implemented without depth or file count constraints.",
                    "Enforce explicit maxDepth and maximum traversed entry counts when walking directories.",
                ));
            }

            // 22. BK-AI-DOS-012 (CWE-400): Error handler writes huge dumps / infinite error log loops causing disk exhaustion
            if RE_DOS_012_DISK_EXHAUSTION.is_match(trimmed) {
                findings.push(Self::create_finding(
                    "BK-AI-DOS-012",
                    "CWE-400",
                    "Error path repeatedly writes huge logs/reports causing disk exhaustion",
                    Severity::Medium,
                    "2.16 Availability, denial of service and resource budgets",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Error handlers must truncate logged payloads and prevent recursive logging loops.",
                    "Exception handler writes unbounded request bodies or full system dumps to disk, risking disk space exhaustion.",
                    "Truncate logged payloads (e.g. limit to 1KB) and use rotating loggers with strict disk quotas.",
                ));
            }
        }

        findings
    }

    /// Helper to construct standardized Finding instances.
    #[allow(clippy::too_many_arguments)]
    fn create_finding(
        rule_id: &str,
        cwe: &str,
        title: &str,
        severity: Severity,
        category: &str,
        path: &Path,
        target_kind: &TargetKind,
        line_no: usize,
        snippet: &str,
        safe_threshold: &str,
        description: &str,
        remediation: &str,
    ) -> Finding {
        let file_tag = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("source");
        let short_id = rule_id.trim_start_matches("BK-AI-");
        let finding_id = format!("{}-{}-L{}", short_id, file_tag, line_no);

        let mut finding = Finding::new(
            finding_id,
            CveId::Custom {
                id: rule_id.to_string(),
                title: title.to_string(),
            },
            severity,
            target_kind.clone(),
            Some(path.to_path_buf()),
            Some(line_no),
            snippet,
            safe_threshold,
            description,
            remediation,
        );
        finding.detector_id = "network-dos".to_string();
        finding.detector_version = "1.0.0".to_string();
        finding.category = category.to_string();
        finding.affectedness = Affectedness::ConfirmedAffected;
        finding.reachability = Reachability::PotentiallyReachable;
        finding.confidence = Confidence::High;
        finding.evidence_certainty = EvidenceCertainty::StronglySupported;
        finding.advisory_ids = vec![cwe.to_string(), rule_id.to_string()];
        finding.evidence_refs.push(EvidenceRef {
            location: format!("{}:{}", path.display(), line_no),
            line_number: Some(line_no),
            snippet: Some(snippet.trim().to_string()),
            sha256: None,
        });
        finding.compute_dedupe_fingerprint();
        finding
    }
}
