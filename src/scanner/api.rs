#![allow(dead_code)]

use crate::types::*;
use regex::Regex;
use std::path::Path;
use std::sync::LazyLock;

// 1. BK-AI-API-001 (CWE-20): Client-Side Only Validation / Unvalidated Request Body Usage
static RE_API_001_UI_COMMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)//.*(?:validation\s+occurs?\s+(?:only\s+)?in\s+UI|validated\s+(?:only\s+)?(?:on|by|in)\s+(?:client|frontend|UI)|client-side\s+validation\s+only)"#)
        .unwrap()
});

static RE_API_001_RAW_BODY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:(?:const|let|var)\s+[a-zA-Z0-9_]+\s*=\s*(?:req|request)\.body\s*;|(?:process|handle|execute|save|create|update|insert)[A-Z][a-zA-Z0-9_]*\s*\(\s*(?:req|request)\.body\s*\))"#)
        .unwrap()
});

static RE_API_001_VALIDATION_GUARDS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:parse|safeParse|validate|validator|schema|check|sanitize|joi|zod|yup|ajv|class-validator)"#)
        .unwrap()
});

// 2. BK-AI-API-002 (CWE-915): Mass assignment / unknown fields accepted into privileged model without allowlist
static RE_API_002_MASS_ASSIGNMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:([A-Z][a-zA-Z0-9_]*)\.(?:create|update|insert|upsert|findByIdAndUpdate|createMany|updateMany|updateAttributes)\s*\(\s*(?:req|request)\.body\s*\)|prisma\.[a-zA-Z0-9_]+\.(?:create|update|upsert)\s*\(\s*\{\s*data\s*:\s*(?:req|request)\.body\s*\}|\b(?:Object\.assign\s*\(\s*[a-zA-Z0-9_]+\s*,\s*(?:req|request)\.body\s*\)|db\.[a-zA-Z0-9_]+\.(?:insert|insertOne|updateOne)\s*\(\s*(?:req|request)\.body\s*\)|[A-Z][a-zA-Z0-9_]*\.objects\.(?:create|update)\s*\(\s*\*\*(?:request\.(?:POST|data)|req\.body)\s*\)))"#)
        .unwrap()
});

static RE_API_002_ALLOWLIST_GUARDS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:pick|allowlist|whitelist|sanitize|cleanPayload)\s*\("#).unwrap()
});

// 3. BK-AI-API-003 (CWE-770): No per-actor rate/size limit on expensive API operations
static RE_API_003_EXPENSIVE_ROUTE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:app|router)\.(?:post|put|get)\s*\(\s*['"][^'"]*(?:export|convert|batch|render|transcode|generate-report|reports?/generate|pdf)[^'"]*['"]\s*,\s*(?:async\s*)?(?:\(\s*(?:req|request)|function\s*\(\s*(?:req|request))"#)
        .unwrap()
});

static RE_API_003_RATE_LIMIT_GUARDS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:rateLimit|rateLimiter|limiter|throttle|rate_limit)"#).unwrap()
});

// 4. BK-AI-API-004 (CWE-400): GraphQL depth, complexity or introspection exposure lacks control
static RE_API_004_GRAPHQL_EXPOSURE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\bintrospection\s*:\s*(?:true|!0|1)\b|\bvalidationRules\s*:\s*\[\s*\]|\bdepthLimit\s*:\s*(?:false|0)\b"#)
        .unwrap()
});

static RE_API_004_PROD_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:NODE_ENV\s*!==\s*['"]production['"]|isDev|isDevelopment|env\s*===\s*['"]development['"])"#)
        .unwrap()
});

// 5. BK-AI-API-005 (CWE-862): WebSocket upgrade/authentication checked once, not per message or room
static RE_API_005_WS_EVENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)socket\.on\s*\(\s*['"](?:join|join_room|joinRoom|subscribe|switch_room)['"]"#)
        .unwrap()
});

static RE_API_005_SOCKET_JOIN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)(?:socket\.join|this\.join)\s*\("#).unwrap());

static RE_API_005_AUTH_GUARDS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:canJoin|hasPermission|authorize|checkAuth|isAllowed|verifyPermission|user\.rooms|socket\.user)"#)
        .unwrap()
});

// 6. BK-AI-API-006 (CWE-306): gRPC metadata/auth interceptors omit service or streaming methods
static RE_API_006_STREAM_CHECK: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:serverStream\(\)|isStreaming\s*\([^)]*\)|getType\(\)\s*==\s*MethodType\.(?:SERVER_STREAMING|BIDI_STREAMING)|method\.contains\s*\(\s*['"]Stream['"]\s*\)|MethodType\.CLIENT_STREAMING)"#)
        .unwrap()
});

static RE_API_006_RETURN_NEXT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)\breturn\s+(?:next|next\.startCall|handler)"#).unwrap());

static RE_API_006_BYPASS_LIST: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:bypass(?:Methods|Paths|Services)|public(?:Methods|RpcPrefixes|Services))\s*=\s*\[[^\]]*(?:Stream|Admin|Internal|User)"#)
        .unwrap()
});

// 7. BK-AI-API-007 (CWE-200): Pagination/filtering unbounded / can enumerate data
static RE_API_007_UNBOUNDED_LIMIT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:(?:const|let|var)\s+limit\s*=\s*(?:parseInt\s*\(\s*|Number\s*\(\s*)?(?:req|request)\.(?:query|params)\.limit\b|\.(?:limit|take)\s*\(\s*(?:parseInt\s*\(\s*|Number\s*\(\s*)?(?:req|request)\.(?:query|params)\.limit\b|\blimit\s*:\s*(?:parseInt\s*\(\s*|Number\s*\(\s*)?(?:req|request)\.(?:query|params)\.limit\b|limit\s*=\s*int\s*\(\s*request\.(?:args|GET)\.get\s*\(\s*['"]limit['"]\s*\)\s*\))"#)
        .unwrap()
});

static RE_API_007_LIMIT_CAP: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:Math\.min|clamp|\.min\(|min\s*\(|Math\.max\([^,]+,\s*Math\.min|\?\s*\d+\s*:\s*limit|limit\s*>\s*\d+)"#)
        .unwrap()
});

// 8. BK-AI-API-008 (CWE-345): Webhook request lacks sender authentication or HMAC signature verification
static RE_API_008_WEBHOOK_ROUTE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:app|router)\.post\s*\(\s*['"][^'"]*webhook(?:s)?(?:/[^'"]*)?['"]"#)
        .unwrap()
});

static RE_API_008_SIG_VERIFY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:constructEvent|createHmac|verifySignature|verifyWebhook|timingSafeEqual|x-hub-signature|stripe-signature|signatureVerification|verify_signature)"#)
        .unwrap()
});

// 9. BK-AI-API-009 (CWE-201): Third-party API credentials forwarded to clients in response
static RE_API_009_LEAK_SECRET_ENV: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:res|response)\.(?:status\s*\(\s*\d+\s*\)\s*\.)?(?:json|send)\s*\(\s*\{[^\}]*process\.env\.(?:[A-Za-z0-9_]*(?:SECRET|PRIVATE|TOKEN|API_KEY|ACCESS_KEY)[A-Za-z0-9_]*)"#)
        .unwrap()
});

static RE_API_009_PUBLIC_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)process\.env\.(?:[A-Za-z0-9_]*(?:PUBLISHABLE|PUBLIC|CLIENT_ID)[A-Za-z0-9_]*)"#,
    )
    .unwrap()
});

// 10. BK-AI-API-010 (CWE-20): HTTP method override or content-type ambiguity bypasses validation
static RE_API_010_METHOD_OVERRIDE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(?:app|router|server)\.use\s*\(\s*methodOverride\s*\("#).unwrap()
});

// 11. BK-AI-API-011 (CWE-524): Cached privileged API response served across users
static RE_API_011_PUBLIC_CACHE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:res|response)\.(?:set|setHeader|header)\s*\(\s*['"]Cache-Control['"]\s*,\s*['"][^'"]*\bpublic\b"#)
        .unwrap()
});

static RE_API_011_AUTH_INDICATOR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:req\.user|request\.user|requireAuth|authMiddleware|passport\.authenticate|bearerAuth|verifyToken|authenticateUser|account|profile)"#)
        .unwrap()
});

// 12. BK-AI-API-012 (CWE-209): Remote service errors returned with sensitive stack traces or connection strings
static RE_API_012_STACK_EXPOSURE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:(?:res|response)(?:\.status\s*\(\s*\d+\s*\))?\.(?:json|send)\s*\(\s*\{[^\}]*(?:stack\s*:\s*(?:err|error)\.stack|error\s*:\s*(?:err|error)\.stack|err\s*:\s*(?:err|error)\.stack)|(?:res|response)(?:\.status\s*\(\s*5\d\d\s*\))?\.(?:json|send)\s*\(\s*(?:err|error)\.stack\s*\))"#)
        .unwrap()
});

// 13. BK-AI-API-013 (CWE-306): Server-to-server trust relies only on obscurity/unverified header
static RE_API_013_UNVERIFIED_HEADER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:(?:req|request)\.(?:headers\s*\[\s*|get\s*\(\s*)['"](?:x-internal|x-internal-token|x-is-admin|x-origin-internal|x-backend-trust)['"]\s*\]?\s*={2,3}\s*['"](?:true|1|internal|secret)['"]|(?:req|request)\.(?:headers\s*\[\s*|get\s*\(\s*)['"]x-forwarded-for['"]\s*\]?\s*={2,3}\s*['"](?:127\.0\.0\.1|localhost)['"])"#)
        .unwrap()
});

// 14. BK-AI-API-014 (CWE-200): Subscription/event stream can consume other principals' updates
static RE_API_014_UNFILTERED_BROADCAST: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:(?:io|io\.sockets)\.emit\s*\(\s*['"][^'"]*(?:order|account|user|payment|invoice|profile|billing|record|document)[^'"]*['"]\s*,\s*[a-zA-Z0-9_]+\s*\)|wss\.clients\.forEach\s*\(\s*(?:function\s*\([a-zA-Z0-9_]+\)|[a-zA-Z0-9_]+\s*=>)\s*\{?[^}]*(?:client|ws)\.send\s*\([^)]*(?:order|account|user|payment|invoice|profile|billing|tenant)[^)]*\))"#)
        .unwrap()
});

pub struct ApiSecurityScanner;

impl ApiSecurityScanner {
    /// Scans source code content for Category 6 API security vulnerabilities:
    /// - BK-AI-API-001 (CWE-20): Request body validation only occurs in UI
    /// - BK-AI-API-002 (CWE-915): Mass assignment / unknown fields accepted into model without allowlist
    /// - BK-AI-API-003 (CWE-770): No per-actor rate limit on expensive API operations
    /// - BK-AI-API-004 (CWE-400): GraphQL depth, complexity or introspection exposure lacks control
    /// - BK-AI-API-005 (CWE-862): WebSocket upgrade/authentication checked once, not per room
    /// - BK-AI-API-006 (CWE-306): gRPC metadata/auth interceptors omit streaming methods
    /// - BK-AI-API-007 (CWE-200): Pagination/filtering unbounded / can enumerate data
    /// - BK-AI-API-008 (CWE-345): Webhook request lacks sender authentication / HMAC signature
    /// - BK-AI-API-009 (CWE-201): Third-party API credentials forwarded to clients in response
    /// - BK-AI-API-010 (CWE-20): HTTP method override or content-type ambiguity bypasses validation
    /// - BK-AI-API-011 (CWE-524): Cached privileged API response served across users
    /// - BK-AI-API-012 (CWE-209): Remote service errors returned with sensitive stack traces
    /// - BK-AI-API-013 (CWE-306): Server-to-server trust relies only on obscurity/unverified header
    /// - BK-AI-API-014 (CWE-200): Subscription/event stream can consume other principals' updates
    pub fn scan_source(path: &Path, content: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        let target_kind = match path.extension().and_then(|ext| ext.to_str()) {
            Some("js" | "mjs" | "cjs" | "ts" | "tsx" | "jsx") => TargetKind::NodeSourceFile,
            _ => TargetKind::GenericSourceFile,
        };

        let file_tag = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("source");

        let lines: Vec<&str> = content.lines().collect();
        let total_lines = lines.len();

        let has_auth_context = RE_API_011_AUTH_INDICATOR.is_match(content);

        for (idx, line) in lines.iter().enumerate() {
            let line_no = idx + 1;
            let trimmed = line.trim();

            if trimmed.is_empty() {
                continue;
            }

            // 1. BK-AI-API-001 (CWE-20): Request body validation only occurs in UI
            if RE_API_001_UI_COMMENT.is_match(trimmed) {
                let id = format!("API-001-{}-{}", file_tag, line_no);
                let mut finding = Finding::new(
                    id,
                    CveId::Custom {
                        id: "BK-AI-API-001".to_string(),
                        title: "Request Body Validation Only Occurs in UI".to_string(),
                    },
                    Severity::High,
                    target_kind.clone(),
                    Some(path.to_path_buf()),
                    Some(line_no),
                    trimmed,
                    "Enforce strict server-side schema validation on all request bodies",
                    format!(
                        "File '{}' indicates client-side only validation at line {}. Server must validate input types, lengths, shapes, and enums.",
                        path.display(),
                        line_no
                    ),
                    "Restore invariant: server enforces type, length, shape, enum",
                );
                Self::populate_metadata(
                    &mut finding,
                    "BK-AI-API-001",
                    "CWE-20",
                    path,
                    line_no,
                    trimmed,
                );
                findings.push(finding);
                continue;
            } else if RE_API_001_RAW_BODY.is_match(trimmed)
                && !RE_API_001_VALIDATION_GUARDS.is_match(trimmed)
                && !RE_API_002_MASS_ASSIGNMENT.is_match(trimmed)
            {
                let id = format!("API-001-{}-{}", file_tag, line_no);
                let mut finding = Finding::new(
                    id,
                    CveId::Custom {
                        id: "BK-AI-API-001".to_string(),
                        title: "Unvalidated Request Body Usage in Application Logic".to_string(),
                    },
                    Severity::High,
                    target_kind.clone(),
                    Some(path.to_path_buf()),
                    Some(line_no),
                    trimmed,
                    "Validate request body against a strict schema (e.g. Zod, Joi) before consumption",
                    format!(
                        "File '{}' uses unvalidated req.body directly at line {}. Request bodies must be validated server-side.",
                        path.display(),
                        line_no
                    ),
                    "Restore invariant: server enforces type, length, shape, enum",
                );
                Self::populate_metadata(
                    &mut finding,
                    "BK-AI-API-001",
                    "CWE-20",
                    path,
                    line_no,
                    trimmed,
                );
                findings.push(finding);
            }

            // Skip further checks on pure comment lines
            if trimmed.starts_with("//") || trimmed.starts_with('#') || trimmed.starts_with('*') {
                continue;
            }

            // 2. BK-AI-API-002 (CWE-915): Mass assignment into privileged model without allowlist
            if RE_API_002_MASS_ASSIGNMENT.is_match(trimmed)
                && !RE_API_002_ALLOWLIST_GUARDS.is_match(trimmed)
            {
                let id = format!("API-002-{}-{}", file_tag, line_no);
                let mut finding = Finding::new(
                    id,
                    CveId::Custom {
                        id: "BK-AI-API-002".to_string(),
                        title: "Mass Assignment / Unfiltered Model Creation".to_string(),
                    },
                    Severity::High,
                    target_kind.clone(),
                    Some(path.to_path_buf()),
                    Some(line_no),
                    trimmed,
                    "Filter input through an explicit allowlist or DTO before binding to persistent models",
                    format!(
                        "File '{}' passes raw user input directly to model creation/update at line {}. Mass assignment allows attackers to overwrite privileged fields.",
                        path.display(),
                        line_no
                    ),
                    "Restore invariant: reject or strip unauthorized fields",
                );
                Self::populate_metadata(
                    &mut finding,
                    "BK-AI-API-002",
                    "CWE-915",
                    path,
                    line_no,
                    trimmed,
                );
                findings.push(finding);
            }

            // 3. BK-AI-API-003 (CWE-770): No per-actor rate limit on expensive API operations
            if RE_API_003_EXPENSIVE_ROUTE.is_match(trimmed)
                && !RE_API_003_RATE_LIMIT_GUARDS.is_match(trimmed)
            {
                let id = format!("API-003-{}-{}", file_tag, line_no);
                let mut finding = Finding::new(
                    id,
                    CveId::Custom {
                        id: "BK-AI-API-003".to_string(),
                        title: "Unbounded Expensive API Operation Without Rate Limiting"
                            .to_string(),
                    },
                    Severity::Medium,
                    target_kind.clone(),
                    Some(path.to_path_buf()),
                    Some(line_no),
                    trimmed,
                    "Apply rate limiting and payload size bounds to resource-intensive operations",
                    format!(
                        "File '{}' declares expensive API operation at line {} without rate limiting middleware. Attackers can trigger denial of service via resource exhaustion.",
                        path.display(),
                        line_no
                    ),
                    "Restore invariant: bounded usage by identity/tenant",
                );
                Self::populate_metadata(
                    &mut finding,
                    "BK-AI-API-003",
                    "CWE-770",
                    path,
                    line_no,
                    trimmed,
                );
                findings.push(finding);
            }

            // 4. BK-AI-API-004 (CWE-400): GraphQL depth, complexity or introspection exposure
            if RE_API_004_GRAPHQL_EXPOSURE.is_match(trimmed)
                && !RE_API_004_PROD_GUARD.is_match(trimmed)
            {
                let id = format!("API-004-{}-{}", file_tag, line_no);
                let mut finding = Finding::new(
                    id,
                    CveId::Custom {
                        id: "BK-AI-API-004".to_string(),
                        title: "GraphQL Uncontrolled Query Depth or Introspection Exposure"
                            .to_string(),
                    },
                    Severity::Medium,
                    target_kind.clone(),
                    Some(path.to_path_buf()),
                    Some(line_no),
                    trimmed,
                    "Disable GraphQL introspection in production and enforce query depth/complexity limits",
                    format!(
                        "File '{}' exposes GraphQL introspection or lacks query depth bounds at line {}. Attackers can enumerate schema or cause recursive query denial of service.",
                        path.display(),
                        line_no
                    ),
                    "Restore invariant: bounded query cost; deliberate schema exposure",
                );
                Self::populate_metadata(
                    &mut finding,
                    "BK-AI-API-004",
                    "CWE-400",
                    path,
                    line_no,
                    trimmed,
                );
                findings.push(finding);
            }

            // 5. BK-AI-API-005 (CWE-862): WebSocket upgrade/authentication checked once, not per room
            if RE_API_005_WS_EVENT.is_match(trimmed) {
                let end_idx = (idx + 8).min(total_lines);
                let block = lines[idx..end_idx].join("\n");
                if RE_API_005_SOCKET_JOIN.is_match(&block)
                    && !RE_API_005_AUTH_GUARDS.is_match(&block)
                {
                    let id = format!("API-005-{}-{}", file_tag, line_no);
                    let mut finding = Finding::new(
                        id,
                        CveId::Custom {
                            id: "BK-AI-API-005".to_string(),
                            title: "WebSocket Room Join Without Per-Room Authorization".to_string(),
                        },
                        Severity::High,
                        target_kind.clone(),
                        Some(path.to_path_buf()),
                        Some(line_no),
                        trimmed,
                        "Verify user permissions before joining rooms or subscribing to private channels",
                        format!(
                            "File '{}' joins WebSocket client to arbitrary room at line {} without authorization check. Connection-time authentication does not authorize room membership.",
                            path.display(),
                            line_no
                        ),
                        "Restore invariant: membership and operations rechecked",
                    );
                    Self::populate_metadata(
                        &mut finding,
                        "BK-AI-API-005",
                        "CWE-862",
                        path,
                        line_no,
                        trimmed,
                    );
                    findings.push(finding);
                }
            }

            // 6. BK-AI-API-006 (CWE-306): gRPC metadata/auth interceptors omit service or streaming methods
            if RE_API_006_BYPASS_LIST.is_match(trimmed) {
                let id = format!("API-006-{}-{}", file_tag, line_no);
                let mut finding = Finding::new(
                    id,
                    CveId::Custom {
                        id: "BK-AI-API-006".to_string(),
                        title: "gRPC Auth Interceptor Omits Streaming or Privileged Methods"
                            .to_string(),
                    },
                    Severity::High,
                    target_kind.clone(),
                    Some(path.to_path_buf()),
                    Some(line_no),
                    trimmed,
                    "Ensure auth interceptor applies to all RPC methods, including streaming and internal services",
                    format!(
                        "File '{}' bypasses authentication on streaming or privileged gRPC methods at line {}.",
                        path.display(),
                        line_no
                    ),
                    "Restore invariant: all privileged RPC paths gated",
                );
                Self::populate_metadata(
                    &mut finding,
                    "BK-AI-API-006",
                    "CWE-306",
                    path,
                    line_no,
                    trimmed,
                );
                findings.push(finding);
            } else if RE_API_006_STREAM_CHECK.is_match(trimmed) {
                let end_idx = (idx + 4).min(total_lines);
                let block = lines[idx..end_idx].join("\n");
                if RE_API_006_RETURN_NEXT.is_match(&block) {
                    let id = format!("API-006-{}-{}", file_tag, line_no);
                    let mut finding = Finding::new(
                        id,
                        CveId::Custom {
                            id: "BK-AI-API-006".to_string(),
                            title: "gRPC Auth Interceptor Omits Streaming Methods".to_string(),
                        },
                        Severity::High,
                        target_kind.clone(),
                        Some(path.to_path_buf()),
                        Some(line_no),
                        trimmed,
                        "Ensure auth interceptor gates all streaming RPC paths properly",
                        format!(
                            "File '{}' returns early on streaming gRPC methods without token verification at line {}.",
                            path.display(),
                            line_no
                        ),
                        "Restore invariant: all privileged RPC paths gated",
                    );
                    Self::populate_metadata(
                        &mut finding,
                        "BK-AI-API-006",
                        "CWE-306",
                        path,
                        line_no,
                        trimmed,
                    );
                    findings.push(finding);
                }
            }

            // 7. BK-AI-API-007 (CWE-200): Pagination/filtering unbounded / can enumerate data
            if RE_API_007_UNBOUNDED_LIMIT.is_match(trimmed)
                && !RE_API_007_LIMIT_CAP.is_match(trimmed)
            {
                let id = format!("API-007-{}-{}", file_tag, line_no);
                let mut finding = Finding::new(
                    id,
                    CveId::Custom {
                        id: "BK-AI-API-007".to_string(),
                        title: "Unbounded Pagination Limit / Mass Data Enumeration".to_string(),
                    },
                    Severity::Medium,
                    target_kind.clone(),
                    Some(path.to_path_buf()),
                    Some(line_no),
                    trimmed,
                    "Enforce strict upper bound (e.g. Math.min(limit, 100)) on pagination limits",
                    format!(
                        "File '{}' accepts unconstrained pagination limit at line {}. Attackers can enumerate entire datasets or exhaust database memory.",
                        path.display(),
                        line_no
                    ),
                    "Restore invariant: scoped query enforced",
                );
                Self::populate_metadata(
                    &mut finding,
                    "BK-AI-API-007",
                    "CWE-200",
                    path,
                    line_no,
                    trimmed,
                );
                findings.push(finding);
            }

            // 8. BK-AI-API-008 (CWE-345): Webhook request lacks sender authentication or HMAC signature verification
            if RE_API_008_WEBHOOK_ROUTE.is_match(trimmed) {
                let end_idx = (idx + 25).min(total_lines);
                let block = lines[idx..end_idx].join("\n");
                if !RE_API_008_SIG_VERIFY.is_match(&block) {
                    let id = format!("API-008-{}-{}", file_tag, line_no);
                    let mut finding = Finding::new(
                        id,
                        CveId::Custom {
                            id: "BK-AI-API-008".to_string(),
                            title: "Webhook Endpoint Missing HMAC Signature Verification"
                                .to_string(),
                        },
                        Severity::High,
                        target_kind.clone(),
                        Some(path.to_path_buf()),
                        Some(line_no),
                        trimmed,
                        "Verify cryptographic webhook signatures (e.g. Stripe-Signature, X-Hub-Signature-256) using constant-time comparison",
                        format!(
                            "File '{}' declares webhook endpoint at line {} without HMAC signature verification. Attackers can forge webhook events.",
                            path.display(),
                            line_no
                        ),
                        "Restore invariant: signature, timestamp and replay as applicable",
                    );
                    Self::populate_metadata(
                        &mut finding,
                        "BK-AI-API-008",
                        "CWE-345",
                        path,
                        line_no,
                        trimmed,
                    );
                    findings.push(finding);
                }
            }

            // 9. BK-AI-API-009 (CWE-201): Third-party API credentials forwarded to clients in response
            if RE_API_009_LEAK_SECRET_ENV.is_match(trimmed)
                && !RE_API_009_PUBLIC_GUARD.is_match(trimmed)
            {
                let id = format!("API-009-{}-{}", file_tag, line_no);
                let mut finding = Finding::new(
                    id,
                    CveId::Custom {
                        id: "BK-AI-API-009".to_string(),
                        title: "Third-Party API Credentials Leaked in Response Payload".to_string(),
                    },
                    Severity::High,
                    target_kind.clone(),
                    Some(path.to_path_buf()),
                    Some(line_no),
                    trimmed,
                    "Never expose sensitive API keys, secret credentials, or private tokens in HTTP responses",
                    format!(
                        "File '{}' returns private environment secret to client in HTTP response at line {}.",
                        path.display(),
                        line_no
                    ),
                    "Restore invariant: tokens restricted to intended backend",
                );
                Self::populate_metadata(
                    &mut finding,
                    "BK-AI-API-009",
                    "CWE-201",
                    path,
                    line_no,
                    trimmed,
                );
                findings.push(finding);
            }

            // 10. BK-AI-API-010 (CWE-20): HTTP method override or content-type ambiguity bypasses validation
            if RE_API_010_METHOD_OVERRIDE.is_match(trimmed) {
                let id = format!("API-010-{}-{}", file_tag, line_no);
                let mut finding = Finding::new(
                    id,
                    CveId::Custom {
                        id: "BK-AI-API-010".to_string(),
                        title: "HTTP Method Override Ambiguity Bypassing Security Controls"
                            .to_string(),
                    },
                    Severity::Medium,
                    target_kind.clone(),
                    Some(path.to_path_buf()),
                    Some(line_no),
                    trimmed,
                    "Avoid global methodOverride middleware or restrict allowed methods and source headers strictly",
                    format!(
                        "File '{}' registers methodOverride middleware at line {}. Attackers can override HTTP verbs to bypass reverse proxy or WAF policies.",
                        path.display(),
                        line_no
                    ),
                    "Restore invariant: equivalent encodings and verbs protected",
                );
                Self::populate_metadata(
                    &mut finding,
                    "BK-AI-API-010",
                    "CWE-20",
                    path,
                    line_no,
                    trimmed,
                );
                findings.push(finding);
            }

            // 11. BK-AI-API-011 (CWE-524): Cached privileged API response served across users
            if RE_API_011_PUBLIC_CACHE.is_match(trimmed) && has_auth_context {
                let id = format!("API-011-{}-{}", file_tag, line_no);
                let mut finding = Finding::new(
                    id,
                    CveId::Custom {
                        id: "BK-AI-API-011".to_string(),
                        title: "Public Cache-Control on Authenticated/Privileged Endpoint"
                            .to_string(),
                    },
                    Severity::High,
                    target_kind.clone(),
                    Some(path.to_path_buf()),
                    Some(line_no),
                    trimmed,
                    "Use 'Cache-Control: private, no-store' on authenticated or user-scoped endpoints",
                    format!(
                        "File '{}' sets public Cache-Control on an authenticated endpoint at line {}. Proxies or CDNs may serve cached sensitive responses across users.",
                        path.display(),
                        line_no
                    ),
                    "Restore invariant: cache key/scope and `Cache-Control` correct",
                );
                Self::populate_metadata(
                    &mut finding,
                    "BK-AI-API-011",
                    "CWE-524",
                    path,
                    line_no,
                    trimmed,
                );
                findings.push(finding);
            }

            // 12. BK-AI-API-012 (CWE-209): Remote service errors returned with sensitive stack traces
            if RE_API_012_STACK_EXPOSURE.is_match(trimmed) {
                let id = format!("API-012-{}-{}", file_tag, line_no);
                let mut finding = Finding::new(
                    id,
                    CveId::Custom {
                        id: "BK-AI-API-012".to_string(),
                        title:
                            "Sensitive Stack Trace or Internal Details Returned in Error Response"
                                .to_string(),
                    },
                    Severity::Medium,
                    target_kind.clone(),
                    Some(path.to_path_buf()),
                    Some(line_no),
                    trimmed,
                    "Log stack traces internally and return generic, sanitized error messages to callers",
                    format!(
                        "File '{}' exposes error stack trace in HTTP response at line {}. Internal paths and dependencies are leaked to callers.",
                        path.display(),
                        line_no
                    ),
                    "Restore invariant: caller sees bounded error details",
                );
                Self::populate_metadata(
                    &mut finding,
                    "BK-AI-API-012",
                    "CWE-209",
                    path,
                    line_no,
                    trimmed,
                );
                findings.push(finding);
            }

            // 13. BK-AI-API-013 (CWE-306): Server-to-server trust relies only on obscurity/unverified header
            if RE_API_013_UNVERIFIED_HEADER.is_match(trimmed) {
                let id = format!("API-013-{}-{}", file_tag, line_no);
                let mut finding = Finding::new(
                    id,
                    CveId::Custom {
                        id: "BK-AI-API-013".to_string(),
                        title: "Server-to-Server Trust Relies Solely on Unverified Header"
                            .to_string(),
                    },
                    Severity::High,
                    target_kind.clone(),
                    Some(path.to_path_buf()),
                    Some(line_no),
                    trimmed,
                    "Authenticate server-to-server calls with mutual TLS (mTLS) or cryptographically verified asymmetric tokens",
                    format!(
                        "File '{}' relies on spoofable header for internal authorization at line {}. Attackers can spoof HTTP headers to bypass access controls.",
                        path.display(),
                        line_no
                    ),
                    "Restore invariant: explicit service authentication/authorization",
                );
                Self::populate_metadata(
                    &mut finding,
                    "BK-AI-API-013",
                    "CWE-306",
                    path,
                    line_no,
                    trimmed,
                );
                findings.push(finding);
            }

            // 14. BK-AI-API-014 (CWE-200): Subscription/event stream can consume other principals' updates
            if RE_API_014_UNFILTERED_BROADCAST.is_match(trimmed) {
                let id = format!("API-014-{}-{}", file_tag, line_no);
                let mut finding = Finding::new(
                    id,
                    CveId::Custom {
                        id: "BK-AI-API-014".to_string(),
                        title: "Realtime Subscription Stream Broadcasting Without Tenant Scope"
                            .to_string(),
                    },
                    Severity::High,
                    target_kind.clone(),
                    Some(path.to_path_buf()),
                    Some(line_no),
                    trimmed,
                    "Enforce tenant-isolated rooms or channels when emitting realtime events to subscribers",
                    format!(
                        "File '{}' broadcasts sensitive data globally at line {} without tenant or user room scoping.",
                        path.display(),
                        line_no
                    ),
                    "Restore invariant: per-topic/channel permission enforced",
                );
                Self::populate_metadata(
                    &mut finding,
                    "BK-AI-API-014",
                    "CWE-200",
                    path,
                    line_no,
                    trimmed,
                );
                findings.push(finding);
            }
        }

        findings
    }

    fn populate_metadata(
        finding: &mut Finding,
        rule_id: &str,
        cwe: &str,
        path: &Path,
        line_no: usize,
        trimmed: &str,
    ) {
        finding.detector_id = "api-security".to_string();
        finding.detector_version = "1.0.0".to_string();
        finding.category = "2.6 HTTP APIs, GraphQL, gRPC and realtime".to_string();
        finding.affectedness = Affectedness::ConfirmedAffected;
        finding.reachability = Reachability::PotentiallyReachable;
        finding.confidence = Confidence::High;
        finding.evidence_certainty = EvidenceCertainty::StronglySupported;
        finding.advisory_ids = vec![cwe.to_string(), rule_id.to_string()];
        finding.evidence_refs.push(EvidenceRef {
            location: format!("{}:{}", path.display(), line_no),
            line_number: Some(line_no),
            snippet: Some(trimmed.to_string()),
            sha256: None,
        });
        finding.compute_dedupe_fingerprint();
    }
}
