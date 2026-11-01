#![allow(dead_code)]

use crate::scanner::finding_builder::{ScannerFindingBuilder, ScannerFindingSpec};
use crate::types::*;
use regex::Regex;
use std::path::Path;
use std::sync::LazyLock;

// ---------------------------------------------------------------------------
// Category 2: Authentication Rules (BK-AI-AUT-001 through BK-AI-AUT-012)
// ---------------------------------------------------------------------------

/// BK-AI-AUT-001: Protected route lacks server-side authentication
static RE_AUT_001_EXPRESS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:app|router)\.(?:get|post|put|delete|patch)\s*\(\s*['"]/(?:api/)?(?:admin|account|profile|settings|dashboard)(?:/[^'"]*)?['"]\s*,\s*(?:async\s*)?(?:function|\([^)]*\)|[a-zA-Z_][a-zA-Z0-9_]*\s*=>)"#).unwrap()
});

static RE_AUT_001_EXPRESS_MULTILINE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:app|router)\.(?:get|post|put|delete|patch)\s*\(\s*['"]/(?:api/)?(?:admin|account|profile|settings|dashboard)(?:/[^'"]*)?['"]\s*,?\s*$"#).unwrap()
});

static RE_AUT_001_FLASK: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)@app\.route\s*\(\s*['"]/(?:api/)?(?:admin|account|profile|settings|dashboard)(?:/[^'"]*)?['"]\s*\)"#).unwrap()
});

/// BK-AI-AUT-002: Middleware bypass through alternate HTTP path or suffix
static RE_AUT_002_BYPASS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:/\.\.;/|\.\.;/|/api/\.\.;|/admin\.\.;|req\.(?:url|path|originalUrl)\.endsWith\s*\(\s*['"]\.(?:json|css|js|ico|png|jpg|txt)['"]\s*\)|X-Original-URL|X-Rewrite-URL)"#).unwrap()
});

/// BK-AI-AUT-003: isAuthenticated stub, always-true mock or demo login remains
static RE_AUT_003_STUB: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:const|let|var)\s+isAuthenticated\s*=\s*(?:\([^)]*\)|[a-zA-Z0-9_]+)?\s*=>\s*true\b|function\s+isAuthenticated\s*\([^)]*\)\s*\{\s*return\s+true\s*;?\s*\}|def\s+is_authenticated\s*\([^)]*\)\s*:\s*return\s+True\b|\bis_authenticated\s*=\s*lambda\b.*:\s*True\b|(?:req|ctx)\.isAuthenticated\s*=\s*(?:\([^)]*\))?\s*=>\s*true\b|\b(?:mockAuth|bypassAuth|demoLogin|fakeAuth)\s*=\s*(?:true|True|1)\b"#).unwrap()
});

/// BK-AI-AUT-004: Passwords stored in plaintext, reversible encryption or fast unsalted hashes
static RE_AUT_004_PASSWORD_STORAGE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\b(?:md5|sha1)\s*\(\s*[^)]*(?:password|pwd|user_pass)|\bhashlib\.(?:md5|sha1)\s*\(\s*[^)]*(?:password|pwd|user_pass)|\bcreateHash\s*\(\s*['"](?:md5|sha1)['"]\s*\)\.update\s*\(\s*[^)]*(?:password|pwd|user_pass)|\b(?:user|account)\.password\s*=\s*(?:req\.body\.password|password_input|raw_password|plaintext)\b|\b(?:AES|createCipheriv)\s*\([^)]*(?:password|user_pass))"#).unwrap()
});

/// BK-AI-AUT-005: Password reset token is guessable or non-crypto
static RE_AUT_005_RESET_TOKEN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(?:reset_?token|reset_?code|password_?reset_?token|forgot_?token)\s*=\s*.*(?:Math\.random\s*\(|random\.random\s*\(|random\.randint\s*\(|\brand\s*\(|\bmt_rand\s*\(|Date\.now\s*\()|(?:Math\.random\s*\(|random\.random\s*\(|random\.randint\s*\(|\brand\s*\(|\bmt_rand\s*\().*(?:reset_?token|reset_?code|forgot_?token)"#).unwrap()
});

/// BK-AI-AUT-006: Email/phone change does not require fresh verification
static RE_AUT_006_CONTACT_CHANGE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(?:user|account)\.(?:email|phone)\s*=\s*(?:req\.body\.(?:email|phone)|new_email|new_phone)\b"#).unwrap()
});

/// BK-AI-AUT-007: No abuse throttling for sign-in, recovery, OTP
static RE_AUT_007_NO_RATE_LIMIT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:app|router)\.(?:post)\s*\(\s*['"]/(?:api/)?(?:login|signin|signup|register|otp|verify-otp|reset-password)(?:/[^'"]*)?['"]\s*,\s*(?:async\s*)?(?:function|\([^)]*\)|[a-zA-Z_][a-zA-Z0-9_]*\s*=>)"#).unwrap()
});

/// BK-AI-AUT-008: MFA disabled for sensitive administrative actions
static RE_AUT_008_MFA_DISABLED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(?:require_?mfa|mfa_?enabled|enforce_?mfa|two_?factor_?required|enable_?mfa)\s*[:=]\s*(?:false|False|0)\b|\b(?:bypass_?mfa|skip_?mfa|disable_?mfa)\s*[:=]\s*(?:true|True|1)\b|\bmfa\s*:\s*false\b"#).unwrap()
});

/// BK-AI-AUT-009: Fail-open login/auth service exception handling
static RE_AUT_009_FAIL_OPEN_LINE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)catch\s*(?:\([^)]*\))?\s*\{\s*(?:console\.(?:log|error|warn)\([^)]*\);\s*)?next\s*\(\s*\)\s*;?\s*\}|catch\s*(?:\([^)]*\))?\s*\{\s*return\s+true\s*;?\s*\}|except\s*(?:Exception)?\s*:\s*(?:#.*)?\s*return\s+True\b|except\s*(?:Exception)?\s*:\s*(?:#.*)?\s*pass\b"#).unwrap()
});

static RE_AUT_009_CATCH_HEADER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)catch\s*(?:\([^)]*\))?\s*\{"#).unwrap());

/// BK-AI-AUT-010: Authentication relies on client-side JS or route guard alone
static RE_AUT_010_CLIENT_AUTH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)if\s*\(\s*(?:localStorage|sessionStorage)\.getItem\s*\(\s*['"](?:token|auth|user|isAdmin|role)['"]\s*\)|(?:\bconst|\blet|\bvar)?\s*(?:isAdmin|isAuthorized)\s*=\s*(?:Boolean\s*\(\s*)?(?:localStorage|sessionStorage)\.getItem|//\s*(?:auth|authentication|authorization)\s*checked\s*(?:only\s*)?(?:in|on)\s*(?:client|frontend|browser|ui)\b|//\s*(?:client-side|frontend)\s*route\s*guard\s*(?:only|alone)\b"#).unwrap()
});

/// BK-AI-AUT-011: Untrusted JWT claims used before verification
static RE_AUT_011_JWT_DECODE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\bjwt\.decode\s*\([^)]*\)|\bjwt_decode\s*\([^)]*\)"#).unwrap()
});

/// BK-AI-AUT-012: OAuth/OIDC state parameter omitted in auth flow
static RE_AUT_012_OAUTH_URL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)https?://[^\s'"]+/(?:(?:o/)?oauth2?/(?:v\d+/)?auth|oauth/authorize|authorize)\?[^\s'"]+"#).unwrap()
});

static RE_AUT_012_OAUTH_CONFIG: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)passport\.authenticate\s*\(\s*['"][^'"]*['"]\s*,\s*\{[^}]*state\s*:\s*false|\bstate\s*:\s*false\b\s*(?:,|\})"#).unwrap()
});

// ---------------------------------------------------------------------------
// Category 4: Sessions, Tokens, Cookies Rules (BK-AI-SES-001 through BK-AI-SES-012)
// ---------------------------------------------------------------------------

/// BK-AI-SES-001: Session ID predictable or generated with non-cryptographic randomness
static RE_SES_001_WEAK_SESSION_ID: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(?:session_?id|sid|session_?token|sess_?id)\s*=\s*.*(?:Math\.random\s*\(|random\.random\s*\(|random\.randint\s*\(|\brand\s*\(|\bmt_rand\s*\(|Date\.now\s*\()|(?:Math\.random\s*\(|random\.random\s*\(|random\.randint\s*\(|\brand\s*\(|\bmt_rand\s*\().*(?:session_?id|sid|session_?token)"#).unwrap()
});

/// BK-AI-SES-002: Session not rotated after login
static RE_SES_002_SAVE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)(?:req\.)?session\.save\s*\("#).unwrap());

/// BK-AI-SES-003: Logout fails to invalidate server session
static RE_SES_003_CLEAR_COOKIE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)res\.clearCookie\s*\(\s*['"](?:session|sid|connect\.sid|auth|token)['"]"#)
        .unwrap()
});

/// BK-AI-SES-004: Cookie carrying session lacks Secure flag
static RE_SES_004_COOKIE_INSECURE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:res\.cookie\s*\([^,]+,\s*[^,]+,\s*\{[^}]*secure\s*:\s*false\b|\bcookie\s*:\s*\{[^}]*secure\s*:\s*false\b)"#).unwrap()
});

/// BK-AI-SES-005: Cookie carrying session lacks HttpOnly flag
static RE_SES_005_COOKIE_NO_HTTPONLY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:res\.cookie\s*\([^,]+,\s*[^,]+,\s*\{[^}]*httpOnly\s*:\s*false\b|\bcookie\s*:\s*\{[^}]*httpOnly\s*:\s*false\b)"#).unwrap()
});

/// BK-AI-SES-006: SameSite defense missing on cookies
static RE_SES_006_SAMESITE_DEFENSE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:sameSite\s*:\s*['"](?:none|None)['"]\s*,\s*secure\s*:\s*false\b|sameSite\s*:\s*false\b)"#).unwrap()
});

/// BK-AI-SES-007: Token lifetime too long or unlimited refresh token
static RE_SES_007_EXCESSIVE_TOKEN_LIFETIME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\bexpiresIn\s*:\s*['"](?:365d|[1-9]\d{2,}d|[1-9]\d*y)['"]|\bexpiresIn\s*:\s*(?:31536000\d*|9999999\d+)|\bmaxAge\s*:\s*(?:31536000000|1000\s*\*\s*60\s*\*\s*60\s*\*\s*24\s*\*\s*(?:365|\d{3,}))|\b(?:expiresIn|max_age)\s*:\s*['"](?:never|unlimited)['"]"#).unwrap()
});

/// BK-AI-SES-008: JWT algorithm confusion or none algorithm allowed
static RE_SES_008_JWT_ALGORITHM: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\balgorithms\s*:\s*\[[^\]]*['"]none['"][^\]]*\]|\balgorithm\s*:\s*['"]none['"]|\balgorithms\s*:\s*\[[^\]]*['"](?:HS256|HS384|HS512)['"][^\]]*,[^\]]*['"](?:RS256|RS384|RS512|ES256|ES384|ES512)['"][^\]]*\]|\balgorithms\s*:\s*\[[^\]]*['"](?:RS256|RS384|RS512|ES256|ES384|ES512)['"][^\]]*,[^\]]*['"](?:HS256|HS384|HS512)['"][^\]]*\]"#).unwrap()
});

/// BK-AI-SES-009: Token logged or embedded in URL/query
static RE_SES_009_TOKEN_EXPOSURE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:console\.log|logger\.(?:info|debug|warn|error))\s*\([^)]*\b(?:auth_?token|access_?token|authToken|bearerToken|jwt_?token|token)\b[^)]*\)|(?:redirect|href|navigate|url)\s*[:=\(]\s*['"][^'"]*[?&](?:access_token|id_token|token)=['"]?\s*\+|['"][^'"]*/callback\?(?:access_token|token|jwt)=['"]"#).unwrap()
});

/// BK-AI-SES-010: LocalStorage/sessionStorage holds sensitive auth tokens
static RE_SES_010_LOCAL_STORAGE_TOKEN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:localStorage|sessionStorage)\.setItem\s*\(\s*['"](?:auth_?token|jwt|access_?token|id_?token|session_?id|bearer_?token|user_?token|refreshToken)['"]|(?:localStorage|sessionStorage)\[['"](?:auth_?token|jwt|access_?token|id_?token|session_?id|refreshToken)['"]\]\s*="#).unwrap()
});

/// BK-AI-SES-011: Session cookie lacks domain/path scoping
static RE_SES_011_COOKIE_DOMAIN_PATH_SCOPE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\bdomain\s*:\s*['"]\*(?:\.[a-zA-Z0-9.-]+)?['"]|(?:\bdomain\s*:\s*['"]\.[a-zA-Z0-9.-]+['"][^}]*\bpath\s*:\s*['"]\/['"]|\bpath\s*:\s*['"]\/['"][^}]*\bdomain\s*:\s*['"]\.[a-zA-Z0-9.-]+['"])"#).unwrap()
});

/// BK-AI-SES-012: Refresh token reuse permitted / missing replay detection
static RE_SES_012_REFRESH_REUSE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(?:refreshTokenReuse|allow_?refresh_?token_?reuse|allow_?token_?reuse|permit_?reuse)\s*[:=]\s*(?:true|True|1)\b|\b(?:rotate_?refresh_?tokens?|refreshTokenRotation)\s*[:=]\s*(?:false|False|0)\b|\b(?:revoke_?old_?refresh_?token|invalidate_?used_?token)\s*[:=]\s*(?:false|False|0)\b|//\s*(?:no\s*refresh\s*token\s*rotation|allow\s*refresh\s*token\s*reuse)"#).unwrap()
});

pub struct AuthSecurityScanner;

impl AuthSecurityScanner {
    /// Scans source code content for authentication and session weaknesses across Categories 2 & 4.
    pub fn scan_source(path: &Path, content: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        let target_kind = match path.extension().and_then(|ext| ext.to_str()) {
            Some("js" | "mjs" | "cjs" | "ts" | "tsx" | "jsx") => TargetKind::NodeSourceFile,
            _ => TargetKind::GenericSourceFile,
        };

        let lines: Vec<&str> = content.lines().collect();

        for (idx, line) in lines.iter().enumerate() {
            let line_no = idx + 1;
            let trimmed = line.trim();

            if trimmed.is_empty() {
                continue;
            }

            // Check comment-specific indicators first before skipping general comments
            if trimmed.starts_with("//")
                || trimmed.starts_with('#')
                || trimmed.starts_with('*')
                || trimmed.starts_with("/*")
            {
                // BK-AI-AUT-008 comment indicator
                let lower_comment = trimmed.to_lowercase();
                if lower_comment.contains("skip mfa") || lower_comment.contains("bypass mfa") {
                    findings.push(Self::create_finding(ScannerFindingSpec {
                    rule_id: "BK-AI-AUT-008",
                    title: "MFA disabled for sensitive administrative actions or weak step-up logic",
                    severity: Severity::High,
                    category: "2.2 Authentication and account lifecycle",
                    path,
                    target_kind: &target_kind,
                    line_no,
                    snippet: trimmed,
                    safe_threshold: "Administrative actions and privilege transitions must enforce multi-factor authentication (MFA).",
                    description: "Code comment indicates MFA step-up verification is bypassed for administrative actions.",
                    remediation: "Enforce mandatory multi-factor authentication step-up verification on administrative endpoints.",
                }));
                }

                // BK-AI-AUT-010 comment indicator check
                if RE_AUT_010_CLIENT_AUTH.is_match(trimmed) {
                    findings.push(Self::create_finding(ScannerFindingSpec {
                    rule_id: "BK-AI-AUT-010",
                    title: "Authentication relies on client-side JS, hidden button or route guard alone",
                    severity: Severity::High,
                    category: "2.2 Authentication and account lifecycle",
                    path,
                    target_kind: &target_kind,
                    line_no,
                    snippet: trimmed,
                    safe_threshold: "Client-side route guards must never substitute for server-side authorization enforcement.",
                    description: "Code comment indicates authentication or authorization is only enforced on the client side.",
                    remediation: "Enforce server-side authorization checks on all backend endpoints rather than trusting client-side route guards.",
                }));
                }

                // BK-AI-SES-012 comment indicator check
                if RE_SES_012_REFRESH_REUSE.is_match(trimmed) {
                    findings.push(Self::create_finding(ScannerFindingSpec {
                    rule_id: "BK-AI-SES-012",
                    title: "Concurrent refresh calls permit token reuse/race or stale session resurrection",
                    severity: Severity::High,
                    category: "2.4 Sessions, tokens, cookies and browser login",
                    path,
                    target_kind: &target_kind,
                    line_no,
                    snippet: trimmed,
                    safe_threshold: "Refresh tokens must be single-use and rotated on every issuance with replay revocation.",
                    description: "Code comment or configuration indicates refresh token reuse is permitted without rotation.",
                    remediation: "Enable refresh token rotation and immediately revoke token family on detected reuse attempts.",
                }));
                }

                continue;
            }

            // ---------------------------------------------------------------
            // Category 2: Authentication Weaknesses
            // ---------------------------------------------------------------

            // 1. BK-AI-AUT-001: Protected route lacks server-side authentication
            if RE_AUT_001_EXPRESS.is_match(trimmed) {
                findings.push(Self::create_finding(ScannerFindingSpec {
                    rule_id: "BK-AI-AUT-001",
                    title: "Protected route lacks server-side authentication",
                    severity: Severity::High,
                    category: "2.2 Authentication and account lifecycle",
                    path,
                    target_kind: &target_kind,
                    line_no,
                    snippet: trimmed,
                    safe_threshold: "Protected routes (/admin, /account, /profile, /settings, /dashboard) must declare server-side auth middleware.",
                    description: "Route handler directly exposes a sensitive administrative or account endpoint without authentication middleware.",
                    remediation: "Add server-side authentication middleware (e.g. requireAuth, authenticate) before the route callback.",
                }));
            } else if RE_AUT_001_EXPRESS_MULTILINE.is_match(trimmed) {
                // Check if the next non-empty line starts directly with a callback
                if let Some(next_line) = lines.iter().skip(idx + 1).find(|l| !l.trim().is_empty()) {
                    let next_trimmed = next_line.trim();
                    if next_trimmed.starts_with("(req, res)")
                        || next_trimmed.starts_with("async (req, res)")
                        || next_trimmed.starts_with("function")
                    {
                        findings.push(Self::create_finding(ScannerFindingSpec {
                    rule_id: "BK-AI-AUT-001",
                    title: "Protected route lacks server-side authentication",
                    severity: Severity::High,
                    category: "2.2 Authentication and account lifecycle",
                    path,
                    target_kind: &target_kind,
                    line_no,
                    snippet: trimmed,
                    safe_threshold: "Protected routes must declare server-side authentication middleware.",
                    description: "Multi-line route declaration binds sensitive endpoint directly to handler callback without auth middleware.",
                    remediation: "Insert authentication middleware before the handler callback.",
                }));
                    }
                }
            } else if RE_AUT_001_FLASK.is_match(trimmed) {
                // Python Flask check: look ahead for def without @login_required
                if let Some(next_line) = lines.iter().skip(idx + 1).find(|l| !l.trim().is_empty()) {
                    let next_trimmed = next_line.trim();
                    if next_trimmed.starts_with("def ") {
                        findings.push(Self::create_finding(ScannerFindingSpec {
                    rule_id: "BK-AI-AUT-001",
                    title: "Protected route lacks server-side authentication",
                    severity: Severity::High,
                    category: "2.2 Authentication and account lifecycle",
                    path,
                    target_kind: &target_kind,
                    line_no,
                    snippet: trimmed,
                    safe_threshold: "Protected Flask endpoints must declare @login_required or auth decorator.",
                    description: "Flask route on sensitive path is directly followed by view function without auth decorator.",
                    remediation: "Apply @login_required or equivalent authentication decorator.",
                }));
                    }
                }
            }

            // 2. BK-AI-AUT-002: Middleware bypass through alternate HTTP path or suffix
            if RE_AUT_002_BYPASS.is_match(trimmed) {
                findings.push(Self::create_finding(ScannerFindingSpec {
                    rule_id: "BK-AI-AUT-002",
                    title: "Middleware bypass through alternate HTTP method, path or transport",
                    severity: Severity::High,
                    category: "2.2 Authentication and account lifecycle",
                    path,
                    target_kind: &target_kind,
                    line_no,
                    snippet: trimmed,
                    safe_threshold: "Canonicalize and normalize request paths before route matching and auth checks.",
                    description: "Path traversal bypass (e.g. '..;') or unnormalized suffix check detected in route handling.",
                    remediation: "Normalize request paths and eliminate matrix parameter or suffix-based middleware bypasses.",
                }));
            }

            // 3. BK-AI-AUT-003: isAuthenticated stub, always-true mock or demo login remains
            if RE_AUT_003_STUB.is_match(trimmed) {
                findings.push(Self::create_finding(ScannerFindingSpec {
                    rule_id: "BK-AI-AUT-003",
                    title: "`isAuthenticated` stub, always-true mock or demo login remains in release",
                    severity: Severity::High,
                    category: "2.2 Authentication and account lifecycle",
                    path,
                    target_kind: &target_kind,
                    line_no,
                    snippet: trimmed,
                    safe_threshold: "Authentication functions must evaluate authentic identity assertions and session state.",
                    description: "Hardcoded always-true authentication stub, mock login or demo bypass detected in code.",
                    remediation: "Remove mock auth bypasses and stubs; implement authentic identity verification.",
                }));
            }

            // 4. BK-AI-AUT-004: Passwords stored in plaintext, reversible encryption or fast unsalted hashes
            if RE_AUT_004_PASSWORD_STORAGE.is_match(trimmed) {
                findings.push(Self::create_finding(ScannerFindingSpec {
                    rule_id: "BK-AI-AUT-004",
                    title: "Passwords stored in plaintext, reversible encryption or fast unsalted hashes",
                    severity: Severity::High,
                    category: "2.2 Authentication and account lifecycle",
                    path,
                    target_kind: &target_kind,
                    line_no,
                    snippet: trimmed,
                    safe_threshold: "Passwords must be hashed using a dedicated memory-hard salted algorithm (Argon2id, bcrypt).",
                    description: "Password stored as plaintext, encrypted reversibly, or hashed with fast unsalted digest (MD5/SHA1).",
                    remediation: "Migrate password storage to Argon2id or bcrypt with unique per-user cryptographic salt.",
                }));
            }

            // 5. BK-AI-AUT-005: Password reset token is guessable or non-crypto
            if RE_AUT_005_RESET_TOKEN.is_match(trimmed) {
                findings.push(Self::create_finding(ScannerFindingSpec {
                    rule_id: "BK-AI-AUT-005",
                    title: "Password reset token is guessable, reusable, not expiring or not bound to user",
                    severity: Severity::High,
                    category: "2.2 Authentication and account lifecycle",
                    path,
                    target_kind: &target_kind,
                    line_no,
                    snippet: trimmed,
                    safe_threshold: "Password reset tokens must be generated using cryptographically secure pseudorandomness (CSPRNG).",
                    description: "Password reset token generated with non-cryptographic randomness (Math.random, rand(), Date.now()).",
                    remediation: "Generate reset tokens using crypto.randomBytes(32) with time-bounded expiration and single-use invalidation.",
                }));
            }

            // 6. BK-AI-AUT-006: Email/phone change does not require fresh verification
            if RE_AUT_006_CONTACT_CHANGE.is_match(trimmed) {
                let start = idx.saturating_sub(15);
                let end = (idx + 15).min(lines.len());
                let window = lines[start..end].join("\n").to_lowercase();
                let has_verification = window.contains("password")
                    || window.contains("verify")
                    || window.contains("token")
                    || window.contains("otp")
                    || window.contains("confirm")
                    || window.contains("reauth");

                if !has_verification {
                    findings.push(Self::create_finding(ScannerFindingSpec {
                    rule_id: "BK-AI-AUT-006",
                    title: "Email/phone change does not require appropriate fresh verification",
                    severity: Severity::Medium,
                    category: "2.2 Authentication and account lifecycle",
                    path,
                    target_kind: &target_kind,
                    line_no,
                    snippet: trimmed,
                    safe_threshold: "Account identifier changes must require current password verification or confirmation token.",
                    description: "Email or phone address updated directly on user record without re-authenticating or confirming via token.",
                    remediation: "Require current password re-entry or send confirmation token to existing address before updating credentials.",
                }));
                }
            }

            // 7. BK-AI-AUT-007: No abuse throttling for sign-in, recovery, OTP
            if RE_AUT_007_NO_RATE_LIMIT.is_match(trimmed) {
                findings.push(Self::create_finding(ScannerFindingSpec {
                    rule_id: "BK-AI-AUT-007",
                    title: "No abuse throttling for sign-in, recovery, OTP or invite issuance",
                    severity: Severity::Medium,
                    category: "2.2 Authentication and account lifecycle",
                    path,
                    target_kind: &target_kind,
                    line_no,
                    snippet: trimmed,
                    safe_threshold: "Authentication endpoints must enforce rate limiting / abuse throttling middleware.",
                    description: "Sign-in, signup, OTP or recovery route declared without rate limiting middleware in handler chain.",
                    remediation: "Apply rate limiting middleware (e.g. express-rate-limit, slow-down) to prevent brute-force abuse.",
                }));
            }

            // 8. BK-AI-AUT-008: MFA disabled for sensitive administrative actions
            if RE_AUT_008_MFA_DISABLED.is_match(trimmed) {
                findings.push(Self::create_finding(ScannerFindingSpec {
                    rule_id: "BK-AI-AUT-008",
                    title: "MFA disabled for sensitive administrative actions or weak step-up logic",
                    severity: Severity::High,
                    category: "2.2 Authentication and account lifecycle",
                    path,
                    target_kind: &target_kind,
                    line_no,
                    snippet: trimmed,
                    safe_threshold: "Administrative actions and privilege transitions must enforce multi-factor authentication (MFA).",
                    description: "MFA enforcement is explicitly disabled or bypassed for sensitive administrative actions.",
                    remediation: "Enforce mandatory multi-factor authentication step-up verification on administrative endpoints.",
                }));
            }

            // 9. BK-AI-AUT-009: Fail-open login/auth service exception handling
            let is_fail_open = if RE_AUT_009_FAIL_OPEN_LINE.is_match(trimmed) {
                true
            } else if RE_AUT_009_CATCH_HEADER.is_match(trimmed) {
                // Check if next non-empty line calls next(); without arguments
                if let Some(next_l) = lines.iter().skip(idx + 1).find(|l| !l.trim().is_empty()) {
                    let next_t = next_l.trim();
                    next_t == "next();"
                        || next_t == "next()"
                        || next_t == "return true;"
                        || next_t == "return true"
                } else {
                    false
                }
            } else {
                false
            };

            if is_fail_open {
                findings.push(Self::create_finding(ScannerFindingSpec {
                    rule_id: "BK-AI-AUT-009",
                    title: "Fail-open login/auth service timeout or exception",
                    severity: Severity::High,
                    category: "2.2 Authentication and account lifecycle",
                    path,
                    target_kind: &target_kind,
                    line_no,
                    snippet: trimmed,
                    safe_threshold: "Authentication filters and service handlers must fail closed upon exception or timeout.",
                    description: "Catch block fails open by invoking next() or returning true without enforcing identity.",
                    remediation: "Fail closed: reject unauthenticated requests with HTTP 401 or forward error via next(err).",
                }));
            }

            // 10. BK-AI-AUT-010: Authentication relies on client-side JS or route guard alone
            if RE_AUT_010_CLIENT_AUTH.is_match(trimmed) {
                findings.push(Self::create_finding(ScannerFindingSpec {
                    rule_id: "BK-AI-AUT-010",
                    title: "Authentication relies on client-side JS, hidden button or route guard alone",
                    severity: Severity::High,
                    category: "2.2 Authentication and account lifecycle",
                    path,
                    target_kind: &target_kind,
                    line_no,
                    snippet: trimmed,
                    safe_threshold: "Client-side state or route guards must never substitute for server-side authorization enforcement.",
                    description: "Authentication check relies on client-side storage or frontend-only route guard.",
                    remediation: "Enforce authorization verification on server-side API endpoints before delivering protected data.",
                }));
            }

            // 11. BK-AI-AUT-011: Untrusted JWT claims used before verification
            if RE_AUT_011_JWT_DECODE.is_match(trimmed) {
                findings.push(Self::create_finding(ScannerFindingSpec {
                    rule_id: "BK-AI-AUT-011",
                    title: "Untrusted JWT claims used before signature/issuer/audience/expiry verification",
                    severity: Severity::High,
                    category: "2.2 Authentication and account lifecycle",
                    path,
                    target_kind: &target_kind,
                    line_no,
                    snippet: trimmed,
                    safe_threshold: "JWT claims must only be consumed after cryptographic signature and claim verification.",
                    description: "jwt.decode() used without verifying signature and claims with jwt.verify().",
                    remediation: "Use jwt.verify(token, secretOrKey) to cryptographically validate signature before reading claims.",
                }));
            }

            // 12. BK-AI-AUT-012: OAuth/OIDC state parameter omitted in auth flow
            let oauth_missing_state = if let Some(m) = RE_AUT_012_OAUTH_URL.find(trimmed) {
                !m.as_str().contains("state=")
            } else {
                RE_AUT_012_OAUTH_CONFIG.is_match(trimmed)
            };

            if oauth_missing_state {
                findings.push(Self::create_finding(ScannerFindingSpec {
                    rule_id: "BK-AI-AUT-012",
                    title: "OAuth/OIDC state, nonce, PKCE or callback/redirect checks omitted where required",
                    severity: Severity::Medium,
                    category: "2.2 Authentication and account lifecycle",
                    path,
                    target_kind: &target_kind,
                    line_no,
                    snippet: trimmed,
                    safe_threshold: "OAuth 2.0 / OIDC authorization requests must include a cryptographically random state parameter.",
                    description: "OAuth authorization URL or configuration omits the CSRF state parameter.",
                    remediation: "Include and validate an unguessable state parameter bound to the user session to prevent OAuth CSRF.",
                }));
            }

            // ---------------------------------------------------------------
            // Category 4: Sessions, Tokens, and Cookies Weaknesses
            // ---------------------------------------------------------------

            // 13. BK-AI-SES-001: Session ID predictable or generated with non-cryptographic randomness
            if RE_SES_001_WEAK_SESSION_ID.is_match(trimmed) {
                findings.push(Self::create_finding(ScannerFindingSpec {
                    rule_id: "BK-AI-SES-001",
                    title: "Session ID predictable or generated with non-cryptographic randomness",
                    severity: Severity::High,
                    category: "2.4 Sessions, tokens, cookies and browser login",
                    path,
                    target_kind: &target_kind,
                    line_no,
                    snippet: trimmed,
                    safe_threshold: "Session identifiers must be generated using cryptographically secure pseudorandomness (CSPRNG).",
                    description: "Session ID generated using non-cryptographic randomness (Math.random, random.randint, Date.now).",
                    remediation: "Generate session identifiers using crypto.randomBytes(32).toString('hex') or secure framework sessions.",
                }));
            }

            // 14. BK-AI-SES-002: Session not rotated after login
            if RE_SES_002_SAVE.is_match(trimmed) {
                let start = idx.saturating_sub(10);
                let end = (idx + 10).min(lines.len());
                let window = lines[start..end].join("\n").to_lowercase();
                let has_user_session_binding = window.contains("session")
                    && (window.contains("userid")
                        || window.contains("user_id")
                        || window.contains("user.")
                        || window.contains("authenticated"));

                if has_user_session_binding && !window.contains("regenerate") {
                    findings.push(Self::create_finding(ScannerFindingSpec {
                    rule_id: "BK-AI-SES-002",
                    title: "Session not rotated after authentication or privilege change",
                    severity: Severity::High,
                    category: "2.4 Sessions, tokens, cookies and browser login",
                    path,
                    target_kind: &target_kind,
                    line_no,
                    snippet: trimmed,
                    safe_threshold: "Session IDs must be regenerated upon authentication or privilege level escalation.",
                    description: "Session state updated on login without calling req.session.regenerate() to prevent fixation attacks.",
                    remediation: "Call req.session.regenerate() before saving authenticated user state into the session store.",
                }));
                }
            }

            // 15. BK-AI-SES-003: Logout fails to invalidate server session
            if RE_SES_003_CLEAR_COOKIE.is_match(trimmed) {
                let start = idx.saturating_sub(10);
                let end = (idx + 10).min(lines.len());
                let window = lines[start..end].join("\n").to_lowercase();
                if (window.contains("logout") || window.contains("signout"))
                    && !window.contains("destroy")
                    && !window.contains("invalidate")
                {
                    findings.push(Self::create_finding(ScannerFindingSpec {
                    rule_id: "BK-AI-SES-003",
                    title: "Logout/password reset fails to invalidate server-side session/refresh token",
                    severity: Severity::High,
                    category: "2.4 Sessions, tokens, cookies and browser login",
                    path,
                    target_kind: &target_kind,
                    line_no,
                    snippet: trimmed,
                    safe_threshold: "Logout must destroy server-side session state in addition to clearing client cookies.",
                    description: "Logout handler clears client cookie but fails to destroy session in server-side session store.",
                    remediation: "Call req.session.destroy() on the server to invalidate the session upon user logout.",
                }));
                }
            }

            // 16. BK-AI-SES-004: Cookie carrying session lacks Secure flag
            if RE_SES_004_COOKIE_INSECURE.is_match(trimmed) {
                findings.push(Self::create_finding(ScannerFindingSpec {
                    rule_id: "BK-AI-SES-004",
                    title: "Cookie carrying session lacks `Secure` where HTTPS is required",
                    severity: Severity::Medium,
                    category: "2.4 Sessions, tokens, cookies and browser login",
                    path,
                    target_kind: &target_kind,
                    line_no,
                    snippet: trimmed,
                    safe_threshold: "Session and authentication cookies must declare secure: true.",
                    description: "Cookie options explicitly set secure: false, risking transmission over cleartext HTTP.",
                    remediation: "Configure secure: true on all session and authentication cookies.",
                }));
            }

            // 17. BK-AI-SES-005: Cookie carrying session lacks HttpOnly flag
            if RE_SES_005_COOKIE_NO_HTTPONLY.is_match(trimmed) {
                findings.push(Self::create_finding(ScannerFindingSpec {
                    rule_id: "BK-AI-SES-005",
                    title: "Cookie carrying session lacks `HttpOnly` without justified JS access",
                    severity: Severity::Medium,
                    category: "2.4 Sessions, tokens, cookies and browser login",
                    path,
                    target_kind: &target_kind,
                    line_no,
                    snippet: trimmed,
                    safe_threshold: "Session and authentication cookies must declare httpOnly: true to prevent script theft.",
                    description: "Cookie options explicitly set httpOnly: false, exposing sensitive session cookie to XSS.",
                    remediation: "Configure httpOnly: true on all session cookies to prevent access via document.cookie.",
                }));
            }

            // 18. BK-AI-SES-006: SameSite defense missing on cookies
            if RE_SES_006_SAMESITE_DEFENSE.is_match(trimmed) {
                findings.push(Self::create_finding(ScannerFindingSpec {
                    rule_id: "BK-AI-SES-006",
                    title: "`SameSite`/CSRF defense missing on relevant browser-driven state changes",
                    severity: Severity::Medium,
                    category: "2.4 Sessions, tokens, cookies and browser login",
                    path,
                    target_kind: &target_kind,
                    line_no,
                    snippet: trimmed,
                    safe_threshold: "Cookies must declare sameSite: 'Strict' or 'Lax' (or sameSite: 'None' strictly with secure: true).",
                    description: "Cookie options set sameSite: 'None' without secure flag or explicitly disables sameSite protection.",
                    remediation: "Configure sameSite: 'Lax' or 'Strict' on authentication cookies to mitigate cross-site request forgery.",
                }));
            }

            // 19. BK-AI-SES-007: Token lifetime too long or unlimited refresh token
            if RE_SES_007_EXCESSIVE_TOKEN_LIFETIME.is_match(trimmed) {
                findings.push(Self::create_finding(ScannerFindingSpec {
                    rule_id: "BK-AI-SES-007",
                    title: "Token lifetime too long or unlimited reusable refresh token",
                    severity: Severity::Medium,
                    category: "2.4 Sessions, tokens, cookies and browser login",
                    path,
                    target_kind: &target_kind,
                    line_no,
                    snippet: trimmed,
                    safe_threshold: "Access tokens must have short, bounded lifetimes (e.g. 15 minutes to 1 hour).",
                    description: "Token lifetime is excessively long (>= 1 year) or configured with unlimited lifetime.",
                    remediation: "Reduce token validity duration (e.g. expiresIn: '15m') and enforce short-lived credentials.",
                }));
            }

            // 20. BK-AI-SES-008: JWT algorithm confusion or none algorithm allowed
            if RE_SES_008_JWT_ALGORITHM.is_match(trimmed) {
                findings.push(Self::create_finding(ScannerFindingSpec {
                    rule_id: "BK-AI-SES-008",
                    title: "JWT algorithm confusion, `none`, or attacker-controlled key locator",
                    severity: Severity::High,
                    category: "2.4 Sessions, tokens, cookies and browser login",
                    path,
                    target_kind: &target_kind,
                    line_no,
                    snippet: trimmed,
                    safe_threshold: "JWT verification must explicitly pin allowed algorithms and reject the 'none' algorithm.",
                    description: "JWT configuration permits 'none' algorithm or combines asymmetric with symmetric algorithms.",
                    remediation: "Explicitly pin permitted algorithms (e.g. algorithms: ['RS256']) and never permit 'none'.",
                }));
            }

            // 21. BK-AI-SES-009: Token logged or embedded in URL/query
            if RE_SES_009_TOKEN_EXPOSURE.is_match(trimmed) {
                findings.push(Self::create_finding(ScannerFindingSpec {
                    rule_id: "BK-AI-SES-009",
                    title: "Token logged, embedded in URL/query, analytics, referrer or browser history",
                    severity: Severity::Medium,
                    category: "2.4 Sessions, tokens, cookies and browser login",
                    path,
                    target_kind: &target_kind,
                    line_no,
                    snippet: trimmed,
                    safe_threshold: "Tokens must not be written to application logs or transmitted in URL query strings.",
                    description: "Authentication token printed to console/logger or transmitted in URL query parameters.",
                    remediation: "Transmit tokens in Authorization HTTP headers and redact tokens from all logging destinations.",
                }));
            }

            // 22. BK-AI-SES-010: LocalStorage/sessionStorage holds sensitive auth tokens
            if RE_SES_010_LOCAL_STORAGE_TOKEN.is_match(trimmed) {
                findings.push(Self::create_finding(ScannerFindingSpec {
                    rule_id: "BK-AI-SES-010",
                    title: "LocalStorage/sessionStorage holds long-lived sensitive credentials without threat review",
                    severity: Severity::High,
                    category: "2.4 Sessions, tokens, cookies and browser login",
                    path,
                    target_kind: &target_kind,
                    line_no,
                    snippet: trimmed,
                    safe_threshold: "Sensitive authentication tokens must not be stored in unencrypted client Web Storage.",
                    description: "Authentication token or session ID saved to localStorage/sessionStorage, vulnerable to XSS exfiltration.",
                    remediation: "Store session identifiers in HttpOnly, Secure, SameSite cookies or short-lived memory state.",
                }));
            }

            // 23. BK-AI-SES-011: Session cookie lacks domain/path scoping
            if RE_SES_011_COOKIE_DOMAIN_PATH_SCOPE.is_match(trimmed) {
                findings.push(Self::create_finding(ScannerFindingSpec {
                    rule_id: "BK-AI-SES-011",
                    title: "Session not scoped by environment, domain, audience or device policy",
                    severity: Severity::Medium,
                    category: "2.4 Sessions, tokens, cookies and browser login",
                    path,
                    target_kind: &target_kind,
                    line_no,
                    snippet: trimmed,
                    safe_threshold: "Session cookies must be narrowly scoped to specific hostnames rather than wildcard subdomains.",
                    description: "Cookie configured with wildcard domain or broad root domain and root path scope.",
                    remediation: "Omit domain attribute for host-only cookies, or explicitly constrain to the target application subdomain.",
                }));
            }

            // 24. BK-AI-SES-012: Refresh token reuse permitted / missing replay detection
            if RE_SES_012_REFRESH_REUSE.is_match(trimmed) {
                findings.push(Self::create_finding(ScannerFindingSpec {
                    rule_id: "BK-AI-SES-012",
                    title: "Concurrent refresh calls permit token reuse/race or stale session resurrection",
                    severity: Severity::High,
                    category: "2.4 Sessions, tokens, cookies and browser login",
                    path,
                    target_kind: &target_kind,
                    line_no,
                    snippet: trimmed,
                    safe_threshold: "Refresh tokens must be single-use with automatic rotation and replay revocation.",
                    description: "Configuration explicitly permits refresh token reuse or disables token rotation.",
                    remediation: "Enforce refresh token rotation (rotateRefreshToken: true) and invalidate token families on reuse.",
                }));
            }
        }

        findings
    }

    /// Helper to construct standardized Finding instances via consolidated [].
    fn create_finding(spec: ScannerFindingSpec<'_>) -> Finding {
        ScannerFindingBuilder::auth_security(spec).build()
    }
}
