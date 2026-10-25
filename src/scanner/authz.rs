#![allow(dead_code, clippy::collapsible_if)]

use crate::types::*;
use regex::Regex;
use std::path::Path;
use std::sync::LazyLock;

// ---------------------------------------------------------------------------
// Static Regex Definitions for Category 3 (Authorization & Privilege)
// ---------------------------------------------------------------------------

// BK-AI-AZ-001 (CWE-639): IDOR/BOLA: object ID accepted from URL without ownership check
static RE_AZ_001_IDOR_FIND: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b[A-Za-z0-9_]+\.(?:findById|findByPk)\s*\(\s*(?:req\.params\.[a-zA-Z0-9_]+|params\.[a-zA-Z0-9_]+)\s*\)"#).unwrap()
});

static RE_AZ_001_PRISMA_MULTILINE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\bfindUnique\s*\(\s*\{[\s\S]*?where:\s*\{[\s\S]*?id:\s*(?:req\.params\.[a-zA-Z0-9_]+|params\.[a-zA-Z0-9_]+)[\s\S]*?\}\s*\}\s*\)"#).unwrap()
});

// BK-AI-AZ-002 (CWE-863): Tenant ID read from body/query/header and trusted without session scope
static RE_AZ_002_TENANT_INPUT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\b(?:const|let|var)\s*(?:\{[^}]*\b(?:tenant_?id|org_?id|organization_?id)\b[^}]*\}|\b(?:tenant_?id|org_?id|organization_?id)\b)\s*=\s*req\.(?:body|query|headers|header|params)\b|\b(?:tenant_?id|org_?id|organization_?id)\s*=\s*request\.(?:json|args|headers)\.get\s*\(\s*['"](?:tenant_?id|org_?id|x-tenant-id|x-org-id)['"]|\breq\.(?:body|query)\.(?:tenant_?id|org_?id|organization_?id)\b|\breq\.headers\s*\[\s*['"](?:x-tenant-id|x-org-id)['"]\s*\]|\breq\.header\s*\(\s*['"](?:x-tenant-id|x-org-id)['"]\s*\))"#).unwrap()
});

// BK-AI-AZ-003 (CWE-915): Mass assignment of server-owned fields
static RE_AZ_003_MASS_ASSIGN_LINE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\b[A-Za-z0-9_]+\.(?:findByIdAndUpdate|updateMany?|updateOne)\s*\([^,]+,\s*(?:req\.body|request\.json)\b|\bObject\.assign\s*\(\s*[a-zA-Z0-9_.]+\s*,\s*(?:req\.body|request\.json)\b|\b[a-zA-Z0-9_.]+\.set\s*\(\s*(?:req\.body|request\.json)\b|\b[a-zA-Z0-9_.]+\.updateAttributes\s*\(\s*(?:req\.body|request\.json)\b|\$set:\s*(?:req\.body|request\.json)\b)"#).unwrap()
});

static RE_AZ_003_PRISMA_MULTILINE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\bprisma\.[a-zA-Z0-9_]+\.update\s*\(\s*\{[\s\S]*?data:\s*(?:req\.body|request\.json)\b[\s\S]*?\}\s*\)"#).unwrap()
});

// BK-AI-AZ-004 (CWE-862): Admin route lacks role/capability enforcement
static RE_AZ_004_ADMIN_ROUTE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(?:app|router)\.(?:get|post|put|delete|patch)\s*\(\s*['"]/(?:api/)?(?:admin|manage|superuser|root)/[^'"]*['"]\s*,\s*([^;]+)"#).unwrap()
});

// BK-AI-AZ-005 (CWE-602): Authorization checked only in UI
static RE_AZ_005_UI_AUTH_LINE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:<\s*(?:AdminRoute|PrivateRoute|AdminOnly|ProtectedLayout)[^>]*\s*(?:render|component)\s*=\s*\{[^}]*(?:user|auth)\.(?:isAdmin|role)|\bonClick\s*=\s*\{\s*(?:\(\)\s*=>\s*)?\{\s*if\s*\(\s*(?:user|auth)\.(?:isAdmin|role\s*===?\s*['"]admin['"])\s*\)|//.*(?:UI|client[- ]side|frontend)[- ]only.*(?:auth|role|permission|check|guard|gate))"#).unwrap()
});

static RE_AZ_005_IF_USER_ADMIN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\bif\s*\(\s*(?:user|currentUser|auth)\.(?:isAdmin|is_admin|role\s*===?\s*['"]admin['"])\s*\)"#).unwrap()
});

// BK-AI-AZ-006 (CWE-863): GraphQL nested resolver bypasses parent object policy
static RE_AZ_006_GQL_RESOLVER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(billingInfo|salary|ssn|creditCards?|bankAccounts?|paymentMethods?|secretNotes?)\s*:\s*(?:async\s*)?\(([^)]*)\)\s*=>"#).unwrap()
});

// BK-AI-AZ-007 (CWE-863): Batch APIs authorize first object but not each element
static RE_AZ_007_BATCH_FIRST: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:checkPermission|authorize|canAccess|isOwner|hasAccess|checkRole|validateOwnership|assertOwner)\s*\([^)]*(?:items|ids|batch|records|docs|req\.body\.[a-zA-Z0-9_]+)\[0\]"#).unwrap()
});

static RE_AZ_007_BATCH_PROP: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:items|ids|batch|records|docs|req\.body\.[a-zA-Z0-9_]+)\[0\]\.[a-zA-Z0-9_]*\s*===?\s*(?:req\.user|user|session)\.[a-zA-Z0-9_]+"#).unwrap()
});

// BK-AI-AZ-008 (CWE-863): Background job/queue trusts caller-provided role instead of rechecking
static RE_AZ_008_WORKER_ROLE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:if\s*\(\s*(?:job\.data|payload|msg|task|message)\.(?:role\s*===?\s*['"][^'"]+['"]|isAdmin|is_admin|permissions\.[a-zA-Z0-9_]+)|\bconst\s*\{[^}]*\b(?:role|isAdmin|permissions)\b[^}]*\}\s*=\s*(?:job\.data|payload|msg|task|message)\b)"#).unwrap()
});

// BK-AI-AZ-009 (CWE-862): Webhook/event handler assumes event payload identity implies permission without verification
static RE_AZ_009_WEBHOOK_ROUTE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(?:app|router)\.post\s*\(\s*['"]/(?:api/)?(?:webhooks?|stripe-webhook|github-webhook|external-events?)[^'"]*['"]"#).unwrap()
});

// BK-AI-AZ-010 (CWE-200): Export/report/download endpoint omits tenancy filtering
static RE_AZ_010_EXPORT_ROUTE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(?:app|router)\.get\s*\(\s*['"]/(?:api/)?(?:export|reports?|download|dump|backup)/[^'"]*['"]"#).unwrap()
});

// BK-AI-AZ-011 (CWE-250): Admin service token reused for normal user request path
static RE_AZ_011_ADMIN_TOKEN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\bprocess\.env\.(?:SUPABASE_SERVICE_ROLE_KEY|SERVICE_ROLE_KEY|MASTER_API_KEY|FIREBASE_ADMIN_CREDENTIALS)\b"#).unwrap()
});

// BK-AI-AZ-012 (CWE-276): Default role includes privileged permissions
static RE_AZ_012_PRIVILEGED_DEFAULT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\bdefault_?role\s*[:=]\s*['"](?:admin|superuser|root|manager)['"]|\brole:\s*\{\s*type:\s*String,\s*default:\s*['"](?:admin|superuser|root)['"]|\bdefault_permissions\s*[:=]\s*\[[^\]]*['"]\*['"][^\]]*\]|\bpermissions:\s*\[\s*['"]\*['"]\s*\]|\bconst\s+DEFAULT_ROLE\s*=\s*['"](?:admin|superuser|root)['"])"#).unwrap()
});

// BK-AI-AZ-013 (CWE-367): Check-then-act privilege check races with ownership/role changes
static RE_AZ_013_TOCTOU: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:await\s+(?:checkPermission|checkOwnership|canAccess|hasPermission|isOwner)\s*\([^)]*\);.*?(?:await\s+(?:delay|sleep|wait|setTimeout|fetch)\s*\([^)]*\)|new\s+Promise).*?await\s+(?:delete|update|remove|modify|save))"#).unwrap()
});

// BK-AI-AZ-014 (CWE-200): Search, cache, or vector index query leaks cross-tenant objects
static RE_AZ_014_PINECONE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(?:index|pineconeIndex|vectorIndex)\.query\s*\(\s*\{([^}]+)\}\s*\)"#)
        .unwrap()
});

static RE_AZ_014_CHROMA: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)\bcollection\.query\s*\(\s*\{([^}]+)\}\s*\)"#).unwrap());

static RE_AZ_014_SIMILARITY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\bvectorStore\.similaritySearch\s*\(\s*[^,)]+\s*,\s*\d+\s*\)"#).unwrap()
});

// ---------------------------------------------------------------------------
// Scanner Implementation
// ---------------------------------------------------------------------------

pub struct AuthzSecurityScanner;

impl AuthzSecurityScanner {
    /// Comprehensive static analysis for Category 3 (Authorization, Tenant Isolation and Privilege)
    pub fn scan_source(path: &Path, content: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let target_kind = match path.extension().and_then(|ext| ext.to_str()) {
            Some("js" | "mjs" | "cjs" | "ts" | "tsx" | "jsx") => TargetKind::NodeSourceFile,
            _ => TargetKind::GenericSourceFile,
        };

        let lines: Vec<&str> = content.lines().collect();

        // 1. Line-by-line and context-aware checks
        for (idx, line) in lines.iter().enumerate() {
            let line_no = idx + 1;
            let trimmed = line.trim();

            if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('*') {
                continue;
            }

            // Check comment for UI-only auth indicators before skipping comments
            let is_comment = trimmed.starts_with("//") || trimmed.starts_with("/*");
            if is_comment {
                if let Some(mat) = RE_AZ_005_UI_AUTH_LINE.find(trimmed) {
                    findings.push(create_authz_finding(
                        "BK-AI-AZ-005",
                        "CWE-602",
                        "Client-Side Only Authorization Enforcement",
                        Severity::High,
                        target_kind.clone(),
                        path,
                        line_no,
                        mat.as_str(),
                        "Enforce authorization checks on every sensitive server-side API handler",
                        &format!(
                            "Privilege checks performed solely on client-side interface at line {}: '{}'. Attackers can invoke underlying endpoints directly.",
                            line_no,
                            mat.as_str()
                        ),
                        "Move authorization verification to the backend service. Never rely on client-side UI visibility or gating alone.",
                    ));
                }
                continue;
            }

            // A. BK-AI-AZ-001 (CWE-639): IDOR/BOLA: object ID accepted from URL without ownership check
            if let Some(mat) = RE_AZ_001_IDOR_FIND.find(trimmed) {
                let start = idx.saturating_sub(2);
                let end = (idx + 6).min(lines.len());
                let has_ownership_check = lines[start..end].iter().any(|l| {
                    let l_trimmed = l.trim();
                    l_trimmed.contains("req.user.id")
                        && (l_trimmed.contains("owner")
                            || l_trimmed.contains("user")
                            || l_trimmed.contains("checkOwnership")
                            || l_trimmed.contains("authorize"))
                        || l_trimmed.contains("checkOwnership")
                        || l_trimmed.contains("can(")
                        || l_trimmed.contains("assertOwner")
                });

                if !has_ownership_check {
                    findings.push(create_authz_finding(
                        "BK-AI-AZ-001",
                        "CWE-639",
                        "IDOR/BOLA: Object ID Accepted Without Ownership Check",
                        Severity::High,
                        target_kind.clone(),
                        path,
                        line_no,
                        mat.as_str(),
                        "Scope object lookups to authenticated user identity or tenant context (e.g. Document.findOne({ _id: req.params.id, userId: req.user.id }))",
                        &format!(
                            "Object lookup using direct URL parameter '{}' at line {} lacks per-object ownership validation, allowing Broken Object Level Authorization (IDOR).",
                            mat.as_str(),
                            line_no
                        ),
                        "Verify that the authenticated caller owns or has explicit permission to access the requested resource before returning or modifying it.",
                    ));
                }
            }

            // B. BK-AI-AZ-002 (CWE-863): Tenant ID read from body/query/header and trusted without session scope
            if let Some(mat) = RE_AZ_002_TENANT_INPUT.find(trimmed) {
                findings.push(create_authz_finding(
                    "BK-AI-AZ-002",
                    "CWE-863",
                    "Untrusted Tenant ID Accepted from Request Scope",
                    Severity::High,
                    target_kind.clone(),
                    path,
                    line_no,
                    mat.as_str(),
                    "Bind tenant context to cryptographically verified session token (e.g. req.user.tenantId)",
                    &format!(
                        "Tenant identifier extracted from untrusted client request input at line {}: '{}'. Attackers can manipulate this value to bypass tenant isolation.",
                        line_no,
                        mat.as_str()
                    ),
                    "Derive tenant scope strictly from the validated session/JWT identity rather than trusting request parameters.",
                ));
            }

            // C. BK-AI-AZ-003 (CWE-915): Mass assignment of server-owned fields
            if let Some(mat) = RE_AZ_003_MASS_ASSIGN_LINE.find(trimmed) {
                findings.push(create_authz_finding(
                    "BK-AI-AZ-003",
                    "CWE-915",
                    "Mass Assignment of Server-Owned Privilege Fields",
                    Severity::High,
                    target_kind.clone(),
                    path,
                    line_no,
                    mat.as_str(),
                    "Use explicit field destructuring or schema allowlists (DTOs) for database mutations",
                    &format!(
                        "Direct assignment of unfiltered request payload at line {}: '{}'. Attackers can tamper with server-managed fields such as role, isAdmin, or permissions.",
                        line_no,
                        mat.as_str()
                    ),
                    "Explicitly pick allowed writable fields or enforce a strict validation DTO before updating database records.",
                ));
            }

            // D. BK-AI-AZ-004 (CWE-862): Admin route lacks role/capability enforcement
            if let Some(caps) = RE_AZ_004_ADMIN_ROUTE.captures(trimmed) {
                let handler_args = caps.get(1).map(|m| m.as_str()).unwrap_or("");
                let has_role_guard = handler_args.contains("checkRole")
                    || handler_args.contains("requireAdmin")
                    || handler_args.contains("hasRole")
                    || handler_args.contains("adminOnly")
                    || handler_args.contains("ensureAdmin")
                    || handler_args.contains("@Roles")
                    || handler_args.contains("Role::Admin")
                    || handler_args.contains("isAdmin")
                    || handler_args.contains("authorizeAdmin")
                    || handler_args.contains("authorize('admin')");

                if !has_role_guard {
                    findings.push(create_authz_finding(
                        "BK-AI-AZ-004",
                        "CWE-862",
                        "Missing Role/Capability Enforcement on Admin Route",
                        Severity::High,
                        target_kind.clone(),
                        path,
                        line_no,
                        trimmed,
                        "Attach explicit role authorization middleware (e.g. checkRole('admin')) to privileged endpoints",
                        &format!(
                            "Administrative endpoint declared at line {} without role/capability enforcement middleware.",
                            line_no
                        ),
                        "Require an authenticated session with verified administrator role before allowing access to administrative routes.",
                    ));
                }
            }

            // E. BK-AI-AZ-005 (CWE-602): Authorization checked only in UI
            if let Some(mat) = RE_AZ_005_UI_AUTH_LINE.find(trimmed) {
                findings.push(create_authz_finding(
                    "BK-AI-AZ-005",
                    "CWE-602",
                    "Client-Side Only Authorization Enforcement",
                    Severity::High,
                    target_kind.clone(),
                    path,
                    line_no,
                    mat.as_str(),
                    "Enforce authorization checks on every sensitive server-side API handler",
                    &format!(
                        "Privilege checks performed solely on client-side interface at line {}: '{}'. Attackers can invoke underlying endpoints directly.",
                        line_no,
                        mat.as_str()
                    ),
                    "Move authorization verification to the backend service. Never rely on client-side UI visibility or gating alone.",
                ));
            } else if RE_AZ_005_IF_USER_ADMIN.is_match(trimmed) && !trimmed.contains("req.") {
                let end = (idx + 5).min(lines.len());
                let has_api_call = lines[idx..end].iter().any(|l| {
                    let l_trimmed = l.trim();
                    l_trimmed.contains("fetch(")
                        || l_trimmed.contains("axios.")
                        || l_trimmed.contains("api.")
                        || l_trimmed.contains("dispatch(")
                });

                if has_api_call {
                    findings.push(create_authz_finding(
                        "BK-AI-AZ-005",
                        "CWE-602",
                        "Client-Side Only Authorization Enforcement",
                        Severity::High,
                        target_kind.clone(),
                        path,
                        line_no,
                        trimmed,
                        "Enforce authorization checks on every sensitive server-side API handler",
                        &format!(
                            "Privilege checks performed solely on client-side interface at line {}: '{}'. Attackers can invoke underlying endpoints directly.",
                            line_no,
                            trimmed
                        ),
                        "Move authorization verification to the backend service. Never rely on client-side UI visibility or gating alone.",
                    ));
                }
            }

            // F. BK-AI-AZ-006 (CWE-863): GraphQL nested resolver bypasses parent object policy
            if let Some(caps) = RE_AZ_006_GQL_RESOLVER.captures(trimmed) {
                let field_name = caps.get(1).map(|m| m.as_str()).unwrap_or("");
                let params = caps.get(2).map(|m| m.as_str()).unwrap_or("");

                let has_context_auth = params.contains("user")
                    || params.contains("auth")
                    || params.contains("currentUser");

                let end = (idx + 8).min(lines.len());
                let body_has_auth = lines[idx..end].iter().any(|l| {
                    let l_trimmed = l.trim();
                    l_trimmed.contains("context.user")
                        || l_trimmed.contains("context.auth")
                        || l_trimmed.contains("ForbiddenError")
                        || l_trimmed.contains("checkPermission")
                        || l_trimmed.contains("@auth")
                });

                if !has_context_auth && !body_has_auth {
                    findings.push(create_authz_finding(
                        "BK-AI-AZ-006",
                        "CWE-863",
                        "GraphQL Nested Resolver Bypasses Parent Authorization",
                        Severity::High,
                        target_kind.clone(),
                        path,
                        line_no,
                        trimmed,
                        "Validate caller authorization against context.user in nested GraphQL field resolvers",
                        &format!(
                            "GraphQL nested resolver for sensitive field '{}' at line {} fetches child data from parent identifier without validating caller permissions.",
                            field_name,
                            line_no
                        ),
                        "Verify caller permissions in nested field resolvers or apply field-level authorization directives.",
                    ));
                }
            }

            // G. BK-AI-AZ-007 (CWE-863): Batch APIs authorize first object but not each element
            let matches_first =
                RE_AZ_007_BATCH_FIRST.is_match(trimmed) || RE_AZ_007_BATCH_PROP.is_match(trimmed);
            if matches_first {
                findings.push(create_authz_finding(
                    "BK-AI-AZ-007",
                    "CWE-863",
                    "Batch API Partial Element Authorization Bypass",
                    Severity::High,
                    target_kind.clone(),
                    path,
                    line_no,
                    trimmed,
                    "Verify ownership and authorization for every element in batch requests",
                    &format!(
                        "Batch API authorization at line {} checks only the first item (index [0]), leaving remaining batch items unauthorized.",
                        line_no
                    ),
                    "Iterate through all batch elements to verify authorization individually, or enforce scoped database query predicates.",
                ));
            }

            // H. BK-AI-AZ-008 (CWE-863): Background job/queue trusts caller-provided role
            if let Some(mat) = RE_AZ_008_WORKER_ROLE.find(trimmed) {
                let start = idx.saturating_sub(5);
                let end = (idx + 5).min(lines.len());
                let has_db_user_fetch = lines[start..end].iter().any(|l| {
                    let l_trimmed = l.trim();
                    l_trimmed.contains("findById")
                        || l_trimmed.contains("findOne")
                        || l_trimmed.contains("getUser")
                        || l_trimmed.contains("fetchUser")
                });

                if !has_db_user_fetch {
                    findings.push(create_authz_finding(
                        "BK-AI-AZ-008",
                        "CWE-863",
                        "Background Worker Trusting Caller-Supplied Role",
                        Severity::High,
                        target_kind.clone(),
                        path,
                        line_no,
                        mat.as_str(),
                        "Re-query authoritative user role and permissions from database during job execution",
                        &format!(
                            "Background worker at line {} trusts role/permissions supplied in message payload: '{}'.",
                            line_no,
                            mat.as_str()
                        ),
                        "Re-validate user permissions against the authoritative database inside the worker handler rather than trusting serialized payload roles.",
                    ));
                }
            }

            // I. BK-AI-AZ-009 (CWE-862): Webhook handler assumes event payload identity implies permission
            if RE_AZ_009_WEBHOOK_ROUTE.is_match(trimmed) {
                let end = (idx + 20).min(lines.len());
                let block = lines[idx..end].join("\n");

                let has_state_mutation = block.contains(".update(")
                    || block.contains(".delete(")
                    || block.contains(".save(")
                    || block.contains("updatePlan")
                    || block.contains("activatePremium")
                    || block.contains("updateSubscription")
                    || block.contains("creditAccount");

                let has_signature_check = block.contains("constructEvent")
                    || block.contains("stripe-signature")
                    || block.contains("x-hub-signature")
                    || block.contains("verifySignature")
                    || block.contains("createHmac")
                    || block.contains("timingSafeEqual")
                    || block.contains("validateWebhook");

                if has_state_mutation && !has_signature_check {
                    findings.push(create_authz_finding(
                        "BK-AI-AZ-009",
                        "CWE-862",
                        "Unverified Webhook Event Identity Trust",
                        Severity::High,
                        target_kind.clone(),
                        path,
                        line_no,
                        trimmed,
                        "Verify cryptographic webhook signatures before processing state modifications",
                        &format!(
                            "Webhook endpoint declared at line {} mutates state based on payload identity without cryptographic signature verification.",
                            line_no
                        ),
                        "Validate the webhook HMAC signature (e.g. stripe.webhooks.constructEvent) against the raw request body before executing actions.",
                    ));
                }
            }

            // J. BK-AI-AZ-010 (CWE-200): Export endpoint omits tenancy filtering
            if RE_AZ_010_EXPORT_ROUTE.is_match(trimmed) {
                let end = (idx + 25).min(lines.len());
                let block = lines[idx..end].join("\n");

                let has_unfiltered_sql = block.contains("SELECT * FROM")
                    && !block.contains("WHERE org_id")
                    && !block.contains("WHERE tenant_id")
                    && !block.contains("WHERE user_id")
                    && !block.contains("WHERE account_id")
                    && !block.contains("WHERE company_id");

                let has_unfiltered_orm = (block.contains(".find()")
                    || block.contains(".findAll()"))
                    && !block.contains("tenantId")
                    && !block.contains("orgId")
                    && !block.contains("userId");

                if has_unfiltered_sql || has_unfiltered_orm {
                    findings.push(create_authz_finding(
                        "BK-AI-AZ-010",
                        "CWE-200",
                        "Export Endpoint Missing Tenancy Isolation Filter",
                        Severity::High,
                        target_kind.clone(),
                        path,
                        line_no,
                        trimmed,
                        "Bind all data export queries to authenticated tenant/user scope in WHERE clauses",
                        &format!(
                            "Export/download endpoint at line {} executes unbounded bulk queries without tenant/organization filtering, risking cross-tenant data leaks.",
                            line_no
                        ),
                        "Enforce strict tenant isolation filters in all reporting and export database queries.",
                    ));
                }
            }

            // K. BK-AI-AZ-011 (CWE-250): Admin service token reused for normal user request path
            if let Some(mat) = RE_AZ_011_ADMIN_TOKEN.find(trimmed) {
                let start = idx.saturating_sub(6);
                let end = (idx + 6).min(lines.len());
                let is_request_handler = lines[start..end].iter().any(|l| {
                    let l_trimmed = l.trim();
                    l_trimmed.contains("(req, res)")
                        || l_trimmed.contains("req: Request")
                        || l_trimmed.contains("app.get")
                        || l_trimmed.contains("app.post")
                        || l_trimmed.contains("router.")
                });

                if is_request_handler {
                    findings.push(create_authz_finding(
                        "BK-AI-AZ-011",
                        "CWE-250",
                        "Admin Service Token Reused on User Request Path",
                        Severity::High,
                        target_kind.clone(),
                        path,
                        line_no,
                        mat.as_str(),
                        "Use user-scoped credentials with Row Level Security (RLS) on client-facing request paths",
                        &format!(
                            "Superuser/service-role credentials used in user request handler at line {}: '{}'. This bypasses RLS and isolation boundaries.",
                            line_no,
                            mat.as_str()
                        ),
                        "Initialize client connections using user session tokens or anon keys enforcing Row Level Security rather than admin service tokens.",
                    ));
                }
            }

            // L. BK-AI-AZ-012 (CWE-276): Default role includes privileged permissions
            if let Some(mat) = RE_AZ_012_PRIVILEGED_DEFAULT.find(trimmed) {
                findings.push(create_authz_finding(
                    "BK-AI-AZ-012",
                    "CWE-276",
                    "Default Role Assigned Privileged Permissions",
                    Severity::High,
                    target_kind.clone(),
                    path,
                    line_no,
                    mat.as_str(),
                    "Apply principle of least privilege with unprivileged default roles (e.g. viewer or member)",
                    &format!(
                        "Default role or permission set includes administrative or wildcard privileges at line {}: '{}'.",
                        line_no,
                        mat.as_str()
                    ),
                    "Assign least-privileged roles by default upon registration and disallow wildcard permissions.",
                ));
            }

            // M. BK-AI-AZ-013 (CWE-367): Check-then-act privilege check races with ownership/role changes
            let is_auth_check = trimmed.contains("checkPermission")
                || trimmed.contains("checkOwnership")
                || trimmed.contains("canAccess")
                || trimmed.contains("hasPermission")
                || trimmed.contains("isOwner");

            if is_auth_check {
                let end = (idx + 10).min(lines.len());
                let block = lines[idx..end].join("\n");
                let has_delay = block.contains("sleep(")
                    || block.contains("delay(")
                    || block.contains("wait(")
                    || block.contains("setTimeout");
                let has_mutation = block.contains("deleteFile(")
                    || block.contains("deleteRecord(")
                    || block.contains(".delete(")
                    || block.contains(".update(")
                    || block.contains(".destroy(");

                if has_delay && has_mutation {
                    findings.push(create_authz_finding(
                        "BK-AI-AZ-013",
                        "CWE-367",
                        "Check-Then-Act Race Condition (TOCTOU) in Authorization",
                        Severity::Medium,
                        target_kind.clone(),
                        path,
                        line_no,
                        trimmed,
                        "Perform atomic conditional updates or use database row locks (e.g. SELECT FOR UPDATE)",
                        &format!(
                            "Authorization check at line {} is separated from state mutation by an asynchronous gap, creating a Time-of-Check to Time-of-Use (TOCTOU) race condition.",
                            line_no
                        ),
                        "Execute permission checks and mutations atomically within a database transaction or atomic conditional query.",
                    ));
                }
            }
        }

        // 2. Multiline structural searches
        // A. BK-AI-AZ-001: Prisma findUnique multiline check
        for mat in RE_AZ_001_PRISMA_MULTILINE.find_iter(content) {
            let offset = mat.start();
            let line_no = line_number_at_offset(content, offset);
            findings.push(create_authz_finding(
                "BK-AI-AZ-001",
                "CWE-639",
                "IDOR/BOLA: Object ID Accepted Without Ownership Check",
                Severity::High,
                target_kind.clone(),
                path,
                line_no,
                mat.as_str(),
                "Scope object lookups to authenticated user identity or tenant context (e.g. Document.findOne({ _id: req.params.id, userId: req.user.id }))",
                &format!(
                    "Prisma findUnique query at line {} takes route parameter directly without per-object ownership check.",
                    line_no
                ),
                "Verify that the authenticated caller owns or has explicit permission to access the requested resource.",
            ));
        }

        // C. BK-AI-AZ-003: Prisma update multiline check
        for mat in RE_AZ_003_PRISMA_MULTILINE.find_iter(content) {
            let offset = mat.start();
            let line_no = line_number_at_offset(content, offset);
            findings.push(create_authz_finding(
                "BK-AI-AZ-003",
                "CWE-915",
                "Mass Assignment of Server-Owned Privilege Fields",
                Severity::High,
                target_kind.clone(),
                path,
                line_no,
                mat.as_str(),
                "Use explicit field destructuring or schema allowlists (DTOs) for database mutations",
                &format!(
                    "Prisma update mutation at line {} accepts raw request body into data parameter without field filtering.",
                    line_no
                ),
                "Explicitly pick allowed writable fields or enforce a strict validation DTO before updating database records.",
            ));
        }

        // N. BK-AI-AZ-014 (CWE-200): Vector search or index query leaks cross-tenant objects
        for cap in RE_AZ_014_PINECONE.captures_iter(content) {
            if let Some(inner) = cap.get(1) {
                let inner_text = inner.as_str();
                let has_filter = inner_text.contains("filter") || inner_text.contains("namespace");
                if !has_filter {
                    let offset = cap.get(0).unwrap().start();
                    let line_no = line_number_at_offset(content, offset);
                    findings.push(create_authz_finding(
                        "BK-AI-AZ-014",
                        "CWE-200",
                        "Cross-Tenant Information Leak in Vector Search or Cache",
                        Severity::High,
                        target_kind.clone(),
                        path,
                        line_no,
                        cap.get(0).unwrap().as_str(),
                        "Include tenant isolation filter (e.g. filter: { tenantId: user.tenantId }) or namespace in vector queries",
                        &format!(
                            "Vector index query at line {} omits tenant filter or namespace isolation, allowing cross-tenant vector leakage.",
                            line_no
                        ),
                        "Always restrict vector search queries to the current tenant namespace or filter by tenant metadata.",
                    ));
                }
            }
        }

        for cap in RE_AZ_014_CHROMA.captures_iter(content) {
            if let Some(inner) = cap.get(1) {
                let inner_text = inner.as_str();
                let has_where = inner_text.contains("where");
                if !has_where {
                    let offset = cap.get(0).unwrap().start();
                    let line_no = line_number_at_offset(content, offset);
                    findings.push(create_authz_finding(
                        "BK-AI-AZ-014",
                        "CWE-200",
                        "Cross-Tenant Information Leak in Vector Search or Cache",
                        Severity::High,
                        target_kind.clone(),
                        path,
                        line_no,
                        cap.get(0).unwrap().as_str(),
                        "Include tenant where clause in collection similarity queries",
                        &format!(
                            "Chroma collection query at line {} lacks tenant where clause filter, exposing cross-tenant embeddings.",
                            line_no
                        ),
                        "Pass tenant metadata criteria in collection query where parameters.",
                    ));
                }
            }
        }

        for mat in RE_AZ_014_SIMILARITY.find_iter(content) {
            let offset = mat.start();
            let line_no = line_number_at_offset(content, offset);
            findings.push(create_authz_finding(
                "BK-AI-AZ-014",
                "CWE-200",
                "Cross-Tenant Information Leak in Vector Search or Cache",
                Severity::High,
                target_kind.clone(),
                path,
                line_no,
                mat.as_str(),
                "Pass metadata filter options to similarity search queries to scope embeddings to active tenant",
                &format!(
                    "Vector store similarity search at line {} executed without tenant metadata filter.",
                    line_no
                ),
                "Supply tenant metadata filter in vectorStore.similaritySearch options.",
            ));
        }

        // Deduplicate findings by fingerprint
        let mut seen = std::collections::HashSet::new();
        findings.retain(|f| seen.insert(f.dedupe_fingerprint.clone()));

        findings
    }
}

// ---------------------------------------------------------------------------
// Helper Functions
// ---------------------------------------------------------------------------

fn line_number_at_offset(content: &str, offset: usize) -> usize {
    content[..offset].chars().filter(|&c| c == '\n').count() + 1
}

#[allow(clippy::too_many_arguments)]
fn create_authz_finding(
    rule_id: &str,
    cwe: &str,
    title: &str,
    severity: Severity,
    target_kind: TargetKind,
    path: &Path,
    line_number: usize,
    detected_pattern: &str,
    safe_threshold: &str,
    description: &str,
    remediation: &str,
) -> Finding {
    let file_tag = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("source");
    let finding_id = format!("{}-{}-L{}", rule_id, file_tag, line_number);

    let mut finding = Finding::new(
        finding_id,
        CveId::Custom {
            id: rule_id.to_string(),
            title: title.to_string(),
        },
        severity,
        target_kind,
        Some(path.to_path_buf()),
        Some(line_number),
        detected_pattern,
        safe_threshold,
        description,
        remediation,
    );
    finding.detector_id = "authz-security".to_string();
    finding.detector_version = "1.0.0".to_string();
    finding.category = "2.3 Authorization, tenant isolation and privilege".to_string();
    finding.affectedness = Affectedness::ConfirmedAffected;
    finding.reachability = Reachability::PotentiallyReachable;
    finding.confidence = Confidence::High;
    finding.evidence_certainty = EvidenceCertainty::StronglySupported;
    finding.advisory_ids = vec![cwe.to_string(), rule_id.to_string()];
    finding.evidence_refs.push(EvidenceRef {
        location: format!("{}:{}", path.display(), line_number),
        line_number: Some(line_number),
        snippet: Some(detected_pattern.to_string()),
        sha256: None,
    });
    finding.compute_dedupe_fingerprint();
    finding
}
