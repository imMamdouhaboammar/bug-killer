#![allow(dead_code, clippy::collapsible_if)]

use crate::types::*;
use regex::Regex;
use std::collections::HashSet;
use std::path::Path;
use std::sync::LazyLock;

// ---------------------------------------------------------------------------
// Category 10: Secrets, Privacy, PII and Data Exposure
// ---------------------------------------------------------------------------

/// BK-AI-SEC-005 (CWE-532): Environment variables or verbatim stack traces dumped
static RE_SEC_005_DUMP_ENV: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:console\.(?:log|dir|info|warn|error|trace)|logger\.(?:info|debug|warn|error|trace|log)|print|logging\.(?:info|debug|warning|error)|dump|var_dump|print_r)\s*\([^)]*?(?:process\.env|os\.environ|os\.environ\.copy\s*\(\s*\)|\$_ENV|\$_SERVER)\b|\bdump\s*\(\s*env\s*\)"#).unwrap()
});

static RE_SEC_005_DUMP_STACK: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:res|response)\.(?:send|json|write)\s*\(\s*(?:err|error)\.stack\s*\)"#).unwrap()
});

/// BK-AI-SEC-006 (CWE-200): Sensitive PII in metrics tags, trace spans or analytics
static RE_SEC_006_PII_TAG: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:tags?|tagMap|span|tracer|metrics|datadog|statsd|newrelic)\.(?:put|setTag|setAttribute|setTags|tag|gauge|increment|histogram)\s*\(\s*['"](?:[^'"]*\.)?(?:ssn|social_security|password|pwd|credit_card|card_number|cvv|cvc|dob|date_of_birth|passport)['"]"#).unwrap()
});

static RE_SEC_006_ANALYTICS_PII: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)analytics\.(?:track|identify)\s*\(\s*(?:['"][^'"]*['"]\s*,\s*)?\{[^}]*\b(?:ssn|social_security|password|pwd|credit_card|card_number|cvv|cvc|passport)\s*:"#).unwrap()
});

static RE_SEC_006_DATADOG_TAG_ARRAY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)datadog\.(?:gauge|increment)\s*\([^)]*tags\s*=\s*\[[^\]]*['"](?:ssn|password|credit_card):"#).unwrap()
});

/// BK-AI-SEC-007 (CWE-359): Unnecessary collection/storage of sensitive user data (CVV, plaintext password)
static RE_SEC_007_CVV_STORAGE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\b(?:cvv|cvc|card_cvv|card_cvc|security_code)\s*:\s*\{\s*type\s*:|@Column\s*\([^)]*\)\s*(?:public\s+|private\s+)?(?:cvv|cvc|cardCvv|cardCvc)\s*:|table\.(?:string|integer)\s*\(\s*['"](?:cvv|cvc|card_cvv)['"]\s*\)|db\.[a-zA-Z0-9_]+\.(?:insert|save|update)\s*\(\s*\{[^}]*\b(?:cvv|cvc)\s*:|INSERT\s+INTO\s+[a-zA-Z0-9_]+\s*\([^)]*\b(?:cvv|cvc)\b[^)]*\)|\b(?:raw_password|plaintext_password|plain_password)\s*:\s*\{\s*type\s*:|@Column\s*\([^)]*\)\s*(?:public\s+|private\s+)?(?:rawPassword|plaintextPassword)\s*:|\b(?:storeCard|saveCard|savePayment|storePayment)\s*\([^)]*\b(?:cvv|cvc)\b)"#).unwrap()
});

/// BK-AI-SEC-008 (CWE-639): Data export/deletion workflows omit authorized ownership verification
static RE_SEC_008_EXPORT_DELETE_ROUTE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:app|router)\.(?:get|post|delete)\s*\(\s*['"]/(?:api/)?(?:export-user-data|export-data|user-data-export|delete-user-data|gdpr-export|gdpr-delete|download-personal-data|purge-user|delete-account)(?:/[^'"]*)?['"]"#).unwrap()
});

/// BK-AI-SEC-009 (CWE-311): Missing encryption-at-rest for sensitive columns/datasets
static RE_SEC_009_ENCRYPTED_FALSE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:ssn|credit_card|card_number|tax_id|bank_account|medical_record)[^;,\n]*encrypted\s*:\s*false|encrypted\s*:\s*false[^;,\n]*(?:ssn|credit_card|card_number|tax_id|bank_account|medical_record)"#).unwrap()
});

static RE_SEC_009_STORAGE_UNENCRYPTED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:ServerSideEncryption|server_side_encryption|encrypted)\s*:\s*(?:false|False|'none'|"none"|None)\b|\bserver_side_encryption_configuration\s*:\s*(?:false|None)\b"#).unwrap()
});

static RE_SEC_009_PLAIN_SENSITIVE_COLUMN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:@Column\s*\(\s*\{[^}]*\}\s*\)\s*(?:public\s+|private\s+)?(?:ssn|creditCard|bankAccount|taxId)\s*:\s*string;|table\.(?:string|text)\s*\(\s*['"](?:credit_card|ssn|bank_account_number|tax_id)['"]\s*\)\s*;)"#).unwrap()
});

/// BK-AI-SEC-011 (CWE-201): Third-party analytics or AI provider receives confidential data without redaction
static RE_SEC_011_AI_CONFIDENTIAL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:openai|anthropic|cohere|bedrock|mistral)\.(?:chat\.completions|messages|completions)\.create\s*\(\s*\{[\s\S]*?(?:req\.body\.(?:creditCard|ssn|password|secret)|user\.(?:ssn|credit_card|password)|credit_card|card_number|cvv)"#).unwrap()
});

static RE_SEC_011_ANALYTICS_CONFIDENTIAL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:mixpanel|segment|posthog|amplitude)\.(?:track|identify|capture)\s*\(\s*[^)]*\b(?:ssn|credit_card|card_number|raw_password|user_password)\b"#).unwrap()
});

/// BK-AI-SEC-012 (CWE-532): Reports and tool replies contain raw secrets/keys
static RE_SEC_012_TOOL_REPLY_SECRET: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:return|resolve)\s*\{[^}]*\b(?:apiKey|api_key|secretKey|secret_key|privateKey|private_key|dbPassword|auth_token)\s*:\s*(?:process\.env\.[A-Z0-9_]+|config\.[a-zA-Z0-9_]+|credentials\.[a-zA-Z0-9_]+|db_password|password)"#).unwrap()
});

static RE_SEC_012_TOOL_RESULT_STRING: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)tool_?result\s*=\s*(?:f['"][^'"]*|['"][^'"]*)\b(?:password|api_key|secret_key|auth_token)\s*[:=]\s*\{?[a-zA-Z0-9_.]+"#).unwrap()
});

// ---------------------------------------------------------------------------
// Category 11: Database & Storage Security
// ---------------------------------------------------------------------------

/// BK-AI-DAT-001 (CWE-250): Database connection uses superuser/owner credentials
static RE_DAT_001_SUPERUSER_CONN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:postgres|postgresql|mysql|mariadb|mongodb)://(?:postgres|root|sa):[^@]+@"#).unwrap()
});

static RE_DAT_001_SUPERUSER_CONFIG: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(?:user|username)\s*:\s*['"](?:postgres|root|sa)['"]|\buser=(?:postgres|root|sa)\b|\bPGUSER\s*=\s*['"]?(?:postgres|root)['"]?"#).unwrap()
});

/// BK-AI-DAT-002 (CWE-863): Row-level security bypassed by service role / admin override
static RE_DAT_002_SERVICE_ROLE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)createClient\s*\(\s*(?:process\.env\.[A-Z0-9_]+|['"][^'"]+['"]|[a-zA-Z0-9_]+)\s*,\s*process\.env\.(?:SUPABASE_SERVICE_ROLE_KEY|SERVICE_ROLE_KEY)\s*\)|createClient\s*\(\s*(?:SUPABASE_URL|url)\s*,\s*(?:SERVICE_ROLE_KEY|supabaseServiceRoleKey)\s*\)"#).unwrap()
});

static RE_DAT_002_BYPASS_FLAG: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(?:bypass_rls|bypassRls|auth\.is_admin)\s*[:=]\s*(?:true|True|1)\b|\bALTER\s+TABLE\s+[a-zA-Z0-9_.]+\s+DISABLE\s+ROW\s+LEVEL\s+SECURITY\b"#).unwrap()
});

/// BK-AI-DAT-003 (CWE-200): Query returns all rows and filters tenant in application memory
static RE_DAT_003_IN_MEMORY_FILTER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(?:findAll\s*\(\s*\)|find\s*\(\s*\{\s*\}\s*\)|find\s*\(\s*\)|fetchAll\s*\(\s*\))\s*\.?[\s\S]{0,100}?\.(?:filter|find)\s*\(\s*(?:[a-zA-Z_][a-zA-Z0-9_]*|\([^)]*\))\s*=>\s*[^.]*\.(?:tenant_?id|org_?id|company_?id)\b"#).unwrap()
});

static RE_DAT_003_VAR_THEN_FILTER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:const|let|var)\s+[a-zA-Z0-9_]+\s*=\s*(?:await\s+)?[a-zA-Z0-9_.]+\.(?:findAll|find)\s*\(\s*\);[\s\S]{0,150}?[a-zA-Z0-9_]+\.filter\s*\([^)]*\.(?:tenant_?id|org_?id|company_?id)"#).unwrap()
});

/// BK-AI-DAT-004 (CWE-798): DB schema/seed inserts hardcoded default admin credentials
static RE_DAT_004_SQL_DEFAULT_ADMIN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\bINSERT\s+INTO\s+[a-zA-Z0-9_.]*(?:users|accounts|admins|members)[^;]*VALUES\s*\([^;]*(?:'admin'|"admin")[^;]*(?:'admin123'|'password'|'admin'|'123456'|'root'|'default'|'password123'|'DefaultAdminPassword!')"#).unwrap()
});

static RE_DAT_004_ORM_DEFAULT_ADMIN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\.(?:insert|create|createMany|seed)\s*\(\s*(?:\[\s*)?\{[\s\S]*?(?:email|username)\s*:\s*['"](?:admin|root|admin@[^'"]+)['"][\s\S]*?password\s*:\s*['"][^'"]+['"]"#).unwrap()
});

/// BK-AI-DAT-005 (CWE-552): Database backup stored publicly or without access restrictions
static RE_DAT_005_BACKUP_PUBLIC_ACL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:aws\s+s3\s+cp|aws\s+s3\s+sync|s3\.upload|s3Client\.send|uploadFile|uploadBackup)[^;\n]*(?:backup|\.sql|\.dump|\.bak|\.tar\.gz|\.pgdump)[^;\n]*(?:--acl\s+public-read|acl\s*:\s*['"]public-read['"]|predefinedAcl\s*:\s*['"]publicRead['"])|(?:--acl\s+public-read|acl\s*:\s*['"]public-read['"]|predefinedAcl\s*:\s*['"]publicRead['"])[^;\n]*(?:backup|\.sql|\.dump|\.bak|\.pgdump)|(?:uploadBackup|backupFile)\s*\([^)]*(?:acl\s*:\s*['"]public-read['"]|--acl\s+public-read)"#).unwrap()
});

static RE_DAT_005_BACKUP_IN_WEBROOT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:mysqldump|pg_dump|mongodump)\s+[^;\n]*>\s*['"]?(?:public|static|www|html)/[^;\n]*(?:\.sql|\.dump|\.bak)"#).unwrap()
});

/// BK-AI-DAT-006 (CWE-362): Balance/inventory mutation without transaction or atomic lock
static RE_DAT_006_NON_ATOMIC_MUTATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:user|account|wallet|inventory|stock|product)\.(?:balance|coins|funds|amount|credits|quantity|inventory_count)\s*=\s*[a-zA-Z0-9_.]+\.(?:balance|coins|funds|amount|credits|quantity|inventory_count)\s*[-+]\s*[a-zA-Z0-9_.]+;?\s*(?:await\s+)?[a-zA-Z0-9_.]+\.save\s*\(\s*\)|(?:user|account|wallet|inventory|stock|product)\.(?:balance|coins|funds|amount|credits|quantity|inventory_count)\s*[-+]=\s*[a-zA-Z0-9_.]+;?\s*(?:await\s+)?[a-zA-Z0-9_.]+\.save\s*\(\s*\)"#).unwrap()
});

/// BK-AI-DAT-007 (CWE-863): Search index or cache bypasses permissions
static RE_DAT_007_VECTOR_QUERY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:pinecone|vectorStore|index|collection)\.query\s*\(\s*\{[\s\S]*?vector\s*:\s*[a-zA-Z0-9_]+[\s\S]*?topK\s*:\s*\d+[\s\S]*?\}\s*\)"#).unwrap()
});

static RE_DAT_007_CACHE_UNCHECKED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:const|let|var)\s+[a-zA-Z0-9_]+\s*=\s*(?:await\s+)?cache\.get\s*\([^)]*\);?\s*(?:return\s+)?(?:res\.(?:json|send)|return)\s*\(\s*[a-zA-Z0-9_]+\s*\)"#).unwrap()
});

/// BK-AI-DAT-008 (CWE-89): ORM raw query escaping assumed but interpolated strings used
static RE_DAT_008_RAW_INTERPOLATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:sequelize\.query|prisma\.\$queryRawUnsafe|db\.raw|connection\.query|db\.query)\s*\(\s*`[^`]*\$\{[^}]+\}[^`]*`"#).unwrap()
});

static RE_DAT_008_RAW_CONCAT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:sequelize\.query|prisma\.\$queryRawUnsafe|db\.raw|connection\.query)\s*\(\s*['"][^'"]*(?:SELECT|UPDATE|DELETE|INSERT)[\s\S]*?['"]\s*\+\s*[a-zA-Z0-9_.]+"#).unwrap()
});

static RE_DAT_008_WHERE_INTERPOLATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\$where\s*:\s*`[^`]*\$\{[^}]+\}[^`]*`"#).unwrap()
});

/// BK-AI-DAT-009 (CWE-284): Migration drops security constraints or audit triggers
static RE_DAT_009_DROP_SECURITY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\bDROP\s+TRIGGER\s+(?:IF\s+EXISTS\s+)?[a-zA-Z0-9_.]*(?:audit|security|auth|verify|log)[a-zA-Z0-9_.]*|\bDROP\s+CONSTRAINT\s+(?:IF\s+EXISTS\s+)?[a-zA-Z0-9_.]*(?:tenant|check_auth|security|isolation|permission|role)[a-zA-Z0-9_.]*|\bALTER\s+TABLE\s+[a-zA-Z0-9_.]+\s+DROP\s+CONSTRAINT\s+[a-zA-Z0-9_.]*|\.dropForeign\s*\(\s*['"](?:tenant_?id|org_?id|user_?id)['"]\s*\)|\.dropTrigger\s*\(\s*['"][^'"]*(?:audit|security|log)[^'"]*['"]\s*\)"#).unwrap()
});

/// BK-AI-DAT-010 (CWE-89): Dynamic table/collection chosen directly from user input
static RE_DAT_010_DYNAMIC_TABLE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:db\.collection|knex|sequelize\.model)\s*\(\s*(?:req\.(?:body|params|query)\.[a-zA-Z0-9_]+)\s*\)|FROM\s+[`"']?\$\{(?:req\.(?:body|params|query)\.[a-zA-Z0-9_]+)\}[`"']?|prisma\s*\[\s*(?:req\.(?:body|params|query)\.[a-zA-Z0-9_]+)\s*\]"#).unwrap()
});

/// BK-AI-DAT-011 (CWE-732): Storage object ACL/public bucket used for private content
static RE_DAT_011_PUBLIC_ACL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(?:acl|ACL)\s*:\s*['"]public-read(?:-write)?['"]|\bpredefinedAcl\s*:\s*['"]publicRead(?:Write)?['"]|\b--acl\s+public-read\b"#).unwrap()
});

/// BK-AI-DAT-012 (CWE-212): Sensitive records survive deletion through caches or views without purge
static RE_DAT_012_UNPURGED_DELETE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:User|Account|Customer|Profile|Session|Member)\.(?:destroy|delete|deleteOne|deleteMany|remove)\s*\([^)]*\)\s*;?[\s\S]{1,200}?(?:res\.(?:json|send)|return\b)"#).unwrap()
});

static RE_DAT_012_COMMENT_INDICATOR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)//.*(?:deleted|destroyed)\s+without\s+(?:clearing|purging|invalidating)\s+(?:cache|redis|view)\b"#).unwrap()
});

// ---------------------------------------------------------------------------
// Scanner Implementation
// ---------------------------------------------------------------------------

pub struct DataPrivacyScanner;

impl DataPrivacyScanner {
    /// Scans source code content for Category 10 and Category 11 security violations.
    pub fn scan_source(path: &Path, content: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut seen = HashSet::new();

        let target_kind = match path.extension().and_then(|ext| ext.to_str()) {
            Some("js" | "jsx" | "ts" | "tsx") => TargetKind::NodeSourceFile,
            Some("json" | "yaml" | "yml") => TargetKind::GenericConfigFile,
            Some("env") => TargetKind::EnvironmentFile,
            _ => TargetKind::GenericSourceFile,
        };

        let lines: Vec<&str> = content.lines().collect();

        // -------------------------------------------------------------------
        // 1. Multi-line Patterns across full content
        // -------------------------------------------------------------------

        // BK-AI-SEC-011: Third-party AI model receives confidential data
        for mat in RE_SEC_011_AI_CONFIDENTIAL.find_iter(content) {
            let matched_str = mat.as_str();
            if !matched_str.contains("redact")
                && !matched_str.contains("mask")
                && !matched_str.contains("anonymize")
                && !matched_str.contains("sanitize")
            {
                let line_no = content[..mat.start()].lines().count().max(1);
                if seen.insert(("BK-AI-SEC-011", line_no)) {
                    let snippet = matched_str.lines().next().unwrap_or(matched_str);
                    findings.push(Self::create_finding(
                        "BK-AI-SEC-011",
                        "Third-Party AI or Analytics Provider Receives Confidential Data Without Redaction",
                        "CWE-201",
                        Severity::High,
                        "2.10 Secrets, privacy, PII and data exposure",
                        path,
                        &target_kind,
                        line_no,
                        snippet,
                        "Redact, mask, or tokenize sensitive user identifiers and credentials before transmitting to external AI/analytics APIs",
                        "External AI provider integration receives un-redacted confidential credentials or sensitive user data",
                        "Restore invariant: consent/contract/data boundary defined",
                    ));
                }
            }
        }

        // BK-AI-DAT-003: Memory-based tenant filtering after unbounded query
        for mat in RE_DAT_003_IN_MEMORY_FILTER.find_iter(content) {
            let line_no = content[..mat.start()].lines().count().max(1);
            if seen.insert(("BK-AI-DAT-003", line_no)) {
                let snippet = mat.as_str().lines().next().unwrap_or(mat.as_str());
                findings.push(Self::create_finding(
                    "BK-AI-DAT-003",
                    "Query Returns All Rows and Filters Tenant in Application Memory",
                    "CWE-200",
                    Severity::High,
                    "2.11 Database, storage, search and persistence",
                    path,
                    &target_kind,
                    line_no,
                    snippet,
                    "Tenant isolation predicates must be executed directly in database query filters",
                    "Query retrieves all database rows without tenancy filter and performs tenant partitioning in application memory",
                    "Restore invariant: tenant filter enforced before access",
                ));
            }
        }

        for mat in RE_DAT_003_VAR_THEN_FILTER.find_iter(content) {
            let line_no = content[..mat.start()].lines().count().max(1);
            if seen.insert(("BK-AI-DAT-003", line_no)) {
                let snippet = mat.as_str().lines().next().unwrap_or(mat.as_str());
                findings.push(Self::create_finding(
                    "BK-AI-DAT-003",
                    "Query Returns All Rows and Filters Tenant in Application Memory",
                    "CWE-200",
                    Severity::High,
                    "2.11 Database, storage, search and persistence",
                    path,
                    &target_kind,
                    line_no,
                    snippet,
                    "Tenant isolation predicates must be executed directly in database query filters",
                    "Query retrieves all database rows without tenancy filter and performs tenant partitioning in application memory",
                    "Restore invariant: tenant filter enforced before access",
                ));
            }
        }

        // BK-AI-DAT-004: DB schema/seed inserts default admin credentials (multi-line ORM)
        for mat in RE_DAT_004_ORM_DEFAULT_ADMIN.find_iter(content) {
            let line_no = content[..mat.start()].lines().count().max(1);
            if seen.insert(("BK-AI-DAT-004", line_no)) {
                let snippet = mat.as_str().lines().next().unwrap_or(mat.as_str());
                findings.push(Self::create_finding(
                    "BK-AI-DAT-004",
                    "Database Schema or Seed Inserts Hardcoded Default Admin Credentials",
                    "CWE-798",
                    Severity::Critical,
                    "2.11 Database, storage, search and persistence",
                    path,
                    &target_kind,
                    line_no,
                    snippet,
                    "Seed scripts and schema migrations must never embed static default credentials",
                    "Database schema or seed migration scripts insert hardcoded default administrative passwords",
                    "Restore invariant: credentials cannot ship in deployment",
                ));
            }
        }

        // BK-AI-DAT-006: Balance mutation without atomic transaction/lock (multi-line)
        for mat in RE_DAT_006_NON_ATOMIC_MUTATION.find_iter(content) {
            let matched_str = mat.as_str();
            let start_offset = mat.start();
            let context_start = start_offset.saturating_sub(200);
            let context_end = (mat.end() + 200).min(content.len());
            let context = &content[context_start..context_end];

            if !context.contains("transaction")
                && !context.contains("FOR UPDATE")
                && !context.contains("LOCK.UPDATE")
                && !context.contains("decrement")
            {
                let line_no = content[..start_offset].lines().count().max(1);
                if seen.insert(("BK-AI-DAT-006", line_no)) {
                    let snippet = matched_str.lines().next().unwrap_or(matched_str);
                    findings.push(Self::create_finding(
                        "BK-AI-DAT-006",
                        "Concurrent Balance or State Mutation Without Atomic Lock or Transaction",
                        "CWE-362",
                        Severity::High,
                        "2.11 Database, storage, search and persistence",
                        path,
                        &target_kind,
                        line_no,
                        snippet,
                        "Financial balances and inventory levels must be updated atomically or under row locks",
                        "Financial balance or inventory mutation performed in memory without row-level lock or atomic update",
                        "Restore invariant: atomic financial/ownership updates",
                    ));
                }
            }
        }

        // BK-AI-DAT-007: Search index or vector query without permission filter
        for mat in RE_DAT_007_VECTOR_QUERY.find_iter(content) {
            let matched_str = mat.as_str();
            if !matched_str.contains("filter:") && !matched_str.contains("filter :") {
                let line_no = content[..mat.start()].lines().count().max(1);
                if seen.insert(("BK-AI-DAT-007", line_no)) {
                    let snippet = matched_str.lines().next().unwrap_or(matched_str);
                    findings.push(Self::create_finding(
                        "BK-AI-DAT-007",
                        "Search Index or Vector Query Bypasses Permission and Tenant Filters",
                        "CWE-863",
                        Severity::High,
                        "2.11 Database, storage, search and persistence",
                        path,
                        &target_kind,
                        line_no,
                        snippet,
                        "Search index queries and cached reads must enforce tenant scoping and access control filters",
                        "Vector search queries or document cache retrieval bypass tenant isolation or permission filters",
                        "Restore invariant: read path enforces tenant and document ACL",
                    ));
                }
            }
        }

        // BK-AI-DAT-007: Unchecked cache retrieval returned directly
        for mat in RE_DAT_007_CACHE_UNCHECKED.find_iter(content) {
            let line_no = content[..mat.start()].lines().count().max(1);
            if seen.insert(("BK-AI-DAT-007", line_no)) {
                let snippet = mat.as_str().lines().next().unwrap_or(mat.as_str());
                findings.push(Self::create_finding(
                    "BK-AI-DAT-007",
                    "Search Index or Cache Bypasses Permissions",
                    "CWE-863",
                    Severity::High,
                    "2.11 Database, storage, search and persistence",
                    path,
                    &target_kind,
                    line_no,
                    snippet,
                    "Search index queries and cached reads must enforce tenant scoping and access control filters",
                    "Cached document returned directly to response without verifying caller tenancy or ownership",
                    "Restore invariant: read path enforces tenant and document ACL",
                ));
            }
        }

        // BK-AI-DAT-012: Sensitive records survive deletion through unpurged caches
        for mat in RE_DAT_012_UNPURGED_DELETE.find_iter(content) {
            let matched_str = mat.as_str();
            if !matched_str.contains("redis")
                && !matched_str.contains("cache")
                && !matched_str.contains("invalidate")
                && !matched_str.contains("purge")
            {
                let line_no = content[..mat.start()].lines().count().max(1);
                if seen.insert(("BK-AI-DAT-012", line_no)) {
                    let snippet = matched_str.lines().next().unwrap_or(matched_str);
                    findings.push(Self::create_finding(
                        "BK-AI-DAT-012",
                        "Sensitive Records Survive Deletion Through Unpurged Caches or Materialized Views",
                        "CWE-212",
                        Severity::Medium,
                        "2.11 Database, storage, search and persistence",
                        path,
                        &target_kind,
                        line_no,
                        snippet,
                        "Data deletion and account purge routines must immediately invalidate related caches and views",
                        "Sensitive user records or credentials deleted from primary storage without invalidating caches or views",
                        "Restore invariant: lifecycle/cascade proof",
                    ));
                }
            }
        }

        // -------------------------------------------------------------------
        // 2. Line-by-Line Patterns with Window Analysis
        // -------------------------------------------------------------------

        for (idx, line) in lines.iter().enumerate() {
            let line_no = idx + 1;
            let trimmed = line.trim();

            if trimmed.is_empty() {
                continue;
            }

            let is_full_comment = trimmed.starts_with("//")
                || trimmed.starts_with('#')
                || trimmed.starts_with("--")
                || trimmed.starts_with("/*")
                || trimmed.starts_with('*');

            // Explicit check for DAT-012 comment indicator
            if is_full_comment && RE_DAT_012_COMMENT_INDICATOR.is_match(trimmed) {
                if seen.insert(("BK-AI-DAT-012", line_no)) {
                    findings.push(Self::create_finding(
                        "BK-AI-DAT-012",
                        "Sensitive Records Survive Deletion Through Unpurged Caches or Materialized Views",
                        "CWE-212",
                        Severity::Medium,
                        "2.11 Database, storage, search and persistence",
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Data deletion and account purge routines must immediately invalidate related caches and views",
                        "Sensitive user records deleted without invalidating redis cache or refreshing views",
                        "Restore invariant: lifecycle/cascade proof",
                    ));
                }
                continue;
            }

            if is_full_comment {
                continue;
            }

            // 1. BK-AI-SEC-005: Environment variables or stack trace dumped verbatim
            if RE_SEC_005_DUMP_ENV.is_match(trimmed) {
                let is_property_access = trimmed.contains("process.env.")
                    || trimmed.contains("process.env[")
                    || trimmed.contains("os.environ.get")
                    || trimmed.contains("os.environ[");

                if !is_property_access
                    && !trimmed.contains("sanitize")
                    && !trimmed.contains("redact")
                    && !trimmed.contains("mask")
                {
                    if seen.insert(("BK-AI-SEC-005", line_no)) {
                        findings.push(Self::create_finding(
                            "BK-AI-SEC-005",
                            "Environment Variables, Payload or Stack Trace Dumped Verbatim",
                            "CWE-532",
                            Severity::High,
                            "2.10 Secrets, privacy, PII and data exposure",
                            path,
                            &target_kind,
                            line_no,
                            trimmed,
                            "Log only designated non-sensitive properties with masking and redaction boundaries",
                            "Sensitive system environment variables dumped verbatim to logs or standard output",
                            "Restore invariant: logging redaction by boundary",
                        ));
                    }
                }
            } else if RE_SEC_005_DUMP_STACK.is_match(trimmed) {
                if seen.insert(("BK-AI-SEC-005", line_no)) {
                    findings.push(Self::create_finding(
                        "BK-AI-SEC-005",
                        "Environment Variables, Payload or Stack Trace Dumped Verbatim",
                        "CWE-532",
                        Severity::High,
                        "2.10 Secrets, privacy, PII and data exposure",
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Sanitize internal exception stacks before returning errors to clients",
                        "Raw internal execution stack trace dumped directly to HTTP client response",
                        "Restore invariant: logging redaction by boundary",
                    ));
                }
            }

            // 2. BK-AI-SEC-006: Sensitive PII in metrics tags, trace spans or analytics
            if RE_SEC_006_PII_TAG.is_match(trimmed)
                || RE_SEC_006_ANALYTICS_PII.is_match(trimmed)
                || RE_SEC_006_DATADOG_TAG_ARRAY.is_match(trimmed)
            {
                if !trimmed.contains("_hash")
                    && !trimmed.contains("masked")
                    && !trimmed.contains("redacted")
                {
                    if seen.insert(("BK-AI-SEC-006", line_no)) {
                        findings.push(Self::create_finding(
                            "BK-AI-SEC-006",
                            "Sensitive PII in Metrics Tags, Trace Spans or Analytics",
                            "CWE-200",
                            Severity::High,
                            "2.10 Secrets, privacy, PII and data exposure",
                            path,
                            &target_kind,
                            line_no,
                            trimmed,
                            "Telemetry tags and metric dimensions must never record PII or credential attributes",
                            "Sensitive PII recorded in metrics tags, trace spans, queue attributes or analytics payloads",
                            "Restore invariant: telemetry data minimized",
                        ));
                    }
                }
            }

            // 3. BK-AI-SEC-007: Unnecessary collection/storage of sensitive user data
            if RE_SEC_007_CVV_STORAGE.is_match(trimmed) {
                if seen.insert(("BK-AI-SEC-007", line_no)) {
                    findings.push(Self::create_finding(
                        "BK-AI-SEC-007",
                        "Unnecessary Collection or Storage of Sensitive User Data",
                        "CWE-359",
                        Severity::Critical,
                        "2.10 Secrets, privacy, PII and data exposure",
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Prohibit persistent storage of prohibited cardholder verification data (CVV/CVC) or plaintext passwords",
                        "Database model or persistence logic stores CVV/CVC codes or plaintext passwords directly",
                        "Restore invariant: data inventory, purpose, retention policy",
                    ));
                }
            }

            // 4. BK-AI-SEC-008: Data export/deletion workflows omit authorized ownership verification
            if RE_SEC_008_EXPORT_DELETE_ROUTE.is_match(trimmed) {
                let start = idx.saturating_sub(5);
                let end = (idx + 25).min(lines.len());
                let window = lines[start..end].join("\n").to_lowercase();

                let has_auth_middleware = window.contains("authenticate")
                    || window.contains("requireauth")
                    || window.contains("verifytoken")
                    || window.contains("passport")
                    || window.contains("checkauth")
                    || window.contains("guard")
                    || window.contains("jwt");

                let checks_ownership = window.contains("req.user.id")
                    || window.contains("user.id ===")
                    || window.contains("user.id == ")
                    || window.contains("session.userid")
                    || window.contains("isowner")
                    || window.contains("assertowner");

                if !has_auth_middleware || !checks_ownership {
                    if seen.insert(("BK-AI-SEC-008", line_no)) {
                        findings.push(Self::create_finding(
                            "BK-AI-SEC-008",
                            "Data Export or Deletion Workflow Omits Authorized Ownership Verification",
                            "CWE-639",
                            Severity::High,
                            "2.10 Secrets, privacy, PII and data exposure",
                            path,
                            &target_kind,
                            line_no,
                            trimmed,
                            "Data export and account deletion workflows must enforce authenticated session ownership",
                            "Data export or deletion endpoint allows unauthenticated or unverified caller access to user data",
                            "Restore invariant: principal and object rights proven",
                        ));
                    }
                }
            }

            // 5. BK-AI-SEC-009: Missing encryption-at-rest for sensitive columns/datasets
            if RE_SEC_009_ENCRYPTED_FALSE.is_match(trimmed)
                || RE_SEC_009_STORAGE_UNENCRYPTED.is_match(trimmed)
                || RE_SEC_009_PLAIN_SENSITIVE_COLUMN.is_match(trimmed)
            {
                let start = idx.saturating_sub(5);
                let end = (idx + 6).min(lines.len());
                let window = lines[start..end].join("\n");

                if !window.contains("encrypted: true")
                    && !window.contains("@EncryptedColumn")
                    && !window.contains("transformer:")
                    && !window.contains("aws:kms")
                {
                    if seen.insert(("BK-AI-SEC-009", line_no)) {
                        findings.push(Self::create_finding(
                            "BK-AI-SEC-009",
                            "Missing Encryption-at-Rest for Regulated or Sensitive Datasets",
                            "CWE-311",
                            Severity::High,
                            "2.10 Secrets, privacy, PII and data exposure",
                            path,
                            &target_kind,
                            line_no,
                            trimmed,
                            "Sensitive data columns and storage buckets must declare encryption at rest",
                            "Sensitive data column or storage configuration explicitly disables or lacks encryption-at-rest",
                            "Restore invariant: data classification determines control",
                        ));
                    }
                }
            }

            // 6. BK-AI-SEC-011: Third-party analytics receives confidential data
            if RE_SEC_011_ANALYTICS_CONFIDENTIAL.is_match(trimmed) {
                if !trimmed.contains("redact")
                    && !trimmed.contains("mask")
                    && !trimmed.contains("anonymize")
                    && !trimmed.contains("sanitize")
                {
                    if seen.insert(("BK-AI-SEC-011", line_no)) {
                        findings.push(Self::create_finding(
                            "BK-AI-SEC-011",
                            "Third-Party AI or Analytics Provider Receives Confidential Data Without Redaction",
                            "CWE-201",
                            Severity::High,
                            "2.10 Secrets, privacy, PII and data exposure",
                            path,
                            &target_kind,
                            line_no,
                            trimmed,
                            "Redact or filter confidential credentials, payment card data, and PII before forwarding to third parties",
                            "Third-party analytics provider receives raw confidential PII without tokenization or redaction",
                            "Restore invariant: consent/contract/data boundary defined",
                        ));
                    }
                }
            }

            // 7. BK-AI-SEC-012: Reports and tool replies contain raw secrets/keys
            if RE_SEC_012_TOOL_REPLY_SECRET.is_match(trimmed)
                || RE_SEC_012_TOOL_RESULT_STRING.is_match(trimmed)
            {
                if !trimmed.contains("mask")
                    && !trimmed.contains("redact")
                    && !trimmed.contains("substring")
                    && !trimmed.contains("slice")
                {
                    if seen.insert(("BK-AI-SEC-012", line_no)) {
                        findings.push(Self::create_finding(
                            "BK-AI-SEC-012",
                            "Reports and Tool Replies Contain Raw Secrets or Keys",
                            "CWE-532",
                            Severity::High,
                            "2.10 Secrets, privacy, PII and data exposure",
                            path,
                            &target_kind,
                            line_no,
                            trimmed,
                            "Tool outputs and user-facing reports must redact API keys, tokens, and credentials",
                            "AI agent tool reply or structured report embeds raw unredacted secret credentials",
                            "Restore invariant: redaction with bounded evidence preview",
                        ));
                    }
                }
            }

            // 8. BK-AI-DAT-001: Database connection uses superuser or root credentials
            if RE_DAT_001_SUPERUSER_CONN.is_match(trimmed)
                || RE_DAT_001_SUPERUSER_CONFIG.is_match(trimmed)
            {
                if seen.insert(("BK-AI-DAT-001", line_no)) {
                    findings.push(Self::create_finding(
                        "BK-AI-DAT-001",
                        "Database Connection Uses Superuser or Owner Credentials",
                        "CWE-250",
                        Severity::High,
                        "2.11 Database, storage, search and persistence",
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Application database connections must use dedicated, least-privileged service accounts",
                        "Database connection configured using superuser or root credentials in application settings",
                        "Restore invariant: least-privilege roles",
                    ));
                }
            }

            // 9. BK-AI-DAT-002: Row-level security bypassed by service role / admin override
            if RE_DAT_002_SERVICE_ROLE.is_match(trimmed)
                || RE_DAT_002_BYPASS_FLAG.is_match(trimmed)
            {
                if seen.insert(("BK-AI-DAT-002", line_no)) {
                    findings.push(Self::create_finding(
                        "BK-AI-DAT-002",
                        "Row-Level Security Bypassed by Service Role or Admin Elevation",
                        "CWE-863",
                        Severity::Critical,
                        "2.11 Database, storage, search and persistence",
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Enforce row-level security and prevent service-role key usage in user-facing request paths",
                        "Database row-level security configured but explicitly bypassed via service role key or admin override",
                        "Restore invariant: server roles and every query path scoped",
                    ));
                }
            }

            // 10. BK-AI-DAT-004: DB schema/seed inserts default admin credentials
            if RE_DAT_004_SQL_DEFAULT_ADMIN.is_match(trimmed)
                || RE_DAT_004_ORM_DEFAULT_ADMIN.is_match(trimmed)
            {
                if seen.insert(("BK-AI-DAT-004", line_no)) {
                    findings.push(Self::create_finding(
                        "BK-AI-DAT-004",
                        "Database Schema or Seed Inserts Hardcoded Default Admin Credentials",
                        "CWE-798",
                        Severity::Critical,
                        "2.11 Database, storage, search and persistence",
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Seed scripts and schema migrations must never embed static default credentials",
                        "Database schema or seed migration scripts insert hardcoded default administrative passwords",
                        "Restore invariant: credentials cannot ship in deployment",
                    ));
                }
            }

            // 11. BK-AI-DAT-005: Database backup stored publicly or without access restrictions
            if RE_DAT_005_BACKUP_PUBLIC_ACL.is_match(trimmed)
                || RE_DAT_005_BACKUP_IN_WEBROOT.is_match(trimmed)
            {
                if seen.insert(("BK-AI-DAT-005", line_no)) {
                    findings.push(Self::create_finding(
                        "BK-AI-DAT-005",
                        "Database Backup Stored Publicly or Without Access Restrictions",
                        "CWE-552",
                        Severity::High,
                        "2.11 Database, storage, search and persistence",
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Database backups and snapshots must be stored in encrypted, private storage locations",
                        "Database backup archive or snapshot stored with public-read ACL or exposed in webroot",
                        "Restore invariant: protection and retention audited",
                    ));
                }
            }

            // 12. BK-AI-DAT-006: Balance mutation without atomic update (lookahead)
            if trimmed.contains(".balance")
                || trimmed.contains(".coins")
                || trimmed.contains(".funds")
                || trimmed.contains(".stock")
                || trimmed.contains(".quantity")
            {
                if trimmed.contains("-=") || trimmed.contains("+=") || trimmed.contains(" = ") {
                    let end_idx = (idx + 4).min(lines.len());
                    let forward_window = lines[idx..end_idx].join("\n");
                    if forward_window.contains(".save()") && !forward_window.contains("transaction") {
                        if seen.insert(("BK-AI-DAT-006", line_no)) {
                            findings.push(Self::create_finding(
                                "BK-AI-DAT-006",
                                "Concurrent Balance or State Mutation Without Atomic Lock or Transaction",
                                "CWE-362",
                                Severity::High,
                                "2.11 Database, storage, search and persistence",
                                path,
                                &target_kind,
                                line_no,
                                trimmed,
                                "Financial balances and inventory levels must be updated atomically or under row locks",
                                "Balance or inventory mutated in application memory and saved without row lock or transaction",
                                "Restore invariant: atomic financial/ownership updates",
                            ));
                        }
                    }
                }
            }

            // 14. BK-AI-DAT-008: ORM raw query interpolation permits SQL injection
            if RE_DAT_008_RAW_INTERPOLATION.is_match(trimmed)
                || RE_DAT_008_RAW_CONCAT.is_match(trimmed)
                || RE_DAT_008_WHERE_INTERPOLATION.is_match(trimmed)
            {
                if seen.insert(("BK-AI-DAT-008", line_no)) {
                    findings.push(Self::create_finding(
                        "BK-AI-DAT-008",
                        "ORM Raw Query Interpolation Permits SQL Injection",
                        "CWE-89",
                        Severity::Critical,
                        "2.11 Database, storage, search and persistence",
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "All raw ORM queries must use parameterized bind variables or tagged safe templates",
                        "ORM raw query uses string interpolation or concatenation instead of parameterized inputs",
                        "Restore invariant: raw fragments controlled",
                    ));
                }
            }

            // 15. BK-AI-DAT-009: Migration drops security constraints or audit triggers
            if RE_DAT_009_DROP_SECURITY.is_match(trimmed) {
                if seen.insert(("BK-AI-DAT-009", line_no)) {
                    findings.push(Self::create_finding(
                        "BK-AI-DAT-009",
                        "Migration Drops Security Constraints or Audit Triggers",
                        "CWE-284",
                        Severity::High,
                        "2.11 Database, storage, search and persistence",
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Database migrations must preserve audit triggers, tenant isolation, and security constraints",
                        "Migration script drops foreign key isolation, audit triggers, or security integrity constraints",
                        "Restore invariant: invariants retained",
                    ));
                }
            }

            // 16. BK-AI-DAT-010: Dynamic table/collection chosen directly from user input
            if RE_DAT_010_DYNAMIC_TABLE.is_match(trimmed) {
                let start = idx.saturating_sub(6);
                let end = (idx + 6).min(lines.len());
                let window = lines[start..end].join("\n").to_lowercase();

                let is_validated = window.contains("includes")
                    || window.contains("allowlist")
                    || window.contains("whitelist")
                    || window.contains("allowed_tables")
                    || window.contains("hasownproperty")
                    || window.contains("table_map");

                if !is_validated {
                    if seen.insert(("BK-AI-DAT-010", line_no)) {
                        findings.push(Self::create_finding(
                            "BK-AI-DAT-010",
                            "Dynamic Table or Collection Chosen Directly from User Input",
                            "CWE-89",
                            Severity::High,
                            "2.11 Database, storage, search and persistence",
                            path,
                            &target_kind,
                            line_no,
                            trimmed,
                            "Table and collection names must be validated against a strictly constrained static allowlist",
                            "Database collection or table name dynamically determined directly from unvalidated request parameters",
                            "Restore invariant: finite allowed target set",
                        ));
                    }
                }
            }

            // 17. BK-AI-DAT-011: Storage object ACL configured for public access
            if RE_DAT_011_PUBLIC_ACL.is_match(trimmed) {
                let lower_trimmed = trimmed.to_lowercase();
                let is_backup = lower_trimmed.contains("backup")
                    || lower_trimmed.contains(".sql")
                    || lower_trimmed.contains(".dump")
                    || lower_trimmed.contains(".bak");
                let is_static_asset = lower_trimmed.contains("favicon")
                    || lower_trimmed.contains("logo")
                    || lower_trimmed.contains("public/assets");

                if !is_static_asset && !is_backup {
                    if seen.insert(("BK-AI-DAT-011", line_no)) {
                        findings.push(Self::create_finding(
                            "BK-AI-DAT-011",
                            "Storage Object ACL or Bucket Configured for Public Access to Private Data",
                            "CWE-732",
                            Severity::High,
                            "2.11 Database, storage, search and persistence",
                            path,
                            &target_kind,
                            line_no,
                            trimmed,
                            "Private documents and storage artifacts must enforce private ACLs and restricted policies",
                            "Storage object ACL or bucket policy configured with public-read for non-public content",
                            "Restore invariant: object-level rights enforced",
                        ));
                    }
                }
            }
        }

        findings
    }

    /// Constructs a standardized Finding with Schema v2 metadata.
    #[allow(clippy::too_many_arguments)]
    fn create_finding(
        rule_id: &str,
        title: &str,
        cwe: &str,
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
        finding.detector_id = "data-privacy".to_string();
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
