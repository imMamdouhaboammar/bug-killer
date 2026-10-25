#![allow(dead_code, clippy::collapsible_if)]

use crate::types::*;
use regex::Regex;
use std::collections::HashSet;
use std::path::Path;
use std::sync::LazyLock;

// ---------------------------------------------------------------------------
// Category 17: Concurrency, Workflow State and Race Conditions (BK-AI-RAC-001 through 010)
// ---------------------------------------------------------------------------

const CATEGORY_RAC: &str = "2.17 Concurrency, workflow state and race conditions";
const CATEGORY_BIZ: &str = "2.20 Business logic, workflows and monetary/privileged effects";

// 1. BK-AI-RAC-001 (CWE-367): TOCTOU on path, URL, credentials or permissions
static RE_RAC_001_PATH_CHECK: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\bfs\.existsSync\s*\(|\bpathExistsSync\s*\(|\bos\.path\.exists\s*\(|\bos\.path\.isfile\s*\(|\bos\.Stat\s*\(|\bfile_exists\s*\(|\bPath\([^)]*\)\.exists\s*\()"#).unwrap()
});

static RE_RAC_001_PATH_ACT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\bfs\.(?:readFileSync|writeFileSync|unlinkSync|createReadStream|createWriteStream|readFile|writeFile|unlink)\b|\bopen\s*\(|\bos\.(?:remove|unlink|Open|ReadFile|WriteFile)\b|\bfile_get_contents\b)"#).unwrap()
});

static RE_RAC_001_PERM_CHECK: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\bcheckAccess\s*\(|\bhasPermission\s*\(|\bcanAccess\s*\(|\bverifyPermission\s*\(|\bcheckUserPermission\s*\(|\bcanUserExecute\s*\()"#).unwrap()
});

static RE_RAC_001_PERM_ACT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\bperformAction\s*\(|\bexecuteAction\s*\(|\bdeleteResource\s*\(|\bmutateResource\s*\(|\bupdateResource\s*\(|\btransferFunds\s*\(|\bgrantRole\s*\()"#).unwrap()
});

static RE_RAC_001_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:try\s*\{|catch\s*\(|except\s+|O_EXCL|O_CREAT|\bwx\b|flock|mutex|lock|with_transaction|FOR\s+UPDATE|atomic|withLock)"#).unwrap()
});

static RE_RAC_001_COMMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)//.*(?:toctou|check-then-act|time-of-check|race condition on file)"#).unwrap()
});

// 2. BK-AI-RAC-002 (CWE-362): Double-submit/double-charge due to non-idempotent retries
static RE_RAC_002_PAYMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:stripe\.(?:charges|paymentIntents)\.create|paypal\.(?:payment|order)\.execute|paymentGateway\.charge|billingClient\.charge|chargeCard|processPayment)\s*\("#).unwrap()
});

static RE_RAC_002_RETRY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:retry\s*\(|for\s*\([^)]*attempt[^)]*\)|while\s*\([^)]*retries[^)]*\))"#)
        .unwrap()
});

static RE_RAC_002_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:idempotency|idempotencyKey|idempotency_key|Idempotency-Key|dedup|transaction_id|requestId)"#).unwrap()
});

static RE_RAC_002_COMMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)//.*(?:double-charge|double submit|non-idempotent charge|retry without idempotency)"#).unwrap()
});

// 3. BK-AI-RAC-003 (CWE-362): Token refresh/rotation race permits replay
static RE_RAC_003_REFRESH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:rotateRefreshToken|refreshTokens?|handleTokenRefresh|exchangeRefreshToken)\s*\(|(?:findRefreshToken|getRefreshToken)\s*\([^)]*\)"#).unwrap()
});

static RE_RAC_003_ISSUE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:generateTokens?|createAccessToken|signToken|createSession)"#).unwrap()
});

static RE_RAC_003_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:invalidateFamily|tokenFamily|revokeAll|atomic|transaction|findOneAndUpdate|FOR\s+UPDATE|compareAndSwap|isRevoked|atomicRotate)"#).unwrap()
});

static RE_RAC_003_COMMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)//.*(?:token refresh race|refresh token replay|concurrent refresh|token rotation race)"#).unwrap()
});

// 4. BK-AI-RAC-004 (CWE-362): Shared mutable state used without synchronization
static RE_RAC_004_GO_FUNC: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)go\s+func\s*\("#).unwrap());

static RE_RAC_004_RUST_STATIC_MUT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"static\s+mut\s+[A-Z0-9_]+\s*:\s*[a-zA-Z0-9_]+"#).unwrap());

static RE_RAC_004_GLOBAL_DECL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:(?:let|var)\s+(?:globalCount(?:er)?|globalState|sharedCounter)\s*=\s*[^;]+;|shared_counter\s*=\s*\d+)"#).unwrap()
});

static RE_RAC_004_MUTATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:globalCount(?:er)?\+\+|globalCount(?:er)?\s*\+=|globalState\[|shared_counter\s*\+=|sharedCounter\+\+|sharedCounter\s*\+=|sharedMap\[)"#).unwrap()
});

static RE_RAC_004_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:Mutex|RwLock|Atomic|sync\.Mutex|sync\.RWMutex|sync\.Map|atomic\.|ConcurrentHashMap|threading\.Lock|lock\.acquire|AtomicI64|AtomicU32)"#).unwrap()
});

static RE_RAC_004_COMMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)//.*(?:shared mutable state|unsynchronized access|data race on global|concurrent map write)"#).unwrap()
});

// 5. BK-AI-RAC-005 (CWE-662): Queue message acknowledged before durable transaction
static RE_RAC_005_ACK: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:channel\.ack|msg\.ack|ch\.Ack|basic_ack|message\.acknowledge)\s*\("#)
        .unwrap()
});

static RE_RAC_005_PROCESS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:processOrder|processMessage|handleJob|db\.(?:commit|query|save)|tx\.Commit|processRecord)"#).unwrap()
});

static RE_RAC_005_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:finally\s*\{[^}]*ack|try\s*\{[^}]*process[^}]*\}\s*finally)"#).unwrap()
});

static RE_RAC_005_COMMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)//.*(?:early ack|ack before process|ack before commit|premature ack|acknowledged before)"#).unwrap()
});

// 6. BK-AI-RAC-006 (CWE-613): Stale cache permission survives user removal/role downgrade
static RE_RAC_006_CACHE_INDEFINITE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:cache\.set|redis\.set)\s*\([^)]*(?:user_roles?|permissions?|user_perms?)[^)]*(?:ttl\s*:\s*(?:0|Infinity)|,\s*0\s*\)|\bnull\b)"#).unwrap()
});

static RE_RAC_006_MUTATE_ROLE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:async\s+)?(?:function\s+)?(?:removeUser|deleteUser|downgradeRole|updateUserRole|revokeRole)\s*\("#).unwrap()
});

static RE_RAC_006_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:cache\.(?:del|delete|invalidate|evict)|redis\.(?:del|unlink)|invalidateCache|evictUserCache)"#).unwrap()
});

static RE_RAC_006_COMMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)//.*(?:stale cache permission|permission cache without invalidation|cache survives role downgrade|missing cache eviction)"#).unwrap()
});

// 7. BK-AI-RAC-007 (CWE-362): Optimistic update race bypasses inventory/limit/policy check
static RE_RAC_007_CHECK: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)if\s*\(\s*(?:item|product|account|user|wallet)\.(?:stock|inventory|balance|credits?)\s*(?:>=?|>)\s*[^)]*\)"#).unwrap()
});

static RE_RAC_007_ACT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\.(?:stock|inventory|balance|credits?)\s*-=|db\.(?:save|update)|items?\.(?:save|update)|user\.(?:save|update))"#).unwrap()
});

static RE_RAC_007_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:WHERE.*(?:stock|inventory|balance)\s*>=|FOR\s+UPDATE|Atomic|transaction|SERIALIZABLE|\$transaction|SELECT\s+FOR\s+UPDATE)"#).unwrap()
});

static RE_RAC_007_COMMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)//.*(?:optimistic race|inventory race|stock check-then-act|non-atomic decrement)"#,
    )
    .unwrap()
});

// 8. BK-AI-RAC-008 (CWE-362): Distributed lease/lock expires during privileged operation
static RE_RAC_008_LOCK: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:redlock\.acquire|redisLock\.lock|acquireLock|acquireDistributedLock)\s*\([^)]*(?:\d{3,5})"#).unwrap()
});

static RE_RAC_008_LONG_OP: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:longRunning|processBatch|migrateData|heavyJob|while\s*\(|await\s+new\s+Promise|sleep\()"#).unwrap()
});

static RE_RAC_008_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:heartbeat|extendLock|autoRenew|lock\.extend|keepAlive|fencingToken|renewalInterval)"#).unwrap()
});

static RE_RAC_008_COMMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)//.*(?:lock expires during|lease without heartbeat|missing lock renewal|lease timeout race)"#).unwrap()
});

// 9. BK-AI-RAC-009 (CWE-367): Background cleanup races with file upload or healing
static RE_RAC_009_CLEANUP: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:fs\.(?:unlinkSync|unlink|rmSync|rm)|os\.remove)\s*\([^)]*(?:upload|temp|tmp|file)"#).unwrap()
});

static RE_RAC_009_CRON_CONTEXT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:cron|setInterval|schedule|cleanTemp|cleanupJob|cleanOldFiles)"#).unwrap()
});

static RE_RAC_009_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:mtime|mtimeMs|age|Date\.now\(\)\s*-|lockfile|activeUploads|inUse|MIN_AGE|retention|olderThan)"#).unwrap()
});

static RE_RAC_009_COMMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)//.*(?:cleanup race|cleaner deletes active upload|temp cleaner races with upload|upload cleanup race)"#).unwrap()
});

// 10. BK-AI-RAC-010 (CWE-362): Concurrent agents act on same target without serialization
static RE_RAC_010_AGENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:agent|worker|subagent)\.(?:applyFix|modifyFile|patchFile|healTarget)\s*\(|(?:async\s+)?(?:function\s+)?(?:agentMutate|applyAgentEdit|healSourceFile)\s*\("#).unwrap()
});

static RE_RAC_010_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:lockfile|acquireFileLock|claimOwnership|Mutex|withLock|flock|acquireWorkspaceLock)"#).unwrap()
});

static RE_RAC_010_COMMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)//.*(?:concurrent agents act without serialization|missing agent file lock|uncoordinated agent mutation|agent ownership race)"#).unwrap()
});

// ---------------------------------------------------------------------------
// Category 20: Business Logic, Workflows & Monetary/Privileged Effects
// (BK-AI-BIZ-001 through 012)
// ---------------------------------------------------------------------------

// 11. BK-AI-BIZ-001 (CWE-602): Payment amount, discount, currency trusted from client
static RE_BIZ_001_CLIENT_AMOUNT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(?:amount|price|unit_amount)\s*:\s*(?:req\.body|request\.(?:json|form|args)|params)\.(?:amount|price|cost|unit_amount)|\bprice\s*=\s*(?:req\.body|request\.(?:json|args))\b"#).unwrap()
});

static RE_BIZ_001_DESTRUCT_AMOUNT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)const\s*\{[^}]*(?:amount|price)[^}]*\}\s*=\s*req\.body;"#).unwrap()
});

static RE_BIZ_001_CHARGE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:stripe\.|checkout\.|charges\.|paymentIntents\.|paypal\.|charge\b|processPayment|chargeCustomer)"#).unwrap()
});

static RE_BIZ_001_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:db\.products|catalog\.getPrice|findProduct|authoritativePrice|serverPrice|db\.items)"#).unwrap()
});

static RE_BIZ_001_COMMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)//.*(?:client-controlled price|trusting client amount|untrusted payment amount|price from req\.body)"#).unwrap()
});

// 12. BK-AI-BIZ-002 (CWE-840): User can reuse coupon/credit beyond permitted count
static RE_BIZ_002_COUPON: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)if\s*\(\s*(?:coupon|promo|code)\s*===?\s*['"][^'"]+['"]\s*\)\s*\{[^}]*(?:discount|total\s*\*=|price\s*-=|cart\.total\s*=)"#).unwrap()
});

static RE_BIZ_002_FUNC: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:function\s+applyCoupon|const\s+applyCoupon)\s*\("#).unwrap()
});

static RE_BIZ_002_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:redemptions|usedCount|maxUses|isRedeemed|markRedeemed|redeemedBy|updateOne.*used|alreadyUsed|redemptionCount)"#).unwrap()
});

static RE_BIZ_002_COMMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)//.*(?:coupon reuse|unlimited discount redemption|missing coupon redemption record|token reuse count)"#).unwrap()
});

// 13. BK-AI-BIZ-003 (CWE-841): State-changing workflow can skip required step
static RE_BIZ_003_SKIP: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:updateOrderStatus|setOrderStatus|orders\.update|db\.orders\.update)\s*\([^)]*(?:status\s*:\s*['"](?:fulfilled|completed|delivered|shipped)['"]|['"](?:fulfilled|completed)['"])"#).unwrap()
});

static RE_BIZ_003_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:order\.status\s*===?|status\s*==|currentStatus|validTransitions|canTransition|ORDER_PAID|OrderState|isPaid|status\s*!==\s*['"]PAID['"])"#).unwrap()
});

static RE_BIZ_003_COMMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)//.*(?:skip required step|workflow skip approval|unverified state transition|skip payment verification)"#).unwrap()
});

// 14. BK-AI-BIZ-004 (CWE-862): Role change/invite lacks proper authorization
static RE_BIZ_004_ENDPOINT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:app|router)\.(?:post|put|patch)\s*\(\s*['"][^'"]*(?:/users?/[^'"]*/role|/orgs?/[^'"]*/owner|/transfer-ownership|/invite-admin)[^'"]*['"]"#).unwrap()
});

static RE_BIZ_004_FUNC: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:function\s+transferOwnership|const\s+transferOwnership)\s*\("#).unwrap()
});

static RE_BIZ_004_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:isAdmin|requireAdmin|isOwner|requireOwner|assertCanManageRoles|checkPermission|hasAdminRole)"#).unwrap()
});

static RE_BIZ_004_COMMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)//.*(?:unauthorized role change|ownership transfer without auth|missing admin check on role change)"#).unwrap()
});

// 15. BK-AI-BIZ-005 (CWE-362): Idempotency key not actor-bound
static RE_BIZ_005_KEY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)const\s+(?:key|idempotencyKey|cacheKey)\s*=\s*(?:req\.headers|request\.headers)\[?['"](?:idempotency-key|x-idempotency-key)['"]\]?"#).unwrap()
});

static RE_BIZ_005_CACHE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:cache|redis)\.(?:get|set)\s*\(\s*(?:key|idempotencyKey|cacheKey)\s*[,)]"#)
        .unwrap()
});

static RE_BIZ_005_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)(?:req\.user|userId|tenantId|\$\{.*user|\$\{.*tenant|scopedIdempotency|actorId)"#,
    )
    .unwrap()
});

static RE_BIZ_005_COMMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)//.*(?:idempotency key not actor-bound|unbound idempotency key|idempotency collision across users|idempotency without user namespace)"#).unwrap()
});

// 16. BK-AI-BIZ-006 (CWE-841): Order completion performed without verified settlement
static RE_BIZ_006_EVENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:case\s*['"](?:checkout\.session\.created|payment_intent\.created|charge\.pending)['"]\s*:|if\s*\(\s*event\.type\s*===?\s*['"](?:checkout\.session\.created|payment_intent\.created)['"]\s*\))"#).unwrap()
});

static RE_BIZ_006_FULFILL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:markOrderPaid|fulfillOrder|grantAccess|deliverProduct|markPaid|fulfill)"#)
        .unwrap()
});

static RE_BIZ_006_COMMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)//.*(?:order completion before settlement|marking paid on created event|unverified settlement|fulfill on session created)"#).unwrap()
});

// 17. BK-AI-BIZ-007 (CWE-841): Reused webhook event alters account more than once
static RE_BIZ_007_WEBHOOK: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:app|router)\.post\s*\(\s*['"][^'"]*webhook[^'"]*['"]"#).unwrap()
});

static RE_BIZ_007_MUTATE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:addCredits|updateBalance|fulfillOrder|processPaymentEvent)"#).unwrap()
});

static RE_BIZ_007_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:processedEvents|processed_events|event\.id|hasProcessedEvent|markEventProcessed|eventId|isDuplicateEvent|processedEventIds)"#).unwrap()
});

static RE_BIZ_007_COMMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)//.*(?:webhook event deduplication missing|duplicate webhook alters account|reused webhook replay|missing webhook idempotency)"#).unwrap()
});

// 18. BK-AI-BIZ-008 (CWE-613): Account deletion misses shared resources or leaves active keys
static RE_BIZ_008_DELETE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:async\s+function\s+(?:deleteAccount|deleteUser|removeAccount)\s*\(|(?:app|router)\.delete\s*\(\s*['"][^'"]*/(?:users?|accounts?)/:id['"])"#).unwrap()
});

static RE_BIZ_008_MUTATE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)(?:users?\.delete|users?\.destroy)"#).unwrap());

static RE_BIZ_008_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:apiKeys|tokens|oauth|credentials|sessions|revokeAll|cascade)"#).unwrap()
});

static RE_BIZ_008_COMMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)//.*(?:account deletion misses active keys|orphaned api keys on deletion|delete account without revoking tokens)"#).unwrap()
});

// 19. BK-AI-BIZ-009 (CWE-200): Multi-tenant report aggregates before access filtering
static RE_BIZ_009_AGG: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:SELECT\s+(?:COUNT|SUM|AVG)\s*\([^)]*\)\s+FROM\s+(?:orders|payments|users|invoices|transactions|accounts)|(?:db|Order|Payment|Invoice)\.(?:aggregate|count|sum)\s*\(\s*(?:\[\s*\{\s*\$group|\{\s*\})?\s*\))"#).unwrap()
});

static RE_BIZ_009_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:WHERE\s+tenant_id|tenant_id\s*=|tenantId|tenant_filter|\$match.*tenantId|where.*tenantId)"#).unwrap()
});

static RE_BIZ_009_COMMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)//.*(?:multi-tenant aggregation before filter|cross-tenant aggregation leak|missing tenant filter in report|aggregate without tenant_id)"#).unwrap()
});

// 20. BK-AI-BIZ-010 (CWE-862): Feature flag/admin backdoor bypasses required policy
static RE_BIZ_010_BYPASS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:(?:req\.headers|request\.headers)\[?['"](?:x-admin-bypass|x-bypass-auth|x-debug-override|admin_override)['"]\]?|if\s*\(\s*(?:req\.query|request\.args)\[?['"](?:debug_bypass|admin_override)['"]\]?\s*===?\s*['"][^'"]+['"]\s*\))"#).unwrap()
});

static RE_BIZ_010_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:process\.env\.NODE_ENV\s*===?\s*['"](?:test|development)['"]|isDevEnv|DEBUG_ONLY)"#).unwrap()
});

static RE_BIZ_010_COMMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)//.*(?:admin backdoor|bypass policy in production|debug bypass active|feature flag bypasses auth)"#).unwrap()
});

// 21. BK-AI-BIZ-011 (CWE-840): Sequence of permitted API calls defeats global quota
static RE_BIZ_011_QUOTA: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)if\s*\(\s*(?:team|subGroup|folder)\.members?\.length\s*<\s*MAX_TEAM_MEMBERS\s*\)"#,
    )
    .unwrap()
});

static RE_BIZ_011_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:org\.total|globalQuota|MAX_GLOBAL|totalMembers|aggregateLimit)"#).unwrap()
});

static RE_BIZ_011_COMMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)//.*(?:defeats global quota|sub-resource bypasses aggregate limit|missing global quota check|aggregate quota bypass)"#).unwrap()
});

// 22. BK-AI-BIZ-012 (CWE-345): Approval decision can be forged or reused
static RE_BIZ_012_APPROVAL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:(?:verifyApproval|validateApproval|checkApprovalSignature)\s*\(\s*(?:sig|signature|approval)\s*\)|if\s*\(\s*(?:approval\.approved|isApproved)\s*&&\s*approval\.signature\s*\)\s*\{[^}]*executeAction\()"#).unwrap()
});

static RE_BIZ_012_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:nonce|actionId|targetId|actionHash|bindPayload|expectedHash|target_id)"#)
        .unwrap()
});

static RE_BIZ_012_COMMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)//.*(?:approval replay|approval can be forged or reused|signature without nonce or target|unbound approval signature)"#).unwrap()
});

// ---------------------------------------------------------------------------
// BizConcurrencyScanner Implementation
// ---------------------------------------------------------------------------

pub struct BizConcurrencyScanner;

impl BizConcurrencyScanner {
    /// Scans source code content for Category 17 (Concurrency & Race Conditions)
    /// and Category 20 (Business Logic & Workflows) vulnerabilities.
    pub fn scan_source(path: &Path, content: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut seen = HashSet::new();

        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if !ext.is_empty()
            && !matches!(
                ext,
                "js" | "mjs"
                    | "cjs"
                    | "ts"
                    | "tsx"
                    | "jsx"
                    | "py"
                    | "go"
                    | "rs"
                    | "java"
                    | "php"
                    | "rb"
            )
        {
            return findings;
        }

        let target_kind = match ext {
            "js" | "mjs" | "cjs" | "ts" | "tsx" | "jsx" => TargetKind::NodeSourceFile,
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

            // Window contexts for multi-line analysis (+/- 8 lines)
            let window_start = idx.saturating_sub(8);
            let window_end = (idx + 9).min(total_lines);
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
            // Category 17: Concurrency & Race Conditions (BK-AI-RAC-001 - 010)
            // ===============================================================

            // 1. BK-AI-RAC-001 (CWE-367): TOCTOU on path, URL, credentials or permissions
            let is_rac_001_vuln = (RE_RAC_001_PATH_CHECK.is_match(trimmed)
                && (RE_RAC_001_PATH_ACT.is_match(&lookahead_window)
                    || RE_RAC_001_PATH_ACT.is_match(&context_window))
                && !RE_RAC_001_GUARD.is_match(&context_window))
                || (RE_RAC_001_PERM_CHECK.is_match(trimmed)
                    && (RE_RAC_001_PERM_ACT.is_match(&lookahead_window)
                        || RE_RAC_001_PERM_ACT.is_match(&context_window))
                    && !RE_RAC_001_GUARD.is_match(&context_window))
                || RE_RAC_001_COMMENT.is_match(trimmed);

            if is_rac_001_vuln && seen.insert(("BK-AI-RAC-001", line_no)) {
                findings.push(Self::create_finding(
                    "BK-AI-RAC-001",
                    "CWE-367",
                    "TOCTOU on path, URL, credentials or permissions",
                    Severity::High,
                    CATEGORY_RAC,
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Check and use must be bound atomically or protected by mutex/transaction.",
                    "Time-of-check to time-of-use (TOCTOU) race condition between file or permission check and subsequent operation.",
                    "Execute operations atomically using file descriptors (O_CREAT|O_EXCL), database row-level locking, or serialized transactions.",
                ));
            }

            // 2. BK-AI-RAC-002 (CWE-362): Double-submit/double-charge due to non-idempotent retries
            let is_rac_002_vuln = (RE_RAC_002_PAYMENT.is_match(trimmed)
                && !RE_RAC_002_GUARD.is_match(&context_window))
                || (RE_RAC_002_RETRY.is_match(trimmed)
                    && context_window.to_lowercase().contains("charge")
                    && !RE_RAC_002_GUARD.is_match(&context_window))
                || RE_RAC_002_COMMENT.is_match(trimmed);

            if is_rac_002_vuln && seen.insert(("BK-AI-RAC-002", line_no)) {
                findings.push(Self::create_finding(
                    "BK-AI-RAC-002",
                    "CWE-362",
                    "Double-submit/double-charge due to non-idempotent retries",
                    Severity::High,
                    CATEGORY_RAC,
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Financial transactions and external state modifications must enforce idempotency keys and retry deduplication.",
                    "Payment or billing charge dispatched without an idempotency key or client retries without transactional deduplication.",
                    "Provide a unique, deterministic idempotency key for all payment mutations and enforce distributed deduplication.",
                ));
            }

            // 3. BK-AI-RAC-003 (CWE-362): Token refresh/rotation race permits replay
            let is_rac_003_vuln = (RE_RAC_003_REFRESH.is_match(trimmed)
                && (RE_RAC_003_ISSUE.is_match(&lookahead_window)
                    || RE_RAC_003_ISSUE.is_match(&context_window))
                && !RE_RAC_003_GUARD.is_match(&context_window))
                || RE_RAC_003_COMMENT.is_match(trimmed);

            if is_rac_003_vuln && seen.insert(("BK-AI-RAC-003", line_no)) {
                findings.push(Self::create_finding(
                    "BK-AI-RAC-003",
                    "CWE-362",
                    "Token refresh/rotation race permits replay",
                    Severity::High,
                    CATEGORY_RAC,
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Token rotation must invalidate token families atomically upon reuse or concurrent exchange.",
                    "Concurrent requests using the same refresh token can produce duplicate active sessions without atomic family invalidation.",
                    "Enforce atomic token rotation with refresh token family tracking and immediate revocation of all family tokens on reuse.",
                ));
            }

            // 4. BK-AI-RAC-004 (CWE-362): Shared mutable state used without synchronization
            let is_rac_004_vuln = ((RE_RAC_004_GO_FUNC.is_match(trimmed)
                || RE_RAC_004_MUTATION.is_match(trimmed)
                || RE_RAC_004_RUST_STATIC_MUT.is_match(trimmed))
                && (RE_RAC_004_MUTATION.is_match(&context_window)
                    || RE_RAC_004_RUST_STATIC_MUT.is_match(trimmed))
                && !RE_RAC_004_GUARD.is_match(&context_window))
                || RE_RAC_004_COMMENT.is_match(trimmed);

            if is_rac_004_vuln && seen.insert(("BK-AI-RAC-004", line_no)) {
                findings.push(Self::create_finding(
                    "BK-AI-RAC-004",
                    "CWE-362",
                    "Shared mutable state used without synchronization",
                    Severity::High,
                    CATEGORY_RAC,
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Shared mutable state accessed across threads or async routines must be synchronized via mutexes or atomics.",
                    "Global or shared variable modified in multi-threaded/concurrent execution path without synchronization primitives.",
                    "Wrap shared mutable state with Mutex, RwLock, atomic variables, or use thread-safe data structures.",
                ));
            }

            // 5. BK-AI-RAC-005 (CWE-662): Queue message acknowledged before durable transaction
            let is_rac_005_vuln = (RE_RAC_005_ACK.is_match(trimmed)
                && RE_RAC_005_PROCESS.is_match(&lookahead_window)
                && !RE_RAC_005_GUARD.is_match(&context_window))
                || RE_RAC_005_COMMENT.is_match(trimmed);

            if is_rac_005_vuln && seen.insert(("BK-AI-RAC-005", line_no)) {
                findings.push(Self::create_finding(
                    "BK-AI-RAC-005",
                    "CWE-662",
                    "Queue message acknowledged before durable and authorized transaction",
                    Severity::High,
                    CATEGORY_RAC,
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Queue messages must only be acknowledged after processing and persistent transaction commit.",
                    "Premature queue message acknowledgment risks data loss if subsequent processing fails or crashes.",
                    "Defer message acknowledgment until all business transactions and DB commits are successfully completed.",
                ));
            }

            // 6. BK-AI-RAC-006 (CWE-613): Stale cache permission survives user removal/role downgrade
            let is_rac_006_vuln = RE_RAC_006_CACHE_INDEFINITE.is_match(trimmed)
                || (RE_RAC_006_MUTATE_ROLE.is_match(trimmed)
                    && !RE_RAC_006_GUARD.is_match(&context_window))
                || RE_RAC_006_COMMENT.is_match(trimmed);

            if is_rac_006_vuln && seen.insert(("BK-AI-RAC-006", line_no)) {
                findings.push(Self::create_finding(
                    "BK-AI-RAC-006",
                    "CWE-613",
                    "Stale cache permission survives user removal/role downgrade",
                    Severity::High,
                    CATEGORY_RAC,
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Permission and role changes must immediately invalidate or evict associated cached authorization entries.",
                    "Cached user permissions or roles remain valid after account deactivation or role downgrade due to missing cache invalidation.",
                    "Purge or invalidate authorization cache entries immediately on user removal, role changes, or permission revocations.",
                ));
            }

            // 7. BK-AI-RAC-007 (CWE-362): Optimistic update race bypasses inventory/limit/policy check
            let is_rac_007_vuln = (RE_RAC_007_CHECK.is_match(trimmed)
                && (RE_RAC_007_ACT.is_match(&lookahead_window)
                    || RE_RAC_007_ACT.is_match(&context_window))
                && !RE_RAC_007_GUARD.is_match(&context_window))
                || RE_RAC_007_COMMENT.is_match(trimmed);

            if is_rac_007_vuln && seen.insert(("BK-AI-RAC-007", line_no)) {
                findings.push(Self::create_finding(
                    "BK-AI-RAC-007",
                    "CWE-362",
                    "Optimistic update race bypasses inventory/limit/policy check",
                    Severity::High,
                    CATEGORY_RAC,
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Resource deductions and limit checks must be performed atomically at the database or storage layer.",
                    "Non-atomic check-then-decrement allows concurrent requests to oversell inventory or exceed credit limits.",
                    "Use atomic conditional updates (e.g., UPDATE ... WHERE stock >= requested) or pessimistic row locks (SELECT FOR UPDATE).",
                ));
            }

            // 8. BK-AI-RAC-008 (CWE-362): Distributed lease/lock expires during privileged operation
            let is_rac_008_vuln = (RE_RAC_008_LOCK.is_match(trimmed)
                && (RE_RAC_008_LONG_OP.is_match(&lookahead_window)
                    || RE_RAC_008_LONG_OP.is_match(&context_window))
                && !RE_RAC_008_GUARD.is_match(&context_window))
                || RE_RAC_008_COMMENT.is_match(trimmed);

            if is_rac_008_vuln && seen.insert(("BK-AI-RAC-008", line_no)) {
                findings.push(Self::create_finding(
                    "BK-AI-RAC-008",
                    "CWE-362",
                    "Distributed lease/lock expires during privileged operation",
                    Severity::High,
                    CATEGORY_RAC,
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Distributed leases must include active heartbeats or fencing tokens to prevent concurrent execution on expiry.",
                    "Distributed lock with fixed TTL expires while a long-running privileged task is executing, admitting a second concurrent worker.",
                    "Implement lease renewal heartbeats, automatic lock extension, or fencing tokens checked at commit time.",
                ));
            }

            // 9. BK-AI-RAC-009 (CWE-367): Background cleanup races with file upload or healing
            let is_rac_009_vuln = (RE_RAC_009_CLEANUP.is_match(trimmed)
                && RE_RAC_009_CRON_CONTEXT.is_match(&context_window)
                && !RE_RAC_009_GUARD.is_match(&context_window))
                || RE_RAC_009_COMMENT.is_match(trimmed);

            if is_rac_009_vuln && seen.insert(("BK-AI-RAC-009", line_no)) {
                findings.push(Self::create_finding(
                    "BK-AI-RAC-009",
                    "CWE-367",
                    "Background cleanup races with file upload or healing transaction",
                    Severity::High,
                    CATEGORY_RAC,
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Cleanup routines must inspect file modification age or active transfer locks before deletion.",
                    "Automated cleanup or cron job deletes temporary files that are actively being streamed or processed.",
                    "Check file age against a conservative threshold (mtime > retention) and verify that no active upload lock is held.",
                ));
            }

            // 10. BK-AI-RAC-010 (CWE-362): Concurrent agents act on same target without serialization
            let is_rac_010_vuln = (RE_RAC_010_AGENT.is_match(trimmed)
                && !RE_RAC_010_GUARD.is_match(&context_window))
                || RE_RAC_010_COMMENT.is_match(trimmed);

            if is_rac_010_vuln && seen.insert(("BK-AI-RAC-010", line_no)) {
                findings.push(Self::create_finding(
                    "BK-AI-RAC-010",
                    "CWE-362",
                    "Concurrent agents act on same target without serialization/ownership",
                    Severity::High,
                    CATEGORY_RAC,
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Multi-agent systems must serialize access to target files or resources via advisory locking or ownership leases.",
                    "Multiple autonomous agents or worker tasks mutate the same source file or environment without concurrency coordination.",
                    "Enforce file-level locks or distributed workspace leases before allowing autonomous agents to apply file modifications.",
                ));
            }

            // ===============================================================
            // Category 20: Business Logic & Workflows (BK-AI-BIZ-001 - 012)
            // ===============================================================

            // 11. BK-AI-BIZ-001 (CWE-602): Payment amount trusted from client
            let is_biz_001_vuln = (RE_BIZ_001_CLIENT_AMOUNT.is_match(trimmed)
                && RE_BIZ_001_CHARGE.is_match(&context_window)
                && !RE_BIZ_001_GUARD.is_match(&context_window))
                || (RE_BIZ_001_DESTRUCT_AMOUNT.is_match(trimmed)
                    && RE_BIZ_001_CHARGE.is_match(&context_window)
                    && !RE_BIZ_001_GUARD.is_match(&context_window))
                || RE_BIZ_001_COMMENT.is_match(trimmed);

            if is_biz_001_vuln && seen.insert(("BK-AI-BIZ-001", line_no)) {
                findings.push(Self::create_finding(
                    "BK-AI-BIZ-001",
                    "CWE-602",
                    "Payment amount, discount, currency or recipient trusted from client",
                    Severity::Critical,
                    CATEGORY_BIZ,
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Payment monetary values, currency codes, and recipient accounts must be calculated server-side from authoritative catalogs.",
                    "Payment or checkout amounts accepted directly from untrusted client request parameters without server-side catalog validation.",
                    "Derive all prices, discount percentages, and currency specifications strictly from database product catalogs on the server.",
                ));
            }

            // 12. BK-AI-BIZ-002 (CWE-840): User can reuse coupon/credit beyond permitted count
            let is_biz_002_vuln = (RE_BIZ_002_COUPON.is_match(trimmed)
                && !RE_BIZ_002_GUARD.is_match(&context_window))
                || (RE_BIZ_002_FUNC.is_match(trimmed)
                    && !RE_BIZ_002_GUARD.is_match(&context_window))
                || RE_BIZ_002_COMMENT.is_match(trimmed);

            if is_biz_002_vuln && seen.insert(("BK-AI-BIZ-002", line_no)) {
                findings.push(Self::create_finding(
                    "BK-AI-BIZ-002",
                    "CWE-840",
                    "User can reuse coupon/credit/refund/redeem token beyond permitted count",
                    Severity::High,
                    CATEGORY_BIZ,
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Promotional redemptions, coupons, and credit allowances must enforce single-use atomic consumption records.",
                    "Coupons or reward redemption tokens applied without atomic consumption verification, allowing unlimited reuse.",
                    "Atomically record redemption per user or coupon in the database, verifying redemption count does not exceed the allowed threshold.",
                ));
            }

            // 13. BK-AI-BIZ-003 (CWE-841): State-changing workflow can skip required step
            let is_biz_003_vuln = (RE_BIZ_003_SKIP.is_match(trimmed)
                && !RE_BIZ_003_GUARD.is_match(&context_window))
                || RE_BIZ_003_COMMENT.is_match(trimmed);

            if is_biz_003_vuln && seen.insert(("BK-AI-BIZ-003", line_no)) {
                findings.push(Self::create_finding(
                    "BK-AI-BIZ-003",
                    "CWE-841",
                    "State-changing workflow can skip required step or approval",
                    Severity::High,
                    CATEGORY_BIZ,
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Workflow state transitions must enforce strict sequential invariants and prerequisite validation.",
                    "State machine transitions allowed to jump directly to a completed or fulfilled status without fulfilling intermediate prerequisites.",
                    "Model business workflows with explicit state machines that strictly enforce prerequisite state checks prior to transition.",
                ));
            }

            // 14. BK-AI-BIZ-004 (CWE-862): Role change/invite lacks proper authorization
            let is_biz_004_vuln = ((RE_BIZ_004_ENDPOINT.is_match(trimmed)
                || RE_BIZ_004_FUNC.is_match(trimmed))
                && !RE_BIZ_004_GUARD.is_match(&context_window))
                || RE_BIZ_004_COMMENT.is_match(trimmed);

            if is_biz_004_vuln && seen.insert(("BK-AI-BIZ-004", line_no)) {
                findings.push(Self::create_finding(
                    "BK-AI-BIZ-004",
                    "CWE-862",
                    "Role change/invite/ownership transfer lacks proper authorization and notice",
                    Severity::High,
                    CATEGORY_BIZ,
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Privilege elevation, ownership transfer, and administrative invitations must verify caller authority.",
                    "Endpoints permitting role updates, invitations, or organization ownership transfer fail to verify administrative authorization.",
                    "Verify caller possesses required administrative or owner privileges before executing role or ownership changes.",
                ));
            }

            // 15. BK-AI-BIZ-005 (CWE-362): Idempotency key not actor-bound
            let is_biz_005_vuln = (RE_BIZ_005_KEY.is_match(trimmed)
                && RE_BIZ_005_CACHE.is_match(&context_window)
                && !RE_BIZ_005_GUARD.is_match(&context_window))
                || RE_BIZ_005_COMMENT.is_match(trimmed);

            if is_biz_005_vuln && seen.insert(("BK-AI-BIZ-005", line_no)) {
                findings.push(Self::create_finding(
                    "BK-AI-BIZ-005",
                    "CWE-362",
                    "Idempotency key not actor-bound or expires incorrectly",
                    Severity::High,
                    CATEGORY_BIZ,
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Idempotency storage keys must be namespaced with actor identity and have bounded expiration.",
                    "Idempotency cache keys are keyed purely by client-supplied tokens without user or tenant scoping, enabling collision or hijacking.",
                    "Prefix idempotency keys with the authenticated tenant and user identifier (${tenant}:${user}:${key}) and assign finite TTLs.",
                ));
            }

            // 16. BK-AI-BIZ-006 (CWE-841): Order completion performed without verified settlement
            let is_biz_006_vuln = (RE_BIZ_006_EVENT.is_match(trimmed)
                && (RE_BIZ_006_FULFILL.is_match(trimmed)
                    || RE_BIZ_006_FULFILL.is_match(&lookahead_window)
                    || RE_BIZ_006_FULFILL.is_match(&context_window)))
                || RE_BIZ_006_COMMENT.is_match(trimmed);

            if is_biz_006_vuln && seen.insert(("BK-AI-BIZ-006", line_no)) {
                findings.push(Self::create_finding(
                    "BK-AI-BIZ-006",
                    "CWE-841",
                    "Order completion performed without verified settlement/fulfilment state",
                    Severity::High,
                    CATEGORY_BIZ,
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Orders must only be marked paid or fulfilled upon receipt of verified financial settlement events.",
                    "Fulfillment or credit grant triggered on session creation or pending status instead of definitive settlement confirmation.",
                    "Restructure webhook and callback listeners to fulfill orders strictly on definitive settlement events (payment_intent.succeeded).",
                ));
            }

            // 17. BK-AI-BIZ-007 (CWE-841): Reused webhook event alters account more than once
            let is_biz_007_vuln = (RE_BIZ_007_WEBHOOK.is_match(trimmed)
                && RE_BIZ_007_MUTATE.is_match(&context_window)
                && !RE_BIZ_007_GUARD.is_match(&context_window))
                || RE_BIZ_007_COMMENT.is_match(trimmed);

            if is_biz_007_vuln && seen.insert(("BK-AI-BIZ-007", line_no)) {
                findings.push(Self::create_finding(
                    "BK-AI-BIZ-007",
                    "CWE-841",
                    "Reused webhook event alters account more than once",
                    Severity::High,
                    CATEGORY_BIZ,
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Inbound webhook processing must record processed event identifiers to prevent replay execution.",
                    "Webhook processor fails to deduplicate incoming events, causing duplicate credit deposits or status toggles upon replay.",
                    "Store unique event identifiers in a dedicated deduplication table and check existence prior to state-altering mutations.",
                ));
            }

            // 18. BK-AI-BIZ-008 (CWE-613): Account deletion misses shared resources or leaves active keys
            let is_biz_008_vuln = (RE_BIZ_008_DELETE.is_match(trimmed)
                && RE_BIZ_008_MUTATE.is_match(&context_window)
                && !RE_BIZ_008_GUARD.is_match(&context_window))
                || RE_BIZ_008_COMMENT.is_match(trimmed);

            if is_biz_008_vuln && seen.insert(("BK-AI-BIZ-008", line_no)) {
                findings.push(Self::create_finding(
                    "BK-AI-BIZ-008",
                    "CWE-613",
                    "Account deletion/transfer misses shared resources or leaves active keys",
                    Severity::High,
                    CATEGORY_BIZ,
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "User or tenant deletion workflows must cascade to revoke all access credentials and API tokens.",
                    "Account termination deletes user record while leaving API tokens, webhooks, or oauth grants active.",
                    "Execute account deletion within an atomic transaction that explicitly revokes all API keys, OAuth tokens, and access credentials.",
                ));
            }

            // 19. BK-AI-BIZ-009 (CWE-200): Multi-tenant report aggregates before access filtering
            let is_biz_009_vuln = (RE_BIZ_009_AGG.is_match(trimmed)
                && !RE_BIZ_009_GUARD.is_match(&context_window))
                || RE_BIZ_009_COMMENT.is_match(trimmed);

            if is_biz_009_vuln && seen.insert(("BK-AI-BIZ-009", line_no)) {
                findings.push(Self::create_finding(
                    "BK-AI-BIZ-009",
                    "CWE-200",
                    "Multi-tenant report aggregates privileged records before access filtering",
                    Severity::High,
                    CATEGORY_BIZ,
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Multi-tenant metrics and analytics queries must partition aggregation by tenant identifier.",
                    "Aggregate statistical query computes totals over all tenants without scoping records by tenant ID.",
                    "Enforce strict tenant filtering in the WHERE / $match clause prior to computing aggregate statistics.",
                ));
            }

            // 20. BK-AI-BIZ-010 (CWE-862): Feature flag/admin backdoor bypasses required policy
            let is_biz_010_vuln = (RE_BIZ_010_BYPASS.is_match(trimmed)
                && !RE_BIZ_010_GUARD.is_match(&context_window))
                || RE_BIZ_010_COMMENT.is_match(trimmed);

            if is_biz_010_vuln && seen.insert(("BK-AI-BIZ-010", line_no)) {
                findings.push(Self::create_finding(
                    "BK-AI-BIZ-010",
                    "CWE-862",
                    "Feature flag/admin backdoor bypasses required policy in production",
                    Severity::Critical,
                    CATEGORY_BIZ,
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Development bypasses, debug overrides, and administrative backdoor flags must be completely absent in production builds.",
                    "Production-accessible debug headers or feature flags allow callers to bypass authorization or security policies.",
                    "Eliminate backdoor override headers or strictly gate them behind non-production environment checks (NODE_ENV === 'test').",
                ));
            }

            // 21. BK-AI-BIZ-011 (CWE-840): Sequence of permitted API calls defeats global quota
            let is_biz_011_vuln = (RE_BIZ_011_QUOTA.is_match(trimmed)
                && !RE_BIZ_011_GUARD.is_match(&context_window))
                || RE_BIZ_011_COMMENT.is_match(trimmed);

            if is_biz_011_vuln && seen.insert(("BK-AI-BIZ-011", line_no)) {
                findings.push(Self::create_finding(
                    "BK-AI-BIZ-011",
                    "CWE-840",
                    "Sequence of individually permitted API calls defeats a global quota",
                    Severity::High,
                    CATEGORY_BIZ,
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Hierarchical sub-resource creations must evaluate and increment aggregate global organization quotas.",
                    "Sub-resource creations only validate local bucket capacity, permitting callers to exceed organization-wide quotas.",
                    "Evaluate cumulative account or organization consumption alongside local bucket limits during resource provisioning.",
                ));
            }

            // 22. BK-AI-BIZ-012 (CWE-345): Approval decision can be forged or reused
            let is_biz_012_vuln = (RE_BIZ_012_APPROVAL.is_match(trimmed)
                && !RE_BIZ_012_GUARD.is_match(&context_window))
                || RE_BIZ_012_COMMENT.is_match(trimmed);

            if is_biz_012_vuln && seen.insert(("BK-AI-BIZ-012", line_no)) {
                findings.push(Self::create_finding(
                    "BK-AI-BIZ-012",
                    "CWE-345",
                    "Approval decision can be forged/reused for another action or target",
                    Severity::High,
                    CATEGORY_BIZ,
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Cryptographic approval authorizations must bind action details, target resource IDs, and single-use nonces.",
                    "Approval signature verification does not bind the signature to specific target resource IDs or nonces, enabling cross-target reuse.",
                    "Bind cryptographic signatures to the specific action type, target resource hash, timestamp, and single-use nonce.",
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
        finding.detector_id = "biz-concurrency".to_string();
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
