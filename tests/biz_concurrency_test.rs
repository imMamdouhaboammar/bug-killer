#[path = "../src/scanner/biz_concurrency.rs"]
mod biz_concurrency;

use biz_concurrency::BizConcurrencyScanner;
pub use bug_killer::types;
use bug_killer::types::Severity;
use std::path::Path;

// ===========================================================================
// Category 17: Concurrency, Workflow State & Race Conditions (RAC-001 - 010)
// ===========================================================================

#[test]
fn test_rac_001_toctou_vulnerable_and_safe() {
    let vuln_code = r#"
const fs = require('fs');

function readConfigFile(filePath) {
    if (fs.existsSync(filePath)) {
        return fs.readFileSync(filePath, 'utf-8');
    }
    return null;
}
"#;
    let path = Path::new("src/config_loader.js");
    let findings = BizConcurrencyScanner::scan_source(path, vuln_code);

    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-RAC-001")
        .expect("Must flag TOCTOU on fs.existsSync followed by readFileSync");
    assert_eq!(f.severity, Severity::High);
    assert_eq!(f.detector_id, "biz-concurrency");
    assert!(f.advisory_ids.contains(&"CWE-367".to_string()));

    let safe_code = r#"
const fs = require('fs');

function readConfigFile(filePath) {
    try {
        return fs.readFileSync(filePath, 'utf-8');
    } catch (err) {
        if (err.code === 'ENOENT') return null;
        throw err;
    }
}
"#;
    let safe_findings = BizConcurrencyScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-RAC-001"),
        "Must not flag when atomic error handling try/catch is present"
    );
}

#[test]
fn test_rac_002_double_charge_vulnerable_and_safe() {
    let vuln_code = r#"
async function chargeCustomer(token, amount) {
    const charge = await stripe.charges.create({
        amount: amount,
        currency: 'usd',
        source: token,
    });
    return charge;
}
"#;
    let path = Path::new("services/billing.ts");
    let findings = BizConcurrencyScanner::scan_source(path, vuln_code);

    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-RAC-002")
        .expect("Must flag payment charge without idempotency key");
    assert_eq!(f.severity, Severity::High);
    assert_eq!(f.detector_id, "biz-concurrency");
    assert!(f.advisory_ids.contains(&"CWE-362".to_string()));

    let safe_code = r#"
async function chargeCustomer(token, amount, orderId) {
    const charge = await stripe.charges.create(
        {
            amount: amount,
            currency: 'usd',
            source: token,
        },
        {
            idempotencyKey: `order_${orderId}`,
        }
    );
    return charge;
}
"#;
    let safe_findings = BizConcurrencyScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-RAC-002"),
        "Must not flag when idempotencyKey is supplied"
    );
}

#[test]
fn test_rac_003_token_refresh_race_vulnerable_and_safe() {
    let vuln_code = r#"
async function refreshTokens(refreshToken) {
    const session = await findRefreshToken(refreshToken);
    if (!session) throw new Error("Invalid refresh token");
    const newTokens = generateTokens(session.userId);
    await saveSession(newTokens);
    return newTokens;
}
"#;
    let path = Path::new("src/auth/token_service.js");
    let findings = BizConcurrencyScanner::scan_source(path, vuln_code);

    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-RAC-003")
        .expect("Must flag token refresh race without family invalidation");
    assert_eq!(f.severity, Severity::High);
    assert_eq!(f.detector_id, "biz-concurrency");
    assert!(f.advisory_ids.contains(&"CWE-362".to_string()));

    let safe_code = r#"
async function refreshTokens(refreshToken) {
    const session = await findRefreshToken(refreshToken);
    if (session.isRevoked) {
        await tokenFamily.revokeAll(session.familyId);
        throw new Error("Token replay detected - invalidating token family");
    }
    return await atomicRotateToken(refreshToken);
}
"#;
    let safe_findings = BizConcurrencyScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-RAC-003"),
        "Must not flag when tokenFamily revocation and atomicRotate are used"
    );
}

#[test]
fn test_rac_004_shared_mutable_state_vulnerable_and_safe() {
    let vuln_code = r#"
package main

var sharedCounter int

func handleEvent() {
    go func() {
        sharedCounter++
    }()
}
"#;
    let path = Path::new("server/metrics.go");
    let findings = BizConcurrencyScanner::scan_source(path, vuln_code);

    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-RAC-004")
        .expect("Must flag shared mutable counter without synchronization");
    assert_eq!(f.severity, Severity::High);
    assert_eq!(f.detector_id, "biz-concurrency");
    assert!(f.advisory_ids.contains(&"CWE-362".to_string()));

    let safe_code = r#"
package main

import "sync/atomic"

var sharedCounter int64

func handleEvent() {
    go func() {
        atomic.AddInt64(&sharedCounter, 1)
    }()
}
"#;
    let safe_findings = BizConcurrencyScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-RAC-004"),
        "Must not flag when atomic operations are used"
    );
}

#[test]
fn test_rac_005_early_ack_vulnerable_and_safe() {
    let vuln_code = r#"
channel.consume(queue, async (msg) => {
    channel.ack(msg);
    await processOrder(JSON.parse(msg.content.toString()));
});
"#;
    let path = Path::new("workers/order_consumer.js");
    let findings = BizConcurrencyScanner::scan_source(path, vuln_code);

    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-RAC-005")
        .expect("Must flag early queue acknowledgment before processOrder");
    assert_eq!(f.severity, Severity::High);
    assert_eq!(f.detector_id, "biz-concurrency");
    assert!(f.advisory_ids.contains(&"CWE-662".to_string()));

    let safe_code = r#"
channel.consume(queue, async (msg) => {
    try {
        await processOrder(JSON.parse(msg.content.toString()));
    } finally {
        channel.ack(msg);
    }
});
"#;
    let safe_findings = BizConcurrencyScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-RAC-005"),
        "Must not flag when ack is inside finally block after processing"
    );
}

#[test]
fn test_rac_006_stale_cache_permission_vulnerable_and_safe() {
    let vuln_code = r#"
async function updateUserRole(userId, newRole) {
    await db.users.update({ id: userId }, { role: newRole });
    // Note: missing cache eviction leaves user permissions cached
}
"#;
    let path = Path::new("services/user_service.ts");
    let findings = BizConcurrencyScanner::scan_source(path, vuln_code);

    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-RAC-006")
        .expect("Must flag role update without cache eviction");
    assert_eq!(f.severity, Severity::High);
    assert_eq!(f.detector_id, "biz-concurrency");
    assert!(f.advisory_ids.contains(&"CWE-613".to_string()));

    let safe_code = r#"
async function updateUserRole(userId, newRole) {
    await db.users.update({ id: userId }, { role: newRole });
    await cache.del(`user_roles:${userId}`);
}
"#;
    let safe_findings = BizConcurrencyScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-RAC-006"),
        "Must not flag when cache.del is executed on role update"
    );
}

#[test]
fn test_rac_007_optimistic_inventory_race_vulnerable_and_safe() {
    let vuln_code = r#"
async function checkoutItem(itemId, qty) {
    const item = await db.items.findById(itemId);
    if (item.stock >= qty) {
        item.stock -= qty;
        await db.items.save(item);
    }
}
"#;
    let path = Path::new("controllers/shop.js");
    let findings = BizConcurrencyScanner::scan_source(path, vuln_code);

    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-RAC-007")
        .expect("Must flag non-atomic stock check and decrement");
    assert_eq!(f.severity, Severity::High);
    assert_eq!(f.detector_id, "biz-concurrency");
    assert!(f.advisory_ids.contains(&"CWE-362".to_string()));

    let safe_code = r#"
async function checkoutItem(itemId, qty) {
    const result = await db.query(
        "UPDATE items SET stock = stock - ? WHERE id = ? AND stock >= ?",
        [qty, itemId, qty]
    );
    return result;
}
"#;
    let safe_findings = BizConcurrencyScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-RAC-007"),
        "Must not flag when atomic SQL WHERE stock >= requested is enforced"
    );
}

#[test]
fn test_rac_008_distributed_lock_expiry_vulnerable_and_safe() {
    let vuln_code = r#"
async function runDataMigration() {
    const lock = await redlock.acquire(['db_migration'], 5000);
    await processBatchRecords();
    await lock.release();
}
"#;
    let path = Path::new("jobs/migration.ts");
    let findings = BizConcurrencyScanner::scan_source(path, vuln_code);

    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-RAC-008")
        .expect("Must flag distributed lock without heartbeat/renewal");
    assert_eq!(f.severity, Severity::High);
    assert_eq!(f.detector_id, "biz-concurrency");
    assert!(f.advisory_ids.contains(&"CWE-362".to_string()));

    let safe_code = r#"
async function runDataMigration() {
    const lock = await redlock.acquire(['db_migration'], 5000);
    const heartbeat = setInterval(() => lock.extend(5000), 2000);
    try {
        await processBatchRecords();
    } finally {
        clearInterval(heartbeat);
        await lock.release();
    }
}
"#;
    let safe_findings = BizConcurrencyScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-RAC-008"),
        "Must not flag when heartbeat renewal is active"
    );
}

#[test]
fn test_rac_009_cleanup_race_upload_vulnerable_and_safe() {
    let vuln_code = r#"
cron.schedule('0 * * * *', () => {
    const files = fs.readdirSync('/tmp/uploads');
    files.forEach(file => {
        fs.unlinkSync('/tmp/uploads/' + file);
    });
});
"#;
    let path = Path::new("schedulers/cleaner.js");
    let findings = BizConcurrencyScanner::scan_source(path, vuln_code);

    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-RAC-009")
        .expect("Must flag cleanup cron deleting active uploads without age or lock check");
    assert_eq!(f.severity, Severity::High);
    assert_eq!(f.detector_id, "biz-concurrency");
    assert!(f.advisory_ids.contains(&"CWE-367".to_string()));

    let safe_code = r#"
cron.schedule('0 * * * *', () => {
    const files = fs.readdirSync('/tmp/uploads');
    const now = Date.now();
    files.forEach(file => {
        const stats = fs.statSync(file);
        if (now - stats.mtimeMs > 24 * 3600 * 1000 && !activeUploads.has(file)) {
            fs.unlinkSync(file);
        }
    });
});
"#;
    let safe_findings = BizConcurrencyScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-RAC-009"),
        "Must not flag when mtime check and activeUploads guard exist"
    );
}

#[test]
fn test_rac_010_concurrent_agents_vulnerable_and_safe() {
    let vuln_code = r#"
async function agentMutate(targetPath, diff) {
    const content = await fs.readFile(targetPath, 'utf-8');
    const patched = applyPatch(content, diff);
    await fs.writeFile(targetPath, patched);
}
"#;
    let path = Path::new("agents/worker.ts");
    let findings = BizConcurrencyScanner::scan_source(path, vuln_code);

    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-RAC-010")
        .expect("Must flag agent mutation without serialization or file lock");
    assert_eq!(f.severity, Severity::High);
    assert_eq!(f.detector_id, "biz-concurrency");
    assert!(f.advisory_ids.contains(&"CWE-362".to_string()));

    let safe_code = r#"
async function agentMutate(targetPath, diff) {
    await withLock(targetPath, async () => {
        const content = await fs.readFile(targetPath, 'utf-8');
        const patched = applyPatch(content, diff);
        await fs.writeFile(targetPath, patched);
    });
}
"#;
    let safe_findings = BizConcurrencyScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-RAC-010"),
        "Must not flag when withLock serialization wraps agent mutation"
    );
}

// ===========================================================================
// Category 20: Business Logic & Monetary/Privileged Effects (BIZ-001 - 012)
// ===========================================================================

#[test]
fn test_biz_001_client_price_trust_vulnerable_and_safe() {
    let vuln_code = r#"
app.post('/checkout', async (req, res) => {
    const session = await stripe.checkout.sessions.create({
        amount: req.body.amount,
        currency: 'usd',
    });
    res.json(session);
});
"#;
    let path = Path::new("routes/checkout.js");
    let findings = BizConcurrencyScanner::scan_source(path, vuln_code);

    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-BIZ-001")
        .expect("Must flag payment amount accepted directly from req.body");
    assert_eq!(f.severity, Severity::Critical);
    assert_eq!(f.detector_id, "biz-concurrency");
    assert!(f.advisory_ids.contains(&"CWE-602".to_string()));

    let safe_code = r#"
app.post('/checkout', async (req, res) => {
    const product = await db.products.findById(req.body.productId);
    const session = await stripe.checkout.sessions.create({
        amount: product.price,
        currency: 'usd',
    });
    res.json(session);
});
"#;
    let safe_findings = BizConcurrencyScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-BIZ-001"),
        "Must not flag when price is derived from database product catalog"
    );
}

#[test]
fn test_biz_002_coupon_reuse_vulnerable_and_safe() {
    let vuln_code = r#"
function applyCoupon(cart, code) {
    if (code === 'HALFOFF') {
        cart.total = cart.total * 0.5;
    }
}
"#;
    let path = Path::new("services/discount.ts");
    let findings = BizConcurrencyScanner::scan_source(path, vuln_code);

    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-BIZ-002")
        .expect("Must flag unrecorded coupon application allowing unlimited reuse");
    assert_eq!(f.severity, Severity::High);
    assert_eq!(f.detector_id, "biz-concurrency");
    assert!(f.advisory_ids.contains(&"CWE-840".to_string()));

    let safe_code = r#"
async function applyCoupon(userId, cart, code) {
    const redemptions = await db.redemptions.count({ userId, code });
    if (redemptions >= 1) {
        throw new Error("Coupon already redeemed by user");
    }
    await db.redemptions.create({ userId, code, redeemedAt: new Date() });
    cart.total = cart.total * 0.5;
}
"#;
    let safe_findings = BizConcurrencyScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-BIZ-002"),
        "Must not flag when redemption count and record creation are enforced"
    );
}

#[test]
fn test_biz_003_skip_order_status_vulnerable_and_safe() {
    let vuln_code = r#"
app.post('/orders/:id/fulfill', async (req, res) => {
    await updateOrderStatus(req.params.id, { status: 'fulfilled' });
    res.send({ status: 'ok' });
});
"#;
    let path = Path::new("routes/fulfillment.js");
    let findings = BizConcurrencyScanner::scan_source(path, vuln_code);

    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-BIZ-003")
        .expect("Must flag order fulfillment skipping prerequisite paid check");
    assert_eq!(f.severity, Severity::High);
    assert_eq!(f.detector_id, "biz-concurrency");
    assert!(f.advisory_ids.contains(&"CWE-841".to_string()));

    let safe_code = r#"
app.post('/orders/:id/fulfill', async (req, res) => {
    const order = await db.orders.findById(req.params.id);
    if (order.status !== 'PAID') {
        return res.status(400).send("Order is not in paid status");
    }
    await updateOrderStatus(order.id, { status: 'fulfilled' });
    res.send({ status: 'ok' });
});
"#;
    let safe_findings = BizConcurrencyScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-BIZ-003"),
        "Must not flag when prerequisite order.status check is enforced"
    );
}

#[test]
fn test_biz_004_role_change_no_auth_vulnerable_and_safe() {
    let vuln_code = r#"
app.post('/users/:id/role', async (req, res) => {
    await db.users.update(req.params.id, { role: req.body.role });
    res.json({ success: true });
});
"#;
    let path = Path::new("routes/admin.js");
    let findings = BizConcurrencyScanner::scan_source(path, vuln_code);

    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-BIZ-004")
        .expect("Must flag role update endpoint lacking authorization check");
    assert_eq!(f.severity, Severity::High);
    assert_eq!(f.detector_id, "biz-concurrency");
    assert!(f.advisory_ids.contains(&"CWE-862".to_string()));

    let safe_code = r#"
app.post('/users/:id/role', async (req, res) => {
    if (!req.user.isAdmin) {
        return res.status(403).send("Admin privileges required");
    }
    await db.users.update(req.params.id, { role: req.body.role });
    res.json({ success: true });
});
"#;
    let safe_findings = BizConcurrencyScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-BIZ-004"),
        "Must not flag when isAdmin authorization is validated"
    );
}

#[test]
fn test_biz_005_unbound_idempotency_key_vulnerable_and_safe() {
    let vuln_code = r#"
app.post('/transfers', async (req, res) => {
    const key = req.headers['idempotency-key'];
    const cached = await cache.get(key);
    if (cached) return res.json(cached);
    const result = await executeTransfer(req.body);
    await cache.set(key, result);
    res.json(result);
});
"#;
    let path = Path::new("controllers/transfer.ts");
    let findings = BizConcurrencyScanner::scan_source(path, vuln_code);

    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-BIZ-005")
        .expect("Must flag idempotency key cached without tenant or user namespace");
    assert_eq!(f.severity, Severity::High);
    assert_eq!(f.detector_id, "biz-concurrency");
    assert!(f.advisory_ids.contains(&"CWE-362".to_string()));

    let safe_code = r#"
app.post('/transfers', async (req, res) => {
    const rawKey = req.headers['idempotency-key'];
    const key = `${req.user.tenantId}:${req.user.id}:${rawKey}`;
    const cached = await cache.get(key);
    if (cached) return res.json(cached);
    const result = await executeTransfer(req.body);
    await cache.set(key, result);
    res.json(result);
});
"#;
    let safe_findings = BizConcurrencyScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-BIZ-005"),
        "Must not flag when key is bound to tenantId and userId"
    );
}

#[test]
fn test_biz_006_fulfill_on_created_vulnerable_and_safe() {
    let vuln_code = r#"
switch (event.type) {
    case 'checkout.session.created':
        await markOrderPaid(session.client_reference_id);
        break;
}
"#;
    let path = Path::new("webhooks/stripe.js");
    let findings = BizConcurrencyScanner::scan_source(path, vuln_code);

    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-BIZ-006")
        .expect("Must flag order fulfilled on created event rather than succeeded");
    assert_eq!(f.severity, Severity::High);
    assert_eq!(f.detector_id, "biz-concurrency");
    assert!(f.advisory_ids.contains(&"CWE-841".to_string()));

    let safe_code = r#"
switch (event.type) {
    case 'payment_intent.succeeded':
        await markOrderPaid(intent.metadata.order_id);
        break;
}
"#;
    let safe_findings = BizConcurrencyScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-BIZ-006"),
        "Must not flag when order is fulfilled on payment_intent.succeeded"
    );
}

#[test]
fn test_biz_007_webhook_no_dedup_vulnerable_and_safe() {
    let vuln_code = r#"
app.post('/api/webhook', async (req, res) => {
    const event = req.body;
    if (event.type === 'charge.succeeded') {
        await addCredits(event.customer, 100);
    }
    res.sendStatus(200);
});
"#;
    let path = Path::new("routes/webhooks.js");
    let findings = BizConcurrencyScanner::scan_source(path, vuln_code);

    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-BIZ-007")
        .expect("Must flag webhook route altering credits without event deduplication");
    assert_eq!(f.severity, Severity::High);
    assert_eq!(f.detector_id, "biz-concurrency");
    assert!(f.advisory_ids.contains(&"CWE-841".to_string()));

    let safe_code = r#"
app.post('/api/webhook', async (req, res) => {
    const event = req.body;
    if (await db.processedEvents.has(event.id)) {
        return res.sendStatus(200);
    }
    await db.processedEvents.insert(event.id);
    if (event.type === 'charge.succeeded') {
        await addCredits(event.customer, 100);
    }
    res.sendStatus(200);
});
"#;
    let safe_findings = BizConcurrencyScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-BIZ-007"),
        "Must not flag when event.id deduplication is enforced"
    );
}

#[test]
fn test_biz_008_delete_account_leaves_keys_vulnerable_and_safe() {
    let vuln_code = r#"
async function deleteAccount(userId) {
    await db.users.delete({ id: userId });
}
"#;
    let path = Path::new("services/account_service.ts");
    let findings = BizConcurrencyScanner::scan_source(path, vuln_code);

    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-BIZ-008")
        .expect("Must flag account deletion omitting token/apiKey revocation");
    assert_eq!(f.severity, Severity::High);
    assert_eq!(f.detector_id, "biz-concurrency");
    assert!(f.advisory_ids.contains(&"CWE-613".to_string()));

    let safe_code = r#"
async function deleteAccount(userId) {
    await db.apiKeys.deleteMany({ userId });
    await db.tokens.deleteMany({ userId });
    await db.users.delete({ id: userId });
}
"#;
    let safe_findings = BizConcurrencyScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-BIZ-008"),
        "Must not flag when apiKeys and tokens are explicitly revoked"
    );
}

#[test]
fn test_biz_009_multi_tenant_aggregate_vulnerable_and_safe() {
    let vuln_code = r#"
app.get('/metrics/revenue', async (req, res) => {
    const total = await db.query("SELECT SUM(amount) FROM payments");
    res.json({ total });
});
"#;
    let path = Path::new("routes/reporting.js");
    let findings = BizConcurrencyScanner::scan_source(path, vuln_code);

    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-BIZ-009")
        .expect("Must flag aggregation query lacking tenant isolation filter");
    assert_eq!(f.severity, Severity::High);
    assert_eq!(f.detector_id, "biz-concurrency");
    assert!(f.advisory_ids.contains(&"CWE-200".to_string()));

    let safe_code = r#"
app.get('/metrics/revenue', async (req, res) => {
    const total = await db.query(
        "SELECT SUM(amount) FROM payments WHERE tenant_id = ?",
        [req.user.tenantId]
    );
    res.json({ total });
});
"#;
    let safe_findings = BizConcurrencyScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-BIZ-009"),
        "Must not flag when WHERE tenant_id filter is applied"
    );
}

#[test]
fn test_biz_010_admin_backdoor_vulnerable_and_safe() {
    let vuln_code = r#"
app.use((req, res, next) => {
    if (req.headers['x-admin-bypass'] === 'test-override-key') {
        req.user = { role: 'admin' };
    }
    next();
});
"#;
    let path = Path::new("middleware/auth.js");
    let findings = BizConcurrencyScanner::scan_source(path, vuln_code);

    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-BIZ-010")
        .expect("Must flag admin backdoor header without environment restriction");
    assert_eq!(f.severity, Severity::Critical);
    assert_eq!(f.detector_id, "biz-concurrency");
    assert!(f.advisory_ids.contains(&"CWE-862".to_string()));

    let safe_code = r#"
app.use((req, res, next) => {
    if (process.env.NODE_ENV === 'test' && req.headers['x-admin-bypass'] === 'test-override-key') {
        req.user = { role: 'admin' };
    }
    next();
});
"#;
    let safe_findings = BizConcurrencyScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-BIZ-010"),
        "Must not flag when bypass is strictly gated behind NODE_ENV === 'test'"
    );
}

#[test]
fn test_biz_011_global_quota_defeat_vulnerable_and_safe() {
    let vuln_code = r#"
async function addMemberToTeam(teamId, memberId) {
    const team = await db.teams.findById(teamId);
    if (team.members.length < MAX_TEAM_MEMBERS) {
        team.members.push(memberId);
        await team.save();
    }
}
"#;
    let path = Path::new("services/team.ts");
    let findings = BizConcurrencyScanner::scan_source(path, vuln_code);

    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-BIZ-011")
        .expect("Must flag sub-resource check omitting aggregate global quota");
    assert_eq!(f.severity, Severity::High);
    assert_eq!(f.detector_id, "biz-concurrency");
    assert!(f.advisory_ids.contains(&"CWE-840".to_string()));

    let safe_code = r#"
async function addMemberToTeam(teamId, memberId) {
    const org = await db.organizations.findByTeam(teamId);
    if (org.totalMembers >= MAX_GLOBAL_MEMBERS) {
        throw new Error("Organization global seat quota reached");
    }
    const team = await db.teams.findById(teamId);
    if (team.members.length < MAX_TEAM_MEMBERS) {
        team.members.push(memberId);
        await team.save();
    }
}
"#;
    let safe_findings = BizConcurrencyScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-BIZ-011"),
        "Must not flag when globalQuota / MAX_GLOBAL check is present"
    );
}

#[test]
fn test_biz_012_unbound_approval_signature_vulnerable_and_safe() {
    let vuln_code = r#"
function verifyApproval(approval) {
    if (approval.approved && approval.signature) {
        executeAction(approval.action);
    }
}
"#;
    let path = Path::new("workflows/approval.js");
    let findings = BizConcurrencyScanner::scan_source(path, vuln_code);

    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-BIZ-012")
        .expect("Must flag approval verification omitting actionId and nonce binding");
    assert_eq!(f.severity, Severity::High);
    assert_eq!(f.detector_id, "biz-concurrency");
    assert!(f.advisory_ids.contains(&"CWE-345".to_string()));

    let safe_code = r#"
function verifyApproval(approval, targetId, nonce) {
    const expectedPayload = `${approval.actionId}:${targetId}:${nonce}`;
    if (validateSignature(expectedPayload, approval.signature)) {
        executeAction(approval.actionId);
    }
}
"#;
    let safe_findings = BizConcurrencyScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-BIZ-012"),
        "Must not flag when signature binds actionId, targetId, and nonce"
    );
}
