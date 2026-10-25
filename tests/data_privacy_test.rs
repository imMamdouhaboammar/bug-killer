use bug_killer::types;

#[path = "../src/scanner/data_privacy.rs"]
pub mod data_privacy;

use bug_killer::types::Severity;
use data_privacy::DataPrivacyScanner;
use std::path::Path;

// ===========================================================================
// Category 10: Secrets, Privacy, PII and Data Exposure Tests
// ===========================================================================

#[test]
fn test_bk_ai_sec_005_dump_environment_or_stack() {
    let vuln_snippet = r#"
app.get('/debug/env', (req, res) => {
    console.log(process.env);
    logger.info("Env dump:", process.env);
    res.send(err.stack);
});

function debugPython() {
    print(os.environ)
    dump(env)
}
"#;
    let path = Path::new("src/server.js");
    let findings = DataPrivacyScanner::scan_source(path, vuln_snippet);

    assert!(!findings.is_empty(), "Must detect environment and stack dumping");
    for f in &findings {
        assert_eq!(f.cve.as_str(), "BK-AI-SEC-005");
        assert_eq!(f.detector_id, "data-privacy");
        assert_eq!(f.severity, Severity::High);
        assert!(f.advisory_ids.contains(&"CWE-532".to_string()));
    }

    let safe_snippet = r#"
app.get('/health', (req, res) => {
    console.log("Starting server in mode:", process.env.NODE_ENV);
    const port = process.env.PORT || 3000;
    logger.info("Sanitized env:", sanitize(process.env));
    res.status(500).json({ error: "Internal Server Error" });
});
"#;
    let safe_findings = DataPrivacyScanner::scan_source(path, safe_snippet);
    assert!(
        safe_findings.is_empty(),
        "Specific property access, sanitized env, or generic errors must not trigger BK-AI-SEC-005"
    );
}

#[test]
fn test_bk_ai_sec_006_pii_in_metrics_and_traces() {
    let vuln_snippet = r#"
function recordTelemetry(user, payment) {
    tags.put("ssn", user.ssn);
    span.setAttribute("user.password", user.password);
    tracer.setTag("credit_card", payment.cardNumber);
    analytics.track("checkout", { cvv: payment.cvv, total: payment.amount });
    datadog.increment("auth.attempt", tags=["password:12345"]);
}
"#;
    let path = Path::new("src/telemetry.ts");
    let findings = DataPrivacyScanner::scan_source(path, vuln_snippet);

    assert_eq!(findings.len(), 5, "Must detect all 5 PII telemetry instances");
    for f in &findings {
        assert_eq!(f.cve.as_str(), "BK-AI-SEC-006");
        assert_eq!(f.detector_id, "data-privacy");
        assert_eq!(f.severity, Severity::High);
        assert!(f.advisory_ids.contains(&"CWE-200".to_string()));
    }

    let safe_snippet = r#"
function recordTelemetry(user, payment) {
    tags.put("userId", user.id);
    span.setAttribute("tenant.id", user.tenantId);
    tracer.setTag("paymentMethod", payment.brand);
    analytics.track("checkout", { orderId: payment.orderId, amount: payment.amount });
    datadog.increment("auth.attempt", tags=["status:success"]);
}
"#;
    let safe_findings = DataPrivacyScanner::scan_source(path, safe_snippet);
    assert!(
        safe_findings.is_empty(),
        "Non-PII metrics and trace dimensions must not trigger BK-AI-SEC-006"
    );
}

#[test]
fn test_bk_ai_sec_007_unnecessary_storage_of_cvv_or_plaintext_passwords() {
    let vuln_snippet = r#"
const CardSchema = new Schema({
    cardNumber: { type: String },
    cvv: { type: String, required: true },
    plaintext_password: { type: String }
});

async function savePayment(req) {
    await db.cards.insert({
        userId: req.user.id,
        cvv: req.body.cvv
    });
    storeCard({ number: req.body.number, cvv: req.body.cvv });
}
"#;
    let path = Path::new("src/models/payment.js");
    let findings = DataPrivacyScanner::scan_source(path, vuln_snippet);

    assert!(!findings.is_empty(), "Must detect persistent storage/schema of CVV and plaintext password");
    for f in &findings {
        assert_eq!(f.cve.as_str(), "BK-AI-SEC-007");
        assert_eq!(f.detector_id, "data-privacy");
        assert_eq!(f.severity, Severity::Critical);
        assert!(f.advisory_ids.contains(&"CWE-359".to_string()));
    }

    let safe_snippet = r#"
const CardSchema = new Schema({
    stripeToken: { type: String },
    last4: { type: String },
    brand: { type: String }
});

async function savePayment(req) {
    const token = await stripe.tokens.create({ card: { number: req.body.number } });
    await db.cards.insert({ userId: req.user.id, stripeToken: token.id });
}
"#;
    let safe_findings = DataPrivacyScanner::scan_source(path, safe_snippet);
    assert!(
        safe_findings.is_empty(),
        "Tokenized card storage must not trigger BK-AI-SEC-007"
    );
}

#[test]
fn test_bk_ai_sec_008_export_delete_without_ownership_verification() {
    let vuln_snippet = r#"
app.get('/api/export-user-data', async (req, res) => {
    const data = await UserData.findByUserId(req.query.userId);
    res.json(data);
});

app.post('/api/delete-user-data', async (req, res) => {
    await UserData.deleteFor(req.body.userId);
    res.json({ deleted: true });
});
"#;
    let path = Path::new("src/routes/gdpr.js");
    let findings = DataPrivacyScanner::scan_source(path, vuln_snippet);

    assert_eq!(findings.len(), 2, "Must flag unauthenticated/unscoped export and delete routes");
    for f in &findings {
        assert_eq!(f.cve.as_str(), "BK-AI-SEC-008");
        assert_eq!(f.detector_id, "data-privacy");
        assert_eq!(f.severity, Severity::High);
        assert!(f.advisory_ids.contains(&"CWE-639".to_string()));
    }

    let safe_snippet = r#"
app.get('/api/export-user-data', authenticate, async (req, res) => {
    if (req.user.id !== req.query.userId) {
        return res.status(403).json({ error: "Unauthorized" });
    }
    const data = await UserData.findByUserId(req.user.id);
    res.json(data);
});
"#;
    let safe_findings = DataPrivacyScanner::scan_source(path, safe_snippet);
    assert!(
        safe_findings.is_empty(),
        "Authenticated export routes verifying session ownership must not trigger BK-AI-SEC-008"
    );
}

#[test]
fn test_bk_ai_sec_009_missing_encryption_at_rest() {
    let vuln_snippet = r#"
const UserSchema = new Schema({
    ssn: { type: String, encrypted: false },
    credit_card: { type: String, encrypted: false }
});

const bucketConfig = {
    Bucket: "financial-records",
    ServerSideEncryption: false
};
"#;
    let path = Path::new("src/config/storage.js");
    let findings = DataPrivacyScanner::scan_source(path, vuln_snippet);

    assert!(!findings.is_empty(), "Must detect sensitive datasets with encryption: false");
    for f in &findings {
        assert_eq!(f.cve.as_str(), "BK-AI-SEC-009");
        assert_eq!(f.detector_id, "data-privacy");
        assert_eq!(f.severity, Severity::High);
        assert!(f.advisory_ids.contains(&"CWE-311".to_string()));
    }

    let safe_snippet = r#"
const UserSchema = new Schema({
    ssn: { type: String, encrypted: true },
    credit_card: { type: String, encrypted: true }
});

const bucketConfig = {
    Bucket: "financial-records",
    ServerSideEncryption: "aws:kms"
};
"#;
    let safe_findings = DataPrivacyScanner::scan_source(path, safe_snippet);
    assert!(
        safe_findings.is_empty(),
        "Encrypted columns and storage buckets must not trigger BK-AI-SEC-009"
    );
}

#[test]
fn test_bk_ai_sec_011_third_party_ai_receives_unredacted_pii() {
    let vuln_snippet = r#"
async function askAiAssistant(req, user) {
    const response = await openai.chat.completions.create({
        model: "gpt-4",
        messages: [{ role: "user", content: `My SSN is ${user.ssn} and password is ${req.body.password}` }]
    });

    segment.track({
        event: "User Login",
        ssn: user.ssn,
        raw_password: req.body.password
    });
}
"#;
    let path = Path::new("src/services/ai.js");
    let findings = DataPrivacyScanner::scan_source(path, vuln_snippet);

    assert!(!findings.is_empty(), "Must detect raw PII sent to AI provider or analytics");
    for f in &findings {
        assert_eq!(f.cve.as_str(), "BK-AI-SEC-011");
        assert_eq!(f.detector_id, "data-privacy");
        assert_eq!(f.severity, Severity::High);
        assert!(f.advisory_ids.contains(&"CWE-201".to_string()));
    }

    let safe_snippet = r#"
async function askAiAssistant(req, user) {
    const sanitizedPrompt = sanitize(req.body.question);
    const response = await openai.chat.completions.create({
        model: "gpt-4",
        messages: [{ role: "user", content: redact(sanitizedPrompt) }]
    });

    segment.track({
        event: "User Login",
        userId: user.id
    });
}
"#;
    let safe_findings = DataPrivacyScanner::scan_source(path, safe_snippet);
    assert!(
        safe_findings.is_empty(),
        "Redacted payloads and non-PII events must not trigger BK-AI-SEC-011"
    );
}

#[test]
fn test_bk_ai_sec_012_reports_and_tool_replies_leak_raw_secrets() {
    let vuln_snippet = r#"
function getDiagnosticReport() {
    return {
        status: "ok",
        apiKey: process.env.API_KEY,
        secretKey: config.secretKey
    };
}

function runTool(cmd) {
    tool_result = f"Connected using password: {db_password}"
}
"#;
    let path = Path::new("src/tools/diagnostics.js");
    let findings = DataPrivacyScanner::scan_source(path, vuln_snippet);

    assert!(!findings.is_empty(), "Must flag raw secrets returned in tool replies or reports");
    for f in &findings {
        assert_eq!(f.cve.as_str(), "BK-AI-SEC-012");
        assert_eq!(f.detector_id, "data-privacy");
        assert_eq!(f.severity, Severity::High);
        assert!(f.advisory_ids.contains(&"CWE-532".to_string()));
    }

    let safe_snippet = r#"
function getDiagnosticReport() {
    return {
        status: "ok",
        apiKey: mask(process.env.API_KEY),
        secretPreview: config.secretKey.slice(-4)
    };
}
"#;
    let safe_findings = DataPrivacyScanner::scan_source(path, safe_snippet);
    assert!(
        safe_findings.is_empty(),
        "Masked or sliced token previews must not trigger BK-AI-SEC-012"
    );
}

// ===========================================================================
// Category 11: Database & Storage Security Tests
// ===========================================================================

#[test]
fn test_bk_ai_dat_001_database_connection_superuser() {
    let vuln_snippet = r#"
const dbConfig = {
    host: "localhost",
    user: "postgres",
    password: "secretpassword"
};

const connStr = "postgres://root:password@localhost:5432/app";
"#;
    let path = Path::new("src/config/database.js");
    let findings = DataPrivacyScanner::scan_source(path, vuln_snippet);

    assert_eq!(findings.len(), 2, "Must flag both superuser user: postgres and root conn URL");
    for f in &findings {
        assert_eq!(f.cve.as_str(), "BK-AI-DAT-001");
        assert_eq!(f.detector_id, "data-privacy");
        assert_eq!(f.severity, Severity::High);
        assert!(f.advisory_ids.contains(&"CWE-250".to_string()));
    }

    let safe_snippet = r#"
const dbConfig = {
    host: "localhost",
    user: "app_user",
    password: process.env.DB_PASSWORD
};

const connStr = "postgres://app_svc:secret@localhost:5432/app";
"#;
    let safe_findings = DataPrivacyScanner::scan_source(path, safe_snippet);
    assert!(
        safe_findings.is_empty(),
        "Least-privileged database user accounts must not trigger BK-AI-DAT-001"
    );
}

#[test]
fn test_bk_ai_dat_002_rls_bypassed_by_service_role() {
    let vuln_snippet = r#"
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);

function fetchItems(req) {
    const query = { bypass_rls: true };
}

// SQL migration
ALTER TABLE users DISABLE ROW LEVEL SECURITY;
"#;
    let path = Path::new("src/routes/items.js");
    let findings = DataPrivacyScanner::scan_source(path, vuln_snippet);

    assert_eq!(findings.len(), 3, "Must flag service role client, bypass flag, and DISABLE RLS");
    for f in &findings {
        assert_eq!(f.cve.as_str(), "BK-AI-DAT-002");
        assert_eq!(f.detector_id, "data-privacy");
        assert_eq!(f.severity, Severity::Critical);
        assert!(f.advisory_ids.contains(&"CWE-863".to_string()));
    }

    let safe_snippet = r#"
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY);

// SQL migration
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
"#;
    let safe_findings = DataPrivacyScanner::scan_source(path, safe_snippet);
    assert!(
        safe_findings.is_empty(),
        "Anon key client initialization and ENABLE RLS must not trigger BK-AI-DAT-002"
    );
}

#[test]
fn test_bk_ai_dat_003_query_filters_tenant_in_memory() {
    let vuln_snippet = r#"
app.get('/api/orders', async (req, res) => {
    const orders = await Order.findAll();
    const userOrders = orders.filter(item => item.tenantId === req.user.tenantId);
    res.json(userOrders);
});
"#;
    let path = Path::new("src/controllers/orderController.js");
    let findings = DataPrivacyScanner::scan_source(path, vuln_snippet);

    assert!(!findings.is_empty(), "Must detect in-memory tenant filtering after findAll()");
    for f in &findings {
        assert_eq!(f.cve.as_str(), "BK-AI-DAT-003");
        assert_eq!(f.detector_id, "data-privacy");
        assert_eq!(f.severity, Severity::High);
        assert!(f.advisory_ids.contains(&"CWE-200".to_string()));
    }

    let safe_snippet = r#"
app.get('/api/orders', async (req, res) => {
    const orders = await Order.findAll({
        where: { tenantId: req.user.tenantId }
    });
    res.json(orders);
});
"#;
    let safe_findings = DataPrivacyScanner::scan_source(path, safe_snippet);
    assert!(
        safe_findings.is_empty(),
        "Database-level tenancy scoping must not trigger BK-AI-DAT-003"
    );
}

#[test]
fn test_bk_ai_dat_004_db_schema_inserts_default_admin() {
    let vuln_snippet = r#"
INSERT INTO users (username, password, role) VALUES ('admin', 'admin123', 'admin');

await knex('users').insert({
    email: 'admin@app.com',
    password: 'DefaultAdminPassword!'
});
"#;
    let path = Path::new("migrations/20261025_seed.sql");
    let findings = DataPrivacyScanner::scan_source(path, vuln_snippet);

    assert_eq!(findings.len(), 2, "Must detect both SQL and ORM seed default admin passwords");
    for f in &findings {
        assert_eq!(f.cve.as_str(), "BK-AI-DAT-004");
        assert_eq!(f.detector_id, "data-privacy");
        assert_eq!(f.severity, Severity::Critical);
        assert!(f.advisory_ids.contains(&"CWE-798".to_string()));
    }

    let safe_snippet = r#"
const tempPassword = crypto.randomBytes(32).toString('hex');
await knex('users').insert({
    email: 'admin@app.com',
    password: await bcrypt.hash(tempPassword, 12)
});
"#;
    let safe_findings = DataPrivacyScanner::scan_source(path, safe_snippet);
    assert!(
        safe_findings.is_empty(),
        "Dynamically generated, hashed random admin credentials must not trigger BK-AI-DAT-004"
    );
}

#[test]
fn test_bk_ai_dat_005_database_backup_stored_publicly() {
    let vuln_snippet = r#"
aws s3 cp backup.sql.gz s3://my-backups/ --acl public-read
uploadBackup(file, { acl: 'public-read' });
mysqldump -u app -p mydb > public/backup.sql
"#;
    let path = Path::new("scripts/backup.sh");
    let findings = DataPrivacyScanner::scan_source(path, vuln_snippet);

    assert!(!findings.is_empty(), "Must detect public-read backups or webroot dumps");
    for f in &findings {
        assert_eq!(f.cve.as_str(), "BK-AI-DAT-005");
        assert_eq!(f.detector_id, "data-privacy");
        assert_eq!(f.severity, Severity::High);
        assert!(f.advisory_ids.contains(&"CWE-552".to_string()));
    }

    let safe_snippet = r#"
aws s3 cp backup.sql.gz s3://my-backups/ --acl private
uploadBackup(file, { acl: 'private' });
mysqldump -u app -p mydb > /var/backups/backup.sql
"#;
    let safe_findings = DataPrivacyScanner::scan_source(path, safe_snippet);
    assert!(
        safe_findings.is_empty(),
        "Private ACL and protected filesystem backup paths must not trigger BK-AI-DAT-005"
    );
}

#[test]
fn test_bk_ai_dat_006_balance_mutation_without_atomic_lock() {
    let vuln_snippet = r#"
app.post('/api/transfer', async (req, res) => {
    const account = await Account.findById(req.body.accountId);
    account.balance = account.balance - req.body.amount;
    await account.save();
    res.json(account);
});
"#;
    let path = Path::new("src/routes/wallet.js");
    let findings = DataPrivacyScanner::scan_source(path, vuln_snippet);

    assert!(!findings.is_empty(), "Must detect non-atomic balance subtraction and save");
    for f in &findings {
        assert_eq!(f.cve.as_str(), "BK-AI-DAT-006");
        assert_eq!(f.detector_id, "data-privacy");
        assert_eq!(f.severity, Severity::High);
        assert!(f.advisory_ids.contains(&"CWE-362".to_string()));
    }

    let safe_snippet = r#"
app.post('/api/transfer', async (req, res) => {
    await sequelize.transaction(async (t) => {
        await Account.decrement('balance', {
            by: req.body.amount,
            where: { id: req.body.accountId },
            transaction: t
        });
    });
    res.json({ success: true });
});
"#;
    let safe_findings = DataPrivacyScanner::scan_source(path, safe_snippet);
    assert!(
        safe_findings.is_empty(),
        "Atomic decrement inside database transaction must not trigger BK-AI-DAT-006"
    );
}

#[test]
fn test_bk_ai_dat_007_search_index_or_cache_bypasses_permissions() {
    let vuln_snippet = r#"
async function searchDocuments(req, res) {
    const results = await pinecone.query({
        vector: embeddings,
        topK: 10
    });
    return res.json(results);
}

async function getCachedDoc(req, res) {
    const doc = await cache.get(req.params.id);
    return res.json(doc);
}
"#;
    let path = Path::new("src/services/search.js");
    let findings = DataPrivacyScanner::scan_source(path, vuln_snippet);

    assert_eq!(findings.len(), 2, "Must flag vector search without filter and unchecked cache return");
    for f in &findings {
        assert_eq!(f.cve.as_str(), "BK-AI-DAT-007");
        assert_eq!(f.detector_id, "data-privacy");
        assert_eq!(f.severity, Severity::High);
        assert!(f.advisory_ids.contains(&"CWE-863".to_string()));
    }

    let safe_snippet = r#"
async function searchDocuments(req, res) {
    const results = await pinecone.query({
        vector: embeddings,
        topK: 10,
        filter: { tenantId: req.user.tenantId }
    });
    return res.json(results);
}
"#;
    let safe_findings = DataPrivacyScanner::scan_source(path, safe_snippet);
    assert!(
        safe_findings.is_empty(),
        "Tenant-scoped vector query must not trigger BK-AI-DAT-007"
    );
}

#[test]
fn test_bk_ai_dat_008_orm_raw_query_interpolation() {
    let vuln_snippet = r#"
async function findUser(id, name) {
    await sequelize.query(`SELECT * FROM users WHERE id = ${id}`);
    await prisma.$queryRawUnsafe(`SELECT * FROM users WHERE name = '${name}'`);
    await db.raw(`SELECT * FROM orders WHERE id = ${id}`);
    User.find({ $where: `this.name == '${name}'` });
}
"#;
    let path = Path::new("src/models/user.js");
    let findings = DataPrivacyScanner::scan_source(path, vuln_snippet);

    assert_eq!(findings.len(), 4, "Must flag all 4 raw ORM string interpolations");
    for f in &findings {
        assert_eq!(f.cve.as_str(), "BK-AI-DAT-008");
        assert_eq!(f.detector_id, "data-privacy");
        assert_eq!(f.severity, Severity::Critical);
        assert!(f.advisory_ids.contains(&"CWE-89".to_string()));
    }

    let safe_snippet = r#"
async function findUser(id, name) {
    await sequelize.query("SELECT * FROM users WHERE id = :id", { replacements: { id } });
    await prisma.$queryRaw`SELECT * FROM users WHERE name = ${name}`;
    await db.raw("SELECT * FROM orders WHERE id = ?", [id]);
}
"#;
    let safe_findings = DataPrivacyScanner::scan_source(path, safe_snippet);
    assert!(
        safe_findings.is_empty(),
        "Parameterized bindings and tagged Prisma template literal must not trigger BK-AI-DAT-008"
    );
}

#[test]
fn test_bk_ai_dat_009_migration_drops_security_constraints_or_triggers() {
    let vuln_snippet = r#"
DROP TRIGGER IF EXISTS audit_log_trigger ON users;
ALTER TABLE users DROP CONSTRAINT check_tenant_isolation;
table.dropForeign('tenant_id');
table.dropTrigger('audit_trigger');
"#;
    let path = Path::new("migrations/20261025_relax.sql");
    let findings = DataPrivacyScanner::scan_source(path, vuln_snippet);

    assert_eq!(findings.len(), 4, "Must flag all dropped audit triggers and security constraints");
    for f in &findings {
        assert_eq!(f.cve.as_str(), "BK-AI-DAT-009");
        assert_eq!(f.detector_id, "data-privacy");
        assert_eq!(f.severity, Severity::High);
        assert!(f.advisory_ids.contains(&"CWE-284".to_string()));
    }

    let safe_snippet = r#"
CREATE TRIGGER audit_log_trigger AFTER INSERT ON users;
ALTER TABLE users ADD CONSTRAINT check_tenant_isolation CHECK (tenant_id IS NOT NULL);
table.foreign('tenant_id').references('tenants.id');
"#;
    let safe_findings = DataPrivacyScanner::scan_source(path, safe_snippet);
    assert!(
        safe_findings.is_empty(),
        "Adding constraints and creating audit triggers must not trigger BK-AI-DAT-009"
    );
}

#[test]
fn test_bk_ai_dat_010_dynamic_table_from_user_input() {
    let vuln_snippet = r#"
app.post('/api/data', async (req, res) => {
    const data = await db.collection(req.body.table).find().toArray();
    const rows = await knex(req.query.table).select();
    res.json({ data, rows });
});
"#;
    let path = Path::new("src/routes/dynamic.js");
    let findings = DataPrivacyScanner::scan_source(path, vuln_snippet);

    assert_eq!(findings.len(), 2, "Must flag dynamic collection and knex table from request");
    for f in &findings {
        assert_eq!(f.cve.as_str(), "BK-AI-DAT-010");
        assert_eq!(f.detector_id, "data-privacy");
        assert_eq!(f.severity, Severity::High);
        assert!(f.advisory_ids.contains(&"CWE-89".to_string()));
    }

    let safe_snippet = r#"
const ALLOWED_TABLES = ['orders', 'invoices', 'receipts'];

app.post('/api/data', async (req, res) => {
    if (!ALLOWED_TABLES.includes(req.body.table)) {
        return res.status(400).json({ error: "Invalid collection" });
    }
    const data = await db.collection(req.body.table).find().toArray();
    res.json({ data });
});
"#;
    let safe_findings = DataPrivacyScanner::scan_source(path, safe_snippet);
    assert!(
        safe_findings.is_empty(),
        "Allowlisted dynamic table selection must not trigger BK-AI-DAT-010"
    );
}

#[test]
fn test_bk_ai_dat_011_storage_object_public_read_acl() {
    let vuln_snippet = r#"
s3.upload({
    Bucket: "user-tax-documents",
    Key: key,
    Body: fileStream,
    ACL: "public-read"
});
"#;
    let path = Path::new("src/services/storage.js");
    let findings = DataPrivacyScanner::scan_source(path, vuln_snippet);

    assert_eq!(findings.len(), 1, "Must flag public-read ACL on storage upload");
    for f in &findings {
        assert_eq!(f.cve.as_str(), "BK-AI-DAT-011");
        assert_eq!(f.detector_id, "data-privacy");
        assert_eq!(f.severity, Severity::High);
        assert!(f.advisory_ids.contains(&"CWE-732".to_string()));
    }

    let safe_snippet = r#"
s3.upload({
    Bucket: "user-tax-documents",
    Key: key,
    Body: fileStream,
    ACL: "private"
});
"#;
    let safe_findings = DataPrivacyScanner::scan_source(path, safe_snippet);
    assert!(
        safe_findings.is_empty(),
        "Private storage ACL must not trigger BK-AI-DAT-011"
    );
}

#[test]
fn test_bk_ai_dat_012_sensitive_record_unpurged_from_cache() {
    let vuln_snippet = r#"
app.delete('/api/users/:id', async (req, res) => {
    // deleted without clearing cache
    await User.destroy({ where: { id: req.params.id } });
    return res.json({ deleted: true });
});
"#;
    let path = Path::new("src/controllers/userController.js");
    let findings = DataPrivacyScanner::scan_source(path, vuln_snippet);

    assert!(!findings.is_empty(), "Must detect record deletion without cache purge");
    for f in &findings {
        assert_eq!(f.cve.as_str(), "BK-AI-DAT-012");
        assert_eq!(f.detector_id, "data-privacy");
        assert_eq!(f.severity, Severity::Medium);
        assert!(f.advisory_ids.contains(&"CWE-212".to_string()));
    }

    let safe_snippet = r#"
app.delete('/api/users/:id', async (req, res) => {
    await User.destroy({ where: { id: req.params.id } });
    await redis.del(`user:${req.params.id}`);
    await cache.invalidate(req.params.id);
    return res.json({ deleted: true });
});
"#;
    let safe_findings = DataPrivacyScanner::scan_source(path, safe_snippet);
    assert!(
        safe_findings.is_empty(),
        "Deleting user record with explicit redis/cache purge must not trigger BK-AI-DAT-012"
    );
}
