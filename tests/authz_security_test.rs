use bug_killer::types;

#[path = "../src/scanner/authz.rs"]
pub mod authz;

use authz::AuthzSecurityScanner;
use bug_killer::types::Severity;
use std::path::Path;

#[test]
fn test_bk_ai_az_001_idor_bola_detection() {
    let vuln_snippet = r#"
app.get('/api/documents/:id', async (req, res) => {
    const doc = await Document.findById(req.params.id);
    res.json(doc);
});

app.get('/api/orders/:id', async (req, res) => {
    const order = await prisma.order.findUnique({
        where: { id: req.params.id }
    });
    res.json(order);
});
"#;
    let path = Path::new("controllers/documentController.js");
    let findings = AuthzSecurityScanner::scan_source(path, vuln_snippet);

    assert_eq!(
        findings.len(),
        2,
        "Must detect both un-scoped findById and findUnique lookups"
    );
    for f in &findings {
        assert_eq!(f.cve.as_str(), "BK-AI-AZ-001");
        assert_eq!(f.severity, Severity::High);
        assert!(f.advisory_ids.contains(&"CWE-639".to_string()));
    }

    let safe_snippet = r#"
app.get('/api/documents/:id', async (req, res) => {
    const doc = await Document.findOne({ _id: req.params.id, userId: req.user.id });
    res.json(doc);
});

app.get('/api/verified/:id', async (req, res) => {
    const doc = await Document.findById(req.params.id);
    if (doc.userId !== req.user.id) {
        return res.status(403).json({ error: 'Forbidden' });
    }
    res.json(doc);
});
"#;
    let safe_findings = AuthzSecurityScanner::scan_source(path, safe_snippet);
    assert!(
        safe_findings.is_empty(),
        "Safe scoped lookups or validated ownership must not trigger BK-AI-AZ-001"
    );
}

#[test]
fn test_bk_ai_az_002_untrusted_tenant_id_detection() {
    let vuln_snippet = r#"
app.post('/api/records', async (req, res) => {
    const tenantId = req.body.tenantId;
    const { org_id } = req.query;
    const headerTenant = req.headers['x-tenant-id'];
    saveRecord({ tenantId, org_id, headerTenant });
});
"#;
    let path = Path::new("routes/records.js");
    let findings = AuthzSecurityScanner::scan_source(path, vuln_snippet);

    assert_eq!(
        findings.len(),
        3,
        "Must flag tenantId from body, query, and header"
    );
    for f in &findings {
        assert_eq!(f.cve.as_str(), "BK-AI-AZ-002");
        assert_eq!(f.severity, Severity::High);
        assert!(f.advisory_ids.contains(&"CWE-863".to_string()));
    }

    let safe_snippet = r#"
app.post('/api/records', async (req, res) => {
    const tenantId = req.user.tenantId;
    const orgId = req.session.orgId;
    saveRecord({ tenantId, orgId });
});
"#;
    let safe_findings = AuthzSecurityScanner::scan_source(path, safe_snippet);
    assert!(
        safe_findings.is_empty(),
        "Session-derived tenant identifiers must be clean"
    );
}

#[test]
fn test_bk_ai_az_003_mass_assignment_detection() {
    let vuln_snippet = r#"
app.put('/api/users/:id', async (req, res) => {
    const updated = await User.findByIdAndUpdate(req.params.id, req.body);
    Object.assign(req.user, req.body);
    await prisma.user.update({ where: { id: req.params.id }, data: req.body });
    res.json(updated);
});
"#;
    let path = Path::new("controllers/userController.js");
    let findings = AuthzSecurityScanner::scan_source(path, vuln_snippet);

    assert_eq!(
        findings.len(),
        3,
        "Must detect findByIdAndUpdate, Object.assign, and prisma mass assignment"
    );
    for f in &findings {
        assert_eq!(f.cve.as_str(), "BK-AI-AZ-003");
        assert_eq!(f.severity, Severity::High);
        assert!(f.advisory_ids.contains(&"CWE-915".to_string()));
    }

    let safe_snippet = r#"
app.put('/api/users/:id', async (req, res) => {
    const { name, bio, avatarUrl } = req.body;
    const updated = await User.findByIdAndUpdate(req.params.id, { name, bio, avatarUrl });
    res.json(updated);
});
"#;
    let safe_findings = AuthzSecurityScanner::scan_source(path, safe_snippet);
    assert!(
        safe_findings.is_empty(),
        "Explicit field allowlist updates must be clean"
    );
}

#[test]
fn test_bk_ai_az_004_admin_route_enforcement_detection() {
    let vuln_snippet = r#"
app.post('/admin/users/delete', (req, res) => {
    deleteUser(req.body.id);
});

router.delete('/api/admin/system/reset', (req, res) => {
    resetSystem();
});
"#;
    let path = Path::new("routes/admin.js");
    let findings = AuthzSecurityScanner::scan_source(path, vuln_snippet);

    assert_eq!(findings.len(), 2, "Must flag un-guarded admin endpoints");
    for f in &findings {
        assert_eq!(f.cve.as_str(), "BK-AI-AZ-004");
        assert_eq!(f.severity, Severity::High);
        assert!(f.advisory_ids.contains(&"CWE-862".to_string()));
    }

    let safe_snippet = r#"
app.post('/admin/users/delete', checkRole('admin'), (req, res) => {
    deleteUser(req.body.id);
});

router.delete('/api/admin/system/reset', requireAdmin, (req, res) => {
    resetSystem();
});
"#;
    let safe_findings = AuthzSecurityScanner::scan_source(path, safe_snippet);
    assert!(
        safe_findings.is_empty(),
        "Protected admin routes must be clean"
    );
}

#[test]
fn test_bk_ai_az_005_client_side_only_authorization_detection() {
    let vuln_snippet = r#"
function AdminPanel({ user }) {
    const handleDelete = async () => {
        if (user.isAdmin) {
            await fetch('/api/admin/purge-cache', { method: 'POST' });
        }
    };
    return (
        <AdminRoute path="/admin" render={() => user.role === 'admin' ? <Dashboard /> : null} />
    );
}
"#;
    let path = Path::new("components/AdminPanel.jsx");
    let findings = AuthzSecurityScanner::scan_source(path, vuln_snippet);

    assert_eq!(
        findings.len(),
        2,
        "Must detect UI-only authorization gating"
    );
    for f in &findings {
        assert_eq!(f.cve.as_str(), "BK-AI-AZ-005");
        assert_eq!(f.severity, Severity::High);
        assert!(f.advisory_ids.contains(&"CWE-602".to_string()));
    }
}

#[test]
fn test_bk_ai_az_006_graphql_nested_resolver_bypass_detection() {
    let vuln_snippet = r#"
const resolvers = {
    User: {
        billingInfo: (parent) => Billing.findOne({ userId: parent.id }),
        salary: async (employee, _, { db }) => db.salary.findUnique({ where: { employeeId: employee.id } }),
    }
};
"#;
    let path = Path::new("graphql/resolvers.js");
    let findings = AuthzSecurityScanner::scan_source(path, vuln_snippet);

    assert_eq!(
        findings.len(),
        2,
        "Must flag GraphQL nested resolvers lacking caller context checks"
    );
    for f in &findings {
        assert_eq!(f.cve.as_str(), "BK-AI-AZ-006");
        assert_eq!(f.severity, Severity::High);
        assert!(f.advisory_ids.contains(&"CWE-863".to_string()));
    }

    let safe_snippet = r#"
const resolvers = {
    User: {
        salary: async (employee, _, { user, db }) => {
            if (user.id !== employee.id && !user.isAdmin) {
                throw new ForbiddenError('Unauthorized access to salary');
            }
            return db.salary.findUnique({ where: { employeeId: employee.id } });
        },
    }
};
"#;
    let safe_findings = AuthzSecurityScanner::scan_source(path, safe_snippet);
    assert!(
        safe_findings.is_empty(),
        "Context-guarded resolvers must be clean"
    );
}

#[test]
fn test_bk_ai_az_007_batch_api_partial_element_auth_detection() {
    let vuln_snippet = r#"
app.post('/api/items/batch-delete', async (req, res) => {
    const { items } = req.body;
    checkPermission(req.user, items[0]);
    for (const item of items) {
        await db.items.delete(item.id);
    }
});
"#;
    let path = Path::new("routes/batch.js");
    let findings = AuthzSecurityScanner::scan_source(path, vuln_snippet);

    assert_eq!(
        findings.len(),
        1,
        "Must detect checkPermission called only on index [0]"
    );
    assert_eq!(findings[0].cve.as_str(), "BK-AI-AZ-007");
    assert_eq!(findings[0].severity, Severity::High);
    assert!(findings[0].advisory_ids.contains(&"CWE-863".to_string()));

    let safe_snippet = r#"
app.post('/api/items/batch-delete', async (req, res) => {
    const { items } = req.body;
    for (const item of items) {
        if (!canAccess(req.user, item)) {
            throw new ForbiddenError();
        }
        await db.items.delete(item.id);
    }
});
"#;
    let safe_findings = AuthzSecurityScanner::scan_source(path, safe_snippet);
    assert!(
        safe_findings.is_empty(),
        "Iterative per-element checks must be clean"
    );
}

#[test]
fn test_bk_ai_az_008_background_worker_trusts_role_detection() {
    let vuln_snippet = r#"
queue.process(async (job) => {
    if (job.data.role === 'admin') {
        await purgeDatabase(job.data.target);
    }
});
"#;
    let path = Path::new("workers/cleanupWorker.js");
    let findings = AuthzSecurityScanner::scan_source(path, vuln_snippet);

    assert_eq!(
        findings.len(),
        1,
        "Must detect worker trusting role in job.data"
    );
    assert_eq!(findings[0].cve.as_str(), "BK-AI-AZ-008");
    assert_eq!(findings[0].severity, Severity::High);
    assert!(findings[0].advisory_ids.contains(&"CWE-863".to_string()));

    let safe_snippet = r#"
queue.process(async (job) => {
    const user = await db.user.findById(job.data.userId);
    if (user.role === 'admin') {
        await purgeDatabase(job.data.target);
    }
});
"#;
    let safe_findings = AuthzSecurityScanner::scan_source(path, safe_snippet);
    assert!(
        safe_findings.is_empty(),
        "Worker querying fresh user status from DB must be clean"
    );
}

#[test]
fn test_bk_ai_az_009_unverified_webhook_identity_detection() {
    let vuln_snippet = r#"
app.post('/webhook', (req, res) => {
    const { customerId, plan } = req.body;
    updateSubscription(customerId, plan);
    res.json({ received: true });
});
"#;
    let path = Path::new("routes/webhooks.js");
    let findings = AuthzSecurityScanner::scan_source(path, vuln_snippet);

    assert_eq!(
        findings.len(),
        1,
        "Must detect state-modifying webhook lacking signature verification"
    );
    assert_eq!(findings[0].cve.as_str(), "BK-AI-AZ-009");
    assert_eq!(findings[0].severity, Severity::High);
    assert!(findings[0].advisory_ids.contains(&"CWE-862".to_string()));

    let safe_snippet = r#"
app.post('/webhook', (req, res) => {
    const sig = req.headers['stripe-signature'];
    const event = stripe.webhooks.constructEvent(req.rawBody, sig, secret);
    updateSubscription(event.data.object.customer, event.data.object.plan);
    res.json({ received: true });
});
"#;
    let safe_findings = AuthzSecurityScanner::scan_source(path, safe_snippet);
    assert!(
        safe_findings.is_empty(),
        "Cryptographically verified webhook must be clean"
    );
}

#[test]
fn test_bk_ai_az_010_export_missing_tenancy_filter_detection() {
    let vuln_snippet = r#"
app.get('/export/customers', async (req, res) => {
    const rows = await db.query('SELECT * FROM customers');
    res.csv(rows);
});
"#;
    let path = Path::new("routes/export.js");
    let findings = AuthzSecurityScanner::scan_source(path, vuln_snippet);

    assert_eq!(
        findings.len(),
        1,
        "Must detect bulk data export without tenancy isolation"
    );
    assert_eq!(findings[0].cve.as_str(), "BK-AI-AZ-010");
    assert_eq!(findings[0].severity, Severity::High);
    assert!(findings[0].advisory_ids.contains(&"CWE-200".to_string()));

    let safe_snippet = r#"
app.get('/export/customers', async (req, res) => {
    const rows = await db.query('SELECT * FROM customers WHERE org_id = ?', [req.user.orgId]);
    res.csv(rows);
});
"#;
    let safe_findings = AuthzSecurityScanner::scan_source(path, safe_snippet);
    assert!(
        safe_findings.is_empty(),
        "Tenancy-isolated export query must be clean"
    );
}

#[test]
fn test_bk_ai_az_011_admin_token_on_user_path_detection() {
    let vuln_snippet = r#"
app.get('/user/profile', (req, res) => {
    const supabase = createClient(SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);
    res.json({ client: supabase });
});
"#;
    let path = Path::new("routes/user.js");
    let findings = AuthzSecurityScanner::scan_source(path, vuln_snippet);

    assert_eq!(
        findings.len(),
        1,
        "Must detect superuser service token used in request handler"
    );
    assert_eq!(findings[0].cve.as_str(), "BK-AI-AZ-011");
    assert_eq!(findings[0].severity, Severity::High);
    assert!(findings[0].advisory_ids.contains(&"CWE-250".to_string()));

    let safe_snippet = r#"
app.get('/user/profile', (req, res) => {
    const supabase = createClient(SUPABASE_URL, process.env.SUPABASE_ANON_KEY);
    res.json({ client: supabase });
});
"#;
    let safe_findings = AuthzSecurityScanner::scan_source(path, safe_snippet);
    assert!(
        safe_findings.is_empty(),
        "User-scoped or anon tokens must be clean"
    );
}

#[test]
fn test_bk_ai_az_012_default_role_privileged_detection() {
    let vuln_snippet = r#"
const userSchema = new Schema({
    name: String,
    role: { type: String, default: 'admin' },
});

const config = {
    default_role: 'superuser',
    permissions: ['*'],
};
"#;
    let path = Path::new("models/User.js");
    let findings = AuthzSecurityScanner::scan_source(path, vuln_snippet);

    assert_eq!(
        findings.len(),
        3,
        "Must flag privileged default roles and wildcard permissions"
    );
    for f in &findings {
        assert_eq!(f.cve.as_str(), "BK-AI-AZ-012");
        assert_eq!(f.severity, Severity::High);
        assert!(f.advisory_ids.contains(&"CWE-276".to_string()));
    }

    let safe_snippet = r#"
const userSchema = new Schema({
    name: String,
    role: { type: String, default: 'viewer' },
});

const config = {
    default_role: 'member',
};
"#;
    let safe_findings = AuthzSecurityScanner::scan_source(path, safe_snippet);
    assert!(
        safe_findings.is_empty(),
        "Least-privileged defaults must be clean"
    );
}

#[test]
fn test_bk_ai_az_013_check_then_act_toctou_detection() {
    let vuln_snippet = r#"
async function deleteResourceHandler(req, res) {
    const isOwner = await checkOwnership(req.user.id, req.params.fileId);
    await wait(200);
    await deleteFile(req.params.fileId);
    res.json({ success: true });
}
"#;
    let path = Path::new("services/fileService.js");
    let findings = AuthzSecurityScanner::scan_source(path, vuln_snippet);

    assert_eq!(findings.len(), 1, "Must detect check-then-act race gap");
    assert_eq!(findings[0].cve.as_str(), "BK-AI-AZ-013");
    assert_eq!(findings[0].severity, Severity::Medium);
    assert!(findings[0].advisory_ids.contains(&"CWE-367".to_string()));

    let safe_snippet = r#"
async function deleteResourceHandler(req, res) {
    const result = await db.collection.findOneAndUpdate(
        { _id: req.params.fileId, ownerId: req.user.id },
        { $set: { deleted: true } }
    );
    res.json({ success: true, result });
}
"#;
    let safe_findings = AuthzSecurityScanner::scan_source(path, safe_snippet);
    assert!(
        safe_findings.is_empty(),
        "Atomic conditional mutation must be clean"
    );
}

#[test]
fn test_bk_ai_az_014_vector_search_cross_tenant_leak_detection() {
    let vuln_snippet = r#"
async function searchKnowledgeBase(query, embeddings) {
    const pineconeMatches = await index.query({ vector: embeddings, topK: 10 });
    const chromaMatches = await collection.query({ query_embeddings: embeddings, n_results: 5 });
    const simMatches = await vectorStore.similaritySearch(query, 10);
    return { pineconeMatches, chromaMatches, simMatches };
}
"#;
    let path = Path::new("services/vectorSearch.js");
    let findings = AuthzSecurityScanner::scan_source(path, vuln_snippet);

    assert_eq!(
        findings.len(),
        3,
        "Must flag all 3 vector queries lacking tenant filter/namespace"
    );
    for f in &findings {
        assert_eq!(f.cve.as_str(), "BK-AI-AZ-014");
        assert_eq!(f.severity, Severity::High);
        assert!(f.advisory_ids.contains(&"CWE-200".to_string()));
    }

    let safe_snippet = r#"
async function searchKnowledgeBase(query, embeddings, tenantId) {
    const pineconeMatches = await index.query({ vector: embeddings, topK: 10, filter: { tenantId } });
    const chromaMatches = await collection.query({ query_embeddings: embeddings, n_results: 5, where: { tenant_id: tenantId } });
    const simMatches = await vectorStore.similaritySearch(query, 10, { filter: { tenantId } });
    return { pineconeMatches, chromaMatches, simMatches };
}
"#;
    let safe_findings = AuthzSecurityScanner::scan_source(path, safe_snippet);
    assert!(
        safe_findings.is_empty(),
        "Tenant-scoped vector searches must be clean"
    );
}
