#[path = "../src/scanner/api.rs"]
mod api;

pub use bug_killer::types;
use api::ApiSecurityScanner;
use bug_killer::types::Severity;
use std::path::Path;

// --- BK-AI-API-001 (CWE-20): Request body validation only occurs in UI ---

#[test]
fn test_api_001_ui_validation_comment_detected() {
    let snippet = r#"
// Validation occurs only in UI
app.post('/api/user/profile', (req, res) => {
    const data = req.body;
    updateUserProfile(data);
    res.json({ success: true });
});
"#;
    let path = Path::new("src/routes/profile.js");
    let findings = ApiSecurityScanner::scan_source(path, snippet);

    assert!(!findings.is_empty(), "Should flag UI validation comment");
    let f = findings.iter().find(|f| f.cve.as_str() == "BK-AI-API-001").expect("Must find BK-AI-API-001");
    assert_eq!(f.severity, Severity::High);
    assert!(f.advisory_ids.contains(&"CWE-20".to_string()));
}

#[test]
fn test_api_001_raw_body_used_directly() {
    let snippet = r#"
app.post('/api/checkout', (req, res) => {
    processPayment(req.body);
    res.json({ status: 'processing' });
});
"#;
    let path = Path::new("src/controllers/payment.js");
    let findings = ApiSecurityScanner::scan_source(path, snippet);

    assert_eq!(findings.len(), 1, "Should flag unvalidated req.body passed to business logic");
    assert_eq!(findings[0].cve.as_str(), "BK-AI-API-001");
    assert_eq!(findings[0].severity, Severity::High);
}

#[test]
fn test_api_001_validated_body_safe() {
    let snippet = r#"
const { z } = require('zod');

const checkoutSchema = z.object({
    amount: z.number().positive(),
    currency: z.string().length(3),
});

app.post('/api/checkout', (req, res) => {
    const validated = checkoutSchema.parse(req.body);
    processPayment(validated);
    res.json({ status: 'processing' });
});
"#;
    let path = Path::new("src/controllers/payment.js");
    let findings = ApiSecurityScanner::scan_source(path, snippet);

    assert!(findings.is_empty(), "Schema validation should not flag BK-AI-API-001");
}

// --- BK-AI-API-002 (CWE-915): Mass assignment / unfiltered model creation ---

#[test]
fn test_api_002_mass_assignment_model_create() {
    let snippet = r#"
app.post('/api/users', async (req, res) => {
    const user = await User.create(req.body);
    res.status(201).json(user);
});
"#;
    let path = Path::new("src/routes/users.js");
    let findings = ApiSecurityScanner::scan_source(path, snippet);

    assert_eq!(findings.len(), 1, "Should flag User.create(req.body)");
    assert_eq!(findings[0].cve.as_str(), "BK-AI-API-002");
    assert_eq!(findings[0].severity, Severity::High);
    assert!(findings[0].advisory_ids.contains(&"CWE-915".to_string()));
}

#[test]
fn test_api_002_mass_assignment_prisma_create() {
    let snippet = r#"
async function createUser(req, res) {
    const account = await prisma.account.create({ data: req.body });
    res.json(account);
}
"#;
    let path = Path::new("src/services/account.ts");
    let findings = ApiSecurityScanner::scan_source(path, snippet);

    assert_eq!(findings.len(), 1, "Should flag prisma.account.create with raw body");
    assert_eq!(findings[0].cve.as_str(), "BK-AI-API-002");
}

#[test]
fn test_api_002_allowlist_safe() {
    let snippet = r#"
app.post('/api/users', async (req, res) => {
    const user = await User.create({
        username: req.body.username,
        email: req.body.email,
    });
    res.status(201).json(user);
});
"#;
    let path = Path::new("src/routes/users.js");
    let findings = ApiSecurityScanner::scan_source(path, snippet);

    assert!(findings.is_empty(), "Allowlisted fields in User.create should be safe");
}

// --- BK-AI-API-003 (CWE-770): No per-actor rate limit on expensive operations ---

#[test]
fn test_api_003_unbounded_expensive_endpoint() {
    let snippet = r#"
router.post('/api/export', async (req, res) => {
    const report = await generatePdfReport(req.body);
    res.send(report);
});
"#;
    let path = Path::new("src/routes/reports.js");
    let findings = ApiSecurityScanner::scan_source(path, snippet);

    assert_eq!(findings.len(), 1, "Should flag /api/export without rate limiter");
    assert_eq!(findings[0].cve.as_str(), "BK-AI-API-003");
    assert_eq!(findings[0].severity, Severity::Medium);
    assert!(findings[0].advisory_ids.contains(&"CWE-770".to_string()));
}

#[test]
fn test_api_003_rate_limited_expensive_endpoint_safe() {
    let snippet = r#"
const rateLimit = require('express-rate-limit');
const exportLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5 });

router.post('/api/export', exportLimiter, async (req, res) => {
    const report = await generatePdfReport(req.body);
    res.send(report);
});
"#;
    let path = Path::new("src/routes/reports.js");
    let findings = ApiSecurityScanner::scan_source(path, snippet);

    assert!(findings.is_empty(), "Rate limited export route should be safe");
}

// --- BK-AI-API-004 (CWE-400): GraphQL depth, complexity or introspection exposure ---

#[test]
fn test_api_004_graphql_introspection_enabled() {
    let snippet = r#"
const server = new ApolloServer({
    typeDefs,
    resolvers,
    introspection: true,
});
"#;
    let path = Path::new("src/graphql/server.js");
    let findings = ApiSecurityScanner::scan_source(path, snippet);

    assert_eq!(findings.len(), 1, "Should flag unconditional introspection: true");
    assert_eq!(findings[0].cve.as_str(), "BK-AI-API-004");
    assert_eq!(findings[0].severity, Severity::Medium);
    assert!(findings[0].advisory_ids.contains(&"CWE-400".to_string()));
}

#[test]
fn test_api_004_graphql_env_guarded_safe() {
    let snippet = r#"
const server = new ApolloServer({
    typeDefs,
    resolvers,
    introspection: process.env.NODE_ENV !== 'production',
});
"#;
    let path = Path::new("src/graphql/server.js");
    let findings = ApiSecurityScanner::scan_source(path, snippet);

    assert!(findings.is_empty(), "Environment guarded introspection should be safe");
}

// --- BK-AI-API-005 (CWE-862): WebSocket upgrade/authentication checked once, not per room ---

#[test]
fn test_api_005_websocket_unchecked_join() {
    let snippet = r#"
io.on('connection', (socket) => {
    socket.on('join_room', (data) => {
        socket.join(data.room);
    });
});
"#;
    let path = Path::new("src/realtime/socket.js");
    let findings = ApiSecurityScanner::scan_source(path, snippet);

    assert_eq!(findings.len(), 1, "Should flag unchecked socket.join in join_room");
    assert_eq!(findings[0].cve.as_str(), "BK-AI-API-005");
    assert_eq!(findings[0].severity, Severity::High);
    assert!(findings[0].advisory_ids.contains(&"CWE-862".to_string()));
}

#[test]
fn test_api_005_websocket_authorized_join_safe() {
    let snippet = r#"
io.on('connection', (socket) => {
    socket.on('join_room', (data) => {
        if (canJoinRoom(socket.user, data.room)) {
            socket.join(data.room);
        }
    });
});
"#;
    let path = Path::new("src/realtime/socket.js");
    let findings = ApiSecurityScanner::scan_source(path, snippet);

    assert!(findings.is_empty(), "Authorized room join should be safe");
}

// --- BK-AI-API-006 (CWE-306): gRPC interceptors omit streaming methods ---

#[test]
fn test_api_006_grpc_streaming_bypass_detected() {
    let snippet = r#"
function authInterceptor(call, headers, next) {
    if (call.getMethodDescriptor().getType().serverStream()) {
        return next.startCall(call, headers);
    }
    verifyToken(headers);
    return next.startCall(call, headers);
}
"#;
    let path = Path::new("src/grpc/authInterceptor.js");
    let findings = ApiSecurityScanner::scan_source(path, snippet);

    assert_eq!(findings.len(), 1, "Should flag gRPC streaming bypass in authInterceptor");
    assert_eq!(findings[0].cve.as_str(), "BK-AI-API-006");
    assert_eq!(findings[0].severity, Severity::High);
    assert!(findings[0].advisory_ids.contains(&"CWE-306".to_string()));
}

#[test]
fn test_api_006_grpc_all_methods_authenticated_safe() {
    let snippet = r#"
function authInterceptor(call, headers, next) {
    const token = headers.get('authorization');
    if (!token) {
        throw new StatusRuntimeException(Status.UNAUTHENTICATED);
    }
    verifyToken(token);
    return next.startCall(call, headers);
}
"#;
    let path = Path::new("src/grpc/authInterceptor.js");
    let findings = ApiSecurityScanner::scan_source(path, snippet);

    assert!(findings.is_empty(), "Unconditional gRPC authentication should be safe");
}

// --- BK-AI-API-007 (CWE-200): Pagination/filtering unbounded ---

#[test]
fn test_api_007_unbounded_pagination_limit() {
    let snippet = r#"
app.get('/api/records', async (req, res) => {
    const limit = parseInt(req.query.limit);
    const records = await db.records.find().limit(limit);
    res.json(records);
});
"#;
    let path = Path::new("src/routes/records.js");
    let findings = ApiSecurityScanner::scan_source(path, snippet);

    assert_eq!(findings.len(), 1, "Should flag uncapped parseInt(req.query.limit)");
    assert_eq!(findings[0].cve.as_str(), "BK-AI-API-007");
    assert_eq!(findings[0].severity, Severity::Medium);
    assert!(findings[0].advisory_ids.contains(&"CWE-200".to_string()));
}

#[test]
fn test_api_007_bounded_pagination_limit_safe() {
    let snippet = r#"
app.get('/api/records', async (req, res) => {
    const limit = Math.min(parseInt(req.query.limit) || 20, 100);
    const records = await db.records.find().limit(limit);
    res.json(records);
});
"#;
    let path = Path::new("src/routes/records.js");
    let findings = ApiSecurityScanner::scan_source(path, snippet);

    assert!(findings.is_empty(), "Math.min capped limit should be safe");
}

// --- BK-AI-API-008 (CWE-345): Webhook request lacks HMAC signature verification ---

#[test]
fn test_api_008_webhook_without_signature_verification() {
    let snippet = r#"
app.post('/api/webhook/stripe', (req, res) => {
    const event = req.body;
    handleOrderPaid(event.data.object);
    res.json({ received: true });
});
"#;
    let path = Path::new("src/webhooks/stripe.js");
    let findings = ApiSecurityScanner::scan_source(path, snippet);

    let webhook_findings: Vec<_> = findings.iter().filter(|f| f.cve.as_str() == "BK-AI-API-008").collect();
    assert_eq!(webhook_findings.len(), 1, "Should flag webhook handler without HMAC verification");
    assert_eq!(webhook_findings[0].severity, Severity::High);
    assert!(webhook_findings[0].advisory_ids.contains(&"CWE-345".to_string()));
}

#[test]
fn test_api_008_webhook_with_signature_verification_safe() {
    let snippet = r#"
app.post('/api/webhook/stripe', (req, res) => {
    const sig = req.headers['stripe-signature'];
    const event = stripe.webhooks.constructEvent(req.body, sig, endpointSecret);
    handleOrderPaid(event.data.object);
    res.json({ received: true });
});
"#;
    let path = Path::new("src/webhooks/stripe.js");
    let findings = ApiSecurityScanner::scan_source(path, snippet);

    assert!(findings.is_empty(), "Webhook with constructEvent verification should be safe");
}

// --- BK-AI-API-009 (CWE-201): Third-party API credentials forwarded to clients ---

#[test]
fn test_api_009_secret_key_leaked_in_response() {
    let snippet = r#"
app.get('/api/config', (req, res) => {
    res.json({ apiKey: process.env.STRIPE_SECRET_KEY });
});
"#;
    let path = Path::new("src/routes/config.js");
    let findings = ApiSecurityScanner::scan_source(path, snippet);

    assert_eq!(findings.len(), 1, "Should flag STRIPE_SECRET_KEY returned in res.json");
    assert_eq!(findings[0].cve.as_str(), "BK-AI-API-009");
    assert_eq!(findings[0].severity, Severity::High);
    assert!(findings[0].advisory_ids.contains(&"CWE-201".to_string()));
}

#[test]
fn test_api_009_publishable_key_in_response_safe() {
    let snippet = r#"
app.get('/api/config', (req, res) => {
    res.json({ publishableKey: process.env.STRIPE_PUBLISHABLE_KEY });
});
"#;
    let path = Path::new("src/routes/config.js");
    let findings = ApiSecurityScanner::scan_source(path, snippet);

    assert!(findings.is_empty(), "Publishable client keys should be safe");
}

// --- BK-AI-API-010 (CWE-20): HTTP method override bypasses validation ---

#[test]
fn test_api_010_method_override_middleware_detected() {
    let snippet = r#"
const express = require('express');
const methodOverride = require('method-override');
const app = express();

app.use(methodOverride());
app.use(express.json());
"#;
    let path = Path::new("src/server.js");
    let findings = ApiSecurityScanner::scan_source(path, snippet);

    assert_eq!(findings.len(), 1, "Should flag app.use(methodOverride())");
    assert_eq!(findings[0].cve.as_str(), "BK-AI-API-010");
    assert_eq!(findings[0].severity, Severity::Medium);
    assert!(findings[0].advisory_ids.contains(&"CWE-20".to_string()));
}

#[test]
fn test_api_010_standard_middleware_safe() {
    let snippet = r#"
const express = require('express');
const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
"#;
    let path = Path::new("src/server.js");
    let findings = ApiSecurityScanner::scan_source(path, snippet);

    assert!(findings.is_empty(), "Standard express middleware should be safe");
}

// --- BK-AI-API-011 (CWE-524): Cached privileged API response served across users ---

#[test]
fn test_api_011_public_cache_on_authenticated_endpoint() {
    let snippet = r#"
app.get('/api/user/profile', requireAuth, (req, res) => {
    res.set('Cache-Control', 'public, max-age=3600');
    res.json({ user: req.user });
});
"#;
    let path = Path::new("src/routes/user.js");
    let findings = ApiSecurityScanner::scan_source(path, snippet);

    assert_eq!(findings.len(), 1, "Should flag public Cache-Control on authenticated endpoint");
    assert_eq!(findings[0].cve.as_str(), "BK-AI-API-011");
    assert_eq!(findings[0].severity, Severity::High);
    assert!(findings[0].advisory_ids.contains(&"CWE-524".to_string()));
}

#[test]
fn test_api_011_private_cache_safe() {
    let snippet = r#"
app.get('/api/user/profile', requireAuth, (req, res) => {
    res.set('Cache-Control', 'private, no-store, no-cache');
    res.json({ user: req.user });
});
"#;
    let path = Path::new("src/routes/user.js");
    let findings = ApiSecurityScanner::scan_source(path, snippet);

    assert!(findings.is_empty(), "Private Cache-Control on authenticated endpoint should be safe");
}

// --- BK-AI-API-012 (CWE-209): Remote service errors returned with sensitive stack traces ---

#[test]
fn test_api_012_error_stack_trace_exposed() {
    let snippet = r#"
app.use((err, req, res, next) => {
    res.status(500).json({ error: err.stack });
});
"#;
    let path = Path::new("src/middleware/errorHandler.js");
    let findings = ApiSecurityScanner::scan_source(path, snippet);

    assert_eq!(findings.len(), 1, "Should flag error stack trace in response");
    assert_eq!(findings[0].cve.as_str(), "BK-AI-API-012");
    assert_eq!(findings[0].severity, Severity::Medium);
    assert!(findings[0].advisory_ids.contains(&"CWE-209".to_string()));
}

#[test]
fn test_api_012_sanitized_error_safe() {
    let snippet = r#"
app.use((err, req, res, next) => {
    logger.error(err.stack);
    res.status(500).json({ error: 'Internal Server Error' });
});
"#;
    let path = Path::new("src/middleware/errorHandler.js");
    let findings = ApiSecurityScanner::scan_source(path, snippet);

    assert!(findings.is_empty(), "Sanitized error message should be safe");
}

// --- BK-AI-API-013 (CWE-306): Server-to-server trust relies only on obscurity/unverified header ---

#[test]
fn test_api_013_unverified_header_trust() {
    let snippet = r#"
function adminGateway(req, res, next) {
    if (req.headers['x-internal'] == 'true') {
        req.isAdmin = true;
        return next();
    }
    res.status(403).json({ error: 'Forbidden' });
}
"#;
    let path = Path::new("src/middleware/adminGateway.js");
    let findings = ApiSecurityScanner::scan_source(path, snippet);

    assert_eq!(findings.len(), 1, "Should flag trust on spoofable x-internal header");
    assert_eq!(findings[0].cve.as_str(), "BK-AI-API-013");
    assert_eq!(findings[0].severity, Severity::High);
    assert!(findings[0].advisory_ids.contains(&"CWE-306".to_string()));
}

#[test]
fn test_api_013_verified_tls_client_safe() {
    let snippet = r#"
function adminGateway(req, res, next) {
    if (req.socket.authorized && req.socket.getPeerCertificate().subject.CN === 'internal-gateway') {
        req.isAdmin = true;
        return next();
    }
    res.status(403).json({ error: 'Forbidden' });
}
"#;
    let path = Path::new("src/middleware/adminGateway.js");
    let findings = ApiSecurityScanner::scan_source(path, snippet);

    assert!(findings.is_empty(), "mTLS client certificate authorization should be safe");
}

// --- BK-AI-API-014 (CWE-200): Subscription/event stream can consume other principals' updates ---

#[test]
fn test_api_014_unfiltered_broadcast_detected() {
    let snippet = r#"
function onOrderProcessed(orderData) {
    io.emit('order_update', orderData);
}
"#;
    let path = Path::new("src/events/orders.js");
    let findings = ApiSecurityScanner::scan_source(path, snippet);

    assert_eq!(findings.len(), 1, "Should flag global broadcast of order_update");
    assert_eq!(findings[0].cve.as_str(), "BK-AI-API-014");
    assert_eq!(findings[0].severity, Severity::High);
    assert!(findings[0].advisory_ids.contains(&"CWE-200".to_string()));
}

#[test]
fn test_api_014_tenant_scoped_emission_safe() {
    let snippet = r#"
function onOrderProcessed(orderData) {
    io.to(`tenant-${orderData.tenantId}`).emit('order_update', orderData);
}
"#;
    let path = Path::new("src/events/orders.js");
    let findings = ApiSecurityScanner::scan_source(path, snippet);

    assert!(findings.is_empty(), "Tenant-scoped room emission should be safe");
}
