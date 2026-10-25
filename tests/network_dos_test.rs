#[path = "../src/scanner/network_dos.rs"]
mod network_dos;

pub use bug_killer::types;
use bug_killer::types::Severity;
use network_dos::NetworkDosScanner;
use std::path::Path;

// ===========================================================================
// Category 8: SSRF & Outbound HTTP Tests (BK-AI-NET-001 through 010)
// ===========================================================================

#[test]
fn test_net_001_vulnerable_axios_user_url() {
    let snippet = r#"
app.get('/fetch-preview', async (req, res) => {
    const response = await axios.get(req.query.url);
    res.send(response.data);
});
"#;
    let path = Path::new("src/routes/preview.js");
    let findings = NetworkDosScanner::scan_source(path, snippet);

    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-NET-001")
        .expect("Must flag user-provided URL in axios.get");
    assert_eq!(f.severity, Severity::High);
    assert_eq!(f.detector_id, "network-dos");
    assert!(f.advisory_ids.contains(&"CWE-918".to_string()));
}

#[test]
fn test_net_001_safe_with_allowlist_guard() {
    let snippet = r#"
app.get('/fetch-preview', async (req, res) => {
    const targetUrl = req.query.url;
    if (!isAllowedUrl(targetUrl)) {
        return res.status(403).send("Forbidden domain");
    }
    const response = await axios.get(targetUrl);
    res.send(response.data);
});
"#;
    let path = Path::new("src/routes/preview.js");
    let findings = NetworkDosScanner::scan_source(path, snippet);
    assert!(
        findings.iter().all(|f| f.cve.as_str() != "BK-AI-NET-001"),
        "Must not flag when validateUrl / isAllowedUrl guard is present"
    );
}

#[test]
fn test_net_002_metadata_access() {
    let snippet = r#"
async function getRole() {
    const res = await axios.get('http://169.254.169.254/latest/meta-data/iam/security-credentials/');
    return res.data;
}
"#;
    let path = Path::new("src/services/aws.js");
    let findings = NetworkDosScanner::scan_source(path, snippet);

    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-NET-002")
        .expect("Must flag 169.254.169.254 metadata endpoint request");
    assert_eq!(f.severity, Severity::High);
    assert_eq!(f.detector_id, "network-dos");
}

#[test]
fn test_net_002_safe_private_ip_filter() {
    let snippet = r#"
async function sendWebhook(destination) {
    if (isPrivateIp(destination)) {
        throw new Error("Loopback and private IPs are blocked");
    }
    return await fetch(destination);
}
"#;
    let path = Path::new("src/services/webhook.js");
    let findings = NetworkDosScanner::scan_source(path, snippet);
    assert!(
        findings.iter().all(|f| f.cve.as_str() != "BK-AI-NET-002"),
        "Should not flag when isPrivateIp guard protects destination"
    );
}

#[test]
fn test_net_003_unconditional_redirect() {
    let snippet = r#"
const client = axios.create({
    maxRedirects: 10,
    timeout: 5000,
});
"#;
    let path = Path::new("src/lib/httpClient.js");
    let findings = NetworkDosScanner::scan_source(path, snippet);

    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-NET-003")
        .expect("Must flag maxRedirects without redirect validator");
    assert_eq!(f.severity, Severity::Medium);
}

#[test]
fn test_net_003_safe_redirect_validation() {
    let snippet = r#"
const client = axios.create({
    maxRedirects: 5,
    beforeRedirect: (options, responseDetails) => {
        validateRedirect(options.href);
    },
});
"#;
    let path = Path::new("src/lib/httpClient.js");
    let findings = NetworkDosScanner::scan_source(path, snippet);
    assert!(
        findings.iter().all(|f| f.cve.as_str() != "BK-AI-NET-003"),
        "Should not flag when beforeRedirect validator is declared"
    );
}

#[test]
fn test_net_004_dns_rebinding_toctou() {
    let snippet = r#"
async function fetchUserResource(rawUrl) {
    const parsed = new URL(rawUrl);
    const resolved = await dns.lookup(parsed.hostname);
    // DNS check then fetch
    const response = await fetch(rawUrl);
    return response.text();
}
"#;
    let path = Path::new("src/services/fetcher.js");
    let findings = NetworkDosScanner::scan_source(path, snippet);

    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-NET-004")
        .expect("Must flag DNS lookup followed by unpinned fetch");
    assert_eq!(f.severity, Severity::High);
}

#[test]
fn test_net_004_safe_pinned_ip() {
    let snippet = r#"
async function fetchUserResource(rawUrl) {
    const parsed = new URL(rawUrl);
    const resolved = await dns.lookup(parsed.hostname);
    const agent = new http.Agent({ lookup: (hostname, opts, cb) => cb(null, resolved.address, 4) });
    const response = await fetch(rawUrl, { agent });
    return response.text();
}
"#;
    let path = Path::new("src/services/fetcher.js");
    let findings = NetworkDosScanner::scan_source(path, snippet);
    assert!(
        findings.iter().all(|f| f.cve.as_str() != "BK-AI-NET-004"),
        "Should not flag when pinned IP agent is used"
    );
}

#[test]
fn test_net_005_dangerous_scheme() {
    let snippet = r#"
const allowedSchemes = ['http', 'https', 'file', 'gopher'];
function fetchResource(scheme, host) {
    return fetch(`${scheme}://${host}`);
}
"#;
    let path = Path::new("src/services/resource.js");
    let findings = NetworkDosScanner::scan_source(path, snippet);

    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-NET-005")
        .expect("Must flag non-HTTP schemes allowed in fetcher");
    assert_eq!(f.severity, Severity::High);
}

#[test]
fn test_net_005_safe_http_only() {
    let snippet = r#"
const allowedSchemes = ['https'];
function fetchResource(scheme, host) {
    if (!allowedSchemes.includes(scheme)) throw new Error('Unsupported scheme');
    return fetch(`https://${host}`);
}
"#;
    let path = Path::new("src/services/resource.js");
    let findings = NetworkDosScanner::scan_source(path, snippet);
    assert!(
        findings.iter().all(|f| f.cve.as_str() != "BK-AI-NET-005"),
        "Should not flag strictly HTTPS scheme allowlists"
    );
}

#[test]
fn test_net_006_proxy_bypass() {
    let snippet = r#"
process.env.NO_PROXY = "*";
const res = await axios.get("https://internal.service.local/data");
"#;
    let path = Path::new("src/lib/egress.js");
    let findings = NetworkDosScanner::scan_source(path, snippet);

    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-NET-006")
        .expect("Must flag NO_PROXY=* wildcard bypass");
    assert_eq!(f.severity, Severity::Medium);
}

#[test]
fn test_net_007_tls_verify_disabled() {
    let snippet = r#"
const agent = new https.Agent({
    rejectUnauthorized: false
});
"#;
    let path = Path::new("src/net/agent.js");
    let findings = NetworkDosScanner::scan_source(path, snippet);

    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-NET-007")
        .expect("Must flag rejectUnauthorized: false");
    assert_eq!(f.severity, Severity::High);
    assert!(f.advisory_ids.contains(&"CWE-295".to_string()));
}

#[test]
fn test_net_007_tls_verify_python() {
    let snippet = r#"
response = requests.get("https://example.com/api", verify=False)
"#;
    let path = Path::new("scripts/sync.py");
    let findings = NetworkDosScanner::scan_source(path, snippet);

    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-NET-007")
        .expect("Must flag verify=False in Python requests");
    assert_eq!(f.severity, Severity::High);
}

#[test]
fn test_net_008_accept_all_certs() {
    let snippet = r#"
const client = tls.connect({
    host: 'api.partner.com',
    port: 443,
    checkServerIdentity: () => null
});
"#;
    let path = Path::new("src/net/tls.js");
    let findings = NetworkDosScanner::scan_source(path, snippet);

    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-NET-008")
        .expect("Must flag checkServerIdentity: () => null stub");
    assert_eq!(f.severity, Severity::High);
}

#[test]
fn test_net_009_auth_forwarding() {
    let snippet = r#"
app.get('/proxy', async (req, res) => {
    // forward authorization to redirect
    const out = await axios.get(req.query.externalUrl, {
        headers: { Authorization: req.headers.authorization }
    });
    res.send(out.data);
});
"#;
    let path = Path::new("src/routes/proxy.js");
    let findings = NetworkDosScanner::scan_source(path, snippet);

    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-NET-009")
        .expect("Must flag forwarding Authorization header to external URL");
    assert_eq!(f.severity, Severity::High);
    assert!(f.advisory_ids.contains(&"CWE-201".to_string()));
}

#[test]
fn test_net_010_timeout_zero() {
    let snippet = r#"
const client = axios.create({
    baseURL: 'https://api.external.com',
    timeout: 0,
});
"#;
    let path = Path::new("src/client.js");
    let findings = NetworkDosScanner::scan_source(path, snippet);

    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-NET-010")
        .expect("Must flag timeout: 0 in network client");
    assert_eq!(f.severity, Severity::Medium);
}

// ===========================================================================
// Category 16: Availability & Denial of Service Tests (BK-AI-DOS-001 through 012)
// ===========================================================================

#[test]
fn test_dos_001_unbounded_recursion() {
    let snippet = r#"
// unbounded recursion
function traverseTree(node) {
    for (const child of node.children) {
        traverseTree(child);
    }
}
"#;
    let path = Path::new("src/utils/tree.js");
    let findings = NetworkDosScanner::scan_source(path, snippet);

    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-DOS-001")
        .expect("Must flag unbounded recursion");
    assert_eq!(f.severity, Severity::High);
    assert!(f.advisory_ids.contains(&"CWE-674".to_string()));
}

#[test]
fn test_dos_001_safe_bounded_recursion() {
    let snippet = r#"
function traverseTree(node, depth = 0) {
    if (depth > 10) return;
    for (const child of node.children) {
        traverseTree(child, depth + 1);
    }
}
"#;
    let path = Path::new("src/utils/tree.js");
    let findings = NetworkDosScanner::scan_source(path, snippet);
    assert!(
        findings.iter().all(|f| f.cve.as_str() != "BK-AI-DOS-001"),
        "Should not flag when recursion depth limit is implemented"
    );
}

#[test]
fn test_dos_002_excessive_body_limit() {
    let snippet = r#"
app.use(express.json({ limit: '100gb' }));
"#;
    let path = Path::new("src/server.js");
    let findings = NetworkDosScanner::scan_source(path, snippet);

    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-DOS-002")
        .expect("Must flag 100gb body limit");
    assert_eq!(f.severity, Severity::High);
}

#[test]
fn test_dos_002_safe_body_limit() {
    let snippet = r#"
app.use(express.json({ limit: '10mb' }));
"#;
    let path = Path::new("src/server.js");
    let findings = NetworkDosScanner::scan_source(path, snippet);
    assert!(
        findings.iter().all(|f| f.cve.as_str() != "BK-AI-DOS-002"),
        "Should not flag standard 10mb body limit"
    );
}

#[test]
fn test_dos_003_unlimited_concurrency() {
    let snippet = r#"
app.post('/batch-process', async (req, res) => {
    await Promise.all(items.map(async item => {
        await processItem(item);
    }));
    res.json({ status: 'done' });
});
"#;
    let path = Path::new("src/controllers/batch.js");
    let findings = NetworkDosScanner::scan_source(path, snippet);

    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-DOS-003")
        .expect("Must flag unbounded Promise.all concurrency");
    assert_eq!(f.severity, Severity::High);
    assert!(f.advisory_ids.contains(&"CWE-770".to_string()));
}

#[test]
fn test_dos_003_safe_concurrency_p_limit() {
    let snippet = r#"
const pLimit = require('p-limit');
const limit = pLimit(5);

app.post('/batch-process', async (req, res) => {
    await Promise.all(items.map(item => limit(() => processItem(item))));
    res.json({ status: 'done' });
});
"#;
    let path = Path::new("src/controllers/batch.js");
    let findings = NetworkDosScanner::scan_source(path, snippet);
    assert!(
        findings.iter().all(|f| f.cve.as_str() != "BK-AI-DOS-003"),
        "Should not flag when pLimit concurrency throttling is present"
    );
}

#[test]
fn test_dos_004_zero_timeout_socket() {
    let snippet = r#"
const server = net.createServer((socket) => {
    socket.setTimeout(0);
});
"#;
    let path = Path::new("src/server/tcp.js");
    let findings = NetworkDosScanner::scan_source(path, snippet);

    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-DOS-004")
        .expect("Must flag socket.setTimeout(0)");
    assert_eq!(f.severity, Severity::Medium);
}

#[test]
fn test_dos_005_retry_storm_zero_delay() {
    let snippet = r#"
// retry storm without backoff
for i in range(100): retry()
"#;
    let path = Path::new("src/services/poller.py");
    let findings = NetworkDosScanner::scan_source(path, snippet);

    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-DOS-005")
        .expect("Must flag retry storm without backoff");
    assert_eq!(f.severity, Severity::Medium);
}

#[test]
fn test_dos_006_unbounded_cache() {
    let snippet = r#"
const cache = {};
function getOrCreate(key, val) {
    cache[key] = val;
    return val;
}
"#;
    let path = Path::new("src/services/cache.js");
    let findings = NetworkDosScanner::scan_source(path, snippet);

    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-DOS-006")
        .expect("Must flag unbounded in-memory cache without eviction");
    assert_eq!(f.severity, Severity::High);
}

#[test]
fn test_dos_006_safe_lru_cache() {
    let snippet = r#"
const { LRUCache } = require('lru-cache');
const cache = new LRUCache({ max: 500, ttl: 1000 * 60 * 5 });
function getOrCreate(key, val) {
    cache.set(key, val);
    return val;
}
"#;
    let path = Path::new("src/services/cache.js");
    let findings = NetworkDosScanner::scan_source(path, snippet);
    assert!(
        findings.iter().all(|f| f.cve.as_str() != "BK-AI-DOS-006"),
        "Should not flag when bounded LRU cache with eviction is used"
    );
}

#[test]
fn test_dos_007_unpaginated_db_query() {
    let snippet = r#"
// query lacks pagination
app.get('/api/users', async (req, res) => {
    const users = await db.query("SELECT * FROM users");
    res.json(users);
});
"#;
    let path = Path::new("src/routes/users.js");
    let findings = NetworkDosScanner::scan_source(path, snippet);

    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-DOS-007")
        .expect("Must flag unpaginated SELECT query");
    assert_eq!(f.severity, Severity::Medium);
}

#[test]
fn test_dos_007_safe_paginated_db_query() {
    let snippet = r#"
app.get('/api/users', async (req, res) => {
    const limit = Math.min(parseInt(req.query.limit) || 20, 100);
    const users = await db.query(`SELECT * FROM users LIMIT ${limit}`);
    res.json(users);
});
"#;
    let path = Path::new("src/routes/users.js");
    let findings = NetworkDosScanner::scan_source(path, snippet);
    assert!(
        findings.iter().all(|f| f.cve.as_str() != "BK-AI-DOS-007"),
        "Should not flag queries with LIMIT clauses"
    );
}

#[test]
fn test_dos_008_catastrophic_backtracking_regex() {
    let snippet = r#"
// catastrophic backtracking
const regex = /(a+)+$/;
const isValid = regex.test(userInput);
"#;
    let path = Path::new("src/validation/matcher.js");
    let findings = NetworkDosScanner::scan_source(path, snippet);

    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-DOS-008")
        .expect("Must flag ReDoS polynomial/catastrophic regex");
    assert_eq!(f.severity, Severity::High);
    assert!(f.advisory_ids.contains(&"CWE-1333".to_string()));
}

#[test]
fn test_dos_009_llm_without_max_tokens() {
    let snippet = r#"
const completion = await openai.chat.completions.create({
    model: "gpt-4o",
    messages: [{ role: "user", content: prompt }]
});
"#;
    let path = Path::new("src/ai/generate.js");
    let findings = NetworkDosScanner::scan_source(path, snippet);

    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-DOS-009")
        .expect("Must flag LLM completion call without max_tokens");
    assert_eq!(f.severity, Severity::High);
}

#[test]
fn test_dos_009_safe_llm_with_max_tokens() {
    let snippet = r#"
const completion = await openai.chat.completions.create({
    model: "gpt-4o",
    messages: [{ role: "user", content: prompt }],
    max_tokens: 1024
});
"#;
    let path = Path::new("src/ai/generate.js");
    let findings = NetworkDosScanner::scan_source(path, snippet);
    assert!(
        findings.iter().all(|f| f.cve.as_str() != "BK-AI-DOS-009"),
        "Should not flag LLM completion specifying max_tokens"
    );
}

#[test]
fn test_dos_010_unbounded_queue_no_backpressure() {
    let snippet = r#"
// unbounded queue
const stream = getStream({ highWaterMark: Infinity });
"#;
    let path = Path::new("src/pipeline/stream.js");
    let findings = NetworkDosScanner::scan_source(path, snippet);

    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-DOS-010")
        .expect("Must flag unbounded queue / highWaterMark: Infinity");
    assert_eq!(f.severity, Severity::Medium);
}

#[test]
fn test_dos_011_unbounded_crawl() {
    let snippet = r#"
// unbounded directory crawl
const files = fs.readdirSync('/var/data', { recursive: true });
"#;
    let path = Path::new("src/storage/scanner.js");
    let findings = NetworkDosScanner::scan_source(path, snippet);

    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-DOS-011")
        .expect("Must flag unbounded directory recursion");
    assert_eq!(f.severity, Severity::Medium);
}

#[test]
fn test_dos_012_disk_exhaustion_error_dump() {
    let snippet = r#"
app.use((err, req, res, next) => {
    fs.appendFileSync('/var/log/app_crashes.log', JSON.stringify(req));
    res.status(500).send("Error logged");
});
"#;
    let path = Path::new("src/middleware/error.js");
    let findings = NetworkDosScanner::scan_source(path, snippet);

    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-DOS-012")
        .expect("Must flag dumping whole req to disk on error");
    assert_eq!(f.severity, Severity::Medium);
}
