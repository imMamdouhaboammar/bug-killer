#[path = "../src/scanner/ops_qa.rs"]
mod ops_qa;

pub use bug_killer::types;
use bug_killer::types::Severity;
use ops_qa::OpsQaScanner;
use std::path::Path;

// ===========================================================================
// Category 19: Errors, Observability & Incident Readiness (OPS-001..012)
// ===========================================================================

#[test]
fn test_ops_001_swallow_security_exception_vulnerable_and_safe() {
    let vuln_code = r#"
function verifyUserSession(token) {
    try {
        jwt.verify(token, secret);
    } catch (err) {}
}
"#;
    let path = Path::new("src/auth/session.js");
    let findings = OpsQaScanner::scan_source(path, vuln_code);
    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-OPS-001")
        .expect("Must detect swallowed security exception");
    assert_eq!(f.severity, Severity::High);
    assert_eq!(f.detector_id, "ops-qa");
    assert!(f.advisory_ids.contains(&"CWE-390".to_string()));

    let safe_code = r#"
function verifyUserSession(token) {
    try {
        jwt.verify(token, secret);
    } catch (err) {
        logger.error("Session verification failed", err);
        throw err;
    }
}
"#;
    let safe_findings = OpsQaScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-OPS-001"),
        "Safe code must not flag BK-AI-OPS-001"
    );
}

#[test]
fn test_ops_002_auth_fallback_allow_vulnerable_and_safe() {
    let vuln_code = r#"
function checkAccess(user, resource) {
    try {
        return authClient.evaluatePolicy(user, resource);
    } catch (err) {
        return true;
    }
}
"#;
    let path = Path::new("src/auth/policy.js");
    let findings = OpsQaScanner::scan_source(path, vuln_code);
    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-OPS-002")
        .expect("Must detect auth check fallback returning allow");
    assert_eq!(f.severity, Severity::Critical);
    assert!(f.advisory_ids.contains(&"CWE-755".to_string()));

    let safe_code = r#"
function checkAccess(user, resource) {
    try {
        return authClient.evaluatePolicy(user, resource);
    } catch (err) {
        return false;
    }
}
"#;
    let safe_findings = OpsQaScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-OPS-002"),
        "Safe code must not flag BK-AI-OPS-002"
    );
}

#[test]
fn test_ops_003_unlogged_security_mutation_vulnerable_and_safe() {
    let vuln_code = r#"
function grantAdminRole(userId) {
    db.users.update(userId, { role: "admin" });
}
"#;
    let path = Path::new("src/admin/roles.js");
    let findings = OpsQaScanner::scan_source(path, vuln_code);
    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-OPS-003")
        .expect("Must detect sensitive role mutation lacking audit log");
    assert_eq!(f.severity, Severity::High);
    assert!(f.advisory_ids.contains(&"CWE-778".to_string()));

    let safe_code = r#"
function grantAdminRole(userId, operatorId) {
    db.users.update(userId, { role: "admin" });
    auditLogger.log("GRANT_ADMIN", { operator: operatorId, target: userId });
}
"#;
    let safe_findings = OpsQaScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-OPS-003"),
        "Safe code with audit logging must not flag BK-AI-OPS-003"
    );
}

#[test]
fn test_ops_004_raw_secret_logging_vulnerable_and_safe() {
    let vuln_code = r#"
function authenticateClient(authHeader) {
    console.log("Client authorization header: " + authHeader);
}
"#;
    let path = Path::new("src/api/auth.js");
    let findings = OpsQaScanner::scan_source(path, vuln_code);
    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-OPS-004")
        .expect("Must detect raw authorization header logged");
    assert_eq!(f.severity, Severity::High);
    assert!(f.advisory_ids.contains(&"CWE-532".to_string()));

    let safe_code = r#"
function authenticateClient(authHeader) {
    console.log("Client auth header present: " + mask_secret(authHeader));
}
"#;
    let safe_findings = OpsQaScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-OPS-004"),
        "Safe code with masked header must not flag BK-AI-OPS-004"
    );
}

#[test]
fn test_ops_005_internal_trace_leak_vulnerable_and_safe() {
    let vuln_code = r#"
app.use((err, req, res, next) => {
    res.status(500).send(err.stack);
});
"#;
    let path = Path::new("src/server/errorHandler.js");
    let findings = OpsQaScanner::scan_source(path, vuln_code);
    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-OPS-005")
        .expect("Must detect error stack leaked to client response");
    assert_eq!(f.severity, Severity::High);
    assert!(f.advisory_ids.contains(&"CWE-209".to_string()));

    let safe_code = r#"
app.use((err, req, res, next) => {
    if (process.env.NODE_ENV === "development") {
        res.status(500).send(err.stack);
    } else {
        res.status(500).send("Internal Server Error");
    }
});
"#;
    let safe_findings = OpsQaScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-OPS-005"),
        "Safe code with development gating must not flag BK-AI-OPS-005"
    );
}

#[test]
fn test_ops_006_alert_disabled_vulnerable_and_safe() {
    let vuln_code = r#"
function muteMonitoring() {
    alerts.disabled = true;
}
"#;
    let path = Path::new("src/ops/alerts.js");
    let findings = OpsQaScanner::scan_source(path, vuln_code);
    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-OPS-006")
        .expect("Must detect alerts disabled without incident signal");
    assert_eq!(f.severity, Severity::Medium);
    assert!(f.advisory_ids.contains(&"CWE-1059".to_string()));

    let safe_code = r#"
function muteMonitoring() {
    alerts.silence({ ticket: "INC-8891", fallback: "pagerduty-sms" });
}
"#;
    let safe_findings = OpsQaScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-OPS-006"),
        "Safe code with ticket and fallback must not flag BK-AI-OPS-006"
    );
}

#[test]
fn test_ops_007_log_injection_vulnerable_and_safe() {
    let vuln_code = r#"
function handleSearch(req, res) {
    logger.info("Search query submitted: " + req.query.user_input);
}
"#;
    let path = Path::new("src/routes/search.js");
    let findings = OpsQaScanner::scan_source(path, vuln_code);
    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-OPS-007")
        .expect("Must detect unescaped user input logged directly");
    assert_eq!(f.severity, Severity::Medium);
    assert!(f.advisory_ids.contains(&"CWE-117".to_string()));

    let safe_code = r#"
function handleSearch(req, res) {
    const clean_input = req.query.user_input.replace(/[\r\n]/g, "");
    logger.info("Search query submitted: " + clean_input);
}
"#;
    let safe_findings = OpsQaScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-OPS-007"),
        "Safe code with newline sanitization must not flag BK-AI-OPS-007"
    );
}

#[test]
fn test_ops_008_audit_missing_correlation_vulnerable_and_safe() {
    let vuln_code = r#"
function recordUserDelete(userId) {
    auditLog.record({
        action: "MUTATION_DELETE_ACCOUNT",
        target: userId
    });
}
"#;
    let path = Path::new("src/audit/events.js");
    let findings = OpsQaScanner::scan_source(path, vuln_code);
    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-OPS-008")
        .expect("Must detect audit event without correlation or trace ID");
    assert_eq!(f.severity, Severity::Medium);
    assert!(f.advisory_ids.contains(&"CWE-778".to_string()));

    let safe_code = r#"
function recordUserDelete(userId, correlation_id) {
    auditLog.record({
        action: "MUTATION_DELETE_ACCOUNT",
        target: userId,
        correlation_id: correlation_id
    });
}
"#;
    let safe_findings = OpsQaScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-OPS-008"),
        "Safe code with correlation_id must not flag BK-AI-OPS-008"
    );
}

#[test]
fn test_ops_009_audit_log_mutation_vulnerable_and_safe() {
    let vuln_code = r#"
async function purgeOldLogs() {
    await db.query("DELETE FROM audit_logs WHERE created_at < NOW() - INTERVAL 90 DAY");
}
"#;
    let path = Path::new("src/jobs/purge.js");
    let findings = OpsQaScanner::scan_source(path, vuln_code);
    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-OPS-009")
        .expect("Must detect DELETE FROM audit_logs operation");
    assert_eq!(f.severity, Severity::High);
    assert!(f.advisory_ids.contains(&"CWE-284".to_string()));

    let safe_code = r#"
// Storage configured under WORM append_only compliance mode
async function fetchOldLogs() {
    await db.query("SELECT * FROM audit_logs WHERE created_at < NOW() - INTERVAL 90 DAY");
}
"#;
    let safe_findings = OpsQaScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-OPS-009"),
        "Safe code with WORM policy must not flag BK-AI-OPS-009"
    );
}

#[test]
fn test_ops_010_untested_backup_restore_vulnerable_and_safe() {
    let vuln_code = r#"
runbook:
  name: "production-disaster-recovery"
  auto_rollback: true
  backup_restore_tested: false
"#;
    let path = Path::new("runbooks/dr.yaml");
    let findings = OpsQaScanner::scan_source(path, vuln_code);
    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-OPS-010")
        .expect("Must detect untested backup restore procedure in runbook");
    assert_eq!(f.severity, Severity::Medium);
    assert!(f.advisory_ids.contains(&"CWE-693".to_string()));

    let safe_code = r#"
runbook:
  name: "production-disaster-recovery"
  auto_rollback: true
  backup_restore_tested: true
"#;
    let safe_findings = OpsQaScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-OPS-010"),
        "Safe code with tested restore must not flag BK-AI-OPS-010"
    );
}

#[test]
fn test_ops_011_shallow_healthcheck_vulnerable_and_safe() {
    let vuln_code = r#"
app.get("/healthz", (req, res) => {
    res.status(200).send("OK");
});
"#;
    let path = Path::new("src/routes/health.js");
    let findings = OpsQaScanner::scan_source(path, vuln_code);
    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-OPS-011")
        .expect("Must detect shallow healthcheck endpoint without dependency checks");
    assert_eq!(f.severity, Severity::Medium);
    assert!(f.advisory_ids.contains(&"CWE-754".to_string()));

    let safe_code = r#"
app.get("/healthz", async (req, res) => {
    const isDbReady = await check_database();
    if (!isDbReady) {
        return res.status(503).send("ServiceUnavailable");
    }
    res.status(200).send("OK");
});
"#;
    let safe_findings = OpsQaScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-OPS-011"),
        "Safe code with dependency readiness check must not flag BK-AI-OPS-011"
    );
}

#[test]
fn test_ops_012_suppressed_security_test_vulnerable_and_safe() {
    let vuln_code = r#"
@pytest.mark.skip(reason="security test fails on CI worker")
def test_jwt_signature_verification():
    pass
"#;
    let path = Path::new("tests/test_auth.py");
    let findings = OpsQaScanner::scan_source(path, vuln_code);
    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-OPS-012")
        .expect("Must detect skipped security test");
    assert_eq!(f.severity, Severity::Medium);
    assert!(f.advisory_ids.contains(&"CWE-1059".to_string()));

    let safe_code = r#"
def test_jwt_signature_verification():
    assert verify_signature(token) is True
"#;
    let safe_findings = OpsQaScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-OPS-012"),
        "Safe active security test must not flag BK-AI-OPS-012"
    );
}

// ===========================================================================
// Category 27: Security-Test Integrity, Human Review & Quality (QAT-001..012)
// ===========================================================================

#[test]
fn test_qat_001_weak_validator_test_vulnerable_and_safe() {
    let vuln_code = r#"
test("auth validator exists", () => {
    expect(authValidator).toBeDefined();
});
"#;
    let path = Path::new("tests/auth.test.js");
    let findings = OpsQaScanner::scan_source(path, vuln_code);
    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-QAT-001")
        .expect("Must detect weak test checking only validator existence");
    assert_eq!(f.severity, Severity::High);
    assert!(f.advisory_ids.contains(&"CWE-1059".to_string()));

    let safe_code = r#"
test("auth validator rejects malformed payload", () => {
    expect(() => authValidator.validate("malformed")).toThrow();
});
"#;
    let safe_findings = OpsQaScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-QAT-001"),
        "Safe test verifying rejection behavior must not flag BK-AI-QAT-001"
    );
}

#[test]
fn test_qat_002_fixture_lacks_safe_lookalike_vulnerable_and_safe() {
    let vuln_code = r#"
rule_fixture_manifest:
  rule_id: "BK-AI-INJ-001"
  safe_lookalike_fixture: false
"#;
    let path = Path::new("fixtures/rules.yaml");
    let findings = OpsQaScanner::scan_source(path, vuln_code);
    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-QAT-002")
        .expect("Must detect fixture definition lacking safe lookalike");
    assert_eq!(f.severity, Severity::Medium);
    assert!(f.advisory_ids.contains(&"CWE-1059".to_string()));

    let safe_code = r#"
rule_fixture_manifest:
  rule_id: "BK-AI-INJ-001"
  safe_lookalike_fixture: true
"#;
    let safe_findings = OpsQaScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-QAT-002"),
        "Safe fixture manifest with safe counterpart must not flag BK-AI-QAT-002"
    );
}

#[test]
fn test_qat_003_scanner_extension_only_vulnerable_and_safe() {
    let vuln_code = r#"
function scanDirectory(file) {
    if (!file.endsWith('.js')) return;
    executeAnalysis(file);
}
"#;
    let path = Path::new("src/engine/traversal.js");
    let findings = OpsQaScanner::scan_source(path, vuln_code);
    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-QAT-003")
        .expect("Must detect scanner relying solely on extension");
    assert_eq!(f.severity, Severity::Medium);
    assert!(f.advisory_ids.contains(&"CWE-1059".to_string()));

    let safe_code = r#"
function scanDirectory(file) {
    if (!file.endsWith('.js') && !detect_content_type(file)) return;
    executeAnalysis(file);
}
"#;
    let safe_findings = OpsQaScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-QAT-003"),
        "Safe scanner with content type sniffing must not flag BK-AI-QAT-003"
    );
}

#[test]
fn test_qat_004_unversioned_rule_coverage_vulnerable_and_safe() {
    let vuln_code = r#"
{
  "rule_id": "BK-AI-SQL-001",
  "framework": "django",
  "version_pinned": false
}
"#;
    let path = Path::new("rules/sql_injection.json");
    let findings = OpsQaScanner::scan_source(path, vuln_code);
    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-QAT-004")
        .expect("Must detect unpinned framework version rule definition");
    assert_eq!(f.severity, Severity::Low);
    assert!(f.advisory_ids.contains(&"CWE-1059".to_string()));

    let safe_code = r#"
{
  "rule_id": "BK-AI-SQL-001",
  "framework": "django",
  "version_pinned": true
}
"#;
    let safe_findings = OpsQaScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-QAT-004"),
        "Safe rule definition with pinned version must not flag BK-AI-QAT-004"
    );
}

#[test]
fn test_qat_005_single_tenant_test_run_vulnerable_and_safe() {
    let vuln_code = r#"
suite("Tenant isolation suite", () => {
    const config = {
        test_tenants: ["tenant_1"],
        matrix_tenant_isolation: false
    };
});
"#;
    let path = Path::new("tests/isolation.test.js");
    let findings = OpsQaScanner::scan_source(path, vuln_code);
    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-QAT-005")
        .expect("Must detect test run covering only single tenant without isolation verification");
    assert_eq!(f.severity, Severity::Medium);
    assert!(f.advisory_ids.contains(&"CWE-1059".to_string()));

    let safe_code = r#"
suite("Tenant isolation suite", () => {
    const config = {
        test_tenants: ["tenant_1", "tenant_2"],
        matrix_tenant_isolation: true
    };
});
"#;
    let safe_findings = OpsQaScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-QAT-005"),
        "Safe test matrix covering multiple tenants must not flag BK-AI-QAT-005"
    );
}

#[test]
fn test_qat_006_ignored_indirect_imports_vulnerable_and_safe() {
    let vuln_code = r#"
analyzer_options:
  resolve_aliases: false
  ignore_dynamic_imports: true
"#;
    let path = Path::new("config/analyzer.yaml");
    let findings = OpsQaScanner::scan_source(path, vuln_code);
    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-QAT-006")
        .expect("Must detect scanner silently ignoring dynamic/indirect imports");
    assert_eq!(f.severity, Severity::Medium);
    assert!(f.advisory_ids.contains(&"CWE-1059".to_string()));

    let safe_code = r#"
analyzer_options:
  resolve_aliases: true
  track_indirect_imports: true
  disclose_untracked_dynamic_imports: true
"#;
    let safe_findings = OpsQaScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-QAT-006"),
        "Safe config disclosing untracked imports must not flag BK-AI-QAT-006"
    );
}

#[test]
fn test_qat_007_severity_from_cwe_alone_vulnerable_and_safe() {
    let vuln_code = r#"
def assign_severity(cwe):
    infer_severity_from_cwe_only = true
    return CWE_SEVERITY[cwe]
"#;
    let path = Path::new("src/scoring/severity.py");
    let findings = OpsQaScanner::scan_source(path, vuln_code);
    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-QAT-007")
        .expect("Must detect severity calculated strictly from CWE table");
    assert_eq!(f.severity, Severity::Medium);
    assert!(f.advisory_ids.contains(&"CWE-1059".to_string()));

    let safe_code = r#"
def assign_severity(cwe, call_graph):
    base_cwe = CWE_SEVERITY[cwe]
    reachability = evaluate_reachability(call_graph)
    return compute_effective_severity(base_cwe, reachability)
"#;
    let safe_findings = OpsQaScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-QAT-007"),
        "Safe scoring factoring reachability must not flag BK-AI-QAT-007"
    );
}

#[test]
fn test_qat_008_untested_mitigation_classification_vulnerable_and_safe() {
    let vuln_code = r#"
function triageVulnerability(finding) {
    finding.status = "Mitigated";
    finding.verified = false;
}
"#;
    let path = Path::new("src/triage/resolution.js");
    let findings = OpsQaScanner::scan_source(path, vuln_code);
    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-QAT-008")
        .expect("Must detect mitigated finding status accepted without test verification");
    assert_eq!(f.severity, Severity::High);
    assert!(f.advisory_ids.contains(&"CWE-1059".to_string()));

    let safe_code = r#"
function triageVulnerability(finding) {
    finding.status = "Mitigated";
    finding.verification_test = "test_guard_sanitizer";
    assert_mitigation_test(finding.verification_test);
}
"#;
    let safe_findings = OpsQaScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-QAT-008"),
        "Safe triage requiring verification test must not flag BK-AI-QAT-008"
    );
}

#[test]
fn test_qat_009_live_external_system_in_test_vulnerable_and_safe() {
    let vuln_code = r#"
describe("Billing test suite", () => {
    it("dispatches live transaction", async () => {
        const response = await fetch("https://api.stripe.com/v1/charges", { method: "POST" });
    });
});
"#;
    let path = Path::new("tests/billing.test.js");
    let findings = OpsQaScanner::scan_source(path, vuln_code);
    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-QAT-009")
        .expect("Must detect live external API invoked directly in test suite");
    assert_eq!(f.severity, Severity::High);
    assert!(f.advisory_ids.contains(&"CWE-1059".to_string()));

    let safe_code = r#"
describe("Billing test suite", () => {
    it("dispatches mocked transaction", async () => {
        nock("https://api.stripe.com").post("/v1/charges").reply(200, { id: "ch_test" });
        const response = await fetch("https://api.stripe.com/v1/charges", { method: "POST" });
    });
});
"#;
    let safe_findings = OpsQaScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-QAT-009"),
        "Safe test using nock/mock must not flag BK-AI-QAT-009"
    );
}

#[test]
fn test_qat_010_hidden_suppressions_in_report_vulnerable_and_safe() {
    let vuln_code = r#"
{
  "report_config": {
    "title": "Quarterly Executive Security Audit",
    "hide_suppressed": true
  }
}
"#;
    let path = Path::new("reports/config.json");
    let findings = OpsQaScanner::scan_source(path, vuln_code);
    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-QAT-010")
        .expect("Must detect report configuration that conceals suppressed findings");
    assert_eq!(f.severity, Severity::Medium);
    assert!(f.advisory_ids.contains(&"CWE-1059".to_string()));

    let safe_code = r#"
{
  "report_config": {
    "title": "Quarterly Executive Security Audit",
    "include_suppressed": true,
    "show_coverage_gaps": true
  }
}
"#;
    let safe_findings = OpsQaScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-QAT-010"),
        "Safe reporting config including suppressions must not flag BK-AI-QAT-010"
    );
}

#[test]
fn test_qat_011_blind_auto_repair_vulnerable_and_safe() {
    let vuln_code = r#"
function autoHealFile(filePath, fixedCode) {
    auto_repair_apply({ create_backup: false });
}
"#;
    let path = Path::new("src/healer/patcher.js");
    let findings = OpsQaScanner::scan_source(path, vuln_code);
    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-QAT-011")
        .expect("Must detect auto repair write without backup or diff");
    assert_eq!(f.severity, Severity::High);
    assert!(f.advisory_ids.contains(&"CWE-1059".to_string()));

    let safe_code = r#"
function autoHealFile(filePath, fixedCode) {
    create_backup(filePath);
    show_diff(filePath, fixedCode);
    verify_repair(filePath);
}
"#;
    let safe_findings = OpsQaScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-QAT-011"),
        "Safe auto repair creating backup and diff must not flag BK-AI-QAT-011"
    );
}

#[test]
fn test_qat_012_self_signed_ai_review_vulnerable_and_safe() {
    let vuln_code = r#"
def evaluate_autonomous_fix(patch):
    ai_review_self_sign = true
    ai_review.verified = True
"#;
    let path = Path::new("src/agent/eval.py");
    let findings = OpsQaScanner::scan_source(path, vuln_code);
    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-QAT-012")
        .expect("Must detect LLM marking its own output as verified");
    assert_eq!(f.severity, Severity::High);
    assert!(f.advisory_ids.contains(&"CWE-1059".to_string()));

    let safe_code = r#"
def evaluate_autonomous_fix(patch):
    consensus = multi_model_consensus(patch)
    sandbox_ok = sandbox_verification(patch)
    return consensus and sandbox_ok
"#;
    let safe_findings = OpsQaScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-QAT-012"),
        "Safe multi-model/sandbox verification must not flag BK-AI-QAT-012"
    );
}
