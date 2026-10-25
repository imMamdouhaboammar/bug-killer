#![allow(dead_code, clippy::collapsible_if)]

use crate::types::*;
use regex::Regex;
use std::collections::HashSet;
use std::path::Path;
use std::sync::LazyLock;

// ===========================================================================
// Category 19: Errors, Observability & Incident Readiness (BK-AI-OPS-001..012)
// Category 27: Security-Test Integrity, Human Review & Quality (BK-AI-QAT-001..012)
// ===========================================================================

const CATEGORY_OPS: &str = "2.19 Errors, observability and incident readiness";
const CATEGORY_QAT: &str = "2.27 Security-test integrity, human review and quality controls";

// ---------------------------------------------------------------------------
// Category 19 Regexes
// ---------------------------------------------------------------------------

/// BK-AI-OPS-001 (CWE-390): Security exception swallowed with empty catch or unwrap_or_default()
static RE_OPS_001_SWALLOW_CATCH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)catch\s*(?:\([^)]*\))?\s*\{\s*(?://[^\n]*\s*)*\}"#).unwrap()
});
static RE_OPS_001_SECURITY_CONTEXT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(?:auth|authenticate|verify_token|verifyToken|jwt|permission|signature|credential|claims|rbac|cipher|decrypt|encrypt|security|password|hash)\b"#).unwrap()
});
static RE_OPS_001_UNWRAP_DEFAULT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(?:verify|authenticate|auth|token|jwt|claims|permission|signature|credentials?)\b[^\n]*\bunwrap_or_default\s*\(\s*\)|\bunwrap_or_default\s*\(\s*\)[^\n]*(?:verify|authenticate|auth|token|jwt|claims|permission)"#).unwrap()
});
static RE_OPS_001_PYTHON_PASS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)except\s+(?:[a-zA-Z0-9_]*(?:Auth|Security|Permission|Token|Crypto|Signature|Forbidden)[a-zA-Z0-9_]*)\s*:\s*(?:pass|\.\.\.)\b"#).unwrap()
});
static RE_OPS_001_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:throw\b|raise\b|return\s+(?:Err\b|false\b|null\b|nil\b)|(?:logger|log|tracing|console)\.(?:error|warn)|panic!\b)"#).unwrap()
});

/// BK-AI-OPS-002 (CWE-755): Authentication/authorization check returns allow after timeout/error
static RE_OPS_002_RETURN_TRUE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\breturn\s+(?:true|1|True|ALLOW|Status::Allowed)\b"#).unwrap()
});
static RE_OPS_002_CATCH_ALLOW: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is)(?:catch\s*(?:\([^)]*\))?\s*\{[^}]*?\breturn\s+(?:true|1|True|ALLOW|Status::Allowed)\b|except\s+[^:]*:\s*[\s\S]*?\breturn\s+True\b|if\s+err\s*!=\s*nil\s*\{[\s\S]*?\breturn\s+true\b)"#).unwrap()
});
static RE_OPS_002_CONFIG_ALLOW: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(?:fallback_allow|fallback_permit|allow_on_timeout|allow_on_error|fail_open)\s*[:=]\s*(?:true|1|True|["']allow["']|["']permit["'])\b|\bon_timeout\s*[:=]\s*["'](?:allow|permit)["']"#).unwrap()
});
static RE_OPS_002_AUTH_CONTEXT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(?:auth|authorize|permission|is_authorized|can_access|check_access|checkAccess|verify|policy|rbac|allow|access_control)\b"#).unwrap()
});
static RE_OPS_002_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(?:fail_closed|return\s+(?:false|False|Err|DENY|Status::Denied)|deny_by_default)\b"#).unwrap()
});

/// BK-AI-OPS-003 (CWE-778): Security-relevant events have no audit log or actor/resource identity
static RE_OPS_003_SENSITIVE_MUTATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:function|fn|def|async\s+def)\s+[a-zA-Z0-9_]*(?:grant_?admin|grant_?role|update_?role|set_?role|reset_?password|change_?password|delete_?user|delete_?account|disable_?mfa|disable_?2fa|update_?policy)[a-zA-Z0-9_]*\b"#).unwrap()
});
static RE_OPS_003_DISABLE_AUDIT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(?:skip_audit|disable_audit|skip_audit_logging|audit_enabled\s*[:=]\s*false)\b"#).unwrap()
});
static RE_OPS_003_AUDIT_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(?:audit|audit_log|auditLog|auditLogger|emit_audit|log_audit|recordAudit|auditTrail|AuditLogger::log)\b"#).unwrap()
});

/// BK-AI-OPS-004 (CWE-532): Raw secrets, authorization headers, PII or decrypted records logged
static RE_OPS_004_LOG_RAW_SECRET: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:console\.(?:log|info|debug|warn|error)|logger\.(?:info|debug|warn|error|log)|logging\.(?:info|debug|warning|error)|log\.(?:Printf|Println|Print|Debug|Info)|tracing::(?:info|debug|warn|error)!)\s*\([^)]*?\b(?:authorization|auth_header|bearer\s+|apiKey|api_key|secret_key|private_key|token|password|passwd|plaintext_secret|ssn|credit_card|cvv)\b"#).unwrap()
});
static RE_OPS_004_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:mask|redact|hash|obscure|strip|truncate|slice|substring|\.length\b|\.len\(\)|\[REDACTED\]|\*{3,}|prefix|suffix)"#).unwrap()
});

/// BK-AI-OPS-005 (CWE-209): Detailed internal stack traces, SQL or file paths sent to untrusted clients
static RE_OPS_005_LEAK_TRACE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:(?:res|response)\.(?:status\s*\(\s*\d+\s*\)\s*\.)?(?:send|json|write)\s*\([^)]*?(?:err|error)\.(?:stack|sql|trace)\b|return\s+jsonify\s*\([^)]*?(?:traceback\.format_exc|err\.sql)\b|(?:w\.Write|io\.WriteString)\s*\([^)]*?debug\.Stack\s*\(\s*\)|(?:res|response)\.(?:send|json)\s*\([^)]*?\{[^}]*?\b(?:stack|traceback|sql_query)\s*:\s*(?:err|error|traceback))"#).unwrap()
});
static RE_OPS_005_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:NODE_ENV\s*===?\s*['"]development['"]|DEBUG\s*===?\s*True|is_dev|isDev|app\.debug|sanitized_error)"#).unwrap()
});

/// BK-AI-OPS-006 (CWE-1059): Alert threshold/recipient disabled without equivalent incident signal
static RE_OPS_006_DISABLE_ALERT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(?:alerts?\.disabled\s*[:=]\s*true|alerts?\.silence(?:_all)?\s*\(|alerting\.disable\s*\(|silence_incident\s*\(|pagerduty\.mute\s*\(|disable_alerts\s*[:=]\s*true|mute_all_alerts\s*[:=]\s*true|silence_all_notifications\s*[:=]\s*true)\b"#).unwrap()
});
static RE_OPS_006_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:fallback|incident_id|ticket|expires?_at|duration|maintenance_window|backup_channel)"#).unwrap()
});

/// BK-AI-OPS-007 (CWE-117): Log forging through unsanitized multiline user fields
static RE_OPS_007_LOG_INJECTION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:logger|log|console)\.(?:info|warn|error|debug|log)\s*\([^)]*?(?:req\.(?:query|params|body|headers)|request\.(?:GET|POST|args|form)|user_input|userInput|untrusted_input)[^)]*?\)|log\.Printf\s*\([^)]*?%s[^)]*?(?:r\.URL\.Query|r\.FormValue|untrusted|userInput)\b"#).unwrap()
});
static RE_OPS_007_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:replace\s*\(\s*['"][\r\n\\]+['"]|replace\s*\(\s*/[\r\n\\]+/|strip_newlines|sanitize_log|encode_for_log|clean_log_input|url\.QueryEscape)"#).unwrap()
});

/// BK-AI-OPS-008 (CWE-778): Traces/audit lack correlation needed to reconstruct critical mutation
static RE_OPS_008_AUDIT_WITHOUT_CORRELATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:auditLog\.record\s*\(|emit_audit\s*\(|AuditEntry\s*\{)"#).unwrap()
});
static RE_OPS_008_DISABLE_CORRELATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(?:correlation_id_enabled\s*[:=]\s*false|omit_trace_id\s*[:=]\s*true|propagate_trace_context\s*[:=]\s*false)\b"#).unwrap()
});
static RE_OPS_008_CORRELATION_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(?:trace_id|correlation_id|correlationId|traceId|span_id|requestId|request_id|traceparent)\b"#).unwrap()
});

/// BK-AI-OPS-009 (CWE-284): Sensitive audit logs can be modified or deleted by same service account
static RE_OPS_009_MUTATE_AUDIT_LOG: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:DELETE\s+FROM\s+(?:audit_logs?|audit_trail|audit_events?|security_log)\b|TRUNCATE(?:\s+TABLE)?\s+(?:audit_logs?|audit_trail|audit_events?)\b|DROP\s+TABLE\s+(?:audit_logs?|audit_trail)\b|(?:s3|s3_client|bucket)\.(?:delete_object|deleteObject|delete_objects)\s*\([^)]*?(?:audit|compliance|audit-log|audit_trail)\b|(?:audit_table|audit_log|AuditLog|AuditTrail)\.(?:delete|destroy|truncate|drop)\s*\()"#).unwrap()
});
static RE_OPS_009_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:WORM|object_lock|objectLock|append_only|appendOnly|immutable|retention_period|compliance_mode)"#).unwrap()
});

/// BK-AI-OPS-010 (CWE-693): Recovery runbook promises rollback but no restorable backup is tested
static RE_OPS_010_UNTESTED_BACKUP: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(?:backup_restore_tested\s*[:=]\s*false|verify_restore_drill\s*[:=]\s*false|restore_verified\s*[:=]\s*false|test_restore_procedure\s*[:=]\s*false|skip_restore_verification\s*[:=]\s*true|rollback_tested\s*[:=]\s*false)\b"#).unwrap()
});
static RE_OPS_010_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(?:backup_restore_tested\s*[:=]\s*true|verify_restore_drill\s*[:=]\s*true|restore_verified\s*[:=]\s*true|periodic_restore_drill|validated_restore_point)\b"#).unwrap()
});

/// BK-AI-OPS-011 (CWE-754): Healthcheck reports success when dependencies/scanners skipped or failed
static RE_OPS_011_HEALTH_ENDPOINT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)/(?:healthz?|ready|health)['"]"#).unwrap()
});
static RE_OPS_011_STATUS_OK: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:res\.(?:status\s*\(\s*200\s*\)\.)?send\s*\(\s*['"]OK['"]|status\s*[:=]\s*["'](?:ok|UP)["']|HTTP_200_OK)"#).unwrap()
});
static RE_OPS_011_CONFIG: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(?:skip_dependency_health_check\s*[:=]\s*true|ignore_downstream_health\s*[:=]\s*true)\b"#).unwrap()
});
static RE_OPS_011_SWALLOW_DEP_ERROR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)catch\s*(?:\([^)]*\))?\s*\{[^{}]*?return\s+res\.status\s*\(\s*200\s*\)"#).unwrap()
});
static RE_OPS_011_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:check_db|check_database|ping_db|check_redis|503|SERVICE_UNAVAILABLE|ServiceUnavailable|is_healthy\s*&&\s*is_db_ready|checkDependencies|ping\(|dependencies_healthy)"#).unwrap()
});

/// BK-AI-OPS-012 (CWE-1059): Security fix suppresses test or warning rather than preserving invariant
static RE_OPS_012_SUPPRESS_TEST: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:@pytest\.mark\.skip\s*\([^)]*?(?:security|cve|vuln|auth|jwt|signature|injection|overflow|exploit)\b|test\.skip\s*\([^)]*?(?:security|cve|vuln|auth|jwt|signature|injection|overflow|exploit)\b|xit\s*\([^)]*?(?:security|cve|vuln|auth|jwt|signature|injection)\b|#\[ignore\s*=\s*["'][^"']*(?:security|cve|vuln|auth|jwt|signature|leak)["']\]|#\[allow\((?:warnings|unused_must_use)\)\]\s*(?:\n\s*)*(?:pub\s+)?fn\s+(?:verify_|check_|validate_)?(?:auth|jwt|token|signature|permission|security))"#).unwrap()
});
static RE_OPS_012_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(?:preserve_invariant|temporary_ci_quarantine_with_ticket|active_security_test)\b"#).unwrap()
});

// ---------------------------------------------------------------------------
// Category 27 Regexes
// ---------------------------------------------------------------------------

/// BK-AI-QAT-001 (CWE-1059): Security test only checks existence of validator rather than rejection
static RE_QAT_001_WEAK_TEST: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:expect\s*\(\s*(?:authValidator|validate[a-zA-Z0-9_]*|security_guard|csrfValidator|sanitizer)\s*\)\.(?:toBeDefined|toBeTruthy|not\.toBeNull)\s*\(\s*\)|assert\s+(?:auth_validator|security_checker|sanitizer)\s+is\s+not\s+None\b|assertIsInstance\s*\(\s*(?:auth_validator|guard|sanitizer)\s*,\s*[A-Za-z0-9_]+\s*\))"#).unwrap()
});
static RE_QAT_001_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:toThrow|rejects|status\s*\)\s*\.toBe\s*\(\s*(?:401|403|400|422)|assertFalse|assertRaises|rejected|assert\s+not\s+validator\.validate\b|is_rejected|is_forbidden|InvalidSignature|Unauthorized)"#).unwrap()
});

/// BK-AI-QAT-002 (CWE-1059): Fixture for each dangerous rule lacks safe lookalike
static RE_QAT_002_NO_SAFE_FIXTURE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(?:safe_lookalike_fixture\s*[:=]\s*false|has_negative_fixture\s*[:=]\s*false|test_fixtures_only_vulnerable\s*[:=]\s*true|omit_safe_fixtures\s*[:=]\s*true|safe_counterparts_required\s*[:=]\s*false)\b"#).unwrap()
});
static RE_QAT_002_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(?:safe_lookalike_fixture\s*[:=]\s*true|has_negative_fixture\s*[:=]\s*true|safe_fixtures\s*:\s*\[|negative_test_fixture|safe_counterpart)\b"#).unwrap()
});

/// BK-AI-QAT-003 (CWE-1059): Scanner detection relies on file extension while supported syntax is embedded/mixed
static RE_QAT_003_EXT_ONLY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(?:rely_only_on_extension\s*[:=]\s*true|filter_by_extension_only\s*[:=]\s*true|skip_embedded_scripts\s*[:=]\s*true)\b|(?:if\s*\(!file\.endsWith\s*\(['"]\.[a-z]+['"]\)\s*\)\s*return;|if\s+not\s+path\.endswith\s*\(['"]\.[a-z]+['"]\):\s*return\b)"#).unwrap()
});
static RE_QAT_003_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:embedded|shebang|detect_content_type|detect_language|extract_embedded_scripts|polyglot|content_sniffing)"#).unwrap()
});

/// BK-AI-QAT-004 (CWE-1059): Rule source/sink coverage not versioned per language/framework
static RE_QAT_004_UNVERSIONED_RULE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:["']?version_pinned["']?\s*[:=]\s*false|unversioned_sinks\s*[:=]\s*true|framework_version_agnostic\s*[:=]\s*true|target_framework_version\s*[:=]\s*["']\*["']|source_sink_version\s*[:=]\s*["']any["'])"#).unwrap()
});
static RE_QAT_004_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:["']?version_pinned["']?\s*[:=]\s*true|version_range|target_version\s*[:=]\s*["'][><=~^0-9]|pinned_framework_versions?)"#).unwrap()
});

/// BK-AI-QAT-005 (CWE-1059): A clean test run covers only one role, principal or tenant
static RE_QAT_005_SINGLE_TENANT_TEST: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(?:single_role_test_only\s*[:=]\s*true|matrix_tenant_isolation\s*[:=]\s*false|cross_role_testing\s*[:=]\s*false|test_tenants\s*[:=]\s*\[\s*["'][^"']+["']\s*\]|roles_tested\s*[:=]\s*\[\s*["']admin["']\s*\])\b"#).unwrap()
});
static RE_QAT_005_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(?:matrix_tenant_isolation\s*[:=]\s*true|cross_role_testing\s*[:=]\s*true|roles\s*:\s*\[[^\]]+,[^\]]+\]|tenants\s*:\s*\[[^\]]+,[^\]]+\]|multi_role_matrix)\b"#).unwrap()
});

/// BK-AI-QAT-006 (CWE-1059): Static scanner ignores indirect imports, aliases, callback/async entrypoints
static RE_QAT_006_SILENT_IGNORE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(?:ignore_dynamic_imports\s*[:=]\s*true|resolve_aliases\s*[:=]\s*false|track_indirect_imports\s*[:=]\s*false|skip_async_callbacks\s*[:=]\s*true|unresolved_import_handling\s*[:=]\s*["']ignore_silent["'])\b"#).unwrap()
});
static RE_QAT_006_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(?:track_indirect_imports\s*[:=]\s*true|resolve_aliases\s*[:=]\s*true|disclose_untracked_dynamic_imports\s*[:=]\s*true|warn_on_unresolved_imports\s*[:=]\s*true)\b"#).unwrap()
});

/// BK-AI-QAT-007 (CWE-1059): Security finding severity inferred from CWE alone rather than actual reachability
static RE_QAT_007_CWE_SEVERITY_ONLY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(?:infer_severity_from_cwe_only\s*[:=]\s*true|severity_from_cwe_only\s*[:=]\s*true|lookup_cwe_severity_only\s*[:=]\s*true)\b|(?:finding\.severity\s*=\s*(?:cwe_severity_map|CWE_SEVERITY_TABLE)\[[^\]]+\];?)|(?:def\s+assign_severity\s*\(\s*cwe\s*\)\s*:\s*return\s+CWE_SEVERITY\[cwe\])"#).unwrap()
});
static RE_QAT_007_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(?:reachability|call_graph|exploitability|exposure|effective_severity|contextual_severity|reachability_factor)\b"#).unwrap()
});

/// BK-AI-QAT-008 (CWE-1059): "Mitigated" classification accepted without a test of the real guard
static RE_QAT_008_STATUS_MITIGATED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\bstatus\s*=\s*['"]Mitigated['"]"#).unwrap()
});
static RE_QAT_008_UNTESTED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(?:verified\s*[:=]\s*false|verification_test\s*=\s*None|accept_mitigation_without_test\s*[:=]\s*true|trust_mitigation_comment\s*[:=]\s*true|mitigation_test_required\s*[:=]\s*false)\b"#).unwrap()
});
static RE_QAT_008_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(?:verification_test|assert_mitigation_test|test_verified\s*[:=]\s*true|verified_by_test|run_verification_test)\b"#).unwrap()
});

/// BK-AI-QAT-009 (CWE-1059): Security test silently calls live external system or mutates production during CI
static RE_QAT_009_LIVE_EXTERNAL_TEST: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:fetch|requests\.(?:get|post|put|delete)|http\.(?:Get|Post)|axios\.(?:get|post))\s*\(\s*['"]https?://(?:api\.stripe\.com|api\.prod\.[a-z0-9_-]+\.[a-z]+|api\.production\.[a-z0-9_-]+\.[a-z]+|prod-db\.[a-z0-9_-]+\.internal)|(?:DATABASE_URL|PROD_DB_URL)\s*[:=]\s*['"]postgres://[^'"]*prod(?:uction)?-db"#).unwrap()
});
static RE_QAT_009_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(?:nock\b|mock|stub|responses\.add|httpretty|wiremock|localhost|127\.0\.0\.1|test_server|fake_api)\b"#).unwrap()
});

/// BK-AI-QAT-010 (CWE-1059): Report hides unknown coverage or suppressions when producing summary/dashboard
static RE_QAT_010_HIDE_SUPPRESSIONS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:["']?hide_suppressed["']?\s*[:=]\s*true|["']?report_suppressed["']?\s*[:=]\s*false|exclude_skipped_from_report\s*[:=]\s*true|hide_coverage_gaps\s*[:=]\s*true|omit_unsupported_coverage\s*[:=]\s*true|suppressions_hidden\s*[:=]\s*true|display_summary\s*\([^)]*?findings\.filter\s*\([^)]*?!f\.suppressed)"#).unwrap()
});
static RE_QAT_010_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:["']?include_suppressed["']?\s*[:=]\s*true|["']?report_suppressed["']?\s*[:=]\s*true|show_coverage_gaps\s*[:=]\s*true|include_suppressed_in_report\s*[:=]\s*true|suppression_audit_trail)"#).unwrap()
});

/// BK-AI-QAT-011 (CWE-1059): Automatic repair writes without showing diff, impact, backup state or verification
static RE_QAT_011_BLIND_REPAIR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:auto_repair_apply\s*\([^)]*create_backup\s*[:=]\s*false|apply_fix_without_backup\s*[:=]\s*true|skip_patch_diff\s*[:=]\s*true|auto_patch_no_backup\s*[:=]\s*true|silent_repair_write\s*[:=]\s*true|fs\.writeFileSync\s*\([^)]*patchedContent\s*\))"#).unwrap()
});
static RE_QAT_011_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:create_backup\s*\(|backup_path|show_diff|display_diff|verify_repair|verify_patch|run_regression_tests)"#).unwrap()
});

/// BK-AI-QAT-012 (CWE-1059): One LLM reviews its own output and marks security as proven without independent evidence
static RE_QAT_012_SELF_SIGNED_AI: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(?:ai_review_self_sign\s*[:=]\s*true|self_verification_only\s*[:=]\s*true|llm_self_approve\s*[:=]\s*true|single_model_self_certification\s*[:=]\s*true)\b|(?:(?:ai_review|llm_review)\.verified\s*=\s*(?:true|True)\b)|(?:if\s+model\.review\s*\(\s*model\.(?:generated_code|output)\s*\)\.approved)"#).unwrap()
});
static RE_QAT_012_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(?:independent_verification|multi_model_consensus|sandbox_verification|compiler_check|dual_model|human_in_the_loop)\b"#).unwrap()
});

// ===========================================================================
// OpsQaScanner Implementation
// ===========================================================================

pub struct OpsQaScanner;

impl OpsQaScanner {
    /// Scan source content for Category 19 (BK-AI-OPS) and Category 27 (BK-AI-QAT) rules.
    pub fn scan_source(path: &Path, content: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut seen: HashSet<(&'static str, usize)> = HashSet::new();

        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();

        let target_kind = match ext.as_str() {
            "js" | "mjs" | "cjs" | "ts" | "tsx" | "jsx" => TargetKind::NodeSourceFile,
            "json" | "yaml" | "yml" | "toml" => TargetKind::GenericConfigFile,
            "env" => TargetKind::EnvironmentFile,
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

            // ===============================================================
            // Category 19: Errors, Observability & Incident Readiness
            // ===============================================================

            // 1. BK-AI-OPS-001 (CWE-390): Security exception swallowed
            let is_ops_001 = ((RE_OPS_001_SWALLOW_CATCH.is_match(trimmed) || RE_OPS_001_SWALLOW_CATCH.is_match(&context_window))
                && RE_OPS_001_SECURITY_CONTEXT.is_match(&context_window)
                && !RE_OPS_001_GUARD.is_match(&context_window))
                || (RE_OPS_001_UNWRAP_DEFAULT.is_match(trimmed) && !RE_OPS_001_GUARD.is_match(&context_window))
                || (RE_OPS_001_PYTHON_PASS.is_match(trimmed) && !RE_OPS_001_GUARD.is_match(&context_window));

            if is_ops_001 && seen.insert(("BK-AI-OPS-001", line_no)) {
                findings.push(Self::create_finding(
                    "BK-AI-OPS-001",
                    "CWE-390",
                    "Security exception swallowed with empty catch or `unwrap_or_default()`",
                    Severity::High,
                    CATEGORY_OPS,
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Exceptions in security paths must fail closed and be recorded with diagnostic context.",
                    "Security-critical exception caught and swallowed with empty handler or default fallback.",
                    "Handle security exceptions explicitly by failing closed (e.g. denying access) and logging appropriate audit context.",
                ));
            }

            // 2. BK-AI-OPS-002 (CWE-755): Auth check returns allow after timeout/error
            let is_ops_002 = ((RE_OPS_002_RETURN_TRUE.is_match(trimmed) || RE_OPS_002_CONFIG_ALLOW.is_match(trimmed))
                && RE_OPS_002_AUTH_CONTEXT.is_match(&context_window)
                && RE_OPS_002_CATCH_ALLOW.is_match(&context_window)
                && !RE_OPS_002_GUARD.is_match(&context_window))
                || (RE_OPS_002_CONFIG_ALLOW.is_match(trimmed) && !RE_OPS_002_GUARD.is_match(&context_window));

            if is_ops_002 && seen.insert(("BK-AI-OPS-002", line_no)) {
                findings.push(Self::create_finding(
                    "BK-AI-OPS-002",
                    "CWE-755",
                    "Authentication/authorization check returns allow after timeout/error",
                    Severity::Critical,
                    CATEGORY_OPS,
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Authentication and authorization subsystems must fail closed on timeouts or runtime errors.",
                    "Access control check defaults to allowing access when encountering timeout, network partition, or unhandled exception.",
                    "Enforce fail-closed semantics: return false or explicit error status when authorization checks fail or time out.",
                ));
            }

            // 3. BK-AI-OPS-003 (CWE-778): Security-relevant events have no audit log
            let is_ops_003 = (RE_OPS_003_SENSITIVE_MUTATION.is_match(trimmed) && !RE_OPS_003_AUDIT_GUARD.is_match(&context_window))
                || RE_OPS_003_DISABLE_AUDIT.is_match(trimmed);

            if is_ops_003 && seen.insert(("BK-AI-OPS-003", line_no)) {
                findings.push(Self::create_finding(
                    "BK-AI-OPS-003",
                    "CWE-778",
                    "Security-relevant events have no audit log or actor/resource identity",
                    Severity::High,
                    CATEGORY_OPS,
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "All administrative mutations and privilege modifications must emit immutable audit records.",
                    "Security-relevant state mutation performed without logging actor identity, target resource, and mutation timestamp.",
                    "Emit structured audit log events with actor ID, resource ID, action name, and correlation context for all privilege changes.",
                ));
            }

            // 4. BK-AI-OPS-004 (CWE-532): Raw secrets, authorization headers, PII logged
            let is_ops_004 = RE_OPS_004_LOG_RAW_SECRET.is_match(trimmed) && !RE_OPS_004_GUARD.is_match(trimmed);

            if is_ops_004 && seen.insert(("BK-AI-OPS-004", line_no)) {
                findings.push(Self::create_finding(
                    "BK-AI-OPS-004",
                    "CWE-532",
                    "Raw secrets, authorization headers, PII or decrypted records logged",
                    Severity::High,
                    CATEGORY_OPS,
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Secrets, auth tokens, passwords, and sensitive PII must never be written to stdout or logs.",
                    "Diagnostic logging statement writes raw secrets, authorization tokens, or sensitive credentials in plaintext.",
                    "Sanitize, mask, or redact tokens and passwords before logging, or omit credentials entirely from log payloads.",
                ));
            }

            // 5. BK-AI-OPS-005 (CWE-209): Detailed internal stack traces sent to untrusted clients
            let is_ops_005 = RE_OPS_005_LEAK_TRACE.is_match(trimmed) && !RE_OPS_005_GUARD.is_match(&context_window);

            if is_ops_005 && seen.insert(("BK-AI-OPS-005", line_no)) {
                findings.push(Self::create_finding(
                    "BK-AI-OPS-005",
                    "CWE-209",
                    "Detailed internal stack traces, SQL or file paths sent to untrusted clients",
                    Severity::High,
                    CATEGORY_OPS,
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Internal debugging diagnostics, stack traces, and database queries must not be exposed to client responses.",
                    "Unhandled error or exception handler serializes raw internal stack traces or database queries to external callers.",
                    "Return generic sanitized error messages to callers and retain raw stack traces exclusively in private server-side logs.",
                ));
            }

            // 6. BK-AI-OPS-006 (CWE-1059): Alert threshold/recipient disabled
            let is_ops_006 = RE_OPS_006_DISABLE_ALERT.is_match(trimmed) && !RE_OPS_006_GUARD.is_match(&context_window);

            if is_ops_006 && seen.insert(("BK-AI-OPS-006", line_no)) {
                findings.push(Self::create_finding(
                    "BK-AI-OPS-006",
                    "CWE-1059",
                    "Alert threshold/recipient disabled without equivalent incident signal",
                    Severity::Medium,
                    CATEGORY_OPS,
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Alert silences or disablement must reference valid incident tickets and fallback notification channels.",
                    "Production alert notifications or incident channels disabled without escalation fallback or active maintenance ticket.",
                    "Require incident ticket binding, expiration timestamps, and fallback notification channels when silencing operational alerts.",
                ));
            }

            // 7. BK-AI-OPS-007 (CWE-117): Log forging through unsanitized multiline user fields
            let is_ops_007 = RE_OPS_007_LOG_INJECTION.is_match(trimmed) && !RE_OPS_007_GUARD.is_match(&context_window);

            if is_ops_007 && seen.insert(("BK-AI-OPS-007", line_no)) {
                findings.push(Self::create_finding(
                    "BK-AI-OPS-007",
                    "CWE-117",
                    "Log forging through unsanitized multiline user fields",
                    Severity::Medium,
                    CATEGORY_OPS,
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "User-controlled strings written to logs must be sanitized against newline injection and carriage returns.",
                    "Untrusted user inputs logged directly without CRLF sanitization, allowing log injection and fake log entry fabrication.",
                    "Strip or escape newline (\\r, \\n) characters from user input prior to logging or use structured JSON logging.",
                ));
            }

            // 8. BK-AI-OPS-008 (CWE-778): Traces/audit lack correlation
            let is_ops_008 = (RE_OPS_008_AUDIT_WITHOUT_CORRELATION.is_match(trimmed) && !RE_OPS_008_CORRELATION_GUARD.is_match(&context_window))
                || RE_OPS_008_DISABLE_CORRELATION.is_match(trimmed);

            if is_ops_008 && seen.insert(("BK-AI-OPS-008", line_no)) {
                findings.push(Self::create_finding(
                    "BK-AI-OPS-008",
                    "CWE-778",
                    "Traces/audit lack correlation needed to reconstruct critical mutation",
                    Severity::Medium,
                    CATEGORY_OPS,
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Audit events and mutation logs must contain correlation and distributed trace identifiers.",
                    "Audit trail record emitted without correlation ID or trace context, impairing cross-service incident reconstruction.",
                    "Attach distributed trace IDs, correlation IDs, or request spans to all emitted audit records.",
                ));
            }

            // 9. BK-AI-OPS-009 (CWE-284): Sensitive audit logs can be modified or deleted
            let is_ops_009 = RE_OPS_009_MUTATE_AUDIT_LOG.is_match(trimmed) && !RE_OPS_009_GUARD.is_match(&context_window);

            if is_ops_009 && seen.insert(("BK-AI-OPS-009", line_no)) {
                findings.push(Self::create_finding(
                    "BK-AI-OPS-009",
                    "CWE-284",
                    "Sensitive audit logs can be modified or deleted by same service account",
                    Severity::High,
                    CATEGORY_OPS,
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Audit storage must be write-once-read-many (WORM) and prohibit in-band deletion by service workers.",
                    "Application service code executes SQL DELETE/TRUNCATE or cloud storage object deletion directly on audit logs.",
                    "Enforce append-only storage and WORM object lock policies, revoking audit deletion privileges from standard application credentials.",
                ));
            }

            // 10. BK-AI-OPS-010 (CWE-693): Recovery runbook promises rollback but no backup tested
            let is_ops_010 = RE_OPS_010_UNTESTED_BACKUP.is_match(trimmed) && !RE_OPS_010_GUARD.is_match(&context_window);

            if is_ops_010 && seen.insert(("BK-AI-OPS-010", line_no)) {
                findings.push(Self::create_finding(
                    "BK-AI-OPS-010",
                    "CWE-693",
                    "Recovery runbook promises rollback but no restorable backup is tested",
                    Severity::Medium,
                    CATEGORY_OPS,
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Rollback and disaster recovery runbooks must be backed by routinely verified automated restore drills.",
                    "Deployment or rollback automation assumes backup viability while backup restoration remains untested.",
                    "Execute automated restore drills and mandate positive test verification before declaring rollback readiness.",
                ));
            }

            // 11. BK-AI-OPS-011 (CWE-754): Healthcheck reports success when dependencies fail
            let is_ops_011 = ((RE_OPS_011_HEALTH_ENDPOINT.is_match(trimmed) || RE_OPS_011_STATUS_OK.is_match(trimmed))
                && RE_OPS_011_HEALTH_ENDPOINT.is_match(&context_window)
                && RE_OPS_011_STATUS_OK.is_match(&context_window)
                && !RE_OPS_011_GUARD.is_match(&context_window))
                || RE_OPS_011_CONFIG.is_match(trimmed)
                || (RE_OPS_011_SWALLOW_DEP_ERROR.is_match(trimmed) && RE_OPS_011_HEALTH_ENDPOINT.is_match(&context_window) && !RE_OPS_011_GUARD.is_match(&context_window));

            if is_ops_011 && seen.insert(("BK-AI-OPS-011", line_no)) {
                findings.push(Self::create_finding(
                    "BK-AI-OPS-011",
                    "CWE-754",
                    "Healthcheck reports success when dependencies/scanners skipped or failed",
                    Severity::Medium,
                    CATEGORY_OPS,
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Health and readiness probes must actively check critical downstream dependencies before reporting success.",
                    "Healthcheck endpoint returns HTTP 200 OK without verifying database or messaging subsystem availability, masking outages.",
                    "Implement deep readiness checks that validate downstream dependency connectivity and return 503 on degraded states.",
                ));
            }

            // 12. BK-AI-OPS-012 (CWE-1059): Security fix suppresses test or warning
            let is_ops_012 = RE_OPS_012_SUPPRESS_TEST.is_match(trimmed) && !RE_OPS_012_GUARD.is_match(&context_window);

            if is_ops_012 && seen.insert(("BK-AI-OPS-012", line_no)) {
                findings.push(Self::create_finding(
                    "BK-AI-OPS-012",
                    "CWE-1059",
                    "Security fix suppresses test or warning rather than preserving invariant",
                    Severity::Medium,
                    CATEGORY_OPS,
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Security regressions must never be suppressed via test skipping or compiler warning silencing.",
                    "Security test skipped or compiler safety check suppressed instead of fixing underlying invariant violation.",
                    "Resolve root cause rather than marking security tests with @skip, #[ignore], or #![allow(warnings)].",
                ));
            }

            // ===============================================================
            // Category 27: Security-Test Integrity, Human Review & Quality
            // ===============================================================

            // 13. BK-AI-QAT-001 (CWE-1059): Security test only checks existence of validator
            let is_qat_001 = RE_QAT_001_WEAK_TEST.is_match(trimmed) && !RE_QAT_001_GUARD.is_match(&context_window);

            if is_qat_001 && seen.insert(("BK-AI-QAT-001", line_no)) {
                findings.push(Self::create_finding(
                    "BK-AI-QAT-001",
                    "CWE-1059",
                    "Security test only checks existence of validator rather than rejection of malicious/unauthorized input",
                    Severity::High,
                    CATEGORY_QAT,
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Security test suites must execute negative assertions verifying rejection of malicious/unauthorized payloads.",
                    "Security unit test merely asserts validator function existence without validating negative rejection behavior.",
                    "Add negative test cases verifying that invalid, malicious, and unauthorized inputs are properly rejected.",
                ));
            }

            // 14. BK-AI-QAT-002 (CWE-1059): Fixture lacks safe lookalike
            let is_qat_002 = RE_QAT_002_NO_SAFE_FIXTURE.is_match(trimmed) && !RE_QAT_002_GUARD.is_match(&context_window);

            if is_qat_002 && seen.insert(("BK-AI-QAT-002", line_no)) {
                findings.push(Self::create_finding(
                    "BK-AI-QAT-002",
                    "CWE-1059",
                    "Fixture for each dangerous rule lacks safe lookalike, causing false positives",
                    Severity::Medium,
                    CATEGORY_QAT,
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Every security detection rule fixture must pair vulnerable patterns with safe lookalike counterparts.",
                    "Security scanner test fixtures omit safe lookalike samples, preventing false-positive regression detection.",
                    "Include paired safe fixtures alongside vulnerable samples for every detection rule to ensure precision.",
                ));
            }

            // 15. BK-AI-QAT-003 (CWE-1059): Scanner detection relies on file extension only
            let is_qat_003 = RE_QAT_003_EXT_ONLY.is_match(trimmed) && !RE_QAT_003_GUARD.is_match(&context_window);

            if is_qat_003 && seen.insert(("BK-AI-QAT-003", line_no)) {
                findings.push(Self::create_finding(
                    "BK-AI-QAT-003",
                    "CWE-1059",
                    "Scanner detection relies on file extension while supported syntax is embedded/mixed",
                    Severity::Medium,
                    CATEGORY_QAT,
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Static analysis engine must inspect embedded scripts, polyglot blocks, and content headers beyond file extensions.",
                    "Security analysis restricts scanning strictly by file extension, bypassing embedded script blocks in mixed formats.",
                    "Use content inspection and language parsers to analyze embedded scripts inside HTML, templates, and markdown.",
                ));
            }

            // 16. BK-AI-QAT-004 (CWE-1059): Rule source/sink coverage not versioned
            let is_qat_004 = RE_QAT_004_UNVERSIONED_RULE.is_match(trimmed) && !RE_QAT_004_GUARD.is_match(&context_window);

            if is_qat_004 && seen.insert(("BK-AI-QAT-004", line_no)) {
                findings.push(Self::create_finding(
                    "BK-AI-QAT-004",
                    "CWE-1059",
                    "Rule source/sink coverage not versioned per language/framework",
                    Severity::Low,
                    CATEGORY_QAT,
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Static analysis rule definitions must explicitly target and pin compatible language/framework version ranges.",
                    "Taint analysis sources and sinks defined without framework version pinning, causing inaccuracies across major versions.",
                    "Bind source/sink rule definitions to specific framework semantic versions and major release boundaries.",
                ));
            }

            // 17. BK-AI-QAT-005 (CWE-1059): Clean test run covers only one role/tenant
            let is_qat_005 = RE_QAT_005_SINGLE_TENANT_TEST.is_match(trimmed) && !RE_QAT_005_GUARD.is_match(&context_window);

            if is_qat_005 && seen.insert(("BK-AI-QAT-005", line_no)) {
                findings.push(Self::create_finding(
                    "BK-AI-QAT-005",
                    "CWE-1059",
                    "A clean test run covers only one role, principal or tenant",
                    Severity::Medium,
                    CATEGORY_QAT,
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Multi-tenant and role-based access control tests must verify cross-tenant isolation and privilege boundaries.",
                    "Security access test suite executes under a single tenant or admin role, leaving cross-tenant isolation unverified.",
                    "Execute test matrices spanning multiple distinct tenant IDs and both privileged and unprivileged user roles.",
                ));
            }

            // 18. BK-AI-QAT-006 (CWE-1059): Static scanner ignores indirect imports/aliases silently
            let is_qat_006 = RE_QAT_006_SILENT_IGNORE.is_match(trimmed) && !RE_QAT_006_GUARD.is_match(&context_window);

            if is_qat_006 && seen.insert(("BK-AI-QAT-006", line_no)) {
                findings.push(Self::create_finding(
                    "BK-AI-QAT-006",
                    "CWE-1059",
                    "Static scanner ignores indirect imports, aliases, callback/async entrypoints without disclosure",
                    Severity::Medium,
                    CATEGORY_QAT,
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Static scanner must disclose and resolve indirect imports, module aliases, and asynchronous callback targets.",
                    "Static analyzer silently ignores indirect imports, dynamic requires, or async entrypoints without disclosure in reports.",
                    "Track indirect imports and module aliases, or prominently disclose unresolved dynamic import boundaries in scan reports.",
                ));
            }

            // 19. BK-AI-QAT-007 (CWE-1059): Severity inferred from CWE alone
            let is_qat_007 = RE_QAT_007_CWE_SEVERITY_ONLY.is_match(trimmed) && !RE_QAT_007_GUARD.is_match(&context_window);

            if is_qat_007 && seen.insert(("BK-AI-QAT-007", line_no)) {
                findings.push(Self::create_finding(
                    "BK-AI-QAT-007",
                    "CWE-1059",
                    "Security finding severity inferred from `CWE` alone rather than actual reachability and impact",
                    Severity::Medium,
                    CATEGORY_QAT,
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Finding severity must synthesize reachability, call graph traversal, and runtime exposure alongside base CWE.",
                    "Severity rating assigned purely from static CWE lookup tables without considering actual reachability or system impact.",
                    "Synthesize finding severity by combining base weakness severity with call-graph reachability and environmental exposure.",
                ));
            }

            // 20. BK-AI-QAT-008 (CWE-1059): "Mitigated" accepted without test of real guard
            let is_qat_008 = ((RE_QAT_008_STATUS_MITIGATED.is_match(trimmed) || RE_QAT_008_UNTESTED.is_match(trimmed))
                && RE_QAT_008_STATUS_MITIGATED.is_match(&context_window)
                && RE_QAT_008_UNTESTED.is_match(&context_window)
                && !RE_QAT_008_GUARD.is_match(&context_window))
                || (RE_QAT_008_UNTESTED.is_match(trimmed) && !RE_QAT_008_GUARD.is_match(&context_window));

            if is_qat_008 && seen.insert(("BK-AI-QAT-008", line_no)) {
                findings.push(Self::create_finding(
                    "BK-AI-QAT-008",
                    "CWE-1059",
                    "\"Mitigated\" classification accepted without a test of the real guard",
                    Severity::High,
                    CATEGORY_QAT,
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Security findings may only be marked as mitigated when verified by passing automated regression tests.",
                    "Security triage status marked as Mitigated based solely on developer assertion without executable test proof.",
                    "Require automated verification test references before accepting mitigated classification for security findings.",
                ));
            }

            // 21. BK-AI-QAT-009 (CWE-1059): Test silently calls live external system or mutates prod
            let is_qat_009 = RE_QAT_009_LIVE_EXTERNAL_TEST.is_match(trimmed) && !RE_QAT_009_GUARD.is_match(&context_window);

            if is_qat_009 && seen.insert(("BK-AI-QAT-009", line_no)) {
                findings.push(Self::create_finding(
                    "BK-AI-QAT-009",
                    "CWE-1059",
                    "Security test silently calls live external system or mutates production during CI",
                    Severity::High,
                    CATEGORY_QAT,
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Automated test suites must isolate external integrations via mocks or local sandboxes to prevent production mutation.",
                    "Security test suite connects directly to live production endpoints or external third-party payment/auth APIs during CI runs.",
                    "Mock external third-party API dependencies using test stubs, wiremock, or local sandbox emulators.",
                ));
            }

            // 22. BK-AI-QAT-010 (CWE-1059): Report hides unknown coverage or suppressions
            let is_qat_010 = RE_QAT_010_HIDE_SUPPRESSIONS.is_match(trimmed) && !RE_QAT_010_GUARD.is_match(&context_window);

            if is_qat_010 && seen.insert(("BK-AI-QAT-010", line_no)) {
                findings.push(Self::create_finding(
                    "BK-AI-QAT-010",
                    "CWE-1059",
                    "Report hides unknown coverage or suppressions when producing summary/dashboard",
                    Severity::Medium,
                    CATEGORY_QAT,
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Executive dashboards and compliance reports must transparently display suppression counts and coverage gaps.",
                    "Security summary report conceals suppressed alerts or unscanned file boundaries, producing a false sense of security.",
                    "Explicitly display suppressed finding metrics, skipped files, and unsupported language coverage gaps in summary reports.",
                ));
            }

            // 23. BK-AI-QAT-011 (CWE-1059): Automatic repair writes without diff, backup or verification
            let is_qat_011 = RE_QAT_011_BLIND_REPAIR.is_match(trimmed) && !RE_QAT_011_GUARD.is_match(&context_window);

            if is_qat_011 && seen.insert(("BK-AI-QAT-011", line_no)) {
                findings.push(Self::create_finding(
                    "BK-AI-QAT-011",
                    "CWE-1059",
                    "Automatic repair writes without showing diff, impact, backup state or verification outcome",
                    Severity::High,
                    CATEGORY_QAT,
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Automated remediation must present verified unified diffs, create restorable backups, and execute verification suites.",
                    "Automated virtual patching modifies source files on disk without presenting diffs, creating backups, or verifying outcomes.",
                    "Generate cryptographic backup snapshots, present user-facing diffs, and run test verification before committing auto-fixes.",
                ));
            }

            // 24. BK-AI-QAT-012 (CWE-1059): One LLM reviews own output and marks security proven
            let is_qat_012 = RE_QAT_012_SELF_SIGNED_AI.is_match(trimmed) && !RE_QAT_012_GUARD.is_match(&context_window);

            if is_qat_012 && seen.insert(("BK-AI-QAT-012", line_no)) {
                findings.push(Self::create_finding(
                    "BK-AI-QAT-012",
                    "CWE-1059",
                    "One LLM reviews its own output and marks security as proven without independent evidence",
                    Severity::High,
                    CATEGORY_QAT,
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "AI-generated code security must be validated via multi-model consensus, sandbox execution, or independent tooling.",
                    "Generative AI model self-approves and certifies its own generated code as secure without independent verification.",
                    "Enforce multi-agent cross-examination, deterministic compiler/linter sandbox validation, or human-in-the-loop review.",
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
        finding.detector_id = "ops-qa".to_string();
        finding.detector_version = "1.0.0".to_string();
        finding.category = category.to_string();
        finding.affectedness = Affectedness::ConfirmedAffected;
        finding.reachability = Reachability::PotentiallyReachable;
        finding.confidence = Confidence::High;
        finding.evidence_certainty = EvidenceCertainty::StronglySupported;
        if cwe != "None" && !cwe.is_empty() {
            finding.advisory_ids.push(cwe.to_string());
        }
        finding.advisory_ids.push(rule_id.to_string());
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
