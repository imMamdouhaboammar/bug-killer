use bug_killer::disclosure::{
    AffectedTarget, ContactChannel, DisclosureAction, DisclosureApprovalManager,
    DisclosureApprovalReceipt, DisclosureAuditEvent, DisclosureAuditLogger, DisclosureDraftBuilder,
    DisclosureSeverity, Redactor, ReporterInfo, RootCause, SafeReproduction, SecurityImpact,
    SensitivityCategory, SuggestedMitigation,
};
use bug_killer::identity::{AgentIdentity, OperatorIdentity};
use chrono::{Duration, Utc};
use sha2::{Digest, Sha256};
use tempfile::tempdir;

#[test]
fn test_credential_redaction_all_categories() {
    let redactor = Redactor::new();

    let gh_pat = format!("ghp_{}", "111122223333444455556666777788889999");
    let gl_pat = format!("glpat-{}", "abcdef1234567890ABCD");
    let aws_key = format!("AKIA{}", "IOSFODNN7EXAMPLE");
    let pem_begin = format!("-----BEGIN {} PRIVATE KEY-----", "RSA");
    let pem_end = format!("-----END {} PRIVATE KEY-----", "RSA");

    // Purely synthetic mock strings for all categories
    let sample = format!(
        r#"
        # Token
        auth: Bearer mock_dummy_token_xyz12345
        gh_pat: {gh_pat}
        gl_pat: {gl_pat}
        synth_token: mock_token_special_secret_999

        # Key
        aws_key: {aws_key}
        aws_sec: aws_secret_access_key="mock_aws_secret_key_long_string_val"
        synth_key: mock_aws_secret_abc123

        # Password
        db_pass: password = "mock_super_secret_password"
        admin_pass: passwd: 'mock_another_secret_pw'

        # PrivateIp
        ip1: 10.244.0.15
        ip2: 172.16.42.1
        ip3: 192.168.1.254
        ip6_local: fe80::1ff:fe23:4567:890a
        ip6_unique: fc00::abcd:1234

        # DatabaseUri
        db1: postgres://mock_admin:mock_secret_db_pass@10.0.0.5:5432/proddb
        db2: mysql://mock_user:mock_pw@192.168.1.1:3306/appdb

        # PrivateKey
        pem: {pem_begin}
        MOCK_PRIVATE_KEY_DATA_LINE_1
        MOCK_PRIVATE_KEY_DATA_LINE_2
        {pem_end}

        # Pii
        ssn: 000-12-3456
        synth_pii: mock_pii_user_identity_999
    "#
    );

    let (redacted, manifest) = redactor.redact_text(&sample);

    // Verify all synthetic secrets were redacted
    assert!(!redacted.contains("mock_dummy_token_xyz12345"));
    assert!(!redacted.contains(&gh_pat));
    assert!(!redacted.contains(&gl_pat));
    assert!(!redacted.contains("mock_token_special_secret_999"));
    assert!(!redacted.contains(&aws_key));
    assert!(!redacted.contains("mock_aws_secret_key_long_string_val"));
    assert!(!redacted.contains("mock_aws_secret_abc123"));
    assert!(!redacted.contains("mock_super_secret_password"));
    assert!(!redacted.contains("mock_another_secret_pw"));
    assert!(!redacted.contains("10.244.0.15"));
    assert!(!redacted.contains("172.16.42.1"));
    assert!(!redacted.contains("192.168.1.254"));
    assert!(!redacted.contains("fe80::1ff:fe23:4567:890a"));
    assert!(!redacted.contains("fc00::abcd:1234"));
    assert!(!redacted.contains("mock_secret_db_pass"));
    assert!(!redacted.contains("MOCK_PRIVATE_KEY_DATA_LINE_1"));
    assert!(!redacted.contains("000-12-3456"));
    assert!(!redacted.contains("mock_pii_user_identity_999"));

    // Verify presence of deterministic markers
    assert!(redacted.contains("[REDACTED:TOKEN:"));
    assert!(redacted.contains("[REDACTED:KEY:"));
    assert!(redacted.contains("[REDACTED:PASSWORD:"));
    assert!(redacted.contains("[REDACTED:PRIVATE_IP:"));
    assert!(redacted.contains("[REDACTED:DATABASE_URI:"));
    assert!(redacted.contains("[REDACTED:PRIVATE_KEY:"));
    assert!(redacted.contains("[REDACTED:PII:"));

    // Verify manifest entries match categories
    assert!(
        manifest
            .entries
            .iter()
            .any(|e| e.category == SensitivityCategory::Token)
    );
    assert!(
        manifest
            .entries
            .iter()
            .any(|e| e.category == SensitivityCategory::Key)
    );
    assert!(
        manifest
            .entries
            .iter()
            .any(|e| e.category == SensitivityCategory::Password)
    );
    assert!(
        manifest
            .entries
            .iter()
            .any(|e| e.category == SensitivityCategory::PrivateIp)
    );
    assert!(
        manifest
            .entries
            .iter()
            .any(|e| e.category == SensitivityCategory::DatabaseUri)
    );
    assert!(
        manifest
            .entries
            .iter()
            .any(|e| e.category == SensitivityCategory::PrivateKey)
    );
    assert!(
        manifest
            .entries
            .iter()
            .any(|e| e.category == SensitivityCategory::Pii)
    );
}

#[test]
fn test_redact_packet_invariance_and_recipient_preservation() {
    let redactor = Redactor::new();
    let dummy_sha = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let mut packet = DisclosureDraftBuilder::new()
        .finding_id("finding-novel-admin-001")
        .title("RCE vulnerability in admin panel at 10.0.1.5")
        .vulnerability_type("Authentication Bypass with mock_token_secret_123")
        .severity(DisclosureSeverity::High)
        .affected_target(AffectedTarget {
            package: "admin-panel".to_string(),
            commit_range: "v1.0.0..v1.0.1".to_string(),
            repository: "https://github.com/example/admin".to_string(),
            source_snapshot_sha256: dummy_sha.to_string(),
        })
        .security_impact(SecurityImpact {
            prerequisites: "Attacker connects to 192.168.1.50 with password: \"mock_secret_pw\""
                .to_string(),
            attack_vector: "Network".to_string(),
            privileges_required: "None".to_string(),
            user_interaction: "None".to_string(),
            scope: "Unchanged".to_string(),
            confidential_impact: "High".to_string(),
            integrity_impact: "High".to_string(),
            availability_impact: "None".to_string(),
        })
        .safe_reproduction(SafeReproduction {
            test_type: "offline_unit_test".to_string(),
            harness_code: "// test harness with Bearer mock_dummy_token_xyz987".to_string(),
            sanitized_input: "header: Authorization: Bearer mock_dummy_token_xyz987".to_string(),
            expected_behavior: "Returns 401 Unauthorized".to_string(),
            observed_behavior:
                "Crash on database query mysql://root:mock_secret_pass@127.0.0.1:3306/db"
                    .to_string(),
        })
        .root_cause(RootCause {
            summary: "Leaked API token: Bearer mock_dummy_token_xyz987 in log trace".to_string(),
            cwe_id: "CWE-287".to_string(),
            trace_evidence_hashes: vec![dummy_sha.to_string()],
        })
        .suggested_mitigation(SuggestedMitigation {
            diff: "- password: \"mock_secret_pw\"\n+ password: \"[sanitized]\"".to_string(),
            compatibility_notes: "Backward compatible fix for internal gateway 10.1.2.3"
                .to_string(),
            fixed_versions: vec!["1.0.2".to_string()],
        })
        .contact_channel(ContactChannel {
            channel_type: "Email".to_string(),
            contact_target: "maintainer@upstream-repo.org".to_string(),
            security_policy_url: None,
        })
        .reporter(ReporterInfo {
            credit_name: "Security Researcher".to_string(),
            contact_email: "researcher@example.com".to_string(),
            embargo_requested_days: 90,
        })
        .build()
        .expect("Valid packet should build");

    let manifest = redactor.redact_packet(&mut packet);

    assert!(manifest.total_redactions >= 5);
    assert!(!packet.title.contains("10.0.1.5"));
    assert!(
        !packet
            .root_cause
            .summary
            .contains("mock_dummy_token_xyz987")
    );
    assert!(
        !packet
            .safe_reproduction
            .observed_behavior
            .contains("mock_secret_pass")
    );
    assert!(!packet.suggested_mitigation.diff.contains("mock_secret_pw"));
    assert!(
        !packet
            .safe_reproduction
            .harness_code
            .contains("mock_dummy_token_xyz987")
    );
    assert!(
        !packet
            .security_impact
            .prerequisites
            .contains("192.168.1.50")
    );

    // Recipient contact target must NEVER be redacted
    assert_eq!(
        packet.contact_channel.contact_target,
        "maintainer@upstream-repo.org"
    );
}

#[test]
fn test_operator_approval_lifecycle_and_adr010_enforcement() {
    let temp = tempdir().unwrap();
    let root = temp.path();

    let operator = OperatorIdentity::get_or_create(root).unwrap();
    let draft_id = "draft-sec-2026";
    let draft_json =
        r#"{"draft_id":"draft-sec-2026","title":"Novel Parser Vulnerability","severity":"High"}"#;
    let recipient = "security@vendor.com";

    // 1. Operator signs approval receipt
    let receipt = DisclosureApprovalManager::sign_approval(
        &operator, draft_id, draft_json, recipient, root, 48,
    )
    .unwrap();

    // 2. Verification succeeds on untampered draft
    assert!(
        DisclosureApprovalManager::verify_approval(&receipt, draft_id, draft_json, recipient, root)
            .is_ok()
    );

    // 3. Save receipt and reload from disk
    let saved_path = DisclosureApprovalManager::save_receipt(root, &receipt).unwrap();
    let loaded_receipt = DisclosureApprovalManager::load_receipt(&saved_path).unwrap();
    assert_eq!(loaded_receipt, receipt);

    // 4. ADR-010: Modified content fails verification
    let tampered_json = r#"{"draft_id":"draft-sec-2026","title":"Novel Parser Vulnerability","severity":"Critical"}"#;
    let tamper_err = DisclosureApprovalManager::verify_approval(
        &receipt,
        draft_id,
        tampered_json,
        recipient,
        root,
    );
    assert!(tamper_err.is_err());
    assert!(tamper_err.unwrap_err().contains("Draft Checksum Mismatch"));

    // 5. ADR-010: Redirecting recipient fails closed
    let wrong_recip_err = DisclosureApprovalManager::verify_approval(
        &receipt,
        draft_id,
        draft_json,
        "attacker@leak.io",
        root,
    );
    assert!(wrong_recip_err.is_err());
    assert!(wrong_recip_err.unwrap_err().contains("Recipient Mismatch"));

    // 6. ADR-010: Nonce replay prevention
    DisclosureApprovalManager::consume_nonce(root, &receipt.nonce).unwrap();
    let replay_err =
        DisclosureApprovalManager::verify_approval(&receipt, draft_id, draft_json, recipient, root);
    assert!(replay_err.is_err());
    assert!(replay_err.unwrap_err().contains("Receipt Replay Detected"));
}

#[test]
fn test_adr008_agent_key_cannot_forge_operator_approval() {
    let temp = tempdir().unwrap();
    let root = temp.path();

    // Agent identity key exists in workspace (.aegis/agent_identity.key)
    let agent = AgentIdentity::get_or_create(root).unwrap();

    let draft_id = "draft-forbidden-001";
    let draft_json = r#"{"draft_id":"draft-forbidden-001","content":"critical bug"}"#;
    let recipient = "security@target.com";
    let canonical_root = DisclosureApprovalManager::canonical_root(root);
    let now = Utc::now();
    let valid_until = (now + Duration::hours(12)).to_rfc3339();
    let nonce = DisclosureApprovalManager::generate_nonce();
    let draft_checksum = DisclosureApprovalManager::compute_draft_checksum(draft_json);

    let payload = DisclosureApprovalManager::compute_receipt_payload(
        draft_id,
        &draft_checksum,
        recipient,
        &canonical_root,
        "compromised-agent",
        &valid_until,
        &nonce,
    );

    // Attempting to forge receipt using agent key
    let forged_signature = agent.sign_bytes(payload.as_bytes());

    let forged_receipt = DisclosureApprovalReceipt {
        draft_id: draft_id.to_string(),
        draft_checksum,
        recipient: recipient.to_string(),
        canonical_root,
        approver: "compromised-agent".into(),
        timestamp: now.to_rfc3339(),
        valid_until,
        nonce,
        operator_public_key: agent.public_key_hex(),
        signature: forged_signature,
    };

    // Verification MUST fail closed under ADR-008
    let result = DisclosureApprovalManager::verify_approval(
        &forged_receipt,
        draft_id,
        draft_json,
        recipient,
        root,
    );

    assert!(result.is_err());
    let err_msg = result.unwrap_err();
    assert!(
        err_msg.contains("Privilege Escalation Rejected") && err_msg.contains("ADR-008"),
        "Expected ADR-008 error message, got: {}",
        err_msg
    );
}

#[test]
fn test_disclosure_audit_logging_and_tamper_evidence() {
    let temp = tempdir().unwrap();
    let root = temp.path();

    let mut hasher = Sha256::new();
    hasher.update(b"canonical_draft_payload");
    let content_sha = format!("{:x}", hasher.finalize());

    // 1. Log sequential lifecycle events
    let ev_create = DisclosureAuditEvent::new(
        "draft-audit-100",
        DisclosureAction::DraftCreated,
        "operator",
        &content_sha,
        "Draft created offline",
        serde_json::json!({"offline": true}),
    );
    let ev_redact = DisclosureAuditEvent::new(
        "draft-audit-100",
        DisclosureAction::DraftRedacted,
        "redactor",
        &content_sha,
        "Redacted credentials",
        serde_json::json!({"redactions": 4}),
    );
    let ev_approve = DisclosureAuditEvent::new(
        "draft-audit-100",
        DisclosureAction::OperatorApproved,
        "operator@company.com",
        &content_sha,
        "Approved for security@upstream.com",
        serde_json::json!({"valid_hours": 24}),
    );
    let ev_submit = DisclosureAuditEvent::new(
        "draft-audit-100",
        DisclosureAction::SubmissionAttempted,
        "agent",
        &content_sha,
        "Encrypted submission delivered",
        serde_json::json!({"channel": "vendor_pvr"}),
    );

    DisclosureAuditLogger::log_event(root, &ev_create).unwrap();
    DisclosureAuditLogger::log_event(root, &ev_redact).unwrap();
    DisclosureAuditLogger::log_event(root, &ev_approve).unwrap();
    DisclosureAuditLogger::log_event(root, &ev_submit).unwrap();

    // 2. Read events and verify sequence
    let events = DisclosureAuditLogger::read_events(root).unwrap();
    assert_eq!(events.len(), 4);
    assert_eq!(events[0].action, DisclosureAction::DraftCreated);
    assert_eq!(events[1].action, DisclosureAction::DraftRedacted);
    assert_eq!(events[2].action, DisclosureAction::OperatorApproved);
    assert_eq!(events[3].action, DisclosureAction::SubmissionAttempted);

    // 3. Verify audit trail integrity passes
    let valid_count = DisclosureAuditLogger::validate_audit_trail(root).unwrap();
    assert_eq!(valid_count, 4);

    // 4. Corrupt the audit log and verify validation fails closed
    let log_file = DisclosureAuditLogger::log_path(root);
    std::fs::write(&log_file, "INVALID_CORRUPTED_JSONL_LINE\n").unwrap();

    let corrupt_res = DisclosureAuditLogger::read_events(root);
    assert!(corrupt_res.is_err());
}
