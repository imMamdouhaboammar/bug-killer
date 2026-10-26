use std::fs;
use std::sync::Arc;
use tempfile::tempdir;

use bug_killer::deep::{
    Installation, PrivacyEngineAdapter, PrivacySkillsRegistry, ToolCapabilityBroker,
};
use bug_killer::engine::adapter::AnalyzerAdapter;
use bug_killer::engine::protocol::{
    AnalysisRequest, CoverageReceiptStatus, EngineStatus, NormalizedSeverity, ProofMethod,
};
use bug_killer::engine::registry::EngineRegistry;
use bug_killer::engine::runner::CancellationToken;
use bug_killer::types::ScanProfile;

#[test]
fn test_privacy_skills_embedded_registry_metrics() {
    let registry = PrivacySkillsRegistry::default_embedded();
    assert_eq!(
        registry.total_skills(),
        282,
        "Embedded privacy registry must contain exactly 282 canonical procedures"
    );
    assert!(!registry.all_skills().is_empty());

    let metrics = registry.metrics();
    assert_eq!(metrics.total_skills, 282);
    assert!(metrics.regulations_count >= 5);
    assert!(metrics.linddun_threats_count >= 6);
    assert!(metrics.owasp_risks_count >= 10);
    assert!(metrics.nist_categories_count >= 4);
    assert!(metrics.iso_clauses_count >= 2);

    // Verify key regulations exist in top_regulations
    let reg_names: Vec<&str> = metrics
        .top_regulations
        .iter()
        .map(|(r, _)| r.as_str())
        .collect();
    assert!(reg_names.contains(&"GDPR"));
    assert!(reg_names.contains(&"CCPA"));
    assert!(reg_names.contains(&"HIPAA"));
    assert!(reg_names.contains(&"EU_AI_ACT"));

    // Verify LINDDUN coverage
    let linddun_skills = registry.find_by_linddun("L");
    assert!(!linddun_skills.is_empty(), "LINDDUN linkability must have procedures");
}

#[test]
fn test_privacy_skill_search_and_recommendations() {
    let registry = PrivacySkillsRegistry::default_embedded();

    // Query by regulation
    let gdpr_skills = registry.find_by_regulation("GDPR");
    assert!(!gdpr_skills.is_empty(), "GDPR index must return procedures");

    // Query by OWASP risk
    let p1_skills = registry.find_by_owasp("P1");
    assert!(!p1_skills.is_empty(), "OWASP P1 must return procedures");

    // Recommend for check ID
    let ai_skills = registry.recommend_for_check("BK-AI-PRIV-002");
    assert!(
        !ai_skills.is_empty(),
        "Check BK-AI-PRIV-002 must return recommended privacy skills"
    );

    // Keyword search
    let redact_skills = registry.search("anonymization");
    assert!(!redact_skills.is_empty());
}

#[test]
fn test_privacy_engine_positive_control_unredacted_ai_pii() {
    let temp = tempdir().expect("tempdir failed");
    let test_file = temp.path().join("ai_service.ts");
    let code = r#"
import OpenAI from 'openai';

const client = new OpenAI();

export async function processUserPrompt(req: any, res: any) {
    const rawCreditCard = req.body.creditCard;
    const response = await client.chat.completions.create({
        model: 'gpt-4o',
        messages: [{ role: 'user', content: req.body.creditCard }]
    });
    return res.json(response);
}
"#;
    fs::write(&test_file, code).expect("failed to write test file");

    let adapter = PrivacyEngineAdapter::new();
    let request = AnalysisRequest {
        schema_version: "1.0".to_string(),
        run_id: "run-priv-pos-001".to_string(),
        engine_id: "privacy-engine-adapter".to_string(),
        snapshot_ref: temp.path().display().to_string(),
        snapshot_sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
        profile: ScanProfile::Deep,
        check_ids: vec!["BK-AI-PRIV-002".to_string()],
        target_ids: vec![test_file.display().to_string()],
        budgets: Default::default(),
        permissions: Default::default(),
        extensions: Default::default(),
        rule_pack_sha256: None,
    };

    let cancel = CancellationToken::new();
    let response = adapter.analyze(&request, &cancel).expect("Analysis must complete");

    assert_eq!(response.status, EngineStatus::Completed);
    assert_eq!(response.run_id, "run-priv-pos-001");
    assert!(!response.findings.is_empty(), "Must detect unredacted PII to AI API");

    let finding = response
        .findings
        .iter()
        .find(|f| f.rule_id == Some("BK-AI-PRIV-002".to_string()))
        .expect("BK-AI-PRIV-002 finding must be present");

    assert_eq!(finding.severity, NormalizedSeverity::High);
    assert!(finding.proof.is_some());
    let proof = finding.proof.as_ref().unwrap();
    assert_eq!(proof.method, ProofMethod::StaticInvariant);
    if let Err(ref e) = response.validate() {
        panic!("Response validation failed: {}", e);
    }
}

#[test]
fn test_privacy_engine_negative_control_sanitized_ai_pii() {
    let temp = tempdir().expect("tempdir failed");
    let test_file = temp.path().join("ai_service_safe.ts");
    let safe_code = r#"
import OpenAI from 'openai';
import { redactPii } from './sanitizer';

const client = new OpenAI();

export async function processUserPrompt(req: any, res: any) {
    const rawCreditCard = req.body.creditCard;
    const sanitized = redactPii(rawCreditCard);
    const response = await client.chat.completions.create({
        model: 'gpt-4o',
        messages: [{ role: 'user', content: sanitized }]
    });
    return res.json(response);
}
"#;
    fs::write(&test_file, safe_code).expect("failed to write test file");

    let adapter = PrivacyEngineAdapter::new();
    let request = AnalysisRequest {
        schema_version: "1.0".to_string(),
        run_id: "run-priv-neg-001".to_string(),
        engine_id: "privacy-engine-adapter".to_string(),
        snapshot_ref: temp.path().display().to_string(),
        snapshot_sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
        profile: ScanProfile::Deep,
        check_ids: vec!["BK-AI-PRIV-002".to_string()],
        target_ids: vec![test_file.display().to_string()],
        budgets: Default::default(),
        permissions: Default::default(),
        extensions: Default::default(),
        rule_pack_sha256: None,
    };

    let cancel = CancellationToken::new();
    let response = adapter.analyze(&request, &cancel).expect("Analysis must complete");

    assert_eq!(response.status, EngineStatus::Completed);
    // Sanitizer breaks taint chain; zero findings
    let pii_findings: Vec<_> = response
        .findings
        .iter()
        .filter(|f| f.rule_id == Some("BK-AI-PRIV-002".to_string()))
        .collect();
    assert_eq!(
        pii_findings.len(),
        0,
        "Sanitized PII flow must not generate false positive finding"
    );
    assert_eq!(response.receipts.len(), 1);
    assert_eq!(response.receipts[0].status, CoverageReceiptStatus::Evaluated);
    assert!(response.validate().is_ok());
}

#[test]
fn test_tool_capability_broker_privacy_discovery() {
    let mut broker = ToolCapabilityBroker::new();
    let all_tools = broker.discover_all();

    let priv_cap = all_tools
        .iter()
        .find(|t| t.tool_id == "privacy-engine-adapter")
        .expect("Privacy engine adapter must be discovered");

    assert_eq!(priv_cap.installation, Installation::Available);
    assert!(priv_cap.capabilities.check_ids.contains(&"BK-AI-PRIV-001".to_string()));
    assert!(priv_cap.capabilities.check_ids.contains(&"BK-AI-PRIV-010".to_string()));

    // Verify recommendations through broker
    let recommended = broker.recommend_privacy_skills("BK-AI-PRIV-004");
    assert!(!recommended.is_empty());
}

#[test]
fn test_engine_registry_deep_profile_routing() {
    let mut registry = EngineRegistry::new();
    registry.register(Arc::new(PrivacyEngineAdapter::new()));

    assert_eq!(registry.list().len(), 1);

    // Quick profile should reject deep-only privacy engine
    let temp = tempdir().expect("tempdir failed");
    let quick_request = AnalysisRequest {
        schema_version: "1.0".to_string(),
        run_id: "run-priv-quick-001".to_string(),
        engine_id: "privacy-engine-adapter".to_string(),
        snapshot_ref: temp.path().display().to_string(),
        snapshot_sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
        profile: ScanProfile::Quick,
        check_ids: vec!["BK-AI-PRIV-001".to_string()],
        target_ids: vec![temp.path().display().to_string()],
        budgets: Default::default(),
        permissions: Default::default(),
        extensions: Default::default(),
        rule_pack_sha256: None,
    };

    let cancel = CancellationToken::new();
    let quick_res = registry.dispatch(&quick_request, &cancel);
    assert!(
        quick_res.is_err(),
        "Privacy engine must reject non-deep scan profiles"
    );

    // Deep profile succeeds
    let deep_request = AnalysisRequest {
        profile: ScanProfile::Deep,
        ..quick_request
    };
    let deep_res = registry.dispatch(&deep_request, &cancel);
    assert!(deep_res.is_ok(), "Privacy engine must accept ScanProfile::Deep");
}
