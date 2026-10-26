use std::fs;
use tempfile::tempdir;

use bug_killer::deep::{
    CvssVector, ThreatswarmAdapter, ThreatswarmCvssEngine, ThreatswarmFindingSync,
    ThreatswarmMitreCatalog, ThreatswarmScopeEnforcer, ToolCapabilityBroker,
};
use bug_killer::engine::adapter::AnalyzerAdapter;
use bug_killer::engine::protocol::{
    AnalysisRequest, CoverageReceiptStatus, EvidenceCertaintyV1, NormalizedSeverity,
};
use bug_killer::engine::runner::CancellationToken;
use bug_killer::types::ScanProfile;

#[test]
fn test_threatswarm_scope_enforcement_contract() {
    let scope_rules = r#"
# Authorized testing perimeters
192.168.1.0/24
10.0.0.0/8
api.internal.corp
test.staging.io
"#;
    let enforcer = ThreatswarmScopeEnforcer::load_from_str(scope_rules);
    assert_eq!(enforcer.entries_count(), 4);

    // In-scope IPs and subnets
    assert!(enforcer.is_in_scope("192.168.1.50"));
    assert!(enforcer.is_in_scope("10.254.12.1"));
    assert!(enforcer.is_in_scope("127.0.0.1"));
    assert!(enforcer.is_in_scope("localhost"));
    assert!(enforcer.is_in_scope("::1"));

    // In-scope hostnames and subdomains
    assert!(enforcer.is_in_scope("api.internal.corp"));
    assert!(enforcer.is_in_scope("sub.api.internal.corp"));
    assert!(enforcer.is_in_scope("test.staging.io"));

    // Out-of-scope targets
    assert!(!enforcer.is_in_scope("192.168.2.1"));
    assert!(!enforcer.is_in_scope("8.8.8.8"));
    assert!(!enforcer.is_in_scope("evil.com"));
    assert!(!enforcer.is_in_scope("attacker.staging.io.fake"));

    // Command verification contract
    assert!(enforcer.verify_command("curl http://192.168.1.100/health").is_ok());
    assert!(enforcer.verify_command("nmap -sV -p 443 api.internal.corp").is_ok());
    assert!(enforcer.verify_command("cargo test --workspace").is_ok());

    let egress_err = enforcer.verify_command("curl https://142.250.190.46/exfil");
    assert!(egress_err.is_err());
    let violation = egress_err.unwrap_err();
    assert_eq!(violation.target, "142.250.190.46");
    assert!(violation.reason.contains("not present in authorized scope"));
}

#[test]
fn test_threatswarm_cvss_engine_and_sla_metrics() {
    // Critical pre-auth RCE (e.g. PHP2Shell)
    let rce = CvssVector::prebuilt_for_pattern("pre-auth-rce");
    let rce_score = rce.calculate_score();
    assert_eq!(rce_score, 9.8);
    assert_eq!(rce.severity_tier(), NormalizedSeverity::Critical);
    assert_eq!(ThreatswarmCvssEngine::remediation_sla_hours(NormalizedSeverity::Critical), 24);

    let profile = ThreatswarmCvssEngine::format_risk_profile(&rce);
    assert!(profile.contains("Base Score: 9.8"));
    assert!(profile.contains("Target: 24 hours"));

    // SQL Injection vector
    let sqli = CvssVector::prebuilt_for_pattern("sqli");
    let sqli_score = sqli.calculate_score();
    assert_eq!(sqli_score, 8.1);
    assert_eq!(sqli.severity_tier(), NormalizedSeverity::High);
    assert_eq!(ThreatswarmCvssEngine::remediation_sla_hours(NormalizedSeverity::High), 72);

    // Parse explicit vector
    let vec_str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H";
    let parsed_score = ThreatswarmCvssEngine::score_vector(vec_str).expect("Valid CVSS vector");
    assert_eq!(parsed_score, 10.0);
}

#[test]
fn test_threatswarm_mitre_enterprise_catalog() {
    let catalog = ThreatswarmMitreCatalog::new();
    assert!(catalog.len() >= 14);

    // Direct technique lookup
    let t1190 = catalog.get("T1190").expect("T1190 must exist");
    assert_eq!(t1190.name, "Exploit Public-Facing Application");
    assert_eq!(t1190.tactic, "Initial Access");

    let t1059 = catalog.get("T1059").expect("T1059 must exist");
    assert_eq!(t1059.name, "Command and Scripting Interpreter");
    assert_eq!(t1059.tactic, "Execution");

    // CWE to ATT&CK TTP mapping
    let cwe78_ttps = catalog.map_cwe("CWE-78");
    assert!(!cwe78_ttps.is_empty());
    assert_eq!(cwe78_ttps[0].id, "T1059");

    let cwe89_ttps = catalog.map_cwe("CWE-89");
    assert!(!cwe89_ttps.is_empty());
    assert_eq!(cwe89_ttps[0].id, "T1190");

    let cwe22_ttps = catalog.map_cwe("CWE-22");
    assert!(!cwe22_ttps.is_empty());
    assert_eq!(cwe22_ttps[0].id, "T1083");
}

#[test]
fn test_threatswarm_findings_sync_and_deduplication() {
    let temp = tempdir().expect("Create temp dir");
    let report_file1 = temp.path().join("subsystem_report.md");
    let report_file2 = temp.path().join("network_findings.md");

    let content1 = r#"
# Subsystem Security Audit
- [CRITICAL] Remote Code Execution via desync in auth.js:42
- [HIGH] Missing TLS validation in payment client:105
"#;
    let content2 = r#"
# Network Surface Scan
- [CRITICAL] Remote Code Execution via desync in auth.js:42
- [HIGH] Unauthorized outbound egress to foreign gateway
- [MEDIUM] Verbose stack traces enabled
"#;
    fs::write(&report_file1, content1).unwrap();
    fs::write(&report_file2, content2).unwrap();

    let summary = ThreatswarmFindingSync::sync_directory(temp.path()).expect("Sync directory");
    assert_eq!(summary.scanned_files, 2);
    // [CRITICAL] Remote Code Execution is deduplicated across reports
    assert_eq!(summary.total_critical, 1);
    assert_eq!(summary.total_high, 2);

    let summary_md_path = temp.path().join("FINDINGS_SUMMARY.md");
    ThreatswarmFindingSync::write_summary_markdown(&summary, &summary_md_path).expect("Write summary");

    let saved_md = fs::read_to_string(&summary_md_path).expect("Read summary markdown");
    assert!(saved_md.contains("# ThreatSwarm Findings Summary"));
    assert!(saved_md.contains("Risk Overview: 1 Critical | 2 High"));
    assert!(saved_md.contains("Remote Code Execution via desync"));
}

#[test]
fn test_threatswarm_analyzer_adapter_execution() {
    let temp = tempdir().expect("Create tempdir");
    let scope_path = temp.path().join("scope.txt");
    fs::write(&scope_path, "127.0.0.1\ninternal.local").unwrap();

    let vulnerable_src = temp.path().join("gateway.ts");
    let code = r#"
import https from 'https';

export function forwardTraffic(payload: any) {
    // Disabled TLS check
    const agent = new https.Agent({ rejectUnauthorized: false });
    
    // Unauthorized out-of-scope egress
    const remote = curl https://93.184.216.34/api/v1;
    return remote;
}
"#;
    fs::write(&vulnerable_src, code).unwrap();

    let adapter = ThreatswarmAdapter::with_scope(&scope_path).expect("Load adapter");
    assert_eq!(adapter.engine_id(), "threatswarm-deep-adapter");
    assert_eq!(adapter.engine_version(), "1.0.0");
    assert!(adapter.supported_profiles().contains(&ScanProfile::Deep));
    assert!(adapter.supported_languages().contains(&"all"));

    let snapshot_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    let request = AnalysisRequest {
        schema_version: "1.0".to_string(),
        run_id: "run-ts-integ-001".to_string(),
        engine_id: "threatswarm-deep-adapter".to_string(),
        snapshot_ref: temp.path().display().to_string(),
        snapshot_sha256: snapshot_sha256.to_string(),
        profile: ScanProfile::Deep,
        check_ids: vec![
            "threatswarm.scope.unauthorized_egress".to_string(),
            "threatswarm.defense.disabled_tls_validation".to_string(),
        ],
        target_ids: vec![temp.path().display().to_string()],
        budgets: Default::default(),
        permissions: Default::default(),
        extensions: Default::default(),
        rule_pack_sha256: None,
    };

    let cancel = CancellationToken::new();
    let response = adapter.analyze(&request, &cancel).expect("Analysis must succeed");

    assert_eq!(response.schema_version, "1.0");
    assert_eq!(response.run_id, "run-ts-integ-001");
    assert_eq!(response.engine_id, "threatswarm-deep-adapter");
    assert_eq!(response.snapshot_sha256, snapshot_sha256);
    assert!(response.validate().is_ok(), "Response must pass protocol v1.0 validation");

    // Findings verification
    assert_eq!(response.findings.len(), 2);
    let egress_finding = response
        .findings
        .iter()
        .find(|f| f.rule_id == Some("threatswarm.scope.unauthorized_egress".to_string()))
        .expect("Egress finding must exist");
    assert_eq!(egress_finding.severity, NormalizedSeverity::High);
    assert_eq!(egress_finding.evidence_certainty, EvidenceCertaintyV1::StronglySupported);
    assert_eq!(egress_finding.weakness_ids, vec!["CWE-918".to_string()]);

    let tls_finding = response
        .findings
        .iter()
        .find(|f| f.rule_id == Some("threatswarm.defense.disabled_tls_validation".to_string()))
        .expect("TLS finding must exist");
    assert_eq!(tls_finding.severity, NormalizedSeverity::High);
    assert_eq!(tls_finding.evidence_certainty, EvidenceCertaintyV1::StronglySupported);
    assert_eq!(tls_finding.weakness_ids, vec!["CWE-295".to_string()]);

    // Receipts verification
    assert!(!response.receipts.is_empty());
    for receipt in &response.receipts {
        assert_eq!(receipt.status, CoverageReceiptStatus::Evaluated);
        assert_eq!(receipt.engine_id, "threatswarm-deep-adapter");
        assert!(receipt.validate().is_ok());
    }
}

#[test]
fn test_threatswarm_broker_registration_contract() {
    let mut broker = ToolCapabilityBroker::new();
    let cap = broker.discover_tool("threatswarm");
    assert_eq!(cap.tool_id, "threatswarm-deep-adapter");
    assert_eq!(cap.installation, bug_killer::deep::Installation::Available);
    assert_eq!(cap.governance.license_review, bug_killer::deep::LicenseReview::Approved);
    assert!(cap.capabilities.check_ids.contains(&"threatswarm.scope.unauthorized_egress".to_string()));
    assert!(cap.capabilities.check_ids.contains(&"threatswarm.defense.disabled_tls_validation".to_string()));
    assert!(cap.capabilities.check_ids.contains(&"threatswarm.cvss.base_score".to_string()));
    assert!(cap.capabilities.check_ids.contains(&"threatswarm.mitre.technique_map".to_string()));

    let all_tools = broker.discover_all();
    let ts_tool = all_tools
        .iter()
        .find(|t| t.tool_id == "threatswarm-deep-adapter");
    assert!(ts_tool.is_some(), "threatswarm-deep-adapter must be in discover_all results");
}
