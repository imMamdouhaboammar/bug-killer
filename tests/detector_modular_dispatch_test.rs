use bug_killer::detectors::agent::{AgentSkillDetector, AiAgentExtDetector, DynamicRulesDetector};
use bug_killer::detectors::auth::{
    AuthSecurityDetector, AuthzSecurityDetector, BizConcurrencyDetector, FilesystemExtDetector,
};
use bug_killer::detectors::iac::{
    CicdSecurityDetector, ContainerIacDetector, IacSecurityDetector, NativeDesktopDetector,
};
use bug_killer::detectors::quality::{BkhSafetyDetector, OpsQaDetector};
use bug_killer::detectors::sast::{
    InjectionSecurityDetector, LanguagePitfallsDetector, MemTempDetector, ParserSecurityDetector,
    TaintSastDetector,
};
use bug_killer::detectors::secrets::{CryptoWeaknessDetector, DataPrivacyDetector, SecretDetector};
use bug_killer::detectors::supply_chain::{OsvScaDetector, SupplyChainDetector};
use bug_killer::detectors::web::{ApiSecurityDetector, NetworkDosDetector, WebSecurityDetector};
use bug_killer::detectors::{DetectorRegistry, ScanContext, SecurityDetector};
use bug_killer::types::{CoverageStatus, ParserFailure, ScanCoverage, ScanProfile, ScanReport};
use chrono::Utc;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::tempdir;

// @lat: [[tests#Security Detector Modular Dispatch Tests]]
#[test]
fn test_all_26_detectors_registration_and_order_parity() {
    let registry = DetectorRegistry::default();
    let detectors = registry.all_detectors();

    assert_eq!(
        detectors.len(),
        26,
        "Expected exactly 26 detectors registered"
    );

    let expected_order = [
        "taint-sast",
        "secret-detector",
        "cicd-security",
        "container-iac",
        "agent-skill",
        "osv-sca",
        "dynamic-rules",
        "injection-security",
        "crypto-weakness",
        "web-security",
        "api-security",
        "auth-security",
        "authz-security",
        "filesystem-ext",
        "data-privacy",
        "parser-security",
        "network-dos",
        "iac-security",
        "supply-chain-security",
        "biz-concurrency",
        "ai-agent-ext",
        "language-pitfalls",
        "ops-qa",
        "native-desktop",
        "bkh-safety",
        "mem-temp",
    ];

    for (idx, expected_id) in expected_order.iter().enumerate() {
        assert_eq!(
            detectors[idx].id(),
            *expected_id,
            "Detector at position {idx} should be {expected_id}"
        );
        assert!(
            !detectors[idx].name().is_empty(),
            "Detector {expected_id} name must not be empty"
        );
        assert!(
            !detectors[idx].supported_rule_ids().is_empty(),
            "Detector {expected_id} must support at least one rule"
        );
        assert!(
            !detectors[idx].supported_languages().is_empty(),
            "Detector {expected_id} must specify supported languages"
        );
        assert!(
            !detectors[idx].supported_targets().is_empty(),
            "Detector {expected_id} must specify supported targets"
        );
        assert_eq!(
            detectors[idx].required_permissions(),
            "READ_ONLY_WORKSPACE",
            "Detector {expected_id} must enforce read-only workspace boundary"
        );
    }
}

#[test]
fn test_all_8_domain_detector_groups_dispatch_coherently() {
    let dir = tempdir().unwrap();
    let root = dir.path().to_path_buf();

    // Create a mock source file
    std::fs::write(root.join("sample.js"), "const x = 1;").unwrap();

    let ctx = ScanContext {
        root: root.clone(),
        profile: ScanProfile::Quick,
        changed_files: None,
        enable_network_osv: false,
        cached_report: Some(Arc::new(ScanReport {
            target_dir: root.clone(),
            scan_time: Utc::now().to_rfc3339(),
            total_files_scanned: 1,
            findings: Vec::new(),
            is_vulnerable: false,
            critical_count: 0,
            high_count: 0,
            coverage: ScanCoverage {
                files_scanned: 1,
                files_excluded: 0,
                parser_failures: Vec::new(),
                unsupported_targets: Vec::new(),
                coverage_status: CoverageStatus::Complete,
                receipts: Vec::new(),
            },
        })),
    };

    // 1. sast group
    let sast_detectors: Vec<Box<dyn SecurityDetector>> = vec![
        Box::new(TaintSastDetector),
        Box::new(InjectionSecurityDetector),
        Box::new(ParserSecurityDetector),
        Box::new(LanguagePitfallsDetector),
        Box::new(MemTempDetector),
    ];
    for d in sast_detectors {
        let res = d.run(&ctx);
        assert_eq!(res.receipt.status, CoverageStatus::Complete);
    }

    // 2. secrets group
    let secret_detectors: Vec<Box<dyn SecurityDetector>> = vec![
        Box::new(SecretDetector),
        Box::new(CryptoWeaknessDetector),
        Box::new(DataPrivacyDetector),
    ];
    for d in secret_detectors {
        let res = d.run(&ctx);
        assert_eq!(res.receipt.status, CoverageStatus::Complete);
    }

    // 3. iac group
    let iac_detectors: Vec<Box<dyn SecurityDetector>> = vec![
        Box::new(CicdSecurityDetector),
        Box::new(ContainerIacDetector),
        Box::new(IacSecurityDetector),
        Box::new(NativeDesktopDetector),
    ];
    for d in iac_detectors {
        let res = d.run(&ctx);
        assert_eq!(res.receipt.status, CoverageStatus::Complete);
    }

    // 4. agent group
    let agent_detectors: Vec<Box<dyn SecurityDetector>> = vec![
        Box::new(AgentSkillDetector),
        Box::new(DynamicRulesDetector),
        Box::new(AiAgentExtDetector),
    ];
    for d in agent_detectors {
        let res = d.run(&ctx);
        assert_eq!(res.receipt.status, CoverageStatus::Complete);
    }

    // 5. supply_chain group
    let supply_detectors: Vec<Box<dyn SecurityDetector>> =
        vec![Box::new(OsvScaDetector), Box::new(SupplyChainDetector)];
    for d in supply_detectors {
        let res = d.run(&ctx);
        // OsvSca without network is NotRun (partial/offline)
        if d.id() == "osv-sca" {
            assert_eq!(res.receipt.status, CoverageStatus::NotRun);
            assert!(
                res.receipt
                    .skipped_reasons
                    .iter()
                    .any(|r| r.contains("Network OSV lookup disabled"))
            );
        } else {
            assert_eq!(res.receipt.status, CoverageStatus::Complete);
        }
    }

    // 6. web group
    let web_detectors: Vec<Box<dyn SecurityDetector>> = vec![
        Box::new(WebSecurityDetector),
        Box::new(ApiSecurityDetector),
        Box::new(NetworkDosDetector),
    ];
    for d in web_detectors {
        let res = d.run(&ctx);
        assert_eq!(res.receipt.status, CoverageStatus::Complete);
    }

    // 7. auth group
    let auth_detectors: Vec<Box<dyn SecurityDetector>> = vec![
        Box::new(AuthSecurityDetector),
        Box::new(AuthzSecurityDetector),
        Box::new(FilesystemExtDetector),
        Box::new(BizConcurrencyDetector),
    ];
    for d in auth_detectors {
        let res = d.run(&ctx);
        assert_eq!(res.receipt.status, CoverageStatus::Complete);
    }

    // 8. quality group
    let quality_detectors: Vec<Box<dyn SecurityDetector>> =
        vec![Box::new(OpsQaDetector), Box::new(BkhSafetyDetector)];
    for d in quality_detectors {
        let res = d.run(&ctx);
        assert_eq!(res.receipt.status, CoverageStatus::Complete);
    }
}

#[test]
fn test_detector_rule_set_union_parity() {
    let registry = DetectorRegistry::default();
    let mut manual_union = HashSet::new();

    for detector in registry.all_detectors() {
        for rule_id in detector.supported_rule_ids() {
            manual_union.insert(rule_id.to_string());
        }
    }

    let registry_union = registry.supported_rule_ids();
    assert_eq!(
        manual_union, registry_union,
        "Registry rule set union must match sum of detector supported rules"
    );
    assert!(
        registry_union.len() > 100,
        "Expected broad catalog coverage with over 100 supported rules"
    );
}

#[test]
fn test_partial_coverage_propagation_for_secret_and_osv_detectors() {
    let dir = tempdir().unwrap();
    let root = dir.path().to_path_buf();

    // Context with simulated parser failure causing partial coverage
    let ctx = ScanContext {
        root: root.clone(),
        profile: ScanProfile::Deep,
        changed_files: None,
        enable_network_osv: false,
        cached_report: Some(Arc::new(ScanReport {
            target_dir: root.clone(),
            scan_time: Utc::now().to_rfc3339(),
            total_files_scanned: 5,
            findings: Vec::new(),
            is_vulnerable: false,
            critical_count: 0,
            high_count: 0,
            coverage: ScanCoverage {
                files_scanned: 4,
                files_excluded: 1,
                parser_failures: vec![ParserFailure {
                    path: PathBuf::from("corrupt.js"),
                    reason: "Syntax error on line 42".to_string(),
                }],
                unsupported_targets: Vec::new(),
                coverage_status: CoverageStatus::Partial,
                receipts: Vec::new(),
            },
        })),
    };

    let secret_res = SecretDetector.run(&ctx);
    assert_eq!(secret_res.receipt.status, CoverageStatus::Partial);
    assert!(!secret_res.receipt.errors.is_empty());
    assert!(secret_res.receipt.errors[0].contains("corrupt.js"));
    assert!(!secret_res.receipt.skipped_reasons.is_empty());

    let osv_res = OsvScaDetector.run(&ctx);
    assert_eq!(osv_res.receipt.status, CoverageStatus::NotRun);
    assert!(osv_res.receipt.skipped_reasons[0].contains("Network OSV lookup disabled"));
}
