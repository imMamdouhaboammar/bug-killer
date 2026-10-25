use bug_killer::healer::AutopilotHealer;
use bug_killer::healer::rollback::RollbackManager;
use bug_killer::rules::{
    DetectionMatcher, RemediationStrategy, RuleEngine, RuleProvenance, VulnerabilityRule,
};
use bug_killer::scanner::FleetScanner;
use bug_killer::types::*;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_dynamic_rules_scan_heal_and_rollback() {
    let dir = tempdir().expect("Failed to create tempdir");
    let root = dir.path();

    // 1. Create a custom rules file in root/rules/custom.json
    let rules_dir = root.join("rules");
    fs::create_dir_all(&rules_dir).unwrap();

    let rule_pytorch = VulnerabilityRule {
        id: "CVE-2024-5480".into(),
        title: "PyTorch Insecure Deserialization via torch.load".into(),
        severity: Severity::Critical,
        description: "torch.load without weights_only=True permits arbitrary code execution".into(),
        target_kind: TargetKind::GenericSourceFile,
        file_patterns: vec!["*.py".into()],
        detection: DetectionMatcher::RegexMatch {
            pattern: r#"torch\.load\s*\(([^)]*)\)"#.into(),
            not_matching: Some(r#"weights_only\s*=\s*True"#.into()),
        },
        remediation: Some(RemediationStrategy::RegexReplace {
            search: r#"torch\.load\(([^)]*)\)"#.into(),
            replace: "torch.load($1, weights_only=True)".into(),
            description: "Enforce weights_only=True in torch.load calls".into(),
        }),
        provenance: RuleProvenance::OperatorApproved,
        trusted: true,
    };

    let rule_nginx = VulnerabilityRule {
        id: "CVE-2023-44487".into(),
        title: "HTTP/2 Rapid Reset DDoS Mitigation".into(),
        severity: Severity::High,
        description: "Mitigate rapid reset flood by enforcing rate limiting in nginx".into(),
        target_kind: TargetKind::NginxConfig,
        file_patterns: vec!["*.conf".into(), "nginx.conf".into()],
        detection: DetectionMatcher::MissingPattern {
            required_pattern: "limit_req_zone".into(),
        },
        remediation: Some(RemediationStrategy::AppendBlock {
            snippet: "limit_req_zone $binary_remote_addr zone=bk_ratelimit:10m rate=100r/s;\nlimit_req zone=bk_ratelimit burst=150 nodelay;".into(),
            description: "Inject HTTP/2 rate limit directives".into(),
        }),
        provenance: RuleProvenance::OperatorApproved,
        trusted: true,
    };

    let rules_file = rules_dir.join("community_rules.json");
    let rules_json = serde_json::to_string_pretty(&vec![rule_pytorch, rule_nginx]).unwrap();
    fs::write(&rules_file, rules_json).unwrap();

    // Pin rules as operator-approved in workspace configuration
    let dot_bk = root.join(".bug-killer");
    fs::create_dir_all(&dot_bk).unwrap();
    fs::write(
        dot_bk.join("trusted_rules.json"),
        r#"["CVE-2024-5480", "CVE-2023-44487"]"#,
    )
    .unwrap();

    // Verify rules are loaded automatically
    let loaded_rules = RuleEngine::load_rules(None, root);
    assert_eq!(
        loaded_rules.len(),
        2,
        "Expected 2 custom rules loaded from rules/ directory"
    );

    // 2. Create vulnerable target files
    let py_file = root.join("inference.py");
    fs::write(&py_file, "import torch\nmodel = torch.load('weights.pt')\n").unwrap();

    let nginx_file = root.join("nginx.conf");
    fs::write(
        &nginx_file,
        "events {}\nhttp {\n    server {\n        listen 443 ssl http2;\n    }\n}\n",
    )
    .unwrap();

    // 3. Scan directory
    let report = FleetScanner::scan_directory(root, false);
    assert!(report.is_vulnerable);
    assert_eq!(report.findings.len(), 2);

    let cve_ids: Vec<String> = report
        .findings
        .iter()
        .map(|f| f.cve.as_str().to_string())
        .collect();
    assert!(cve_ids.contains(&"CVE-2024-5480".to_string()));
    assert!(cve_ids.contains(&"CVE-2023-44487".to_string()));

    // 4. Plan and execute healing
    let plan = AutopilotHealer::plan_healing(&report);
    assert_eq!(plan.len(), 2);

    let (manifest, applied_count) =
        AutopilotHealer::execute_healing(root, &plan).expect("Healing should succeed");
    assert_eq!(applied_count, 2);

    // Verify file content after healing
    let healed_py = fs::read_to_string(&py_file).unwrap();
    assert!(healed_py.contains("torch.load('weights.pt', weights_only=True)"));

    let healed_nginx = fs::read_to_string(&nginx_file).unwrap();
    assert!(healed_nginx.contains("limit_req_zone $binary_remote_addr zone=bk_ratelimit"));

    // 5. Re-scan must be clean
    let re_report = FleetScanner::scan_directory(root, false);
    assert!(
        !re_report.is_vulnerable,
        "Project should be completely clean after healing"
    );
    assert_eq!(re_report.findings.len(), 0);

    // 6. Test cryptographic rollback
    let restored_count =
        RollbackManager::rollback(root, &manifest.backup_id).expect("Rollback should succeed");
    assert_eq!(restored_count, 2);

    let restored_py = fs::read_to_string(&py_file).unwrap();
    assert_eq!(
        restored_py,
        "import torch\nmodel = torch.load('weights.pt')\n"
    );

    let restored_nginx = fs::read_to_string(&nginx_file).unwrap();
    assert_eq!(
        restored_nginx,
        "events {}\nhttp {\n    server {\n        listen 443 ssl http2;\n    }\n}\n"
    );
}
