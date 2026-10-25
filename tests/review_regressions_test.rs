use bug_killer::scanner::FleetScanner;
use bug_killer::scanner::ai_agent::AgentSecurityScanner;
use bug_killer::scanner::cicd::CicdScanner;
use bug_killer::scanner::data_privacy::DataPrivacyScanner;
use bug_killer::scanner::injection::InjectionScanner;
use bug_killer::scanner::language_pitfalls::LanguagePitfallsScanner;
use bug_killer::scanner::native_desktop::NativeDesktopScanner;
use bug_killer::scanner::network_dos::NetworkDosScanner;
use bug_killer::scanner::parser_security::ParserSecurityScanner;
use bug_killer::scanner::web::WebSecurityScanner;
use std::fs;
use std::path::Path;
use tempfile::tempdir;

fn rule_count(findings: &[bug_killer::types::Finding], rule: &str) -> usize {
    findings.iter().filter(|f| f.cve.as_str() == rule).count()
}

#[test]
fn npm_manifest_under_agent_directory_is_not_an_agent_configuration() {
    let path = Path::new(".agents/skills/agent-build/package.json");
    let findings = AgentSecurityScanner::scan_agent_config_str(
        path,
        r#"{"name":"example-package","version":"1.0.0","scripts":{"test":"node test.js"}}"#,
    );
    assert_eq!(rule_count(&findings, "BK-AI-LLM-017"), 0);
}

#[test]
fn pinned_github_action_with_version_comment_is_not_unpinned() {
    let sha = "0123456789abcdef0123456789abcdef01234567";
    let content =
        format!("jobs:\n  scan:\n    steps:\n      - uses: actions/checkout@{sha} # v4\n");
    let findings = CicdScanner::scan_workflow(Path::new(".github/workflows/test.yml"), &content);
    assert_eq!(rule_count(&findings, "BK-AI-CIC-003"), 0);
}

#[test]
fn privacy_multiline_finding_points_to_actual_start_line() {
    let content = "const a = 1;\nconst b = 2;\nopenai.chat.completions.create({\n  messages: req.body.password\n});";
    let findings = DataPrivacyScanner::scan_source(Path::new("service.ts"), content);
    let finding = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-SEC-011")
        .unwrap();
    assert_eq!(finding.line_number, Some(3));
}

#[test]
fn regexp_escaping_helper_is_not_regex_compilation() {
    let content = "const escaped = escapeRegExp(userInput);\nconst regex = new RegExp(userInput);";
    let findings = InjectionScanner::scan_redos(Path::new("service.js"), content);
    assert_eq!(rule_count(&findings, "BK-AI-INJ-015"), 1);
    assert_eq!(findings[0].line_number, Some(2));
}

#[test]
fn security_rule_ids_in_comments_are_not_executable_vulnerabilities() {
    let content = "// BK-AI-LNG-001: PHP include controlled by user\n// BK-AI-LNG-002: php unserialize\n// BK-AI-LNG-003: php shell_exec fed from request\n";
    let findings = LanguagePitfallsScanner::scan_source(Path::new("guide.php"), content);
    assert!(
        findings.is_empty(),
        "Comments cannot demonstrate exploitability"
    );
}

#[test]
fn python_argument_unpacking_is_not_a_null_pointer_dereference() {
    let findings = NativeDesktopScanner::scan_source(Path::new("script.py"), "print(*items)\n");
    assert_eq!(rule_count(&findings, "BK-AI-MEM-004"), 0);
}

#[test]
fn tls_disable_detector_matches_quoted_values_and_end_of_line() {
    let findings = NetworkDosScanner::scan_source(
        Path::new("service.js"),
        "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';\n",
    );
    assert_eq!(rule_count(&findings, "BK-AI-NET-007"), 1);
}

#[test]
fn random_iv_generation_is_not_reported_as_static_iv() {
    let findings = ParserSecurityScanner::scan_source(
        Path::new("encrypt.js"),
        "const IV = crypto.randomBytes(12);\n",
    );
    assert_eq!(rule_count(&findings, "BK-AI-CRY-005"), 0);
}

#[test]
fn literal_single_quoted_relative_redirect_is_not_open_redirect() {
    let findings = WebSecurityScanner::scan_source(
        Path::new("frontend.js"),
        "window.location.href = '/redirect-success';\n",
    );
    assert_eq!(rule_count(&findings, "BK-AI-WEB-004"), 0);
}

#[test]
fn fleet_scans_native_c_sources_instead_of_skipping_them() {
    let tmp = tempdir().unwrap();
    let file = tmp.path().join("unsafe.c");
    fs::write(&file, "void f(char *p) { strcpy(p, input); }\n").unwrap();
    let report = FleetScanner::scan_directory(tmp.path(), false);
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.cve.as_str() == "BK-AI-MEM-005"),
        "Native source code must be routed to the native memory scanner"
    );
}
