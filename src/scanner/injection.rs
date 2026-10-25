use crate::types::*;
use regex::Regex;
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::LazyLock;

static RE_YAML_UNTRUSTED_VAR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\$(?:CI_COMMIT_TITLE|CI_COMMIT_DESCRIPTION|CI_COMMIT_MESSAGE|CI_MERGE_REQUEST_TITLE|CI_MERGE_REQUEST_DESCRIPTION|CI_MERGE_REQUEST_SOURCE_BRANCH_NAME|CI_EXTERNAL_PULL_REQUEST_SOURCE_BRANCH_NAME|GITLAB_USER_NAME|BITBUCKET_PR_TITLE|BITBUCKET_PR_COMMENT|BITBUCKET_COMMIT_MESSAGE)|\$\{(?:CI_COMMIT_TITLE|CI_COMMIT_DESCRIPTION|CI_COMMIT_MESSAGE|CI_MERGE_REQUEST_TITLE|CI_MERGE_REQUEST_DESCRIPTION|CI_MERGE_REQUEST_SOURCE_BRANCH_NAME|CI_EXTERNAL_PULL_REQUEST_SOURCE_BRANCH_NAME|GITLAB_USER_NAME|BITBUCKET_PR_TITLE|BITBUCKET_PR_COMMENT|BITBUCKET_COMMIT_MESSAGE)\}"#)
        .unwrap()
});

static RE_YAML_UNSAFE_TAG: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?:!!python/object(?:/(?:apply|new))?|!ruby/object|tag:yaml\.org,2002:js/function|!(?:expr|inline)\b)"#)
        .unwrap()
});

static RE_YAML_PIPE_LOOKUP: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"lookup\s*\(\s*['"](?:pipe|eval|exec)['"]|\{\{\s*eval\s*\("#).unwrap()
});

static RE_JS_DYNAMIC_REGEXP: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?:new\s+RegExp|RegExp)\s*\(\s*([^,\)\s]+)"#).unwrap());

static RE_PY_DYNAMIC_COMPILE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"re\.compile\s*\(\s*([^,\)\s]+)"#).unwrap());

static RE_PY_DYNAMIC_FUNC: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"re\.(?:search|match|findall|finditer)\s*\(\s*([^,\)\s]+)"#).unwrap()
});

static RE_NESTED_QUANTIFIERS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"\([^)]*[\+\*][^)]*\)[\+\*]"#).unwrap());

#[allow(dead_code)]
pub struct InjectionScanner;

#[allow(dead_code)]
impl InjectionScanner {
    /// Scans non-GitHub YAML files for expression and code injection vulnerabilities (BK-AI-INJ-014).
    pub fn scan_yaml_expr_injection(path: &Path, content: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let path_str = path.to_string_lossy().replace('\\', "/");

        // GitHub Actions workflows are scanned by CicdScanner (BK-AI-CIC-001)
        if path_str.contains(".github/workflows") || path_str.contains(".github/actions") {
            return findings;
        }

        let file_hash = format!("{:x}", Sha256::digest(path_str.as_bytes()));

        for (idx, line) in content.lines().enumerate() {
            let line_num = idx + 1;
            let trimmed = line.trim();

            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            // 1. Untrusted CI variable interpolation (GitLab, Bitbucket, etc.)
            if RE_YAML_UNTRUSTED_VAR.is_match(trimmed) {
                let mut finding = Finding::new(
                    format!("INJ-YAML-VAR-{}-L{}", &file_hash[..8], line_num),
                    CveId::Custom {
                        id: "BK-AI-INJ-014".to_string(),
                        title: "YAML/CI Expression Injection from Uncontrolled Strings".to_string(),
                    },
                    Severity::Critical,
                    TargetKind::GenericConfigFile,
                    Some(path.to_path_buf()),
                    Some(line_num),
                    trimmed.to_string(),
                    "Store untrusted CI metadata in safe environment variables or files rather than direct interpolation",
                    format!(
                        "Untrusted CI expression directly interpolated into YAML at line {}: {}",
                        line_num, trimmed
                    ),
                    "Avoid direct variable interpolation in script steps. Use shell environment mapping or file reading.",
                );
                finding.detector_id = "injection-security".to_string();
                finding.category = "2.1 Injection and interpreter boundaries".to_string();
                finding.affectedness = Affectedness::ConfirmedAffected;
                finding.reachability = Reachability::ConfirmedReachable;
                finding.confidence = Confidence::Confirmed;
                finding.evidence_certainty = EvidenceCertainty::Confirmed;
                findings.push(finding);
                continue;
            }

            // 2. Unsafe YAML deserialization tags (!!python/object, !ruby/object, etc.)
            if RE_YAML_UNSAFE_TAG.is_match(trimmed) {
                let mut finding = Finding::new(
                    format!("INJ-YAML-TAG-{}-L{}", &file_hash[..8], line_num),
                    CveId::Custom {
                        id: "BK-AI-INJ-014".to_string(),
                        title:
                            "Unsafe YAML Deserialization Tag Permitting Arbitrary Code Execution"
                                .to_string(),
                    },
                    Severity::Critical,
                    TargetKind::GenericConfigFile,
                    Some(path.to_path_buf()),
                    Some(line_num),
                    trimmed.to_string(),
                    "Parse YAML using safe deserializers (e.g. yaml.safe_load) without executable object tags",
                    format!(
                        "Dangerous YAML custom tag with arbitrary code execution capability found at line {}: {}",
                        line_num, trimmed
                    ),
                    "Remove object constructor tags and load configurations strictly into pure scalar/mapping structures.",
                );
                finding.detector_id = "injection-security".to_string();
                finding.category = "2.1 Injection and interpreter boundaries".to_string();
                finding.affectedness = Affectedness::ConfirmedAffected;
                finding.reachability = Reachability::ConfirmedReachable;
                finding.confidence = Confidence::Confirmed;
                finding.evidence_certainty = EvidenceCertainty::Confirmed;
                findings.push(finding);
                continue;
            }

            // 3. Unsafe pipe or eval lookups (Ansible, Jinja2 template interpolations)
            if RE_YAML_PIPE_LOOKUP.is_match(trimmed) {
                let mut finding = Finding::new(
                    format!("INJ-YAML-LOOKUP-{}-L{}", &file_hash[..8], line_num),
                    CveId::Custom {
                        id: "BK-AI-INJ-014".to_string(),
                        title: "YAML Pipe/Eval Expression Injection via Dynamic Template Lookup"
                            .to_string(),
                    },
                    Severity::High,
                    TargetKind::GenericConfigFile,
                    Some(path.to_path_buf()),
                    Some(line_num),
                    trimmed.to_string(),
                    "Disable arbitrary pipe/eval lookups in configuration files",
                    format!(
                        "Potentially dangerous pipe/eval expression lookup detected at line {}: {}",
                        line_num, trimmed
                    ),
                    "Replace dynamic pipe lookup plugins with dedicated tasks using strict parameter validation.",
                );
                finding.detector_id = "injection-security".to_string();
                finding.category = "2.1 Injection and interpreter boundaries".to_string();
                finding.affectedness = Affectedness::ConfirmedAffected;
                finding.reachability = Reachability::ConfirmedReachable;
                finding.confidence = Confidence::Confirmed;
                finding.evidence_certainty = EvidenceCertainty::Confirmed;
                findings.push(finding);
            }
        }

        findings
    }

    /// Scans JavaScript/TypeScript and Python source files for ReDoS vulnerabilities (BK-AI-INJ-015).
    pub fn scan_redos(path: &Path, content: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let path_str = path.to_string_lossy().replace('\\', "/");
        let file_hash = format!("{:x}", Sha256::digest(path_str.as_bytes()));

        let target_kind = if path
            .extension()
            .map(|e| e == "js" || e == "ts" || e == "jsx" || e == "tsx")
            .unwrap_or(false)
        {
            TargetKind::NodeSourceFile
        } else {
            TargetKind::GenericSourceFile
        };

        for (idx, line) in content.lines().enumerate() {
            let line_num = idx + 1;
            let trimmed = line.trim();

            if trimmed.is_empty() || trimmed.starts_with("//") || trimmed.starts_with('#') {
                continue;
            }

            // 1. JavaScript/TypeScript dynamic new RegExp(userInput)
            if let Some(caps) = RE_JS_DYNAMIC_REGEXP.captures(trimmed) {
                let arg = caps.get(1).map(|m| m.as_str().trim()).unwrap_or("");
                let is_static_string = (arg.starts_with('"') && arg.ends_with('"'))
                    || (arg.starts_with('\'') && arg.ends_with('\''))
                    || (arg.starts_with('`') && arg.ends_with('`') && !arg.contains("${"));

                if !is_static_string && !arg.is_empty() {
                    let mut finding = Finding::new(
                        format!("INJ-REDOS-JS-DYN-{}-L{}", &file_hash[..8], line_num),
                        CveId::Custom {
                            id: "BK-AI-INJ-015".to_string(),
                            title:
                                "Regular Expression Denial of Service (ReDoS) via Untrusted Pattern"
                                    .to_string(),
                        },
                        Severity::High,
                        target_kind.clone(),
                        Some(path.to_path_buf()),
                        Some(line_num),
                        trimmed.to_string(),
                        "Validate regular expression syntax and bound worst-case execution complexity",
                        format!(
                            "Dynamic regular expression constructed from uncontrolled argument '{}' at line {}",
                            arg, line_num
                        ),
                        "Sanitize user input with escape-string-regexp or match using static patterns.",
                    );
                    finding.detector_id = "injection-security".to_string();
                    finding.category = "2.1 Injection and interpreter boundaries".to_string();
                    finding.affectedness = Affectedness::ConfirmedAffected;
                    finding.reachability = Reachability::ConfirmedReachable;
                    finding.confidence = Confidence::Confirmed;
                    finding.evidence_certainty = EvidenceCertainty::Confirmed;
                    findings.push(finding);
                    continue;
                }
            }

            // 2. Python dynamic re.compile(user_input) or re.search(user_input, ...)
            if let Some(caps) = RE_PY_DYNAMIC_COMPILE.captures(trimmed) {
                let arg = caps.get(1).map(|m| m.as_str().trim()).unwrap_or("");
                let is_static_string = (arg.starts_with('"') && arg.ends_with('"'))
                    || (arg.starts_with('\'') && arg.ends_with('\''))
                    || ((arg.starts_with("r\"") || arg.starts_with("r'"))
                        && (arg.ends_with('"') || arg.ends_with('\'')));

                if !is_static_string && !arg.is_empty() {
                    let mut finding = Finding::new(
                        format!("INJ-REDOS-PY-DYN-{}-L{}", &file_hash[..8], line_num),
                        CveId::Custom {
                            id: "BK-AI-INJ-015".to_string(),
                            title:
                                "Regular Expression Denial of Service (ReDoS) via Untrusted Pattern"
                                    .to_string(),
                        },
                        Severity::High,
                        target_kind.clone(),
                        Some(path.to_path_buf()),
                        Some(line_num),
                        trimmed.to_string(),
                        "Validate regular expression syntax and bound worst-case execution complexity",
                        format!(
                            "Python re.compile invoked with dynamic pattern '{}' at line {}",
                            arg, line_num
                        ),
                        "Use re.escape(pattern) before compilation or enforce static expression constraints.",
                    );
                    finding.detector_id = "injection-security".to_string();
                    finding.category = "2.1 Injection and interpreter boundaries".to_string();
                    finding.affectedness = Affectedness::ConfirmedAffected;
                    finding.reachability = Reachability::ConfirmedReachable;
                    finding.confidence = Confidence::Confirmed;
                    finding.evidence_certainty = EvidenceCertainty::Confirmed;
                    findings.push(finding);
                    continue;
                }
            } else if let Some(caps) = RE_PY_DYNAMIC_FUNC.captures(trimmed) {
                let arg = caps.get(1).map(|m| m.as_str().trim()).unwrap_or("");
                let is_static_string = (arg.starts_with('"') && arg.ends_with('"'))
                    || (arg.starts_with('\'') && arg.ends_with('\''))
                    || ((arg.starts_with("r\"") || arg.starts_with("r'"))
                        && (arg.ends_with('"') || arg.ends_with('\'')));

                if !is_static_string
                    && !arg.is_empty()
                    && (arg.contains("pattern")
                        || arg.contains("query")
                        || arg.contains("user")
                        || arg.contains("input")
                        || arg.contains("regex"))
                {
                    let mut finding = Finding::new(
                        format!("INJ-REDOS-PY-FUNC-{}-L{}", &file_hash[..8], line_num),
                        CveId::Custom {
                            id: "BK-AI-INJ-015".to_string(),
                            title:
                                "Regular Expression Denial of Service (ReDoS) via Untrusted Pattern"
                                    .to_string(),
                        },
                        Severity::High,
                        target_kind.clone(),
                        Some(path.to_path_buf()),
                        Some(line_num),
                        trimmed.to_string(),
                        "Validate regular expression syntax and bound worst-case execution complexity",
                        format!(
                            "Python regex function called with dynamic pattern argument '{}' at line {}",
                            arg, line_num
                        ),
                        "Use re.escape(pattern) before searching or enforce static expressions.",
                    );
                    finding.detector_id = "injection-security".to_string();
                    finding.category = "2.1 Injection and interpreter boundaries".to_string();
                    finding.affectedness = Affectedness::ConfirmedAffected;
                    finding.reachability = Reachability::ConfirmedReachable;
                    finding.confidence = Confidence::Confirmed;
                    finding.evidence_certainty = EvidenceCertainty::Confirmed;
                    findings.push(finding);
                    continue;
                }
            }

            // 3. Catastrophic backtracking patterns (nested quantifiers: (a+)+, ([a-z]+)*)
            if RE_NESTED_QUANTIFIERS.is_match(trimmed)
                && (trimmed.contains("RegExp")
                    || trimmed.contains("re.compile")
                    || trimmed.contains('/')
                    || trimmed.contains("pattern"))
            {
                let mut finding = Finding::new(
                    format!("INJ-REDOS-NESTED-{}-L{}", &file_hash[..8], line_num),
                    CveId::Custom {
                        id: "BK-AI-INJ-015".to_string(),
                        title:
                            "Regular Expression Denial of Service (ReDoS) via Nested Quantifiers"
                                .to_string(),
                    },
                    Severity::High,
                    target_kind.clone(),
                    Some(path.to_path_buf()),
                    Some(line_num),
                    trimmed.to_string(),
                    "Eliminate nested quantifiers or overlapping repetition groups",
                    format!(
                        "Potentially catastrophic nested quantifier pattern detected at line {}: {}",
                        line_num, trimmed
                    ),
                    "Refactor regex to remove nested repetitions (e.g. replace (a+)+ with a+) or bound maximum input length.",
                );
                finding.detector_id = "injection-security".to_string();
                finding.category = "2.1 Injection and interpreter boundaries".to_string();
                finding.affectedness = Affectedness::ConfirmedAffected;
                finding.reachability = Reachability::ConfirmedReachable;
                finding.confidence = Confidence::Confirmed;
                finding.evidence_certainty = EvidenceCertainty::Confirmed;
                findings.push(finding);
            }
        }

        findings
    }
}
