use crate::types::*;
use ast_grep_core::{Doc, Node, tree_sitter::LanguageExt};
use ast_grep_language::SupportLang;
use regex::Regex;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::ops::Range;
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
    LazyLock::new(|| Regex::new(r#"\b(?:new\s+RegExp|RegExp)\s*\(\s*([^,\)\s]+)"#).unwrap());

static RE_PY_DYNAMIC_COMPILE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"re\.compile\s*\(\s*([^,\)\s]+)"#).unwrap());

static RE_PY_DYNAMIC_FUNC: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"re\.(?:search|match|findall|finditer)\s*\(\s*([^,\)\s]+)"#).unwrap()
});

static RE_NESTED_QUANTIFIERS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"\([^)]*[\+\*][^)]*\)[\+\*]"#).unwrap());

#[derive(Default)]
struct PythonRegexSyntax<'a> {
    static_compiles: HashSet<usize>,
    dynamic_compiles: HashMap<usize, &'a str>,
    non_code: Vec<Range<usize>>,
}

impl PythonRegexSyntax<'_> {
    fn is_non_code(&self, offset: usize) -> bool {
        let after = self.non_code.partition_point(|span| span.start <= offset);
        after
            .checked_sub(1)
            .is_some_and(|index| self.non_code[index].contains(&offset))
    }
}

fn python_regex_syntax(source: &str) -> PythonRegexSyntax<'_> {
    let tree = SupportLang::Python.ast_grep(source);
    let mut syntax = PythonRegexSyntax::default();
    for node in tree.root().dfs() {
        match node.kind().as_ref() {
            "comment" | "string_content" if !node.get_inner_node().has_error() => {
                syntax.non_code.push(node.range());
                continue;
            }
            "call" => {}
            _ => continue,
        }
        let call = node;
        let Some(callee) = call.field("function") else {
            continue;
        };
        if callee.kind() != "attribute"
            || !callee
                .field("object")
                .is_some_and(|node| node.text() == "re")
            || !callee
                .field("attribute")
                .is_some_and(|node| node.text() == "compile")
            || call.get_inner_node().has_error()
        {
            continue;
        }
        let Some(args) = call.field("arguments") else {
            continue;
        };
        let Some(mut argument) = python_compile_argument(&args) else {
            continue;
        };
        while argument.kind() == "parenthesized_expression" {
            let Some(inner) = argument
                .children()
                .find(|node| node.is_named() && !node.is_extra())
            else {
                break;
            };
            argument = inner;
        }
        if is_python_string_literal(&argument) {
            syntax.static_compiles.insert(callee.range().start);
        } else {
            syntax
                .dynamic_compiles
                .entry(callee.start_pos().line() + 1)
                .or_insert(&source[argument.range()]);
        }
    }
    syntax
}

fn python_compile_argument<'a, D: Doc>(args: &Node<'a, D>) -> Option<Node<'a, D>> {
    let mut arguments = args
        .children()
        .filter(|node| node.is_named() && !node.is_extra());
    let first = arguments.next()?;
    if first.kind() != "keyword_argument" {
        return Some(first);
    }
    std::iter::once(first).chain(arguments).find_map(|arg| {
        let name = arg.field("name")?;
        if name.text() == "pattern" {
            arg.field("value")
        } else {
            None
        }
    })
}

fn is_python_string_literal<D: Doc>(node: &Node<'_, D>) -> bool {
    matches!(node.kind().as_ref(), "string" | "concatenated_string")
        && node
            .dfs()
            .filter(|child| child.kind() == "string_start")
            .all(|start| {
                start
                    .text()
                    .trim_end_matches(['\'', '"'])
                    .bytes()
                    .all(|byte| b"bBrRuU".contains(&byte))
            })
}

fn legacy_python_string(arg: &str) -> bool {
    (arg.starts_with('"') && arg.ends_with('"'))
        || (arg.starts_with('\'') && arg.ends_with('\''))
        || ((arg.starts_with("r\"") || arg.starts_with("r'"))
            && (arg.ends_with('"') || arg.ends_with('\'')))
}

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

        let file_hash = crate::to_hex(Sha256::digest(path_str.as_bytes()));

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
        let file_hash = crate::to_hex(Sha256::digest(path_str.as_bytes()));

        let target_kind = if path
            .extension()
            .map(|e| e == "js" || e == "ts" || e == "jsx" || e == "tsx")
            .unwrap_or(false)
        {
            TargetKind::NodeSourceFile
        } else {
            TargetKind::GenericSourceFile
        };

        let python = if path.extension().is_some_and(|ext| ext == "py")
            && (content.contains("compile") || content.contains("re."))
        {
            python_regex_syntax(content)
        } else {
            PythonRegexSyntax::default()
        };

        let mut next_line_offset = 0;
        for (idx, line) in content.split_inclusive('\n').enumerate() {
            let line_num = idx + 1;
            let line_offset = next_line_offset;
            next_line_offset += line.len();
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

            let mut had_unresolved_compile = false;
            let compile_pattern = python.dynamic_compiles.get(&line_num).copied().or_else(|| {
                RE_PY_DYNAMIC_COMPILE
                    .captures_iter(line)
                    .find_map(|captures| {
                        let offset = line_offset + captures.get(0)?.start();
                        if python.static_compiles.contains(&offset) || python.is_non_code(offset) {
                            return None;
                        }
                        had_unresolved_compile = true;
                        let arg = captures.get(1)?.as_str();
                        (!legacy_python_string(arg)).then_some(arg)
                    })
            });
            if let Some(arg) = compile_pattern {
                let mut finding = Finding::new(
                    format!("INJ-REDOS-PY-DYN-{}-L{}", &file_hash[..8], line_num),
                    CveId::Custom {
                        id: "BK-AI-INJ-015".to_string(),
                        title: "Regular Expression Denial of Service (ReDoS) via Untrusted Pattern"
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
            let function_pattern = if had_unresolved_compile {
                None
            } else {
                RE_PY_DYNAMIC_FUNC.captures_iter(line).find_map(|captures| {
                    let offset = line_offset + captures.get(0)?.start();
                    let arg = captures.get(1)?.as_str();
                    (!python.is_non_code(offset)
                        && !legacy_python_string(arg)
                        && ["pattern", "query", "user", "input", "regex"]
                            .iter()
                            .any(|term| arg.contains(term)))
                    .then_some(arg)
                })
            };
            if let Some(arg) = function_pattern {
                let mut finding = Finding::new(
                    format!("INJ-REDOS-PY-FUNC-{}-L{}", &file_hash[..8], line_num),
                    CveId::Custom {
                        id: "BK-AI-INJ-015".to_string(),
                        title: "Regular Expression Denial of Service (ReDoS) via Untrusted Pattern"
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
