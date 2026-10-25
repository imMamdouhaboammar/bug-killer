use crate::types::*;
use regex::Regex;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub enum TaintSourceKind {
    HttpParam,
    HttpBody,
    HttpHeader,
    EnvVar,
    CliArg,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaintSinkKind {
    SqlInjection,
    CommandInjection,
    PathTraversal,
    ServerSideRequestForgery,
    ReflectedXss,
}

impl TaintSinkKind {
    pub fn title(&self) -> &'static str {
        match self {
            Self::SqlInjection => "SQL Injection (Unsanitized User Input in SQL Query)",
            Self::CommandInjection => "Command Injection (Direct Execution of User Input)",
            Self::PathTraversal => "Path Traversal (Unvalidated File Path Access)",
            Self::ServerSideRequestForgery => {
                "SSRF (Untrusted Destination URL in Outgoing HTTP Request)"
            }
            Self::ReflectedXss => {
                "Reflected Cross-Site Scripting (Unescaped User Input in HTTP Response)"
            }
        }
    }

    pub fn cve_identifier(&self) -> &'static str {
        match self {
            Self::SqlInjection => "CWE-89",
            Self::CommandInjection => "CWE-78",
            Self::PathTraversal => "CWE-22",
            Self::ServerSideRequestForgery => "CWE-918",
            Self::ReflectedXss => "CWE-79",
        }
    }

    pub fn severity(&self) -> Severity {
        match self {
            Self::SqlInjection | Self::CommandInjection => Severity::Critical,
            Self::PathTraversal | Self::ServerSideRequestForgery => Severity::High,
            Self::ReflectedXss => Severity::Medium,
        }
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct TaintFinding {
    pub file_path: PathBuf,
    pub source_kind: TaintSourceKind,
    pub sink_kind: TaintSinkKind,
    pub variable_name: String,
    pub source_line: usize,
    pub source_snippet: String,
    pub sink_line: usize,
    pub sink_snippet: String,
    pub remediation: String,
}

impl TaintFinding {
    pub fn into_finding(self) -> Finding {
        let title = format!(
            "{}: {}",
            self.sink_kind.cve_identifier(),
            self.sink_kind.title()
        );
        let desc = format!(
            "Untrusted input from line {} ({}) propagates into dangerous sink at line {} without sanitization.",
            self.source_line,
            self.source_snippet.trim(),
            self.sink_line
        );
        let mut finding = Finding::new(
            format!(
                "taint-{}-L{}",
                self.sink_kind.cve_identifier().to_lowercase(),
                self.sink_line
            ),
            CveId::Custom {
                id: self.sink_kind.cve_identifier().to_string(),
                title,
            },
            self.sink_kind.severity(),
            TargetKind::GenericSourceFile,
            Some(self.file_path),
            Some(self.sink_line),
            self.sink_snippet.trim().to_string(),
            "Sanitize input, parameterize queries, or bind to safe validator",
            desc,
            self.remediation,
        );
        finding.detector_id = "taint-engine".to_string();
        finding.affectedness = Affectedness::PotentiallyAffected;
        finding.reachability = Reachability::PotentiallyReachable;
        finding.confidence = Confidence::Medium;
        finding.evidence_certainty = EvidenceCertainty::PatternIndicator;
        finding.uncertainty_reasons.push(
            "Lexical pattern indicator; interprocedural dataflow, contextual sanitization, and runtime execution reachability are unverified."
                .to_string(),
        );
        finding.compute_dedupe_fingerprint();
        finding
    }
}

pub struct TaintEngine;

impl TaintEngine {
    pub fn scan_source(path: &Path, content: &str) -> Vec<TaintFinding> {
        let mut findings = Vec::new();

        // Map tainted variable -> (source_kind, source_line, source_snippet)
        let mut tainted_vars: HashMap<String, (TaintSourceKind, usize, String)> = HashMap::new();

        // Regex patterns for Source extraction
        let re_js_source = Regex::new(r#"(?:const|let|var)\s+([a-zA-Z0-9_$]+)\s*=\s*(?:req\.(?:query|body|params|headers)|request\.(?:query|body|params))"#).unwrap();
        let re_py_source = Regex::new(
            r#"([a-zA-Z0-9_]+)\s*=\s*request\.(?:args|form|values|json|GET|POST)(?:\[|\.get\()"#,
        )
        .unwrap();
        let re_php_source =
            Regex::new(r#"(\$[a-zA-Z0-9_]+)\s*=\s*\$_(?:GET|POST|REQUEST|COOKIE)\["#).unwrap();
        let re_go_source = Regex::new(
            r#"([a-zA-Z0-9_]+)\s*:=\s*r\.(?:URL\.Query\(\)\.Get|FormValue|PostFormValue)\("#,
        )
        .unwrap();
        let re_go_containment_guard = Regex::new(
            r#"^if\s+!strings\.HasPrefix\(([a-zA-Z_][a-zA-Z0-9_]*)\s*,\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\+\s*string\(os\.PathSeparator\)\)\s*\{$"#,
        )
        .unwrap();

        let lines: Vec<&str> = content.lines().collect();

        for (idx, line) in lines.iter().enumerate() {
            let line_no = idx + 1;
            let trimmed = line.trim();

            if trimmed.starts_with("//") || trimmed.starts_with('#') || trimmed.is_empty() {
                continue;
            }

            // Discover primary sources before following assignments and sinks.
            if let Some(caps) = re_js_source.captures(trimmed) {
                let var = caps[1].to_string();
                tainted_vars.insert(
                    var.clone(),
                    (TaintSourceKind::HttpParam, line_no, trimmed.to_string()),
                );
                continue;
            }
            if let Some(caps) = re_py_source.captures(trimmed) {
                let var = caps[1].to_string();
                tainted_vars.insert(
                    var.clone(),
                    (TaintSourceKind::HttpParam, line_no, trimmed.to_string()),
                );
                continue;
            }
            if let Some(caps) = re_php_source.captures(trimmed) {
                let var = caps[1].to_string();
                tainted_vars.insert(
                    var.clone(),
                    (TaintSourceKind::HttpParam, line_no, trimmed.to_string()),
                );
                continue;
            }
            if let Some(caps) = re_go_source.captures(trimmed) {
                let var = caps[1].to_string();
                tainted_vars.insert(
                    var.clone(),
                    (TaintSourceKind::HttpParam, line_no, trimmed.to_string()),
                );
                continue;
            }

            // 3. Propagate taint to derived variables across JS, Python, PHP, and Go
            if let Some(eq_idx) = trimmed.find('=') {
                let left_part = trimmed[..eq_idx].trim();
                let right_part = trimmed[eq_idx + 1..].trim();

                let target_var = left_part
                    .trim_start_matches("const ")
                    .trim_start_matches("let ")
                    .trim_start_matches("var ")
                    .trim_end_matches(':')
                    .trim();

                if !target_var.is_empty()
                    && !target_var.contains(' ')
                    && !target_var.contains('(')
                    && !target_var.contains('[')
                {
                    // A successful numeric conversion yields a numeric value, but only
                    // the assigned result is safe for SQL concatenation. The input
                    // remains tainted; URL/HTML escaping is not SQL sanitization.
                    if ["parseInt(", "Number(", "int(", "float(", "intval("]
                        .iter()
                        .any(|prefix| right_part.starts_with(prefix))
                    {
                        tainted_vars.remove(target_var);
                        continue;
                    }
                    for (source_var, source_info) in tainted_vars.clone() {
                        if right_part.contains(&source_var) && target_var != source_var {
                            tainted_vars.insert(target_var.to_string(), source_info);
                            break;
                        }
                    }
                }
            }

            // Recognize the narrow Go path-containment proof only when the
            // cleaned path is rejected with an unconditional early return.
            // A plain filepath.Clean() is NOT a path traversal sanitizer.
            if path.extension().is_some_and(|ext| ext == "go") {
                if let Some(caps) = re_go_containment_guard.captures(trimmed) {
                    let candidate = caps[1].to_string();
                    let base_dir = caps[2].to_string();
                    let source_was_cleaned = lines[..idx].iter().rev().take(30).any(|previous| {
                        let previous = previous.trim();
                        previous.starts_with(&format!(
                            "{candidate} := filepath.Clean(filepath.Join({base_dir},"
                        ))
                    });
                    let base_is_constant = lines[..idx].iter().any(|previous| {
                        previous.trim().starts_with(&format!("const {base_dir} ="))
                    });
                    let mut saw_return = false;
                    let mut closed_block = false;
                    for body_line in lines[idx + 1..].iter().take(10) {
                        let body_line = body_line.trim();
                        if body_line == "}" {
                            closed_block = true;
                            break;
                        }
                        // Nested control flow cannot establish an unconditional denial.
                        if body_line.contains('{') || body_line.starts_with("//") {
                            break;
                        }
                        if body_line == "return" {
                            saw_return = true;
                        }
                    }
                    if source_was_cleaned && base_is_constant && saw_return && closed_block {
                        tainted_vars.remove(&candidate);
                    }
                }
            }

            // 4. Match against Sinks
            for (var, (source_kind, src_line, src_snippet)) in &tainted_vars {
                if !trimmed.contains(var) {
                    continue;
                }

                // Exclude lines where the variable is only assigned or tested
                if trimmed.starts_with(&format!("const {} =", var))
                    || trimmed.starts_with(&format!("let {} =", var))
                    || trimmed.starts_with(&format!("var {} =", var))
                    || trimmed.starts_with(&format!("{} =", var))
                    || trimmed.starts_with(&format!("{} :=", var))
                {
                    continue;
                }

                // Sink A: SQL Injection
                if (trimmed.contains("db.query(")
                    || trimmed.contains("pool.query(")
                    || trimmed.contains("cursor.execute(")
                    || trimmed.contains("mysqli_query(")
                    || trimmed.contains("->query("))
                    && !trimmed.contains(", [")
                    && !trimmed.contains(", (")
                {
                    findings.push(TaintFinding {
                        file_path: path.to_path_buf(),
                        source_kind: source_kind.clone(),
                        sink_kind: TaintSinkKind::SqlInjection,
                        variable_name: var.clone(),
                        source_line: *src_line,
                        source_snippet: src_snippet.clone(),
                        sink_line: line_no,
                        sink_snippet: trimmed.to_string(),
                        remediation: "Use parameterized queries ($1, ?) with query parameters array instead of raw string concatenation.".into(),
                    });
                    break;
                }

                // Sink B: Command Injection / Dynamic Code Execution
                if trimmed.contains("exec(")
                    || trimmed.contains("execSync(")
                    || trimmed.contains("child_process.exec(")
                    || trimmed.contains("os.system(")
                    || trimmed.contains("subprocess.Popen(")
                    || trimmed.contains("shell_exec(")
                    || trimmed.contains("system(")
                    || trimmed.contains("passthru(")
                    || trimmed.contains("eval(")
                {
                    findings.push(TaintFinding {
                        file_path: path.to_path_buf(),
                        source_kind: source_kind.clone(),
                        sink_kind: TaintSinkKind::CommandInjection,
                        variable_name: var.clone(),
                        source_line: *src_line,
                        source_snippet: src_snippet.clone(),
                        sink_line: line_no,
                        sink_snippet: trimmed.to_string(),
                        remediation: "Avoid spawning shell processes with user input. Use safe arguments array with spawnFile() or validate against strict allowlist.".into(),
                    });
                    break;
                }

                // Sink C: Path Traversal
                if (trimmed.contains("fs.readFile(")
                    || trimmed.contains("fs.readFileSync(")
                    || trimmed.contains("os.ReadFile(")
                    || trimmed.contains("os.Open(")
                    || trimmed.contains("open(")
                    || trimmed.contains("file_get_contents(")
                    || trimmed.contains("include "))
                    && (trimmed.contains("path.join(")
                        || trimmed.contains("+")
                        || trimmed.contains('.'))
                {
                    findings.push(TaintFinding {
                        file_path: path.to_path_buf(),
                        source_kind: source_kind.clone(),
                        sink_kind: TaintSinkKind::PathTraversal,
                        variable_name: var.clone(),
                        source_line: *src_line,
                        source_snippet: src_snippet.clone(),
                        sink_line: line_no,
                        sink_snippet: trimmed.to_string(),
                        remediation: "Validate paths with path.resolve(), verify base directory bounds, or apply filepath.Clean().".into(),
                    });
                    break;
                }

                // Sink D: SSRF
                if (trimmed.contains("fetch(")
                    || trimmed.contains("axios.get(")
                    || trimmed.contains("requests.get(")
                    || trimmed.contains("http.Get("))
                    && !trimmed.contains("https://api.trusted.")
                {
                    findings.push(TaintFinding {
                        file_path: path.to_path_buf(),
                        source_kind: source_kind.clone(),
                        sink_kind: TaintSinkKind::ServerSideRequestForgery,
                        variable_name: var.clone(),
                        source_line: *src_line,
                        source_snippet: src_snippet.clone(),
                        sink_line: line_no,
                        sink_snippet: trimmed.to_string(),
                        remediation: "Restrict outgoing HTTP requests to an explicit domain allowlist and block internal RFC1918 private IP ranges.".into(),
                    });
                    break;
                }

                // Sink E: Reflected XSS
                if trimmed.contains("res.send(")
                    || trimmed.contains("res.write(")
                    || trimmed.contains("echo ")
                    || trimmed.contains("document.write(")
                {
                    findings.push(TaintFinding {
                        file_path: path.to_path_buf(),
                        source_kind: source_kind.clone(),
                        sink_kind: TaintSinkKind::ReflectedXss,
                        variable_name: var.clone(),
                        source_line: *src_line,
                        source_snippet: src_snippet.clone(),
                        sink_line: line_no,
                        sink_snippet: trimmed.to_string(),
                        remediation: "Escape HTML entities or set Content-Type to application/json before transmitting response.".into(),
                    });
                    break;
                }
            }
        }

        findings
    }
}
