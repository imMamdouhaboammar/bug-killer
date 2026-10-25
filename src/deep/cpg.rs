use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::path::Path;
use std::time::Instant;

use crate::engine::runner::{AnalysisError, CancellationToken};

/// Classification of a CPG node within control, dataflow, or call graphs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CpgNodeKind {
    Source,
    Sink,
    Sanitizer,
    CallSite,
    Variable,
    Return,
    Param,
    Call,
    Identifier,
    DynamicDispatch,
    Method,
}

pub type NodeKind = CpgNodeKind;

/// Type of dependency edge between nodes in the Code Property Graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CpgEdgeKind {
    DataFlow,
    ControlFlow,
    CallDirect,
    CallDynamic,
    Ast,
    Cfg,
    Cdg,
    Ddg,
    Call,
    DynamicCall,
}

pub type EdgeKind = CpgEdgeKind;

/// Certainty of a dataflow trace path from source to sink.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TraceCertainty {
    Confirmed,
    Uncertain,
    Suspected,
}

impl TraceCertainty {
    pub fn as_str(&self) -> &'static str {
        match self {
            TraceCertainty::Confirmed => "CONFIRMED",
            TraceCertainty::Uncertain => "UNCERTAIN",
            TraceCertainty::Suspected => "SUSPECTED",
        }
    }
}

/// Individual node in the Code Property Graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CpgNode {
    pub id: usize,
    pub file: String,
    pub line: usize,
    pub code: String,
    pub kind: CpgNodeKind,
    pub symbol: Option<String>,
}

/// Directed edge in the Code Property Graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CpgEdge {
    pub from: usize,
    pub to: usize,
    pub kind: CpgEdgeKind,
    pub is_inferred: bool,
}

/// Step along an interprocedural or intraprocedural taint propagation path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataflowStep {
    pub step_index: usize,
    pub node_id: usize,
    pub file: String,
    pub line: usize,
    pub code: String,
    pub is_dynamic: bool,
    pub label: String,
    pub edge_kind: Option<CpgEdgeKind>,
    pub function_name: Option<String>,
}

pub type TaintStep = DataflowStep;
pub type TraceStep = DataflowStep;

/// Complete taint trace discovered between an untrusted input and a sensitive sink.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CpgDataflowTrace {
    pub trace_id: String,
    pub source_id: usize,
    pub sink_id: usize,
    pub source_file: String,
    pub source_line: u32,
    pub sink_file: String,
    pub sink_line: u32,
    pub steps: Vec<DataflowStep>,
    pub certainty: TraceCertainty,
    pub weakness: String,
    pub is_multi_file: bool,
    pub uncertainty_reasons: Vec<String>,
    pub is_sanitized: bool,
    pub sanitizer_node_id: Option<usize>,
}

pub type TaintFlow = CpgDataflowTrace;

/// Code Property Graph supporting inter-procedural multi-file cross-function taint and dataflow analysis.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CpgGraph {
    pub nodes: Vec<CpgNode>,
    pub edges: Vec<CpgEdge>,
    adjacency: HashMap<usize, Vec<(usize, CpgEdgeKind, bool)>>,
}

pub type CodePropertyGraph = CpgGraph;

/// Exploration result tuple: (path_node_ids, has_dynamic, is_sanitized, uncertainty_reasons)
pub type BoundedPathResult = (Vec<usize>, bool, bool, Vec<String>);

impl CpgGraph {
    pub fn new() -> Self {
        Self {
            nodes: Vec::new(),
            edges: Vec::new(),
            adjacency: HashMap::new(),
        }
    }

    /// Add a node to the CPG, returning its unique node ID.
    pub fn add_node(
        &mut self,
        file: &str,
        line: usize,
        code: &str,
        kind: CpgNodeKind,
        symbol: Option<&str>,
    ) -> usize {
        let id = self.nodes.len();
        self.nodes.push(CpgNode {
            id,
            file: file.to_string(),
            line,
            code: code.to_string(),
            kind,
            symbol: symbol.map(|s| s.to_string()),
        });
        id
    }

    /// Add a directed dependency edge.
    pub fn add_edge(&mut self, from: usize, to: usize, kind: CpgEdgeKind, is_inferred: bool) {
        self.edges.push(CpgEdge {
            from,
            to,
            kind,
            is_inferred,
        });
        self.adjacency
            .entry(from)
            .or_default()
            .push((to, kind, is_inferred));
    }

    /// Add a data flow edge between two nodes.
    pub fn add_dataflow_edge(&mut self, from: usize, to: usize) {
        self.add_edge(from, to, CpgEdgeKind::DataFlow, false);
    }

    /// Add a control flow edge between two nodes.
    pub fn add_controlflow_edge(&mut self, from: usize, to: usize) {
        self.add_edge(from, to, CpgEdgeKind::ControlFlow, false);
    }

    /// Connect interprocedural cross-file call site to target function entry (resolved call).
    pub fn add_call_edge(&mut self, caller_call_node: usize, callee_entry_node: usize) {
        self.add_edge(
            caller_call_node,
            callee_entry_node,
            CpgEdgeKind::CallDirect,
            false,
        );
    }

    /// Connect unresolved dynamic dispatch / reflection call.
    pub fn add_dynamic_call_edge(&mut self, caller_dynamic_node: usize, callee_entry_node: usize) {
        self.add_edge(
            caller_dynamic_node,
            callee_entry_node,
            CpgEdgeKind::CallDynamic,
            true,
        );
    }

    /// Access all nodes in the graph.
    pub fn nodes(&self) -> &[CpgNode] {
        &self.nodes
    }

    /// Access all edges in the graph.
    pub fn edges(&self) -> &[CpgEdge] {
        &self.edges
    }

    /// Compute taint propagation flows from all sources to all sinks (synchronous helper).
    pub fn find_taint_flows(&self) -> Vec<TaintFlow> {
        let cancel_token = CancellationToken::new();
        self.propagate_taint_bounded(&cancel_token, None)
            .unwrap_or_default()
    }

    /// Computes inter-procedural taint propagation observing cooperative cancellation.
    pub fn propagate_taint(
        &self,
        cancel_token: &CancellationToken,
    ) -> Result<Vec<CpgDataflowTrace>, AnalysisError> {
        self.propagate_taint_bounded(cancel_token, None)
    }

    /// Computes taint propagation observing both cancellation tokens and optional execution deadlines.
    pub fn propagate_taint_bounded(
        &self,
        cancel_token: &CancellationToken,
        deadline: Option<Instant>,
    ) -> Result<Vec<CpgDataflowTrace>, AnalysisError> {
        let mut flows = Vec::new();
        let sources: Vec<usize> = self
            .nodes
            .iter()
            .filter(|n| n.kind == CpgNodeKind::Source)
            .map(|n| n.id)
            .collect();

        for source_id in sources {
            if cancel_token.is_cancelled() {
                return Err(AnalysisError::Cancelled);
            }
            if let Some(dl) = deadline {
                if Instant::now() >= dl {
                    return Err(AnalysisError::Timeout(0));
                }
            }

            let paths = self.explore_paths_bounded(source_id, cancel_token, deadline)?;
            for (path_nodes, has_dynamic, is_sanitized, uncertainty_reasons) in paths {
                if is_sanitized {
                    // Sanitizer neutralized the taint chain; defense intact, zero vulnerability reported
                    continue;
                }
                if let Some(&last_id) = path_nodes.last() {
                    let last_node = &self.nodes[last_id];
                    if last_node.kind == CpgNodeKind::Sink {
                        let source_node = &self.nodes[source_id];
                        let steps = path_nodes
                            .iter()
                            .enumerate()
                            .map(|(idx, &nid)| {
                                let node = &self.nodes[nid];
                                DataflowStep {
                                    step_index: idx,
                                    node_id: nid,
                                    file: node.file.clone(),
                                    line: node.line,
                                    code: node.code.clone(),
                                    is_dynamic: node.kind == CpgNodeKind::DynamicDispatch,
                                    label: node
                                        .symbol
                                        .clone()
                                        .unwrap_or_else(|| format!("{:?}", node.kind)),
                                    edge_kind: None,
                                    function_name: node.symbol.clone(),
                                }
                            })
                            .collect();

                        let is_multi_file = source_node.file != last_node.file;
                        let certainty = if has_dynamic {
                            TraceCertainty::Uncertain
                        } else {
                            TraceCertainty::Confirmed
                        };

                        let weakness = Self::infer_weakness(&last_node.code);

                        flows.push(CpgDataflowTrace {
                            trace_id: format!("trace-{}-{}", source_id, last_id),
                            source_id,
                            sink_id: last_id,
                            source_file: source_node.file.clone(),
                            source_line: source_node.line as u32,
                            sink_file: last_node.file.clone(),
                            sink_line: last_node.line as u32,
                            steps,
                            certainty,
                            weakness,
                            is_multi_file,
                            uncertainty_reasons,
                            is_sanitized: false,
                            sanitizer_node_id: None,
                        });
                    }
                }
            }
        }

        Ok(flows)
    }

    fn infer_weakness(sink_code: &str) -> String {
        let lower = sink_code.to_ascii_lowercase();
        if lower.contains("query")
            || lower.contains("sql")
            || lower.contains("select")
            || lower.contains("cursor.execute")
        {
            "CWE-89".to_string()
        } else if lower.contains("exec")
            || lower.contains("system")
            || lower.contains("spawn")
            || lower.contains("popen")
        {
            "CWE-78".to_string()
        } else if lower.contains("readfile") || lower.contains("open") || lower.contains("path") {
            "CWE-22".to_string()
        } else if lower.contains("fetch")
            || lower.contains("axios")
            || lower.contains("request")
            || lower.contains("http")
        {
            "CWE-918".to_string()
        } else if lower.contains("write") || lower.contains("html") || lower.contains("render") {
            "CWE-79".to_string()
        } else {
            "CWE-89".to_string()
        }
    }

    fn explore_paths_bounded(
        &self,
        start_id: usize,
        cancel_token: &CancellationToken,
        deadline: Option<Instant>,
    ) -> Result<Vec<BoundedPathResult>, AnalysisError> {
        let mut results = Vec::new();
        // State: (current_path, has_dynamic, is_sanitized, uncertainty_reasons)
        let mut queue = VecDeque::new();
        let start_node = &self.nodes[start_id];
        let start_dynamic = start_node.kind == CpgNodeKind::DynamicDispatch;
        let start_sanitized = start_node.kind == CpgNodeKind::Sanitizer;
        let mut start_reasons = Vec::new();
        if start_dynamic {
            start_reasons.push(format!(
                "Dynamic source dispatch at {}:{}",
                start_node.file, start_node.line
            ));
        }

        queue.push_back((
            vec![start_id],
            start_dynamic,
            start_sanitized,
            start_reasons,
        ));

        while let Some((current_path, has_dynamic, is_sanitized, reasons)) = queue.pop_front() {
            if cancel_token.is_cancelled() {
                return Err(AnalysisError::Cancelled);
            }
            if let Some(dl) = deadline {
                if Instant::now() >= dl {
                    return Err(AnalysisError::Timeout(0));
                }
            }

            let last_id = *current_path.last().unwrap();
            let last_node = &self.nodes[last_id];

            if last_node.kind == CpgNodeKind::Sink || is_sanitized {
                results.push((current_path, has_dynamic, is_sanitized, reasons));
                continue;
            }

            if let Some(edges) = self.adjacency.get(&last_id) {
                let mut extended = false;
                for &(next_id, edge_kind, is_inferred) in edges {
                    if current_path.contains(&next_id) {
                        // Prevent infinite cycles
                        continue;
                    }
                    let next_node = &self.nodes[next_id];
                    let is_dynamic_edge = is_inferred
                        || edge_kind == CpgEdgeKind::CallDynamic
                        || edge_kind == CpgEdgeKind::DynamicCall
                        || next_node.kind == CpgNodeKind::DynamicDispatch;

                    let step_dynamic = has_dynamic || is_dynamic_edge;
                    let mut step_reasons = reasons.clone();
                    if is_dynamic_edge {
                        step_reasons.push(format!(
                            "Dynamic dispatch or reflection crossed at {}:{} ({})",
                            next_node.file, next_node.line, next_node.code
                        ));
                    }

                    let step_sanitized = is_sanitized || next_node.kind == CpgNodeKind::Sanitizer;

                    let mut next_path = current_path.clone();
                    next_path.push(next_id);
                    queue.push_back((next_path, step_dynamic, step_sanitized, step_reasons));
                    extended = true;
                }

                if !extended && current_path.len() > 1 {
                    results.push((current_path, has_dynamic, is_sanitized, reasons));
                }
            } else if current_path.len() > 1 {
                results.push((current_path, has_dynamic, is_sanitized, reasons));
            }
        }

        Ok(results)
    }
}

/// Automated multi-file source parser and Code Property Graph builder.
pub struct CpgBuilder {
    cpg: CpgGraph,
    files: HashMap<String, String>,
}

impl Default for CpgBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl CpgBuilder {
    pub fn new() -> Self {
        Self {
            cpg: CpgGraph::new(),
            files: HashMap::new(),
        }
    }

    /// Add a source file to the multi-file project workspace.
    pub fn add_source_file(&mut self, path: impl AsRef<Path>, content: &str) -> &mut Self {
        let p_str = path.as_ref().display().to_string();
        self.files.insert(p_str, content.to_string());
        self
    }

    /// Constructs a builder populated with files from a workspace directory.
    pub fn from_directory(root: &Path) -> std::io::Result<Self> {
        let mut builder = Self::new();
        if root.is_file() {
            if let Ok(content) = std::fs::read_to_string(root) {
                builder.add_source_file(root, &content);
            }
            return Ok(builder);
        }

        for entry in walkdir::WalkDir::new(root)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path();
            if path.is_file() {
                let ext = path
                    .extension()
                    .and_then(|s| s.to_str())
                    .unwrap_or("")
                    .to_ascii_lowercase();
                if matches!(
                    ext.as_str(),
                    "js" | "mjs"
                        | "cjs"
                        | "ts"
                        | "tsx"
                        | "py"
                        | "php"
                        | "go"
                        | "rs"
                        | "c"
                        | "cpp"
                        | "java"
                ) {
                    if let Ok(content) = std::fs::read_to_string(path) {
                        builder.add_source_file(path, &content);
                    }
                }
            }
        }
        Ok(builder)
    }

    fn extract_defined_var(line: &str) -> Option<String> {
        let trimmed = line.trim();
        if trimmed.starts_with("//") || trimmed.starts_with('#') {
            return None;
        }
        for prefix in &["const ", "let ", "var "] {
            if let Some(rest) = trimmed.strip_prefix(prefix) {
                let var_name = rest.split(['=', ':', ' ']).next()?.trim();
                if !var_name.is_empty() {
                    return Some(var_name.to_string());
                }
            }
        }
        if trimmed.starts_with('$') {
            if let Some(idx) = trimmed.find('=') {
                let var_name = trimmed[..idx].trim();
                if !var_name.is_empty() {
                    return Some(var_name.to_string());
                }
            }
        }
        if let Some(idx) = trimmed.find(":=") {
            let var_name = trimmed[..idx].trim();
            if !var_name.is_empty() && !var_name.contains(' ') {
                return Some(var_name.to_string());
            }
        }
        if let Some(idx) = trimmed.find('=') {
            let before = trimmed[..idx].trim();
            let after = &trimmed[idx + 1..];
            if !before.is_empty()
                && !after.starts_with('=')
                && !before.ends_with('!')
                && !before.ends_with('<')
                && !before.ends_with('>')
                && !before.contains(' ')
                && !before.contains('(')
            {
                return Some(before.to_string());
            }
        }
        None
    }

    fn extract_call_arg(line: &str) -> Option<String> {
        if let Some(open) = line.rfind('(') {
            if let Some(close) = line[open..].find(')') {
                let arg_inside = line[open + 1..open + close].trim();
                let first_arg = arg_inside.split(',').next()?.trim();
                if !first_arg.is_empty()
                    && !first_arg.contains(' ')
                    && !first_arg.starts_with('"')
                    && !first_arg.starts_with('\'')
                {
                    return Some(first_arg.to_string());
                }
            }
        }
        None
    }

    /// Build the Code Property Graph and resolve multi-file dataflow and call edges.
    pub fn build(mut self) -> CpgGraph {
        let mut file_keys: Vec<_> = self.files.keys().cloned().collect();
        file_keys.sort();

        // Pass 1: Global discovery of function declarations and parameter entry points across all files
        let mut function_defs: HashMap<String, (String, usize, usize, Vec<String>)> =
            HashMap::new(); // fn_name -> (file, line, entry_id, params)

        for file in &file_keys {
            let content = &self.files[file];
            for (line_idx, line) in content.lines().enumerate() {
                let line_num = line_idx + 1;
                let trimmed = line.trim();

                if trimmed.contains("function ")
                    || trimmed.contains("def ")
                    || trimmed.contains("func ")
                {
                    let parts: Vec<&str> = trimmed.split_whitespace().collect();
                    for (i, p) in parts.iter().enumerate() {
                        if (*p == "function" || *p == "def" || *p == "func") && i + 1 < parts.len()
                        {
                            let fn_raw = parts[i + 1];
                            let fn_name = fn_raw.split('(').next().unwrap_or(fn_raw).trim();
                            if !fn_name.is_empty() {
                                // Extract parameter names inside `(...)`
                                let mut params = Vec::new();
                                if let Some(open) = trimmed.find('(') {
                                    if let Some(close) = trimmed[open..].find(')') {
                                        let inside = trimmed[open + 1..open + close].trim();
                                        for param in inside.split(',') {
                                            let p_clean = param
                                                .split_whitespace()
                                                .next()
                                                .unwrap_or("")
                                                .trim();
                                            if !p_clean.is_empty()
                                                && p_clean != "req"
                                                && p_clean != "res"
                                            {
                                                params.push(p_clean.to_string());
                                            }
                                        }
                                    }
                                }

                                let entry_id = self.cpg.add_node(
                                    file,
                                    line_num,
                                    trimmed,
                                    CpgNodeKind::Param,
                                    Some(fn_name),
                                );
                                function_defs.insert(
                                    fn_name.to_string(),
                                    (file.clone(), line_num, entry_id, params),
                                );
                            }
                        }
                    }
                }
            }
        }

        // Pass 2: Line-by-line semantic extraction of Sources, Sanitizers, Calls, and Sinks
        let mut call_sites: Vec<(String, usize, String, usize, bool)> = Vec::new(); // (file, line, callee_name, call_node_id, is_dynamic)

        for file in &file_keys {
            let content = &self.files[file];
            // Track variable name -> most recent defining node_id in this scope
            let mut var_to_node: HashMap<String, usize> = HashMap::new();

            for (line_idx, line) in content.lines().enumerate() {
                let line_num = line_idx + 1;
                let trimmed = line.trim();

                // 2a. Function definition line: bind parameters to entry node
                for (fn_name, (fn_file, fn_line, entry_id, params)) in &function_defs {
                    if fn_file == file && *fn_line == line_num {
                        for param in params {
                            var_to_node.insert(param.clone(), *entry_id);
                        }
                        var_to_node.insert(fn_name.clone(), *entry_id);
                    }
                }

                // 2b. Check for Sanitizer
                let is_sanitizer = trimmed.contains("intval(")
                    || trimmed.contains("escape_string(")
                    || trimmed.contains("sanitize(")
                    || trimmed.contains("sanitize_sql_param(")
                    || trimmed.contains("prepare_statement(")
                    || trimmed.contains("parseInt(")
                    || trimmed.contains("Number(")
                    || trimmed.contains("shlex.quote(")
                    || trimmed.contains("htmlspecialchars(");

                if is_sanitizer {
                    let san_id = self.cpg.add_node(
                        file,
                        line_num,
                        trimmed,
                        CpgNodeKind::Sanitizer,
                        Some("sanitizer"),
                    );

                    // Check which tainted variable is being sanitized
                    let arg_var = Self::extract_call_arg(trimmed);
                    if let Some(ref arg) = arg_var {
                        if let Some(&def_node) = var_to_node.get(arg) {
                            self.cpg
                                .add_edge(def_node, san_id, CpgEdgeKind::DataFlow, false);
                        }
                    }

                    // If it defines a clean variable (e.g. `const cleanId = intval(rawId);`), bind cleanId to sanitizer node
                    if let Some(def_var) = Self::extract_defined_var(trimmed) {
                        var_to_node.insert(def_var, san_id);
                    }
                    continue;
                }

                // 2c. Check for Source
                let is_source = trimmed.contains("req.query")
                    || trimmed.contains("req.body")
                    || trimmed.contains("req.params")
                    || trimmed.contains("req.headers")
                    || trimmed.contains("request.args")
                    || trimmed.contains("request.form")
                    || trimmed.contains("request.values")
                    || trimmed.contains("request.json")
                    || trimmed.contains("request.GET")
                    || trimmed.contains("request.POST")
                    || trimmed.contains("$_GET")
                    || trimmed.contains("$_POST")
                    || trimmed.contains("$_REQUEST")
                    || trimmed.contains("r.URL.Query()")
                    || trimmed.contains("r.FormValue")
                    || trimmed.contains("input(");

                if is_source {
                    let src_id = self.cpg.add_node(
                        file,
                        line_num,
                        trimmed,
                        CpgNodeKind::Source,
                        Some("untrusted_input"),
                    );

                    if let Some(def_var) = Self::extract_defined_var(trimmed) {
                        var_to_node.insert(def_var, src_id);
                    }
                    continue;
                }

                // 2d. Check for Dynamic Dispatch
                let is_dynamic_dispatch = trimmed.contains("[action](")
                    || trimmed.contains("handler[")
                    || trimmed.contains("dispatchTable[")
                    || trimmed.contains("getattr(")
                    || trimmed.contains("eval(");

                if is_dynamic_dispatch {
                    let dyn_id = self.cpg.add_node(
                        file,
                        line_num,
                        trimmed,
                        CpgNodeKind::DynamicDispatch,
                        Some("dynamic_call"),
                    );

                    // The argument passed into the dynamic dispatch is the data payload!
                    let arg_var = Self::extract_call_arg(trimmed);
                    if let Some(ref arg) = arg_var {
                        if let Some(&def_node) = var_to_node.get(arg) {
                            self.cpg
                                .add_edge(def_node, dyn_id, CpgEdgeKind::DataFlow, false);
                        }
                    }

                    call_sites.push((file.clone(), line_num, "dynamic".to_string(), dyn_id, true));
                    continue;
                }

                // 2e. Check for CallSite to known functions
                let mut is_call_site = false;
                for fn_name in function_defs.keys() {
                    if trimmed.contains(&format!("{}(", fn_name))
                        && !trimmed.contains("function ")
                        && !trimmed.contains("def ")
                    {
                        let call_id = self.cpg.add_node(
                            file,
                            line_num,
                            trimmed,
                            CpgNodeKind::CallSite,
                            Some(fn_name),
                        );

                        let arg_var = Self::extract_call_arg(trimmed);
                        if let Some(ref arg) = arg_var {
                            if let Some(&def_node) = var_to_node.get(arg) {
                                self.cpg
                                    .add_edge(def_node, call_id, CpgEdgeKind::DataFlow, false);
                            }
                        }

                        call_sites.push((file.clone(), line_num, fn_name.clone(), call_id, false));
                        is_call_site = true;
                        break;
                    }
                }
                if is_call_site {
                    continue;
                }

                // 2f. Check for Sinks
                let is_sink = trimmed.contains("db.query(")
                    || trimmed.contains("cursor.execute(")
                    || trimmed.contains("db.execute(")
                    || trimmed.contains("sql.Exec(")
                    || trimmed.contains("child_process.exec(")
                    || trimmed.contains("child_process.spawn(")
                    || trimmed.contains("os.system(")
                    || trimmed.contains("subprocess.run(")
                    || trimmed.contains("fs.readFile(")
                    || trimmed.contains("os.ReadFile(")
                    || trimmed.contains("system(");

                if is_sink {
                    let sink_id =
                        self.cpg
                            .add_node(file, line_num, trimmed, CpgNodeKind::Sink, Some("sink"));
                    let arg_var = Self::extract_call_arg(trimmed);
                    if let Some(ref arg) = arg_var {
                        if let Some(&def_node) = var_to_node.get(arg) {
                            self.cpg
                                .add_edge(def_node, sink_id, CpgEdgeKind::DataFlow, false);
                        }
                    } else {
                        // Check if any active variable is mentioned in the sink expression
                        for (v, &node_id) in &var_to_node {
                            if trimmed.contains(v) {
                                self.cpg
                                    .add_edge(node_id, sink_id, CpgEdgeKind::DataFlow, false);
                            }
                        }
                    }
                    continue;
                }

                // 2g. Intermediate variable assignment (e.g. `const sql = "SELECT..." + id;`)
                if let Some(def_var) = Self::extract_defined_var(trimmed) {
                    let var_node_id = self.cpg.add_node(
                        file,
                        line_num,
                        trimmed,
                        CpgNodeKind::Variable,
                        Some(&def_var),
                    );

                    for (prev_var, &prev_node) in &var_to_node {
                        if trimmed.contains(prev_var) {
                            self.cpg
                                .add_edge(prev_node, var_node_id, CpgEdgeKind::DataFlow, false);
                        }
                    }

                    var_to_node.insert(def_var, var_node_id);
                }
            }
        }

        // Pass 3: Resolve inter-procedural call edges across files
        for (call_file, _, callee_name, call_node_id, is_dynamic) in call_sites {
            if is_dynamic {
                // Connect dynamic dispatch to potential callee entries in different files
                for (fn_file, _, entry_id, _) in function_defs.values() {
                    if fn_file != &call_file {
                        self.cpg.add_dynamic_call_edge(call_node_id, *entry_id);
                    }
                }
            } else if let Some((_, _, entry_id, _)) = function_defs.get(&callee_name) {
                self.cpg.add_call_edge(call_node_id, *entry_id);
            }
        }

        self.cpg
    }
}
