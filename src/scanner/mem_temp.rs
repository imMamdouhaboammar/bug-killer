#![allow(dead_code, clippy::collapsible_if)]

use crate::types::*;
use regex::Regex;
use std::collections::HashSet;
use std::path::Path;
use std::sync::LazyLock;

// ============================================================================
// Category 18: Native code, FFI and memory safety (BK-AI-MEM-001 to MEM-003)
// Category 7: Filesystem, path traversal and archive extraction (BK-AI-FIL-008)
// ============================================================================

/// BK-AI-MEM-001 (CWE-125 / CWE-787): Out-of-bounds read/write in C/C++/Zig/unsafe Rust or FFI
static RE_MEM_001_OOB_ACCESS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\bget_unchecked(?:_mut)?\s*\(|\*\s*[^;,\n]+?\.(?:add|offset)\s*\([^)]+\)|[^;,\n]+?\.(?:add|offset)\s*\([^)]+\)\.(?:read|write)\s*\(|std::ptr::(?:read|write)\s*\(\s*[^;,\n]+?\.(?:add|offset)|\*\s*\(\s*[a-zA-Z0-9_]+\s*\+\s*[a-zA-Z0-9_]*(?:idx|index|offset|pos|i|j|k)\s*\)|\b(?:ptr|raw_ptr|buffer|buf|array|arr|data|slice|dest|src|items|elements|table)\[\s*[a-zA-Z0-9_]*(?:idx|index|offset|pos|i|j|k|len|count|n)\s*\]|//.*(?:out-of-bounds\s+(?:read|write)|oob\s+(?:read|write)|ptr\[idx\]\s+without\s+bounds|slice\[offset\]\s+without\s+bounds|unchecked\s+(?:index|indexing|offset|subscript)|out of bounds read|out of bounds write))"#).unwrap()
});
static RE_MEM_001_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:if\s*(?:\()?[a-zA-Z0-9_]*(?:idx|index|offset|pos|i|j|k|len|count)\s*<\s*|if\s*(?:\()?[a-zA-Z0-9_]*(?:idx|index|offset|pos|i|j|k|len|count)\s*>=\s*|for\s*\([^;]*;\s*[a-zA-Z0-9_]+\s*<\s*|assert!\s*\([^)]*<|assert\s*\([^)]*<|\.get\s*\(|\.get_mut\s*\(|bounds_check|check_bounds|verify_bounds|in_bounds|within_bounds|is_valid_index|checked_add|ensure!\s*\([^)]*<)"#).unwrap()
});

/// BK-AI-MEM-002 (CWE-416 / CWE-415): Use-after-free, double-free or invalid lifetime across callbacks
static RE_MEM_002_FREE_CALL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?:\bfree\s*\(\s*([a-zA-Z0-9_]+)\s*\)|\bdelete\s+(?:\[\]\s*)?([a-zA-Z0-9_]+)|\bg_free\s*\(\s*([a-zA-Z0-9_]+)\s*\)|\bkfree\s*\(\s*([a-zA-Z0-9_]+)\s*\))"#).unwrap()
});
static RE_MEM_002_COMMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)//.*(?:use-after-free|double-free|use\s+after\s+free|double\s+free|uaf\b|calling\s+free\s+twice|free\(ptr\);.*\*ptr|invalid\s+lifetime\s+across\s+callbacks)"#).unwrap()
});
static RE_MEM_002_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:unique_ptr|shared_ptr|std::unique_ptr|std::shared_ptr|Arc<|Rc<|Box<|realloc|reallocated|\bNonNull\b)"#).unwrap()
});

/// BK-AI-MEM-003 (CWE-190): Integer overflow/wraparound corrupts length/offset/allocation
static RE_MEM_003_ALLOC_OVERFLOW: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\bmalloc\s*\(\s*[^)]*?\b[a-zA-Z0-9_]+\s*\*\s*[^)]+\)|\brealloc\s*\(\s*[^,]+,\s*[^)]*?\b[a-zA-Z0-9_]+\s*\*\s*[^)]+\)|\balloca\s*\(\s*[^)]*?\b[a-zA-Z0-9_]+\s*\*\s*[^)]+\)|\bnew\s+[a-zA-Z0-9_]+\[\s*[^\]]*?\b[a-zA-Z0-9_]+\s*\*\s*[^\]]+\]|\bVec::with_capacity\s*\(\s*[^)]*?\b[a-zA-Z0-9_]+\s*\*\s*[^)]+\)|\bvec!\[\s*0(?:u8)?\s*;\s*[^\]]*?\b[a-zA-Z0-9_]+\s*\*\s*[^\]]+\]|\bBuffer\.alloc(?:Unsafe)?\s*\(\s*[^)]*?\b[a-zA-Z0-9_]+\s*\*\s*[^)]+\)|\bnew\s+ArrayBuffer\s*\(\s*[^)]*?\b[a-zA-Z0-9_]+\s*\*\s*[^)]+\)|//.*(?:integer\s+overflow|wraparound.*corrupts|count\s*\*\s*size.*malloc|malloc\(count\s*\*\s*size\)|unchecked\s+multiplication.*alloc))"#).unwrap()
});
static RE_MEM_003_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:checked_mul|saturating_mul|overflowing_mul|__builtin_mul_overflow|__builtin_add_overflow|mul_overflow|SIZE_MAX|usize::MAX|reallocarray|Layout::array|calloc\s*\(|MAX_ALLOWED|MAX_SIZE|MAX_ITEMS|MAX_LIMIT|if\s*\([^)]*>\s*MAX)"#).unwrap()
});

/// BK-AI-FIL-008 (CWE-377): Temporary file predictable or opened insecurely
static RE_FIL_008_INSECURE_TEMP: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\btempfile\.mktemp\s*\(|\bos\.(?:tmpnam|tempnam)\s*\(|\bmktemp\s*\(|\b(?:tmpnam|tempnam)\s*\(|\bmktemp\s+-u\b|['"]/tmp/[a-zA-Z0-9_\-\.\/]+['"]|//.*(?:temporary\s+file\s+predictable|insecure\s+temp\s+file|hardcoded\s+/tmp/|tempfile\.mktemp|os\.tmpnam|mktemp\(\)\s+in\s+shell|predictable\s+temp\s+path))"#).unwrap()
});
static RE_FIL_008_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:NamedTemporaryFile|TemporaryDirectory|mkstemp|mkdtemp|NamedTempFile|tempfile::|os\.CreateTemp|os\.MkdirTemp|O_EXCL|0o?600|randomUUID|randomBytes)"#).unwrap()
});

// ============================================================================
// Scanner Implementation
// ============================================================================

pub struct MemTempScanner;

impl MemTempScanner {
    /// Scans source code content for Memory Safety (OOB, UAF, Integer Overflow Allocation)
    /// and Insecure Temporary File vulnerabilities.
    pub fn scan_source(path: &Path, content: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut seen = HashSet::new();

        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();

        let is_supported = matches!(
            ext.as_str(),
            "c" | "cpp"
                | "cc"
                | "cxx"
                | "h"
                | "hpp"
                | "hxx"
                | "rs"
                | "zig"
                | "go"
                | "py"
                | "js"
                | "mjs"
                | "cjs"
                | "ts"
                | "tsx"
                | "jsx"
                | "sh"
                | "bash"
                | "zsh"
                | "java"
                | "kt"
                | "swift"
                | "txt"
                | ""
        );
        if !is_supported {
            return findings;
        }

        let target_kind = match ext.as_str() {
            "js" | "mjs" | "cjs" | "ts" | "tsx" | "jsx" => TargetKind::NodeSourceFile,
            _ => TargetKind::GenericSourceFile,
        };

        let lines: Vec<&str> = content.lines().collect();
        let total_lines = lines.len();

        for (idx, line) in lines.iter().enumerate() {
            let line_no = idx + 1;
            let trimmed = line.trim();

            if trimmed.is_empty() {
                continue;
            }

            // Window contexts for multi-line analysis (+/- 6 lines)
            let window_start = idx.saturating_sub(6);
            let window_end = (idx + 7).min(total_lines);
            let context_window = lines[window_start..window_end].join("\n");

            let is_comment = trimmed.starts_with("//")
                || trimmed.starts_with('#')
                || trimmed.starts_with("/*")
                || trimmed.starts_with("*/")
                || trimmed.starts_with("* ")
                || trimmed == "*"
                || trimmed.starts_with("<!--");

            if is_comment {
                let lower = trimmed.to_lowercase();

                // BK-AI-MEM-001 comment trigger
                if lower.contains("out-of-bounds read")
                    || lower.contains("out-of-bounds write")
                    || lower.contains("oob read")
                    || lower.contains("oob write")
                    || lower.contains("ptr[idx] without bounds")
                    || lower.contains("slice[offset] without bounds")
                    || lower.contains("unchecked index")
                {
                    Self::push_finding(
                        &mut findings,
                        &mut seen,
                        "BK-AI-MEM-001",
                        &["CWE-125", "CWE-787"],
                        "Out-of-bounds read/write in C/C++/Zig/unsafe Rust or FFI",
                        Severity::Critical,
                        "2.18 Native code, FFI and memory safety",
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Enforce strict bounds validation prior to pointer indexing, slice arithmetic, or unchecked indexing",
                        "Code comment indicates unchecked out-of-bounds read or write condition.",
                        "Perform explicit bounds validation (e.g. index < len), utilize safe accessors (.get()), or assert bounds before unsafe pointer dereference.",
                    );
                }

                // BK-AI-MEM-002 comment trigger
                if lower.contains("use-after-free")
                    || lower.contains("double-free")
                    || lower.contains("double free")
                    || lower.contains("use after free")
                    || lower.contains("calling free twice")
                    || lower.contains("free(ptr); ... *ptr")
                    || lower.contains("invalid lifetime across callbacks")
                {
                    Self::push_finding(
                        &mut findings,
                        &mut seen,
                        "BK-AI-MEM-002",
                        &["CWE-416", "CWE-415"],
                        "Use-after-free, double-free or invalid lifetime across callbacks",
                        Severity::Critical,
                        "2.18 Native code, FFI and memory safety",
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Ensure pointers are nullified post-deallocation, avoid duplicate frees, and enforce valid lifetimes across execution callbacks",
                        "Code comment indicates potential use-after-free, double-free, or invalid lifetime defect.",
                        "Nullify pointer immediately upon deallocation (ptr = NULL), transition to RAII / smart pointer ownership (std::unique_ptr, Box), and eliminate redundant free calls.",
                    );
                }

                // BK-AI-MEM-003 comment trigger
                if lower.contains("integer overflow")
                    || lower.contains("wraparound corrupts")
                    || lower.contains("count * size")
                    || lower.contains("malloc(count * size)")
                    || lower.contains("unchecked multiplication")
                {
                    Self::push_finding(
                        &mut findings,
                        &mut seen,
                        "BK-AI-MEM-003",
                        &["CWE-190"],
                        "Integer overflow/wraparound corrupts length/offset/allocation",
                        Severity::High,
                        "2.18 Native code, FFI and memory safety",
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Validate arithmetic operations against integer bounds using checked math or safe allocation wrappers before sizing memory",
                        "Code comment indicates integer multiplication or addition sizing allocation without overflow checks.",
                        "Employ checked arithmetic (checked_mul, __builtin_mul_overflow) or safe multi-argument allocation primitives (calloc, reallocarray, Layout::array).",
                    );
                }

                // BK-AI-FIL-008 comment trigger
                if lower.contains("temporary file predictable")
                    || lower.contains("insecure temp file")
                    || lower.contains("hardcoded /tmp/")
                    || lower.contains("tempfile.mktemp")
                    || lower.contains("os.tmpnam")
                    || lower.contains("mktemp() in shell")
                    || lower.contains("predictable temp path")
                {
                    Self::push_finding(
                        &mut findings,
                        &mut seen,
                        "BK-AI-FIL-008",
                        &["CWE-377"],
                        "Temporary file predictable or opened insecurely",
                        Severity::High,
                        "2.7 Filesystem, path traversal and archive extraction",
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Use cryptographically secure, atomically created temporary files with exclusive creation flags and restrictive permissions",
                        "Code comment indicates predictable or insecure temporary file usage.",
                        "Replace with atomic, unpredictably named temp files using safe APIs (mkstemp, NamedTemporaryFile, tempfile::NamedTempFile, os.CreateTemp) with 0600 permissions.",
                    );
                }

                continue;
            }

            // ----------------------------------------------------------------
            // 1. BK-AI-MEM-001: Out-of-bounds read/write
            // ----------------------------------------------------------------
            if RE_MEM_001_OOB_ACCESS.is_match(trimmed)
                && !RE_MEM_001_GUARD.is_match(&context_window)
            {
                Self::push_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-MEM-001",
                    &["CWE-125", "CWE-787"],
                    "Out-of-bounds read/write in C/C++/Zig/unsafe Rust or FFI",
                    Severity::Critical,
                    "2.18 Native code, FFI and memory safety",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Enforce strict bounds validation prior to pointer indexing, slice arithmetic, or unchecked indexing",
                    "Out-of-bounds read or write detected via unchecked pointer arithmetic, raw pointer indexing, or get_unchecked without bounds validation.",
                    "Perform explicit bounds validation (e.g. index < len), utilize safe accessors (.get()), or assert bounds before unsafe pointer dereference.",
                );
            }

            // ----------------------------------------------------------------
            // 2. BK-AI-MEM-002: Use-after-free or double-free
            // ----------------------------------------------------------------
            if let Some(caps) = RE_MEM_002_FREE_CALL.captures(trimmed) {
                let freed_var = caps
                    .get(1)
                    .or_else(|| caps.get(2))
                    .or_else(|| caps.get(3))
                    .or_else(|| caps.get(4))
                    .map(|m| m.as_str());

                if let Some(var) = freed_var {
                    let re_escaped = regex::escape(var);
                    let re_null_reassign = Regex::new(&format!(
                        r#"(?i)(?:^|[^\w\*]){}\s*=\s*(?:NULL|nullptr|0|None|malloc|calloc|realloc|new\b)"#,
                        re_escaped
                    ))
                    .ok();
                    let re_double_free = Regex::new(&format!(
                        r#"\b(?:free|delete|g_free|kfree)\s*(?:\(\s*)?(?:\[\]\s*)?{}\b"#,
                        re_escaped
                    ))
                    .ok();
                    let re_uaf = Regex::new(&format!(
                        r#"(?:\*\s*{var}\b|\b{var}\s*->|\b{var}\s*\[|\b(?:printf|use|process|read|write)\s*\([^)]*\b{var}\b)"#,
                        var = re_escaped
                    ))
                    .ok();

                    // Check lookahead lines
                    let lookahead_limit = (idx + 15).min(total_lines);
                    let mut defect_found = false;

                    for (sub_idx, sub_line) in
                        lines.iter().enumerate().take(lookahead_limit).skip(idx + 1)
                    {
                        let sub_trimmed = sub_line.trim();
                        if sub_trimmed.is_empty() {
                            continue;
                        }

                        // If variable was nullified or reallocated, safe!
                        if let Some(ref re_null) = re_null_reassign {
                            if re_null.is_match(sub_trimmed) {
                                break;
                            }
                        }

                        // Check double free
                        if let Some(ref re_df) = re_double_free {
                            if re_df.is_match(sub_trimmed)
                                && !RE_MEM_002_GUARD.is_match(&context_window)
                            {
                                Self::push_finding(
                                    &mut findings,
                                    &mut seen,
                                    "BK-AI-MEM-002",
                                    &["CWE-416", "CWE-415"],
                                    "Use-after-free, double-free or invalid lifetime across callbacks",
                                    Severity::Critical,
                                    "2.18 Native code, FFI and memory safety",
                                    path,
                                    &target_kind,
                                    sub_idx + 1,
                                    sub_trimmed,
                                    "Ensure pointers are nullified post-deallocation, avoid duplicate frees, and enforce valid lifetimes across execution callbacks",
                                    "Double-free detected: pointer is freed multiple times without intermediate reallocation.",
                                    "Nullify pointer immediately upon deallocation (ptr = NULL) or manage memory through RAII smart pointers.",
                                );
                                defect_found = true;
                                break;
                            }
                        }

                        // Check use after free
                        if let Some(ref re_use) = re_uaf {
                            if re_use.is_match(sub_trimmed)
                                && !RE_MEM_002_GUARD.is_match(&context_window)
                            {
                                Self::push_finding(
                                    &mut findings,
                                    &mut seen,
                                    "BK-AI-MEM-002",
                                    &["CWE-416", "CWE-415"],
                                    "Use-after-free, double-free or invalid lifetime across callbacks",
                                    Severity::Critical,
                                    "2.18 Native code, FFI and memory safety",
                                    path,
                                    &target_kind,
                                    sub_idx + 1,
                                    sub_trimmed,
                                    "Ensure pointers are nullified post-deallocation, avoid duplicate frees, and enforce valid lifetimes across execution callbacks",
                                    "Use-after-free detected: memory is freed and subsequently accessed or dereferenced.",
                                    "Nullify pointer immediately upon deallocation (ptr = NULL) and eliminate post-free references.",
                                );
                                defect_found = true;
                                break;
                            }
                        }
                    }

                    // Also check if double-free or UAF exists on the same line after the initial free
                    if !defect_found {
                        if let Some(match_pos) = trimmed.find(var) {
                            let remainder = &trimmed[match_pos + var.len()..];
                            let has_null = re_null_reassign
                                .as_ref()
                                .is_some_and(|re| re.is_match(remainder));
                            if !has_null {
                                let has_df = re_double_free
                                    .as_ref()
                                    .is_some_and(|re| re.is_match(remainder));
                                let has_uaf =
                                    re_uaf.as_ref().is_some_and(|re| re.is_match(remainder));
                                if (has_df || has_uaf)
                                    && !RE_MEM_002_GUARD.is_match(&context_window)
                                {
                                    Self::push_finding(
                                        &mut findings,
                                        &mut seen,
                                        "BK-AI-MEM-002",
                                        &["CWE-416", "CWE-415"],
                                        "Use-after-free, double-free or invalid lifetime across callbacks",
                                        Severity::Critical,
                                        "2.18 Native code, FFI and memory safety",
                                        path,
                                        &target_kind,
                                        line_no,
                                        trimmed,
                                        "Ensure pointers are nullified post-deallocation, avoid duplicate frees, and enforce valid lifetimes across execution callbacks",
                                        "Use-after-free or double-free detected on same statement line.",
                                        "Nullify pointer immediately upon deallocation and avoid reusing freed pointer references.",
                                    );
                                }
                            }
                        }
                    }
                }
            }

            // ----------------------------------------------------------------
            // 3. BK-AI-MEM-003: Integer overflow in allocation
            // ----------------------------------------------------------------
            if RE_MEM_003_ALLOC_OVERFLOW.is_match(trimmed)
                && !RE_MEM_003_GUARD.is_match(&context_window)
            {
                Self::push_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-MEM-003",
                    &["CWE-190"],
                    "Integer overflow/wraparound corrupts length/offset/allocation",
                    Severity::High,
                    "2.18 Native code, FFI and memory safety",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Validate arithmetic operations against integer bounds using checked math or safe allocation wrappers before sizing memory",
                    "Integer multiplication or addition passed directly to memory allocation primitive without overflow checks, potentially wrapping around to small allocation.",
                    "Employ checked arithmetic (checked_mul, __builtin_mul_overflow) or safe multi-argument allocation primitives (calloc, reallocarray, Layout::array).",
                );
            }

            // ----------------------------------------------------------------
            // 4. BK-AI-FIL-008: Predictable or insecure temporary file
            // ----------------------------------------------------------------
            if RE_FIL_008_INSECURE_TEMP.is_match(trimmed)
                && !RE_FIL_008_GUARD.is_match(&context_window)
            {
                Self::push_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-FIL-008",
                    &["CWE-377"],
                    "Temporary file predictable or opened insecurely",
                    Severity::High,
                    "2.7 Filesystem, path traversal and archive extraction",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Use cryptographically secure, atomically created temporary files with exclusive creation flags and restrictive permissions",
                    "Insecure temporary file creation detected via hardcoded predictable /tmp/ paths or vulnerable APIs (mktemp, tmpnam, tempfile.mktemp).",
                    "Replace with atomic, unpredictably named temp files using safe APIs (mkstemp, NamedTemporaryFile, tempfile::NamedTempFile, os.CreateTemp) with 0600 permissions.",
                );
            }
        }

        findings
    }

    #[allow(clippy::too_many_arguments)]
    fn push_finding(
        findings: &mut Vec<Finding>,
        seen: &mut HashSet<(String, usize)>,
        rule_id: &str,
        cwes: &[&str],
        title: &str,
        severity: Severity,
        category: &str,
        path: &Path,
        target_kind: &TargetKind,
        line_no: usize,
        snippet: &str,
        safe_threshold: &str,
        description: &str,
        remediation: &str,
    ) {
        if !seen.insert((rule_id.to_string(), line_no)) {
            return;
        }

        let file_tag = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("source");
        let short_id = rule_id.trim_start_matches("BK-AI-");
        let finding_id = format!("{}-{}-L{}", short_id, file_tag, line_no);

        let mut finding = Finding::new(
            finding_id,
            CveId::Custom {
                id: rule_id.to_string(),
                title: title.to_string(),
            },
            severity,
            target_kind.clone(),
            Some(path.to_path_buf()),
            Some(line_no),
            snippet,
            safe_threshold,
            description,
            remediation,
        );
        finding.detector_id = "mem-temp".to_string();
        finding.detector_version = "1.0.0".to_string();
        finding.category = category.to_string();
        finding.affectedness = Affectedness::ConfirmedAffected;
        finding.reachability = Reachability::PotentiallyReachable;
        finding.confidence = Confidence::High;
        finding.evidence_certainty = EvidenceCertainty::StronglySupported;
        let mut advisory_ids: Vec<String> = cwes.iter().map(|c| c.to_string()).collect();
        advisory_ids.push(rule_id.to_string());
        finding.advisory_ids = advisory_ids;
        finding.evidence_refs.push(EvidenceRef {
            location: format!("{}:{}", path.display(), line_no),
            line_number: Some(line_no),
            snippet: Some(snippet.trim().to_string()),
            sha256: None,
        });
        finding.compute_dedupe_fingerprint();
        findings.push(finding);
    }
}
