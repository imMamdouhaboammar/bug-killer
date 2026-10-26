use bug_killer::types::{self, Severity};
use std::path::Path;

#[path = "../src/scanner/mem_temp.rs"]
mod mem_temp;

use mem_temp::MemTempScanner;

// ============================================================================
// 1. BK-AI-MEM-001: Out-of-bounds read/write
// ============================================================================

#[test]
fn test_mem_001_oob_rust_unsafe_raw_ptr() {
    let vuln_code = r#"
pub unsafe fn read_offset(ptr: *const u8, idx: usize) -> u8 {
    *ptr.add(idx)
}
"#;
    let path = Path::new("src/ffi/raw_buffer.rs");
    let findings = MemTempScanner::scan_source(path, vuln_code);

    assert_eq!(findings.len(), 1);
    let f = &findings[0];
    assert_eq!(f.cve.as_str(), "BK-AI-MEM-001");
    assert_eq!(f.detector_id, "mem-temp");
    assert_eq!(f.severity, Severity::Critical);
    assert_eq!(f.category, "2.18 Native code, FFI and memory safety");
    assert!(f.advisory_ids.contains(&"CWE-125".to_string()));
    assert!(f.advisory_ids.contains(&"CWE-787".to_string()));
    assert!(f.advisory_ids.contains(&"BK-AI-MEM-001".to_string()));
    assert!(!f.dedupe_fingerprint.is_empty());

    let safe_code = r#"
pub unsafe fn read_offset_guarded(ptr: *const u8, idx: usize, len: usize) -> Option<u8> {
    if idx < len {
        Some(*ptr.add(idx))
    } else {
        None
    }
}
"#;
    let safe_findings = MemTempScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-MEM-001")
    );
}

#[test]
fn test_mem_001_oob_c_array_index() {
    let vuln_code = r#"
void set_element(int *arr, int idx, int val) {
    arr[idx] = val;
}
"#;
    let path = Path::new("native/buffer.c");
    let findings = MemTempScanner::scan_source(path, vuln_code);

    assert_eq!(findings.len(), 1);
    let f = &findings[0];
    assert_eq!(f.cve.as_str(), "BK-AI-MEM-001");
    assert_eq!(f.detector_id, "mem-temp");
    assert_eq!(f.severity, Severity::Critical);

    let safe_code = r#"
void set_element_safe(int *arr, int idx, int val, int max_len) {
    if (idx < max_len) {
        arr[idx] = val;
    }
}
"#;
    let safe_findings = MemTempScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-MEM-001")
    );
}

#[test]
fn test_mem_001_oob_slice_get_unchecked() {
    let vuln_code = r#"
pub unsafe fn read_fast(slice: &[u8], offset: usize) -> u8 {
    *slice.get_unchecked(offset)
}
"#;
    let path = Path::new("src/parser/slice.rs");
    let findings = MemTempScanner::scan_source(path, vuln_code);

    assert_eq!(findings.len(), 1);
    let f = &findings[0];
    assert_eq!(f.cve.as_str(), "BK-AI-MEM-001");

    let safe_code = r#"
pub fn read_safe(slice: &[u8], offset: usize) -> Option<u8> {
    slice.get(offset).copied()
}
"#;
    let safe_findings = MemTempScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-MEM-001")
    );
}

// ============================================================================
// 2. BK-AI-MEM-002: Use-after-free and double-free
// ============================================================================

#[test]
fn test_mem_002_double_free_c() {
    let vuln_code = r#"
void free_connection(char *conn_buf) {
    free(conn_buf);
    // Cleanup other resources
    free(conn_buf);
}
"#;
    let path = Path::new("native/net.c");
    let findings = MemTempScanner::scan_source(path, vuln_code);

    assert_eq!(findings.len(), 1);
    let f = &findings[0];
    assert_eq!(f.cve.as_str(), "BK-AI-MEM-002");
    assert_eq!(f.detector_id, "mem-temp");
    assert_eq!(f.severity, Severity::Critical);
    assert_eq!(f.category, "2.18 Native code, FFI and memory safety");
    assert!(f.advisory_ids.contains(&"CWE-416".to_string()));
    assert!(f.advisory_ids.contains(&"CWE-415".to_string()));

    let safe_code = r#"
void free_connection_safe(char *conn_buf) {
    free(conn_buf);
    conn_buf = NULL;
    free(conn_buf);
}
"#;
    let safe_findings = MemTempScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-MEM-002")
    );
}

#[test]
fn test_mem_002_use_after_free_c() {
    let vuln_code = r#"
void process_packet(char *packet) {
    free(packet);
    *packet = 0;
}
"#;
    let path = Path::new("native/packet.c");
    let findings = MemTempScanner::scan_source(path, vuln_code);

    assert_eq!(findings.len(), 1);
    let f = &findings[0];
    assert_eq!(f.cve.as_str(), "BK-AI-MEM-002");
    assert_eq!(f.severity, Severity::Critical);

    let safe_two_pointers = r#"
void free_two_buffers(char *buf_a, char *buf_b) {
    free(buf_a);
    free(buf_b);
}
"#;
    let safe_findings = MemTempScanner::scan_source(path, safe_two_pointers);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-MEM-002")
    );
}

#[test]
fn test_mem_002_inline_double_free() {
    let vuln_code = r#"
void cleanup_inline(char *ptr) {
    free(ptr); free(ptr);
}
"#;
    let path = Path::new("native/inline.c");
    let findings = MemTempScanner::scan_source(path, vuln_code);

    assert_eq!(findings.len(), 1);
    let f = &findings[0];
    assert_eq!(f.cve.as_str(), "BK-AI-MEM-002");
}

#[test]
fn test_mem_002_cpp_delete_uaf() {
    let vuln_code = r#"
void destroy_node(Node *node) {
    delete node;
    node->next = nullptr;
}
"#;
    let path = Path::new("cpp/tree.cpp");
    let findings = MemTempScanner::scan_source(path, vuln_code);

    assert_eq!(findings.len(), 1);
    let f = &findings[0];
    assert_eq!(f.cve.as_str(), "BK-AI-MEM-002");

    let safe_code = r#"
void destroy_node_raii(std::unique_ptr<Node> node) {
    // RAII destructor takes care of cleanup safely
}
"#;
    let safe_findings = MemTempScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-MEM-002")
    );
}

#[test]
fn test_mem_002_typescript_delete_property_not_flagged() {
    let js_code = r#"
export function cleanHeaders(headers: Record<string, string>) {
    delete headers['cookie'];
    delete headers['x-admin-secret'];
    return headers;
}
"#;
    let path = Path::new("lib/security/headers.ts");
    let findings = MemTempScanner::scan_source(path, js_code);
    assert!(
        findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-MEM-002"),
        "JavaScript / TypeScript delete operator on object properties must not be flagged as C/C++ memory double-free"
    );
}

// ============================================================================
// 3. BK-AI-MEM-003: Integer overflow in allocation
// ============================================================================

#[test]
fn test_mem_003_integer_overflow_malloc() {
    let vuln_code = r#"
void *alloc_matrix(size_t width, size_t height) {
    return malloc(width * height);
}
"#;
    let path = Path::new("native/image.c");
    let findings = MemTempScanner::scan_source(path, vuln_code);

    assert_eq!(findings.len(), 1);
    let f = &findings[0];
    assert_eq!(f.cve.as_str(), "BK-AI-MEM-003");
    assert_eq!(f.detector_id, "mem-temp");
    assert_eq!(f.severity, Severity::High);
    assert_eq!(f.category, "2.18 Native code, FFI and memory safety");
    assert!(f.advisory_ids.contains(&"CWE-190".to_string()));

    let safe_code_builtin = r#"
void *alloc_matrix_safe(size_t width, size_t height) {
    size_t total;
    if (__builtin_mul_overflow(width, height, &total)) {
        return NULL;
    }
    return malloc(total);
}
"#;
    let safe_findings = MemTempScanner::scan_source(path, safe_code_builtin);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-MEM-003")
    );

    let safe_code_calloc = r#"
void *alloc_matrix_calloc(size_t width, size_t height) {
    return calloc(width, height);
}
"#;
    let calloc_findings = MemTempScanner::scan_source(path, safe_code_calloc);
    assert!(
        calloc_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-MEM-003")
    );
}

#[test]
fn test_mem_003_integer_overflow_rust_vec() {
    let vuln_code = r#"
pub fn allocate_items(count: usize, item_size: usize) -> Vec<u8> {
    Vec::with_capacity(count * item_size)
}
"#;
    let path = Path::new("src/buffer.rs");
    let findings = MemTempScanner::scan_source(path, vuln_code);

    assert_eq!(findings.len(), 1);
    let f = &findings[0];
    assert_eq!(f.cve.as_str(), "BK-AI-MEM-003");

    let safe_code = r#"
pub fn allocate_items_safe(count: usize, item_size: usize) -> Option<Vec<u8>> {
    let total = count.checked_mul(item_size)?;
    Some(Vec::with_capacity(total))
}
"#;
    let safe_findings = MemTempScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-MEM-003")
    );
}

#[test]
fn test_mem_003_integer_overflow_node_buffer() {
    let vuln_code = r#"
function createBuffer(numElements, elementSize) {
    return Buffer.alloc(numElements * elementSize);
}
"#;
    let path = Path::new("src/allocator.js");
    let findings = MemTempScanner::scan_source(path, vuln_code);

    assert_eq!(findings.len(), 1);
    let f = &findings[0];
    assert_eq!(f.cve.as_str(), "BK-AI-MEM-003");

    let safe_code = r#"
function createBufferSafe(numElements, elementSize) {
    if (numElements > MAX_ALLOWED || elementSize > MAX_ALLOWED) {
        throw new Error("Size exceeds maximum limits");
    }
    return Buffer.alloc(numElements * elementSize);
}
"#;
    let safe_findings = MemTempScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-MEM-003")
    );
}

// ============================================================================
// 4. BK-AI-FIL-008: Predictable or insecure temporary file
// ============================================================================

#[test]
fn test_fil_008_python_mktemp_insecure() {
    let vuln_code = r#"
import tempfile

def write_scratch(data):
    filename = tempfile.mktemp()
    with open(filename, 'w') as f:
        f.write(data)
"#;
    let path = Path::new("scripts/scratch.py");
    let findings = MemTempScanner::scan_source(path, vuln_code);

    assert_eq!(findings.len(), 1);
    let f = &findings[0];
    assert_eq!(f.cve.as_str(), "BK-AI-FIL-008");
    assert_eq!(f.detector_id, "mem-temp");
    assert_eq!(f.severity, Severity::High);
    assert_eq!(
        f.category,
        "2.7 Filesystem, path traversal and archive extraction"
    );
    assert!(f.advisory_ids.contains(&"CWE-377".to_string()));

    let safe_code = r#"
import tempfile

def write_scratch_safe(data):
    with tempfile.NamedTemporaryFile(delete=True) as tmp:
        tmp.write(data)
"#;
    let safe_findings = MemTempScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-FIL-008")
    );
}

#[test]
fn test_fil_008_c_tmpnam_mktemp() {
    let vuln_code = r#"
void write_temp(const char *content) {
    char tpl[] = "/tmp/my_temp_XXXXXX";
    char *name = mktemp(tpl);
    FILE *f = fopen(name, "w");
}
"#;
    let path = Path::new("native/temp_util.c");
    let findings = MemTempScanner::scan_source(path, vuln_code);

    assert!(!findings.is_empty());
    let f = &findings[0];
    assert_eq!(f.cve.as_str(), "BK-AI-FIL-008");

    let safe_code = r#"
void write_temp_safe(const char *content) {
    char tpl[] = "/tmp/my_temp_XXXXXX";
    int fd = mkstemp(tpl);
}
"#;
    let safe_findings = MemTempScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-FIL-008")
    );
}

#[test]
fn test_fil_008_hardcoded_tmp_path() {
    let vuln_code = r#"
fn persist_session(data: &[u8]) {
    std::fs::write("/tmp/app_session.dat", data).unwrap();
}
"#;
    let path = Path::new("src/session.rs");
    let findings = MemTempScanner::scan_source(path, vuln_code);

    assert_eq!(findings.len(), 1);
    let f = &findings[0];
    assert_eq!(f.cve.as_str(), "BK-AI-FIL-008");

    let safe_code = r#"
fn persist_session_safe(data: &[u8]) {
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    std::io::Write::write_all(&mut tmp, data).unwrap();
}
"#;
    let safe_findings = MemTempScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-FIL-008")
    );
}

#[test]
fn test_fil_008_shell_hardcoded_tmp() {
    let vuln_code = r#"
#!/usr/bin/env bash
TMP_LOG="/tmp/deploy_debug.log"
echo "deploying" > "$TMP_LOG"
"#;
    let path = Path::new("scripts/deploy.sh");
    let findings = MemTempScanner::scan_source(path, vuln_code);

    assert_eq!(findings.len(), 1);
    let f = &findings[0];
    assert_eq!(f.cve.as_str(), "BK-AI-FIL-008");
}

#[test]
fn test_fil_008_python_os_tmpnam() {
    let vuln_code = r#"
import os

def create_tmp_file():
    path = os.tmpnam()
    return open(path, "w")
"#;
    let path = Path::new("scripts/tmp_gen.py");
    let findings = MemTempScanner::scan_source(path, vuln_code);

    assert_eq!(findings.len(), 1);
    let f = &findings[0];
    assert_eq!(f.cve.as_str(), "BK-AI-FIL-008");
}

// ============================================================================
// 5. Comment indicator tests for all 4 rules
// ============================================================================

#[test]
fn test_mem_temp_comment_indicators() {
    let content = r#"
// out-of-bounds read in unsafe block
// use-after-free detected in callback
// integer overflow in allocation size
// temporary file predictable path
"#;
    let path = Path::new("src/audit_comments.rs");
    let findings = MemTempScanner::scan_source(path, content);

    assert_eq!(findings.len(), 4);
    assert!(findings.iter().any(|f| f.cve.as_str() == "BK-AI-MEM-001"));
    assert!(findings.iter().any(|f| f.cve.as_str() == "BK-AI-MEM-002"));
    assert!(findings.iter().any(|f| f.cve.as_str() == "BK-AI-MEM-003"));
    assert!(findings.iter().any(|f| f.cve.as_str() == "BK-AI-FIL-008"));
}

// ============================================================================
// 6. Unsupported extensions ignored
// ============================================================================

#[test]
fn test_unsupported_extensions_ignored() {
    let content = r#"
char *p = mktemp(tpl);
"#;
    let path = Path::new("assets/image.png");
    let findings = MemTempScanner::scan_source(path, content);
    assert!(findings.is_empty());
}
