use bug_killer::types::{self, Severity};
use std::path::Path;

#[path = "../src/scanner/native_desktop.rs"]
mod native_desktop;

use native_desktop::NativeDesktopScanner;

// ============================================================================
// Category 18: Native Code, FFI and Memory Safety Tests
// ============================================================================

#[test]
fn test_mem_004_null_pointer_dereference() {
    let vuln_code = r#"
fn deref_raw(raw_ptr: *const i32) -> i32 {
    unsafe {
        *raw_ptr
    }
}
"#;
    let path = Path::new("src/ffi/pointer.rs");
    let findings = NativeDesktopScanner::scan_source(path, vuln_code);

    assert_eq!(findings.len(), 1);
    let f = &findings[0];
    assert_eq!(f.cve.as_str(), "BK-AI-MEM-004");
    assert_eq!(f.detector_id, "native-desktop");
    assert_eq!(f.severity, Severity::High);
    assert_eq!(f.category, "2.18 Native code, FFI and memory safety");

    let safe_code = r#"
fn deref_raw(raw_ptr: *const i32) -> Option<i32> {
    if raw_ptr.is_null() {
        return None;
    }
    unsafe { Some(*raw_ptr) }
}
"#;
    let safe_findings = NativeDesktopScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-MEM-004")
    );
}

#[test]
fn test_mem_005_buffer_copy_lacks_bounds() {
    let vuln_code = r#"
void copy_payload(char *dest, const char *src) {
    strcpy(dest, src);
}
"#;
    let path = Path::new("native/packet.c");
    let findings = NativeDesktopScanner::scan_source(path, vuln_code);

    assert_eq!(findings.len(), 1);
    let f = &findings[0];
    assert_eq!(f.cve.as_str(), "BK-AI-MEM-005");
    assert_eq!(f.detector_id, "native-desktop");
    assert_eq!(f.severity, Severity::Critical);
    assert_eq!(f.category, "2.18 Native code, FFI and memory safety");

    let safe_code = r#"
void copy_payload(char *dest, const char *src, size_t max_len) {
    strlcpy(dest, src, max_len);
}
"#;
    let safe_findings = NativeDesktopScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-MEM-005")
    );
}

#[test]
fn test_mem_006_unchecked_slice_pointer_conversion() {
    let vuln_code = r#"
pub unsafe fn decode_slice<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    std::slice::from_raw_parts(ptr, len)
}
"#;
    let path = Path::new("src/codec/slice.rs");
    let findings = NativeDesktopScanner::scan_source(path, vuln_code);

    assert_eq!(findings.len(), 1);
    let f = &findings[0];
    assert_eq!(f.cve.as_str(), "BK-AI-MEM-006");
    assert_eq!(f.detector_id, "native-desktop");
    assert_eq!(f.severity, Severity::High);

    let safe_code = r#"
pub unsafe fn decode_slice<'a>(ptr: *const u8, len: usize) -> Option<&'a [u8]> {
    assert!(len <= 4096);
    Some(std::slice::from_raw_parts(ptr, len))
}
"#;
    let safe_findings = NativeDesktopScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-MEM-006")
    );
}

#[test]
fn test_mem_007_strncpy_truncation_without_null() {
    let vuln_code = r#"
void process_tag(char *dest, const char *src) {
    strncpy(dest, src, sizeof(dest));
}
"#;
    let path = Path::new("src/native/string_utils.c");
    let findings = NativeDesktopScanner::scan_source(path, vuln_code);

    assert_eq!(findings.len(), 1);
    let f = &findings[0];
    assert_eq!(f.cve.as_str(), "BK-AI-MEM-007");
    assert_eq!(f.detector_id, "native-desktop");
    assert_eq!(f.severity, Severity::High);

    let safe_code = r#"
void process_tag(char *dest, const char *src) {
    strncpy(dest, src, sizeof(dest));
    dest[sizeof(dest) - 1] = '\0';
}
"#;
    let safe_findings = NativeDesktopScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-MEM-007")
    );
}

#[test]
fn test_mem_008_untrusted_native_decoder_privileged() {
    let vuln_code = r#"
void load_dynamic_plugin(const char *userPluginPath) {
    void *h = dlopen(userPluginPath, RTLD_NOW);
}
"#;
    let path = Path::new("services/loader.c");
    let findings = NativeDesktopScanner::scan_source(path, vuln_code);

    assert_eq!(findings.len(), 1);
    let f = &findings[0];
    assert_eq!(f.cve.as_str(), "BK-AI-MEM-008");
    assert_eq!(f.detector_id, "native-desktop");
    assert_eq!(f.severity, Severity::Critical);

    let safe_code = r#"
void load_dynamic_plugin(const char *userPluginPath) {
    if (!verify_signature(userPluginPath)) {
        return;
    }
    void *h = dlopen(userPluginPath, RTLD_NOW);
}
"#;
    let safe_findings = NativeDesktopScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-MEM-008")
    );
}

#[test]
fn test_mem_009_panic_crosses_ffi_boundary() {
    let vuln_code = r#"
#[no_mangle]
pub extern "C" fn ffi_calculate(val: i32) -> i32 {
    if val < 0 {
        panic!("negative input not allowed");
    }
    val * 2
}
"#;
    let path = Path::new("src/ffi/exports.rs");
    let findings = NativeDesktopScanner::scan_source(path, vuln_code);

    assert_eq!(findings.len(), 1);
    let f = &findings[0];
    assert_eq!(f.cve.as_str(), "BK-AI-MEM-009");
    assert_eq!(f.detector_id, "native-desktop");
    assert_eq!(f.severity, Severity::High);

    let safe_code = r#"
#[no_mangle]
pub extern "C" fn ffi_calculate(val: i32) -> i32 {
    std::panic::catch_unwind(|| {
        if val < 0 {
            return -1;
        }
        val * 2
    }).unwrap_or(-1)
}
"#;
    let safe_findings = NativeDesktopScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-MEM-009")
    );
}

#[test]
fn test_mem_010_compiler_hardening_flags_removed() {
    let vuln_code = r#"
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-stack-protector -z execstack")
"#;
    let path = Path::new("CMakeLists.txt");
    let findings = NativeDesktopScanner::scan_source(path, vuln_code);

    assert_eq!(findings.len(), 1);
    let f = &findings[0];
    assert_eq!(f.cve.as_str(), "BK-AI-MEM-010");
    assert_eq!(f.detector_id, "native-desktop");
    assert_eq!(f.severity, Severity::High);

    let safe_code = r#"
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fstack-protector-strong -z noexecstack")
"#;
    let safe_findings = NativeDesktopScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-MEM-010")
    );
}

#[test]
fn test_mem_011_allocator_mismatch_unzeroed_secret() {
    let vuln_code = r#"
void clear_credentials(char *secret_key) {
    free(secret_key);
}
"#;
    let path = Path::new("native/auth.c");
    let findings = NativeDesktopScanner::scan_source(path, vuln_code);

    assert_eq!(findings.len(), 1);
    let f = &findings[0];
    assert_eq!(f.cve.as_str(), "BK-AI-MEM-011");
    assert_eq!(f.detector_id, "native-desktop");
    assert_eq!(f.severity, Severity::High);

    let safe_code = r#"
void clear_credentials(char *secret_key, size_t key_len) {
    explicit_bzero(secret_key, key_len);
    free(secret_key);
}
"#;
    let safe_findings = NativeDesktopScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-MEM-011")
    );
}

#[test]
fn test_mem_012_binary_parser_untrusted_length() {
    let vuln_code = r#"
fn parse_payload(reader: &mut PacketReader) -> Vec<u8> {
    let payload_len = reader.read_u32();
    let mut buf = vec![0u8; payload_len as usize];
    buf
}
"#;
    let path = Path::new("src/parser/binary.rs");
    let findings = NativeDesktopScanner::scan_source(path, vuln_code);

    assert_eq!(findings.len(), 1);
    let f = &findings[0];
    assert_eq!(f.cve.as_str(), "BK-AI-MEM-012");
    assert_eq!(f.detector_id, "native-desktop");
    assert_eq!(f.severity, Severity::High);

    let safe_code = r#"
fn parse_payload(reader: &mut PacketReader) -> Result<Vec<u8>, Error> {
    let payload_len = reader.read_u32();
    if payload_len > MAX_ALLOWED {
        return Err(Error::ExcessiveLength);
    }
    let mut buf = vec![0u8; payload_len as usize];
    Ok(buf)
}
"#;
    let safe_findings = NativeDesktopScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-MEM-012")
    );
}

// ============================================================================
// Category 25: Mobile, Desktop, Electron and Local Apps Tests
// ============================================================================

#[test]
fn test_mob_001_client_bundle_cloud_api_keys() {
    let vuln_code = r#"
const mobileConfig = {
    FIREBASE_ADMIN_KEY: "dummy_admin_key_placeholder_not_real_key",
};
"#;
    let path = Path::new("mobile/config.js");
    let findings = NativeDesktopScanner::scan_source(path, vuln_code);

    assert_eq!(findings.len(), 1);
    let f = &findings[0];
    assert_eq!(f.cve.as_str(), "BK-AI-MOB-001");
    assert_eq!(f.detector_id, "native-desktop");
    assert_eq!(f.severity, Severity::Critical);
    assert_eq!(f.category, "2.25 Mobile, desktop, electron and local apps");

    let safe_code = r#"
const mobileConfig = {
    apiKey: process.env.PUBLIC_CLIENT_KEY,
};
"#;
    let safe_findings = NativeDesktopScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-MOB-001")
    );
}

#[test]
fn test_mob_002_plaintext_token_preferences() {
    let vuln_code = r#"
func saveAuth(token: String) {
    UserDefaults.standard.set(token, forKey: "user_auth_token")
}
"#;
    let path = Path::new("iOS/AuthManager.swift");
    let findings = NativeDesktopScanner::scan_source(path, vuln_code);

    assert_eq!(findings.len(), 1);
    let f = &findings[0];
    assert_eq!(f.cve.as_str(), "BK-AI-MOB-002");
    assert_eq!(f.detector_id, "native-desktop");
    assert_eq!(f.severity, Severity::High);

    let safe_code = r#"
func saveAuth(token: String) {
    Keychain.standard.save(token, forKey: "user_auth_token")
}
"#;
    let safe_findings = NativeDesktopScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-MOB-002")
    );
}

#[test]
fn test_mob_003_android_exported_without_permission() {
    let vuln_code = r#"
<activity android:name=".PreviewActivity" android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.VIEW" />
    </intent-filter>
</activity>
"#;
    let path = Path::new("android/AndroidManifest.xml");
    let findings = NativeDesktopScanner::scan_source(path, vuln_code);

    assert_eq!(findings.len(), 1);
    let f = &findings[0];
    assert_eq!(f.cve.as_str(), "BK-AI-MOB-003");
    assert_eq!(f.detector_id, "native-desktop");
    assert_eq!(f.severity, Severity::High);

    let safe_code = r#"
<activity android:name=".PreviewActivity" android:exported="true" android:permission="com.example.app.PREVIEW">
    <intent-filter>
        <action android:name="android.intent.action.VIEW" />
    </intent-filter>
</activity>
"#;
    let safe_findings = NativeDesktopScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-MOB-003")
    );
}

#[test]
fn test_mob_004_deep_link_unsafe_url_command() {
    let vuln_code = r#"
app.setAsDefaultProtocolClient('myapp');
app.on('open-url', (event, url) => {
    shell.openExternal(url);
});
"#;
    let path = Path::new("electron/main.js");
    let findings = NativeDesktopScanner::scan_source(path, vuln_code);

    assert!(findings.iter().any(|f| f.cve.as_str() == "BK-AI-MOB-004"));
    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-MOB-004")
        .unwrap();
    assert_eq!(f.detector_id, "native-desktop");
    assert_eq!(f.severity, Severity::High);

    let safe_code = r#"
app.setAsDefaultProtocolClient('myapp');
app.on('open-url', (event, url) => {
    if (isValidUrl(url) && allowed_hosts.includes(new URL(url).hostname)) {
        shell.openExternal(url);
    }
});
"#;
    let safe_findings = NativeDesktopScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-MOB-004")
    );
}

#[test]
fn test_mob_005_electron_node_integration_unsafe_isolation() {
    let vuln_code = r#"
const mainWindow = new BrowserWindow({
    webPreferences: {
        nodeIntegration: true,
        contextIsolation: false
    }
});
"#;
    let path = Path::new("electron/window.js");
    let findings = NativeDesktopScanner::scan_source(path, vuln_code);

    assert_eq!(findings.len(), 2);
    assert!(findings.iter().all(|f| f.cve.as_str() == "BK-AI-MOB-005"));
    assert_eq!(findings[0].detector_id, "native-desktop");
    assert_eq!(findings[0].severity, Severity::Critical);

    let safe_code = r#"
const mainWindow = new BrowserWindow({
    webPreferences: {
        nodeIntegration: false,
        contextIsolation: true
    }
});
"#;
    let safe_findings = NativeDesktopScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-MOB-005")
    );
}

#[test]
fn test_mob_006_electron_ipc_blindly_executes_command() {
    let vuln_code = r#"
ipcMain.on('execute', (_, cmd) => {
    exec(cmd);
});
"#;
    let path = Path::new("electron/ipc.js");
    let findings = NativeDesktopScanner::scan_source(path, vuln_code);

    assert_eq!(findings.len(), 1);
    let f = &findings[0];
    assert_eq!(f.cve.as_str(), "BK-AI-MOB-006");
    assert_eq!(f.detector_id, "native-desktop");
    assert_eq!(f.severity, Severity::Critical);

    let safe_code = r#"
ipcMain.on('execute', (_, cmd) => {
    if (allowedCommands.includes(cmd)) {
        exec(cmd);
    }
});
"#;
    let safe_findings = NativeDesktopScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-MOB-006")
    );
}

#[test]
fn test_mob_007_tls_trust_all_certs_insecure() {
    let vuln_code = r#"
const agent = new https.Agent({
    rejectUnauthorized: false
});
"#;
    let path = Path::new("mobile/network.js");
    let findings = NativeDesktopScanner::scan_source(path, vuln_code);

    assert_eq!(findings.len(), 1);
    let f = &findings[0];
    assert_eq!(f.cve.as_str(), "BK-AI-MOB-007");
    assert_eq!(f.detector_id, "native-desktop");
    assert_eq!(f.severity, Severity::Critical);

    let safe_code = r#"
const agent = new https.Agent({
    rejectUnauthorized: true
});
"#;
    let safe_findings = NativeDesktopScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-MOB-007")
    );
}

#[test]
fn test_mob_008_world_accessible_local_files() {
    let vuln_code = r#"
function initStorage(databasePath) {
    fs.chmodSync(databasePath, 0o777);
}
"#;
    let path = Path::new("desktop/storage.js");
    let findings = NativeDesktopScanner::scan_source(path, vuln_code);

    assert_eq!(findings.len(), 1);
    let f = &findings[0];
    assert_eq!(f.cve.as_str(), "BK-AI-MOB-008");
    assert_eq!(f.detector_id, "native-desktop");
    assert_eq!(f.severity, Severity::High);

    let safe_code = r#"
function initStorage(databasePath) {
    fs.chmodSync(databasePath, 0o600);
}
"#;
    let safe_findings = NativeDesktopScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-MOB-008")
    );
}

#[test]
fn test_mob_009_untrusted_app_updates_without_signature() {
    let vuln_code = r#"
function setupUpdates() {
    autoUpdater.setFeedURL({
        url: "http://updates.internal.com/app/releases"
    });
}
"#;
    let path = Path::new("electron/updater.js");
    let findings = NativeDesktopScanner::scan_source(path, vuln_code);

    assert_eq!(findings.len(), 1);
    let f = &findings[0];
    assert_eq!(f.cve.as_str(), "BK-AI-MOB-009");
    assert_eq!(f.detector_id, "native-desktop");
    assert_eq!(f.severity, Severity::Critical);

    let safe_code = r#"
function setupUpdates() {
    autoUpdater.setFeedURL({
        url: "https://updates.internal.com/app/releases"
    });
}
"#;
    let safe_findings = NativeDesktopScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-MOB-009")
    );
}

#[test]
fn test_mob_010_clipboard_notifications_expose_secret() {
    let vuln_code = r#"
function copySessionSecret(secretToken) {
    Clipboard.setString(secretToken);
}
"#;
    let path = Path::new("mobile/views/profile.js");
    let findings = NativeDesktopScanner::scan_source(path, vuln_code);

    assert_eq!(findings.len(), 1);
    let f = &findings[0];
    assert_eq!(f.cve.as_str(), "BK-AI-MOB-010");
    assert_eq!(f.detector_id, "native-desktop");
    assert_eq!(f.severity, Severity::High);

    let safe_code = r#"
function copySessionSecret(secretToken) {
    if (FLAG_SECURE) {
        Clipboard.setString(maskSecret(secretToken));
    }
}
"#;
    let safe_findings = NativeDesktopScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-MOB-010")
    );
}

// ============================================================================
// Category 21: AI Coding Assistant-Specific Traps Tests
// ============================================================================

#[test]
fn test_aic_004_tests_rewritten_weakened() {
    let vuln_code = r#"
def test_user_authentication():
    # Test was failing due to database disconnect
    assert True
"#;
    let path = Path::new("tests/test_auth.py");
    let findings = NativeDesktopScanner::scan_source(path, vuln_code);

    assert_eq!(findings.len(), 1);
    let f = &findings[0];
    assert_eq!(f.cve.as_str(), "BK-AI-AIC-004");
    assert_eq!(f.detector_id, "native-desktop");
    assert_eq!(f.severity, Severity::High);
    assert_eq!(
        f.category,
        "2.21 AI coding assistant-specific engineering traps"
    );

    let safe_code = r#"
def test_user_authentication():
    res = auth_client.login("user", "pass")
    assert res.status_code == 200
    assert res.token in active_sessions
"#;
    let safe_findings = NativeDesktopScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-AIC-004")
    );
}

// ============================================================================
// Category 22: LLM, RAG, Autonomous Agent and MCP Application Flaws Tests
// ============================================================================

#[test]
fn test_llm_019_agent_chain_unchecked_proposal() {
    let vuln_code = r#"
def run_agent_chain(planner, executor):
    proposal = planner.get_output()
    executor.execute(proposal)
"#;
    let path = Path::new("agent/orchestrator.py");
    let findings = NativeDesktopScanner::scan_source(path, vuln_code);

    assert_eq!(findings.len(), 1);
    let f = &findings[0];
    assert_eq!(f.cve.as_str(), "BK-AI-LLM-019");
    assert_eq!(f.detector_id, "native-desktop");
    assert_eq!(f.severity, Severity::High);
    assert_eq!(
        f.category,
        "2.22 LLM, RAG, autonomous agent and MCP application flaws"
    );

    let safe_code = r#"
def run_agent_chain(planner, executor):
    proposal = planner.get_output()
    if require_human_confirmation(proposal) and policy_gate(proposal):
        executor.execute(proposal)
"#;
    let safe_findings = NativeDesktopScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-LLM-019")
    );
}

#[test]
fn test_llm_021_agent_loop_lacks_cancellation() {
    let vuln_code = r#"
async def run_autonomous_loop(agent):
    while True:
        await agent.step()
"#;
    let path = Path::new("agent/loop.py");
    let findings = NativeDesktopScanner::scan_source(path, vuln_code);

    assert_eq!(findings.len(), 1);
    let f = &findings[0];
    assert_eq!(f.cve.as_str(), "BK-AI-LLM-021");
    assert_eq!(f.detector_id, "native-desktop");
    assert_eq!(f.severity, Severity::High);
    assert_eq!(
        f.category,
        "2.22 LLM, RAG, autonomous agent and MCP application flaws"
    );

    let safe_code = r#"
async def run_autonomous_loop(agent, abort_signal):
    while True:
        if abort_signal.is_aborted():
            break
        await agent.step()
"#;
    let safe_findings = NativeDesktopScanner::scan_source(path, safe_code);
    assert!(
        safe_findings
            .iter()
            .all(|f| f.cve.as_str() != "BK-AI-LLM-021")
    );
}

// ============================================================================
// Comment Indicator Tests
// ============================================================================

#[test]
fn test_native_desktop_comment_indicators() {
    let comments_code = r#"
// null pointer dereference in legacy decoder
// buffer copy lacks verified bounds in packet handler
// unchecked slice/pointer conversion from raw buffer
// strncpy without explicit null termination
// untrusted native decoder loaded in root service
// panic crosses foreign function boundary in ffi
// compiler/hardening flags removed to fix build
// allocator mismatch leaks secret-bearing memory
// binary parser trusts declared length header
// client bundle contains cloud key for admin
// sensitive token stored in plaintext preferences
// android exported without permission
// deep-link accepts unsafe external command
// electron renderer has node integration enabled
// electron ipc main blindly executes renderer command
// trust all certificates in mobile client
// local database contain private content accessible to all
// untrusted app updates without signature verification
// clipboard expose secret values
// tests are rewritten/weakened after failure
// agent chain allows one agent's unchecked proposal
// agent continues acting after revocation without stop check
"#;
    let path = Path::new("comments_audit.rs");
    let findings = NativeDesktopScanner::scan_source(path, comments_code);

    assert_eq!(findings.len(), 22);

    let rules = [
        "BK-AI-MEM-004",
        "BK-AI-MEM-005",
        "BK-AI-MEM-006",
        "BK-AI-MEM-007",
        "BK-AI-MEM-008",
        "BK-AI-MEM-009",
        "BK-AI-MEM-010",
        "BK-AI-MEM-011",
        "BK-AI-MEM-012",
        "BK-AI-MOB-001",
        "BK-AI-MOB-002",
        "BK-AI-MOB-003",
        "BK-AI-MOB-004",
        "BK-AI-MOB-005",
        "BK-AI-MOB-006",
        "BK-AI-MOB-007",
        "BK-AI-MOB-008",
        "BK-AI-MOB-009",
        "BK-AI-MOB-010",
        "BK-AI-AIC-004",
        "BK-AI-LLM-019",
        "BK-AI-LLM-021",
    ];

    for rule in rules {
        assert!(
            findings.iter().any(|f| f.cve.as_str() == rule),
            "Expected finding for rule {}",
            rule
        );
    }
}
