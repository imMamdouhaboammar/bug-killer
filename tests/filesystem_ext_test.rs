#![allow(clippy::collapsible_if)]

pub use bug_killer::types;
use bug_killer::types::*;
use std::path::Path;

#[path = "../src/scanner/filesystem_ext.rs"]
mod filesystem_ext;

use filesystem_ext::FilesystemExtScanner;

// ============================================================================
// Category 7: Filesystem, Uploads, Archives and Path Traversal
// ============================================================================

// 1. BK-AI-FIL-003: Zip Slip
#[test]
fn test_fil_003_zip_slip_vulnerable_and_safe() {
    let vuln_snippet = r#"
        zip.getEntries().forEach(entry => {
            const destPath = path.join('/tmp/extracted', entry.entryName);
            fs.writeFileSync(destPath, entry.getData());
        });
        tarfile.extractall('/var/data');
    "#;
    let path = Path::new("src/services/unpacker.js");
    let findings = FilesystemExtScanner::scan_source(path, vuln_snippet);

    assert_eq!(findings.len(), 2, "Expected 2 findings for Zip Slip");
    assert!(findings.iter().all(|f| f.cve.as_str() == "BK-AI-FIL-003"));
    assert!(findings.iter().all(|f| f.severity == Severity::Critical));
    assert!(findings.iter().all(|f| f.detector_id == "filesystem-ext"));
    assert!(findings.iter().all(|f| f.category == "2.7 Filesystem, uploads, archives and path traversal"));

    let safe_snippet = r#"
        zip.getEntries().forEach(entry => {
            const targetPath = path.resolve(destDir, entry.entryName);
            if (!targetPath.startsWith(destDir)) {
                throw new Error('Path traversal attempt detected');
            }
            fs.writeFileSync(targetPath, entry.getData());
        });
        tarfile.extractall('/var/data', filter='data');
    "#;
    let safe_findings = FilesystemExtScanner::scan_source(path, safe_snippet);
    assert!(safe_findings.is_empty(), "Safe archive extraction must not trigger finding");
}

// 2. BK-AI-FIL-004: Unsafe Archive Decompression / Zip Bomb
#[test]
fn test_fil_004_zip_bomb_vulnerable_and_safe() {
    let vuln_snippet = r#"
        const decompressStream = (req, res) => {
            req.pipe(zlib.createGunzip()).pipe(fs.createWriteStream('/tmp/output'));
            const decompressed = zlib.gunzipSync(req.body);
        };
    "#;
    let path = Path::new("src/routes/decompress.js");
    let findings = FilesystemExtScanner::scan_source(path, vuln_snippet);

    assert_eq!(findings.len(), 2, "Expected 2 findings for unconstrained decompression");
    assert!(findings.iter().all(|f| f.cve.as_str() == "BK-AI-FIL-004"));
    assert!(findings.iter().all(|f| f.severity == Severity::High));

    let safe_snippet = r#"
        const safeDecompress = (req, res) => {
            const MAX_SIZE = 10 * 1024 * 1024;
            const sizeLimit = new ByteLimiter({ maxSize: MAX_SIZE });
            req.pipe(sizeLimit).pipe(zlib.createGunzip()).pipe(dest);
        };
    "#;
    let safe_findings = FilesystemExtScanner::scan_source(path, safe_snippet);
    assert!(safe_findings.is_empty(), "Size-bounded decompression must not trigger finding");
}

// 3. BK-AI-FIL-005: Uploaded File Extension Trusted
#[test]
fn test_fil_005_extension_trusted_vulnerable_and_safe() {
    let vuln_snippet = r#"
        function validateUpload(file) {
            const ext = file.originalname.split('.').pop();
            if (ALLOWED_EXTENSIONS.includes(ext)) {
                return true;
            }
            const mimeType = mime.lookup(file.originalname);
            return mimeType === 'image/jpeg';
        }
    "#;
    let path = Path::new("src/upload/validator.js");
    let findings = FilesystemExtScanner::scan_source(path, vuln_snippet);

    assert!(!findings.is_empty(), "Expected finding for trusting uploaded extension");
    assert_eq!(findings[0].cve.as_str(), "BK-AI-FIL-005");
    assert_eq!(findings[0].advisory_ids, vec!["CWE-434", "BK-AI-FIL-005"]);

    let safe_snippet = r#"
        import { fileTypeFromBuffer } from 'file-type';
        async function validateUpload(file) {
            const type = await fileTypeFromBuffer(file.buffer);
            if (!type || !['image/png', 'image/jpeg'].includes(type.mime)) {
                throw new Error('Invalid file signature');
            }
        }
    "#;
    let safe_findings = FilesystemExtScanner::scan_source(path, safe_snippet);
    assert!(safe_findings.is_empty(), "Magic byte inspection must not trigger finding");
}

// 4. BK-AI-FIL-006: User Upload Stored in Executable/Public Directory or 0777
#[test]
fn test_fil_006_public_upload_vulnerable_and_safe() {
    let vuln_snippet = r#"
        const storage = multer.diskStorage({
            destination: './public/uploads',
            filename: (req, file, cb) => cb(null, file.originalname)
        });
        fs.chmodSync(uploadedPath, 0o777);
    "#;
    let path = Path::new("src/config/multer.js");
    let findings = FilesystemExtScanner::scan_source(path, vuln_snippet);

    assert_eq!(findings.len(), 2, "Expected 2 findings for public destination and 0777 permissions");
    assert!(findings.iter().all(|f| f.cve.as_str() == "BK-AI-FIL-006"));

    let safe_snippet = r#"
        const storage = multer.diskStorage({
            destination: '/var/app/storage/private_uploads',
            filename: (req, file, cb) => cb(null, crypto.randomUUID())
        });
        fs.chmodSync(uploadedPath, 0o600);
    "#;
    let safe_findings = FilesystemExtScanner::scan_source(path, safe_snippet);
    assert!(safe_findings.is_empty(), "Private non-executable storage must not trigger finding");
}

// 5. BK-AI-FIL-007: Filename Allows Path Separators / Control Characters
#[test]
fn test_fil_007_raw_filename_traversal_vulnerable_and_safe() {
    let vuln_snippet = r#"
        const saveAvatar = (req, res) => {
            const filePath = path.join(UPLOAD_DIR, req.body.filename);
            fs.writeFileSync(filePath, req.body.data);
        };
    "#;
    let path = Path::new("src/controllers/avatar.js");
    let findings = FilesystemExtScanner::scan_source(path, vuln_snippet);

    assert!(!findings.is_empty(), "Expected finding for unvalidated filename in path.join");
    assert_eq!(findings[0].cve.as_str(), "BK-AI-FIL-007");

    let safe_snippet = r#"
        const saveAvatar = (req, res) => {
            const safeName = path.basename(req.body.filename);
            const filePath = path.join(UPLOAD_DIR, safeName);
            fs.writeFileSync(filePath, req.body.data);
        };
    "#;
    let safe_findings = FilesystemExtScanner::scan_source(path, safe_snippet);
    assert!(safe_findings.is_empty(), "path.basename sanitization must not trigger finding");
}

// 6. BK-AI-FIL-009: Insecure Temporary/Backup Files
#[test]
fn test_fil_009_insecure_temp_backup_vulnerable_and_safe() {
    let vuln_snippet = r#"
        import tempfile
        tmp_name = tempfile.mktemp()
        backup_path = "/tmp/backup.key"
        with open("/tmp/secret.json", "w") as f:
            f.write(secret_data)
    "#;
    let path = Path::new("scripts/backup_helper.py");
    let findings = FilesystemExtScanner::scan_source(path, vuln_snippet);

    assert_eq!(findings.len(), 3, "Expected 3 findings for mktemp, /tmp/backup.key and /tmp/secret.json");
    assert!(findings.iter().all(|f| f.cve.as_str() == "BK-AI-FIL-009"));

    let safe_snippet = r#"
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", delete=True) as tmp:
            tmp.write(secret_data)
    "#;
    let safe_findings = FilesystemExtScanner::scan_source(path, safe_snippet);
    assert!(safe_findings.is_empty(), "NamedTemporaryFile must not trigger finding");
}

// 7. BK-AI-FIL-010: Unsafe File Overwrite or Deletion
#[test]
fn test_fil_010_unsafe_unlink_vulnerable_and_safe() {
    let vuln_snippet = r#"
        app.post('/api/file/delete', (req, res) => {
            fs.unlinkSync(req.query.path);
            res.send('File deleted');
        });
    "#;
    let path = Path::new("src/routes/files.js");
    let findings = FilesystemExtScanner::scan_source(path, vuln_snippet);

    assert_eq!(findings.len(), 1, "Expected finding for unconstrained unlinkSync");
    assert_eq!(findings[0].cve.as_str(), "BK-AI-FIL-010");

    let safe_snippet = r#"
        app.post('/api/file/delete', (req, res) => {
            const safePath = path.resolve(BASE_DIR, path.basename(req.query.path));
            if (!isPathInside(safePath, BASE_DIR)) {
                return res.status(403).send('Forbidden');
            }
            fs.unlinkSync(safePath);
        });
    "#;
    let safe_findings = FilesystemExtScanner::scan_source(path, safe_snippet);
    assert!(safe_findings.is_empty(), "Guarded path deletion must not trigger finding");
}

// 8. BK-AI-FIL-011: TOCTOU Between File Validation and Opening
#[test]
fn test_fil_011_toctou_vulnerable_and_safe() {
    let vuln_snippet = r#"
        function updateConfigFile(configPath, data) {
            if (fs.existsSync(configPath)) {
                fs.writeFileSync(configPath, data);
            }
        }
    "#;
    let path = Path::new("src/utils/config.js");
    let findings = FilesystemExtScanner::scan_source(path, vuln_snippet);

    assert_eq!(findings.len(), 1, "Expected finding for TOCTOU existsSync -> writeFileSync");
    assert_eq!(findings[0].cve.as_str(), "BK-AI-FIL-011");
    assert_eq!(findings[0].severity, Severity::Medium);

    let safe_snippet = r#"
        function updateConfigFile(configPath, data) {
            const fd = fs.openSync(configPath, 'wx');
            fs.writeSync(fd, data);
            fs.closeSync(fd);
        }
    "#;
    let safe_findings = FilesystemExtScanner::scan_source(path, safe_snippet);
    assert!(safe_findings.is_empty(), "Atomic open with 'wx' must not trigger finding");
}

// 9. BK-AI-FIL-012: Files Served/Downloaded Without Authorization Check
#[test]
fn test_fil_012_unauth_file_download_vulnerable_and_safe() {
    let vuln_snippet = r#"
        router.get('/download/:id', (req, res) => {
            res.download(path.join(FILE_STORE, req.params.id));
        });
    "#;
    let path = Path::new("src/routes/download.js");
    let findings = FilesystemExtScanner::scan_source(path, vuln_snippet);

    assert!(!findings.is_empty(), "Expected finding for unauthenticated file download");
    assert_eq!(findings[0].cve.as_str(), "BK-AI-FIL-012");

    let safe_snippet = r#"
        router.get('/download/:id', requireAuth, async (req, res) => {
            const file = await db.files.findById(req.params.id);
            if (!file || file.ownerId !== req.user.id) {
                return res.status(403).send('Forbidden');
            }
            res.download(file.storagePath);
        });
    "#;
    let safe_findings = FilesystemExtScanner::scan_source(path, safe_snippet);
    assert!(safe_findings.is_empty(), "Authorized download route must not trigger finding");
}

// 10. BK-AI-FIL-013: Uploaded SVG/HTML Rendered Inline Without Attachment or CSP
#[test]
fn test_fil_013_inline_svg_vulnerable_and_safe() {
    let vuln_snippet = r#"
        app.get('/avatar.svg', (req, res) => {
            res.setHeader('Content-Type', 'image/svg+xml');
            res.send(userUploadedSvg);
        });
    "#;
    let path = Path::new("src/routes/avatar.js");
    let findings = FilesystemExtScanner::scan_source(path, vuln_snippet);

    assert_eq!(findings.len(), 1, "Expected finding for inline SVG header");
    assert_eq!(findings[0].cve.as_str(), "BK-AI-FIL-013");

    let safe_snippet = r#"
        app.get('/avatar.svg', (req, res) => {
            res.setHeader('Content-Type', 'image/svg+xml');
            res.setHeader('Content-Disposition', 'attachment; filename="avatar.svg"');
            res.setHeader('Content-Security-Policy', "default-src 'none'");
            res.send(userUploadedSvg);
        });
    "#;
    let safe_findings = FilesystemExtScanner::scan_source(path, safe_snippet);
    assert!(safe_findings.is_empty(), "Attachment disposition must not trigger finding");
}

// 11. BK-AI-FIL-014: File Parser Accepts Unbounded Content / Recursive Structure
#[test]
fn test_fil_014_unbounded_parser_vulnerable_and_safe() {
    let vuln_snippet = r#"
        const parser = new xml2js.Parser({ noent: true });
        xml.etree.ElementTree.parse(userXmlFile);
    "#;
    let path = Path::new("src/parsers/xml.js");
    let findings = FilesystemExtScanner::scan_source(path, vuln_snippet);

    assert_eq!(findings.len(), 2, "Expected 2 findings for unbounded XML parsers");
    assert!(findings.iter().all(|f| f.cve.as_str() == "BK-AI-FIL-014"));

    let safe_snippet = r#"
        import defusedxml.ElementTree as ET
        ET.parse(userXmlFile)
    "#;
    let safe_findings = FilesystemExtScanner::scan_source(path, safe_snippet);
    assert!(safe_findings.is_empty(), "defusedxml usage must not trigger finding");
}

// ============================================================================
// Category 1: Injection and Interpreter Boundaries
// ============================================================================

// 12. BK-AI-INJ-002: Dynamic SQL Identifiers, Ordering Without Allowlist
#[test]
fn test_inj_002_dynamic_sql_identifiers_vulnerable_and_safe() {
    let vuln_snippet = r#"
        async function getUsers(req, res) {
            const query = `SELECT * FROM users ORDER BY ${req.query.sort}`;
            return db.raw(query);
        }
        knex('accounts').orderBy(req.query.sortCol);
    "#;
    let path = Path::new("src/db/users.js");
    let findings = FilesystemExtScanner::scan_source(path, vuln_snippet);

    assert_eq!(findings.len(), 2, "Expected 2 findings for dynamic SQL ORDER BY");
    assert!(findings.iter().all(|f| f.cve.as_str() == "BK-AI-INJ-002"));
    assert!(findings.iter().all(|f| f.category == "2.1 Injection and interpreter boundaries"));

    let safe_snippet = r#"
        async function getUsers(req, res) {
            const ALLOWED_COLUMNS = ['id', 'username', 'created_at'];
            if (!ALLOWED_COLUMNS.includes(req.query.sort)) {
                throw new Error('Invalid sort column');
            }
            return db('users').orderBy(req.query.sort);
        }
    "#;
    let safe_findings = FilesystemExtScanner::scan_source(path, safe_snippet);
    assert!(safe_findings.is_empty(), "Allowlisted columns must not trigger finding");
}

// 13. BK-AI-INJ-004: Command-Line Argument Injection in Subprocess Array
#[test]
fn test_inj_004_subprocess_arg_injection_vulnerable_and_safe() {
    let vuln_snippet = r#"
        execFile('git', ['checkout', req.query.branch], callback);
        subprocess.run(['git', 'log', user_branch])
    "#;
    let path = Path::new("src/vcs/git_service.js");
    let findings = FilesystemExtScanner::scan_source(path, vuln_snippet);

    assert_eq!(findings.len(), 2, "Expected 2 findings for subprocess argument injection");
    assert!(findings.iter().all(|f| f.cve.as_str() == "BK-AI-INJ-004"));

    let safe_snippet = r#"
        execFile('git', ['checkout', '--', req.query.branch], callback);
        subprocess.run(['git', 'log', '--', user_branch])
    "#;
    let safe_findings = FilesystemExtScanner::scan_source(path, safe_snippet);
    assert!(safe_findings.is_empty(), "'--' delimiter must prevent argument injection finding");
}

// 14. BK-AI-INJ-005: OS Command Execution via Helper/Wrapper/Library
#[test]
fn test_inj_005_os_command_wrapper_vulnerable_and_safe() {
    let vuln_snippet = r#"
        child_process.exec(`ping -c 1 ${req.query.host}`);
        os.system(f"convert {user_img} output.png")
        subprocess.run(cmd, shell=True)
    "#;
    let path = Path::new("src/tools/network.js");
    let findings = FilesystemExtScanner::scan_source(path, vuln_snippet);

    assert_eq!(findings.len(), 3, "Expected 3 findings for shell execution wrappers");
    assert!(findings.iter().all(|f| f.cve.as_str() == "BK-AI-INJ-005"));
    assert!(findings.iter().all(|f| f.severity == Severity::Critical));

    let safe_snippet = r#"
        child_process.execFile('ping', ['-c', '1', '--', req.query.host]);
        subprocess.run(['convert', '--', user_img, 'output.png'], shell=False)
    "#;
    let safe_findings = FilesystemExtScanner::scan_source(path, safe_snippet);
    assert!(safe_findings.is_empty(), "execFile without shell must not trigger finding");
}

// 15. BK-AI-INJ-008: Server-Side Template Expressions Compiled from User Data
#[test]
fn test_inj_008_template_expression_compiled_vulnerable_and_safe() {
    let vuln_snippet = r#"
        import jinja2
        tpl = jinja2.Template(request.args.get('template'))
        res = ejs.render(req.body.template, { user: req.user });
    "#;
    let path = Path::new("src/templates/renderer.py");
    let findings = FilesystemExtScanner::scan_source(path, vuln_snippet);

    assert_eq!(findings.len(), 2, "Expected 2 findings for SSTI compilation");
    assert!(findings.iter().all(|f| f.cve.as_str() == "BK-AI-INJ-008"));

    let safe_snippet = r#"
        template = env.get_template('profile.html')
        res = template.render(user=user)
    "#;
    let safe_findings = FilesystemExtScanner::scan_source(path, safe_snippet);
    assert!(safe_findings.is_empty(), "Static file template rendering must not trigger finding");
}

// 16. BK-AI-INJ-009: Template Escape Bypass (`safe`, raw output) Applied to Untrusted Values
#[test]
fn test_inj_009_template_escape_bypass_vulnerable_and_safe() {
    let vuln_snippet = r#"
        <div>{{ req.query.comment | safe }}</div>
        <div>{!! $userComment !!}</div>
        <span><%- req.body.bio %></span>
    "#;
    let path = Path::new("src/views/comment.html");
    let findings = FilesystemExtScanner::scan_source(path, vuln_snippet);

    assert_eq!(findings.len(), 3, "Expected 3 findings for template escape bypass");
    assert!(findings.iter().all(|f| f.cve.as_str() == "BK-AI-INJ-009"));

    let safe_snippet = r#"
        <div>{{ req.query.comment }}</div>
        <div>{{{ $userComment }}}</div>
        <span><%= req.body.bio %></span>
    "#;
    let safe_findings = FilesystemExtScanner::scan_source(path, safe_snippet);
    assert!(safe_findings.is_empty(), "Default escaped template tags must not trigger finding");
}

// 17. BK-AI-INJ-010: XPath/XQuery Expression Assembled from Inputs
#[test]
fn test_inj_010_xpath_injection_vulnerable_and_safe() {
    let vuln_snippet = r#"
        const nodes = xpath.select(`//user[username/text()='${req.body.username}']`, doc);
        const results = doc.xpath(f"//employee[@id='{user_id}']")
    "#;
    let path = Path::new("src/auth/xml_auth.js");
    let findings = FilesystemExtScanner::scan_source(path, vuln_snippet);

    assert_eq!(findings.len(), 2, "Expected 2 findings for XPath string assembly");
    assert!(findings.iter().all(|f| f.cve.as_str() == "BK-AI-INJ-010"));

    let safe_snippet = r#"
        const nodes = xpath.select("//user[username/text()=$username]", doc, {
            variables: { username: req.body.username }
        });
    "#;
    let safe_findings = FilesystemExtScanner::scan_source(path, safe_snippet);
    assert!(safe_findings.is_empty(), "Parameterized XPath must not trigger finding");
}

// 18. BK-AI-INJ-011: LDAP Filter/DN Assembled Without Escaping
#[test]
fn test_inj_011_ldap_injection_vulnerable_and_safe() {
    let vuln_snippet = r#"
        client.search("dc=example,dc=com", {
            filter: `(&(uid=${req.body.username})(userPassword=${req.body.password}))`
        }, (err, res) => {});
        search_filter = f"(&(sAMAccountName={user_input}))"
    "#;
    let path = Path::new("src/auth/ldap.js");
    let findings = FilesystemExtScanner::scan_source(path, vuln_snippet);

    assert_eq!(findings.len(), 2, "Expected 2 findings for LDAP filter injection");
    assert!(findings.iter().all(|f| f.cve.as_str() == "BK-AI-INJ-011"));

    let safe_snippet = r#"
        const safeUser = escapeLDAPFilter(req.body.username);
        client.search("dc=example,dc=com", {
            filter: `(&(uid=${safeUser}))`
        }, (err, res) => {});
    "#;
    let safe_findings = FilesystemExtScanner::scan_source(path, safe_snippet);
    assert!(safe_findings.is_empty(), "Escaped LDAP filter must not trigger finding");
}

// 19. BK-AI-INJ-012: NoSQL Query/Operator Injection from User Objects
#[test]
fn test_inj_012_nosql_injection_vulnerable_and_safe() {
    let vuln_snippet = r#"
        User.findOne({ username: req.body.username, password: req.body.password });
        db.users.find({ email: req.query.email });
    "#;
    let path = Path::new("src/models/user.js");
    let findings = FilesystemExtScanner::scan_source(path, vuln_snippet);

    assert_eq!(findings.len(), 2, "Expected 2 findings for unvalidated NoSQL query object parameters");
    assert!(findings.iter().all(|f| f.cve.as_str() == "BK-AI-INJ-012"));

    let safe_snippet = r#"
        User.findOne({
            username: String(req.body.username),
            password: String(req.body.password)
        });
    "#;
    let safe_findings = FilesystemExtScanner::scan_source(path, safe_snippet);
    assert!(safe_findings.is_empty(), "String casting must not trigger NoSQL finding");
}

// 20. BK-AI-INJ-013: CRLF Injection into HTTP Response Headers or Logs
#[test]
fn test_inj_013_crlf_injection_vulnerable_and_safe() {
    let vuln_snippet = r#"
        res.setHeader('X-Custom-Token', req.query.token);
        logger.info("User action performed by: " + req.query.user);
    "#;
    let path = Path::new("src/controllers/token.js");
    let findings = FilesystemExtScanner::scan_source(path, vuln_snippet);

    assert_eq!(findings.len(), 2, "Expected 2 findings for CRLF injection into header/log");
    assert!(findings.iter().all(|f| f.cve.as_str() == "BK-AI-INJ-013"));
    assert!(findings.iter().all(|f| f.severity == Severity::Medium));

    let safe_snippet = r#"
        const sanitizedToken = req.query.token.replace(/[\r\n]+/g, '');
        res.setHeader('X-Custom-Token', sanitizedToken);
        const sanitizedUser = req.query.user.replace(/[\r\n]+/g, '');
        logger.info("User action performed by: " + sanitizedUser);
    "#;
    let safe_findings = FilesystemExtScanner::scan_source(path, safe_snippet);
    assert!(safe_findings.is_empty(), "CRLF-stripped inputs must not trigger finding");
}

// 21. BK-AI-INJ-016: Trusting Generic `sanitize()` or `escape()` Without Checking Context
#[test]
fn test_inj_016_generic_sanitize_misuse_vulnerable_and_safe() {
    let vuln_snippet = r#"
        const sql = "SELECT * FROM users WHERE id = '" + validator.escape(userInput) + "'";
        const cmd = "cat " + validator.escape(filename);
        const scriptBlock = "<script> var config = escape(userData); </script>";
    "#;
    let path = Path::new("src/views/bad_escape.js");
    let findings = FilesystemExtScanner::scan_source(path, vuln_snippet);

    assert_eq!(findings.len(), 3, "Expected 3 findings for improper generic sanitize context");
    assert!(findings.iter().all(|f| f.cve.as_str() == "BK-AI-INJ-016"));

    let safe_snippet = r#"
        const sql = db.raw("SELECT * FROM users WHERE id = ?", [userInput]);
        const scriptBlock = `<script> var config = ${JSON.stringify(userData)}; </script>`;
    "#;
    let safe_findings = FilesystemExtScanner::scan_source(path, safe_snippet);
    assert!(safe_findings.is_empty(), "Context-appropriate encoding must not trigger finding");
}
