use bug_killer::types::{self, Severity};
use std::path::Path;

#[path = "../src/scanner/parser_security.rs"]
mod parser_security;

use parser_security::ParserSecurityScanner;

// ===========================================================================
// Category 12: Parsers & Serialization Rules (BK-AI-PAR-001 to BK-AI-PAR-012)
// ===========================================================================

#[test]
fn test_par_001_pickle_deserialization() {
    let vuln_code = r#"
import pickle
import _pickle
import shelve

def load_user_session(data):
    session = pickle.loads(data)
    fast_data = _pickle.loads(data)
    store = shelve.open("user_cache.db")
    return session
"#;
    let path = Path::new("services/session.py");
    let findings = ParserSecurityScanner::scan_source(path, vuln_code);

    assert_eq!(findings.len(), 3);
    assert!(findings.iter().all(|f| f.cve.as_str() == "BK-AI-PAR-001"));
    assert_eq!(findings[0].detector_id, "parser-security");
    assert_eq!(findings[0].severity, Severity::High);

    let safe_code = r#"
import json

def load_user_session(data):
    return json.loads(data.decode('utf-8'))
"#;
    let safe_findings = ParserSecurityScanner::scan_source(path, safe_code);
    assert!(safe_findings.is_empty());
}

#[test]
fn test_par_002_yaml_unsafe_loader() {
    let vuln_code = r#"
import yaml

def parse_config(content):
    cfg1 = yaml.load(content, Loader=yaml.Loader)
    cfg2 = yaml.unsafe_load(content)
    return cfg1
"#;
    let path = Path::new("config/loader.py");
    let findings = ParserSecurityScanner::scan_source(path, vuln_code);

    assert_eq!(findings.len(), 2);
    assert!(findings.iter().all(|f| f.cve.as_str() == "BK-AI-PAR-002"));

    let safe_code = r#"
import yaml

def parse_config(content):
    return yaml.safe_load(content)
"#;
    let safe_findings = ParserSecurityScanner::scan_source(path, safe_code);
    assert!(safe_findings.is_empty());
}

#[test]
fn test_par_003_unsafe_object_deserialization() {
    let vuln_code = r#"
<?php
$data = $_POST['serialized_user'];
$user = unserialize($data);
?>
"#;
    let path = Path::new("legacy/user.php");
    let findings = ParserSecurityScanner::scan_source(path, vuln_code);

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].cve.as_str(), "BK-AI-PAR-003");

    let vuln_ruby_dotnet = r#"
def restore_state(payload)
    Marshal.load(payload)
end

public void DeserializeNet(Stream stream) {
    new BinaryFormatter().Deserialize(stream);
}
"#;
    let path_mixed = Path::new("worker/processor.cs");
    let mixed_findings = ParserSecurityScanner::scan_source(path_mixed, vuln_ruby_dotnet);
    assert_eq!(mixed_findings.len(), 2);
    assert!(mixed_findings.iter().all(|f| f.cve.as_str() == "BK-AI-PAR-003"));

    let safe_php = r#"
<?php
$data = $_POST['serialized_user'];
$user = unserialize($data, ['allowed_classes' => false]);
$json_user = json_decode($data, true);
?>
"#;
    let safe_findings = ParserSecurityScanner::scan_source(path, safe_php);
    assert!(safe_findings.is_empty());
}

#[test]
fn test_par_004_xxe_resolution_enabled() {
    let vuln_code = r#"
from lxml import etree

parser1 = etree.XMLParser(resolve_entities=True)
parser2 = etree.XMLParser(load_dtd=True)
"#;
    let path = Path::new("parsers/xml_handler.py");
    let findings = ParserSecurityScanner::scan_source(path, vuln_code);

    assert_eq!(findings.len(), 2);
    assert!(findings.iter().all(|f| f.cve.as_str() == "BK-AI-PAR-004"));

    let safe_code = r#"
from lxml import etree

parser = etree.XMLParser(resolve_entities=False, load_dtd=False)
doc = etree.fromstring(xml_data, parser=parser)
"#;
    let safe_findings = ParserSecurityScanner::scan_source(path, safe_code);
    assert!(safe_findings.is_empty());
}

#[test]
fn test_par_005_prototype_pollution_unsafe_merge() {
    let vuln_code = r#"
const _ = require('lodash');

function applySettings(target, payload) {
    target["__proto__"] = payload.proto;
    _.merge(target, req.body);
}
"#;
    let path = Path::new("src/utils/merge.js");
    let findings = ParserSecurityScanner::scan_source(path, vuln_code);

    assert_eq!(findings.len(), 2);
    assert!(findings.iter().all(|f| f.cve.as_str() == "BK-AI-PAR-005"));

    let safe_code = r#"
function safeMerge(target, source) {
    for (const key of Object.keys(source)) {
        if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
            continue;
        }
        target[key] = source[key];
    }
}
"#;
    let safe_findings = ParserSecurityScanner::scan_source(path, safe_code);
    assert!(safe_findings.is_empty());
}

#[test]
fn test_par_006_unsafe_reflection() {
    let vuln_code = r#"
public Object createHandler(HttpServletRequest req) throws Exception {
    String className = req.getParameter("handler");
    return Class.forName(className).newInstance();
}
"#;
    let path = Path::new("src/main/java/Dispatcher.java");
    let findings = ParserSecurityScanner::scan_source(path, vuln_code);

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].cve.as_str(), "BK-AI-PAR-006");

    let safe_code = r#"
public Object createHandler(String key) {
    return HANDLER_REGISTRY.getOrDefault(key, DefaultHandler::new).get();
}
"#;
    let safe_findings = ParserSecurityScanner::scan_source(path, safe_code);
    assert!(safe_findings.is_empty());
}

#[test]
fn test_par_007_unbounded_nesting_limit() {
    let vuln_code = r#"
const parser = new JsonStreamParser({
    maxDepth: 0,
    disableDepthLimit: true,
});
"#;
    let path = Path::new("src/parser/stream.ts");
    let findings = ParserSecurityScanner::scan_source(path, vuln_code);

    assert_eq!(findings.len(), 2);
    assert!(findings.iter().all(|f| f.cve.as_str() == "BK-AI-PAR-007"));

    let safe_code = r#"
const parser = new JsonStreamParser({
    maxDepth: 32,
    disableDepthLimit: false,
});
"#;
    let safe_findings = ParserSecurityScanner::scan_source(path, safe_code);
    assert!(safe_findings.is_empty());
}

#[test]
fn test_par_008_mime_confusion() {
    let vuln_code = r#"
app.get('/media/:id', (req, res) => {
    // Serve user media download
    res.setHeader('Content-Type', 'text/html'); // media upload file_path
    res.sendFile(mediaFilePath);
});
"#;
    let path = Path::new("src/routes/media.js");
    let findings = ParserSecurityScanner::scan_source(path, vuln_code);

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].cve.as_str(), "BK-AI-PAR-008");

    let safe_code = r#"
app.get('/media/:id', (req, res) => {
    res.setHeader('Content-Type', 'image/png');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.sendFile(mediaFilePath);
});
"#;
    let safe_findings = ParserSecurityScanner::scan_source(path, safe_code);
    assert!(safe_findings.is_empty());
}

#[test]
fn test_par_009_csv_formula_injection() {
    let vuln_code = r#"
function exportReport(rows) {
    // csv formula injection
    return rows.map(r => `${r.name},${r.userInput}`).join('\n');
}
"#;
    let path = Path::new("src/services/csvExport.js");
    let findings = ParserSecurityScanner::scan_source(path, vuln_code);

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].cve.as_str(), "BK-AI-PAR-009");

    let safe_code = r#"
function exportReport(rows) {
    return rows.map(r => `${sanitizeCsv(r.name)},${sanitizeCsv(r.userInput)}`).join('\n');
}
"#;
    let safe_findings = ParserSecurityScanner::scan_source(path, safe_code);
    assert!(safe_findings.is_empty());
}

#[test]
fn test_par_010_markdown_html_enabled() {
    let vuln_code = r#"
import { marked } from 'marked';
import MarkdownIt from 'markdown-it';

marked.setOptions({ sanitize: false });
const md = new MarkdownIt({ html: true });
"#;
    let path = Path::new("src/renderers/markdown.ts");
    let findings = ParserSecurityScanner::scan_source(path, vuln_code);

    assert_eq!(findings.len(), 2);
    assert!(findings.iter().all(|f| f.cve.as_str() == "BK-AI-PAR-010"));

    let safe_code = r#"
import MarkdownIt from 'markdown-it';
import DOMPurify from 'dompurify';

const md = new MarkdownIt({ html: false });
const cleanHtml = DOMPurify.sanitize(md.render(input));
"#;
    let safe_findings = ParserSecurityScanner::scan_source(path, safe_code);
    assert!(safe_findings.is_empty());
}

#[test]
fn test_par_011_double_decode() {
    let vuln_code = r#"
function normalizePath(input) {
    const fullyDecoded = decodeURIComponent(decodeURIComponent(input));
    return fullyDecoded;
}
"#;
    let path = Path::new("src/routing/url_normalizer.js");
    let findings = ParserSecurityScanner::scan_source(path, vuln_code);

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].cve.as_str(), "BK-AI-PAR-011");

    let safe_code = r#"
function normalizePath(input) {
    const singleDecoded = decodeURIComponent(input);
    validateCleanPath(singleDecoded);
    return singleDecoded;
}
"#;
    let safe_findings = ParserSecurityScanner::scan_source(path, safe_code);
    assert!(safe_findings.is_empty());
}

#[test]
fn test_par_012_native_codec_containment() {
    let vuln_code = r#"
const cp = require('child_process');

function convertImage(uploadPath) {
    // native codec without containment
    cp.execSync(`convert ${uploadPath} -resize 100x100 out.png`);
}
"#;
    let path = Path::new("src/workers/transcoder.js");
    let findings = ParserSecurityScanner::scan_source(path, vuln_code);

    assert_eq!(findings.len(), 2);
    assert!(findings.iter().all(|f| f.cve.as_str() == "BK-AI-PAR-012"));

    let safe_code = r#"
function convertImage(uploadPath) {
    return runIsolatedContainer(["convert", uploadPath, "-resize", "100x100", "out.png"], {
        timeoutMs: 5000,
        memoryLimitMb: 128,
    });
}
"#;
    let safe_findings = ParserSecurityScanner::scan_source(path, safe_code);
    assert!(safe_findings.is_empty());
}

// ===========================================================================
// Category 9: Cryptography Ext Rules (BK-AI-CRY-004 to BK-AI-CRY-012)
// ===========================================================================

#[test]
fn test_cry_004_unauthenticated_encryption() {
    let vuln_code = r#"
const crypto = require('crypto');

function encryptData(key, iv, plaintext) {
    // unauthenticated encryption
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    return Buffer.concat([cipher.update(plaintext), cipher.final()]);
}
"#;
    let path = Path::new("src/crypto/encryption.js");
    let findings = ParserSecurityScanner::scan_source(path, vuln_code);

    assert_eq!(findings.len(), 2);
    assert!(findings.iter().all(|f| f.cve.as_str() == "BK-AI-CRY-004"));
    assert_eq!(findings[0].category, "2.9 Cryptography, randomness and key management");

    let safe_code = r#"
const crypto = require('crypto');

function encryptData(key, iv, plaintext) {
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();
    return { ct, tag };
}
"#;
    let safe_findings = ParserSecurityScanner::scan_source(path, safe_code);
    assert!(safe_findings.is_empty());
}

#[test]
fn test_cry_005_static_nonce_reuse() {
    let vuln_code = r#"
def encrypt_record(key, data):
    nonce = b"000000000000"
    iv = "1234567890123456"
    return cipher.encrypt(nonce, data)
"#;
    let path = Path::new("crypto/vault.py");
    let findings = ParserSecurityScanner::scan_source(path, vuln_code);

    assert_eq!(findings.len(), 2);
    assert!(findings.iter().all(|f| f.cve.as_str() == "BK-AI-CRY-005"));

    let safe_code = r#"
import os

def encrypt_record(key, data):
    nonce = os.urandom(12)
    return cipher.encrypt(nonce, data)
"#;
    let safe_findings = ParserSecurityScanner::scan_source(path, safe_code);
    assert!(safe_findings.is_empty());
}

#[test]
fn test_cry_006_hardcoded_cryptographic_keys() {
    let vuln_code = format!(
        "const PRIVATE_KEY = \"-----BEGIN RSA {}\";\nconst SECRET_KEY = \"my_super_secret_production_key_12345\";\n",
        "PRIVATE KEY-----MIIEowIBAAKCAQEA..."
    );
    let path = Path::new("src/config/secrets.js");
    let findings = ParserSecurityScanner::scan_source(path, &vuln_code);

    assert_eq!(findings.len(), 2);
    assert!(findings.iter().all(|f| f.cve.as_str() == "BK-AI-CRY-006"));

    let safe_code = r#"
const SECRET_KEY = process.env.ENCRYPTION_SECRET_KEY;
const PRIVATE_KEY = process.env.RSA_PRIVATE_KEY_PEM;
"#;
    let safe_findings = ParserSecurityScanner::scan_source(path, safe_code);
    assert!(safe_findings.is_empty());
}

#[test]
fn test_cry_007_cert_rotation_expiration_ignored() {
    let vuln_code = r#"
const https = require('https');

const agent = new https.Agent({
    rejectUnauthorized: false,
    strictSSL: false,
    ignoreExpiration: true,
});
"#;
    let path = Path::new("src/net/client.js");
    let findings = ParserSecurityScanner::scan_source(path, vuln_code);

    assert_eq!(findings.len(), 3);
    assert!(findings.iter().all(|f| f.cve.as_str() == "BK-AI-CRY-007"));

    let safe_code = r#"
const https = require('https');

const agent = new https.Agent({
    rejectUnauthorized: true,
    strictSSL: true,
    ignoreExpiration: false,
});
"#;
    let safe_findings = ParserSecurityScanner::scan_source(path, safe_code);
    assert!(safe_findings.is_empty());
}

#[test]
fn test_cry_008_non_crypto_hash_signature() {
    let vuln_code = r#"
function verifyWebhook(payload, signature) {
    if (crc32(payload) === signature) {
        return true;
    }
    return false;
}
"#;
    let path = Path::new("src/auth/webhook.js");
    let findings = ParserSecurityScanner::scan_source(path, vuln_code);

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].cve.as_str(), "BK-AI-CRY-008");

    let safe_code = r#"
const crypto = require('crypto');

function verifyWebhook(payload, signature, secret) {
    const expected = crypto.createHmac('sha256', secret).update(payload).digest('hex');
    return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected));
}
"#;
    let safe_findings = ParserSecurityScanner::scan_source(path, safe_code);
    assert!(safe_findings.is_empty());
}

#[test]
fn test_cry_009_canonical_mismatch_signature() {
    let vuln_code = r#"
function processWebhook(req) {
    // canonical mismatch
    verifySignature(req.rawBody.trim());
    return JSON.parse(req.body);
}
"#;
    let path = Path::new("src/auth/signature_verifier.js");
    let findings = ParserSecurityScanner::scan_source(path, vuln_code);

    assert_eq!(findings.len(), 2);
    assert!(findings.iter().all(|f| f.cve.as_str() == "BK-AI-CRY-009"));

    let safe_code = r#"
function processWebhook(req) {
    verifySignature(req.rawBody);
    return parseExact(req.rawBody);
}
"#;
    let safe_findings = ParserSecurityScanner::scan_source(path, safe_code);
    assert!(safe_findings.is_empty());
}

#[test]
fn test_cry_010_timing_leak_secret_comparison() {
    let vuln_code = r#"
function checkApiToken(token, expectedToken) {
    if (token === expectedToken) {
        return true;
    }
    return false;
}
"#;
    let path = Path::new("src/auth/guard.js");
    let findings = ParserSecurityScanner::scan_source(path, vuln_code);

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].cve.as_str(), "BK-AI-CRY-010");

    let safe_code = r#"
const crypto = require('crypto');

function checkApiToken(token, expectedToken) {
    const a = Buffer.from(token);
    const b = Buffer.from(expectedToken);
    if (a.length === b.length && crypto.timingSafeEqual(a, b)) {
        return true;
    }
    return false;
}
"#;
    let safe_findings = ParserSecurityScanner::scan_source(path, safe_code);
    assert!(safe_findings.is_empty());
}

#[test]
fn test_cry_011_unsafe_tls_downgrade() {
    let vuln_code = r#"
const tls = require('tls');

const options = {
    minVersion: 'TLSv1',
    secureProtocol: 'SSLv3_method',
};
"#;
    let path = Path::new("src/tls/config.js");
    let findings = ParserSecurityScanner::scan_source(path, vuln_code);

    assert_eq!(findings.len(), 2);
    assert!(findings.iter().all(|f| f.cve.as_str() == "BK-AI-CRY-011"));

    let safe_code = r#"
const tls = require('tls');

const options = {
    minVersion: 'TLSv1.3',
};
"#;
    let safe_findings = ParserSecurityScanner::scan_source(path, safe_code);
    assert!(safe_findings.is_empty());
}

#[test]
fn test_cry_012_tenant_binding_omitted() {
    let vuln_code = r#"
def encrypt_tenant_record(cipher, nonce, data):
    # no tenant binding
    return cipher.encrypt(nonce, data, associated_data=None)
"#;
    let path = Path::new("services/tenant_crypto.py");
    let findings = ParserSecurityScanner::scan_source(path, vuln_code);

    assert_eq!(findings.len(), 2);
    assert!(findings.iter().all(|f| f.cve.as_str() == "BK-AI-CRY-012"));

    let safe_code = r#"
def encrypt_tenant_record(cipher, nonce, data, tenant_id):
    return cipher.encrypt(nonce, data, associated_data=tenant_id.encode('utf-8'))
"#;
    let safe_findings = ParserSecurityScanner::scan_source(path, safe_code);
    assert!(safe_findings.is_empty());
}
