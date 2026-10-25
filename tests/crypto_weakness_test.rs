use bug_killer::scanner::crypto::CryptoScanner;
use bug_killer::types::Severity;
use std::path::Path;

#[test]
fn test_python_weak_hash_md5_detection() {
    let snippet = r#"
import hashlib

def hash_password(pwd: str) -> str:
    return hashlib.md5(pwd.encode('utf-8')).hexdigest()
"#;
    let path = Path::new("auth/hasher.py");
    let findings = CryptoScanner::scan_source(path, snippet);

    assert_eq!(findings.len(), 1, "Should flag Python MD5 usage");
    assert_eq!(findings[0].cve.as_str(), "BK-AI-CRY-001");
    assert!(findings[0].description.contains("MD5"));
    assert_eq!(findings[0].severity, Severity::High);
}

#[test]
fn test_python_weak_hash_sha1_detection() {
    let snippet = r#"
import hashlib

def compute_checksum(data: bytes) -> str:
    m = hashlib.sha1()
    m.update(data)
    return m.hexdigest()

def dynamic_hasher(data: bytes) -> str:
    return hashlib.new('md5', data).hexdigest()
"#;
    let path = Path::new("utils/crypto_helper.py");
    let findings = CryptoScanner::scan_source(path, snippet);

    assert_eq!(
        findings.len(),
        2,
        "Should flag both sha1 and hashlib.new('md5')"
    );
    assert!(findings.iter().all(|f| f.cve.as_str() == "BK-AI-CRY-001"));
}

#[test]
fn test_javascript_weak_hash_detection() {
    let snippet = r#"
const crypto = require('crypto');

function hashToken(token) {
    return crypto.createHash('md5').update(token).digest('hex');
}

function legacyVerify(secret) {
    const h = crypto.createHash('sha1');
    return h.update(secret).digest('base64');
}
"#;
    let path = Path::new("src/auth/tokenService.js");
    let findings = CryptoScanner::scan_source(path, snippet);

    assert_eq!(
        findings.len(),
        2,
        "Should flag JS md5 and sha1 createHash calls"
    );
    assert!(findings.iter().all(|f| f.cve.as_str() == "BK-AI-CRY-001"));
}

#[test]
fn test_python_hardcoded_static_iv() {
    let snippet = r#"
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

STATIC_IV = b"0123456789abcdef"

def encrypt_record(key, plaintext):
    cipher = Cipher(algorithms.AES(key), modes.CBC(STATIC_IV))
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()

def zero_iv_cipher(key):
    return Cipher(algorithms.AES(key), modes.CBC(b"\x00" * 16))
"#;
    let path = Path::new("security/cipher.py");
    let findings = CryptoScanner::scan_source(path, snippet);

    assert_eq!(findings.len(), 2, "Should flag hardcoded static IVs");
    assert!(findings.iter().all(|f| f.cve.as_str() == "BK-AI-CRY-002"));
    assert_eq!(findings[0].severity, Severity::High);
}

#[test]
fn test_javascript_hardcoded_static_iv() {
    let snippet = r#"
import crypto from 'crypto';

const staticIv = '0123456789abcdef';

export function encryptPayload(key, text) {
    const cipher = crypto.createCipheriv('aes-256-cbc', key, staticIv);
    return cipher.update(text, 'utf8', 'hex') + cipher.final('hex');
}

export function zeroIvEncrypt(key, text) {
    const zeroIv = Buffer.alloc(16, 0);
    const cipher = crypto.createCipheriv('aes-128-cbc', key, zeroIv);
    return cipher.update(text);
}
"#;
    let path = Path::new("lib/encrypt.ts");
    let findings = CryptoScanner::scan_source(path, snippet);

    assert_eq!(
        findings.len(),
        2,
        "Should flag hardcoded static IV in JS/TS"
    );
    assert!(findings.iter().all(|f| f.cve.as_str() == "BK-AI-CRY-002"));
}

#[test]
fn test_python_aes_ecb_mode_detection() {
    let snippet = r#"
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from Crypto.Cipher import AES

def build_insecure_cipher(key):
    return Cipher(algorithms.AES(key), modes.ECB())

def pycrypto_ecb(key):
    return AES.new(key, AES.MODE_ECB)
"#;
    let path = Path::new("crypto/block_cipher.py");
    let findings = CryptoScanner::scan_source(path, snippet);

    assert_eq!(
        findings.len(),
        2,
        "Should flag both cryptography modes.ECB() and PyCryptodome AES.MODE_ECB"
    );
    assert!(findings.iter().all(|f| f.cve.as_str() == "BK-AI-CRY-003"));
    assert_eq!(findings[0].severity, Severity::High);
}

#[test]
fn test_javascript_aes_ecb_mode_detection() {
    let snippet = r#"
const crypto = require('crypto');

function badEncrypt(key, data) {
    const cipher = crypto.createCipheriv('aes-256-ecb', key, null);
    return cipher.update(data, 'utf8', 'hex') + cipher.final('hex');
}

function badEncrypt128(key, data) {
    return crypto.createCipheriv('AES-128-ECB', key, '');
}
"#;
    let path = Path::new("server/crypto/legacy.js");
    let findings = CryptoScanner::scan_source(path, snippet);

    assert_eq!(findings.len(), 2, "Should flag JS ECB mode ciphers");
    assert!(findings.iter().all(|f| f.cve.as_str() == "BK-AI-CRY-003"));
}

#[test]
fn test_secure_crypto_patterns_clean() {
    let py_clean = r#"
import os
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def secure_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def secure_encrypt(key: bytes, plaintext: bytes):
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    return iv, encryptor.update(plaintext) + encryptor.finalize()
"#;
    let js_clean = r#"
const crypto = require('crypto');

function secureHash(token) {
    return crypto.createHash('sha256').update(token).digest('hex');
}

function secureEncrypt(key, text) {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    return { iv, ct: cipher.update(text) };
}
"#;
    let py_findings = CryptoScanner::scan_source(Path::new("app/secure.py"), py_clean);
    let js_findings = CryptoScanner::scan_source(Path::new("app/secure.js"), js_clean);

    assert!(
        py_findings.is_empty(),
        "Secure Python crypto must yield 0 findings"
    );
    assert!(
        js_findings.is_empty(),
        "Secure JS crypto must yield 0 findings"
    );
}
