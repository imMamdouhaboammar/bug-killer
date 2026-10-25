#![allow(dead_code)]

use crate::types::*;
use regex::Regex;
use std::path::Path;
use std::sync::LazyLock;

static RE_WEAK_HASH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\bhashlib\.(?:md5|sha1)\s*\(|\bhashlib\.new\s*\(\s*['"](?:md5|sha1)['"]|\bcreateHash\s*\(\s*['"](?:md5|sha1)['"]|\bcreateHmac\s*\(\s*['"](?:md5|sha1)['"]|\b(?:MD5|SHA1?)\.new\s*\()"#).unwrap()
});

static RE_ECB_MODE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\bmodes\.ECB\s*\(|\b[A-Za-z0-9_]*\.?MODE_ECB\b|\bcreateCipher(?:iv)?\s*\(\s*['"][^'"]*[-_]ecb['"]|Cipher\.getInstance\s*\(\s*['"][^'"]*/ECB/[^'"]*['"])"#).unwrap()
});

static RE_STATIC_IV_PY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\bmodes\.(?:CBC|CTR|CFB|OFB|GCM)\s*\(\s*(?:b?["'][^"']+["'](?:\s*\*\s*\d+)?|bytes\s*\([^)]+\)|[a-z0-9_]*(?:static|fixed|zero|default)[a-z0-9_]*)\s*\)|\bAES\.new\s*\([^,]+,\s*AES\.MODE_(?:CBC|CTR|CFB|OFB)\s*,\s*(?:b?["'][^"']+["'](?:\s*\*\s*\d+)?|bytes\s*\([^)]+\)|[a-z0-9_]*(?:static|fixed|zero|default)[a-z0-9_]*)\s*\))"#).unwrap()
});

static RE_STATIC_IV_JS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\bcreateCipheriv\s*\(\s*['"][^'"]+['"]\s*,\s*[^,]+\s*,\s*(?:['"][^'"]+['"]|Buffer\.alloc\s*\([^)]*\)|Buffer\.from\s*\([^)]+\)|[a-z0-9_]*(?:static|fixed|zero|default)[a-z0-9_]*)\s*\)"#).unwrap()
});

pub struct CryptoScanner;

impl CryptoScanner {
    /// Scans source code content for cryptographic weaknesses:
    /// - BK-AI-CRY-001: Weak hash functions (MD5, SHA1)
    /// - BK-AI-CRY-002: Hardcoded static initialization vectors (IVs) or nonces
    /// - BK-AI-CRY-003: Insecure cipher modes (AES ECB mode)
    pub fn scan_source(path: &Path, content: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        let target_kind = match path.extension().and_then(|ext| ext.to_str()) {
            Some("js" | "mjs" | "cjs" | "ts" | "tsx" | "jsx") => TargetKind::NodeSourceFile,
            _ => TargetKind::GenericSourceFile,
        };

        let file_tag = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("source");

        for (idx, line) in content.lines().enumerate() {
            let line_no = idx + 1;
            let trimmed = line.trim();

            if trimmed.is_empty()
                || trimmed.starts_with("//")
                || trimmed.starts_with('#')
                || trimmed.starts_with('*')
            {
                continue;
            }

            // 1. Weak hash functions (BK-AI-CRY-001)
            let weak_hash_matches: Vec<_> = RE_WEAK_HASH.find_iter(line).collect();
            for (m_idx, m) in weak_hash_matches.iter().enumerate() {
                let id = if weak_hash_matches.len() > 1 {
                    format!("CRY-001-{}-{}-{}", file_tag, line_no, m_idx + 1)
                } else {
                    format!("CRY-001-{}-{}", file_tag, line_no)
                };

                let mut finding = Finding::new(
                    id,
                    CveId::Custom {
                        id: "BK-AI-CRY-001".to_string(),
                        title: "Weak Cryptographic Hash Function (MD5/SHA1)".to_string(),
                    },
                    Severity::High,
                    target_kind.clone(),
                    Some(path.to_path_buf()),
                    Some(line_no),
                    m.as_str(),
                    "Use collision-resistant hash functions (SHA-256/SHA-512) or password KDFs (Argon2id/bcrypt)",
                    format!(
                        "File '{}' uses weak/broken hash algorithm ({}) at line {}. MD5 and SHA-1 are vulnerable to practical collision attacks.",
                        path.display(),
                        m.as_str(),
                        line_no
                    ),
                    "Migrate to SHA-256 or SHA-3 for digests, or Argon2id/bcrypt for password hashing.",
                );
                finding.detector_id = "crypto-weakness".to_string();
                finding.detector_version = "1.0.0".to_string();
                finding.category = "2.9 Cryptography, randomness and key management".to_string();
                finding.affectedness = Affectedness::ConfirmedAffected;
                finding.reachability = Reachability::PotentiallyReachable;
                finding.confidence = Confidence::High;
                finding.evidence_certainty = EvidenceCertainty::StronglySupported;
                finding.evidence_refs.push(EvidenceRef {
                    location: format!("{}:{}", path.display(), line_no),
                    line_number: Some(line_no),
                    snippet: Some(trimmed.to_string()),
                    sha256: None,
                });
                finding.compute_dedupe_fingerprint();
                findings.push(finding);
            }

            // 2. Insecure cipher mode: ECB (BK-AI-CRY-003)
            let mut is_ecb = false;
            if let Some(m) = RE_ECB_MODE.find(line) {
                is_ecb = true;
                let id = format!("CRY-003-{}-{}", file_tag, line_no);
                let mut finding = Finding::new(
                    id,
                    CveId::Custom {
                        id: "BK-AI-CRY-003".to_string(),
                        title: "Insecure Cipher Mode (Electronic Codebook / ECB)".to_string(),
                    },
                    Severity::High,
                    target_kind.clone(),
                    Some(path.to_path_buf()),
                    Some(line_no),
                    m.as_str(),
                    "Use authenticated AEAD cipher modes such as AES-GCM or ChaCha20-Poly1305",
                    format!(
                        "File '{}' uses Electronic Codebook (ECB) cipher mode at line {}. ECB mode does not provide semantic security and leaks plaintext patterns.",
                        path.display(),
                        line_no
                    ),
                    "Switch from ECB mode to authenticated encryption (AEAD) like AES-256-GCM with unique nonces.",
                );
                finding.detector_id = "crypto-weakness".to_string();
                finding.detector_version = "1.0.0".to_string();
                finding.category = "2.9 Cryptography, randomness and key management".to_string();
                finding.affectedness = Affectedness::ConfirmedAffected;
                finding.reachability = Reachability::PotentiallyReachable;
                finding.confidence = Confidence::High;
                finding.evidence_certainty = EvidenceCertainty::StronglySupported;
                finding.evidence_refs.push(EvidenceRef {
                    location: format!("{}:{}", path.display(), line_no),
                    line_number: Some(line_no),
                    snippet: Some(trimmed.to_string()),
                    sha256: None,
                });
                finding.compute_dedupe_fingerprint();
                findings.push(finding);
            }

            // 3. Hardcoded static IV / nonce (BK-AI-CRY-002) - skip if ECB mode
            if !is_ecb {
                let static_iv_match = RE_STATIC_IV_PY
                    .find(line)
                    .or_else(|| RE_STATIC_IV_JS.find(line));

                if let Some(m) = static_iv_match {
                    let id = format!("CRY-002-{}-{}", file_tag, line_no);
                    let mut finding = Finding::new(
                        id,
                        CveId::Custom {
                            id: "BK-AI-CRY-002".to_string(),
                            title: "Hardcoded Static Initialization Vector (IV) / Nonce"
                                .to_string(),
                        },
                        Severity::High,
                        target_kind.clone(),
                        Some(path.to_path_buf()),
                        Some(line_no),
                        m.as_str(),
                        "Generate cryptographically random IV/nonce per operation using CSPRNG",
                        format!(
                            "File '{}' uses a hardcoded, static, or predictable IV at line {}. Reusing static IVs destroys confidentiality across ciphertexts.",
                            path.display(),
                            line_no
                        ),
                        "Generate a fresh cryptographically secure random IV for each encryption operation (e.g. os.urandom or crypto.randomBytes).",
                    );
                    finding.detector_id = "crypto-weakness".to_string();
                    finding.detector_version = "1.0.0".to_string();
                    finding.category =
                        "2.9 Cryptography, randomness and key management".to_string();
                    finding.affectedness = Affectedness::ConfirmedAffected;
                    finding.reachability = Reachability::PotentiallyReachable;
                    finding.confidence = Confidence::High;
                    finding.evidence_certainty = EvidenceCertainty::StronglySupported;
                    finding.evidence_refs.push(EvidenceRef {
                        location: format!("{}:{}", path.display(), line_no),
                        line_number: Some(line_no),
                        snippet: Some(trimmed.to_string()),
                        sha256: None,
                    });
                    finding.compute_dedupe_fingerprint();
                    findings.push(finding);
                }
            }
        }

        findings
    }
}
