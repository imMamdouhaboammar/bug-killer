use crate::types::*;
use regex::Regex;
use std::path::Path;
use std::sync::LazyLock;

static RE_AWS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b(AKIA[0-9A-Z]{16})\b").unwrap());
static RE_GITHUB: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{50,})\b").unwrap()
});
static RE_OPENAI: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(sk-[a-zA-Z0-9_-]{24,})\b").unwrap());
static RE_GENERIC_KEY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(api[_-]?key|secret[_-]?key|auth[_-]?token|access[_-]?token)\s*[:=]\s*["']([A-Za-z0-9_\-]{24,})["']"#).unwrap()
});
static RE_PRIVATE_KEY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"-----BEGIN\s+([A-Z0-9_\-\s]+)?PRIVATE\s+KEY-----").unwrap());

pub struct SecretScanner;

impl SecretScanner {
    /// Redacts a sensitive token, preserving only a tiny non-sensitive prefix and suffix.
    pub fn redact_secret(token: &str) -> String {
        if token.len() <= 8 {
            return "[REDACTED]".to_string();
        }
        let prefix = &token[..4];
        let suffix = &token[token.len() - 4..];
        format!("{}...[REDACTED]...{}", prefix, suffix)
    }

    /// Scans a file for hardcoded secrets, private keys, or exposed credentials.
    pub fn scan_file(path: &Path, content: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let file_name = path.file_name().unwrap_or_default().to_string_lossy();

        // 1. Check for committed private key files (BK-AI-SEC-002)
        if RE_PRIVATE_KEY.is_match(content) {
            let mut finding = Finding::new(
                format!("SEC-KEY-{}", path.display()),
                CveId::Custom {
                    id: "BK-AI-SEC-002".to_string(),
                    title: "Exposed Unencrypted Private Key Committed to Workspace".to_string(),
                },
                Severity::Critical,
                TargetKind::GenericConfigFile,
                Some(path.to_path_buf()),
                Some(1),
                "-----BEGIN PRIVATE KEY-----",
                "Store private keys in hardware tokens, secure secret managers, or encrypted keyrings",
                format!(
                    "File '{}' contains an unencrypted private cryptographic key",
                    path.display()
                ),
                "Remove private key file from repository and immediately revoke and rotate associated certificates",
            );
            finding.detector_id = "secret-detector".to_string();
            finding.category = "2.10 Secrets, privacy, PII and data exposure".to_string();
            finding.affectedness = Affectedness::ConfirmedAffected;
            finding.reachability = Reachability::ConfirmedReachable;
            finding.confidence = Confidence::Confirmed;
            finding.evidence_certainty = EvidenceCertainty::Confirmed;
            finding.evidence_digest = "cryptographic_private_key_material".to_string();
            findings.push(finding);
            return findings;
        }

        // 2. Line by line scanning for hardcoded API keys and tokens (BK-AI-SEC-001)
        for (line_idx, line) in content.lines().enumerate() {
            let line_num = line_idx + 1;
            let trimmed = line.trim();

            // Skip comments in source files if they look like examples
            if trimmed.starts_with("//") || trimmed.starts_with('#') || trimmed.starts_with('*') {
                if trimmed.contains("example")
                    || trimmed.contains("dummy")
                    || trimmed.contains("your_key_here")
                {
                    continue;
                }
            }

            // AWS access key
            if let Some(caps) = RE_AWS.captures(line) {
                let raw_token = &caps[1];
                if !raw_token.contains("EXAMPLE") {
                    let redacted = Self::redact_secret(raw_token);
                    let mut finding = Finding::new(
                        format!("SEC-AWS-{}-{}", path.display(), line_num),
                        CveId::Custom {
                            id: "BK-AI-SEC-001".to_string(),
                            title: "Hardcoded AWS Access Key ID in Source Code".to_string(),
                        },
                        Severity::Critical,
                        TargetKind::GenericSourceFile,
                        Some(path.to_path_buf()),
                        Some(line_num),
                        redacted.clone(),
                        "Use environment variables or cloud identity roles (IAM Roles for Workloads)",
                        format!("AWS Access Key detected at line {}: {}", line_num, redacted),
                        "Extract key to environment variable and rotate the exposed AWS credential immediately",
                    );
                    finding.detector_id = "secret-detector".to_string();
                    finding.category = "2.10 Secrets, privacy, PII and data exposure".to_string();
                    finding.affectedness = Affectedness::ConfirmedAffected;
                    finding.reachability = Reachability::ConfirmedReachable;
                    finding.confidence = Confidence::Confirmed;
                    finding.evidence_certainty = EvidenceCertainty::Confirmed;
                    findings.push(finding);
                }
            }

            // GitHub PAT
            if let Some(caps) = RE_GITHUB.captures(line) {
                let raw_token = &caps[1];
                let redacted = Self::redact_secret(raw_token);
                let mut finding = Finding::new(
                    format!("SEC-GH-{}-{}", path.display(), line_num),
                    CveId::Custom {
                        id: "BK-AI-SEC-001".to_string(),
                        title: "Hardcoded GitHub Personal Access Token in Source Code".to_string(),
                    },
                    Severity::Critical,
                    TargetKind::GenericSourceFile,
                    Some(path.to_path_buf()),
                    Some(line_num),
                    redacted.clone(),
                    "Use secrets manager or GitHub Actions encrypted repository secrets",
                    format!(
                        "GitHub Personal Access Token detected at line {}: {}",
                        line_num, redacted
                    ),
                    "Revoke token via GitHub Security Settings and load from environment variable",
                );
                finding.detector_id = "secret-detector".to_string();
                finding.category = "2.10 Secrets, privacy, PII and data exposure".to_string();
                finding.affectedness = Affectedness::ConfirmedAffected;
                finding.reachability = Reachability::ConfirmedReachable;
                finding.confidence = Confidence::Confirmed;
                finding.evidence_certainty = EvidenceCertainty::Confirmed;
                findings.push(finding);
            }

            // OpenAI API Key
            if let Some(caps) = RE_OPENAI.captures(line) {
                let raw_token = &caps[1];
                let redacted = Self::redact_secret(raw_token);
                let mut finding = Finding::new(
                    format!("SEC-OAI-{}-{}", path.display(), line_num),
                    CveId::Custom {
                        id: "BK-AI-SEC-001".to_string(),
                        title: "Hardcoded OpenAI API Key in Source Code".to_string(),
                    },
                    Severity::High,
                    TargetKind::GenericSourceFile,
                    Some(path.to_path_buf()),
                    Some(line_num),
                    redacted.clone(),
                    "Use OPENAI_API_KEY environment variable",
                    format!("OpenAI API key detected at line {}: {}", line_num, redacted),
                    "Extract key to .env file (excluded from git) or load via process.env",
                );
                finding.detector_id = "secret-detector".to_string();
                finding.category = "2.10 Secrets, privacy, PII and data exposure".to_string();
                finding.affectedness = Affectedness::ConfirmedAffected;
                finding.reachability = Reachability::ConfirmedReachable;
                finding.confidence = Confidence::Confirmed;
                finding.evidence_certainty = EvidenceCertainty::Confirmed;
                findings.push(finding);
            }

            // Generic high-entropy secret assignment
            if let Some(caps) = RE_GENERIC_KEY.captures(line) {
                let key_name = &caps[1];
                let raw_token = &caps[2];
                // Ignore obvious dummy values
                if !raw_token.contains("test")
                    && !raw_token.contains("example")
                    && !raw_token.contains("placeholder")
                    && !raw_token.contains("dummy")
                    && !raw_token.contains("00000000")
                {
                    let redacted = Self::redact_secret(raw_token);
                    let mut finding = Finding::new(
                        format!("SEC-GEN-{}-{}", path.display(), line_num),
                        CveId::Custom {
                            id: "BK-AI-SEC-001".to_string(),
                            title: format!(
                                "Hardcoded Credential Assignment ('{}') in Code",
                                key_name
                            ),
                        },
                        Severity::High,
                        TargetKind::GenericSourceFile,
                        Some(path.to_path_buf()),
                        Some(line_num),
                        format!("{}: {}", key_name, redacted),
                        "Inject credentials via runtime environment configuration",
                        format!(
                            "Hardcoded secret token assigned to '{}' at line {}",
                            key_name, line_num
                        ),
                        "Replace literal string assignment with environment variable lookup",
                    );
                    finding.detector_id = "secret-detector".to_string();
                    finding.category = "2.10 Secrets, privacy, PII and data exposure".to_string();
                    finding.affectedness = Affectedness::LikelyAffected;
                    finding.reachability = Reachability::PotentiallyReachable;
                    finding.confidence = Confidence::High;
                    finding.evidence_certainty = EvidenceCertainty::StronglySupported;
                    findings.push(finding);
                }
            }
        }

        // 3. Dockerfile ARG/ENV secret leakage (BK-AI-SEC-004)
        if file_name == "Dockerfile" || file_name.starts_with("Dockerfile.") {
            for (line_idx, line) in content.lines().enumerate() {
                let trimmed = line.trim();
                if (trimmed.starts_with("ARG ") || trimmed.starts_with("ENV "))
                    && (trimmed.to_lowercase().contains("token")
                        || trimmed.to_lowercase().contains("secret")
                        || trimmed.to_lowercase().contains("password")
                        || trimmed.to_lowercase().contains("api_key"))
                    && trimmed.contains('=')
                {
                    let mut finding = Finding::new(
                        format!("SEC-DKR-{}-{}", path.display(), line_idx + 1),
                        CveId::Custom {
                            id: "BK-AI-SEC-004".to_string(),
                            title: "Secret Value Baked into Dockerfile ARG or ENV Layer"
                                .to_string(),
                        },
                        Severity::High,
                        TargetKind::Dockerfile,
                        Some(path.to_path_buf()),
                        Some(line_idx + 1),
                        "ARG/ENV with secret value",
                        "Mount secrets with 'RUN --mount=type=secret' to avoid persisting in image layers",
                        format!(
                            "Potential secret declared in Dockerfile at line {}: {}",
                            line_idx + 1,
                            trimmed
                        ),
                        "Use BuildKit secret mounts rather than permanent ARG/ENV declarations",
                    );
                    finding.detector_id = "secret-detector".to_string();
                    finding.category = "2.10 Secrets, privacy, PII and data exposure".to_string();
                    finding.affectedness = Affectedness::ConfirmedAffected;
                    finding.reachability = Reachability::ConfirmedReachable;
                    finding.confidence = Confidence::High;
                    finding.evidence_certainty = EvidenceCertainty::Confirmed;
                    findings.push(finding);
                }
            }
        }

        findings
    }
}
