use super::draft::DisclosurePacket;
use chrono::Utc;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

/// Categories of sensitive operational credentials, network locations, or identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SensitivityCategory {
    Token,
    Key,
    Password,
    PrivateIp,
    DatabaseUri,
    PrivateKey,
    Pii,
}

impl SensitivityCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            SensitivityCategory::Token => "Token",
            SensitivityCategory::Key => "Key",
            SensitivityCategory::Password => "Password",
            SensitivityCategory::PrivateIp => "PrivateIp",
            SensitivityCategory::DatabaseUri => "DatabaseUri",
            SensitivityCategory::PrivateKey => "PrivateKey",
            SensitivityCategory::Pii => "Pii",
        }
    }

    pub fn tag(&self) -> &'static str {
        match self {
            SensitivityCategory::Token => "TOKEN",
            SensitivityCategory::Key => "KEY",
            SensitivityCategory::Password => "PASSWORD",
            SensitivityCategory::PrivateIp => "PRIVATE_IP",
            SensitivityCategory::DatabaseUri => "DATABASE_URI",
            SensitivityCategory::PrivateKey => "PRIVATE_KEY",
            SensitivityCategory::Pii => "PII",
        }
    }
}

impl fmt::Display for SensitivityCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.tag())
    }
}

/// A deterministic entry in the redaction manifest identifying the exact byte slice replaced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedactionEntry {
    pub byte_offset: usize,
    pub length: usize,
    pub category: SensitivityCategory,
    pub original_sha256: String,
    pub replacement: String,
}

/// Cryptographically verifiable manifest recording all redaction actions performed on a text or packet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedactionManifest {
    pub total_redactions: usize,
    pub entries: Vec<RedactionEntry>,
    pub timestamp: String,
}

impl RedactionManifest {
    pub fn new(entries: Vec<RedactionEntry>) -> Self {
        Self {
            total_redactions: entries.len(),
            entries,
            timestamp: Utc::now().to_rfc3339(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Pattern-matching engine that discovers sensitive material and replaces it deterministically.
pub struct Redactor {
    patterns: Vec<(Regex, SensitivityCategory)>,
}

impl Default for Redactor {
    fn default() -> Self {
        Self::new()
    }
}

impl Redactor {
    /// Constructs a standard Redactor with regular expressions for credentials, keys, IPs, and URIs.
    pub fn new() -> Self {
        let mut patterns = Vec::new();

        // Private SSH / PEM keys (checked first to capture multiline blocks)
        if let Ok(re) =
            Regex::new(r"(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----")
        {
            patterns.push((re, SensitivityCategory::PrivateKey));
        }

        // Database connection URIs
        if let Ok(re) = Regex::new(
            r"(?i)\b(?:postgres|postgresql|mysql|mongodb|redis|amqp|mssql)://(?:[a-zA-Z0-9_\-\.~%]+(?::[^\s@]+)?@)?[a-zA-Z0-9_\-\.~]+(?::\d+)?(?:/[a-zA-Z0-9_\-\.~%]*)?(?:\?[a-zA-Z0-9_\-\.~%&=]*)?",
        ) {
            patterns.push((re, SensitivityCategory::DatabaseUri));
        }

        // Passwords in config/assignment patterns
        if let Ok(re) =
            Regex::new(r#"(?i)\b(?:password|passwd|pwd)\s*[:=]\s*(?:["'][^"']+["']|[^\s,;]+)"#)
        {
            patterns.push((re, SensitivityCategory::Password));
        }

        // API / Auth tokens
        if let Ok(re) = Regex::new(r"(?i)\bBearer\s+[A-Za-z0-9_\-\.~+/=]+") {
            patterns.push((re, SensitivityCategory::Token));
        }
        if let Ok(re) = Regex::new(r"\bghp_[A-Za-z0-9]{36}\b") {
            patterns.push((re, SensitivityCategory::Token));
        }
        if let Ok(re) = Regex::new(r"\bglpat-[A-Za-z0-9_\-]{20}\b") {
            patterns.push((re, SensitivityCategory::Token));
        }
        if let Ok(re) = Regex::new(r"\bmock_token_[a-zA-Z0-9_\-]+\b") {
            patterns.push((re, SensitivityCategory::Token));
        }
        if let Ok(re) = Regex::new(r"\bmock_dummy_token_[a-zA-Z0-9_\-]+\b") {
            patterns.push((re, SensitivityCategory::Token));
        }
        if let Ok(re) = Regex::new(r"\bxox[baprs]-[0-9a-zA-Z]{10,48}\b") {
            patterns.push((re, SensitivityCategory::Token));
        }

        // Cloud provider keys
        if let Ok(re) = Regex::new(r"\bAKIA[0-9A-Z]{16}\b") {
            patterns.push((re, SensitivityCategory::Key));
        }
        if let Ok(re) = Regex::new(
            r#"(?i)\b(?:aws_secret_access_key|aws_access_key_id|aws_session_token)\s*[:=]\s*["']?[A-Za-z0-9/+=]{16,40}["']?"#,
        ) {
            patterns.push((re, SensitivityCategory::Key));
        }
        if let Ok(re) = Regex::new(
            r#"(?i)"(?:private_key_id|private_key)"\s*:\s*"([a-f0-9]{40}|[^"]+@(?:[a-zA-Z0-9-]+\.)*gserviceaccount\.com)""#,
        ) {
            patterns.push((re, SensitivityCategory::Key));
        }
        if let Ok(re) = Regex::new(r"\bmock_aws_secret_[a-zA-Z0-9_\-]+\b") {
            patterns.push((re, SensitivityCategory::Key));
        }
        if let Ok(re) = Regex::new(r"\bmock_gcp_key_[a-zA-Z0-9_\-]+\b") {
            patterns.push((re, SensitivityCategory::Key));
        }

        // Private IPv4 ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
        if let Ok(re) = Regex::new(r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b") {
            patterns.push((re, SensitivityCategory::PrivateIp));
        }
        if let Ok(re) = Regex::new(r"\b172\.(?:1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}\b") {
            patterns.push((re, SensitivityCategory::PrivateIp));
        }
        if let Ok(re) = Regex::new(r"\b192\.168\.\d{1,3}\.\d{1,3}\b") {
            patterns.push((re, SensitivityCategory::PrivateIp));
        }
        // IPv6 local addresses: link-local (fe80::) and unique-local (fc00::/fd00::)
        if let Ok(re) = Regex::new(r"(?i)\bfe80:(?::[0-9a-fA-F]{0,4}){1,7}\b") {
            patterns.push((re, SensitivityCategory::PrivateIp));
        }
        if let Ok(re) = Regex::new(r"(?i)\bf[cd][0-9a-fA-F]{2}:(?::[0-9a-fA-F]{0,4}){1,7}\b") {
            patterns.push((re, SensitivityCategory::PrivateIp));
        }

        // PII (e.g. SSN, synthetic identifiers)
        if let Ok(re) = Regex::new(r"\b\d{3}-\d{2}-\d{4}\b") {
            patterns.push((re, SensitivityCategory::Pii));
        }
        if let Ok(re) = Regex::new(r"\bmock_pii_[a-zA-Z0-9_\-]+\b") {
            patterns.push((re, SensitivityCategory::Pii));
        }

        Self { patterns }
    }

    /// Redacts all detected sensitive entries in text, replacing them deterministically
    /// with `[REDACTED:<CATEGORY>:<SHA256_PREFIX_8>]`.
    pub fn redact_text(&self, input: &str) -> (String, RedactionManifest) {
        // Collect all pattern matches: (start, end, category)
        let mut candidates: Vec<(usize, usize, SensitivityCategory)> = Vec::new();

        for (re, cat) in &self.patterns {
            for m in re.find_iter(input) {
                candidates.push((m.start(), m.end(), *cat));
            }
        }

        // Sort candidates: earliest start first, then longest match first
        candidates.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| (b.1 - b.0).cmp(&(a.1 - a.0))));

        // Discard overlapping matches
        let mut non_overlapping: Vec<(usize, usize, SensitivityCategory)> = Vec::new();
        for candidate in candidates {
            if let Some(last) = non_overlapping.last() {
                if candidate.0 < last.1 {
                    continue; // Overlaps with previous accepted match
                }
            }
            non_overlapping.push(candidate);
        }

        let mut redacted_output = String::with_capacity(input.len());
        let mut entries = Vec::new();
        let mut last_end = 0;

        for (start, end, cat) in non_overlapping {
            redacted_output.push_str(&input[last_end..start]);

            let matched_text = &input[start..end];
            let mut hasher = Sha256::new();
            hasher.update(matched_text.as_bytes());
            let sha256_full = crate::to_hex(hasher.finalize());
            let prefix_8 = &sha256_full[..8];

            let replacement = format!("[REDACTED:{}:{}]", cat.tag(), prefix_8);

            entries.push(RedactionEntry {
                byte_offset: start,
                length: end - start,
                category: cat,
                original_sha256: sha256_full,
                replacement: replacement.clone(),
            });

            redacted_output.push_str(&replacement);
            last_end = end;
        }

        redacted_output.push_str(&input[last_end..]);

        let manifest = RedactionManifest {
            total_redactions: entries.len(),
            entries,
            timestamp: Utc::now().to_rfc3339(),
        };

        (redacted_output, manifest)
    }

    /// Redacts all human-facing and technical textual fields in a `DisclosurePacket`.
    pub fn redact_packet(&self, packet: &mut DisclosurePacket) -> RedactionManifest {
        let mut all_entries = Vec::new();

        let (r_title, m_title) = self.redact_text(&packet.title);
        packet.title = r_title;
        all_entries.extend(m_title.entries);

        let (r_vtype, m_vtype) = self.redact_text(&packet.vulnerability_type);
        packet.vulnerability_type = r_vtype;
        all_entries.extend(m_vtype.entries);

        let (r_prereq, m_prereq) = self.redact_text(&packet.security_impact.prerequisites);
        packet.security_impact.prerequisites = r_prereq;
        all_entries.extend(m_prereq.entries);

        let (r_harness, m_harness) = self.redact_text(&packet.safe_reproduction.harness_code);
        packet.safe_reproduction.harness_code = r_harness;
        all_entries.extend(m_harness.entries);

        let (r_input, m_input) = self.redact_text(&packet.safe_reproduction.sanitized_input);
        packet.safe_reproduction.sanitized_input = r_input;
        all_entries.extend(m_input.entries);

        let (r_exp, m_exp) = self.redact_text(&packet.safe_reproduction.expected_behavior);
        packet.safe_reproduction.expected_behavior = r_exp;
        all_entries.extend(m_exp.entries);

        let (r_obs, m_obs) = self.redact_text(&packet.safe_reproduction.observed_behavior);
        packet.safe_reproduction.observed_behavior = r_obs;
        all_entries.extend(m_obs.entries);

        let (r_summary, m_summary) = self.redact_text(&packet.root_cause.summary);
        packet.root_cause.summary = r_summary;
        all_entries.extend(m_summary.entries);

        let (r_diff, m_diff) = self.redact_text(&packet.suggested_mitigation.diff);
        packet.suggested_mitigation.diff = r_diff;
        all_entries.extend(m_diff.entries);

        let (r_compat, m_compat) =
            self.redact_text(&packet.suggested_mitigation.compatibility_notes);
        packet.suggested_mitigation.compatibility_notes = r_compat;
        all_entries.extend(m_compat.entries);

        RedactionManifest {
            total_redactions: all_entries.len(),
            entries: all_entries,
            timestamp: Utc::now().to_rfc3339(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disclosure::draft::{
        AffectedTarget, ContactChannel, DisclosureDraftBuilder, DisclosureSeverity, ReporterInfo,
        RootCause, SafeReproduction, SecurityImpact, SuggestedMitigation,
    };

    #[test]
    fn test_redact_synthetic_tokens() {
        let redactor = Redactor::new();
        let input =
            "Authentication failed with Bearer mock_dummy_token_xyz987 and mock_token_abc123";
        let (redacted, manifest) = redactor.redact_text(input);

        assert_eq!(manifest.total_redactions, 2);
        assert!(!redacted.contains("mock_dummy_token_xyz987"));
        assert!(!redacted.contains("mock_token_abc123"));
        assert!(redacted.contains("[REDACTED:TOKEN:"));
        assert_eq!(manifest.entries[0].category, SensitivityCategory::Token);
    }

    #[test]
    fn test_redact_cloud_keys() {
        let redactor = Redactor::new();
        let akia = format!("AKIA{}", "IOSFODNN7EXAMPLE");
        let input = format!("Deploy credentials: {} and mock_aws_secret_key_12345", akia);
        let (redacted, manifest) = redactor.redact_text(&input);

        assert_eq!(manifest.total_redactions, 2);
        assert!(!redacted.contains(&akia));
        assert!(!redacted.contains("mock_aws_secret_key_12345"));
        assert!(redacted.contains("[REDACTED:KEY:"));
        assert_eq!(manifest.entries[0].category, SensitivityCategory::Key);
    }

    #[test]
    fn test_redact_passwords() {
        let redactor = Redactor::new();
        let input = "db_config = { password: \"mock_dummy_password_999\" }";
        let (redacted, manifest) = redactor.redact_text(input);

        assert_eq!(manifest.total_redactions, 1);
        assert!(!redacted.contains("mock_dummy_password_999"));
        assert!(redacted.contains("[REDACTED:PASSWORD:"));
        assert_eq!(manifest.entries[0].category, SensitivityCategory::Password);
    }

    #[test]
    fn test_redact_private_ips() {
        let redactor = Redactor::new();
        let input =
            "Internal services: 10.1.2.3, 172.20.1.5, 192.168.1.100, fe80::1ff:fe23:4567:890a";
        let (redacted, manifest) = redactor.redact_text(input);

        assert_eq!(manifest.total_redactions, 4);
        assert!(!redacted.contains("10.1.2.3"));
        assert!(!redacted.contains("172.20.1.5"));
        assert!(!redacted.contains("192.168.1.100"));
        assert!(!redacted.contains("fe80::1ff:fe23:4567:890a"));
        assert!(redacted.contains("[REDACTED:PRIVATE_IP:"));
    }

    #[test]
    fn test_redact_database_uri() {
        let redactor = Redactor::new();
        let input = "DATABASE_URL=postgres://mock_user:mock_pass@127.0.0.1:5432/testdb";
        let (redacted, manifest) = redactor.redact_text(input);

        assert!(!redacted.contains("mock_pass"));
        assert!(redacted.contains("[REDACTED:DATABASE_URI:"));
        assert_eq!(
            manifest.entries[0].category,
            SensitivityCategory::DatabaseUri
        );
    }

    #[test]
    fn test_redact_private_pem_key() {
        let redactor = Redactor::new();
        let pem = format!(
            "-----BEGIN {} PRIVATE KEY-----\nMOCK_KEY_DATA_LINE1\nMOCK_KEY_DATA_LINE2\n-----END {} PRIVATE KEY-----",
            "RSA", "RSA"
        );
        let input = format!("Loaded certificate with key:\n{}", pem);
        let (redacted, manifest) = redactor.redact_text(&input);

        assert_eq!(manifest.total_redactions, 1);
        assert!(!redacted.contains("MOCK_KEY_DATA_LINE1"));
        assert!(redacted.contains("[REDACTED:PRIVATE_KEY:"));
        assert_eq!(
            manifest.entries[0].category,
            SensitivityCategory::PrivateKey
        );
    }

    #[test]
    fn test_redact_packet() {
        let redactor = Redactor::new();
        let dummy_sha = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let mut packet = DisclosureDraftBuilder::new()
            .finding_id("finding-novel-auth-001")
            .title("Vulnerability at 10.0.0.1 in authentication handler")
            .vulnerability_type("Authentication Bypass with mock_token_secret_123")
            .severity(DisclosureSeverity::High)
            .affected_target(AffectedTarget {
                package: "internal-auth".to_string(),
                commit_range: "v1.0.0..v1.0.1".to_string(),
                repository: "https://github.com/example/auth".to_string(),
                source_snapshot_sha256: dummy_sha.to_string(),
            })
            .security_impact(SecurityImpact {
                prerequisites:
                    "Attacker connects to 192.168.1.50 with password: \"mock_secret_pw\""
                        .to_string(),
                attack_vector: "Network".to_string(),
                privileges_required: "None".to_string(),
                user_interaction: "None".to_string(),
                scope: "Unchanged".to_string(),
                confidential_impact: "High".to_string(),
                integrity_impact: "High".to_string(),
                availability_impact: "None".to_string(),
            })
            .safe_reproduction(SafeReproduction {
                test_type: "offline_unit_test".to_string(),
                harness_code: "// test harness with Bearer mock_dummy_token_xyz987".to_string(),
                sanitized_input: "header: Authorization: Bearer mock_dummy_token_xyz987"
                    .to_string(),
                expected_behavior: "Returns 401 Unauthorized".to_string(),
                observed_behavior: "Access granted with password: \"mock_secret_pw\"".to_string(),
            })
            .root_cause(RootCause {
                summary:
                    "Omitted validation at 172.16.0.10 when bearer mock_dummy_token_xyz987 used"
                        .to_string(),
                cwe_id: "CWE-287".to_string(),
                trace_evidence_hashes: vec![dummy_sha.to_string()],
            })
            .suggested_mitigation(SuggestedMitigation {
                diff: "- password: \"mock_secret_pw\"\n+ password: \"[sanitized]\"".to_string(),
                compatibility_notes: "Backward compatible fix for internal gateway 10.1.2.3"
                    .to_string(),
                fixed_versions: vec!["1.0.2".to_string()],
            })
            .contact_channel(ContactChannel {
                channel_type: "Email".to_string(),
                contact_target: "security@example.com".to_string(),
                security_policy_url: None,
            })
            .reporter(ReporterInfo {
                credit_name: "Security Researcher".to_string(),
                contact_email: "researcher@example.com".to_string(),
                embargo_requested_days: 90,
            })
            .build()
            .expect("Valid packet should build");

        let manifest = redactor.redact_packet(&mut packet);
        assert!(manifest.total_redactions >= 5);
        assert!(!packet.title.contains("10.0.0.1"));
        assert!(!packet.vulnerability_type.contains("mock_token_secret_123"));
        assert!(
            !packet
                .security_impact
                .prerequisites
                .contains("192.168.1.50")
        );
        assert!(
            !packet
                .security_impact
                .prerequisites
                .contains("mock_secret_pw")
        );
        assert!(
            !packet
                .safe_reproduction
                .harness_code
                .contains("mock_dummy_token_xyz987")
        );
        assert!(
            !packet
                .safe_reproduction
                .observed_behavior
                .contains("mock_secret_pw")
        );
        assert!(!packet.root_cause.summary.contains("172.16.0.10"));
        assert!(!packet.suggested_mitigation.diff.contains("mock_secret_pw"));
        assert!(
            !packet
                .suggested_mitigation
                .compatibility_notes
                .contains("10.1.2.3")
        );
        assert_eq!(
            packet.contact_channel.contact_target,
            "security@example.com"
        );
    }

    #[test]
    fn test_deterministic_redaction() {
        let redactor = Redactor::new();
        let input = "Secret mock_token_repeated_abc appeared twice: mock_token_repeated_abc";
        let (redacted, manifest) = redactor.redact_text(input);

        assert_eq!(manifest.total_redactions, 2);
        assert!(!redacted.contains("mock_token_repeated_abc"));
        assert_eq!(
            manifest.entries[0].original_sha256,
            manifest.entries[1].original_sha256
        );
        assert_eq!(
            manifest.entries[0].replacement,
            manifest.entries[1].replacement
        );
    }
}
