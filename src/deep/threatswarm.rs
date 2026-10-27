use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::time::Instant;

use chrono::Utc;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::engine::adapter::{AdapterCapabilities, AnalyzerAdapter};
use crate::engine::protocol::{
    AnalysisRequest, AnalysisResponse, CoverageReceiptStatus, CoverageReceiptV1, EngineDescriptor,
    EngineStatus, EvidenceCertaintyV1, EvidenceItemKind, EvidenceItemV1, FindingKind,
    FindingStatus, FindingV1, NormalizedSeverity, NormalizedTargetKind, ReceiptCounts,
    ResourceUsage, SourceSpanV1, TargetDescriptor,
};
use crate::engine::runner::{AnalysisError, CancellationToken};
use crate::types::{ScanProfile, TargetKind};

// =========================================================================
// 1. ThreatSwarm Scope Enforcer (Deterministic Network Boundary Defense)
// =========================================================================

/// A parsed scope definition entry from `scope.txt`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScopeEntry {
    /// IPv4 CIDR subnet (e.g. 10.0.0.0/8, 192.168.1.0/24)
    Ipv4Cidr { network: u32, mask: u32, prefix: u8 },
    /// Single IPv4 address (/32)
    Ipv4(u32),
    /// Single IPv6 address (/128)
    Ipv6([u8; 16]),
    /// Domain or FQDN suffix (e.g. "example.com", "*.internal.corp")
    Domain(String),
}

impl ScopeEntry {
    /// Matches an IPv4 address against this entry.
    pub fn matches_ipv4(&self, ip: u32) -> bool {
        match self {
            ScopeEntry::Ipv4Cidr { network, mask, .. } => (ip & mask) == (*network & mask),
            ScopeEntry::Ipv4(single) => ip == *single,
            _ => false,
        }
    }

    /// Matches an IPv6 address against this entry.
    pub fn matches_ipv6(&self, ip: &[u8; 16]) -> bool {
        match self {
            ScopeEntry::Ipv6(single) => ip == single,
            _ => false,
        }
    }

    /// Matches a domain or hostname against this entry.
    pub fn matches_domain(&self, domain: &str) -> bool {
        match self {
            ScopeEntry::Domain(allowed) => {
                let d_lower = domain.to_lowercase();
                let a_lower = allowed.to_lowercase();
                if d_lower == a_lower {
                    return true;
                }
                if let Some(suffix) = a_lower.strip_prefix("*.") {
                    return d_lower.ends_with(suffix);
                }
                d_lower.ends_with(&format!(".{}", a_lower))
            }
            _ => false,
        }
    }
}

/// Scope boundary violation report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeViolation {
    pub target: String,
    pub command_snippet: String,
    pub scope_file: Option<String>,
    pub reason: String,
}

static RE_NETWORK_COMMANDS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:nmap|nuclei|httpx|feroxbuster|ffuf|gobuster|nikto|sqlmap|curl|wget|ssh|sftp|ftp|telnet|netcat|ncat|nc|tcpdump|tshark|wireshark|grpcurl)\b").unwrap()
});

static RE_IP: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b").unwrap()
});

static RE_HOST: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+(?:\.[a-zA-Z]{2,}))\b").unwrap()
});

/// High-performance scope verification engine enforcing zero unauthorized network egress.
#[derive(Debug, Clone, Default)]
pub struct ThreatswarmScopeEnforcer {
    entries: Vec<ScopeEntry>,
    scope_path: Option<PathBuf>,
}

impl ThreatswarmScopeEnforcer {
    /// Creates a new scope enforcer with an empty scope list.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            scope_path: None,
        }
    }

    /// Loads scope rules from standard `scope.txt` file content.
    pub fn load_from_str(content: &str) -> Self {
        let mut entries = Vec::new();
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            if let Some(entry) = Self::parse_scope_line(trimmed) {
                entries.push(entry);
            }
        }
        Self {
            entries,
            scope_path: None,
        }
    }

    /// Loads scope rules from a file path on disk.
    pub fn load_from_file(path: impl AsRef<Path>) -> Result<Self, String> {
        let p = path.as_ref();
        let content = fs::read_to_string(p)
            .map_err(|e| format!("Failed to read scope file '{}': {}", p.display(), e))?;
        let mut enforcer = Self::load_from_str(&content);
        enforcer.scope_path = Some(p.to_path_buf());
        Ok(enforcer)
    }

    /// Parses a single line from scope.txt into a typed ScopeEntry.
    pub fn parse_scope_line(line: &str) -> Option<ScopeEntry> {
        let cleaned = line.trim();
        if cleaned.is_empty() {
            return None;
        }

        // 1. Try IPv4 with CIDR prefix (e.g. 10.0.0.0/8, 192.168.1.0/24)
        if let Some((ip_str, prefix_str)) = cleaned.split_once('/') {
            if let Ok(prefix) = prefix_str.parse::<u8>() {
                if prefix <= 32 {
                    if let Ok(v4) = ip_str.parse::<std::net::Ipv4Addr>() {
                        let ip_u32 = u32::from_be_bytes(v4.octets());
                        let mask = if prefix == 0 {
                            0u32
                        } else {
                            !((1u32 << (32 - prefix)) - 1)
                        };
                        return Some(ScopeEntry::Ipv4Cidr {
                            network: ip_u32 & mask,
                            mask,
                            prefix,
                        });
                    }
                }
            }
        }

        // 2. Try single IP address
        if let Ok(addr) = cleaned.parse::<IpAddr>() {
            match addr {
                IpAddr::V4(v4) => return Some(ScopeEntry::Ipv4(u32::from_be_bytes(v4.octets()))),
                IpAddr::V6(v6) => return Some(ScopeEntry::Ipv6(v6.octets())),
            }
        }

        // 3. Fallback to domain/hostname
        Some(ScopeEntry::Domain(cleaned.to_lowercase()))
    }

    /// Checks whether a given target (IP or hostname) is localhost / loopback.
    pub fn is_localhost(target: &str) -> bool {
        let t = target.trim().to_lowercase();
        if t == "localhost" || t == "127.0.0.1" || t == "::1" || t == "0.0.0.0" {
            return true;
        }
        if t.starts_with("127.") {
            return true;
        }
        if let Ok(addr) = t.parse::<IpAddr>() {
            return addr.is_loopback() || addr == IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0));
        }
        false
    }

    /// Evaluates whether a target host or IP is explicitly authorized within the active scope.
    pub fn is_in_scope(&self, target: &str) -> bool {
        let t = target.trim();
        if Self::is_localhost(t) {
            return true;
        }

        if let Ok(addr) = t.parse::<IpAddr>() {
            match addr {
                IpAddr::V4(v4) => {
                    let ip_u32 = u32::from_be_bytes(v4.octets());
                    return self.entries.iter().any(|e| e.matches_ipv4(ip_u32));
                }
                IpAddr::V6(v6) => {
                    let octets = v6.octets();
                    return self.entries.iter().any(|e| e.matches_ipv6(&octets));
                }
            }
        }

        self.entries.iter().any(|e| e.matches_domain(t))
    }

    /// Detects if a shell command string invokes tools requiring external network connectivity.
    pub fn is_network_command(command: &str) -> bool {
        RE_NETWORK_COMMANDS.is_match(command)
    }

    /// Extracts potential network targets (IP addresses and FQDN hostnames) from a command string.
    pub fn extract_targets(command: &str) -> (Vec<String>, Vec<String>) {
        let mut ips = Vec::new();
        for mat in RE_IP.find_iter(command) {
            ips.push(mat.as_str().to_string());
        }

        let mut hosts = Vec::new();
        for cap in RE_HOST.captures_iter(command) {
            if let Some(m) = cap.get(1) {
                let h = m.as_str().trim();
                let lower = h.to_lowercase();
                // Filter false positives (file names, versions, code calls)
                let is_file_ext = lower.ends_with(".log")
                    || lower.ends_with(".json")
                    || lower.ends_with(".txt")
                    || lower.ends_with(".py")
                    || lower.ends_with(".rs")
                    || lower.ends_with(".js")
                    || lower.ends_with(".ts")
                    || lower.ends_with(".sh")
                    || lower.ends_with(".tar")
                    || lower.ends_with(".gz")
                    || lower.ends_with(".zip");
                let is_version = lower.chars().all(|c| c.is_ascii_digit() || c == '.');
                let is_code_call = lower.contains("stdout.") || lower.contains("stderr.");

                if !is_file_ext && !is_version && !is_code_call && !h.is_empty() {
                    hosts.push(h.to_string());
                }
            }
        }

        (ips, hosts)
    }

    /// Verifies a command string against the scope rules. Returns Err on any out-of-scope target.
    pub fn verify_command(&self, command: &str) -> Result<(), ScopeViolation> {
        if !Self::is_network_command(command) {
            return Ok(());
        }

        let (ips, hosts) = Self::extract_targets(command);
        let all_targets: Vec<String> = ips.into_iter().chain(hosts).collect();

        if all_targets.is_empty() {
            return Ok(());
        }

        for target in all_targets {
            if !self.is_in_scope(&target) {
                return Err(ScopeViolation {
                    target: target.clone(),
                    command_snippet: command.chars().take(120).collect(),
                    scope_file: self.scope_path.as_ref().map(|p| p.display().to_string()),
                    reason: format!(
                        "Target '{}' is not present in authorized scope definition",
                        target
                    ),
                });
            }
        }

        Ok(())
    }

    pub fn entries_count(&self) -> usize {
        self.entries.len()
    }
}

// =========================================================================
// 2. CVSS 3.1 Vector & Scoring Engine
// =========================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttackVector {
    Network,
    Adjacent,
    Local,
    Physical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttackComplexity {
    Low,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PrivilegesRequired {
    None,
    Low,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UserInteraction {
    None,
    Required,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Scope {
    Unchanged,
    Changed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ImpactMetric {
    None,
    Low,
    High,
}

/// A parsed CVSS v3.1 vector representation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CvssVector {
    pub attack_vector: AttackVector,
    pub attack_complexity: AttackComplexity,
    pub privileges_required: PrivilegesRequired,
    pub user_interaction: UserInteraction,
    pub scope: Scope,
    pub confidentiality: ImpactMetric,
    pub integrity: ImpactMetric,
    pub availability: ImpactMetric,
}

impl Default for CvssVector {
    fn default() -> Self {
        Self {
            attack_vector: AttackVector::Network,
            attack_complexity: AttackComplexity::Low,
            privileges_required: PrivilegesRequired::None,
            user_interaction: UserInteraction::None,
            scope: Scope::Unchanged,
            confidentiality: ImpactMetric::High,
            integrity: ImpactMetric::High,
            availability: ImpactMetric::High,
        }
    }
}

impl CvssVector {
    /// Parses a standard CVSS 3.1 vector string (e.g. `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`).
    pub fn parse(vector_str: &str) -> Result<Self, String> {
        let mut av = None;
        let mut ac = None;
        let mut pr = None;
        let mut ui = None;
        let mut s = None;
        let mut c = None;
        let mut i = None;
        let mut a = None;

        let parts: Vec<&str> = vector_str.split('/').collect();
        for part in parts {
            let (key, val) = part
                .split_once(':')
                .ok_or_else(|| format!("Invalid metric token '{}'", part))?;
            match key.trim().to_uppercase().as_str() {
                "CVSS" => {} // prefix check
                "AV" => {
                    av = Some(match val.trim().to_uppercase().as_str() {
                        "N" => AttackVector::Network,
                        "A" => AttackVector::Adjacent,
                        "L" => AttackVector::Local,
                        "P" => AttackVector::Physical,
                        other => return Err(format!("Unknown AV value: {}", other)),
                    })
                }
                "AC" => {
                    ac = Some(match val.trim().to_uppercase().as_str() {
                        "L" => AttackComplexity::Low,
                        "H" => AttackComplexity::High,
                        other => return Err(format!("Unknown AC value: {}", other)),
                    })
                }
                "PR" => {
                    pr = Some(match val.trim().to_uppercase().as_str() {
                        "N" => PrivilegesRequired::None,
                        "L" => PrivilegesRequired::Low,
                        "H" => PrivilegesRequired::High,
                        other => return Err(format!("Unknown PR value: {}", other)),
                    })
                }
                "UI" => {
                    ui = Some(match val.trim().to_uppercase().as_str() {
                        "N" => UserInteraction::None,
                        "R" => UserInteraction::Required,
                        other => return Err(format!("Unknown UI value: {}", other)),
                    })
                }
                "S" => {
                    s = Some(match val.trim().to_uppercase().as_str() {
                        "U" => Scope::Unchanged,
                        "C" => Scope::Changed,
                        other => return Err(format!("Unknown S value: {}", other)),
                    })
                }
                "C" => {
                    c = Some(match val.trim().to_uppercase().as_str() {
                        "N" => ImpactMetric::None,
                        "L" => ImpactMetric::Low,
                        "H" => ImpactMetric::High,
                        other => return Err(format!("Unknown C value: {}", other)),
                    })
                }
                "I" => {
                    i = Some(match val.trim().to_uppercase().as_str() {
                        "N" => ImpactMetric::None,
                        "L" => ImpactMetric::Low,
                        "H" => ImpactMetric::High,
                        other => return Err(format!("Unknown I value: {}", other)),
                    })
                }
                "A" => {
                    a = Some(match val.trim().to_uppercase().as_str() {
                        "N" => ImpactMetric::None,
                        "L" => ImpactMetric::Low,
                        "H" => ImpactMetric::High,
                        other => return Err(format!("Unknown A value: {}", other)),
                    })
                }
                _ => {}
            }
        }

        Ok(Self {
            attack_vector: av.ok_or("Missing AV metric")?,
            attack_complexity: ac.ok_or("Missing AC metric")?,
            privileges_required: pr.ok_or("Missing PR metric")?,
            user_interaction: ui.ok_or("Missing UI metric")?,
            scope: s.ok_or("Missing S metric")?,
            confidentiality: c.ok_or("Missing C metric")?,
            integrity: i.ok_or("Missing I metric")?,
            availability: a.ok_or("Missing A metric")?,
        })
    }

    /// Formats this struct back into canonical CVSS:3.1 vector string.
    pub fn to_vector_string(&self) -> String {
        format!(
            "CVSS:3.1/AV:{}/AC:{}/PR:{}/UI:{}/S:{}/C:{}/I:{}/A:{}",
            match self.attack_vector {
                AttackVector::Network => "N",
                AttackVector::Adjacent => "A",
                AttackVector::Local => "L",
                AttackVector::Physical => "P",
            },
            match self.attack_complexity {
                AttackComplexity::Low => "L",
                AttackComplexity::High => "H",
            },
            match self.privileges_required {
                PrivilegesRequired::None => "N",
                PrivilegesRequired::Low => "L",
                PrivilegesRequired::High => "H",
            },
            match self.user_interaction {
                UserInteraction::None => "N",
                UserInteraction::Required => "R",
            },
            match self.scope {
                Scope::Unchanged => "U",
                Scope::Changed => "C",
            },
            match self.confidentiality {
                ImpactMetric::None => "N",
                ImpactMetric::Low => "L",
                ImpactMetric::High => "H",
            },
            match self.integrity {
                ImpactMetric::None => "N",
                ImpactMetric::Low => "L",
                ImpactMetric::High => "H",
            },
            match self.availability {
                ImpactMetric::None => "N",
                ImpactMetric::Low => "L",
                ImpactMetric::High => "H",
            }
        )
    }

    /// Computes the standard CVSS 3.1 Base Score.
    pub fn calculate_score(&self) -> f64 {
        let av_score = match self.attack_vector {
            AttackVector::Network => 0.85,
            AttackVector::Adjacent => 0.62,
            AttackVector::Local => 0.55,
            AttackVector::Physical => 0.20,
        };

        let ac_score = match self.attack_complexity {
            AttackComplexity::Low => 0.77,
            AttackComplexity::High => 0.44,
        };

        let pr_score = match (self.scope, self.privileges_required) {
            (Scope::Unchanged, PrivilegesRequired::None) => 0.85,
            (Scope::Unchanged, PrivilegesRequired::Low) => 0.62,
            (Scope::Unchanged, PrivilegesRequired::High) => 0.27,
            (Scope::Changed, PrivilegesRequired::None) => 0.85,
            (Scope::Changed, PrivilegesRequired::Low) => 0.68,
            (Scope::Changed, PrivilegesRequired::High) => 0.50,
        };

        let ui_score = match self.user_interaction {
            UserInteraction::None => 0.85,
            UserInteraction::Required => 0.62,
        };

        let c_score = match self.confidentiality {
            ImpactMetric::None => 0.0,
            ImpactMetric::Low => 0.22,
            ImpactMetric::High => 0.56,
        };

        let i_score = match self.integrity {
            ImpactMetric::None => 0.0,
            ImpactMetric::Low => 0.22,
            ImpactMetric::High => 0.56,
        };

        let a_score = match self.availability {
            ImpactMetric::None => 0.0,
            ImpactMetric::Low => 0.22,
            ImpactMetric::High => 0.56,
        };

        let iss = 1.0 - ((1.0 - c_score) * (1.0 - i_score) * (1.0 - a_score));

        let impact = match self.scope {
            Scope::Unchanged => 6.42 * iss,
            Scope::Changed => {
                let term: f64 = iss - 0.029;
                let sub: f64 = 3.25 * (iss - 0.02_f64).powi(15);
                7.52 * term - sub
            }
        };

        let exploitability: f64 = 8.22 * av_score * ac_score * pr_score * ui_score;

        if impact <= 0.0 {
            return 0.0;
        }

        let raw_score: f64 = match self.scope {
            Scope::Unchanged => f64::min(impact + exploitability, 10.0),
            Scope::Changed => f64::min(1.08 * (impact + exploitability), 10.0),
        };

        Self::roundup(raw_score)
    }

    /// CVSS 3.1 Roundup function (ceil to nearest 0.1).
    fn roundup(val: f64) -> f64 {
        let int_val = (val * 100_000.0).round() as i64;
        if int_val % 10_000 == 0 {
            (int_val as f64) / 100_000.0
        } else {
            (((int_val / 10_000) + 1) as f64) / 10.0
        }
    }

    /// Maps calculated base score to NormalizedSeverity tier.
    pub fn severity_tier(&self) -> NormalizedSeverity {
        let score = self.calculate_score();
        if score >= 9.0 {
            NormalizedSeverity::Critical
        } else if score >= 7.0 {
            NormalizedSeverity::High
        } else if score >= 4.0 {
            NormalizedSeverity::Medium
        } else if score >= 0.1 {
            NormalizedSeverity::Low
        } else {
            NormalizedSeverity::Info
        }
    }

    /// Returns prebuilt canonical vector for common weakness patterns.
    pub fn prebuilt_for_pattern(pattern: &str) -> Self {
        match pattern.to_lowercase().as_str() {
            "pre-auth-rce" | "rce" | "php2shell" => Self {
                attack_vector: AttackVector::Network,
                attack_complexity: AttackComplexity::Low,
                privileges_required: PrivilegesRequired::None,
                user_interaction: UserInteraction::None,
                scope: Scope::Unchanged,
                confidentiality: ImpactMetric::High,
                integrity: ImpactMetric::High,
                availability: ImpactMetric::High,
            },
            "post-auth-rce" => Self {
                attack_vector: AttackVector::Network,
                attack_complexity: AttackComplexity::Low,
                privileges_required: PrivilegesRequired::Low,
                user_interaction: UserInteraction::None,
                scope: Scope::Unchanged,
                confidentiality: ImpactMetric::High,
                integrity: ImpactMetric::High,
                availability: ImpactMetric::High,
            },
            "sqli" | "sql-injection" => Self {
                attack_vector: AttackVector::Network,
                attack_complexity: AttackComplexity::Low,
                privileges_required: PrivilegesRequired::Low,
                user_interaction: UserInteraction::None,
                scope: Scope::Unchanged,
                confidentiality: ImpactMetric::High,
                integrity: ImpactMetric::High,
                availability: ImpactMetric::None,
            },
            "ssrf" | "server-side-request-forgery" => Self {
                attack_vector: AttackVector::Network,
                attack_complexity: AttackComplexity::Low,
                privileges_required: PrivilegesRequired::None,
                user_interaction: UserInteraction::None,
                scope: Scope::Changed,
                confidentiality: ImpactMetric::High,
                integrity: ImpactMetric::High,
                availability: ImpactMetric::None,
            },
            "idor" => Self {
                attack_vector: AttackVector::Network,
                attack_complexity: AttackComplexity::Low,
                privileges_required: PrivilegesRequired::Low,
                user_interaction: UserInteraction::None,
                scope: Scope::Unchanged,
                confidentiality: ImpactMetric::High,
                integrity: ImpactMetric::None,
                availability: ImpactMetric::None,
            },
            "lpe" | "privesc" => Self {
                attack_vector: AttackVector::Local,
                attack_complexity: AttackComplexity::Low,
                privileges_required: PrivilegesRequired::Low,
                user_interaction: UserInteraction::None,
                scope: Scope::Unchanged,
                confidentiality: ImpactMetric::High,
                integrity: ImpactMetric::High,
                availability: ImpactMetric::High,
            },
            _ => Self::default(),
        }
    }
}

/// CVSS v3.1 calculation and remediation planning engine.
pub struct ThreatswarmCvssEngine;

impl ThreatswarmCvssEngine {
    /// Computes the standard CVSS v3.1 score for a vector string.
    pub fn score_vector(vector_str: &str) -> Result<f64, String> {
        let vec = CvssVector::parse(vector_str)?;
        Ok(vec.calculate_score())
    }

    /// Evaluates recommended remediation SLA in hours based on normalized severity tier.
    pub fn remediation_sla_hours(severity: NormalizedSeverity) -> u32 {
        match severity {
            NormalizedSeverity::Critical => 24,
            NormalizedSeverity::High => 72,
            NormalizedSeverity::Medium => 168,
            NormalizedSeverity::Low => 720,
            NormalizedSeverity::Info | NormalizedSeverity::Unknown => 2160,
        }
    }

    /// Formats an executive risk profile with score, tier, and remediation target.
    pub fn format_risk_profile(vector: &CvssVector) -> String {
        let score = vector.calculate_score();
        let tier = vector.severity_tier();
        let sla = Self::remediation_sla_hours(tier);
        format!(
            "CVSS:3.1 Base Score: {:.1} ({:?}) | SLA Target: {} hours | Vector: {}",
            score,
            tier,
            sla,
            vector.to_vector_string()
        )
    }
}

// =========================================================================
// 3. MITRE ATT&CK Catalog & Technique Mapper
// =========================================================================

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MitreTechnique {
    pub id: String,
    pub name: String,
    pub tactic: String,
    pub description: String,
}

#[derive(Debug, Clone, Default)]
pub struct ThreatswarmMitreCatalog {
    techniques: BTreeMap<String, MitreTechnique>,
}

impl ThreatswarmMitreCatalog {
    /// Builds the curated MITRE ATT&CK enterprise catalog.
    pub fn new() -> Self {
        let mut techniques = BTreeMap::new();
        let entries = [
            (
                "T1595",
                "Active Scanning",
                "Reconnaissance",
                "Scanning network infrastructure for open ports, versions, and vulnerabilities.",
            ),
            (
                "T1190",
                "Exploit Public-Facing Application",
                "Initial Access",
                "Exploitation of software vulnerabilities in Internet-facing web servers or APIs.",
            ),
            (
                "T1059",
                "Command and Scripting Interpreter",
                "Execution",
                "Executing arbitrary commands via bash, sh, python, powershell, or node.",
            ),
            (
                "T1078",
                "Valid Accounts",
                "Initial Access",
                "Adversaries obtaining and abusing credentials of existing accounts.",
            ),
            (
                "T1003",
                "OS Credential Dumping",
                "Credential Access",
                "Extracting plaintext credentials, tokens, or hashes from process memory or files.",
            ),
            (
                "T1021",
                "Remote Services",
                "Lateral Movement",
                "Validating remote management protocols (SSH, SMB, RDP, WinRM) across subnets.",
            ),
            (
                "T1068",
                "Exploitation for Privilege Escalation",
                "Privilege Escalation",
                "Leveraging system vulnerabilities or misconfigurations to gain elevated privileges.",
            ),
            (
                "T1055",
                "Process Injection",
                "Defense Evasion",
                "Injecting code into processes to evade process-based defenses.",
            ),
            (
                "T1027",
                "Obfuscated Files or Information",
                "Defense Evasion",
                "Hiding malicious payloads or command strings via encoding or compression.",
            ),
            (
                "T1562",
                "Impair Defenses",
                "Defense Evasion",
                "Disabling audit logging, safety guards, or virtual patching hooks.",
            ),
            (
                "T1486",
                "Data Encrypted for Impact",
                "Impact",
                "Encrypting target assets to interrupt operational availability.",
            ),
            (
                "T1110",
                "Brute Force",
                "Credential Access",
                "Attempting automated password guessing or spraying across user endpoints.",
            ),
            (
                "T1046",
                "Network Service Discovery",
                "Discovery",
                "Enumerating listening services and daemon fingerprints.",
            ),
            (
                "T1071",
                "Application Layer Protocol",
                "Command and Control",
                "Standard web protocol communication (HTTP/HTTPS, DNS) for exfiltration or C2.",
            ),
            (
                "T1083",
                "File and Directory Discovery",
                "Discovery",
                "Adversaries enumerating files and directories on a system to find sensitive assets or traversal paths.",
            ),
            (
                "T1005",
                "Data from Local System",
                "Collection",
                "Adversaries extracting sensitive data from local system files, configurations, and paths.",
            ),
        ];

        for (id, name, tactic, desc) in entries {
            techniques.insert(
                id.to_string(),
                MitreTechnique {
                    id: id.to_string(),
                    name: name.to_string(),
                    tactic: tactic.to_string(),
                    description: desc.to_string(),
                },
            );
        }

        Self { techniques }
    }

    /// Number of indexed MITRE ATT&CK techniques.
    pub fn len(&self) -> usize {
        self.techniques.len()
    }

    /// Whether catalog has zero techniques.
    pub fn is_empty(&self) -> bool {
        self.techniques.is_empty()
    }

    /// Retrieves technique details by ID (e.g. "T1190").
    pub fn get(&self, id: &str) -> Option<&MitreTechnique> {
        self.techniques.get(id)
    }

    /// Maps CWE identifiers or vulnerability classes to corresponding ATT&CK techniques.
    pub fn map_cwe(&self, cwe: &str) -> Vec<&MitreTechnique> {
        let upper = cwe.to_uppercase();
        let target_ids: &[&str] = if upper.contains("CWE-78") || upper.contains("CWE-77") {
            &["T1059"] // Command injection
        } else if upper.contains("CWE-89") || upper.contains("CWE-943") {
            &["T1190"] // SQL injection / Exploit public-facing app
        } else if upper.contains("CWE-918") {
            &["T1190", "T1046"] // SSRF
        } else if upper.contains("CWE-798") || upper.contains("CWE-259") {
            &["T1078"] // Hardcoded credentials / Valid accounts
        } else if upper.contains("CWE-122")
            || upper.contains("CWE-787")
            || upper.contains("CWE-120")
        {
            &["T1190", "T1068"] // Buffer overflow / Memory corruption RCE
        } else if upper.contains("CWE-22") || upper.contains("CWE-23") {
            &["T1083", "T1005"] // Path traversal / File disclosure
        } else {
            &["T1190"]
        };

        target_ids.iter().filter_map(|&id| self.get(id)).collect()
    }
}

// =========================================================================
// 4. Finding Synchronizer & Reporter
// =========================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingSyncSummary {
    pub total_critical: usize,
    pub total_high: usize,
    pub scanned_files: usize,
    pub critical_findings: Vec<String>,
    pub high_findings: Vec<String>,
    pub generated_at: String,
}

pub struct ThreatswarmFindingSync;

impl ThreatswarmFindingSync {
    /// Scans a directory for findings markdown files and generates an aggregated summary.
    pub fn sync_directory(dir: &Path) -> Result<FindingSyncSummary, String> {
        if !dir.exists() {
            return Err(format!("Directory '{}' does not exist", dir.display()));
        }

        let mut critical_findings = Vec::new();
        let mut high_findings = Vec::new();
        let mut scanned_files = 0;
        let mut seen = HashSet::new();

        let walker = walkdir::WalkDir::new(dir).follow_links(false);
        for entry in walker.into_iter().filter_map(|e| e.ok()) {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }

            let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if file_name.ends_with(".md")
                && (file_name.contains("finding")
                    || file_name.contains("report")
                    || file_name.contains("vuln"))
                && file_name != "FINDINGS_SUMMARY.md"
            {
                scanned_files += 1;
                if let Ok(content) = fs::read_to_string(path) {
                    for line in content.lines() {
                        let trimmed = line.trim();
                        if trimmed.is_empty() {
                            continue;
                        }
                        if trimmed.to_uppercase().contains("[CRITICAL]")
                            || trimmed.to_uppercase().contains("SEVERITY: CRITICAL")
                        {
                            if seen.insert(trimmed.to_string()) {
                                critical_findings.push(format!(
                                    "{} (source: {})",
                                    trimmed,
                                    path.display()
                                ));
                            }
                        } else if trimmed.to_uppercase().contains("[HIGH]")
                            || trimmed.to_uppercase().contains("SEVERITY: HIGH")
                        {
                            if seen.insert(trimmed.to_string()) {
                                high_findings.push(format!(
                                    "{} (source: {})",
                                    trimmed,
                                    path.display()
                                ));
                            }
                        }
                    }
                }
            }
        }

        let summary = FindingSyncSummary {
            total_critical: critical_findings.len(),
            total_high: high_findings.len(),
            scanned_files,
            critical_findings,
            high_findings,
            generated_at: Utc::now().to_rfc3339(),
        };

        Ok(summary)
    }

    /// Extracts, filters, and deduplicates findings from markdown text.
    pub fn sync_markdown_content(content: &str, source_name: &str) -> FindingSyncSummary {
        let mut critical_findings = Vec::new();
        let mut high_findings = Vec::new();
        let mut seen = HashSet::new();

        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if trimmed.to_uppercase().contains("[CRITICAL]")
                || trimmed.to_uppercase().contains("SEVERITY: CRITICAL")
            {
                if seen.insert(trimmed.to_string()) {
                    critical_findings.push(format!("{} (source: {})", trimmed, source_name));
                }
            } else if trimmed.to_uppercase().contains("[HIGH]")
                || trimmed.to_uppercase().contains("SEVERITY: HIGH")
            {
                if seen.insert(trimmed.to_string()) {
                    high_findings.push(format!("{} (source: {})", trimmed, source_name));
                }
            }
        }

        FindingSyncSummary {
            total_critical: critical_findings.len(),
            total_high: high_findings.len(),
            scanned_files: 1,
            critical_findings,
            high_findings,
            generated_at: Utc::now().to_rfc3339(),
        }
    }

    /// Generates markdown report content for a findings summary.
    pub fn generate_summary_markdown(summary: &FindingSyncSummary) -> String {
        let mut md = String::new();
        md.push_str("# ThreatSwarm Findings Summary\n\n");
        md.push_str(&format!("Generated at: {}\n", summary.generated_at));
        md.push_str(&format!(
            "Evidence Files Scanned: {}\n\n",
            summary.scanned_files
        ));
        md.push_str(&format!(
            "### Risk Overview: {} Critical | {} High\n\n",
            summary.total_critical, summary.total_high
        ));

        if !summary.critical_findings.is_empty() {
            md.push_str("## 🚨 Critical Severity Findings\n\n");
            for c in &summary.critical_findings {
                md.push_str(&format!("- {}\n", c));
            }
            md.push('\n');
        }

        if !summary.high_findings.is_empty() {
            md.push_str("## ⚠️ High Severity Findings\n\n");
            for h in &summary.high_findings {
                md.push_str(&format!("- {}\n", h));
            }
            md.push('\n');
        }

        if summary.total_critical == 0 && summary.total_high == 0 {
            md.push_str("No active Critical or High findings identified in the evidence set.\n");
        }

        md
    }

    /// Writes the synchronized findings report to `FINDINGS_SUMMARY.md`.
    pub fn write_summary_markdown(
        summary: &FindingSyncSummary,
        out_path: &Path,
    ) -> Result<(), std::io::Error> {
        let md = Self::generate_summary_markdown(summary);
        fs::write(out_path, md)
    }
}

// =========================================================================
// 5. ThreatSwarm Deep Engine Analyzer Adapter
// =========================================================================

/// ThreatSwarm deep defensive intelligence and scope enforcement analyzer adapter.
#[derive(Debug, Clone)]
pub struct ThreatswarmAdapter {
    engine_id: String,
    engine_version: String,
    scope_enforcer: ThreatswarmScopeEnforcer,
    mitre_catalog: ThreatswarmMitreCatalog,
}

impl Default for ThreatswarmAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl ThreatswarmAdapter {
    pub fn new() -> Self {
        Self {
            engine_id: "threatswarm-deep-adapter".to_string(),
            engine_version: "1.0.0".to_string(),
            scope_enforcer: ThreatswarmScopeEnforcer::new(),
            mitre_catalog: ThreatswarmMitreCatalog::new(),
        }
    }

    pub fn with_scope(scope_file: impl AsRef<Path>) -> Result<Self, String> {
        let enforcer = ThreatswarmScopeEnforcer::load_from_file(scope_file)?;
        Ok(Self {
            engine_id: "threatswarm-deep-adapter".to_string(),
            engine_version: "1.0.0".to_string(),
            scope_enforcer: enforcer,
            mitre_catalog: ThreatswarmMitreCatalog::new(),
        })
    }

    /// Returns reference to scope enforcer.
    pub fn scope_enforcer(&self) -> &ThreatswarmScopeEnforcer {
        &self.scope_enforcer
    }

    /// Returns reference to MITRE ATT&CK catalog.
    pub fn mitre_catalog(&self) -> &ThreatswarmMitreCatalog {
        &self.mitre_catalog
    }

    /// Evaluates a source line against ThreatSwarm defensive heuristics.
    fn check_line(
        &self,
        run_id: &str,
        snapshot_sha256: &str,
        file_path: &str,
        line_num: usize,
        line: &str,
    ) -> Option<FindingV1> {
        let trimmed = line.trim();

        // 1. Unbounded egress / out-of-scope curl/fetch/http
        let is_egress_call = (trimmed.contains("curl ") || trimmed.contains("wget "))
            && (trimmed.contains("http://") || trimmed.contains("https://"));
        if is_egress_call {
            let (ips, hosts) = ThreatswarmScopeEnforcer::extract_targets(trimmed);
            let mut violated_target = None;
            for t in ips.into_iter().chain(hosts) {
                if !self.scope_enforcer.is_in_scope(&t) {
                    violated_target = Some(t);
                    break;
                }
            }

            if let Some(target) = violated_target {
                let cvss = CvssVector::prebuilt_for_pattern("ssrf");
                let vector_str = cvss.to_vector_string();
                let tech = self.mitre_catalog.get("T1190");

                let finding_id = {
                    let mut h = Sha256::new();
                    h.update(run_id.as_bytes());
                    h.update(file_path.as_bytes());
                    h.update((line_num as u64).to_be_bytes());
                    crate::to_hex(h.finalize())
                };

                let mut extensions = serde_json::Map::new();
                extensions.insert(
                    "cvss_vector".to_string(),
                    serde_json::Value::String(vector_str.clone()),
                );
                extensions.insert(
                    "cvss_score".to_string(),
                    serde_json::json!(cvss.calculate_score()),
                );
                if let Some(t) = tech {
                    extensions.insert(
                        "mitre_technique_id".to_string(),
                        serde_json::Value::String(t.id.clone()),
                    );
                    extensions.insert(
                        "mitre_technique_name".to_string(),
                        serde_json::Value::String(t.name.clone()),
                    );
                    extensions.insert(
                        "mitre_tactic".to_string(),
                        serde_json::Value::String(t.tactic.clone()),
                    );
                }

                let span = SourceSpanV1 {
                    start_line: line_num as u32,
                    end_line: line_num as u32,
                    start_column: Some(1),
                    end_column: Some(trimmed.len() as u32),
                };

                let target_desc = TargetDescriptor {
                    target_id: file_path.to_string(),
                    kind: NormalizedTargetKind::File,
                    path: Some(file_path.to_string()),
                    package_purl: None,
                    version: None,
                    span: Some(span),
                };

                let receipt_id = format!(
                    "ts-rcpt-{}-{}",
                    &snapshot_sha256[..8.min(snapshot_sha256.len())],
                    line_num
                );

                return Some(FindingV1 {
                    schema_version: "1.0".to_string(),
                    run_id: run_id.to_string(),
                    finding_id: finding_id.clone(),
                    fingerprint: Some(finding_id),
                    kind: FindingKind::Catalog,
                    status: FindingStatus::Suspected,
                    title: format!("Unauthorized Network Egress Target '{}'", target),
                    summary: Some(format!(
                        "Outbound network call to '{}' outside authorized scope boundary",
                        target
                    )),
                    severity: NormalizedSeverity::High,
                    evidence_certainty: EvidenceCertaintyV1::StronglySupported,
                    rule_id: Some("threatswarm.scope.unauthorized_egress".to_string()),
                    weakness_ids: vec!["CWE-918".to_string()],
                    advisory_ids: Vec::new(),
                    engine: EngineDescriptor {
                        id: self.engine_id.clone(),
                        version: self.engine_version.clone(),
                        rule_pack_sha256: None,
                    },
                    target: target_desc,
                    source_snapshot_sha256: snapshot_sha256.to_string(),
                    evidence: vec![
                        EvidenceItemV1 {
                            kind: EvidenceItemKind::SourceSpan,
                            artifact_sha256: snapshot_sha256.to_string(),
                            description: format!(
                                "Outbound request to '{}' without scope allowlisting",
                                target
                            ),
                            reference: Some(format!("{}:{}", file_path, line_num)),
                            limitations: Vec::new(),
                        },
                        EvidenceItemV1 {
                            kind: EvidenceItemKind::Other,
                            artifact_sha256: snapshot_sha256.to_string(),
                            description: format!(
                                "CVSS 3.1 Base Score: {:.1} ({})",
                                cvss.calculate_score(),
                                vector_str
                            ),
                            reference: None,
                            limitations: Vec::new(),
                        },
                    ],
                    proof: None,
                    coverage_receipt_ids: vec![receipt_id],
                    uncertainty_reasons: Vec::new(),
                    remediation_plan_id: None,
                    created_at: Utc::now().to_rfc3339(),
                    updated_at: None,
                    extensions,
                });
            }
        }

        // 2. Disabled TLS Certificate Verification
        let disabled_tls = trimmed.contains("rejectUnauthorized: false")
            || trimmed.contains("verify=False")
            || trimmed.contains("InsecureSkipVerify: true")
            || trimmed.contains("CURLOPT_SSL_VERIFYPEER => false");
        if disabled_tls {
            let cvss = CvssVector {
                attack_vector: AttackVector::Network,
                attack_complexity: AttackComplexity::High,
                privileges_required: PrivilegesRequired::None,
                user_interaction: UserInteraction::None,
                scope: Scope::Unchanged,
                confidentiality: ImpactMetric::High,
                integrity: ImpactMetric::High,
                availability: ImpactMetric::None,
            };
            let vector_str = cvss.to_vector_string();
            let tech = self.mitre_catalog.get("T1562");

            let finding_id = {
                let mut h = Sha256::new();
                h.update(run_id.as_bytes());
                h.update(file_path.as_bytes());
                h.update("tls".as_bytes());
                h.update((line_num as u64).to_be_bytes());
                crate::to_hex(h.finalize())
            };

            let mut extensions = serde_json::Map::new();
            extensions.insert(
                "cvss_vector".to_string(),
                serde_json::Value::String(vector_str.clone()),
            );
            extensions.insert(
                "cvss_score".to_string(),
                serde_json::json!(cvss.calculate_score()),
            );
            if let Some(t) = tech {
                extensions.insert(
                    "mitre_technique_id".to_string(),
                    serde_json::Value::String(t.id.clone()),
                );
                extensions.insert(
                    "mitre_technique_name".to_string(),
                    serde_json::Value::String(t.name.clone()),
                );
                extensions.insert(
                    "mitre_tactic".to_string(),
                    serde_json::Value::String(t.tactic.clone()),
                );
            }

            let span = SourceSpanV1 {
                start_line: line_num as u32,
                end_line: line_num as u32,
                start_column: Some(1),
                end_column: Some(trimmed.len() as u32),
            };

            let target_desc = TargetDescriptor {
                target_id: file_path.to_string(),
                kind: NormalizedTargetKind::File,
                path: Some(file_path.to_string()),
                package_purl: None,
                version: None,
                span: Some(span),
            };

            let receipt_id = format!(
                "ts-rcpt-{}-tls-{}",
                &snapshot_sha256[..8.min(snapshot_sha256.len())],
                line_num
            );

            return Some(FindingV1 {
                schema_version: "1.0".to_string(),
                run_id: run_id.to_string(),
                finding_id: finding_id.clone(),
                fingerprint: Some(finding_id),
                kind: FindingKind::Catalog,
                status: FindingStatus::Suspected,
                title: "Disabled TLS Peer Certificate Verification".to_string(),
                summary: Some("Disabled TLS certificate verification permits adversary Man-in-the-Middle traffic interception".to_string()),
                severity: NormalizedSeverity::High,
                evidence_certainty: EvidenceCertaintyV1::StronglySupported,
                rule_id: Some("threatswarm.defense.disabled_tls_validation".to_string()),
                weakness_ids: vec!["CWE-295".to_string()],
                advisory_ids: Vec::new(),
                engine: EngineDescriptor {
                    id: self.engine_id.clone(),
                    version: self.engine_version.clone(),
                    rule_pack_sha256: None,
                },
                target: target_desc,
                source_snapshot_sha256: snapshot_sha256.to_string(),
                evidence: vec![
                    EvidenceItemV1 {
                        kind: EvidenceItemKind::SourceSpan,
                        artifact_sha256: snapshot_sha256.to_string(),
                        description: "Explicit flag disabling TLS peer certificate validation".to_string(),
                        reference: Some(format!("{}:{}", file_path, line_num)),
                        limitations: Vec::new(),
                    },
                ],
                proof: None,
                coverage_receipt_ids: vec![receipt_id],
                uncertainty_reasons: Vec::new(),
                remediation_plan_id: None,
                created_at: Utc::now().to_rfc3339(),
                updated_at: None,
                extensions,
            });
        }

        None
    }
}

impl AnalyzerAdapter for ThreatswarmAdapter {
    fn engine_id(&self) -> &str {
        &self.engine_id
    }

    fn engine_version(&self) -> &str {
        &self.engine_version
    }

    fn supported_profiles(&self) -> &[ScanProfile] {
        &[
            ScanProfile::Quick,
            ScanProfile::Project,
            ScanProfile::Ci,
            ScanProfile::Deep,
        ]
    }

    fn supported_languages(&self) -> &[&str] {
        &[
            "all",
            "rust",
            "go",
            "javascript",
            "typescript",
            "python",
            "php",
            "c",
            "cpp",
        ]
    }

    fn supported_target_kinds(&self) -> &[TargetKind] {
        &[
            TargetKind::GenericSourceFile,
            TargetKind::GenericConfigFile,
            TargetKind::NodeSourceFile,
        ]
    }

    fn supported_checks(&self) -> &[&str] {
        &[
            "threatswarm.scope.unauthorized_egress",
            "threatswarm.defense.disabled_tls_validation",
            "threatswarm.mitre.mapping",
            "threatswarm.cvss.evaluation",
        ]
    }

    fn capabilities(&self) -> AdapterCapabilities {
        AdapterCapabilities {
            requires_network: false,
            requires_mutation: false,
            is_isolated: true,
            supports_cancellation: true,
        }
    }

    fn analyze(
        &self,
        request: &AnalysisRequest,
        cancel_token: &CancellationToken,
    ) -> Result<AnalysisResponse, AnalysisError> {
        let start_time = Instant::now();
        let target_root = Path::new(&request.snapshot_ref);

        if !target_root.exists() {
            return Err(AnalysisError::ExecutionFailed(format!(
                "Target snapshot root '{}' not found",
                request.snapshot_ref
            )));
        }

        let mut findings = Vec::new();
        let mut files_scanned = 0;

        if target_root.is_file() {
            if let Ok(content) = fs::read_to_string(target_root) {
                files_scanned += 1;
                for (idx, line) in content.lines().enumerate() {
                    if cancel_token.is_cancelled() {
                        return Err(AnalysisError::Cancelled);
                    }
                    if let Some(f) = self.check_line(
                        &request.run_id,
                        &request.snapshot_sha256,
                        &request.snapshot_ref,
                        idx + 1,
                        line,
                    ) {
                        findings.push(f);
                    }
                }
            }
        } else {
            let walker = walkdir::WalkDir::new(target_root)
                .follow_links(false)
                .into_iter()
                .filter_entry(|e| {
                    if e.depth() == 0 {
                        return true;
                    }
                    let name = e.file_name().to_string_lossy();
                    !name.starts_with('.') && name != "node_modules" && name != "target"
                });

            for entry in walker.filter_map(|e| e.ok()) {
                if cancel_token.is_cancelled() {
                    return Err(AnalysisError::Cancelled);
                }
                let path = entry.path();
                if path.is_file() {
                    let ext = path
                        .extension()
                        .and_then(|s| s.to_str())
                        .unwrap_or("")
                        .to_lowercase();
                    if matches!(
                        ext.as_str(),
                        "js" | "ts"
                            | "py"
                            | "go"
                            | "rs"
                            | "php"
                            | "c"
                            | "cpp"
                            | "json"
                            | "yaml"
                            | "yml"
                    ) {
                        if let Ok(content) = fs::read_to_string(path) {
                            files_scanned += 1;
                            let rel_path = path
                                .strip_prefix(target_root)
                                .unwrap_or(path)
                                .to_string_lossy()
                                .to_string();
                            for (idx, line) in content.lines().enumerate() {
                                if let Some(f) = self.check_line(
                                    &request.run_id,
                                    &request.snapshot_sha256,
                                    &rel_path,
                                    idx + 1,
                                    line,
                                ) {
                                    findings.push(f);
                                }
                            }
                        }
                    }
                }
            }
        }

        let elapsed = start_time.elapsed();
        let now = Utc::now().to_rfc3339();
        let receipt = CoverageReceiptV1 {
            schema_version: "1.0".to_string(),
            receipt_id: format!("rcpt-ts-{}", Utc::now().timestamp_micros()),
            run_id: request.run_id.clone(),
            engine_id: self.engine_id.clone(),
            engine_version: self.engine_version.clone(),
            check_id: "threatswarm.scope.scan".to_string(),
            target_id: request.snapshot_ref.clone(),
            snapshot_sha256: request.snapshot_sha256.clone(),
            status: CoverageReceiptStatus::Evaluated,
            counts: ReceiptCounts {
                items_discovered: files_scanned as u64,
                items_examined: files_scanned as u64,
                items_excluded: 0,
                items_skipped: 0,
            },
            reason_codes: Vec::new(),
            details: vec![format!(
                "Scanned with ThreatSwarm scope and ATT&CK mapping engine (rules: {})",
                self.supported_checks().len()
            )],
            started_at: now.clone(),
            completed_at: now.clone(),
            required_by_policy: Some(false),
            artifact_digests: Vec::new(),
            previous_receipt_id: None,
        };

        Ok(AnalysisResponse {
            schema_version: "1.0".to_string(),
            run_id: request.run_id.clone(),
            engine_id: self.engine_id.clone(),
            engine_version: self.engine_version.clone(),
            snapshot_sha256: request.snapshot_sha256.clone(),
            status: EngineStatus::Completed,
            findings,
            receipts: vec![receipt],
            diagnostics: Vec::new(),
            resources: ResourceUsage {
                duration_ms: elapsed.as_millis() as u64,
                peak_memory_bytes: 0,
            },
            completed_at: now,
        })
    }
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scope_enforcer_cidr_and_domain() {
        let scope_data = r#"
# Authorized testing scope
192.168.1.0/24
10.0.0.5
api.internal.corp
*.staging.local
"#;
        let enforcer = ThreatswarmScopeEnforcer::load_from_str(scope_data);
        assert_eq!(enforcer.entries_count(), 4);

        // Localhost is always in scope
        assert!(enforcer.is_in_scope("127.0.0.1"));
        assert!(enforcer.is_in_scope("localhost"));

        // Subnet matches
        assert!(enforcer.is_in_scope("192.168.1.42"));
        assert!(!enforcer.is_in_scope("192.168.2.42"));

        // Single IP matches
        assert!(enforcer.is_in_scope("10.0.0.5"));
        assert!(!enforcer.is_in_scope("10.0.0.6"));

        // Domain matches
        assert!(enforcer.is_in_scope("api.internal.corp"));
        assert!(enforcer.is_in_scope("auth.staging.local"));
        assert!(!enforcer.is_in_scope("malicious.external.com"));
    }

    #[test]
    fn test_scope_enforcer_command_verification() {
        let scope_data = "10.10.10.0/24\ninternal.local";
        let enforcer = ThreatswarmScopeEnforcer::load_from_str(scope_data);

        // In-scope commands pass
        assert!(
            enforcer
                .verify_command("curl http://10.10.10.5/api")
                .is_ok()
        );
        assert!(enforcer.verify_command("nmap -sV internal.local").is_ok());
        assert!(enforcer.verify_command("cargo test --workspace").is_ok());

        // Out-of-scope commands fail
        let res = enforcer.verify_command("curl https://8.8.8.8/exfil");
        assert!(res.is_err());
        let err = res.unwrap_err();
        assert_eq!(err.target, "8.8.8.8");
    }

    #[test]
    fn test_cvss_vector_calculation_and_roundtrip() {
        // Critical pre-auth RCE (9.8)
        let vector_str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
        let cvss = CvssVector::parse(vector_str).expect("Valid CVSS vector must parse");
        assert_eq!(cvss.calculate_score(), 9.8);
        assert_eq!(cvss.severity_tier(), NormalizedSeverity::Critical);
        assert_eq!(cvss.to_vector_string(), vector_str);

        // Changed scope SSRF (10.0)
        let vector_changed = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H";
        let cvss_c = CvssVector::parse(vector_changed).expect("Parse changed vector");
        assert_eq!(cvss_c.calculate_score(), 10.0);
        assert_eq!(cvss_c.severity_tier(), NormalizedSeverity::Critical);

        // High Post-auth RCE (8.8)
        let vector_post = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H";
        let cvss_p = CvssVector::parse(vector_post).expect("Parse post-auth vector");
        assert_eq!(cvss_p.calculate_score(), 8.8);
        assert_eq!(cvss_p.severity_tier(), NormalizedSeverity::High);
    }

    #[test]
    fn test_mitre_attack_catalog_cwe_mapping() {
        let catalog = ThreatswarmMitreCatalog::new();
        let cmd_inj = catalog.map_cwe("CWE-78");
        assert!(!cmd_inj.is_empty());
        assert_eq!(cmd_inj[0].id, "T1059");

        let sqli = catalog.map_cwe("CWE-89");
        assert!(!sqli.is_empty());
        assert_eq!(sqli[0].id, "T1190");
    }

    #[test]
    fn test_threatswarm_adapter_detection() {
        let scope_data = "127.0.0.1\ninternal.corp";
        let enforcer = ThreatswarmScopeEnforcer::load_from_str(scope_data);
        let adapter = ThreatswarmAdapter {
            engine_id: "threatswarm-deep-adapter".to_string(),
            engine_version: "1.0.0".to_string(),
            scope_enforcer: enforcer,
            mitre_catalog: ThreatswarmMitreCatalog::new(),
        };

        let dummy_hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

        // Out of scope egress line
        let f1 = adapter.check_line(
            "run-ts-001",
            dummy_hash,
            "client.js",
            10,
            r#"const res = curl https://93.184.216.34/api/data"#,
        );
        assert!(f1.is_some());
        let finding = f1.unwrap();
        assert_eq!(
            finding.rule_id,
            Some("threatswarm.scope.unauthorized_egress".to_string())
        );
        assert_eq!(finding.severity, NormalizedSeverity::High);
        assert!(finding.validate().is_ok());

        // Disabled TLS verification line
        let f2 = adapter.check_line(
            "run-ts-001",
            dummy_hash,
            "fetcher.py",
            25,
            r#"requests.get(url, verify=False)"#,
        );
        assert!(f2.is_some());
        let tls_finding = f2.unwrap();
        assert_eq!(
            tls_finding.rule_id,
            Some("threatswarm.defense.disabled_tls_validation".to_string())
        );
        assert!(tls_finding.validate().is_ok());
    }

    #[test]
    fn test_finding_sync_and_prebuilt_cvss() {
        // Prebuilt vectors
        let rce = CvssVector::prebuilt_for_pattern("pre-auth-rce");
        assert_eq!(rce.calculate_score(), 9.8);
        assert_eq!(rce.severity_tier(), NormalizedSeverity::Critical);
        assert_eq!(
            ThreatswarmCvssEngine::remediation_sla_hours(NormalizedSeverity::Critical),
            24
        );
        assert_eq!(
            ThreatswarmCvssEngine::remediation_sla_hours(NormalizedSeverity::High),
            72
        );

        // Finding sync parser
        let sample_md = r#"
# Vulnerability Report
- [CRITICAL] Remote Code Execution via deserialization in auth.js
- [HIGH] Missing TLS verification in payment gateway
- [CRITICAL] Remote Code Execution via deserialization in auth.js
- [MEDIUM] Information disclosure in debug logs
"#;
        let summary = ThreatswarmFindingSync::sync_markdown_content(sample_md, "test_report.md");
        assert_eq!(summary.total_critical, 1); // deduplicated duplicate
        assert_eq!(summary.total_high, 1);
        assert_eq!(summary.critical_findings.len(), 1);
        assert_eq!(summary.high_findings.len(), 1);

        let summary_md = ThreatswarmFindingSync::generate_summary_markdown(&summary);
        assert!(summary_md.contains("# ThreatSwarm Findings Summary"));
        assert!(summary_md.contains("Critical Severity Findings"));
        assert!(summary_md.contains("High Severity Findings"));
    }
}
