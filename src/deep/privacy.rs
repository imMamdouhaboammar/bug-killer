use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, OnceLock};
use std::time::Instant;

use chrono::Utc;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::deep::cpg::{CpgBuilder, CpgDataflowTrace};
use crate::engine::adapter::{AdapterCapabilities, AnalyzerAdapter};
use crate::engine::protocol::{
    AnalysisRequest, AnalysisResponse, CoverageReceiptStatus, CoverageReceiptV1, EngineDescriptor,
    EngineStatus, EvidenceCertaintyV1, EvidenceItemKind, EvidenceItemV1, FindingKind,
    FindingStatus, FindingV1, NormalizedSeverity, NormalizedTargetKind, ProofMethod, ProofV1,
    ReceiptCounts, ResourceUsage, SourceSpanV1, TargetDescriptor,
};
use crate::engine::runner::{AnalysisError, CancellationToken};
use crate::types::{ScanProfile, TargetKind};

// =========================================================================
// Privacy Framework & Weakness Classifications
// =========================================================================

/// Primary privacy regulation or compliance framework.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PrivacyFramework {
    Gdpr,
    Ccpa,
    Hipaa,
    EuAiAct,
    Linddun,
    OwaspPrivacyTop10,
    Iso27701,
    NistPf,
    General,
}

impl PrivacyFramework {
    pub fn as_str(&self) -> &'static str {
        match self {
            PrivacyFramework::Gdpr => "GDPR",
            PrivacyFramework::Ccpa => "CCPA",
            PrivacyFramework::Hipaa => "HIPAA",
            PrivacyFramework::EuAiAct => "EU_AI_ACT",
            PrivacyFramework::Linddun => "LINDDUN",
            PrivacyFramework::OwaspPrivacyTop10 => "OWASP_PRIVACY_TOP10",
            PrivacyFramework::Iso27701 => "ISO_27701",
            PrivacyFramework::NistPf => "NIST_PF",
            PrivacyFramework::General => "GENERAL",
        }
    }

    pub fn from_str_loose(s: &str) -> Self {
        match s.to_uppercase().trim() {
            "GDPR" => PrivacyFramework::Gdpr,
            "CCPA" | "CPRA" => PrivacyFramework::Ccpa,
            "HIPAA" | "HITECH" => PrivacyFramework::Hipaa,
            "EU_AI_ACT" | "AI_ACT" => PrivacyFramework::EuAiAct,
            "LINDDUN" => PrivacyFramework::Linddun,
            "OWASP" | "OWASP_PRIVACY_TOP10" => PrivacyFramework::OwaspPrivacyTop10,
            "ISO_27701" | "ISO27701" => PrivacyFramework::Iso27701,
            "NIST_PF" | "NIST" => PrivacyFramework::NistPf,
            _ => PrivacyFramework::General,
        }
    }
}

// =========================================================================
// Privacy Skill Domain Model & Inverted Index Registry
// =========================================================================

/// A structured privacy compliance procedure from the Privacy & Data Protection Skills library.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacySkill {
    pub id: String,
    pub name: String,
    pub description: String,
    pub regulations: Vec<String>,
    pub owasp_risks: Vec<String>,
    pub nist_categories: Vec<String>,
    pub iso_clauses: Vec<String>,
    pub linddun_threats: Vec<String>,
    pub has_script: bool,
    pub has_template: bool,
    pub path: String,
}

impl PrivacySkill {
    pub fn matches_query(&self, q: &str) -> bool {
        let q_lower = q.to_lowercase();
        if self.id.to_lowercase().contains(&q_lower)
            || self.name.to_lowercase().contains(&q_lower)
            || self.description.to_lowercase().contains(&q_lower)
        {
            return true;
        }
        if self
            .regulations
            .iter()
            .any(|r| r.to_lowercase().contains(&q_lower))
        {
            return true;
        }
        if self
            .owasp_risks
            .iter()
            .any(|o| o.to_lowercase().contains(&q_lower))
        {
            return true;
        }
        if self
            .linddun_threats
            .iter()
            .any(|l| l.to_lowercase().contains(&q_lower))
        {
            return true;
        }
        false
    }

    pub fn has_regulation(&self, reg: &str) -> bool {
        let needle = reg.trim().to_uppercase();
        self.regulations
            .iter()
            .any(|r| r.to_uppercase().contains(&needle))
    }

    pub fn has_owasp_risk(&self, risk: &str) -> bool {
        let needle = risk.trim().to_uppercase();
        self.owasp_risks
            .iter()
            .any(|r| r.to_uppercase().starts_with(&needle))
    }

    pub fn has_linddun_threat(&self, threat: &str) -> bool {
        let needle = threat.trim().to_uppercase();
        self.linddun_threats
            .iter()
            .any(|t| t.to_uppercase() == needle)
    }

    pub fn script_path(&self) -> Option<PathBuf> {
        if self.has_script {
            Some(PathBuf::from(&self.path).join("scripts").join("process.py"))
        } else {
            None
        }
    }

    pub fn template_path(&self) -> Option<PathBuf> {
        if self.has_template {
            Some(PathBuf::from(&self.path).join("assets").join("template.md"))
        } else {
            None
        }
    }
}

/// Metrics summary across the Privacy Skills catalog.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PrivacyRegistryMetrics {
    pub total_skills: usize,
    pub regulations_count: usize,
    pub owasp_risks_count: usize,
    pub nist_categories_count: usize,
    pub iso_clauses_count: usize,
    pub linddun_threats_count: usize,
    pub top_regulations: Vec<(String, usize)>,
    pub top_owasp_risks: Vec<(String, usize)>,
}

static EMBEDDED_PRIVACY_REGISTRY: OnceLock<PrivacySkillsRegistry> = OnceLock::new();

/// Deep index for curated Privacy & Data Protection compliance procedures.
#[derive(Debug, Clone)]
pub struct PrivacySkillsRegistry {
    skills: Vec<PrivacySkill>,
    by_id: HashMap<String, usize>,
    by_regulation: HashMap<String, Vec<usize>>,
    by_owasp: HashMap<String, Vec<usize>>,
    by_linddun: HashMap<String, Vec<usize>>,
    by_nist: HashMap<String, Vec<usize>>,
    by_iso: HashMap<String, Vec<usize>>,
}

impl Default for PrivacySkillsRegistry {
    fn default() -> Self {
        Self::default_embedded().clone()
    }
}

impl PrivacySkillsRegistry {
    pub fn new() -> Self {
        Self {
            skills: Vec::new(),
            by_id: HashMap::new(),
            by_regulation: HashMap::new(),
            by_owasp: HashMap::new(),
            by_linddun: HashMap::new(),
            by_nist: HashMap::new(),
            by_iso: HashMap::new(),
        }
    }

    pub fn from_skills(skills: Vec<PrivacySkill>) -> Self {
        let mut by_id = HashMap::with_capacity(skills.len());
        let mut by_regulation: HashMap<String, Vec<usize>> = HashMap::new();
        let mut by_owasp: HashMap<String, Vec<usize>> = HashMap::new();
        let mut by_linddun: HashMap<String, Vec<usize>> = HashMap::new();
        let mut by_nist: HashMap<String, Vec<usize>> = HashMap::new();
        let mut by_iso: HashMap<String, Vec<usize>> = HashMap::new();

        for (idx, skill) in skills.iter().enumerate() {
            by_id.insert(skill.id.clone(), idx);

            for reg in &skill.regulations {
                by_regulation
                    .entry(reg.to_uppercase())
                    .or_default()
                    .push(idx);
            }

            for owasp in &skill.owasp_risks {
                let code = owasp.split(':').next().unwrap_or(owasp).to_uppercase();
                by_owasp.entry(code).or_default().push(idx);
            }

            for linddun in &skill.linddun_threats {
                by_linddun
                    .entry(linddun.to_uppercase())
                    .or_default()
                    .push(idx);
            }

            for nist in &skill.nist_categories {
                by_nist.entry(nist.to_uppercase()).or_default().push(idx);
            }

            for iso in &skill.iso_clauses {
                by_iso.entry(iso.clone()).or_default().push(idx);
            }
        }

        Self {
            skills,
            by_id,
            by_regulation,
            by_owasp,
            by_linddun,
            by_nist,
            by_iso,
        }
    }

    /// Access the embedded privacy skills catalog.
    pub fn default_embedded() -> &'static PrivacySkillsRegistry {
        EMBEDDED_PRIVACY_REGISTRY.get_or_init(|| {
            let json_str = include_str!("privacy_skills_data.json");
            let skills: Vec<PrivacySkill> =
                serde_json::from_str(json_str).expect("Embedded privacy skills catalog must parse");
            PrivacySkillsRegistry::from_skills(skills)
        })
    }

    pub fn total_skills(&self) -> usize {
        self.skills.len()
    }

    pub fn all_skills(&self) -> &[PrivacySkill] {
        &self.skills
    }

    pub fn get_by_id(&self, id: &str) -> Option<&PrivacySkill> {
        self.by_id.get(id).map(|&idx| &self.skills[idx])
    }

    pub fn find_by_regulation(&self, reg: &str) -> Vec<&PrivacySkill> {
        let needle = reg.trim().to_uppercase();
        self.by_regulation
            .get(&needle)
            .map(|indices| indices.iter().map(|&idx| &self.skills[idx]).collect())
            .unwrap_or_default()
    }

    pub fn find_by_owasp(&self, risk: &str) -> Vec<&PrivacySkill> {
        let needle = risk.trim().to_uppercase();
        self.by_owasp
            .get(&needle)
            .map(|indices| indices.iter().map(|&idx| &self.skills[idx]).collect())
            .unwrap_or_default()
    }

    pub fn find_by_linddun(&self, threat: &str) -> Vec<&PrivacySkill> {
        let needle = threat.trim().to_uppercase();
        self.by_linddun
            .get(&needle)
            .map(|indices| indices.iter().map(|&idx| &self.skills[idx]).collect())
            .unwrap_or_default()
    }

    pub fn search(&self, query: &str) -> Vec<&PrivacySkill> {
        let q = query.trim();
        if q.is_empty() {
            return self.skills.iter().collect();
        }
        self.skills.iter().filter(|s| s.matches_query(q)).collect()
    }

    /// Recommends relevant privacy procedures for a given check ID or weakness code.
    pub fn recommend_for_check(&self, check_id: &str) -> Vec<&PrivacySkill> {
        let mut results = Vec::new();
        let mut seen = HashSet::new();

        let norm = check_id.to_uppercase();
        if norm.contains("PRIV-001") || norm.contains("CWE-311") || norm.contains("P1") {
            for s in self.find_by_owasp("P1") {
                if seen.insert(&s.id) {
                    results.push(s);
                }
            }
        }
        if norm.contains("PRIV-002") || norm.contains("CWE-532") || norm.contains("P2") {
            for s in self.find_by_owasp("P2") {
                if seen.insert(&s.id) {
                    results.push(s);
                }
            }
        }
        if norm.contains("PRIV-003") || norm.contains("CWE-862") || norm.contains("P4") {
            for s in self.find_by_owasp("P4") {
                if seen.insert(&s.id) {
                    results.push(s);
                }
            }
        }
        if norm.contains("PRIV-004") || norm.contains("CWE-404") || norm.contains("P6") {
            for s in self.find_by_owasp("P6") {
                if seen.insert(&s.id) {
                    results.push(s);
                }
            }
        }
        if norm.contains("PRIV-005") || norm.contains("CWE-639") || norm.contains("P9") {
            for s in self.find_by_owasp("P9") {
                if seen.insert(&s.id) {
                    results.push(s);
                }
            }
        }
        if norm.contains("PRIV-006") || norm.contains("CWE-201") || norm.contains("P10") {
            for s in self.find_by_owasp("P10") {
                if seen.insert(&s.id) {
                    results.push(s);
                }
            }
        }
        if norm.contains("LINDDUN") || norm.contains("PRIV-007") {
            for s in self.find_by_linddun("L") {
                if seen.insert(&s.id) {
                    results.push(s);
                }
            }
            for s in self.search("linddun") {
                if seen.insert(&s.id) {
                    results.push(s);
                }
            }
        }
        if norm.contains("HIPAA") || norm.contains("PRIV-008") {
            for s in self.find_by_regulation("HIPAA") {
                if seen.insert(&s.id) {
                    results.push(s);
                }
            }
        }
        if norm.contains("AI") || norm.contains("PRIV-009") {
            for s in self.find_by_regulation("EU_AI_ACT") {
                if seen.insert(&s.id) {
                    results.push(s);
                }
            }
        }
        if norm.contains("BREACH") || norm.contains("PRIV-010") || norm.contains("P3") {
            for s in self.find_by_owasp("P3") {
                if seen.insert(&s.id) {
                    results.push(s);
                }
            }
        }

        results
    }

    pub fn metrics(&self) -> PrivacyRegistryMetrics {
        let mut top_regulations: Vec<(String, usize)> = self
            .by_regulation
            .iter()
            .map(|(k, v)| (k.clone(), v.len()))
            .collect();
        top_regulations.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

        let mut top_owasp_risks: Vec<(String, usize)> = self
            .by_owasp
            .iter()
            .map(|(k, v)| (k.clone(), v.len()))
            .collect();
        top_owasp_risks.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

        PrivacyRegistryMetrics {
            total_skills: self.skills.len(),
            regulations_count: self.by_regulation.len(),
            owasp_risks_count: self.by_owasp.len(),
            nist_categories_count: self.by_nist.len(),
            iso_clauses_count: self.by_iso.len(),
            linddun_threats_count: self.by_linddun.len(),
            top_regulations,
            top_owasp_risks,
        }
    }
}

// =========================================================================
// Privacy Finding Structured Data Type
// =========================================================================

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PrivacyFinding {
    pub check_id: String,
    pub title: String,
    pub framework: PrivacyFramework,
    pub severity: NormalizedSeverity,
    pub file_path: String,
    pub line_number: usize,
    pub column: usize,
    pub snippet: String,
    pub description: String,
    pub remediation: String,
    pub associated_skill_id: Option<String>,
    pub dataflow_trace: Option<CpgDataflowTrace>,
}

// =========================================================================
// Regex Rules for Static Privacy Checks
// =========================================================================

static RE_PII_DIRECT_UNENCRYPTED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:@Column\s*\([^)]*\{[^}]*\}\s*\)\s*(?:public\s+|private\s+)?(?:ssn|social_security|credit_card|card_number|tax_id|bank_account|passport_number)\s*:\s*string;|table\.(?:string|text)\s*\(\s*['"](?:ssn|credit_card|tax_id|bank_account)['"]\s*\)\s*;|['"](?:ssn|credit_card)['"]\s*:\s*\{\s*type\s*:\s*String\s*,\s*encrypted\s*:\s*false)"#).unwrap()
});

static RE_INDEFINITE_RETENTION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:retention_period\s*:\s*(?:null|none|'indefinite'|"indefinite"|0)|ttl\s*:\s*(?:null|none|0)|purge_expired_users\s*:\s*false|keep_pii_indefinitely\s*:\s*true|//.*(?:indefinite data retention|no storage limitation|pii retained permanently))"#).unwrap()
});

static RE_DSAR_UNPROTECTED_ROUTE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:app|router)\.(?:get|post|delete)\s*\(\s*['"]/(?:api/)?(?:export-user-data|export-data|user-data-export|delete-user-data|gdpr-export|gdpr-delete|download-personal-data|purge-user|delete-account)(?:/[^'"]*)?['"]\s*,\s*(?:async\s*)?\(\s*(?:req|request)\s*,\s*(?:res|response)\s*\)\s*=>"#).unwrap()
});

static RE_AUTH_OWNERSHIP_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:verifyUserOwnership|requireAuth|authenticate|verifyToken|authorizeOwner|req\.user\.id\s*===\s*targetId|isAuthorizedOwner)"#).unwrap()
});

static RE_AI_UNREDACTED_PII: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:openai|anthropic|cohere|bedrock|mistral|client|ai)\.(?:chat\.completions|messages|completions)\.create\s*\(\s*\{[\s\S]*?(?:req\.body\.(?:ssn|creditCard|credit_card|password|medical_record|diagnosis)|user\.(?:ssn|credit_card|password)|credit_card|card_number|cvv)"#).unwrap()
});

static RE_AI_AUTOMATED_DECISION_HIGH_RISK: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:autonomous_high_risk_decision\s*:\s*true|human_in_the_loop\s*:\s*false|auto_reject_loan\s*\(\s*|auto_deny_benefit\s*\(\s*|//.*(?:fully automated decision without human oversight|autonomous profiling without human-in-the-loop))"#).unwrap()
});

static RE_HIPAA_UNSAFE_PHI: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:patient_medical_record|phi_raw_export|patient_diagnosis)\s*=\s*.*(?:medical_history|ssn|health_condition|mrn|patient_ssn)"#).unwrap()
});

static RE_HIPAA_DEIDENTIFY_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:deidentify_hipaa|safe_harbor_redact|anonymize_phi|mask_mrn|expert_determination_verified)"#).unwrap()
});

static RE_BREACH_NOTIFICATION_DEFICIENCY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:onSecurityIncident\s*=\s*\([^)]*\)\s*=>|//.*(?:breach response omits 72h regulatory notification|incident handler lacks supervisory authority notice))"#).unwrap()
});

// =========================================================================
// Privacy Deep Engine Adapter Implementation
// =========================================================================

/// Deep Privacy & Data Protection Analyzer Adapter.
#[derive(Debug, Clone)]
pub struct PrivacyEngineAdapter {
    engine_id: String,
    engine_version: String,
}

impl Default for PrivacyEngineAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl PrivacyEngineAdapter {
    pub fn new() -> Self {
        Self {
            engine_id: "privacy-engine-adapter".to_string(),
            engine_version: "1.0.0".to_string(),
        }
    }

    /// Evaluates target file content using static pattern matching and contextual rule triggers.
    pub fn evaluate_file(path: &Path, content: &str) -> Vec<PrivacyFinding> {
        let mut findings = Vec::new();
        let path_str = path.to_string_lossy().to_string();

        let registry = PrivacySkillsRegistry::default_embedded();

        // 1. Indefinite Retention & Storage Limitation (OWASP P6 / GDPR Art. 5(1)(e))
        for (idx, line) in content.lines().enumerate() {
            let line_num = idx + 1;
            let trimmed = line.trim();

            if RE_INDEFINITE_RETENTION.is_match(trimmed) {
                let skill_id = registry
                    .recommend_for_check("BK-AI-PRIV-004")
                    .first()
                    .map(|s| s.id.clone())
                    .unwrap_or_else(|| "automating-storage-limitation-controls".to_string());

                findings.push(PrivacyFinding {
                    check_id: "BK-AI-PRIV-004".to_string(),
                    title: "Indefinite Data Retention & Storage Limitation Non-Compliance".to_string(),
                    framework: PrivacyFramework::Gdpr,
                    severity: NormalizedSeverity::High,
                    file_path: path_str.clone(),
                    line_number: line_num,
                    column: 1,
                    snippet: trimmed.to_string(),
                    description: "PII or user dataset is configured with indefinite retention or missing TTL expiration, violating GDPR Art. 5(1)(e) and OWASP P6.".to_string(),
                    remediation: "Define an enforceable retention schedule (TTL) and automated purge job. Refer to skill 'automating-storage-limitation-controls'.".to_string(),
                    associated_skill_id: Some(skill_id),
                    dataflow_trace: None,
                });
            }

            // 2. Insecure PII Storage & Missing Encryption (OWASP P1 / GDPR Art. 32 / HIPAA § 164.312)
            if RE_PII_DIRECT_UNENCRYPTED.is_match(trimmed) {
                let skill_id = registry
                    .recommend_for_check("BK-AI-PRIV-001")
                    .first()
                    .map(|s| s.id.clone())
                    .unwrap_or_else(|| "implementing-data-protection-by-default".to_string());

                findings.push(PrivacyFinding {
                    check_id: "BK-AI-PRIV-001".to_string(),
                    title: "Insecure PII Storage & Missing Encryption-at-Rest".to_string(),
                    framework: PrivacyFramework::Gdpr,
                    severity: NormalizedSeverity::Critical,
                    file_path: path_str.clone(),
                    line_number: line_num,
                    column: 1,
                    snippet: trimmed.to_string(),
                    description: "Sensitive identifier column (SSN, credit card, tax ID) defined without mandatory encryption-at-rest or explicit encrypted: false.".to_string(),
                    remediation: "Enforce column-level envelope encryption (AES-256-GCM / KMS). Refer to skill 'implementing-data-protection-by-default'.".to_string(),
                    associated_skill_id: Some(skill_id),
                    dataflow_trace: None,
                });
            }

            // 3. Automated Decision Making without Human Oversight (EU AI Act Art. 14 / GDPR Art. 22)
            if RE_AI_AUTOMATED_DECISION_HIGH_RISK.is_match(trimmed) {
                let skill_id = registry
                    .recommend_for_check("BK-AI-PRIV-009")
                    .first()
                    .map(|s| s.id.clone())
                    .unwrap_or_else(|| "ai-automated-decisions".to_string());

                findings.push(PrivacyFinding {
                    check_id: "BK-AI-PRIV-009".to_string(),
                    title: "Automated Decision Making without Human-in-the-Loop Safeguards".to_string(),
                    framework: PrivacyFramework::EuAiAct,
                    severity: NormalizedSeverity::High,
                    file_path: path_str.clone(),
                    line_number: line_num,
                    column: 1,
                    snippet: trimmed.to_string(),
                    description: "High-risk decision pipeline or profiling executes autonomously without human oversight mechanisms, violating EU AI Act Art. 14 and GDPR Art. 22.".to_string(),
                    remediation: "Implement a human-in-the-loop review step and recourse workflow. Refer to skill 'ai-automated-decisions'.".to_string(),
                    associated_skill_id: Some(skill_id),
                    dataflow_trace: None,
                });
            }

            // 4. Unsafe PHI Exposure without Safe Harbor De-identification (HIPAA § 164.514)
            if RE_HIPAA_UNSAFE_PHI.is_match(trimmed) && !RE_HIPAA_DEIDENTIFY_GUARD.is_match(content)
            {
                let skill_id = registry
                    .recommend_for_check("BK-AI-PRIV-008")
                    .first()
                    .map(|s| s.id.clone())
                    .unwrap_or_else(|| "hipaa-deidentification".to_string());

                findings.push(PrivacyFinding {
                    check_id: "BK-AI-PRIV-008".to_string(),
                    title: "Unsafe Protected Health Information (PHI) Exposure without De-identification".to_string(),
                    framework: PrivacyFramework::Hipaa,
                    severity: NormalizedSeverity::Critical,
                    file_path: path_str.clone(),
                    line_number: line_num,
                    column: 1,
                    snippet: trimmed.to_string(),
                    description: "Patient health record is exported or manipulated without applying HIPAA Safe Harbor de-identification (stripping 18 identifiers).".to_string(),
                    remediation: "Pass health records through deidentify_hipaa() or expert determination. Refer to skill 'hipaa-deidentification'.".to_string(),
                    associated_skill_id: Some(skill_id),
                    dataflow_trace: None,
                });
            }

            // 5. Data Breach Notification Deficiency (OWASP P3 / GDPR Art. 33)
            if RE_BREACH_NOTIFICATION_DEFICIENCY.is_match(trimmed)
                && !content.contains("notify_dpa_72h")
            {
                let skill_id = registry
                    .recommend_for_check("BK-AI-PRIV-010")
                    .first()
                    .map(|s| s.id.clone())
                    .unwrap_or_else(|| "breach-72h-notification".to_string());

                findings.push(PrivacyFinding {
                    check_id: "BK-AI-PRIV-010".to_string(),
                    title: "Data Breach 72h Notification & Audit Trail Deficiency".to_string(),
                    framework: PrivacyFramework::Gdpr,
                    severity: NormalizedSeverity::High,
                    file_path: path_str.clone(),
                    line_number: line_num,
                    column: 1,
                    snippet: trimmed.to_string(),
                    description: "Security incident response handler omits mandatory 72-hour supervisory authority notification workflow required by GDPR Art. 33.".to_string(),
                    remediation: "Integrate automated 72-hour supervisory authority escalation playbook. Refer to skill 'breach-72h-notification'.".to_string(),
                    associated_skill_id: Some(skill_id),
                    dataflow_trace: None,
                });
            }
        }

        // 6. DSAR Export / Deletion Unprotected Route (OWASP P9 / GDPR Art. 17 / CCPA § 1798.105)
        if RE_DSAR_UNPROTECTED_ROUTE.is_match(content) && !RE_AUTH_OWNERSHIP_GUARD.is_match(content)
        {
            let skill_id = registry
                .recommend_for_check("BK-AI-PRIV-005")
                .first()
                .map(|s| s.id.clone())
                .unwrap_or_else(|| "dsar-intake-system".to_string());

            findings.push(PrivacyFinding {
                check_id: "BK-AI-PRIV-005".to_string(),
                title: "Missing DSAR Deletion / Export Ownership Gate".to_string(),
                framework: PrivacyFramework::Gdpr,
                severity: NormalizedSeverity::Critical,
                file_path: path_str.clone(),
                line_number: 1,
                column: 1,
                snippet: "app.post('/api/delete-user-data', ...)".to_string(),
                description: "DSAR data deletion/export route lacks authorized ownership verification, permitting unauthorized account wipe or data exfiltration.".to_string(),
                remediation: "Wrap DSAR endpoints with verifyUserOwnership() and require signed session verification. Refer to skill 'dsar-intake-system'.".to_string(),
                associated_skill_id: Some(skill_id),
                dataflow_trace: None,
            });
        }

        // 7. Direct AI Model Call with Unredacted PII (OWASP P1 / EU AI Act Art. 10)
        if RE_AI_UNREDACTED_PII.is_match(content) {
            let skill_id = registry
                .recommend_for_check("BK-AI-PRIV-002")
                .first()
                .map(|s| s.id.clone())
                .unwrap_or_else(|| "ai-model-privacy-audit".to_string());

            findings.push(PrivacyFinding {
                check_id: "BK-AI-PRIV-002".to_string(),
                title: "Third-Party AI API Receives Unredacted Confidential PII".to_string(),
                framework: PrivacyFramework::EuAiAct,
                severity: NormalizedSeverity::High,
                file_path: path_str,
                line_number: 1,
                column: 1,
                snippet: "openai.chat.completions.create({ ... req.body.ssn })".to_string(),
                description: "Unredacted personal data (SSN, credit card, medical diagnosis) passed directly into third-party AI model prompts.".to_string(),
                remediation: "Anonymize or redact personal data prior to dispatching prompts to remote AI models. Refer to skill 'ai-model-privacy-audit'.".to_string(),
                associated_skill_id: Some(skill_id),
                dataflow_trace: None,
            });
        }

        findings
    }
}

impl AnalyzerAdapter for PrivacyEngineAdapter {
    fn engine_id(&self) -> &str {
        &self.engine_id
    }

    fn engine_version(&self) -> &str {
        &self.engine_version
    }

    fn supported_profiles(&self) -> &[ScanProfile] {
        &[
            ScanProfile::Deep,
            ScanProfile::Audit,
            ScanProfile::Project,
            ScanProfile::Ci,
        ]
    }

    fn supported_languages(&self) -> &[&str] {
        &[
            "javascript",
            "typescript",
            "python",
            "php",
            "go",
            "rust",
            "java",
            "csharp",
            "ruby",
            "yaml",
            "json",
            "dockerfile",
            "markdown",
            "generic",
        ]
    }

    fn supported_target_kinds(&self) -> &[TargetKind] {
        &[
            TargetKind::GenericSourceFile,
            TargetKind::GenericConfigFile,
            TargetKind::AgentSkillManifest,
            TargetKind::Dockerfile,
        ]
    }

    fn supported_checks(&self) -> &[&str] {
        &[
            "BK-AI-PRIV-001",
            "BK-AI-PRIV-002",
            "BK-AI-PRIV-003",
            "BK-AI-PRIV-004",
            "BK-AI-PRIV-005",
            "BK-AI-PRIV-006",
            "BK-AI-PRIV-007",
            "BK-AI-PRIV-008",
            "BK-AI-PRIV-009",
            "BK-AI-PRIV-010",
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
        let now = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

        if cancel_token.is_cancelled() {
            return Err(AnalysisError::Cancelled);
        }

        // Profile validation: reject Quick profile fail-closed
        if request.profile == ScanProfile::Quick {
            return Err(AnalysisError::ExecutionFailed(
                "PrivacyEngineAdapter requires Deep, Audit, Project, or Ci profile".to_string(),
            ));
        }

        let mut findings = Vec::new();
        let targets = if request.target_ids.is_empty() {
            vec![PathBuf::from(".")]
        } else {
            request.target_ids.iter().map(PathBuf::from).collect()
        };

        // 1. Multi-file CPG Taint Flow Analysis for PII Leakage
        let mut cpg_builder = CpgBuilder::new();
        let mut source_files = Vec::new();

        for target in &targets {
            if cancel_token.is_cancelled() {
                return Err(AnalysisError::Cancelled);
            }

            if target.is_file() {
                if let Ok(c) = std::fs::read_to_string(target) {
                    cpg_builder.add_source_file(target, &c);
                    source_files.push((target.clone(), c));
                }
            } else if target.is_dir() {
                for entry in walkdir::WalkDir::new(target)
                    .follow_links(false)
                    .into_iter()
                    .filter_map(|e| e.ok())
                {
                    if cancel_token.is_cancelled() {
                        return Err(AnalysisError::Cancelled);
                    }

                    let p = entry.path();
                    if p.is_file() {
                        let ext = p
                            .extension()
                            .and_then(|s| s.to_str())
                            .unwrap_or("")
                            .to_ascii_lowercase();
                        if matches!(
                            ext.as_str(),
                            "js" | "mjs"
                                | "cjs"
                                | "ts"
                                | "tsx"
                                | "py"
                                | "php"
                                | "go"
                                | "rs"
                                | "java"
                        ) {
                            if let Ok(c) = std::fs::read_to_string(p) {
                                cpg_builder.add_source_file(p, &c);
                                source_files.push((p.to_path_buf(), c));
                            }
                        }
                    }
                }
            }
        }

        // Execute CPG taint analysis
        let cpg = cpg_builder.build();
        let taint_flows = cpg.find_taint_flows();
        let receipt_id = format!("receipt-{}-0", request.run_id);

        for flow in taint_flows {
            // Check if sink involves AI, analytics, or logging of PII
            let is_privacy_sink = flow.weakness.contains("CWE-89")
                || flow.weakness.contains("CWE-200")
                || flow.weakness.contains("CWE-201")
                || flow.weakness.contains("CWE-532");

            if is_privacy_sink {
                let trace_json = serde_json::to_string(&flow).unwrap_or_default();
                let trace_sha256 = crate::to_hex(Sha256::digest(trace_json.as_bytes()));
                let check_id = "BK-AI-PRIV-002".to_string();

                let safe_sink_path = flow.sink_file.replace(['/', '\\'], "-");
                let f_id = format!(
                    "priv-{}-{}-L{}",
                    check_id.to_lowercase(),
                    safe_sink_path,
                    flow.sink_line
                );

                let finding = FindingV1 {
                    schema_version: "1.0".to_string(),
                    run_id: request.run_id.clone(),
                    finding_id: f_id,
                    fingerprint: Some(format!("fp-{}", &trace_sha256[..16])),
                    kind: FindingKind::Catalog,
                    status: FindingStatus::Verified,
                    title: "Sensitive PII propagates to untrusted logging/sink endpoint"
                        .to_string(),
                    summary: Some(format!(
                        "Untrusted PII from {}:{} flows to sensitive sink at {}:{} without sanitization.",
                        flow.source_file, flow.source_line, flow.sink_file, flow.sink_line
                    )),
                    severity: NormalizedSeverity::High,
                    evidence_certainty: EvidenceCertaintyV1::Confirmed,
                    rule_id: Some(check_id),
                    weakness_ids: vec!["CWE-200".to_string(), "CWE-532".to_string()],
                    advisory_ids: Vec::new(),
                    engine: EngineDescriptor {
                        id: self.engine_id.clone(),
                        version: self.engine_version.clone(),
                        rule_pack_sha256: None,
                    },
                    target: TargetDescriptor {
                        target_id: format!("file://{}", flow.sink_file),
                        kind: NormalizedTargetKind::File,
                        path: Some(flow.sink_file.clone()),
                        package_purl: None,
                        version: None,
                        span: Some(SourceSpanV1 {
                            start_line: flow.sink_line,
                            end_line: flow.sink_line,
                            start_column: None,
                            end_column: None,
                        }),
                    },
                    source_snapshot_sha256: request.snapshot_sha256.clone(),
                    evidence: vec![EvidenceItemV1 {
                        kind: EvidenceItemKind::DataflowTrace,
                        artifact_sha256: trace_sha256.clone(),
                        description: format!(
                            "CPG taint flow from {}:{} to {}:{}",
                            flow.source_file, flow.source_line, flow.sink_file, flow.sink_line
                        ),
                        reference: Some(trace_json),
                        limitations: Vec::new(),
                    }],
                    proof: Some(ProofV1 {
                        method: ProofMethod::StaticInvariant,
                        artifact_sha256: trace_sha256,
                        reproduced_on_snapshot: request.snapshot_sha256.clone(),
                        limitations: Vec::new(),
                    }),
                    coverage_receipt_ids: vec![receipt_id.clone()],
                    uncertainty_reasons: Vec::new(),
                    remediation_plan_id: None,
                    created_at: now.clone(),
                    updated_at: None,
                    extensions: serde_json::Map::new(),
                };

                findings.push(finding);
            }
        }

        // 2. Static Pattern & Compliance Checks
        for (file_path, content) in &source_files {
            if cancel_token.is_cancelled() {
                return Err(AnalysisError::Cancelled);
            }

            let priv_findings = Self::evaluate_file(file_path, content);
            for pf in priv_findings {
                let file_str = file_path.to_string_lossy().to_string();
                let snippet_sha256 = crate::to_hex(Sha256::digest(pf.snippet.as_bytes()));
                let finding_id = format!(
                    "priv-{}-{}-L{}",
                    pf.check_id.to_lowercase(),
                    &snippet_sha256[..8],
                    pf.line_number
                );

                let mut ext = serde_json::Map::new();
                ext.insert(
                    "framework".to_string(),
                    serde_json::Value::String(pf.framework.as_str().to_string()),
                );
                if let Some(skill_id) = &pf.associated_skill_id {
                    ext.insert(
                        "recommended_skill".to_string(),
                        serde_json::Value::String(skill_id.clone()),
                    );
                }

                let cwe_id = match pf.check_id.as_str() {
                    "BK-AI-PRIV-001" => "CWE-311",
                    "BK-AI-PRIV-002" => "CWE-359",
                    "BK-AI-PRIV-003" => "CWE-532",
                    "BK-AI-PRIV-004" => "CWE-404",
                    "BK-AI-PRIV-005" => "CWE-285",
                    "BK-AI-PRIV-006" => "CWE-840",
                    "BK-AI-PRIV-007" => "CWE-359",
                    "BK-AI-PRIV-008" => "CWE-359",
                    "BK-AI-PRIV-009" => "CWE-840",
                    "BK-AI-PRIV-010" => "CWE-778",
                    _ => "CWE-359",
                };

                let finding = FindingV1 {
                    schema_version: "1.0".to_string(),
                    run_id: request.run_id.clone(),
                    finding_id: finding_id.clone(),
                    fingerprint: Some(format!("fp-{}", &snippet_sha256[..16])),
                    kind: FindingKind::Catalog,
                    status: FindingStatus::Verified,
                    title: pf.title,
                    summary: Some(pf.description.clone()),
                    severity: pf.severity,
                    evidence_certainty: EvidenceCertaintyV1::Confirmed,
                    rule_id: Some(pf.check_id.clone()),
                    weakness_ids: vec![cwe_id.to_string()],
                    advisory_ids: Vec::new(),
                    engine: EngineDescriptor {
                        id: self.engine_id.clone(),
                        version: self.engine_version.clone(),
                        rule_pack_sha256: None,
                    },
                    target: TargetDescriptor {
                        target_id: format!("file://{}", file_str),
                        kind: NormalizedTargetKind::File,
                        path: Some(file_str.clone()),
                        package_purl: None,
                        version: None,
                        span: Some(SourceSpanV1 {
                            start_line: pf.line_number as u32,
                            end_line: pf.line_number as u32,
                            start_column: Some(pf.column as u32),
                            end_column: Some((pf.column + pf.snippet.len()) as u32),
                        }),
                    },
                    source_snapshot_sha256: request.snapshot_sha256.clone(),
                    evidence: vec![EvidenceItemV1 {
                        kind: EvidenceItemKind::SourceSpan,
                        artifact_sha256: snippet_sha256.clone(),
                        description: pf.description,
                        reference: Some(pf.snippet),
                        limitations: Vec::new(),
                    }],
                    proof: Some(ProofV1 {
                        method: ProofMethod::StaticInvariant,
                        artifact_sha256: snippet_sha256,
                        reproduced_on_snapshot: request.snapshot_sha256.clone(),
                        limitations: Vec::new(),
                    }),
                    coverage_receipt_ids: vec![receipt_id.clone()],
                    uncertainty_reasons: Vec::new(),
                    remediation_plan_id: None,
                    created_at: now.clone(),
                    updated_at: None,
                    extensions: ext,
                };

                findings.push(finding);
            }
        }

        let duration_ms = start_time.elapsed().as_millis() as u64;

        let receipts = targets
            .iter()
            .enumerate()
            .map(|(i, target)| CoverageReceiptV1 {
                schema_version: "1.0".to_string(),
                receipt_id: format!("receipt-{}-{}", request.run_id, i),
                run_id: request.run_id.clone(),
                engine_id: self.engine_id.clone(),
                engine_version: self.engine_version.clone(),
                check_id: request
                    .check_ids
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "privacy.gdpr".to_string()),
                target_id: target.to_string_lossy().to_string(),
                snapshot_sha256: request.snapshot_sha256.clone(),
                status: CoverageReceiptStatus::Evaluated,
                counts: ReceiptCounts {
                    items_discovered: source_files.len() as u64,
                    items_examined: source_files.len() as u64,
                    items_excluded: 0,
                    items_skipped: 0,
                },
                reason_codes: Vec::new(),
                details: vec![
                    "Privacy and data protection compliance analysis complete".to_string(),
                ],
                started_at: now.clone(),
                completed_at: now.clone(),
                required_by_policy: Some(false),
                artifact_digests: Vec::new(),
                previous_receipt_id: None,
            })
            .collect();

        Ok(AnalysisResponse {
            schema_version: "1.0".to_string(),
            run_id: request.run_id.clone(),
            engine_id: self.engine_id.clone(),
            engine_version: self.engine_version.clone(),
            snapshot_sha256: request.snapshot_sha256.clone(),
            status: EngineStatus::Completed,
            findings,
            receipts,
            diagnostics: Vec::new(),
            resources: ResourceUsage {
                duration_ms,
                peak_memory_bytes: 0,
            },
            completed_at: now,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_embedded_privacy_skills_registry_loaded() {
        let reg = PrivacySkillsRegistry::default_embedded();
        assert_eq!(reg.total_skills(), 282, "Must contain exactly 282 skills");

        // Verify regulations indexed
        let gdpr_skills = reg.find_by_regulation("GDPR");
        assert!(!gdpr_skills.is_empty(), "Must index GDPR skills");

        let hipaa_skills = reg.find_by_regulation("HIPAA");
        assert!(!hipaa_skills.is_empty(), "Must index HIPAA skills");

        let ai_skills = reg.find_by_regulation("EU_AI_ACT");
        assert!(!ai_skills.is_empty(), "Must index EU AI Act skills");

        // Verify OWASP risks indexed
        let p1_skills = reg.find_by_owasp("P1");
        assert!(!p1_skills.is_empty(), "Must index OWASP P1 skills");

        // Verify metrics
        let metrics = reg.metrics();
        assert_eq!(metrics.total_skills, 282);
        assert!(metrics.regulations_count > 0);
    }

    #[test]
    fn test_privacy_skill_search_and_recommend() {
        let reg = PrivacySkillsRegistry::default_embedded();
        let results = reg.search("differential privacy");
        assert!(!results.is_empty());
        assert!(results.iter().any(|s| s.id == "differential-privacy-prod"));

        let recs = reg.recommend_for_check("BK-AI-PRIV-001");
        assert!(!recs.is_empty());
    }

    #[test]
    fn test_privacy_engine_adapter_profile_handling() {
        let adapter = PrivacyEngineAdapter::new();
        assert_eq!(adapter.engine_id(), "privacy-engine-adapter");
        assert!(adapter.can_handle_profile(ScanProfile::Deep));
        assert!(adapter.can_handle_profile(ScanProfile::Audit));
        assert!(!adapter.can_handle_profile(ScanProfile::Quick));
    }

    #[test]
    fn test_privacy_engine_static_eval_indefinite_retention() {
        let content = r#"
// config.js
module.exports = {
    retention_period: "indefinite",
    keep_pii_indefinitely: true
};
"#;
        let findings = PrivacyEngineAdapter::evaluate_file(Path::new("config.js"), content);
        assert!(!findings.is_empty());
        assert_eq!(findings[0].check_id, "BK-AI-PRIV-004");
        assert_eq!(findings[0].framework, PrivacyFramework::Gdpr);
    }

    #[test]
    fn test_privacy_engine_static_eval_dsar_missing_auth() {
        let content = r#"
app.post('/api/delete-user-data', async (req, res) => {
    const userId = req.body.userId;
    await db.users.delete({ id: userId });
    res.json({ status: 'deleted' });
});
"#;
        let findings = PrivacyEngineAdapter::evaluate_file(Path::new("routes/user.js"), content);
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.check_id == "BK-AI-PRIV-005"));
    }
}
