use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

/// High-level defensive classification of a cybersecurity skill within Bug Killer's defensive perimeter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DefensiveClass {
    Detection,
    Hardening,
    VirtualPatching,
    ForensicsTriage,
    AuditCompliance,
    AdversarialSimulation,
}

impl DefensiveClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            DefensiveClass::Detection => "DETECTION",
            DefensiveClass::Hardening => "HARDENING",
            DefensiveClass::VirtualPatching => "VIRTUAL_PATCHING",
            DefensiveClass::ForensicsTriage => "FORENSICS_TRIAGE",
            DefensiveClass::AuditCompliance => "AUDIT_COMPLIANCE",
            DefensiveClass::AdversarialSimulation => "ADVERSARIAL_SIMULATION",
        }
    }

    pub fn from_str_loose(s: &str) -> Self {
        match s.to_uppercase().trim() {
            "DETECTION" | "DETECT" | "HUNTING" => DefensiveClass::Detection,
            "HARDENING" | "HARDEN" | "CONFIGURATION" => DefensiveClass::Hardening,
            "VIRTUAL_PATCHING" | "PATCH" | "REMEDIATION" | "MITIGATION" => {
                DefensiveClass::VirtualPatching
            }
            "FORENSICS_TRIAGE" | "FORENSICS" | "TRIAGE" | "INCIDENT_RESPONSE" => {
                DefensiveClass::ForensicsTriage
            }
            "AUDIT_COMPLIANCE" | "COMPLIANCE" | "AUDIT" | "GOVERNANCE" => {
                DefensiveClass::AuditCompliance
            }
            "ADVERSARIAL_SIMULATION" | "SIMULATION" | "RED_TEAM" | "PURPLE_TEAM" => {
                DefensiveClass::AdversarialSimulation
            }
            _ => DefensiveClass::Detection,
        }
    }
}

/// A structured cybersecurity skill imported from Anthropic Cybersecurity Skills.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CybersecuritySkill {
    pub id: String,
    pub name: String,
    pub description: String,
    pub domain: String,
    pub subdomain: String,
    pub tags: Vec<String>,
    pub nist_csf: Vec<String>,
    pub mitre_attack: Vec<String>,
    pub defensive_class: DefensiveClass,
    pub version: String,
    pub author: String,
    pub path: String,
}

impl CybersecuritySkill {
    /// Checks whether this skill matches a general search query.
    pub fn matches_query(&self, q: &str) -> bool {
        let q_lower = q.to_lowercase();
        if self.id.to_lowercase().contains(&q_lower)
            || self.name.to_lowercase().contains(&q_lower)
            || self.description.to_lowercase().contains(&q_lower)
            || self.subdomain.to_lowercase().contains(&q_lower)
        {
            return true;
        }
        if self
            .tags
            .iter()
            .any(|t| t.to_lowercase().contains(&q_lower))
        {
            return true;
        }
        if self
            .mitre_attack
            .iter()
            .any(|m| m.to_lowercase().contains(&q_lower))
        {
            return true;
        }
        if self
            .nist_csf
            .iter()
            .any(|n| n.to_lowercase().contains(&q_lower))
        {
            return true;
        }
        false
    }

    /// Checks whether this skill is mapped to a specific MITRE ATT&CK technique ID (e.g. "T1190").
    pub fn has_mitre_technique(&self, technique_id: &str) -> bool {
        let needle = technique_id.trim().to_uppercase();
        self.mitre_attack.iter().any(|m| {
            let m_upper = m.to_uppercase();
            m_upper == needle || m_upper.starts_with(&format!("{}.", needle))
        })
    }

    /// Checks whether this skill is mapped to a specific NIST CSF control (e.g. "PR.DS-01").
    pub fn has_nist_control(&self, control_id: &str) -> bool {
        let needle = control_id.trim().to_uppercase();
        self.nist_csf
            .iter()
            .any(|n| n.to_uppercase().contains(&needle))
    }

    /// Checks whether this skill has the given tag.
    pub fn has_tag(&self, tag: &str) -> bool {
        let needle = tag.trim().to_lowercase();
        self.tags.iter().any(|t| t.to_lowercase() == needle)
    }
}

/// Statistical breakdown of skills across subdomains, frameworks, and defensive postures.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SkillsRegistryMetrics {
    pub total_skills: usize,
    pub subdomains_count: usize,
    pub mitre_techniques_count: usize,
    pub nist_controls_count: usize,
    pub defensive_classes: HashMap<String, usize>,
    pub top_subdomains: Vec<(String, usize)>,
}

static EMBEDDED_REGISTRY: OnceLock<CybersecuritySkillsRegistry> = OnceLock::new();

/// Deep knowledge engine and index for curated cybersecurity skills.
#[derive(Debug, Clone)]
pub struct CybersecuritySkillsRegistry {
    skills: Vec<CybersecuritySkill>,
    by_id: HashMap<String, usize>,
    by_subdomain: HashMap<String, Vec<usize>>,
    by_mitre: HashMap<String, Vec<usize>>,
    by_nist: HashMap<String, Vec<usize>>,
    by_tag: HashMap<String, Vec<usize>>,
    by_class: HashMap<DefensiveClass, Vec<usize>>,
    catalog_path: Option<PathBuf>,
}

impl Default for CybersecuritySkillsRegistry {
    fn default() -> Self {
        Self::default_embedded().clone()
    }
}

impl CybersecuritySkillsRegistry {
    /// Creates an empty registry.
    pub fn new() -> Self {
        Self {
            skills: Vec::new(),
            by_id: HashMap::new(),
            by_subdomain: HashMap::new(),
            by_mitre: HashMap::new(),
            by_nist: HashMap::new(),
            by_tag: HashMap::new(),
            by_class: HashMap::new(),
            catalog_path: None,
        }
    }

    /// Builds a registry from a list of skills, establishing inverted indexes for all attributes.
    pub fn from_skills(skills: Vec<CybersecuritySkill>) -> Self {
        let mut by_id = HashMap::with_capacity(skills.len());
        let mut by_subdomain: HashMap<String, Vec<usize>> = HashMap::new();
        let mut by_mitre: HashMap<String, Vec<usize>> = HashMap::new();
        let mut by_nist: HashMap<String, Vec<usize>> = HashMap::new();
        let mut by_tag: HashMap<String, Vec<usize>> = HashMap::new();
        let mut by_class: HashMap<DefensiveClass, Vec<usize>> = HashMap::new();

        for (idx, skill) in skills.iter().enumerate() {
            by_id.insert(skill.id.clone(), idx);
            by_id.insert(skill.name.clone(), idx);

            by_subdomain
                .entry(skill.subdomain.to_lowercase())
                .or_default()
                .push(idx);

            for mitre in &skill.mitre_attack {
                let m_norm = mitre.to_uppercase();
                by_mitre.entry(m_norm.clone()).or_default().push(idx);
                // Also index root technique if sub-technique (e.g. T1059.007 -> T1059)
                if let Some((root, _)) = m_norm.split_once('.') {
                    by_mitre.entry(root.to_string()).or_default().push(idx);
                }
            }

            for nist in &skill.nist_csf {
                by_nist.entry(nist.to_uppercase()).or_default().push(idx);
            }

            for tag in &skill.tags {
                by_tag.entry(tag.to_lowercase()).or_default().push(idx);
            }

            by_class.entry(skill.defensive_class).or_default().push(idx);
        }

        Self {
            skills,
            by_id,
            by_subdomain,
            by_mitre,
            by_nist,
            by_tag,
            by_class,
            catalog_path: None,
        }
    }

    /// Parses skills from a JSON string.
    pub fn from_json_str(json_str: &str) -> Result<Self, String> {
        let skills: Vec<CybersecuritySkill> = serde_json::from_str(json_str)
            .map_err(|e| format!("Failed to parse skills JSON: {}", e))?;
        Ok(Self::from_skills(skills))
    }

    /// Loads skills from a JSON file path.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, String> {
        let path_ref = path.as_ref();
        let content = std::fs::read_to_string(path_ref)
            .map_err(|e| format!("Failed to read skills file '{}': {}", path_ref.display(), e))?;
        let mut registry = Self::from_json_str(&content)?;
        registry.catalog_path = Some(path_ref.to_path_buf());
        Ok(registry)
    }

    /// Returns the global embedded registry instance compiled directly into the binary.
    pub fn default_embedded() -> &'static Self {
        EMBEDDED_REGISTRY.get_or_init(|| {
            const EMBEDDED_JSON: &str = include_str!("cyber_skills_data.json");
            Self::from_json_str(EMBEDDED_JSON).unwrap_or_else(|e| {
                panic!(
                    "Critical: Failed to parse embedded cyber_skills_data.json: {}",
                    e
                )
            })
        })
    }

    /// Loads registry from disk if available at standard workspace paths, falling back to embedded.
    pub fn load_or_default(workspace_root: Option<&Path>) -> Self {
        let candidates = [
            workspace_root.map(|p| p.join("rules/cybersecurity_skills/catalog.json")),
            workspace_root.map(|p| p.join("catalog.json")),
            Some(PathBuf::from("rules/cybersecurity_skills/catalog.json")),
            Some(PathBuf::from("cybersecurity_skills/catalog.json")),
        ];

        for cand in candidates.into_iter().flatten() {
            if cand.is_file() {
                if let Ok(reg) = Self::from_file(&cand) {
                    return reg;
                }
            }
        }

        Self::default_embedded().clone()
    }

    /// Number of skills currently indexed.
    pub fn len(&self) -> usize {
        self.skills.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.skills.is_empty()
    }

    /// Retrieves a skill by exact ID or name.
    pub fn get(&self, id: &str) -> Option<&CybersecuritySkill> {
        self.by_id.get(id).map(|&idx| &self.skills[idx])
    }

    /// Returns a slice of all indexed skills.
    pub fn all(&self) -> &[CybersecuritySkill] {
        &self.skills
    }

    /// Returns all distinct subdomains present in the registry.
    pub fn subdomains(&self) -> Vec<String> {
        let mut subs: Vec<String> = self.by_subdomain.keys().cloned().collect();
        subs.sort();
        subs
    }

    /// Retrieves all skills within a specific subdomain.
    pub fn find_by_subdomain(&self, subdomain: &str) -> Vec<&CybersecuritySkill> {
        let key = subdomain.to_lowercase();
        self.by_subdomain
            .get(&key)
            .map(|indices| indices.iter().map(|&i| &self.skills[i]).collect())
            .unwrap_or_default()
    }

    /// Retrieves all skills mapped to a MITRE ATT&CK technique ID (e.g. "T1190").
    pub fn find_by_mitre(&self, technique_id: &str) -> Vec<&CybersecuritySkill> {
        let key = technique_id.trim().to_uppercase();
        self.by_mitre
            .get(&key)
            .map(|indices| {
                let mut set = std::collections::BTreeSet::new();
                for &idx in indices {
                    set.insert(idx);
                }
                set.into_iter().map(|i| &self.skills[i]).collect()
            })
            .unwrap_or_default()
    }

    /// Retrieves all skills mapped to a NIST CSF control ID (e.g. "PR.DS-01").
    pub fn find_by_nist(&self, control_id: &str) -> Vec<&CybersecuritySkill> {
        let key = control_id.trim().to_uppercase();
        self.by_nist
            .get(&key)
            .map(|indices| indices.iter().map(|&i| &self.skills[i]).collect())
            .unwrap_or_default()
    }

    /// Retrieves all skills with a specific tag.
    pub fn find_by_tag(&self, tag: &str) -> Vec<&CybersecuritySkill> {
        let key = tag.trim().to_lowercase();
        self.by_tag
            .get(&key)
            .map(|indices| indices.iter().map(|&i| &self.skills[i]).collect())
            .unwrap_or_default()
    }

    /// Retrieves all skills matching a specific defensive posture.
    pub fn find_by_defensive_class(&self, class: DefensiveClass) -> Vec<&CybersecuritySkill> {
        self.by_class
            .get(&class)
            .map(|indices| indices.iter().map(|&i| &self.skills[i]).collect())
            .unwrap_or_default()
    }

    /// Full-text search across skill identifiers, titles, descriptions, subdomains, tags, and framework mappings.
    pub fn search(&self, query: &str) -> Vec<&CybersecuritySkill> {
        let q = query.trim();
        if q.is_empty() {
            return self.skills.iter().collect();
        }
        self.skills.iter().filter(|s| s.matches_query(q)).collect()
    }

    /// Recommends relevant cybersecurity skills for a specific CVE identifier.
    pub fn recommend_for_cve(&self, cve_id: &str) -> Vec<&CybersecuritySkill> {
        let cve_upper = cve_id.trim().to_uppercase();

        // 1. First-class CVE coverage for core runtime targets
        let keywords: Vec<&str> =
            if cve_upper.contains("2026-109618") || cve_upper.contains("2026-109619") {
                // PHP2Shell memory corruption / heap overflow / OOB execution
                vec![
                    "php",
                    "heap",
                    "memory",
                    "buffer",
                    "overflow",
                    "remote-code-execution",
                    "rce",
                ]
            } else if cve_upper.contains("2026-111497") {
                // Node2Shell brotli memory desync / buffer overwrite
                vec![
                    "node",
                    "brotli",
                    "buffer",
                    "memory",
                    "deserialization",
                    "dos",
                ]
            } else if cve_upper.contains("2021-44228") || cve_upper.contains("LOG4SHELL") {
                vec!["jndi", "log4j", "java", "rce", "injection"]
            } else if cve_upper.contains("2020-1472") || cve_upper.contains("ZEROLOGON") {
                vec![
                    "zerologon",
                    "netlogon",
                    "active-directory",
                    "privilege-escalation",
                ]
            } else if cve_upper.contains("2017-010") || cve_upper.contains("ETERNALBLUE") {
                vec!["smb", "eternalblue", "ms17-010", "windows"]
            } else {
                // Generic query decomposition
                cve_upper.split('-').collect()
            };

        let mut results = Vec::new();
        let mut seen = std::collections::HashSet::new();

        for kw in keywords {
            if kw.len() < 3 {
                continue;
            }
            for skill in self.search(kw) {
                if seen.insert(&skill.id) {
                    results.push(skill);
                }
            }
        }

        // Always prioritize defensive and virtual patch skills first
        results.sort_by_key(|s| match s.defensive_class {
            DefensiveClass::VirtualPatching => 0,
            DefensiveClass::Detection => 1,
            DefensiveClass::Hardening => 2,
            DefensiveClass::ForensicsTriage => 3,
            DefensiveClass::AuditCompliance => 4,
            DefensiveClass::AdversarialSimulation => 5,
        });

        results
    }

    /// Recommends relevant skills for an operations room mission goal (known, prevention, research, etc.).
    pub fn recommend_for_goal(&self, goal: &str) -> Vec<&CybersecuritySkill> {
        match goal.to_lowercase().trim() {
            "known" => {
                let mut list = self.find_by_defensive_class(DefensiveClass::AuditCompliance);
                list.extend(self.find_by_defensive_class(DefensiveClass::Detection));
                list.retain(|s| {
                    s.tags.iter().any(|t| {
                        let t_l = t.to_lowercase();
                        t_l.contains("cve")
                            || t_l.contains("vulnerability")
                            || t_l.contains("sbom")
                            || t_l.contains("sca")
                    })
                });
                list
            }
            "prevention" => {
                let mut list = self.find_by_defensive_class(DefensiveClass::VirtualPatching);
                list.extend(self.find_by_defensive_class(DefensiveClass::Hardening));
                list.extend(self.find_by_subdomain("web-application-security"));
                list.extend(self.find_by_subdomain("container-security"));
                list.extend(self.find_by_subdomain("cloud-security"));
                list.sort_by(|a, b| a.id.cmp(&b.id));
                list.dedup_by(|a, b| a.id == b.id);
                list
            }
            "research" => {
                let mut list = self.find_by_defensive_class(DefensiveClass::AdversarialSimulation);
                list.extend(self.find_by_subdomain("malware-analysis"));
                list.extend(self.find_by_subdomain("threat-hunting"));
                list.sort_by(|a, b| a.id.cmp(&b.id));
                list.dedup_by(|a, b| a.id == b.id);
                list
            }
            "forensics" | "incident_response" => {
                self.find_by_defensive_class(DefensiveClass::ForensicsTriage)
            }
            "compliance" | "audit" => self.find_by_defensive_class(DefensiveClass::AuditCompliance),
            _ => self.skills.iter().collect(),
        }
    }

    /// Recommends relevant skills associated with an external security tool (Semgrep, CodeQL, Joern, Trivy, etc.).
    pub fn recommend_for_tool(&self, tool_id: &str) -> Vec<&CybersecuritySkill> {
        let t_norm = tool_id.to_lowercase();
        let filter_tags: &[&str] = if t_norm.contains("semgrep") {
            &[
                "sast",
                "semgrep",
                "ast",
                "code-review",
                "injection",
                "xss",
                "deserialization",
            ]
        } else if t_norm.contains("codeql") {
            &[
                "codeql",
                "cpg",
                "memory-corruption",
                "dataflow",
                "taint",
                "buffer-overflow",
                "source-sink",
            ]
        } else if t_norm.contains("joern") {
            &[
                "cpg",
                "code-property-graph",
                "ast",
                "cfg",
                "taint-analysis",
                "binary-analysis",
                "static-analysis",
            ]
        } else if t_norm.contains("trivy") {
            &[
                "container-security",
                "docker",
                "kubernetes",
                "sbom",
                "iac",
                "vulnerability-management",
                "cve",
            ]
        } else if t_norm.contains("osv") {
            &[
                "sca",
                "supply-chain",
                "dependency",
                "vulnerability-management",
                "cve",
            ]
        } else if t_norm.contains("nuclei") {
            &[
                "dast",
                "api-security",
                "web-application-security",
                "fuzzing",
            ]
        } else if t_norm.contains("gitleaks") || t_norm.contains("trufflehog") {
            &["secrets", "credentials", "credential-access", "api-key"]
        } else {
            &[]
        };

        let mut results = Vec::new();
        let mut seen = std::collections::HashSet::new();

        for tag in filter_tags {
            for s in self.find_by_tag(tag) {
                if seen.insert(&s.id) {
                    results.push(s);
                }
            }
            for s in self.search(tag) {
                if seen.insert(&s.id) {
                    results.push(s);
                }
            }
        }

        results
    }

    /// Computes summary metrics across the skills catalog.
    pub fn metrics(&self) -> SkillsRegistryMetrics {
        let mut defensive_classes = HashMap::new();
        for s in &self.skills {
            *defensive_classes
                .entry(s.defensive_class.as_str().to_string())
                .or_insert(0) += 1;
        }

        let mut top_subdomains: Vec<(String, usize)> = self
            .by_subdomain
            .iter()
            .map(|(k, v)| (k.clone(), v.len()))
            .collect();
        top_subdomains.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

        SkillsRegistryMetrics {
            total_skills: self.skills.len(),
            subdomains_count: self.by_subdomain.len(),
            mitre_techniques_count: self.by_mitre.len(),
            nist_controls_count: self.by_nist.len(),
            defensive_classes,
            top_subdomains,
        }
    }
}
