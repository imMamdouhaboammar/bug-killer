#[allow(dead_code)]
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::OnceLock;

/// Lifecycle state of a rule in the Security Rule Registry.
///
/// Rules without operational automated detectors must remain `Cataloged` or `ReviewRequired`.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RuleLifecycle {
    Cataloged,
    Experimental,
    SupportedStatic,
    SupportedDynamic,
    ReviewRequired,
    Deprecated,
}

#[allow(dead_code)]
impl RuleLifecycle {
    pub fn as_str(&self) -> &'static str {
        match self {
            RuleLifecycle::Cataloged => "CATALOGED",
            RuleLifecycle::Experimental => "EXPERIMENTAL",
            RuleLifecycle::SupportedStatic => "SUPPORTED_STATIC",
            RuleLifecycle::SupportedDynamic => "SUPPORTED_DYNAMIC",
            RuleLifecycle::ReviewRequired => "REVIEW_REQUIRED",
            RuleLifecycle::Deprecated => "DEPRECATED",
        }
    }

    pub fn is_supported(&self) -> bool {
        matches!(
            self,
            RuleLifecycle::SupportedStatic | RuleLifecycle::SupportedDynamic
        )
    }
}

/// Primary kind of evidence required to confirm or refute a rule.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum EvidenceKind {
    Flow,
    Ast,
    Config,
    Sca,
    Secret,
    Test,
    Dast,
    Fuzz,
    Review,
    Agent,
}

#[allow(dead_code)]
impl EvidenceKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            EvidenceKind::Flow => "FLOW",
            EvidenceKind::Ast => "AST",
            EvidenceKind::Config => "CONFIG",
            EvidenceKind::Sca => "SCA",
            EvidenceKind::Secret => "SECRET",
            EvidenceKind::Test => "TEST",
            EvidenceKind::Dast => "DAST",
            EvidenceKind::Fuzz => "FUZZ",
            EvidenceKind::Review => "REVIEW",
            EvidenceKind::Agent => "AGENT",
        }
    }
}

/// Category metadata definition.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CategoryInfo {
    pub number: u8,
    pub name: String,
    pub title: String,
}

/// A strongly-typed security rule from the AI-Generated Code Security Issues Catalog.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogRule {
    pub rule_id: String,
    pub short_id: String,
    pub rule_version: String,
    pub category_number: u8,
    pub category: String,
    pub description: String,
    pub cwe: Option<String>,
    pub detection_method: String,
    pub required_evidence: Vec<EvidenceKind>,
    pub status: RuleLifecycle,
    pub applicable_languages: Vec<String>,
    pub supported_targets: Vec<String>,
    pub known_limitations: String,
    pub false_positive_considerations: String,
    pub remediation_guidance: String,
    pub verification_requirements: String,
}

/// Security Rule Catalog containing all 373 rules across 27 categories.
#[allow(dead_code)]
pub struct SecurityCatalog {
    rules: Vec<CatalogRule>,
    by_id: HashMap<String, usize>,
    by_short_id: HashMap<String, usize>,
    categories: Vec<CategoryInfo>,
}

#[allow(dead_code)]
static CATALOG_INSTANCE: OnceLock<SecurityCatalog> = OnceLock::new();

#[allow(dead_code)]
impl SecurityCatalog {
    /// Returns a reference to the global static security catalog instance.
    pub fn global() -> &'static SecurityCatalog {
        CATALOG_INSTANCE
            .get_or_init(|| Self::load_embedded().expect("Embedded security catalog must be valid"))
    }

    /// Loads the catalog from embedded JSON source.
    pub fn load_embedded() -> Result<Self, String> {
        let raw_json = include_str!("catalog_data.json");
        let rules: Vec<CatalogRule> = serde_json::from_str(raw_json)
            .map_err(|e| format!("Failed to parse embedded catalog JSON: {}", e))?;

        let mut by_id = HashMap::with_capacity(rules.len());
        let mut by_short_id = HashMap::with_capacity(rules.len());
        let mut cat_map: HashMap<u8, String> = HashMap::new();

        for (idx, r) in rules.iter().enumerate() {
            if by_id.insert(r.rule_id.clone(), idx).is_some() {
                return Err(format!("Duplicate rule_id detected: {}", r.rule_id));
            }
            by_short_id.insert(r.short_id.clone(), idx);

            cat_map
                .entry(r.category_number)
                .or_insert_with(|| r.category.clone());
        }

        let mut categories = Vec::new();
        for num in 1..=27 {
            if let Some(title) = cat_map.get(&num) {
                let name = title
                    .trim_start_matches(|c: char| c.is_ascii_digit() || c == '.' || c == ' ')
                    .to_string();
                categories.push(CategoryInfo {
                    number: num,
                    name,
                    title: title.clone(),
                });
            }
        }

        let catalog = Self {
            rules,
            by_id,
            by_short_id,
            categories,
        };

        catalog.validate()?;
        Ok(catalog)
    }

    /// Verifies catalog completeness, non-empty invariants, and consistency.
    pub fn validate(&self) -> Result<(), String> {
        if self.rules.len() != 373 {
            return Err(format!(
                "Catalog must contain exactly 373 rules, found {}",
                self.rules.len()
            ));
        }

        if self.categories.len() != 27 {
            return Err(format!(
                "Catalog must contain exactly 27 categories, found {}",
                self.categories.len()
            ));
        }

        for rule in &self.rules {
            if !rule.rule_id.starts_with("BK-AI-") {
                return Err(format!(
                    "Rule ID must start with 'BK-AI-': {}",
                    rule.rule_id
                ));
            }
            if rule.description.trim().is_empty() {
                return Err(format!("Empty description for rule {}", rule.rule_id));
            }
            if rule.category_number < 1 || rule.category_number > 27 {
                return Err(format!(
                    "Invalid category number {} for rule {}",
                    rule.category_number, rule.rule_id
                ));
            }
        }

        Ok(())
    }

    /// Returns a slice of all catalog rules.
    pub fn all_rules(&self) -> &[CatalogRule] {
        &self.rules
    }

    /// Total count of rules in the catalog.
    pub fn count(&self) -> usize {
        self.rules.len()
    }

    /// Total count of categories in the catalog.
    pub fn category_count(&self) -> usize {
        self.categories.len()
    }

    /// Looks up a rule by full ID (e.g. `BK-AI-INJ-001`).
    pub fn get_rule(&self, rule_id: &str) -> Option<&CatalogRule> {
        let normalized = if rule_id.starts_with("BK-AI-") {
            rule_id.to_string()
        } else {
            format!("BK-AI-{}", rule_id)
        };
        self.by_id.get(&normalized).map(|&idx| &self.rules[idx])
    }

    /// Looks up a rule by short ID (e.g. `INJ-001`).
    pub fn get_rule_by_short_id(&self, short_id: &str) -> Option<&CatalogRule> {
        self.by_short_id.get(short_id).map(|&idx| &self.rules[idx])
    }

    /// Returns all rules in a specific category number (1 to 27).
    pub fn rules_by_category(&self, cat_num: u8) -> Vec<&CatalogRule> {
        self.rules
            .iter()
            .filter(|r| r.category_number == cat_num)
            .collect()
    }

    /// Returns all rules matching a specific lifecycle status.
    pub fn rules_by_status(&self, status: RuleLifecycle) -> Vec<&CatalogRule> {
        self.rules.iter().filter(|r| r.status == status).collect()
    }

    /// Returns all currently supported rules (static or dynamic).
    pub fn supported_rules(&self) -> Vec<&CatalogRule> {
        self.rules
            .iter()
            .filter(|r| r.status.is_supported())
            .collect()
    }

    /// Returns all unsupported rules (cataloged, review-required, experimental, deprecated).
    pub fn unsupported_rules(&self) -> Vec<&CatalogRule> {
        self.rules
            .iter()
            .filter(|r| !r.status.is_supported())
            .collect()
    }

    /// Returns all category definitions.
    pub fn categories(&self) -> &[CategoryInfo] {
        &self.categories
    }

    /// Filters rules by language applicability.
    pub fn rules_for_language(&self, lang: &str) -> Vec<&CatalogRule> {
        let lang_lower = lang.to_lowercase();
        self.rules
            .iter()
            .filter(|r| {
                r.applicable_languages.contains(&"generic".to_string())
                    || r.applicable_languages.iter().any(|l| l == &lang_lower)
            })
            .collect()
    }
}
