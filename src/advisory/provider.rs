use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AdvisoryStatus {
    Active,
    Withdrawn,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdvisorySource {
    pub provider: String,
    pub url: String,
    pub retrieved_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AdvisoryEvent {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub introduced: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fixed: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_affected: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdvisoryRange {
    #[serde(rename = "type")]
    pub range_type: String,
    #[serde(default)]
    pub events: Vec<AdvisoryEvent>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdvisoryAffected {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purl: Option<String>,
    pub ecosystem: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default)]
    pub ranges: Vec<AdvisoryRange>,
    #[serde(default)]
    pub fixed_versions: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdvisoryRecord {
    pub schema_version: String,
    pub advisory_id: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    pub source: AdvisorySource,
    pub source_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub published_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modified_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub withdrawn_at: Option<String>,
    #[serde(default)]
    pub affected: Vec<AdvisoryAffected>,
    #[serde(default)]
    pub references: Vec<String>,
    pub status: AdvisoryStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
}

pub trait AdvisoryProvider: Send + Sync {
    fn get_advisories_for_package(&self, purl: &str) -> Vec<AdvisoryRecord>;
}

#[derive(Debug, Clone, Default)]
pub struct MockAdvisoryProvider {
    advisories: Vec<AdvisoryRecord>,
}

impl MockAdvisoryProvider {
    pub fn new() -> Self {
        Self {
            advisories: Vec::new(),
        }
    }

    pub fn with_advisories(advisories: Vec<AdvisoryRecord>) -> Self {
        Self { advisories }
    }

    pub fn add_advisory(&mut self, record: AdvisoryRecord) {
        self.advisories.push(record);
    }
}

impl AdvisoryProvider for MockAdvisoryProvider {
    fn get_advisories_for_package(&self, purl: &str) -> Vec<AdvisoryRecord> {
        let clean_purl = purl.split('@').next().unwrap_or(purl);

        self.advisories
            .iter()
            .filter(|adv| {
                adv.affected.iter().any(|aff| {
                    if let Some(ref aff_purl) = aff.purl {
                        let clean_aff_purl = aff_purl.split('@').next().unwrap_or(aff_purl);
                        if clean_aff_purl.eq_ignore_ascii_case(clean_purl) {
                            return true;
                        }
                    }
                    if let Some(ref aff_name) = aff.name {
                        let purl_lower = purl.to_lowercase();
                        let eco_lower = aff.ecosystem.to_lowercase();
                        let name_lower = aff_name.to_lowercase();

                        if purl_lower.contains(&eco_lower) && purl_lower.contains(&name_lower) {
                            return true;
                        }
                    }
                    false
                })
            })
            .cloned()
            .collect()
    }
}
