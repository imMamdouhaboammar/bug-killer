use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Severity {
    Critical,
    High,
    Medium,
    HighBug,
    Bug,
    Low,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::HighBug => "HIGH_BUG",
            Severity::Bug => "BUG",
            Severity::Low => "LOW",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RevalidationVerdict {
    TruePositive,
    FalsePositive,
    Fixed,
    Uncertain,
    AcceptedRisk,
    Duplicate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TriagePriority {
    P0,
    P1,
    P2,
    #[serde(rename = "skip")]
    Skip,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FileStatus {
    Pending,
    Processing,
    Analyzed,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectConfig {
    pub project_id: String,
    pub root_path: String,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub github_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CandidateMatch {
    pub vuln_slug: String,
    pub line_numbers: Vec<usize>,
    pub snippet: String,
    pub matched_pattern: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Triage {
    pub priority: TriagePriority,
    pub exploitability: String,
    pub impact: String,
    pub reasoning: String,
    pub triaged_at: String,
    pub model: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Revalidation {
    pub verdict: RevalidationVerdict,
    pub reasoning: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub adjusted_severity: Option<Severity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duplicate_of: Option<String>,
    pub revalidated_at: String,
    pub run_id: String,
    pub model: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub finding_id: String,
    pub severity: Severity,
    pub vuln_slug: String,
    pub title: String,
    pub description: String,
    pub line_numbers: Vec<usize>,
    pub recommendation: String,
    pub confidence: Confidence,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub triage: Option<Triage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revalidation: Option<Revalidation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub produced_by_run_id: Option<String>,
}

pub fn compute_finding_id(project_id: &str, file_path: &str, title: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(project_id.as_bytes());
    hasher.update(b":");
    hasher.update(file_path.as_bytes());
    hasher.update(b":");
    hasher.update(title.trim().as_bytes());
    let hex = crate::identity::to_hex(hasher.finalize());
    format!("finding_{}", &hex[..16])
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TokenUsage {
    pub input_tokens: usize,
    pub output_tokens: usize,
    pub cache_read_input_tokens: usize,
    pub cache_creation_input_tokens: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisEntry {
    pub run_id: String,
    pub investigated_at: String,
    pub duration_ms: u64,
    pub agent_type: String,
    pub model: String,
    pub finding_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cost_usd: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage: Option<TokenUsage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phase: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitCommitter {
    pub name: String,
    pub email: String,
    pub date: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitInfo {
    pub recent_committers: Vec<GitCommitter>,
    pub enriched_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileRecord {
    pub file_path: String,
    pub project_id: String,
    pub candidates: Vec<CandidateMatch>,
    pub last_scanned_at: String,
    pub last_scanned_run_id: String,
    pub file_hash: String,
    pub findings: Vec<Finding>,
    pub analysis_history: Vec<AnalysisEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_info: Option<GitInfo>,
    pub status: FileStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locked_by_run_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locked_at: Option<String>,
}

impl FileRecord {
    pub fn new(file_path: String, project_id: String, file_hash: String, run_id: String) -> Self {
        let now = Utc::now().to_rfc3339();
        Self {
            file_path,
            project_id,
            candidates: Vec::new(),
            last_scanned_at: now,
            last_scanned_run_id: run_id,
            file_hash,
            findings: Vec::new(),
            analysis_history: Vec::new(),
            git_info: None,
            status: FileStatus::Pending,
            locked_by_run_id: None,
            locked_at: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RunStats {
    pub files_scanned: usize,
    pub candidates_found: usize,
    pub files_processed: usize,
    pub findings_count: usize,
    pub total_cost_usd: f64,
    pub total_input_tokens: usize,
    pub total_output_tokens: usize,
    pub total_duration_ms: u64,
    pub findings_revalidated: usize,
    pub true_positives: usize,
    pub false_positives: usize,
    pub fixed: usize,
    pub uncertain: usize,
    pub duplicates: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunMeta {
    pub run_id: String,
    pub project_id: String,
    pub root_path: String,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<String>,
    pub run_type: String,
    pub phase: String,
    pub pid: u32,
    pub hostname: String,
    pub stats: RunStats,
}

impl RunMeta {
    pub fn new(run_id: String, project_id: String, root_path: String, run_type: String) -> Self {
        let now = Utc::now().to_rfc3339();
        let pid = std::process::id();
        let hostname = std::env::var("HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
        Self {
            run_id,
            project_id,
            root_path,
            created_at: now,
            completed_at: None,
            run_type,
            phase: "running".to_string(),
            pid,
            hostname,
            stats: RunStats::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SurfaceEntry {
    pub id: String,
    pub kind: String,
    pub exposure: String,
    pub file_globs: Vec<String>,
    pub representative_files: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SurfaceInventory {
    pub project_id: String,
    pub generated_at: String,
    pub surfaces: Vec<SurfaceEntry>,
}
