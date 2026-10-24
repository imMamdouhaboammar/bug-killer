use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CveId {
    Php2ShellOom(String),     // CVE-2026-109618
    Php2ShellStale(String),   // CVE-2026-109619
    Node2ShellBrotli(String), // CVE-2026-111497
}

impl CveId {
    pub fn as_str(&self) -> &str {
        match self {
            CveId::Php2ShellOom(_) => "CVE-2026-109618",
            CveId::Php2ShellStale(_) => "CVE-2026-109619",
            CveId::Node2ShellBrotli(_) => "CVE-2026-111497",
        }
    }

    pub fn title(&self) -> &str {
        match self {
            CveId::Php2ShellOom(_) => "PHP2Shell: RCE via Out-of-Memory (OOM) Heap Corruption",
            CveId::Php2ShellStale(_) => "PHP2Shell: RCE via Stale Global State / Use-After-Free Across Requests",
            CveId::Node2ShellBrotli(_) => "Node2Shell: Out-of-Bounds Memory Write in Bundled Google Brotli Decoder",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TargetKind {
    PhpRuntime,
    PhpConfigFile,
    PhpFpmPool,
    ComposerManifest,
    NodeRuntime,
    NodePackageManifest,
    NodeLockfile,
    NodeSourceFile,
    NginxConfig,
    ApacheConfig,
    CaddyConfig,
    Dockerfile,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub cve: CveId,
    pub severity: Severity,
    pub target_kind: TargetKind,
    pub file_path: Option<PathBuf>,
    pub line_number: Option<usize>,
    pub detected_version_or_pattern: String,
    pub safe_threshold: String,
    pub description: String,
    pub suggested_remediation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PatchActionType {
    NginxVirtualPatch,
    ApacheVirtualPatch,
    NodeMiddlewareGuard,
    PackageManifestVersionBump,
    ComposerVersionBump,
    DockerfileBaseImageBump,
    PhpIniHardening,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchAction {
    pub action_type: PatchActionType,
    pub target_file: PathBuf,
    pub original_checksum: String,
    pub diff_description: String,
    pub replacement_content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupRecord {
    pub relative_target_path: String,
    pub original_sha256: String,
    pub backup_file_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupManifest {
    pub backup_id: String,
    pub created_at: String,
    pub root_dir: String,
    pub records: Vec<BackupRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub target_dir: PathBuf,
    pub scan_time: String,
    pub total_files_scanned: usize,
    pub findings: Vec<Finding>,
    pub is_vulnerable: bool,
    pub critical_count: usize,
    pub high_count: usize,
}
