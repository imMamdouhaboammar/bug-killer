pub mod coordinator;
pub mod enrich;
pub mod export;
pub mod matchers;
pub mod processor;
pub mod prompt;
pub mod revalidate;
pub mod scanner;
pub mod storage;
pub mod triage;
pub mod types;

pub use coordinator::initialize_project;
pub use enrich::enrich_findings;
pub use export::{export_json, export_md_dir, generate_markdown_report, render_terminal_summary};
pub use matchers::{Matcher, MatcherRegistry, NoiseTier};
pub use processor::{
    DeepSecAIClient, HttpAIClient, MockAIClient, ProcessOptions, process_repository,
};
pub use prompt::{CORE_PROMPT, assemble_prompt};
pub use revalidate::{RevalidateOptions, revalidate_findings};
pub use scanner::{ScanOptions, detect_tech, is_ignored_path, scan_content, scan_repository};
pub use storage::StorageManager;
pub use triage::triage_findings;
pub use types::*;
