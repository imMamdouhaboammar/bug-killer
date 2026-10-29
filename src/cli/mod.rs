pub mod handlers;

pub use clap::CommandFactory;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "bug-killer")]
#[command(
    about = "Bug Killer: Let Your AI Find Deep & Ghosty Bugs, Vulnerabilities, and Security Issues and Heal From Them",
    version = "0.1.0"
)]
pub struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Launch the interactive Bug Killer REPL shell
    Shell {
        /// Initial working directory path (default: current directory)
        #[arg(default_value = ".")]
        path: PathBuf,
    },

    /// Run diagnostic system and environment health audit
    Doctor {
        /// Target directory path (default: current directory)
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Output diagnostic report as JSON
        #[arg(long)]
        json: bool,
    },

    /// Start live surveillance monitoring filesystem for security regressions
    Watch {
        /// Target directory path (default: current directory)
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Surveillance polling interval in seconds (default: 3)
        #[arg(short, long, default_value_t = 3)]
        interval: u64,

        /// Automatically apply safe healing patches upon detecting vulnerabilities
        #[arg(long, default_value_t = false)]
        auto_heal: bool,

        /// Custom path to rules directory or JSON rule file
        #[arg(long)]
        rules: Option<PathBuf>,
    },

    /// Generate shell auto-completion script for bash, zsh, fish, or powershell
    Completion {
        /// Target shell (bash, zsh, fish, powershell, elvish)
        shell: String,
    },

    /// Scan target directories and systems for PHP2Shell (CVE-2026-109618, CVE-2026-109619) and Node2Shell (CVE-2026-111497)
    Scan {
        /// Target directory path (default: current directory)
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Output results as JSON
        #[arg(long)]
        json: bool,

        /// Also inspect host binary runtimes (php, node) on PATH
        #[arg(long, default_value_t = false)]
        check_runtime: bool,

        /// Custom path to rules directory or JSON rule file
        #[arg(long)]
        rules: Option<PathBuf>,

        /// Also query free open vulnerability database (OSV.dev) for dependencies
        #[arg(long, default_value_t = false)]
        osv: bool,

        /// Also perform scope-aware taint analysis on source code
        #[arg(long, default_value_t = false)]
        taint: bool,
    },

    /// Defensively probe a live web application endpoint for security posture, headers, and disclosures
    Probe {
        /// Target URL (e.g. http://localhost:8080 or https://example.com)
        url: String,

        /// Output diagnostic probe report as JSON
        #[arg(long)]
        json: bool,

        /// Request timeout in seconds (default: 10)
        #[arg(short, long, default_value_t = 10)]
        timeout: u64,

        /// Allow probing sensitive endpoints (/.env, /.git/HEAD) on authorized local targets (default: false)
        #[arg(long, default_value_t = false)]
        sensitive_paths: bool,

        /// Confirm you have permission to probe the exact target URL and host
        #[arg(long, default_value_t = false)]
        authorized: bool,

        /// Include internal/private IP destinations for the explicitly authorized host
        #[arg(long, requires = "authorized", default_value_t = false)]
        allow_private_targets: bool,
    },

    /// Query open-source vulnerability database (https://osv.dev) for dependencies across npm, Packagist, PyPI, and crates.io
    Osv {
        /// Target directory path (default: current directory)
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Output results as JSON
        #[arg(long)]
        json: bool,
    },

    /// Plan and automatically heal vulnerable configurations, Dockerfiles, manifests, and web servers
    Heal {
        /// Target directory path (default: current directory)
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Show planned patches and diffs without modifying files
        #[arg(long)]
        dry_run: bool,

        /// Deprecated unsafe shortcut; rejected in favor of operator-signed approval
        #[arg(long, default_value_t = false)]
        apply: bool,

        /// Deprecated unsafe shortcut; rejected in favor of operator-signed approval
        #[arg(long, default_value_t = false)]
        auto_apply: bool,

        /// Custom path to rules directory or JSON rule file
        #[arg(long)]
        rules: Option<PathBuf>,

        /// Include OSV open vulnerability database findings in healing
        #[arg(long, default_value_t = false)]
        osv: bool,

        /// Allow untrusted workspace dynamic rules to be planned and auto-applied
        #[arg(long, default_value_t = false)]
        allow_untrusted_rules: bool,
    },

    /// Roll back an applied healing session using a backup ID
    Rollback {
        /// Backup ID (from 'bug-killer history')
        backup_id: String,

        /// Root directory where backup was created (default: current directory)
        #[arg(default_value = ".")]
        path: PathBuf,
    },

    /// List all healing snapshots and backups
    History {
        /// Root directory (default: current directory)
        #[arg(default_value = ".")]
        path: PathBuf,
    },

    /// Display deep technical teardown and remediation blueprint for a specific CVE
    CveInfo {
        /// CVE identifier (e.g. CVE-2026-109618, CVE-2026-109619, CVE-2026-111497)
        cve_id: String,
    },

    /// Model-agnostic AI agent investigation and capability diagnostics
    #[command(subcommand)]
    Agent(AgentCommands),

    /// Retrieve full evidence receipts and cryptographic hashes for a specific finding
    Evidence {
        /// Finding ID or fingerprint prefix
        finding_id: String,

        /// Target directory path (default: current directory)
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Output results as JSON
        #[arg(long)]
        json: bool,
    },

    /// Plan a prospective, non-mutating repair for a finding with cryptographic diff hash
    Plan {
        /// Finding ID or fingerprint prefix
        finding_id: String,

        /// Target directory path (default: current directory)
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Output results as JSON
        #[arg(long)]
        json: bool,
    },

    /// Issue an operator approval receipt for a planned remediation
    Approve {
        /// Finding ID or plan identifier to approve
        plan_id: String,

        /// Target directory path (default: current directory)
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Operator email or identity key
        #[arg(long, default_value = "operator@bug-killer.local")]
        approver: String,

        /// Validity duration in minutes (default: 60)
        #[arg(long, default_value_t = 60)]
        validity_mins: i64,

        /// Output results as JSON
        #[arg(long)]
        json: bool,
    },

    /// Display the public key derived from a separately provisioned operator signing key
    OperatorPublicKey,

    /// Apply an approved prospective remediation plan with operator approval verification
    Apply {
        /// Finding ID or plan identifier to apply
        plan_id: String,

        /// Explicit path to operator approval receipt file
        #[arg(long)]
        approval_file: Option<PathBuf>,

        /// Target directory path (default: current directory)
        #[arg(default_value = ".")]
        path: PathBuf,
    },

    /// Model Context Protocol (MCP) server and integration commands
    #[command(subcommand)]
    Mcp(McpCommands),

    /// Initialize Bug Killer in a project, create security configuration, and run baseline scan
    Init {
        /// Target directory path (default: current directory)
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Install Git pre-commit security hook (default: true)
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        hooks: bool,

        /// Output results as JSON
        #[arg(long)]
        json: bool,
    },

    /// Bug Killer Security Guard suite (scan, status, explain, fix, verify, guidance, catalog)
    Security {
        #[command(subcommand)]
        action: SecurityAction,
    },

    /// Sibling & external tool capability broker (doctor, list, explain)
    #[command(subcommand)]
    Engine(EngineCommands),

    /// Agentic Security Operations Room (plan, status, evidence)
    #[command(subcommand)]
    Room(RoomCommands),

    /// Novel vulnerability hunter & bounded research runner (plan, run, candidate, verify)
    #[command(subcommand)]
    Hunter(HunterCommands),

    /// Autonomous novel vulnerability hunter on target project (full end-to-end research loop)
    Hunt {
        /// Target project directory (default: current directory)
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Maximum hypotheses to evaluate (default: 10)
        #[arg(long, default_value_t = 10)]
        max_hypotheses: usize,

        /// Output diagnostic report as JSON
        #[arg(long)]
        json: bool,
    },

    /// Responsible private disclosure & PVR draft generation (draft)
    #[command(subcommand)]
    Disclose(DiscloseCommands),

    /// Advisory feeds & dependency vulnerability cache (sync, status)
    #[command(subcommand)]
    Advisory(AdvisoryCommands),

    /// Software asset inventory & CycloneDX / JSON SBOM extraction
    Inventory {
        /// Target directory path (default: current directory)
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Export CycloneDX SBOM format (default: json)
        #[arg(long)]
        sbom: Option<String>,

        /// Output diagnostic report as JSON
        #[arg(long)]
        json: bool,
    },

    /// DeepSec: Agent-Powered Security Review Harness
    Deepsec {
        #[command(subcommand)]
        cmd: DeepsecCommands,
    },
}

#[derive(Subcommand, Debug)]
pub enum McpCommands {
    /// Run the stdio MCP server for external agent integration
    Serve {
        /// Transport protocol (stdio)
        #[arg(long, default_value = "stdio")]
        transport: String,

        /// Run in strictly read-only mode prohibiting state mutations (default: true)
        #[arg(long, default_value_t = true)]
        read_only: bool,

        /// Root workspace directory (default: current directory)
        #[arg(default_value = ".")]
        path: PathBuf,
    },

    /// Generate copy-pasteable MCP server configuration snippets for external coding agents
    Config {
        /// Target host agent (claude, codex, gemini, all)
        #[arg(long, default_value = "all")]
        host: String,

        /// Custom path to bug-killer binary
        #[arg(long)]
        binary: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum AgentCommands {
    /// Inspect configured model provider capability and health without leaking secrets
    Doctor {
        /// Provider name (local, openai, deepseek, kimi, minimax, claude, gemini, ollama)
        #[arg(long, default_value = "local")]
        provider: String,

        /// Output results as JSON
        #[arg(long)]
        json: bool,
    },

    /// Run bounded read-only autonomous investigation loop over target workspace
    Investigate {
        /// Target directory path (default: current directory)
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Provider name (local, deepseek, kimi, minimax, claude, gemini, openai, ollama)
        #[arg(long, default_value = "local")]
        provider: String,

        /// Model identifier override (e.g. deepseek-chat, gpt-4o, llama3.3)
        #[arg(long)]
        model: Option<String>,

        /// Execution mode (strictly read-only)
        #[arg(long, default_value = "read-only")]
        mode: String,

        /// Maximum investigation steps before terminal halt (default: 24)
        #[arg(long, default_value_t = 24)]
        max_steps: usize,

        /// Approved export profile name for remote providers (required if allow_remote_data_export is true)
        #[arg(long)]
        export_profile: Option<String>,

        /// Output results as JSON
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum SecurityAction {
    /// Execute security guard scan across all applicable catalog rules
    Scan {
        /// Target directory path (default: current directory)
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Scan profile (quick, project, ci, deep; default: quick)
        #[arg(long, default_value = "quick", value_parser = ["quick", "project", "ci", "deep"])]
        profile: String,

        /// Scan only git-changed / staged files
        #[arg(long, default_value_t = false)]
        changed_only: bool,

        /// Scan the exact staged Git index snapshot (for pre-commit enforcement)
        #[arg(long, conflicts_with = "changed_only", default_value_t = false)]
        staged: bool,

        /// Exit with code 1 for findings at or above this severity
        #[arg(long, value_parser = ["critical", "high", "medium", "low"])]
        fail_on: Option<String>,

        /// Also query free open vulnerability database (OSV.dev)
        #[arg(long, default_value_t = false)]
        osv: bool,

        /// Machine-readable report contract version (1 or 2)
        #[arg(long, value_parser = ["1", "2"])]
        report_version: Option<String>,

        /// Machine-readable exit-code contract version (v1 or v2)
        #[arg(long, value_parser = ["v1", "v2"])]
        exit_contract: Option<String>,

        /// Optional comma-separated list of specific engines to execute
        #[arg(long)]
        engine: Option<String>,

        /// Output results as JSON
        #[arg(long)]
        json: bool,
    },

    /// Inspect workspace rule-target coverage receipts and unassessed gaps
    Coverage {
        /// Target directory path (default: current directory)
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Report exact per-rule evaluation status
        #[arg(long, default_value_t = false)]
        per_rule: bool,

        /// Output results as JSON
        #[arg(long)]
        json: bool,
    },

    /// Show current workspace security guard status and baseline findings
    Status {
        /// Target directory path (default: current directory)
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Output results as JSON
        #[arg(long)]
        json: bool,
    },

    /// Explain a finding using the 373-rule AI-Generated Code Security Catalog
    Explain {
        /// Finding ID or fingerprint prefix
        finding_id: String,

        /// Target directory path (default: current directory)
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Output results as JSON
        #[arg(long)]
        json: bool,
    },

    /// Propose or apply an authorized bounded security repair
    Fix {
        /// Finding ID or fingerprint prefix
        finding_id: String,

        /// Target directory path (default: current directory)
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Generate repair proposal and diff preview without modifying files
        #[arg(long, default_value_t = false, conflicts_with = "apply")]
        plan: bool,

        /// Apply authorized repair with atomic Ed25519 backup and verification
        #[arg(long, default_value_t = false)]
        apply: bool,

        /// Optional operator approval receipt token (required for Level 3 fixes)
        #[arg(long)]
        receipt: Option<String>,

        /// Output results as JSON
        #[arg(long)]
        json: bool,
    },

    /// Independently verify workspace security status and coverage completeness
    Verify {
        /// Target directory path (default: current directory)
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Output results as JSON
        #[arg(long)]
        json: bool,
    },

    /// Generate pre-generation security guidance for a coding task
    Guidance {
        /// Task description or feature brief (e.g. "Add user file upload endpoint")
        task: String,

        /// Target programming language
        #[arg(long, default_value = "generic")]
        language: String,

        /// Output results as JSON
        #[arg(long)]
        json: bool,
    },

    /// Query or browse the 373-rule AI-Generated Code Security Issues Catalog
    Catalog {
        /// Filter by category number (1 to 27)
        #[arg(long)]
        category: Option<u8>,

        /// Filter by rule lifecycle status (cataloged, supported_static, review_required, etc.)
        #[arg(long)]
        status: Option<String>,

        /// Output results as JSON
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum EngineCommands {
    /// Check health, versions, and installation status of sibling security engines
    Doctor {
        /// Target directory path (default: current directory)
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Output results as JSON
        #[arg(long)]
        json: bool,
    },

    /// List all registered sibling tool capabilities and execution transports
    List {
        /// Output results as JSON
        #[arg(long)]
        json: bool,
    },

    /// Explain which security tools match a specified goal (known, prevention, research)
    Explain {
        /// Mission goal: known, prevention, or research
        #[arg(long, default_value = "prevention")]
        goal: String,

        /// Target directory path (default: current directory)
        #[arg(long, default_value = ".")]
        target: PathBuf,

        /// Output results as JSON
        #[arg(long)]
        json: bool,
    },

    /// Query, inspect, and recommend deep cybersecurity skills and MITRE/NIST mappings
    Skills {
        /// Subcommand action: list, show, search, recommend, stats
        #[arg(default_value = "list")]
        action: String,

        /// Filter by subdomain, tag, or MITRE technique ID
        #[arg(long)]
        filter: Option<String>,

        /// Skill identifier for 'show' action
        #[arg(long)]
        id: Option<String>,

        /// Target CVE ID or mission goal for 'recommend' action
        #[arg(long)]
        cve: Option<String>,

        /// Query string for 'search' action
        #[arg(long)]
        query: Option<String>,

        /// Maximum results to display (default: 25)
        #[arg(long, default_value_t = 25)]
        limit: usize,

        /// Output results as JSON
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum RoomCommands {
    /// Plan an operations room security run across matching tools
    Plan {
        /// Target directory path (default: current directory)
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Mission goal: known, prevention, or research
        #[arg(long, default_value = "prevention")]
        goal: String,

        /// Execution profile: quick, project, ci, or deep
        #[arg(long, default_value = "project")]
        profile: String,

        /// Output plan as JSON
        #[arg(long)]
        json: bool,
    },

    /// Inspect terminal state and per-tool execution receipts of a room run
    Status {
        /// Execution run ID
        run_id: String,

        /// Include individual tool execution receipts
        #[arg(long, default_value_t = true)]
        receipts: bool,

        /// Output status as JSON
        #[arg(long)]
        json: bool,
    },

    /// Correlate multi-engine evidence and coverage ledger
    Evidence {
        /// Execution run ID
        run_id: String,

        /// Include unexamined/skipped rule gaps
        #[arg(long, default_value_t = false)]
        include_gaps: bool,

        /// Output results as JSON
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum HunterCommands {
    /// Run autonomous end-to-end novel vulnerability hunt loop on target project
    Hunt {
        /// Target project directory (default: current directory)
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Maximum hypotheses to evaluate (default: 10)
        #[arg(long, default_value_t = 10)]
        max_hypotheses: usize,

        /// Output results as JSON
        #[arg(long)]
        json: bool,
    },

    /// Generate bounded research hypotheses for unknown weakness exploration
    Plan {
        /// Target directory path (default: current directory)
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Custom path to policy YAML file
        #[arg(long)]
        policy: Option<PathBuf>,

        /// Output results as JSON
        #[arg(long)]
        json: bool,
    },

    /// Run bounded sandboxed fuzzing and experimentation on research candidates
    Run {
        /// Research plan identifier
        #[arg(long)]
        plan: Option<String>,

        /// Strictly execute in isolated sandbox without host mutation (default: true)
        #[arg(long, default_value_t = true)]
        sandbox_only: bool,

        /// Output results as JSON
        #[arg(long)]
        json: bool,
    },

    /// Inspect a research candidate or list active candidates in the queue
    Candidate {
        /// Candidate identifier (e.g. cand-cwe787-001)
        id: Option<String>,

        /// Include full reproduction evidence and crash logs
        #[arg(long, default_value_t = false)]
        evidence: bool,

        /// Output results as JSON
        #[arg(long)]
        json: bool,
    },

    /// Execute isolated deterministic reproduction verification on a candidate
    Verify {
        /// Candidate identifier to verify
        id: String,

        /// Run in strictly offline mode without network access (default: true)
        #[arg(long, default_value_t = true)]
        offline: bool,

        /// Output results as JSON
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum DiscloseCommands {
    /// Synthesize a private responsible disclosure draft (PVR markdown or JSON)
    Draft {
        /// Finding ID or candidate ID
        finding_id: String,

        /// Target directory path (default: current directory)
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Private draft mode preventing unapproved external network disclosure (default: true)
        #[arg(long, default_value_t = true)]
        private: bool,

        /// Output file path for generated report (e.g. ./report.md)
        #[arg(long)]
        output: Option<PathBuf>,

        /// Output packet as JSON
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum DeepsecCommands {
    /// Initialize deepsec for a codebase, generating INFO.md and running baseline scan
    Init {
        #[arg(default_value = ".")]
        path: PathBuf,
        #[arg(long)]
        project_id: Option<String>,
    },
    /// Fast regex pattern scan across repository
    Scan {
        #[arg(default_value = ".")]
        path: PathBuf,
        #[arg(long)]
        project_id: Option<String>,
        #[arg(long)]
        filter: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// AI investigation of candidate files
    Process {
        #[arg(default_value = ".")]
        path: PathBuf,
        #[arg(long)]
        project_id: Option<String>,
        #[arg(long, default_value_t = 5)]
        batch_size: usize,
        #[arg(long)]
        limit: Option<usize>,
        #[arg(long)]
        filter: Option<String>,
        #[arg(long)]
        max_cost_usd: Option<f64>,
        #[arg(long, default_value = "claude-opus-4-8")]
        model: String,
        #[arg(long, default_value = "claude")]
        agent: String,
        #[arg(long)]
        json: bool,
    },
    /// Revalidate findings to eliminate false positives and check git fixes
    Revalidate {
        #[arg(default_value = ".")]
        path: PathBuf,
        #[arg(long)]
        project_id: Option<String>,
        #[arg(long, default_value_t = false)]
        force: bool,
        #[arg(long, default_value = "claude-opus-4-8")]
        model: String,
        #[arg(long)]
        json: bool,
    },
    /// Prioritize findings into P0/P1/P2 buckets
    Triage {
        #[arg(default_value = ".")]
        path: PathBuf,
        #[arg(long)]
        project_id: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Enrich findings with git committer and authorship history
    Enrich {
        #[arg(default_value = ".")]
        path: PathBuf,
        #[arg(long)]
        project_id: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Render human-readable summary and report
    Report {
        #[arg(default_value = ".")]
        path: PathBuf,
        #[arg(long)]
        project_id: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Export findings to JSON or markdown directory
    Export {
        #[arg(default_value = ".")]
        path: PathBuf,
        #[arg(long)]
        project_id: Option<String>,
        #[arg(long, default_value = "json")]
        format: String,
        #[arg(long, default_value = "findings.json")]
        out: PathBuf,
    },
    /// Show data mirror status and file counts
    Status {
        #[arg(default_value = ".")]
        path: PathBuf,
        #[arg(long)]
        project_id: Option<String>,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum AdvisoryCommands {
    /// Synchronize and cache open-source vulnerability advisory feeds
    Sync {
        /// Custom path to offline cache directory
        #[arg(long)]
        offline_cache: Option<PathBuf>,

        /// Comma-separated advisory sources (default: osv,ghsa)
        #[arg(long, default_value = "osv,ghsa")]
        sources: String,

        /// Output sync receipt as JSON
        #[arg(long)]
        json: bool,
    },

    /// Check status and freshness of the local advisory feed cache
    Status {
        /// Target directory path (default: current directory)
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Output status as JSON
        #[arg(long)]
        json: bool,
    },
}

pub fn compute_scan_exit_code(report: &crate::types::ScanReport) -> i32 {
    if report
        .findings
        .iter()
        .any(|f| f.affectedness == crate::types::Affectedness::ConfirmedAffected)
    {
        1
    } else if report
        .findings
        .iter()
        .any(|f| f.affectedness == crate::types::Affectedness::PotentiallyAffected)
    {
        2
    } else if !report.coverage.parser_failures.is_empty()
        || report.coverage.coverage_status != crate::types::CoverageStatus::Complete
    {
        3
    } else {
        0
    }
}

pub fn run(cli: Cli) -> i32 {
    match cli.command {
        Commands::Shell { path } => handlers::diagnostics::handle_shell(path),
        Commands::Doctor { path, json } => handlers::diagnostics::handle_doctor(path, json),
        Commands::Watch {
            path,
            interval,
            auto_heal,
            rules,
        } => handlers::diagnostics::handle_watch(path, interval, auto_heal, rules),
        Commands::Completion { shell } => handlers::diagnostics::handle_completion(shell),
        Commands::Scan {
            path,
            json,
            check_runtime,
            rules,
            osv,
            taint,
        } => handlers::scan::handle_scan(path, json, check_runtime, rules, osv, taint),
        Commands::Probe {
            url,
            json,
            timeout,
            sensitive_paths,
            authorized,
            allow_private_targets,
        } => handlers::scan::handle_probe(
            url,
            json,
            timeout,
            sensitive_paths,
            authorized,
            allow_private_targets,
        ),
        Commands::Osv { path, json } => handlers::scan::handle_osv(path, json),
        Commands::Heal {
            path,
            dry_run,
            apply,
            auto_apply,
            rules,
            osv,
            allow_untrusted_rules,
        } => handlers::healer::handle_heal(
            path,
            dry_run,
            apply,
            auto_apply,
            rules,
            osv,
            allow_untrusted_rules,
        ),
        Commands::Rollback { backup_id, path } => {
            handlers::healer::handle_rollback(backup_id, path)
        }
        Commands::History { path } => handlers::healer::handle_history(path),
        Commands::CveInfo { cve_id } => handlers::scan::handle_cve_info(cve_id),
        Commands::Agent(cmd) => handlers::agent::handle_agent(cmd),
        Commands::Evidence {
            finding_id,
            path,
            json,
        } => handlers::scan::handle_evidence(finding_id, path, json),
        Commands::Plan {
            finding_id,
            path,
            json,
        } => handlers::healer::handle_plan(finding_id, path, json),
        Commands::Approve {
            plan_id,
            path,
            approver,
            validity_mins,
            json,
        } => handlers::healer::handle_approve(plan_id, path, approver, validity_mins, json),
        Commands::OperatorPublicKey => handlers::healer::handle_operator_public_key(),
        Commands::Apply {
            plan_id,
            approval_file,
            path,
        } => handlers::healer::handle_apply(plan_id, approval_file, path),
        Commands::Mcp(cmd) => handlers::agent::handle_mcp(cmd),
        Commands::Init { path, hooks, json } => {
            handlers::diagnostics::handle_init(path, hooks, json)
        }
        Commands::Security { action } => handlers::security::handle_security(action),
        Commands::Engine(cmd) => handlers::engine::handle_engine(cmd),
        Commands::Room(cmd) => handlers::engine::handle_room(cmd),
        Commands::Hunter(cmd) => handlers::hunter::handle_hunter(cmd),
        Commands::Hunt {
            path,
            max_hypotheses,
            json,
        } => handlers::hunter::handle_hunt(path, max_hypotheses, json),
        Commands::Disclose(cmd) => handlers::disclosure::handle_disclose(cmd),
        Commands::Advisory(cmd) => handlers::advisory::handle_advisory(cmd),
        Commands::Inventory { path, sbom, json } => {
            handlers::diagnostics::handle_inventory(path, sbom, json)
        }
        Commands::Deepsec { cmd } => handlers::deepsec::handle_deepsec(cmd),
    }
}
