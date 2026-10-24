#![allow(clippy::collapsible_if, clippy::doc_lazy_continuation)]

mod agent;
mod completion;
mod cve_db;
mod dast;
mod doctor;
mod healer;
mod identity;
mod mcp;
mod osv;
mod rules;
mod scanner;
mod shell;
mod taint;
mod types;
mod watcher;

use agent::investigation::InvestigationSupervisor;
use agent::privacy::PrivacyPolicy;
use agent::provider::{AgentModelConfig, ModelProvider, ProviderAdapter};
use clap::{CommandFactory, Parser, Subcommand};
use completion::CompletionGenerator;
use dast::DastProber;
use doctor::SystemDoctor;
use healer::AutopilotHealer;
use healer::approval::ApprovalManager;
use healer::backup::BackupManager;
use healer::rollback::RollbackManager;
use mcp::{HostConfigGenerator, McpServer};
use osv::OsvClient;
use rules::RuleEngine;
use scanner::FleetScanner;
use shell::ShellEngine;
use std::path::PathBuf;
use types::Severity;
use watcher::WatcherEngine;

#[derive(Parser, Debug)]
#[command(name = "bug-killer")]
#[command(
    about = "Bug Killer: Let Your AI Find Deep & Ghosty Bugs, Vulnerabilities, and Security Issues and Heal From Them",
    version = "0.1.0"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
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

        /// Apply planned safe patches to filesystem (Default: false, plan-only mode)
        #[arg(long, default_value_t = false)]
        apply: bool,

        /// Automatically apply all safe patches (Alias for --apply, Default: false)
        #[arg(long, default_value_t = false)]
        auto_apply: bool,

        /// Custom path to rules directory or JSON rule file
        #[arg(long)]
        rules: Option<PathBuf>,

        /// Include OSV open vulnerability database findings in healing
        #[arg(long, default_value_t = false)]
        osv: bool,
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
}

#[derive(Subcommand, Debug)]
enum McpCommands {
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
enum AgentCommands {
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

fn compute_scan_exit_code(report: &types::ScanReport) -> i32 {
    if report
        .findings
        .iter()
        .any(|f| f.affectedness == types::Affectedness::ConfirmedAffected)
    {
        1
    } else if report
        .findings
        .iter()
        .any(|f| f.affectedness == types::Affectedness::PotentiallyAffected)
    {
        2
    } else if !report.coverage.parser_failures.is_empty()
        || report.coverage.coverage_status != types::CoverageStatus::Complete
    {
        3
    } else {
        0
    }
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Shell { path } => {
            let mut shell = ShellEngine::new(path);
            shell.run();
        }

        Commands::Doctor { path, json } => {
            let report = SystemDoctor::diagnose(&path);
            if json {
                println!("{}", serde_json::to_string_pretty(&report).unwrap());
                return;
            }

            println!("\n=======================================================");
            println!("  🩺  BUG KILLER SYSTEM DOCTOR REPORT");
            println!("=======================================================");
            println!("Target Workspace:  {}", path.display());
            println!("Operating System:  {}", report.os);
            println!("Architecture:      {}", report.arch);
            println!(
                "Overall Health:    {}\n",
                if report.overall_healthy {
                    "HEALTHY ✅"
                } else {
                    "ATTENTION REQUIRED ⚠️"
                }
            );

            for item in report.items {
                let badge = match item.status {
                    doctor::CheckStatus::Ok => "✅ OK  ",
                    doctor::CheckStatus::Warning => "⚠️ WARN",
                    doctor::CheckStatus::Failure => "❌ FAIL",
                    doctor::CheckStatus::NotInstalled => "⚪ NONE",
                };
                println!("{} {:<32} {}", badge, item.name, item.detected);
                if item.status != doctor::CheckStatus::Ok {
                    println!("   Recommendation: {}", item.recommendation);
                }
            }
            println!();
        }

        Commands::Watch {
            path,
            interval,
            auto_heal,
            rules: _,
        } => {
            WatcherEngine::watch(&path, interval, auto_heal, None);
        }

        Commands::Completion { shell } => {
            let mut cmd = Cli::command();
            if let Err(e) = CompletionGenerator::generate_completion(&shell, &mut cmd) {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }

        Commands::Scan {
            path,
            json,
            check_runtime,
            rules,
            osv,
            taint,
        } => {
            let active_rules = RuleEngine::load_rules(rules.as_deref(), &path);
            let mut report = FleetScanner::scan_directory_with_rules_and_taint(
                &path,
                check_runtime,
                &active_rules,
                taint,
            );

            if osv {
                let osv_client = OsvClient::new();
                let osv_findings = osv_client.scan_workspace(&path);
                for f in osv_findings {
                    if !report.findings.iter().any(|existing| existing.id == f.id) {
                        if f.severity == Severity::Critical {
                            report.critical_count += 1;
                        } else if f.severity == Severity::High {
                            report.high_count += 1;
                        }
                        report.findings.push(f);
                    }
                }
                report.is_vulnerable = !report.findings.is_empty();
            }

            if json {
                println!("{}", serde_json::to_string_pretty(&report).unwrap());
                let code = compute_scan_exit_code(&report);
                if code != 0 {
                    std::process::exit(code);
                }
                return;
            }

            println!("\n=======================================================");
            println!("  🎯  BUG KILLER: DEEP VULNERABILITY AUDIT REPORT");
            println!("=======================================================");
            println!("Target:               {}", report.target_dir.display());
            println!("Timestamp:            {}", report.scan_time);
            println!("Total Files Audited:  {}", report.total_files_scanned);
            println!("Active Dynamic Rules: {}", active_rules.len());
            println!(
                "OSV.dev Integration:  {}",
                if osv {
                    "ENABLED (Live Query)"
                } else {
                    "DISABLED (Use --osv to enable)"
                }
            );
            println!(
                "Taint Analysis:       {}",
                if taint {
                    "ENABLED (AST Dataflow)"
                } else {
                    "DISABLED (Use --taint to enable)"
                }
            );
            println!(
                "Audit Status:         {}",
                if report.is_vulnerable {
                    "EXPOSED ⚠️"
                } else if !report.is_clean() {
                    "PARTIAL / INCOMPLETE ⚠️"
                } else {
                    "CLEAN ✅"
                }
            );
            println!(
                "Coverage Status:      {:?}",
                report.coverage.coverage_status
            );
            println!("Files Audited:        {}", report.total_files_scanned);
            println!("Files Excluded:       {}", report.coverage.files_excluded);
            if !report.coverage.parser_failures.is_empty() {
                println!(
                    "Parser/I/O Failures:  {}",
                    report.coverage.parser_failures.len()
                );
            }
            println!("Critical:             {}", report.critical_count);
            println!("High:                 {}", report.high_count);
            println!("-------------------------------------------------------\n");

            if !report.coverage.parser_failures.is_empty() {
                println!("⚠️  Scanner encountered the following parser/read failures:");
                for failure in &report.coverage.parser_failures {
                    println!("   • {}: {}", failure.path.display(), failure.reason);
                }
                println!();
            }

            if report.findings.is_empty() {
                if report.is_clean() {
                    println!(
                        "✅ Zero exposures or vulnerability violations detected across full coverage."
                    );
                } else {
                    println!(
                        "⚠️ Zero exposures detected in audited files, but scan coverage was PARTIAL / INCOMPLETE."
                    );
                }
                let code = compute_scan_exit_code(&report);
                if code != 0 {
                    std::process::exit(code);
                }
                return;
            }

            for (idx, finding) in report.findings.iter().enumerate() {
                let sev_badge = match finding.severity {
                    Severity::Critical => "[CRITICAL]",
                    Severity::High => "[HIGH]",
                    Severity::Medium => "[MEDIUM]",
                    Severity::Low => "[LOW]",
                };

                println!(
                    "{}. {} {} - {}",
                    idx + 1,
                    sev_badge,
                    finding.cve.as_str(),
                    finding.cve.title()
                );
                if let Some(ref p) = finding.file_path {
                    let line_str = finding
                        .line_number
                        .map(|l| format!(":{}", l))
                        .unwrap_or_default();
                    println!("   Location:     {}{}", p.display(), line_str);
                }
                println!("   Affectedness: {}", finding.affectedness.as_str());
                println!("   Reachability: {}", finding.reachability.as_str());
                println!("   Confidence:   {}", finding.confidence.as_str());
                println!("   Pattern:      {}", finding.detected_version_or_pattern);
                println!("   Threshold:    {}", finding.safe_threshold);
                if !finding.uncertainty_reasons.is_empty() {
                    println!(
                        "   Uncertainty:  {}",
                        finding.uncertainty_reasons.join("; ")
                    );
                }
                if !finding.missing_checks.is_empty() {
                    println!("   Missing:      {}", finding.missing_checks.join(", "));
                }
                println!("   Details:      {}", finding.description);
                println!("   Remediation:  {}\n", finding.suggested_remediation);
            }

            println!(
                "Run 'bug-killer heal {} --dry-run{}' to preview automated remediation.",
                path.display(),
                if osv { " --osv" } else { "" }
            );

            let code = compute_scan_exit_code(&report);
            if code != 0 {
                std::process::exit(code);
            }
        }

        Commands::Osv { path, json } => {
            println!("🔍 Querying open-source vulnerability database (https://osv.dev)...");
            let osv_client = OsvClient::new();
            let findings = osv_client.scan_workspace(&path);

            if json {
                println!("{}", serde_json::to_string_pretty(&findings).unwrap());
                return;
            }

            println!("\n=======================================================");
            println!("  🌐  OSV.DEV OPEN VULNERABILITY AUDIT REPORT");
            println!("=======================================================");
            println!("Target Workspace:     {}", path.display());
            println!("Data Source:          https://osv.dev (Google / OpenSSF)");
            println!("Total Advisories:     {}\n", findings.len());

            if findings.is_empty() {
                println!("✅ Zero known open-source vulnerabilities reported by OSV.dev.");
                return;
            }

            for (idx, finding) in findings.iter().enumerate() {
                let sev_badge = match finding.severity {
                    Severity::Critical => "[CRITICAL]",
                    Severity::High => "[HIGH]",
                    Severity::Medium => "[MEDIUM]",
                    Severity::Low => "[LOW]",
                };

                println!(
                    "{}. {} {} - {}",
                    idx + 1,
                    sev_badge,
                    finding.cve.as_str(),
                    finding.cve.title()
                );
                if let Some(ref p) = finding.file_path {
                    println!("   Manifest:    {}", p.display());
                }
                println!("   Package:     {}", finding.detected_version_or_pattern);
                println!("   Threshold:   {}", finding.safe_threshold);
                println!("   Remediation: {}\n", finding.suggested_remediation);
            }

            println!(
                "Run 'bug-killer heal {} --osv' to automatically upgrade vulnerable packages.",
                path.display()
            );
        }

        Commands::Heal {
            path,
            dry_run,
            apply,
            auto_apply,
            rules,
            osv,
        } => {
            let active_rules = RuleEngine::load_rules(rules.as_deref(), &path);
            let mut report = FleetScanner::scan_directory_with_rules(&path, false, &active_rules);

            if osv {
                let osv_client = OsvClient::new();
                let osv_findings = osv_client.scan_workspace(&path);
                for f in osv_findings {
                    if !report.findings.iter().any(|existing| existing.id == f.id) {
                        report.findings.push(f);
                    }
                }
            }

            let plan = AutopilotHealer::plan_healing_with_rules(&report, &active_rules);

            println!("\n=======================================================");
            println!("  🎯  BUG KILLER: AUTOPILOT HEALER");
            println!("=======================================================");
            println!("Target:               {}", path.display());
            println!("Active Dynamic Rules: {}", active_rules.len());
            println!(
                "OSV.dev Integration:  {}",
                if osv { "ENABLED" } else { "DISABLED" }
            );
            println!("Vulnerable Findings:  {}", report.findings.len());
            println!("Planned Patches:      {}", plan.len());
            println!(
                "Execution Mode:       {}",
                if dry_run || (!apply && !auto_apply) {
                    "PLAN-ONLY (Zero filesystem mutations)"
                } else {
                    "AUTHORIZED APPLY (Modifying files with cryptographic backup)"
                }
            );
            println!("-------------------------------------------------------\n");

            if plan.is_empty() {
                println!("ℹ️ No automated file patches applicable or all files already patched.");
                return;
            }

            for (idx, action) in plan.iter().enumerate() {
                println!("{}. Action:  {:?}", idx + 1, action.action_type);
                println!("   Target:  {}", action.target_file.display());
                println!("   Diff:    {}", action.diff_description);
                println!("   SHA256:  {}\n", action.original_checksum);
            }

            if dry_run || (!apply && !auto_apply) {
                println!(
                    "🔒 Plan-Only Default: No filesystem mutations applied without explicit operator flag."
                );
                println!("To apply these changes with cryptographic non-repudiation:");
                println!("  bug-killer heal {} --apply", path.display());
                return;
            }

            match AutopilotHealer::execute_healing(&path, &plan) {
                Ok((manifest, count)) => {
                    println!(
                        "✅ Successfully applied {} automated healing patches!",
                        count
                    );
                    println!("📦 Backup Snapshot Created: {}", manifest.backup_id);
                    println!(
                        "   To rollback if needed: bug-killer rollback {}",
                        manifest.backup_id
                    );
                }
                Err(e) => {
                    eprintln!("❌ Healing execution failed: {}", e);
                    std::process::exit(1);
                }
            }
        }

        Commands::Rollback { backup_id, path } => {
            println!(
                "Attempting cryptographic rollback for snapshot '{}'...",
                backup_id
            );
            match RollbackManager::rollback(&path, &backup_id) {
                Ok(count) => {
                    println!(
                        "✅ Successfully rolled back {} files from backup snapshot {}.",
                        count, backup_id
                    );
                }
                Err(e) => {
                    eprintln!("❌ Rollback failed: {}", e);
                    std::process::exit(1);
                }
            }
        }

        Commands::History { path } => {
            let backups = BackupManager::list_backups(&path);
            println!("\n=======================================================");
            println!("  📜  BUG KILLER: BACKUP SNAPSHOT HISTORY");
            println!("=======================================================");
            if backups.is_empty() {
                println!("Zero backup snapshots recorded in .aegis/backups/");
                return;
            }

            for b in backups {
                println!("Snapshot ID:  {}", b.backup_id);
                println!("Created At:   {}", b.created_at);
                println!("Files Backed: {}", b.records.len());
                for r in b.records {
                    let hash_prefix = if r.original_sha256.len() >= 12 {
                        &r.original_sha256[..12]
                    } else {
                        &r.original_sha256
                    };
                    println!("  - {} (SHA256: {})", r.relative_target_path, hash_prefix);
                }
                println!("-------------------------------------------------------");
            }
        }

        Commands::Probe { url, json, timeout } => match DastProber::probe(&url, timeout) {
            Ok(report) => {
                if json {
                    println!("{}", serde_json::to_string_pretty(&report).unwrap());
                    return;
                }

                println!("\n=======================================================");
                println!("  🛡️  BUG KILLER: DEFENSIVE DAST PROBE REPORT");
                println!("=======================================================");
                println!("Target URL:           {}", report.target_url);
                println!("Timestamp:            {}", report.probe_time);
                println!("Status Code:          HTTP {}", report.status_code);
                println!("Duration:             {}ms", report.duration_ms);
                println!("Headers Audited:      {}", report.headers_checked);
                println!("Endpoints Audited:    {}", report.endpoints_audited);
                println!(
                    "Vulnerabilities:      {}",
                    if report.is_vulnerable {
                        "EXPOSED ⚠️"
                    } else {
                        "HARDENED ✅"
                    }
                );
                println!("Critical:             {}", report.critical_count);
                println!("High:                 {}", report.high_count);
                println!("-------------------------------------------------------\n");

                if report.findings.is_empty() {
                    println!(
                        "✅ All inspected security headers and defensive endpoints are hardened."
                    );
                    return;
                }

                for (idx, finding) in report.findings.iter().enumerate() {
                    let sev_badge = match finding.severity {
                        Severity::Critical => "[CRITICAL]",
                        Severity::High => "[HIGH]",
                        Severity::Medium => "[MEDIUM]",
                        Severity::Low => "[LOW]",
                    };

                    println!(
                        "{}. {} {} - {}",
                        idx + 1,
                        sev_badge,
                        finding.id,
                        finding.title
                    );
                    println!("   Target:      {}", finding.target_url);
                    println!("   Evidence:    {}", finding.evidence);
                    println!("   Remediation: {}\n", finding.remediation);
                }
            }
            Err(e) => {
                eprintln!("❌ DAST Probe Error: {}", e);
                std::process::exit(1);
            }
        },

        Commands::CveInfo { cve_id } => {
            let norm = cve_id.trim().to_uppercase();
            if norm.contains("109618") {
                println!("\n=== CVE-2026-109618: PHP2Shell (Out-of-Memory Heap Corruption) ===");
                println!("CVSS: 9.2 (Critical) | Vector: Remote Code Execution (RCE)");
                println!("Root Cause: PHP runtime uses longjmp() on OOM errors to abort requests.");
                println!(
                    "In certain SAPI contexts, request memory is left uninitialized prior to allocation."
                );
                println!(
                    "Subsequent cleanups evaluate uninitialized heap structures, yielding reliable RCE."
                );
                println!(
                    "Fixed Releases: PHP 8.2.35+, 8.3.36+, 8.4.27+, 8.5.12+ (All <= 8.1 are EOL)"
                );
            } else if norm.contains("109619") {
                println!(
                    "\n=== CVE-2026-109619: PHP2Shell (Stale Global State / Use-After-Free) ==="
                );
                println!("CVSS: 9.8 (Critical) | Vector: Remote Code Execution (RCE)");
                println!(
                    "Root Cause: Global state variables pointing into request memory fail to reset properly"
                );
                println!(
                    "under error-handling conditions. The memory is freed but globals retain stale references."
                );
                println!(
                    "Consecutive requests reuse stale heap pointers leading to UAF code execution."
                );
                println!(
                    "Fixed Releases: PHP 8.2.35+, 8.3.36+, 8.4.27+, 8.5.12+ (All <= 8.1 are EOL)"
                );
            } else if norm.contains("111497") {
                println!(
                    "\n=== CVE-2026-111497: Node2Shell (Bundled Brotli Decoder Out-of-Bounds Write) ==="
                );
                println!("CVSS: 8.8 (High/Critical) | Vector: Memory Corruption / RCE");
                println!(
                    "Root Cause: Missing bounds check in Google reference Brotli library (v1.0.3 - 1.2.0)"
                );
                println!("statically linked inside Node.js native runtime (node:zlib).");
                println!(
                    "Attack Vector: Malformed Brotli payload sent via HTTP 'Content-Encoding: br' or fetch()."
                );
                println!(
                    "Fixed Releases: Node.js v22.23.4+, v24.22.1+, v26.12.1+ (Node <= 20 is EOL)"
                );
            } else {
                println!(
                    "Unknown CVE ID. Supported: CVE-2026-109618, CVE-2026-109619, CVE-2026-111497"
                );
            }
        }

        Commands::Agent(agent_cmd) => match agent_cmd {
            AgentCommands::Doctor { provider, json } => {
                let model_provider = ModelProvider::from_str_loose(&provider);
                let config = AgentModelConfig {
                    provider: model_provider,
                    model_name: "default".into(),
                    ..Default::default()
                };
                let adapter = ProviderAdapter::new(config);
                let health = adapter.check_health();
                if json {
                    println!("{}", serde_json::to_string_pretty(&health).unwrap());
                    return;
                }
                println!("\n=======================================================");
                println!("  🤖  BUG KILLER AGENT PROVIDER HEALTH & CAPABILITY");
                println!("=======================================================");
                println!("Provider:          {}", health.provider);
                println!("Model:             {}", health.model);
                println!(
                    "Available:         {}",
                    if health.is_available {
                        "READY ✅"
                    } else {
                        "NOT READY ⚠️"
                    }
                );
                println!(
                    "Local / Offline:   {}",
                    if health.is_local {
                        "YES (Air-gapped)"
                    } else {
                        "NO (Remote Network)"
                    }
                );
                println!("Endpoint:          {}", health.endpoint);
                println!(
                    "Requires Key:      {}",
                    if health.requires_key { "YES" } else { "NO" }
                );
                println!(
                    "Key Configured:    {}",
                    if health.key_configured {
                        "YES (Set in environment)"
                    } else {
                        "NO (Unset)"
                    }
                );
                println!(
                    "Function Calling:  {}",
                    if health.capability.supports_function_calling {
                        "YES"
                    } else {
                        "NO"
                    }
                );
                println!(
                    "Structured Output: {}",
                    if health.capability.supports_structured_output {
                        "YES"
                    } else {
                        "NO"
                    }
                );
                println!(
                    "Max Context:       {} tokens",
                    health.capability.max_context_tokens
                );
                println!(
                    "Max Output:        {} tokens\n",
                    health.capability.max_output_tokens
                );
            }

            AgentCommands::Investigate {
                path,
                provider,
                model,
                mode: _mode,
                max_steps,
                export_profile,
                json,
            } => {
                let model_prov = ModelProvider::from_str_loose(&provider);
                let model_name = model.unwrap_or_else(|| "default".into());
                let privacy_policy = if let Some(ref _profile) = export_profile {
                    PrivacyPolicy::new_approved_export(vec![provider.clone()])
                } else {
                    PrivacyPolicy::default()
                };

                let config = AgentModelConfig {
                    provider: model_prov,
                    model_name,
                    privacy_policy,
                    ..Default::default()
                };

                let adapter = ProviderAdapter::new(config);
                let mut supervisor = InvestigationSupervisor::new(adapter, max_steps);
                match supervisor.run_investigation(&path) {
                    Ok(report) => {
                        if json {
                            println!("{}", serde_json::to_string_pretty(&report).unwrap());
                            return;
                        }
                        println!("\n=======================================================");
                        println!("  🔍  AUTONOMOUS AGENT INVESTIGATION REPORT");
                        println!("=======================================================");
                        println!("Investigation ID:  {}", report.investigation_id);
                        println!("Target Directory:  {}", report.target_dir.display());
                        println!("Terminal State:    {:?}", report.state);
                        println!(
                            "Steps Executed:    {}/{}",
                            report.total_steps, report.max_steps_allowed
                        );
                        println!("Findings Found:    {}", report.findings.len());
                        println!("Plans Proposed:    {}", report.proposed_plans.len());
                        println!("Vetoes Triggered:  {}", report.vetoes.len());
                        println!("Audit Digest:      {}\n", report.audit_digest);

                        for step in &report.steps_history {
                            println!(
                                "Step {}: [{:?}] {} -> {}",
                                step.step_index, step.state, step.action, step.outcome_summary
                            );
                        }
                        println!();
                    }
                    Err(e) => {
                        eprintln!("Investigation failed: {}", e);
                        std::process::exit(4);
                    }
                }
            }
        },

        Commands::Evidence {
            finding_id,
            path,
            json,
        } => {
            let scan_report = FleetScanner::scan_directory(&path, true);
            let target_finding = scan_report
                .findings
                .iter()
                .find(|f| f.id == finding_id || f.dedupe_fingerprint.starts_with(&finding_id));
            if let Some(f) = target_finding {
                if json {
                    println!("{}", serde_json::to_string_pretty(f).unwrap());
                    return;
                }
                println!("\n=== EVIDENCE RECORD FOR FINDING {} ===", f.id);
                println!("CVE:               {}", f.cve.as_str());
                println!("Severity:          {:?}", f.severity);
                println!("Affectedness:      {}", f.affectedness.as_str());
                println!("Reachability:      {}", f.reachability.as_str());
                println!("Confidence:        {}", f.confidence.as_str());
                println!("Target Kind:       {:?}", f.target_kind);
                println!(
                    "Target File:       {}",
                    f.file_path
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "none".into())
                );
                println!("Pattern/Version:   {}", f.detected_version_or_pattern);
                println!("Dedupe Hash:       {}", f.dedupe_fingerprint);
                println!("Supported Checks:  {:?}", f.supported_checks);
                println!("Missing Checks:    {:?}", f.missing_checks);
                println!("Uncertainty:       {:?}\n", f.uncertainty_reasons);
            } else {
                eprintln!("Finding '{}' not found in workspace scan.", finding_id);
                std::process::exit(1);
            }
        }

        Commands::Plan {
            finding_id,
            path,
            json,
        } => {
            let scan_report = FleetScanner::scan_directory(&path, true);
            let target_finding = scan_report
                .findings
                .iter()
                .find(|f| f.id == finding_id || f.dedupe_fingerprint.starts_with(&finding_id));
            if let Some(f) = target_finding {
                let single_report = types::ScanReport {
                    findings: vec![f.clone()],
                    ..scan_report
                };
                let plan = AutopilotHealer::plan_healing(&single_report);
                if json {
                    println!("{}", serde_json::to_string_pretty(&plan).unwrap());
                    return;
                }
                println!("\n=== REMEDIATION PLAN FOR FINDING {} ===", f.id);
                for action in plan {
                    println!("Action Type:   {:?}", action.action_type);
                    println!("Target File:   {}", action.target_file.display());
                    println!("Diff:          {}", action.diff_description);
                    println!("Original Hash: {}", action.original_checksum);
                }
                println!();
            } else {
                eprintln!("Finding '{}' not found in workspace scan.", finding_id);
                std::process::exit(1);
            }
        }

        Commands::Approve {
            plan_id,
            path,
            approver,
            validity_mins,
            json,
        } => {
            let scan_report = FleetScanner::scan_directory(&path, true);
            let target_finding = scan_report
                .findings
                .iter()
                .find(|f| f.id == plan_id || f.dedupe_fingerprint.starts_with(&plan_id));

            let plan = if let Some(f) = target_finding {
                let single_report = types::ScanReport {
                    findings: vec![f.clone()],
                    ..scan_report
                };
                AutopilotHealer::plan_healing(&single_report)
            } else {
                AutopilotHealer::plan_healing(&scan_report)
            };

            if plan.is_empty() {
                eprintln!(
                    "No prospective patch actions available to approve for plan '{}'",
                    plan_id
                );
                std::process::exit(1);
            }

            let plan_checksum = ApprovalManager::compute_plan_checksum(&plan);
            match ApprovalManager::create_approval_receipt(
                &path,
                &plan_id,
                &plan_checksum,
                &approver,
                validity_mins,
            ) {
                Ok(receipt) => {
                    let receipt_file = ApprovalManager::save_receipt(&path, &receipt)
                        .unwrap_or_else(|e| {
                            eprintln!("Warning: Failed to persist receipt to disk: {}", e);
                            path.join(format!("{}.receipt.json", plan_id))
                        });

                    if json {
                        println!("{}", serde_json::to_string_pretty(&receipt).unwrap());
                        return;
                    }

                    println!("\n=======================================================");
                    println!("  ✍️  OPERATOR APPROVAL RECEIPT ISSUED");
                    println!("=======================================================");
                    println!("Plan ID:          {}", receipt.plan_id);
                    println!("Plan Checksum:    {}", receipt.plan_checksum);
                    println!("Approver:         {}", receipt.approver);
                    println!("Valid Until:      {}", receipt.valid_until);
                    println!("Signature:        {}...\n", &receipt.signature[..24]);
                    println!("Receipt saved to: {}", receipt_file.display());
                    println!("To apply this plan:");
                    println!(
                        "  bug-killer apply {} --approval-file {}",
                        plan_id,
                        receipt_file.display()
                    );
                }
                Err(e) => {
                    eprintln!("Failed to issue approval receipt: {}", e);
                    std::process::exit(4);
                }
            }
        }

        Commands::Apply {
            plan_id,
            approval_file,
            path,
        } => {
            let receipt_path = approval_file.unwrap_or_else(|| {
                path.join(".bug-killer")
                    .join("approvals")
                    .join(format!("{}.receipt.json", plan_id))
            });

            let receipt = match ApprovalManager::load_receipt(&receipt_path) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!(
                        "Operator approval verification failed: {}. Cannot apply mutations without valid approval receipt.",
                        e
                    );
                    std::process::exit(4);
                }
            };

            let scan_report = FleetScanner::scan_directory(&path, true);
            let target_finding = scan_report
                .findings
                .iter()
                .find(|f| f.id == plan_id || f.dedupe_fingerprint.starts_with(&plan_id));

            let plan = if let Some(f) = target_finding {
                let single_report = types::ScanReport {
                    findings: vec![f.clone()],
                    ..scan_report
                };
                AutopilotHealer::plan_healing(&single_report)
            } else {
                AutopilotHealer::plan_healing(&scan_report)
            };

            match ApprovalManager::execute_supervised_healing(&path, &receipt, &plan) {
                Ok((manifest, count)) => {
                    println!(
                        "\n✅ Successfully applied {} supervised patches under operator approval!",
                        count
                    );
                    println!("📦 Backup Snapshot Created: {}", manifest.backup_id);
                    println!(
                        "   To rollback if needed: bug-killer rollback {}\n",
                        manifest.backup_id
                    );
                }
                Err(e) => {
                    eprintln!("❌ Supervised execution failed: {}", e);
                    std::process::exit(4);
                }
            }
        }

        Commands::Mcp(mcp_cmd) => match mcp_cmd {
            McpCommands::Serve {
                transport,
                read_only,
                path,
            } => {
                if transport != "stdio" {
                    eprintln!(
                        "Unsupported transport: '{}'. Only 'stdio' is currently supported.",
                        transport
                    );
                    std::process::exit(5);
                }
                let mut server = McpServer::new(path, read_only);
                if let Err(e) = server.run_stdio() {
                    eprintln!("MCP server error: {}", e);
                    std::process::exit(5);
                }
            }
            McpCommands::Config { host, binary } => {
                let bin_ref = binary.as_deref();
                match host.to_lowercase().as_str() {
                    "claude" | "claude-code" => {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&HostConfigGenerator::claude_code_config(
                                bin_ref
                            ))
                            .unwrap()
                        );
                    }
                    "codex" => {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&HostConfigGenerator::codex_config(
                                bin_ref
                            ))
                            .unwrap()
                        );
                    }
                    "gemini" | "gemini-cli" => {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&HostConfigGenerator::gemini_cli_config(
                                bin_ref
                            ))
                            .unwrap()
                        );
                    }
                    _ => {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&HostConfigGenerator::generate_all(
                                bin_ref
                            ))
                            .unwrap()
                        );
                    }
                }
            }
        },
    }
}
