#![allow(clippy::collapsible_if, clippy::doc_lazy_continuation)]

mod types;
mod cve_db;
mod scanner;
mod healer;
mod doctor;
mod watcher;
mod shell;
mod completion;
mod identity;
mod rules;
mod osv;

use clap::{CommandFactory, Parser, Subcommand};
use std::path::PathBuf;
use types::Severity;
use scanner::FleetScanner;
use healer::AutopilotHealer;
use healer::backup::BackupManager;
use healer::rollback::RollbackManager;
use doctor::SystemDoctor;
use watcher::WatcherEngine;
use shell::ShellEngine;
use completion::CompletionGenerator;
use rules::RuleEngine;
use osv::OsvClient;

#[derive(Parser, Debug)]
#[command(name = "bug-killer")]
#[command(about = "Bug Killer: Let Your AI Find Deep & Ghosty Bugs, Vulnerabilities, and Security Issues and Heal From Them", version = "0.1.0")]
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

        /// Automatically apply all safe patches without confirmation
        #[arg(long, default_value_t = true)]
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
            println!("Overall Health:    {}\n", if report.overall_healthy { "HEALTHY ✅" } else { "ATTENTION REQUIRED ⚠️" });

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

        Commands::Watch { path, interval, auto_heal, rules: _ } => {
            WatcherEngine::watch(&path, interval, auto_heal, None);
        }

        Commands::Completion { shell } => {
            let mut cmd = Cli::command();
            if let Err(e) = CompletionGenerator::generate_completion(&shell, &mut cmd) {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }

        Commands::Scan { path, json, check_runtime, rules, osv } => {
            let active_rules = RuleEngine::load_rules(rules.as_deref(), &path);
            let mut report = FleetScanner::scan_directory_with_rules(&path, check_runtime, &active_rules);

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
                return;
            }

            println!("\n=======================================================");
            println!("  🎯  BUG KILLER: DEEP VULNERABILITY AUDIT REPORT");
            println!("=======================================================");
            println!("Target:               {}", report.target_dir.display());
            println!("Timestamp:            {}", report.scan_time);
            println!("Total Files Audited:  {}", report.total_files_scanned);
            println!("Active Dynamic Rules: {}", active_rules.len());
            println!("OSV.dev Integration:  {}", if osv { "ENABLED (Live Query)" } else { "DISABLED (Use --osv to enable)" });
            println!("Vulnerabilities:      {}", if report.is_vulnerable { "EXPOSED ⚠️" } else { "CLEAN ✅" });
            println!("Critical:             {}", report.critical_count);
            println!("High:                 {}", report.high_count);
            println!("-------------------------------------------------------\n");

            if report.findings.is_empty() {
                println!("✅ Zero exposures or vulnerability violations detected.");
                return;
            }

            for (idx, finding) in report.findings.iter().enumerate() {
                let sev_badge = match finding.severity {
                    Severity::Critical => "[CRITICAL]",
                    Severity::High => "[HIGH]",
                    Severity::Medium => "[MEDIUM]",
                    Severity::Low => "[LOW]",
                };

                println!("{}. {} {} - {}", idx + 1, sev_badge, finding.cve.as_str(), finding.cve.title());
                if let Some(ref p) = finding.file_path {
                    let line_str = finding.line_number.map(|l| format!(":{}", l)).unwrap_or_default();
                    println!("   Location:    {}{}", p.display(), line_str);
                }
                println!("   Pattern:     {}", finding.detected_version_or_pattern);
                println!("   Threshold:   {}", finding.safe_threshold);
                println!("   Details:     {}", finding.description);
                println!("   Remediation: {}\n", finding.suggested_remediation);
            }

            println!("Run 'bug-killer heal {} --dry-run{}' to preview automated remediation.", path.display(), if osv { " --osv" } else { "" });
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

                println!("{}. {} {} - {}", idx + 1, sev_badge, finding.cve.as_str(), finding.cve.title());
                if let Some(ref p) = finding.file_path {
                    println!("   Manifest:    {}", p.display());
                }
                println!("   Package:     {}", finding.detected_version_or_pattern);
                println!("   Threshold:   {}", finding.safe_threshold);
                println!("   Remediation: {}\n", finding.suggested_remediation);
            }

            println!("Run 'bug-killer heal {} --osv' to automatically upgrade vulnerable packages.", path.display());
        }

        Commands::Heal { path, dry_run, auto_apply, rules, osv } => {
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
            println!("OSV.dev Integration:  {}", if osv { "ENABLED" } else { "DISABLED" });
            println!("Vulnerable Findings:  {}", report.findings.len());
            println!("Planned Patches:      {}", plan.len());
            println!("Dry-Run Mode:         {}", if dry_run { "ENABLED (No files will be modified)" } else { "DISABLED (Live Execution)" });
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

            if dry_run {
                println!("To apply these changes, run without --dry-run:");
                println!("  bug-killer heal {}", path.display());
                return;
            }

            if auto_apply {
                match AutopilotHealer::execute_healing(&path, &plan) {
                    Ok((manifest, count)) => {
                        println!("✅ Successfully applied {} automated healing patches!", count);
                        println!("📦 Backup Snapshot Created: {}", manifest.backup_id);
                        println!("   To rollback if needed: bug-killer rollback {}", manifest.backup_id);
                    }
                    Err(e) => {
                        eprintln!("❌ Healing execution failed: {}", e);
                        std::process::exit(1);
                    }
                }
            }
        }

        Commands::Rollback { backup_id, path } => {
            println!("Attempting cryptographic rollback for snapshot '{}'...", backup_id);
            match RollbackManager::rollback(&path, &backup_id) {
                Ok(count) => {
                    println!("✅ Successfully rolled back {} files from backup snapshot {}.", count, backup_id);
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
                    let hash_prefix = if r.original_sha256.len() >= 12 { &r.original_sha256[..12] } else { &r.original_sha256 };
                    println!("  - {} (SHA256: {})", r.relative_target_path, hash_prefix);
                }
                println!("-------------------------------------------------------");
            }
        }

        Commands::CveInfo { cve_id } => {
            let norm = cve_id.trim().to_uppercase();
            if norm.contains("109618") {
                println!("\n=== CVE-2026-109618: PHP2Shell (Out-of-Memory Heap Corruption) ===");
                println!("CVSS: 9.2 (Critical) | Vector: Remote Code Execution (RCE)");
                println!("Root Cause: PHP runtime uses longjmp() on OOM errors to abort requests.");
                println!("In certain SAPI contexts, request memory is left uninitialized prior to allocation.");
                println!("Subsequent cleanups evaluate uninitialized heap structures, yielding reliable RCE.");
                println!("Fixed Releases: PHP 8.2.35+, 8.3.36+, 8.4.27+, 8.5.12+ (All <= 8.1 are EOL)");
            } else if norm.contains("109619") {
                println!("\n=== CVE-2026-109619: PHP2Shell (Stale Global State / Use-After-Free) ===");
                println!("CVSS: 9.8 (Critical) | Vector: Remote Code Execution (RCE)");
                println!("Root Cause: Global state variables pointing into request memory fail to reset properly");
                println!("under error-handling conditions. The memory is freed but globals retain stale references.");
                println!("Consecutive requests reuse stale heap pointers leading to UAF code execution.");
                println!("Fixed Releases: PHP 8.2.35+, 8.3.36+, 8.4.27+, 8.5.12+ (All <= 8.1 are EOL)");
            } else if norm.contains("111497") {
                println!("\n=== CVE-2026-111497: Node2Shell (Bundled Brotli Decoder Out-of-Bounds Write) ===");
                println!("CVSS: 8.8 (High/Critical) | Vector: Memory Corruption / RCE");
                println!("Root Cause: Missing bounds check in Google reference Brotli library (v1.0.3 - 1.2.0)");
                println!("statically linked inside Node.js native runtime (node:zlib).");
                println!("Attack Vector: Malformed Brotli payload sent via HTTP 'Content-Encoding: br' or fetch().");
                println!("Fixed Releases: Node.js v22.23.4+, v24.22.1+, v26.12.1+ (Node <= 20 is EOL)");
            } else {
                println!("Unknown CVE ID. Supported: CVE-2026-109618, CVE-2026-109619, CVE-2026-111497");
            }
        }
    }
}
