use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use crate::types::{ScanReport, PatchAction, Severity};
use crate::scanner::FleetScanner;
use crate::healer::AutopilotHealer;
use crate::healer::backup::BackupManager;
use crate::healer::rollback::RollbackManager;
use crate::doctor::SystemDoctor;
use crate::watcher::WatcherEngine;

pub struct ShellEngine {
    current_dir: PathBuf,
    last_report: Option<ScanReport>,
    last_plan: Option<Vec<PatchAction>>,
}

impl ShellEngine {
    pub fn new(initial_dir: PathBuf) -> Self {
        let abs = std::fs::canonicalize(&initial_dir).unwrap_or(initial_dir);
        Self {
            current_dir: abs,
            last_report: None,
            last_plan: None,
        }
    }

    /// Launches the interactive REPL loop.
    pub fn run(&mut self) {
        println!("=======================================================");
        println!("  🎯  BUG KILLER INTERACTIVE SHELL (bk-shell v0.1.0)");
        println!("  Type 'help' for commands, 'scan' to audit, 'exit' to quit.");
        println!("=======================================================");

        let stdin = io::stdin();
        let mut stdout = io::stdout();

        loop {
            // Render interactive prompt with active status
            let status_badge = match &self.last_report {
                Some(r) if r.is_vulnerable => format!("⚠️  vuln:{}", r.findings.len()),
                Some(_) => "✅ clean".to_string(),
                None => "idle".to_string(),
            };

            let dir_name = self.current_dir.file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "/".into());

            print!("bk [{}] ({}) > ", dir_name, status_badge);
            let _ = stdout.flush();

            let mut line = String::new();
            if stdin.lock().read_line(&mut line).is_err() {
                break;
            }

            let input = line.trim();
            if input.is_empty() {
                continue;
            }

            let tokens: Vec<&str> = input.split_whitespace().collect();
            let cmd = tokens[0].to_lowercase();
            let args = &tokens[1..];

            match cmd.as_str() {
                "exit" | "quit" | "q" => {
                    println!("Exiting Bug Killer Shell. Stay safe!");
                    break;
                }
                "help" | "?" => self.print_help(),
                "pwd" => println!("Current Directory: {}", self.current_dir.display()),
                "cd" => {
                    let target = if args.is_empty() { "." } else { args[0] };
                    let new_path = self.current_dir.join(target);
                    match std::fs::canonicalize(&new_path) {
                        Ok(p) => {
                            self.current_dir = p;
                            self.last_report = None;
                            self.last_plan = None;
                            println!("Changed directory to: {}", self.current_dir.display());
                        }
                        Err(e) => eprintln!("cd: cannot change directory: {}", e),
                    }
                }
                "scan" => self.execute_scan(args),
                "findings" | "ls-vuln" => self.show_findings(),
                "plan" => self.show_plan(),
                "diff" => self.show_diffs(),
                "heal" => self.execute_heal(args),
                "verify" => self.execute_verify(),
                "rollback" => self.execute_rollback(args),
                "history" => self.show_history(),
                "doctor" => self.run_doctor(),
                "cve" | "info" => self.show_cve(args),
                "watch" => self.run_watch(args),
                "clear" | "cls" => {
                    print!("\x1B[2J\x1B[1;1H");
                    let _ = stdout.flush();
                }
                _ => {
                    println!("Unknown command: '{}'. Type 'help' for available commands.", cmd);
                }
            }
        }
    }

    fn print_help(&self) {
        println!("\nAvailable Interactive Commands:");
        println!("  scan [path]           Audit target directory (defaults to current dir)");
        println!("  findings              Display details for all detected vulnerabilities");
        println!("  plan                  Generate and preview automated healing actions");
        println!("  diff                  Show code and configuration diffs for planned patches");
        println!("  heal [--dry-run]      Execute atomic healing with pre-mutation backup");
        println!("  verify                Run post-patch verification pass to confirm zero exposures");
        println!("  history               List all backup snapshots recorded in .aegis/backups/");
        println!("  rollback <backup_id>  Revert target directory to exact state of snapshot");
        println!("  doctor                Check local environment (Node, PHP, Nginx, Docker, permissions)");
        println!("  cve <cve_id>          Display root cause, mechanics, and remediation for a CVE");
        println!("  watch [secs]          Enter live surveillance mode monitoring filesystem changes");
        println!("  cd <path>             Change active workspace directory");
        println!("  pwd                   Print current active workspace directory");
        println!("  clear                 Clear console screen");
        println!("  exit / quit           Exit the interactive shell\n");
    }

    fn execute_scan(&mut self, args: &[&str]) {
        let path = if args.is_empty() {
            self.current_dir.clone()
        } else {
            self.current_dir.join(args[0])
        };

        println!("Scanning target: {}...", path.display());
        let report = FleetScanner::scan_directory(&path, true);
        println!(
            "Audit complete. Files: {} | Vulnerable: {} | Critical: {} | High: {}",
            report.total_files_scanned,
            if report.is_vulnerable { "YES ⚠️" } else { "NO ✅" },
            report.critical_count,
            report.high_count
        );

        let plan = AutopilotHealer::plan_healing(&report);
        self.last_report = Some(report);
        self.last_plan = Some(plan);

        if let Some(ref r) = self.last_report {
            if r.is_vulnerable {
                println!("Type 'findings' to inspect issues, or 'heal --dry-run' to preview repairs.");
            }
        }
    }

    fn show_findings(&self) {
        let report = match &self.last_report {
            Some(r) => r,
            None => {
                println!("No audit report available. Run 'scan' first.");
                return;
            }
        };

        if report.findings.is_empty() {
            println!("✅ Zero vulnerabilities detected in current workspace.");
            return;
        }

        println!("\nDetected Vulnerabilities ({} total):", report.findings.len());
        for (idx, f) in report.findings.iter().enumerate() {
            let sev = match f.severity {
                Severity::Critical => "[CRITICAL]",
                Severity::High => "[HIGH]",
                Severity::Medium => "[MEDIUM]",
                Severity::Low => "[LOW]",
            };
            println!("{}. {} {} - {}", idx + 1, sev, f.cve.as_str(), f.cve.title());
            if let Some(ref p) = f.file_path {
                let line_str = f.line_number.map(|l| format!(":{}", l)).unwrap_or_default();
                println!("   Location:    {}{}", p.display(), line_str);
            }
            println!("   Pattern:     {}", f.detected_version_or_pattern);
            println!("   Threshold:   {}", f.safe_threshold);
            println!("   Remediation: {}\n", f.suggested_remediation);
        }
    }

    fn show_plan(&self) {
        let plan = match &self.last_plan {
            Some(p) => p,
            None => {
                println!("No healing plan generated. Run 'scan' first.");
                return;
            }
        };

        if plan.is_empty() {
            println!("ℹ️ Zero automated patches required (system clean or already healed).");
            return;
        }

        println!("\nPlanned Remediation Patches ({} total):", plan.len());
        for (idx, a) in plan.iter().enumerate() {
            println!("{}. Action:  {:?}", idx + 1, a.action_type);
            println!("   Target:  {}", a.target_file.display());
            println!("   Diff:    {}", a.diff_description);
            println!("   SHA256:  {}\n", a.original_checksum);
        }
    }

    fn show_diffs(&self) {
        let plan = match &self.last_plan {
            Some(p) => p,
            None => {
                println!("No healing plan available. Run 'scan' first.");
                return;
            }
        };

        if plan.is_empty() {
            println!("No diffs to display.");
            return;
        }

        println!("\n--- Proposed Patch Diffs ---");
        for (idx, a) in plan.iter().enumerate() {
            println!("\n[Patch {}/{}] Target: {}", idx + 1, plan.len(), a.target_file.display());
            println!("Action: {:?}", a.action_type);
            println!("Details: {}", a.diff_description);
            println!("Pre-mutation Checksum: {}", a.original_checksum);
        }
    }

    fn execute_heal(&mut self, args: &[&str]) {
        let dry_run = args.contains(&"--dry-run");

        let plan = match &self.last_plan {
            Some(p) => p.clone(),
            None => {
                println!("No healing plan generated. Run 'scan' first.");
                return;
            }
        };

        if plan.is_empty() {
            println!("Zero patches to apply.");
            return;
        }

        if dry_run {
            println!("Dry-run mode: {} patches would be applied.", plan.len());
            self.show_plan();
            println!("To apply live, run 'heal'.");
            return;
        }

        println!("Applying {} healing patches atomically...", plan.len());
        match AutopilotHealer::execute_healing(&self.current_dir, &plan) {
            Ok((manifest, count)) => {
                println!("✅ Successfully applied {} healing patches!", count);
                println!("📦 Backup Snapshot ID: {}", manifest.backup_id);
                println!("   To rollback if needed: rollback {}", manifest.backup_id);

                // Auto-refresh report and plan
                self.execute_scan(&[]);
            }
            Err(e) => eprintln!("❌ Healing failed: {}", e),
        }
    }

    fn execute_verify(&mut self) {
        println!("Running post-repair verification on {}...", self.current_dir.display());
        let report = FleetScanner::scan_directory(&self.current_dir, false);
        let plan = AutopilotHealer::plan_healing(&report);

        if report.is_vulnerable && !plan.is_empty() {
            println!("⚠️ Verification Warning: {} remaining unmitigated exposures found.", plan.len());
        } else {
            println!("✅ System verified! Zero unmitigated exposures remain.");
        }

        self.last_report = Some(report);
        self.last_plan = Some(plan);
    }

    fn execute_rollback(&mut self, args: &[&str]) {
        if args.is_empty() {
            println!("Usage: rollback <backup_id>");
            println!("Run 'history' to view recorded snapshot IDs.");
            return;
        }

        let backup_id = args[0];
        println!("Rolling back snapshot '{}'...", backup_id);
        match RollbackManager::rollback(&self.current_dir, backup_id) {
            Ok(count) => {
                println!("✅ Successfully restored {} files to pre-mutation state.", count);
                self.execute_scan(&[]);
            }
            Err(e) => eprintln!("❌ Rollback failed: {}", e),
        }
    }

    fn show_history(&self) {
        let backups = BackupManager::list_backups(&self.current_dir);
        if backups.is_empty() {
            println!("Zero backup snapshots recorded in .aegis/backups/");
            return;
        }

        println!("\nRecorded Backup Snapshots ({} total):", backups.len());
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

    fn run_doctor(&self) {
        let report = SystemDoctor::diagnose(&self.current_dir);
        println!("\n=======================================================");
        println!("  🩺  BUG KILLER SYSTEM DOCTOR REPORT");
        println!("=======================================================");
        println!("Operating System:  {}", report.os);
        println!("Architecture:      {}", report.arch);
        println!("Overall Health:    {}\n", if report.overall_healthy { "HEALTHY ✅" } else { "ATTENTION REQUIRED ⚠️" });

        for item in report.items {
            let badge = match item.status {
                crate::doctor::CheckStatus::Ok => "✅ OK  ",
                crate::doctor::CheckStatus::Warning => "⚠️ WARN",
                crate::doctor::CheckStatus::Failure => "❌ FAIL",
                crate::doctor::CheckStatus::NotInstalled => "⚪ NONE",
            };
            println!("{} {:<32} {}", badge, item.name, item.detected);
            if item.status != crate::doctor::CheckStatus::Ok {
                println!("   Recommendation: {}", item.recommendation);
            }
        }
        println!();
    }

    fn show_cve(&self, args: &[&str]) {
        if args.is_empty() {
            println!("Usage: cve <cve_id> (e.g. cve CVE-2026-109618, cve CVE-2026-111497)");
            return;
        }
        let norm = args[0].to_uppercase();
        if norm.contains("109618") {
            println!("\n=== CVE-2026-109618: PHP2Shell (Out-of-Memory Heap Corruption) ===");
            println!("CVSS: 9.2 (Critical) | Vector: Remote Code Execution (RCE)");
            println!("Root Cause: PHP runtime uses longjmp() on OOM errors to abort requests.");
            println!("In persistent worker SAPIs, uninitialized memory cleanups cause reliable RCE.");
            println!("Fixed Releases: PHP 8.2.35+, 8.3.36+, 8.4.27+, 8.5.12+ (All <= 8.1 are EOL)");
        } else if norm.contains("109619") {
            println!("\n=== CVE-2026-109619: PHP2Shell (Stale Global State / Use-After-Free) ===");
            println!("CVSS: 9.8 (Critical) | Vector: Remote Code Execution (RCE)");
            println!("Root Cause: Global state variables pointing into request memory fail to reset properly.");
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
            println!("Unknown CVE ID: '{}'. Supported: CVE-2026-109618, CVE-2026-109619, CVE-2026-111497", args[0]);
        }
    }

    fn run_watch(&self, args: &[&str]) {
        let interval: u64 = args.first().and_then(|s| s.parse().ok()).unwrap_or(3);
        WatcherEngine::watch(&self.current_dir, interval, false, None);
    }
}
