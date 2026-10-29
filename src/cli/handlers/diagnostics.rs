use crate::cli::Cli;
use crate::completion::CompletionGenerator;
use crate::doctor::{self, SystemDoctor};
use crate::osv::OsvClient;
use crate::scanner::host::HostProcessScanner;
use crate::security_guard::SecurityGuard;
use crate::shell::ShellEngine;
use crate::watcher::WatcherEngine;
use clap::CommandFactory;
use std::path::PathBuf;

pub fn handle_shell(path: PathBuf) -> i32 {
    let mut shell = ShellEngine::new(path);
    shell.run();
    0
}

pub fn handle_doctor(path: PathBuf, json: bool) -> i32 {
    let report = SystemDoctor::diagnose(&path);
    if json {
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
        return 0;
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
    0
}

pub fn handle_watch(path: PathBuf, interval: u64, auto_heal: bool, _rules: Option<PathBuf>) -> i32 {
    if auto_heal {
        eprintln!(
            "Independent operator approval is required; watch --auto-heal cannot execute unapproved patches. Use 'approve' and 'apply'."
        );
        return 4;
    }
    WatcherEngine::watch(&path, interval, auto_heal, None);
    0
}

pub fn handle_completion(shell: String) -> i32 {
    let mut cmd = Cli::command();
    if let Err(e) = CompletionGenerator::generate_completion(&shell, &mut cmd) {
        eprintln!("Error: {}", e);
        return 1;
    }
    0
}

pub fn handle_init(path: PathBuf, hooks: bool, json: bool) -> i32 {
    if !json {
        println!(
            "🚀 Initializing Bug Killer Security Guard in {}...",
            path.display()
        );
    }
    match SecurityGuard::init(&path, hooks) {
        Ok(receipt) => {
            if json {
                println!("{}", serde_json::to_string_pretty(&receipt).unwrap());
            } else {
                println!("✅ Initialization complete for '{}'", receipt.project_name);
                println!(
                    "   Languages detected: {}",
                    receipt.detected_languages.join(", ")
                );
                println!(
                    "   Package managers: {}",
                    if receipt.package_managers.is_empty() {
                        "none".to_string()
                    } else {
                        receipt.package_managers.join(", ")
                    }
                );
                println!("   Config: {}", receipt.config_path.display());
                println!("   Policy: {}", receipt.policy_path.display());
                println!("   Baseline report: {}", receipt.baseline_path.display());
                println!(
                    "   Git pre-commit hook: {}",
                    if receipt.git_hook_installed {
                        "installed"
                    } else {
                        "skipped/not a git repo"
                    }
                );
                println!(
                    "   Baseline findings: {} ({})",
                    receipt.baseline_findings_count,
                    if receipt.baseline_clean {
                        "CLEAN"
                    } else {
                        "FINDINGS DETECTED"
                    }
                );
            }
            0
        }
        Err(e) => {
            eprintln!("❌ Initialization failed: {}", e);
            1
        }
    }
}

pub fn handle_inventory(path: PathBuf, sbom: Option<String>, json: bool) -> i32 {
    let packages = OsvClient::discover_packages(&path);
    let processes = HostProcessScanner::discover_running_processes();
    let mut sbom_packages = Vec::new();
    for p in &packages {
        sbom_packages.push(serde_json::json!({
            "name": p.name,
            "version": p.version,
            "ecosystem": p.ecosystem,
            "manifest_path": p.file_path.display().to_string(),
            "purl": format!("pkg:{}/{}@{}", p.ecosystem.to_lowercase(), p.name, p.version)
        }));
    }
    let inventory = serde_json::json!({
        "workspace": path.display().to_string(),
        "format": sbom.unwrap_or_else(|| "json".to_string()),
        "total_discovered_packages": packages.len(),
        "packages": sbom_packages,
        "total_host_processes": processes.len(),
        "processes": processes,
    });
    if json {
        println!("{}", serde_json::to_string_pretty(&inventory).unwrap());
    } else {
        println!("\n=======================================================");
        println!("  📦  WORKSPACE SOFTWARE ASSET INVENTORY");
        println!("=======================================================");
        println!("Target Workspace:   {}", path.display());
        println!("Packages Discovered: {}", packages.len());
        println!("Processes Running:   {}\n", processes.len());
        for p in packages.iter().take(20) {
            println!("  • {:<20} {} ({})", p.name, p.version, p.ecosystem);
        }
        if packages.len() > 20 {
            println!(
                "  ... and {} more packages (use --json to view all)",
                packages.len() - 20
            );
        }
    }
    0
}
