#![allow(clippy::collapsible_if, clippy::manual_flatten)]

mod binary_audit;
mod mem_audit;

use clap::Parser;
use std::fs;
use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};
use binary_audit::{BinaryAuditor, DeepBinaryFinding};
use mem_audit::{ProcessMemoryAuditor, ProcessMemoryFinding};

#[derive(Parser, Debug)]
#[command(name = "bug-killer-inspector")]
#[command(about = "Bug Killer Deep Binary Inspector & Reachability Analyzer", version = "0.1.0")]
struct Cli {
    /// Path to input coverage-ledger.json
    #[arg(short, long, default_value = "coverage-ledger.json")]
    ledger: PathBuf,

    /// Output findings JSON path
    #[arg(short, long, default_value = "findings.json")]
    out: PathBuf,

    /// Direct single binary audit path
    #[arg(long)]
    binary: Option<PathBuf>,

    /// Direct single PID memory audit
    #[arg(long)]
    pid: Option<i32>,
}

#[derive(Debug, Deserialize)]
struct LedgerAsset {
    #[serde(rename = "type")]
    _asset_type: String,
    path: String,
    source: String,
    associated_pid: Option<i32>,
}

#[derive(Debug, Deserialize)]
struct CoverageLedgerInput {
    host_id: String,
    total_assets: usize,
    assets: Vec<LedgerAsset>,
}

#[derive(Debug, Serialize)]
struct ComprehensiveAuditReport {
    host_id: String,
    audit_timestamp: String,
    total_assets_inspected: usize,
    critical_findings_count: usize,
    high_findings_count: usize,
    binary_findings: Vec<DeepBinaryFinding>,
    process_findings: Vec<ProcessMemoryFinding>,
}

fn main() {
    let cli = Cli::parse();

    // 1. Single target mode
    if let Some(ref bin_path) = cli.binary {
        match BinaryAuditor::audit_binary(bin_path) {
            Ok(finding) => {
                println!("{}", serde_json::to_string_pretty(&finding).unwrap());
            }
            Err(e) => {
                eprintln!("[-] Error inspecting {:?}: {}", bin_path, e);
                std::process::exit(1);
            }
        }
        return;
    }

    if let Some(pid) = cli.pid {
        match ProcessMemoryAuditor::audit_process(pid) {
            Ok(finding) => {
                println!("{}", serde_json::to_string_pretty(&finding).unwrap());
            }
            Err(e) => {
                eprintln!("[-] Error inspecting PID {}: {}", pid, e);
                std::process::exit(1);
            }
        }
        return;
    }

    // 2. Ledger-driven fleet audit mode
    if !cli.ledger.exists() {
        eprintln!("[-] Coverage ledger {:?} not found. Run orchestrator first.", cli.ledger);
        std::process::exit(1);
    }

    let ledger_data = fs::read_to_string(&cli.ledger).expect("Failed to read ledger");
    let ledger: CoverageLedgerInput = serde_json::from_str(&ledger_data).expect("Invalid ledger JSON");

    println!("[+] Aegis Inspector: Ingested ledger from '{}' (Total Assets: {})", ledger.host_id, ledger.total_assets);

    let mut binary_findings = Vec::new();
    let mut process_findings = Vec::new();
    let mut critical_count = 0;
    let mut high_count = 0;

    for asset in &ledger.assets {
        if asset.source == "binary" || asset.source == "shared_object" {
            let path = Path::new(&asset.path);
            if path.exists() {
                if let Ok(finding) = BinaryAuditor::audit_binary(path) {
                    if finding.is_vulnerable {
                        if finding.severity == "CRITICAL" {
                            critical_count += 1;
                        } else {
                            high_count += 1;
                        }
                    }
                    binary_findings.push(finding);
                }
            }
        } else if asset.source == "process" {
            if let Some(pid) = asset.associated_pid {
                if let Ok(p_finding) = ProcessMemoryAuditor::audit_process(pid) {
                    if p_finding.is_exposed {
                        critical_count += 1;
                    }
                    process_findings.push(p_finding);
                }
            }
        }
    }

    let report = ComprehensiveAuditReport {
        host_id: ledger.host_id,
        audit_timestamp: chrono::Utc::now().to_rfc3339(),
        total_assets_inspected: binary_findings.len() + process_findings.len(),
        critical_findings_count: critical_count,
        high_findings_count: high_count,
        binary_findings,
        process_findings,
    };

    let out_json = serde_json::to_string_pretty(&report).unwrap();
    fs::write(&cli.out, &out_json).expect("Failed to write findings.json");

    println!("[✓] Findings written to '{}' (Critical: {}, High: {})", cli.out.display(), critical_count, high_count);
}
