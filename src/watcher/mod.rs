use crate::healer::AutopilotHealer;
use crate::scanner::FleetScanner;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::sleep;
use std::time::Duration;

pub struct WatcherEngine;

impl WatcherEngine {
    /// Runs a surveillance loop over target_dir, checking for changes every `interval_secs`.
    /// When changes are detected, a full scan is triggered.
    /// If `auto_heal` is true, safe patches are automatically applied and recorded.
    pub fn watch(
        target_dir: &Path,
        interval_secs: u64,
        auto_heal: bool,
        shutdown_signal: Option<Arc<AtomicBool>>,
    ) {
        println!("=======================================================");
        println!("  👁️  BUG KILLER: LIVE SURVEILLANCE & WATCHER ENGINE");
        println!("=======================================================");
        println!("Target Directory:   {}", target_dir.display());
        println!("Polling Interval:   {}s", interval_secs);
        println!(
            "Autopilot Healing:  {}",
            if auto_heal {
                "ENABLED"
            } else {
                "DISABLED (Alert Only)"
            }
        );
        println!("Press Ctrl+C to terminate surveillance.\n");

        let mut file_state: HashMap<PathBuf, u64> = Self::snapshot_mtimes(target_dir);
        let mut cycle = 0;

        loop {
            if let Some(ref sig) = shutdown_signal {
                if sig.load(Ordering::Relaxed) {
                    println!("\n[bk-watch] Shutdown signal received. Exiting surveillance loop.");
                    break;
                }
            }

            sleep(Duration::from_secs(interval_secs));
            cycle += 1;

            let current_state = Self::snapshot_mtimes(target_dir);
            let has_modifications = current_state != file_state;

            if has_modifications || cycle == 1 {
                file_state = current_state;
                let timestamp = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ");
                println!(
                    "[{}] Filesystem delta detected. Triggering scan...",
                    timestamp
                );

                let report = FleetScanner::scan_directory(target_dir, false);

                if report.is_vulnerable {
                    println!(
                        "⚠️  VULNERABILITIES DETECTED: {} Critical, {} High across {} findings.",
                        report.critical_count,
                        report.high_count,
                        report.findings.len()
                    );

                    for finding in &report.findings {
                        let path_str = finding
                            .file_path
                            .as_ref()
                            .map(|p| p.display().to_string())
                            .unwrap_or_else(|| "runtime".into());
                        println!(
                            "   - [{}] {} @ {}",
                            finding.cve.as_str(),
                            finding.cve.title(),
                            path_str
                        );
                    }

                    if auto_heal {
                        let plan = AutopilotHealer::plan_healing(&report);
                        if !plan.is_empty() {
                            println!("🩹 Applying {} autopilot healing patches...", plan.len());
                            match AutopilotHealer::execute_healing(target_dir, &plan) {
                                Ok((manifest, count)) => {
                                    println!(
                                        "✅ Successfully applied {} healing patches! Snapshot ID: {}",
                                        count, manifest.backup_id
                                    );
                                    // Update state to include healed files
                                    file_state = Self::snapshot_mtimes(target_dir);
                                }
                                Err(e) => eprintln!("❌ Healing failed: {}", e),
                            }
                        }
                    }
                } else {
                    println!("✅ All targets secure. Zero unmitigated exposures.");
                }
            }
        }
    }

    /// Captures the latest modification timestamp (in unix secs) for all audit-relevant files.
    pub fn snapshot_mtimes(root: &Path) -> HashMap<PathBuf, u64> {
        let mut map = HashMap::new();
        for entry in walkdir::WalkDir::new(root)
            .into_iter()
            .filter_entry(|e| {
                if e.depth() == 0 {
                    return true;
                }
                let name = e.file_name().to_string_lossy();
                !name.starts_with('.')
                    && name != "node_modules"
                    && name != "vendor"
                    && name != "target"
            })
            .flatten()
        {
            let path = entry.path();
            if path.is_file() {
                if let Ok(metadata) = path.metadata() {
                    if let Ok(mtime) = metadata.modified() {
                        let duration = mtime
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default();
                        map.insert(path.to_path_buf(), duration.as_secs());
                    }
                }
            }
        }
        map
    }
}
