use std::fs;
use std::path::Path;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessMemoryFinding {
    pub pid: i32,
    pub is_exposed: bool,
    pub mapped_vulnerable_libraries: Vec<String>,
    pub execution_regions_count: usize,
    pub risk_summary: String,
}

pub struct ProcessMemoryAuditor;

impl ProcessMemoryAuditor {
    /// Inspects `/proc/[PID]/maps` securely without crashing or blocking target process.
    pub fn audit_process(pid: i32) -> Result<ProcessMemoryFinding, String> {
        let maps_path = format!("/proc/{}/maps", pid);
        if !Path::new(&maps_path).exists() {
            return Ok(ProcessMemoryFinding {
                pid,
                is_exposed: false,
                mapped_vulnerable_libraries: vec![],
                execution_regions_count: 0,
                risk_summary: format!("PID {} not running or non-Linux environment (/proc unavailable)", pid),
            });
        }

        let content = fs::read_to_string(&maps_path)
            .map_err(|e| format!("Failed to read {}: {}", maps_path, e))?;

        let mut exec_count = 0;
        let mut vuln_libs = Vec::new();

        for line in content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 6 {
                continue;
            }

            let permissions = parts[1];
            let path = parts[5];

            if permissions.contains('x') {
                exec_count += 1;
            }

            // Detect vulnerable shared libraries mapped in execution segments
            if path.contains("libphp") || path.contains("php") {
                if !vuln_libs.contains(&path.to_string()) {
                    vuln_libs.push(path.to_string());
                }
            }
        }

        let is_exposed = !vuln_libs.is_empty();
        let risk_summary = if is_exposed {
            format!("Process {} mapped {} vulnerable runtime libraries into active memory space.", pid, vuln_libs.len())
        } else {
            format!("Process {} verified: zero unpatched runtime memory segments mapped.", pid)
        };

        Ok(ProcessMemoryFinding {
            pid,
            is_exposed,
            mapped_vulnerable_libraries: vuln_libs,
            execution_regions_count: exec_count,
            risk_summary,
        })
    }
}
