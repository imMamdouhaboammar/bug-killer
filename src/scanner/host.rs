use crate::types::*;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct RunningProcess {
    pub pid: u32,
    pub name: String,
    pub binary_path: Option<PathBuf>,
    pub cmdline: Option<String>,
}

pub struct HostProcessScanner;

impl HostProcessScanner {
    /// Discovers active runtime processes on the local system (PHP, Node, Webservers).
    pub fn discover_running_processes() -> Vec<RunningProcess> {
        let mut processes = Vec::new();

        #[cfg(target_os = "linux")]
        {
            if let Ok(entries) = std::fs::read_dir("/proc") {
                for entry in entries.flatten() {
                    let file_name = entry.file_name();
                    let name_str = file_name.to_string_lossy();
                    if let Ok(pid) = name_str.parse::<u32>() {
                        let proc_dir = entry.path();
                        let comm_path = proc_dir.join("comm");
                        let comm = std::fs::read_to_string(&comm_path)
                            .map(|s| s.trim().to_string())
                            .unwrap_or_default();

                        let exe_path = std::fs::read_link(proc_dir.join("exe")).ok();
                        let cmdline = std::fs::read_to_string(proc_dir.join("cmdline"))
                            .map(|s| s.replace('\0', " ").trim().to_string())
                            .ok();

                        let lower = comm.to_lowercase();
                        if lower.contains("php")
                            || lower.contains("node")
                            || lower.contains("nginx")
                            || lower.contains("apache")
                            || lower.contains("httpd")
                            || lower.contains("caddy")
                        {
                            processes.push(RunningProcess {
                                pid,
                                name: comm,
                                binary_path: exe_path,
                                cmdline,
                            });
                        }
                    }
                }
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            // Lightweight non-Linux fallback using `ps`
            if let Ok(output) = std::process::Command::new("ps")
                .args(["-A", "-o", "pid,comm"])
                .output()
            {
                if output.status.success() {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    for line in stdout.lines().skip(1) {
                        let trimmed = line.trim();
                        let parts: Vec<&str> = trimmed.split_whitespace().collect();
                        if parts.len() >= 2 {
                            if let Ok(pid) = parts[0].parse::<u32>() {
                                let comm = parts[1..].join(" ");
                                let lower = comm.to_lowercase();
                                if lower.contains("php")
                                    || lower.contains("node")
                                    || lower.contains("nginx")
                                    || lower.contains("apache")
                                    || lower.contains("httpd")
                                    || lower.contains("caddy")
                                {
                                    let bin_path = PathBuf::from(&comm);
                                    processes.push(RunningProcess {
                                        pid,
                                        name: bin_path
                                            .file_name()
                                            .map(|n| n.to_string_lossy().to_string())
                                            .unwrap_or_else(|| comm.clone()),
                                        binary_path: Some(bin_path),
                                        cmdline: None,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        processes
    }

    /// Correlates discovered live processes with scanner findings to anchor runtime identity.
    pub fn correlate_findings_with_runtime(findings: &mut [Finding], procs: &[RunningProcess]) {
        for f in findings.iter_mut() {
            for p in procs {
                let p_lower = p.name.to_lowercase();
                let matches = match f.target_kind {
                    TargetKind::PhpRuntime | TargetKind::PhpConfigFile | TargetKind::PhpFpmPool => {
                        p_lower.contains("php")
                    }
                    TargetKind::NodeRuntime
                    | TargetKind::NodePackageManifest
                    | TargetKind::NodeSourceFile => p_lower.contains("node"),
                    TargetKind::NginxConfig => p_lower.contains("nginx"),
                    TargetKind::ApacheConfig => {
                        p_lower.contains("apache") || p_lower.contains("httpd")
                    }
                    TargetKind::CaddyConfig => p_lower.contains("caddy"),
                    _ => false,
                };

                if matches {
                    let path_str = p
                        .binary_path
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "unknown".into());
                    let cmd_str = p.cmdline.as_deref().unwrap_or(&p.name);
                    f.runtime_process_identity = Some(format!(
                        "pid:{}, name:{}, path:{}, cmd:{}",
                        p.pid, p.name, path_str, cmd_str
                    ));
                    f.reachability = Reachability::ConfirmedReachable;
                    f.confidence = Confidence::High;
                    f.uncertainty_reasons.retain(|r| !r.contains("runtime"));
                    break;
                }
            }
        }
    }
}
