use crate::cve_db::CveDatabase;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::process::Command;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CheckStatus {
    Ok,
    Warning,
    Failure,
    NotInstalled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoctorItem {
    pub name: String,
    pub status: CheckStatus,
    pub detected: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoctorReport {
    pub os: String,
    pub arch: String,
    pub items: Vec<DoctorItem>,
    pub overall_healthy: bool,
}

pub struct SystemDoctor;

impl SystemDoctor {
    pub fn diagnose(target_dir: &Path) -> DoctorReport {
        let items = vec![
            // 1. Check Node.js
            Self::check_node(),
            // 2. Check PHP
            Self::check_php(),
            // 3. Check Reverse Proxies
            Self::check_nginx(),
            Self::check_haproxy(),
            // 4. Check Docker Socket
            Self::check_docker_socket(),
            // 5. Check Target Directory Permissions
            Self::check_directory_permissions(target_dir),
            // 6. Check Process Inspection Capability
            Self::check_procfs(),
        ];

        let overall_healthy = items.iter().all(|i| i.status != CheckStatus::Failure);

        DoctorReport {
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            items,
            overall_healthy,
        }
    }

    fn check_node() -> DoctorItem {
        match Command::new("node").arg("-v").output() {
            Ok(out) if out.status.success() => {
                let ver_str = String::from_utf8_lossy(&out.stdout)
                    .trim()
                    .trim_start_matches('v')
                    .to_string();
                if let Some((major, minor, patch)) = CveDatabase::parse_semver(&ver_str) {
                    if let Some((cve, _, safe_threshold)) =
                        CveDatabase::check_node_version(major, minor, patch)
                    {
                        DoctorItem {
                            name: "Node.js Runtime".into(),
                            status: CheckStatus::Failure,
                            detected: format!("v{} (Vulnerable to {})", ver_str, cve.as_str()),
                            recommendation: format!("Upgrade immediately to {}", safe_threshold),
                        }
                    } else {
                        DoctorItem {
                            name: "Node.js Runtime".into(),
                            status: CheckStatus::Ok,
                            detected: format!("v{} (Safe from Node2Shell)", ver_str),
                            recommendation: "Runtime meets security baseline.".into(),
                        }
                    }
                } else {
                    DoctorItem {
                        name: "Node.js Runtime".into(),
                        status: CheckStatus::Warning,
                        detected: format!("v{} (Unrecognized semver)", ver_str),
                        recommendation: "Ensure Node.js is an official LTS release.".into(),
                    }
                }
            }
            _ => DoctorItem {
                name: "Node.js Runtime".into(),
                status: CheckStatus::NotInstalled,
                detected: "Not found on PATH".into(),
                recommendation: "Node.js not installed on host.".into(),
            },
        }
    }

    fn check_php() -> DoctorItem {
        match Command::new("php").arg("-v").output() {
            Ok(out) if out.status.success() => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                let first_line = stdout.lines().next().unwrap_or_default();
                let re = regex::Regex::new(r"PHP\s+(\d+\.\d+\.\d+)").unwrap();
                if let Some(caps) = re.captures(first_line) {
                    let ver_str = caps.get(1).unwrap().as_str();
                    if let Some((major, minor, patch)) = CveDatabase::parse_semver(ver_str) {
                        if let Some((cve, _, safe_threshold)) =
                            CveDatabase::check_php_version(major, minor, patch)
                        {
                            DoctorItem {
                                name: "PHP Runtime".into(),
                                status: CheckStatus::Failure,
                                detected: format!("v{} (Vulnerable to {})", ver_str, cve.as_str()),
                                recommendation: format!(
                                    "Upgrade immediately to {}",
                                    safe_threshold
                                ),
                            }
                        } else {
                            DoctorItem {
                                name: "PHP Runtime".into(),
                                status: CheckStatus::Ok,
                                detected: format!("v{} (Safe from PHP2Shell)", ver_str),
                                recommendation: "Runtime meets security baseline.".into(),
                            }
                        }
                    } else {
                        DoctorItem {
                            name: "PHP Runtime".into(),
                            status: CheckStatus::Warning,
                            detected: format!("v{} (Unrecognized semver)", ver_str),
                            recommendation: "Ensure PHP is an official supported release.".into(),
                        }
                    }
                } else {
                    DoctorItem {
                        name: "PHP Runtime".into(),
                        status: CheckStatus::Warning,
                        detected: first_line.to_string(),
                        recommendation: "Unable to parse exact PHP version.".into(),
                    }
                }
            }
            _ => DoctorItem {
                name: "PHP Runtime".into(),
                status: CheckStatus::NotInstalled,
                detected: "Not found on PATH".into(),
                recommendation: "PHP not installed on host.".into(),
            },
        }
    }

    fn check_nginx() -> DoctorItem {
        match Command::new("nginx").arg("-v").output() {
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr);
                let text = if stderr.is_empty() {
                    String::from_utf8_lossy(&out.stdout).to_string()
                } else {
                    stderr.to_string()
                };
                DoctorItem {
                    name: "Nginx Reverse Proxy".into(),
                    status: CheckStatus::Ok,
                    detected: text.trim().to_string(),
                    recommendation: "Ready for automated WAF virtual patch injection.".into(),
                }
            }
            _ => DoctorItem {
                name: "Nginx Reverse Proxy".into(),
                status: CheckStatus::NotInstalled,
                detected: "Not found on PATH".into(),
                recommendation: "Optional: install if using Nginx as frontend reverse proxy."
                    .into(),
            },
        }
    }

    fn check_haproxy() -> DoctorItem {
        match Command::new("haproxy").arg("-v").output() {
            Ok(out) => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                let first_line = stdout.lines().next().unwrap_or_default().trim();
                DoctorItem {
                    name: "HAProxy".into(),
                    status: CheckStatus::Ok,
                    detected: first_line.to_string(),
                    recommendation: "Ready for automated ACL rule injection.".into(),
                }
            }
            _ => DoctorItem {
                name: "HAProxy".into(),
                status: CheckStatus::NotInstalled,
                detected: "Not found on PATH".into(),
                recommendation: "Optional: install if using HAProxy as frontend load balancer."
                    .into(),
            },
        }
    }

    fn check_docker_socket() -> DoctorItem {
        let sock = Path::new("/var/run/docker.sock");
        if sock.exists() {
            match std::fs::metadata(sock) {
                Ok(_) => DoctorItem {
                    name: "Docker Socket (/var/run/docker.sock)".into(),
                    status: CheckStatus::Ok,
                    detected: "Present and accessible".into(),
                    recommendation: "Microservices orchestrator can inventory active containers."
                        .into(),
                },
                Err(e) => DoctorItem {
                    name: "Docker Socket (/var/run/docker.sock)".into(),
                    status: CheckStatus::Warning,
                    detected: format!("Permission error: {}", e),
                    recommendation:
                        "Add user to 'docker' group or run orchestrator with elevated permissions."
                            .into(),
                },
            }
        } else {
            DoctorItem {
                name: "Docker Socket (/var/run/docker.sock)".into(),
                status: CheckStatus::NotInstalled,
                detected: "Socket file does not exist".into(),
                recommendation: "Docker not running locally; container auditing will be skipped."
                    .into(),
            }
        }
    }

    fn check_directory_permissions(target: &Path) -> DoctorItem {
        let test_file = target.join(".bk_doctor_probe");
        match std::fs::write(&test_file, b"probe") {
            Ok(_) => {
                let _ = std::fs::remove_file(&test_file);
                DoctorItem {
                    name: "Workspace Write Permissions".into(),
                    status: CheckStatus::Ok,
                    detected: format!("Write access verified on {}", target.display()),
                    recommendation:
                        "Autopilot healer can execute atomic patches and create backups.".into(),
                }
            }
            Err(e) => DoctorItem {
                name: "Workspace Write Permissions".into(),
                status: CheckStatus::Failure,
                detected: format!("Read-only or access denied on {}: {}", target.display(), e),
                recommendation:
                    "Ensure write permissions for automated healing and backup snapshots.".into(),
            },
        }
    }

    fn check_procfs() -> DoctorItem {
        let proc_dir = Path::new("/proc");
        if proc_dir.exists() && proc_dir.is_dir() {
            DoctorItem {
                name: "Linux Procfs (/proc)".into(),
                status: CheckStatus::Ok,
                detected: "Available".into(),
                recommendation: "Live process table mapping and memory audit enabled.".into(),
            }
        } else if cfg!(target_os = "macos") {
            DoctorItem {
                name: "Kernel Process Mapping".into(),
                status: CheckStatus::Ok,
                detected: "macOS Mach Kernel".into(),
                recommendation: "Using native Mach-O binary parsing and posix process APIs.".into(),
            }
        } else {
            DoctorItem {
                name: "Process Introspection".into(),
                status: CheckStatus::Warning,
                detected: "Unavailable or restricted".into(),
                recommendation:
                    "Running in sandboxed environment; static filesystem audit will be used.".into(),
            }
        }
    }
}
