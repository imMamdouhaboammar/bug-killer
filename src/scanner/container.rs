use crate::types::*;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

pub struct ContainerScanner;

impl ContainerScanner {
    /// Scans a Dockerfile or Containerfile for container security and supply-chain risks.
    pub fn scan_dockerfile(path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => return findings,
        };

        let file_digest = format!("{:x}", Sha256::digest(path.to_string_lossy().as_bytes()));
        let mut has_user_directive = false;
        let mut last_user = String::new();
        let mut last_user_line = 0;

        for (idx, line) in content.lines().enumerate() {
            let line_num = idx + 1;
            let trimmed = line.trim();

            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            // 1. USER directive analysis
            if let Some(user_part) = trimmed.strip_prefix("USER ") {
                has_user_directive = true;
                last_user = user_part.trim().to_string();
                last_user_line = line_num;
            }

            // 2. Untrusted curl/wget piping to shell
            if (trimmed.starts_with("RUN ")
                || trimmed.starts_with("ENTRYPOINT ")
                || trimmed.starts_with("CMD "))
                && (trimmed.contains("curl ") || trimmed.contains("wget "))
                && (trimmed.contains("| bash")
                    || trimmed.contains("| sh")
                    || trimmed.contains("| /bin/bash")
                    || trimmed.contains("| /bin/sh"))
            {
                let mut finding = Finding::new(
                    format!("container-curl-pipe-sh-{}-L{}", &file_digest[..8], line_num),
                    CveId::Custom {
                        id: "BK-CONTAINER-002".to_string(),
                        title: "Untrusted Script Execution via curl/wget Piping to Shell".to_string(),
                    },
                    Severity::High,
                    TargetKind::Dockerfile,
                    Some(path.to_path_buf()),
                    Some(line_num),
                    trimmed.to_string(),
                    "Download script, verify SHA-256 checksum or GPG signature before execution".to_string(),
                    "Piping remote scripts directly from curl/wget to a shell bypasses integrity verification and exposes build containers to MITM and supply-chain compromise.".to_string(),
                    "Download the installation artifact to disk, verify its cryptographic hash against an immutable vendor checksum, and execute the verified local file.".to_string(),
                );
                finding.detector_id = "container-scanner".to_string();
                finding.category = "supply-chain-risk".to_string();
                finding.affectedness = Affectedness::ConfirmedAffected;
                finding.reachability = Reachability::PotentiallyReachable;
                finding.confidence = Confidence::High;
                finding.supported_checks = vec!["dockerfile_shell_pipe_check".to_string()];
                finding.compute_dedupe_fingerprint();
                findings.push(finding);
            }

            // 3. Plaintext secret / credential exposure in ENV or ARG
            if trimmed.starts_with("ENV ") || trimmed.starts_with("ARG ") {
                let assignment = if let Some(e) = trimmed.strip_prefix("ENV ") {
                    e
                } else {
                    trimmed.strip_prefix("ARG ").unwrap_or_default()
                };

                let lower = assignment.to_lowercase();
                let sensitive_keys = [
                    "api_key",
                    "secret_key",
                    "access_key",
                    "password",
                    "passwd",
                    "private_key",
                    "auth_token",
                    "github_token",
                    "jwt_secret",
                    "database_url",
                ];

                for key in &sensitive_keys {
                    if lower.contains(key) {
                        let is_placeholder = assignment.contains("${")
                            || assignment.contains("$(")
                            || assignment.contains("\"\"")
                            || assignment.ends_with('=');

                        if !is_placeholder {
                            let mut finding = Finding::new(
                                format!("container-secret-exposure-{}-L{}", &file_digest[..8], line_num),
                                CveId::Custom {
                                    id: "BK-CONTAINER-003".to_string(),
                                    title: "Secrets Embedded in Dockerfile Layer or Container Arguments".to_string(),
                                },
                                Severity::Critical,
                                TargetKind::Dockerfile,
                                Some(path.to_path_buf()),
                                Some(line_num),
                                format!("[REDACTED] Assignment matches sensitive key '{}'", key),
                                "Use Docker BuildKit secret mounts (--mount=type=secret) or runtime environment variables".to_string(),
                                format!("Sensitive credential '{}' is baked directly into the Docker image filesystem layer, where it persists in the image history and can be extracted by any consumer.", key),
                                "Remove hardcoded credentials from the Dockerfile. Use Docker BuildKit secret mounts (--mount=type=secret,id=...) or inject credentials dynamically at container execution time.".to_string(),
                            );
                            finding.detector_id = "container-scanner".to_string();
                            finding.category = "credential-leakage".to_string();
                            finding.advisory_ids.push("BK-AI-INF-007".to_string());
                            finding.affectedness = Affectedness::ConfirmedAffected;
                            finding.reachability = Reachability::ConfirmedReachable;
                            finding.confidence = Confidence::High;
                            finding.supported_checks =
                                vec!["dockerfile_secret_pattern_check".to_string()];
                            finding.compute_dedupe_fingerprint();
                            findings.push(finding);
                            break;
                        }
                    }
                }
            }

            // 4. Insecure 0.0.0.0 binding exposure (BK-AI-INF-001)
            if trimmed.contains("0.0.0.0")
                && (trimmed.starts_with("EXPOSE ")
                    || trimmed.starts_with("CMD ")
                    || trimmed.starts_with("ENTRYPOINT ")
                    || trimmed.contains("--bind")
                    || trimmed.contains("--host"))
            {
                let mut finding = Finding::new(
                    format!("container-bind-all-{}-L{}", &file_digest[..8], line_num),
                    CveId::Custom {
                        id: "BK-AI-INF-001".to_string(),
                        title: "Service Exposed on 0.0.0.0 (Public Interface Binding)".to_string(),
                    },
                    Severity::Medium,
                    TargetKind::Dockerfile,
                    Some(path.to_path_buf()),
                    Some(line_num),
                    trimmed.to_string(),
                    "Bind internal services to loopback 127.0.0.1 or rely on container overlay networking".to_string(),
                    "Binding directly to 0.0.0.0 exposes administrative, debugging, or internal application endpoints to all available network interfaces without firewall isolation.".to_string(),
                    "Change service binding from 0.0.0.0 to 127.0.0.1 for local services, or enforce ingress security policies.".to_string(),
                );
                finding.detector_id = "container-scanner".to_string();
                finding.category = "container-hardening".to_string();
                finding.affectedness = Affectedness::ConfirmedAffected;
                finding.reachability = Reachability::PotentiallyReachable;
                finding.confidence = Confidence::High;
                finding.supported_checks = vec!["dockerfile_bind_all_check".to_string()];
                finding.compute_dedupe_fingerprint();
                findings.push(finding);
            }

            // 4. Docker daemon socket exposure or dangerous mounts
            if trimmed.contains("/var/run/docker.sock") {
                let mut finding = Finding::new(
                    format!("container-docker-socket-{}-L{}", &file_digest[..8], line_num),
                    CveId::Custom {
                        id: "BK-CONTAINER-004".to_string(),
                        title: "Docker Daemon Socket Exposure".to_string(),
                    },
                    Severity::Critical,
                    TargetKind::Dockerfile,
                    Some(path.to_path_buf()),
                    Some(line_num),
                    trimmed.to_string(),
                    "Do not expose Docker daemon socket (/var/run/docker.sock) inside containers".to_string(),
                    "Exposing the host Docker daemon socket grants root-equivalent control over the host engine, enabling trivial container escape.".to_string(),
                    "Remove docker.sock volume mounts. Use rootless container engines or dedicated agent APIs with scoped permissions.".to_string(),
                );
                finding.detector_id = "container-scanner".to_string();
                finding.category = "container-hardening".to_string();
                finding.advisory_ids.push("BK-AI-INF-004".to_string());
                finding.affectedness = Affectedness::ConfirmedAffected;
                finding.reachability = Reachability::ConfirmedReachable;
                finding.confidence = Confidence::High;
                finding.supported_checks = vec!["dockerfile_daemon_socket_check".to_string()];
                finding.compute_dedupe_fingerprint();
                findings.push(finding);
            }
        }

        // Evaluate USER policy: default root or explicit USER root
        if !has_user_directive || last_user == "root" || last_user == "0" {
            let line = if last_user_line > 0 {
                Some(last_user_line)
            } else {
                None
            };
            let (evidence, title, sev) = if !has_user_directive {
                (
                    "Missing USER instruction: container defaults to root execution".to_string(),
                    "Container Runs as Root by Default (Missing USER)".to_string(),
                    Severity::Medium,
                )
            } else {
                (
                    "Explicit 'USER root' or 'USER 0' directive detected".to_string(),
                    "Container Explicitly Configured to Run as Root".to_string(),
                    Severity::High,
                )
            };

            let mut finding = Finding::new(
                format!("container-root-user-{}", &file_digest[..8]),
                CveId::Custom {
                    id: "BK-AI-INF-003".to_string(),
                    title,
                },
                sev,
                TargetKind::Dockerfile,
                Some(path.to_path_buf()),
                line,
                evidence,
                "Define and switch to an unprivileged non-root USER before ENTRYPOINT".to_string(),
                "Running containers as root violates the principle of least privilege. In the event of a container breakout or runtime vulnerability, root in the container can compromise the host namespace.".to_string(),
                "Create a dedicated non-root user and group (e.g. 'RUN addgroup -S app && adduser -S app -G app') and specify 'USER app' prior to ENTRYPOINT or CMD.".to_string(),
            );
            finding.detector_id = "container-scanner".to_string();
            finding.category = "container-hardening".to_string();
            finding.advisory_ids.push("BK-CONTAINER-001".to_string());
            finding.affectedness = Affectedness::ConfirmedAffected;
            finding.reachability = Reachability::ConfirmedReachable;
            finding.confidence = Confidence::High;
            finding.supported_checks = vec!["dockerfile_user_directive_check".to_string()];
            finding.missing_checks = vec!["runtime_container_cap_drop_verification".to_string()];
            finding.compute_dedupe_fingerprint();
            findings.push(finding);
        }

        findings
    }
}
