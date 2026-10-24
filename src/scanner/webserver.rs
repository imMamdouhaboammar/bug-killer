use std::fs;
use std::path::Path;
use crate::types::*;

pub struct WebServerScanner;

impl WebServerScanner {
    /// Scans Nginx configuration files for missing Brotli request body filtering or PHP-FPM proxying.
    pub fn scan_nginx_config(path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => return findings,
        };

        let has_virtual_patch = content.contains("BUG KILLER VIRTUAL PATCH (CVE-2026-111497") || content.contains("AEGIS VIRTUAL PATCH (CVE-2026-111497");
        let has_brotli_filter = content.contains("$http_content_encoding") && content.contains("br");
        let proxies_to_node_or_upstream = content.contains("proxy_pass");
        let proxies_to_php = content.contains("fastcgi_pass") || content.contains("php");

        if proxies_to_node_or_upstream && !has_brotli_filter && !has_virtual_patch {
            findings.push(Finding {
                id: "NGINX-NODE-MISSING-BROTLI-FILTER".to_string(),
                cve: CveId::Node2ShellBrotli("CVE-2026-111497".into()),
                severity: Severity::High,
                target_kind: TargetKind::NginxConfig,
                file_path: Some(path.to_path_buf()),
                line_number: None,
                detected_version_or_pattern: "proxy_pass configured without request body Content-Encoding: br filter".to_string(),
                safe_threshold: "Inject Bug Killer Nginx virtual patch blocking uninspected 'Content-Encoding: br'".to_string(),
                description: "Nginx reverse proxy passes client request bodies directly to upstream without checking for Brotli encoding, allowing CVE-2026-111497 exploit payloads to reach Node.js decoder.".to_string(),
                suggested_remediation: "Apply Bug Killer Nginx virtual patch to return 415 on Brotli-compressed request bodies.".to_string(),
            });
        }

        if proxies_to_php && !content.contains("fastcgi_buffer_size") {
            findings.push(Finding {
                id: "NGINX-PHP-UNBOUNDED-BUFFERS".to_string(),
                cve: CveId::Php2ShellOom("CVE-2026-109618".into()),
                severity: Severity::Medium,
                target_kind: TargetKind::NginxConfig,
                file_path: Some(path.to_path_buf()),
                line_number: None,
                detected_version_or_pattern: "fastcgi_pass without bounded buffer size configuration".to_string(),
                safe_threshold: "Explicit fastcgi_buffer_size 128k; fastcgi_buffers 4 256k;".to_string(),
                description: "FastCGI pass lacks explicit buffer boundaries, facilitating memory exhaustion attacks against PHP-FPM pools.".to_string(),
                suggested_remediation: "Harden Nginx FastCGI buffer parameters.".to_string(),
            });
        }

        findings
    }

    /// Scans Apache configuration files or `.htaccess`.
    pub fn scan_apache_config(path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => return findings,
        };

        if content.contains("mod_php") {
            findings.push(Finding {
                id: "APACHE-MOD-PHP-DETECTED".to_string(),
                cve: CveId::Php2ShellStale("CVE-2026-109619".into()),
                severity: Severity::Critical,
                target_kind: TargetKind::ApacheConfig,
                file_path: Some(path.to_path_buf()),
                line_number: None,
                detected_version_or_pattern: "mod_php Apache module enabled".to_string(),
                safe_threshold: "Migrate to PHP-FPM with isolated worker pools and updated PHP runtime >= 8.2.35".to_string(),
                description: "Apache mod_php runs PHP directly inside web server worker process memory. Stale global state from CVE-2026-109619 corrupts Apache worker memory directly across requests.".to_string(),
                suggested_remediation: "Disable mod_php, migrate to PHP-FPM with strict worker recycling and upgrade PHP runtime.".to_string(),
            });
        }

        findings
    }
}
