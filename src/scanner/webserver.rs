use crate::types::*;
use std::fs;
use std::path::Path;

pub struct WebServerScanner;

impl WebServerScanner {
    /// Scans Nginx configuration files for missing Brotli request body filtering or PHP-FPM proxying.
    pub fn scan_nginx_config(path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => return findings,
        };

        let has_virtual_patch = content.contains("BUG KILLER VIRTUAL PATCH (CVE-2026-111497")
            || content.contains("AEGIS VIRTUAL PATCH (CVE-2026-111497");
        let has_brotli_filter =
            content.contains("$http_content_encoding") && content.contains("br");
        let proxies_to_node_or_upstream = content.contains("proxy_pass");
        let proxies_to_php = content.contains("fastcgi_pass") || content.contains("php");

        if proxies_to_node_or_upstream && !has_brotli_filter && !has_virtual_patch {
            let mut finding = Finding::new(
                "NGINX-NODE-MISSING-BROTLI-FILTER",
                CveId::Node2ShellBrotli("CVE-2026-111497".into()),
                Severity::High,
                TargetKind::NginxConfig,
                Some(path.to_path_buf()),
                None,
                "proxy_pass configured without request body Content-Encoding: br filter",
                "Inject Bug Killer Nginx virtual patch blocking uninspected 'Content-Encoding: br'",
                "Nginx reverse proxy passes client request bodies directly to upstream without checking for Brotli encoding, allowing CVE-2026-111497 exploit payloads to reach Node.js decoder.",
                "Apply Bug Killer Nginx virtual patch to return 415 on Brotli-compressed request bodies.",
            );
            finding.detector_id = "nginx-proxy".to_string();
            finding.affectedness = Affectedness::PotentiallyAffected;
            finding.reachability = Reachability::PotentiallyReachable;
            finding.confidence = Confidence::Medium;
            finding.compute_dedupe_fingerprint();
            findings.push(finding);
        }

        if proxies_to_php && !content.contains("fastcgi_buffer_size") {
            let mut finding = Finding::new(
                "NGINX-PHP-UNBOUNDED-BUFFERS",
                CveId::Php2ShellOom("CVE-2026-109618".into()),
                Severity::Medium,
                TargetKind::NginxConfig,
                Some(path.to_path_buf()),
                None,
                "fastcgi_pass without bounded buffer size configuration",
                "Explicit fastcgi_buffer_size 128k; fastcgi_buffers 4 256k;",
                "FastCGI pass lacks explicit buffer boundaries, facilitating memory exhaustion attacks against PHP-FPM pools.",
                "Harden Nginx FastCGI buffer parameters.",
            );
            finding.detector_id = "nginx-fastcgi".to_string();
            finding.affectedness = Affectedness::PotentiallyAffected;
            finding.reachability = Reachability::PotentiallyReachable;
            finding.confidence = Confidence::Medium;
            finding.compute_dedupe_fingerprint();
            findings.push(finding);
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
            let mut finding = Finding::new(
                "APACHE-MOD-PHP-DETECTED",
                CveId::Php2ShellStale("CVE-2026-109619".into()),
                Severity::Critical,
                TargetKind::ApacheConfig,
                Some(path.to_path_buf()),
                None,
                "mod_php Apache module enabled",
                "Migrate to PHP-FPM with isolated worker pools and updated PHP runtime >= 8.2.35",
                "Apache mod_php runs PHP directly inside web server worker process memory. Stale global state from CVE-2026-109619 corrupts Apache worker memory directly across requests.",
                "Disable mod_php, migrate to PHP-FPM with strict worker recycling and upgrade PHP runtime.",
            );
            finding.detector_id = "apache-mod-php".to_string();
            finding.affectedness = Affectedness::ConfirmedAffected;
            finding.reachability = Reachability::ConfirmedReachable;
            finding.confidence = Confidence::High;
            finding.compute_dedupe_fingerprint();
            findings.push(finding);
        }

        findings
    }
}
