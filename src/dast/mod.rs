use crate::types::Severity;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DastCategory {
    SecurityHeaders,
    InformationDisclosure,
    CookieSecurity,
    SensitiveEndpointExposure,
    ErrorHandling,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DastFinding {
    pub id: String,
    pub title: String,
    pub severity: Severity,
    pub category: DastCategory,
    pub target_url: String,
    pub evidence: String,
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DastReport {
    pub target_url: String,
    pub probe_time: String,
    pub duration_ms: u64,
    pub status_code: u16,
    pub findings: Vec<DastFinding>,
    pub is_vulnerable: bool,
    pub critical_count: usize,
    pub high_count: usize,
    pub headers_checked: usize,
    pub endpoints_audited: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DastScopeConfig {
    pub allow_sensitive_paths: bool,
    pub timeout_seconds: u64,
    pub max_response_bytes: usize,
}

impl Default for DastScopeConfig {
    fn default() -> Self {
        Self {
            allow_sensitive_paths: false,
            timeout_seconds: 10,
            max_response_bytes: 1024 * 1024,
        }
    }
}

/// Validates target destination against scope rules, unsupported schemes, userinfo credentials, and metadata IPs.
pub fn validate_target_url(raw_url: &str) -> Result<String, String> {
    let trimmed = raw_url.trim();
    if !trimmed.starts_with("http://") && !trimmed.starts_with("https://") {
        return Err(format!(
            "Unsupported Scheme: Only http:// and https:// protocols are permitted for defensive DAST. Got: {}",
            trimmed
        ));
    }

    let rest = if let Some(stripped) = trimmed.strip_prefix("https://") {
        stripped
    } else if let Some(stripped) = trimmed.strip_prefix("http://") {
        stripped
    } else {
        return Err("Unsupported Scheme: Missing protocol prefix".into());
    };

    // Find authority boundary (before '/', '?', '#')
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];

    // Check for userinfo (embedded credentials like user:pass@)
    if authority.contains('@') {
        return Err(
            "Prohibited Credentials: Embedded userinfo credentials in target URL are prohibited."
                .into(),
        );
    }

    // Extract host (handle IPv6 like [::1]:8080 or host:8080)
    let host = if authority.starts_with('[') {
        if let Some(close_bracket) = authority.find(']') {
            &authority[1..close_bracket]
        } else {
            return Err("Malformed IPv6 host in target URL".into());
        }
    } else if let Some(colon) = authority.find(':') {
        &authority[..colon]
    } else {
        authority
    };

    let host_lower = host.to_lowercase();

    // Check prohibited cloud metadata / link-local hostnames
    if host_lower == "metadata.google.internal"
        || host_lower == "instance-data"
        || host_lower == "metadata"
    {
        return Err("Scope Violation: Prohibited Destination - Cloud metadata service hostnames are prohibited from DAST probing.".into());
    }

    // Check prohibited cloud metadata / link-local IPs
    if host_lower == "169.254.169.254"
        || host_lower == "169.254.169.253"
        || host_lower == "169.254.170.2"
    {
        return Err("Scope Violation: Prohibited Destination - Cloud metadata service IPs (169.254.x.x) are prohibited from DAST probing.".into());
    }

    // Check if host is IPv4
    if let Ok(ipv4) = host.parse::<std::net::Ipv4Addr>() {
        if ipv4.is_link_local() {
            return Err("Scope Violation: Prohibited Destination - IPv4 link-local addresses (169.254.0.0/16) are prohibited.".into());
        }
    }

    // Check if host is IPv6
    if let Ok(ipv6) = host.parse::<std::net::Ipv6Addr>() {
        if ipv6.is_unicast_link_local() {
            return Err("Scope Violation: Prohibited Destination - IPv6 link-local addresses are prohibited.".into());
        }
    }

    Ok(trimmed.trim_end_matches('/').to_string())
}

pub struct DastProber;

impl DastProber {
    /// Defensively audits a live endpoint using safe default scope (sensitive paths disabled).
    #[allow(dead_code)]
    pub fn probe(base_url: &str, timeout_secs: u64) -> Result<DastReport, String> {
        let config = DastScopeConfig {
            allow_sensitive_paths: false,
            timeout_seconds: timeout_secs,
            max_response_bytes: 1024 * 1024,
        };
        Self::probe_with_config(base_url, &config)
    }

    /// Defensively audits a live endpoint with explicit scope configuration.
    pub fn probe_with_config(
        base_url: &str,
        config: &DastScopeConfig,
    ) -> Result<DastReport, String> {
        let start = Instant::now();
        let normalized_url = validate_target_url(base_url)?;

        let ureq_config = ureq::config::Config::builder()
            .timeout_global(Some(Duration::from_secs(config.timeout_seconds)))
            .build();
        let agent = ureq_config.new_agent();

        // 1. Audit root endpoint
        let root_resp = agent
            .get(&normalized_url)
            .call()
            .map_err(|e| format!("Failed to reach target URL {}: {}", normalized_url, e))?;

        let status_code = root_resp.status().as_u16();
        let mut findings = Vec::new();
        let mut headers_checked = 0;

        // Collect headers
        let headers: Vec<(String, String)> = root_resp
            .headers()
            .iter()
            .map(|(k, v)| {
                (
                    k.as_str().to_lowercase(),
                    v.to_str().unwrap_or_default().to_string(),
                )
            })
            .collect();

        let header_map: std::collections::HashMap<String, String> = headers.into_iter().collect();

        let content_type = header_map
            .get("content-type")
            .cloned()
            .unwrap_or_default()
            .to_lowercase();
        let is_html = content_type.is_empty() || content_type.contains("text/html");
        let csp_val = header_map
            .get("content-security-policy")
            .map(|s| s.as_str())
            .unwrap_or("");
        let csp_has_frame_ancestors = csp_val.contains("frame-ancestors");

        // 2. Audit Security Headers
        // A. Content-Security-Policy
        headers_checked += 1;
        if let Some(csp) = header_map.get("content-security-policy") {
            if csp.contains("unsafe-inline") || csp.contains("unsafe-eval") {
                findings.push(DastFinding {
                    id: "DAST-HDR-CSP-WEAK".into(),
                    title: "Permissive Content-Security-Policy (Unsafe Directives)".into(),
                    severity: Severity::Medium,
                    category: DastCategory::SecurityHeaders,
                    target_url: normalized_url.clone(),
                    evidence: format!("CSP contains unsafe directive: {}", csp),
                    remediation: "Remove 'unsafe-inline' and 'unsafe-eval' from CSP. Use nonces or SHA-256 hashes for authorized scripts.".into(),
                });
            }
        } else if is_html {
            findings.push(DastFinding {
                id: "DAST-HDR-CSP-MISSING".into(),
                title: "Missing Content-Security-Policy (CSP) Header".into(),
                severity: Severity::High,
                category: DastCategory::SecurityHeaders,
                target_url: normalized_url.clone(),
                evidence: "Content-Security-Policy header is absent from HTML server response".into(),
                remediation: "Configure Content-Security-Policy (e.g. default-src 'self') in reverse proxy or web application.".into(),
            });
        }

        // B. Strict-Transport-Security (HSTS) on HTTPS
        headers_checked += 1;
        if normalized_url.starts_with("https://")
            && !header_map.contains_key("strict-transport-security")
        {
            findings.push(DastFinding {
                id: "DAST-HDR-HSTS-MISSING".into(),
                title: "Missing Strict-Transport-Security (HSTS) Header".into(),
                severity: Severity::High,
                category: DastCategory::SecurityHeaders,
                target_url: normalized_url.clone(),
                evidence: "HSTS header absent on HTTPS connection".into(),
                remediation: "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to enforce TLS.".into(),
            });
        }

        // C. X-Content-Type-Options
        headers_checked += 1;
        match header_map.get("x-content-type-options") {
            Some(v) if v.to_lowercase() == "nosniff" => {}
            Some(v) => {
                findings.push(DastFinding {
                    id: "DAST-HDR-CTO-INVALID".into(),
                    title: "Invalid X-Content-Type-Options Header".into(),
                    severity: Severity::Low,
                    category: DastCategory::SecurityHeaders,
                    target_url: normalized_url.clone(),
                    evidence: format!("Expected 'nosniff', found: {}", v),
                    remediation: "Set 'X-Content-Type-Options: nosniff'.".into(),
                });
            }
            None => {
                findings.push(DastFinding {
                    id: "DAST-HDR-CTO-MISSING".into(),
                    title: "Missing X-Content-Type-Options Header".into(),
                    severity: Severity::Low,
                    category: DastCategory::SecurityHeaders,
                    target_url: normalized_url.clone(),
                    evidence: "X-Content-Type-Options header is absent".into(),
                    remediation: "Set 'X-Content-Type-Options: nosniff' to prevent MIME type sniffing attacks.".into(),
                });
            }
        }

        // D. X-Frame-Options
        headers_checked += 1;
        if csp_has_frame_ancestors || !is_html {
            // Frame protections already handled by CSP frame-ancestors or response is non-HTML API.
        } else if let Some(xfo) = header_map.get("x-frame-options") {
            let upper = xfo.to_uppercase();
            if upper != "DENY" && upper != "SAMEORIGIN" {
                findings.push(DastFinding {
                    id: "DAST-HDR-XFO-WEAK".into(),
                    title: "Permissive X-Frame-Options Header".into(),
                    severity: Severity::Medium,
                    category: DastCategory::SecurityHeaders,
                    target_url: normalized_url.clone(),
                    evidence: format!("Found X-Frame-Options: {}", xfo),
                    remediation: "Set 'X-Frame-Options: DENY' or 'SAMEORIGIN' to mitigate clickjacking attacks.".into(),
                });
            }
        } else {
            findings.push(DastFinding {
                id: "DAST-HDR-XFO-MISSING".into(),
                title: "Missing X-Frame-Options Header".into(),
                severity: Severity::Medium,
                category: DastCategory::SecurityHeaders,
                target_url: normalized_url.clone(),
                evidence: "X-Frame-Options header is absent".into(),
                remediation: "Configure 'X-Frame-Options: SAMEORIGIN' to prevent framing by unauthorized origins.".into(),
            });
        }

        // E. Information Disclosure (Server & X-Powered-By)
        headers_checked += 1;
        if let Some(xpb) = header_map.get("x-powered-by") {
            findings.push(DastFinding {
                id: "DAST-LEAK-X-POWERED-BY".into(),
                title: "Server Technology Disclosure via X-Powered-By".into(),
                severity: Severity::Low,
                category: DastCategory::InformationDisclosure,
                target_url: normalized_url.clone(),
                evidence: format!("X-Powered-By: {}", xpb),
                remediation:
                    "Disable or strip X-Powered-By headers in web server or application config."
                        .into(),
            });
        }

        if let Some(srv) = header_map.get("server") {
            if srv.chars().any(|c| c.is_ascii_digit()) {
                findings.push(DastFinding {
                    id: "DAST-LEAK-SERVER-VERSION".into(),
                    title: "Exact Server Version Banner Disclosure".into(),
                    severity: Severity::Low,
                    category: DastCategory::InformationDisclosure,
                    target_url: normalized_url.clone(),
                    evidence: format!("Server: {}", srv),
                    remediation: "Configure server_tokens off (Nginx) or ServerTokens Prod (Apache) to hide banner versions.".into(),
                });
            }
        }

        // 3. Audit Cookie Flags
        if let Some(cookies) = header_map.get("set-cookie") {
            let lower = cookies.to_lowercase();
            if !lower.contains("httponly") {
                findings.push(DastFinding {
                    id: "DAST-COOKIE-NO-HTTPONLY".into(),
                    title: "Cookie Missing HttpOnly Flag".into(),
                    severity: Severity::Medium,
                    category: DastCategory::CookieSecurity,
                    target_url: normalized_url.clone(),
                    evidence: format!("Set-Cookie directive lacks HttpOnly: {}", cookies),
                    remediation: "Set HttpOnly flag on session cookies to block client-side JavaScript access.".into(),
                });
            }
            if normalized_url.starts_with("https://") && !lower.contains("secure") {
                findings.push(DastFinding {
                    id: "DAST-COOKIE-NO-SECURE".into(),
                    title: "Cookie Missing Secure Flag over HTTPS".into(),
                    severity: Severity::Medium,
                    category: DastCategory::CookieSecurity,
                    target_url: normalized_url.clone(),
                    evidence: format!("Set-Cookie directive lacks Secure: {}", cookies),
                    remediation: "Set Secure attribute on all cookies transmitted over TLS.".into(),
                });
            }
            if !lower.contains("samesite") {
                findings.push(DastFinding {
                    id: "DAST-COOKIE-NO-SAMESITE".into(),
                    title: "Cookie Missing SameSite Protection".into(),
                    severity: Severity::Low,
                    category: DastCategory::CookieSecurity,
                    target_url: normalized_url.clone(),
                    evidence: format!("Set-Cookie directive lacks SameSite: {}", cookies),
                    remediation: "Set SameSite=Lax or SameSite=Strict to defend against Cross-Site Request Forgery (CSRF).".into(),
                });
            }
        }

        // 4. Defensive Sensitive Endpoint Exposure Probing (GET without mutation, strictly gated)
        let mut endpoints_audited = 1;

        if config.allow_sensitive_paths {
            let sensitive_paths = [
                (
                    "/.env",
                    Severity::Critical,
                    "Environment configuration file exposed containing secrets",
                    "Block access to hidden and dotfiles in web server rules.",
                ),
                (
                    "/.git/HEAD",
                    Severity::Critical,
                    "Git repository metadata exposed to public internet",
                    "Deny access to /.git/ directories in reverse proxy.",
                ),
                (
                    "/actuator/health",
                    Severity::Medium,
                    "Spring Boot actuator endpoint exposed publicly",
                    "Restrict actuator management endpoints to internal network.",
                ),
                (
                    "/swagger.json",
                    Severity::Low,
                    "Swagger API schema exposed without authentication",
                    "Authenticate API documentation endpoints or restrict in production.",
                ),
            ];

            for (path, sev, desc, rem) in sensitive_paths {
                endpoints_audited += 1;
                let target = format!("{}{}", normalized_url, path);
                if let Ok(resp) = agent.get(&target).call() {
                    if resp.status().as_u16() == 200 {
                        let clean_id = path
                            .trim_start_matches('/')
                            .trim_start_matches('.')
                            .replace(['.', '/'], "-")
                            .to_uppercase();
                        findings.push(DastFinding {
                            id: format!("DAST-EXPOSURE-{}", clean_id),
                            title: format!("Exposed Sensitive Endpoint ({})", path),
                            severity: sev,
                            category: DastCategory::SensitiveEndpointExposure,
                            target_url: target,
                            evidence: format!("HTTP 200 OK returned on sensitive path: {}", desc),
                            remediation: rem.to_string(),
                        });
                    }
                }
            }
        }

        let duration_ms = start.elapsed().as_millis() as u64;
        let critical_count = findings
            .iter()
            .filter(|f| f.severity == Severity::Critical)
            .count();
        let high_count = findings
            .iter()
            .filter(|f| f.severity == Severity::High)
            .count();
        let is_vulnerable = !findings.is_empty();

        Ok(DastReport {
            target_url: normalized_url,
            probe_time: Utc::now().to_rfc3339(),
            duration_ms,
            status_code,
            findings,
            is_vulnerable,
            critical_count,
            high_count,
            headers_checked,
            endpoints_audited,
        })
    }
}
