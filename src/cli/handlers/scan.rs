use crate::cli::compute_scan_exit_code;
use crate::dast::{DastProber, DastScopeConfig};
use crate::osv::OsvClient;
use crate::rules::RuleEngine;
use crate::scanner::FleetScanner;
use crate::types::{self, Severity};
use std::path::PathBuf;

pub fn handle_scan(
    path: PathBuf,
    json: bool,
    check_runtime: bool,
    rules: Option<PathBuf>,
    osv: bool,
    taint: bool,
) -> i32 {
    let active_rules = RuleEngine::load_rules(rules.as_deref(), &path);
    let mut report = FleetScanner::scan_directory_with_rules_and_taint(
        &path,
        check_runtime,
        &active_rules,
        taint,
    );

    if osv {
        let osv_client = OsvClient::new();
        let (osv_findings, osv_receipt) = osv_client.scan_workspace_with_receipt(&path);
        if osv_receipt.status != types::CoverageStatus::Complete {
            report.coverage.coverage_status = types::CoverageStatus::Partial;
        }
        report.coverage.receipts.push(osv_receipt);
        for f in osv_findings {
            if !report.findings.iter().any(|existing| existing.id == f.id) {
                if f.severity == Severity::Critical {
                    report.critical_count += 1;
                } else if f.severity == Severity::High {
                    report.high_count += 1;
                }
                report.findings.push(f);
            }
        }
        report.is_vulnerable = !report.findings.is_empty();
    }

    if json {
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
        return compute_scan_exit_code(&report);
    }

    println!("\n=======================================================");
    println!("  🎯  BUG KILLER: DEEP VULNERABILITY AUDIT REPORT");
    println!("=======================================================");
    println!("Target:               {}", report.target_dir.display());
    println!("Timestamp:            {}", report.scan_time);
    println!("Total Files Audited:  {}", report.total_files_scanned);
    println!("Active Dynamic Rules: {}", active_rules.len());
    println!(
        "OSV.dev Integration:  {}",
        if osv {
            "ENABLED (Live Query)"
        } else {
            "DISABLED (Use --osv to enable)"
        }
    );
    println!(
        "Taint Analysis:       {}",
        if taint {
            "ENABLED (AST Dataflow)"
        } else {
            "DISABLED (Use --taint to enable)"
        }
    );
    println!(
        "Audit Status:         {}",
        if report.is_vulnerable {
            "EXPOSED ⚠️"
        } else if !report.is_clean() {
            "PARTIAL / INCOMPLETE ⚠️"
        } else {
            "CLEAN ✅"
        }
    );
    println!(
        "Coverage Status:      {:?}",
        report.coverage.coverage_status
    );
    println!("Files Audited:        {}", report.total_files_scanned);
    println!("Files Excluded:       {}", report.coverage.files_excluded);
    if !report.coverage.parser_failures.is_empty() {
        println!(
            "Parser/I/O Failures:  {}",
            report.coverage.parser_failures.len()
        );
    }
    println!("Critical:             {}", report.critical_count);
    println!("High:                 {}", report.high_count);
    println!("-------------------------------------------------------\n");

    if !report.coverage.parser_failures.is_empty() {
        println!("⚠️  Scanner encountered the following parser/read failures:");
        for failure in &report.coverage.parser_failures {
            println!("   • {}: {}", failure.path.display(), failure.reason);
        }
        println!();
    }

    if report.findings.is_empty() {
        if report.is_clean() {
            println!(
                "✅ Zero exposures or vulnerability violations detected across full coverage."
            );
        } else {
            println!(
                "⚠️ Zero exposures detected in audited files, but scan coverage was PARTIAL / INCOMPLETE."
            );
        }
        return compute_scan_exit_code(&report);
    }

    for (idx, finding) in report.findings.iter().enumerate() {
        let sev_badge = match finding.severity {
            Severity::Critical => "[CRITICAL]",
            Severity::High => "[HIGH]",
            Severity::Medium => "[MEDIUM]",
            Severity::Low => "[LOW]",
        };

        println!(
            "{}. {} {} - {}",
            idx + 1,
            sev_badge,
            finding.cve.as_str(),
            finding.cve.title()
        );
        if let Some(ref p) = finding.file_path {
            let line_str = finding
                .line_number
                .map(|l| format!(":{}", l))
                .unwrap_or_default();
            println!("   Location:     {}{}", p.display(), line_str);
        }
        println!("   Affectedness: {}", finding.affectedness.as_str());
        println!("   Reachability: {}", finding.reachability.as_str());
        println!("   Confidence:   {}", finding.confidence.as_str());
        println!("   Pattern:      {}", finding.detected_version_or_pattern);
        println!("   Threshold:    {}", finding.safe_threshold);
        if !finding.uncertainty_reasons.is_empty() {
            println!(
                "   Uncertainty:  {}",
                finding.uncertainty_reasons.join("; ")
            );
        }
        if !finding.missing_checks.is_empty() {
            println!("   Missing:      {}", finding.missing_checks.join(", "));
        }
        println!("   Details:      {}", finding.description);
        println!("   Remediation:  {}\n", finding.suggested_remediation);
    }

    println!(
        "Run 'bug-killer heal {} --dry-run{}' to preview automated remediation.",
        path.display(),
        if osv { " --osv" } else { "" }
    );

    compute_scan_exit_code(&report)
}

pub fn handle_osv(path: PathBuf, json: bool) -> i32 {
    println!("🔍 Querying open-source vulnerability database (https://osv.dev)...");
    let osv_client = OsvClient::new();
    let (findings, receipt) = osv_client.scan_workspace_with_receipt(&path);

    if json {
        let output = serde_json::json!({
            "findings": findings,
            "receipt": receipt
        });
        println!("{}", serde_json::to_string_pretty(&output).unwrap());
        return 0;
    }

    println!("\n=======================================================");
    println!("  🌐  OSV.DEV OPEN VULNERABILITY AUDIT REPORT");
    println!("=======================================================");
    println!("Target Workspace:     {}", path.display());
    println!("Data Source:          https://osv.dev (Google / OpenSSF)");
    println!("Coverage Status:      {:?}", receipt.status);
    println!("Packages Examined:    {}", receipt.items_examined);
    println!("Total Advisories:     {}\n", findings.len());

    if !receipt.skipped_reasons.is_empty() {
        println!("ℹ️  Skipped constraints (require lockfile for exact CVE lookup):");
        for r in &receipt.skipped_reasons {
            println!("   • {}", r);
        }
        println!();
    }

    if !receipt.errors.is_empty() {
        println!("⚠️  OSV API lookup errors:");
        for e in &receipt.errors {
            println!("   • {}", e);
        }
        println!();
    }

    if findings.is_empty() {
        if receipt.status == types::CoverageStatus::Complete {
            println!("✅ Zero known open-source vulnerabilities reported by OSV.dev.");
        } else {
            println!(
                "⚠️  Zero findings reported, but coverage is incomplete ({:?}).",
                receipt.status
            );
        }
        return 0;
    }

    for (idx, finding) in findings.iter().enumerate() {
        let sev_badge = match finding.severity {
            Severity::Critical => "[CRITICAL]",
            Severity::High => "[HIGH]",
            Severity::Medium => "[MEDIUM]",
            Severity::Low => "[LOW]",
        };

        println!(
            "{}. {} {} - {}",
            idx + 1,
            sev_badge,
            finding.cve.as_str(),
            finding.cve.title()
        );
        if let Some(ref p) = finding.file_path {
            println!("   Manifest:    {}", p.display());
        }
        println!("   Package:     {}", finding.detected_version_or_pattern);
        println!("   Threshold:   {}", finding.safe_threshold);
        println!("   Remediation: {}\n", finding.suggested_remediation);
    }

    println!(
        "Run 'bug-killer heal {} --osv' to automatically upgrade vulnerable packages.",
        path.display()
    );
    0
}

pub fn handle_probe(
    url: String,
    json: bool,
    timeout: u64,
    sensitive_paths: bool,
    authorized: bool,
    allow_private_targets: bool,
) -> i32 {
    let config = DastScopeConfig {
        authorized,
        allow_private_targets,
        allow_sensitive_paths: sensitive_paths,
        timeout_seconds: timeout,
        max_response_bytes: 1024 * 1024,
    };
    match DastProber::probe_with_config(&url, &config) {
        Ok(report) => {
            if json {
                println!("{}", serde_json::to_string_pretty(&report).unwrap());
                return 0;
            }

            println!("\n=======================================================");
            println!("  🛡️  BUG KILLER: DEFENSIVE DAST PROBE REPORT");
            println!("=======================================================");
            println!("Target URL:           {}", report.target_url);
            println!("Timestamp:            {}", report.probe_time);
            println!("Status Code:          HTTP {}", report.status_code);
            println!("Duration:             {}ms", report.duration_ms);
            println!("Headers Audited:      {}", report.headers_checked);
            println!("Endpoints Audited:    {}", report.endpoints_audited);
            println!(
                "Vulnerabilities:      {}",
                if report.is_vulnerable {
                    "EXPOSED ⚠️"
                } else {
                    "HARDENED ✅"
                }
            );
            println!("Critical:             {}", report.critical_count);
            println!("High:                 {}", report.high_count);
            println!("-------------------------------------------------------\n");

            if report.findings.is_empty() {
                println!("✅ All inspected security headers and defensive endpoints are hardened.");
                return 0;
            }

            for (idx, finding) in report.findings.iter().enumerate() {
                let sev_badge = match finding.severity {
                    Severity::Critical => "[CRITICAL]",
                    Severity::High => "[HIGH]",
                    Severity::Medium => "[MEDIUM]",
                    Severity::Low => "[LOW]",
                };

                println!(
                    "{}. {} {} - {}",
                    idx + 1,
                    sev_badge,
                    finding.id,
                    finding.title
                );
                println!("   Target:      {}", finding.target_url);
                println!("   Evidence:    {}", finding.evidence);
                println!("   Remediation: {}\n", finding.remediation);
            }
            0
        }
        Err(e) => {
            eprintln!("❌ DAST Probe Error: {}", e);
            1
        }
    }
}

pub fn handle_cve_info(cve_id: String) -> i32 {
    let norm = cve_id.trim().to_uppercase();
    if norm.contains("109618") {
        println!("\n=== CVE-2026-109618: PHP2Shell (Out-of-Memory Heap Corruption) ===");
        println!("CVSS: 9.2 (Critical) | Vector: Remote Code Execution (RCE)");
        println!("Root Cause: PHP runtime uses longjmp() on OOM errors to abort requests.");
        println!(
            "In certain SAPI contexts, request memory is left uninitialized prior to allocation."
        );
        println!(
            "Subsequent cleanups evaluate uninitialized heap structures, yielding reliable RCE."
        );
        println!("Fixed Releases: PHP 8.2.35+, 8.3.36+, 8.4.27+, 8.5.12+ (All <= 8.1 are EOL)");
    } else if norm.contains("109619") {
        println!("\n=== CVE-2026-109619: PHP2Shell (Stale Global State / Use-After-Free) ===");
        println!("CVSS: 9.8 (Critical) | Vector: Remote Code Execution (RCE)");
        println!(
            "Root Cause: Global state variables pointing into request memory fail to reset properly"
        );
        println!(
            "under error-handling conditions. The memory is freed but globals retain stale references."
        );
        println!("Consecutive requests reuse stale heap pointers leading to UAF code execution.");
        println!("Fixed Releases: PHP 8.2.35+, 8.3.36+, 8.4.27+, 8.5.12+ (All <= 8.1 are EOL)");
    } else if norm.contains("111497") {
        println!(
            "\n=== CVE-2026-111497: Node2Shell (Bundled Brotli Decoder Out-of-Bounds Write) ==="
        );
        println!("CVSS: 8.8 (High/Critical) | Vector: Memory Corruption / RCE");
        println!(
            "Root Cause: Missing bounds check in Google reference Brotli library (v1.0.3 - 1.2.0)"
        );
        println!("statically linked inside Node.js native runtime (node:zlib).");
        println!(
            "Attack Vector: Malformed Brotli payload sent via HTTP 'Content-Encoding: br' or fetch()."
        );
        println!("Fixed Releases: Node.js v22.23.4+, v24.22.1+, v26.12.1+ (Node <= 20 is EOL)");
    } else {
        println!("Unknown CVE ID. Supported: CVE-2026-109618, CVE-2026-109619, CVE-2026-111497");
    }
    0
}

pub fn handle_evidence(finding_id: String, path: PathBuf, json: bool) -> i32 {
    let scan_report = FleetScanner::scan_directory(&path, true);
    let target_finding = scan_report
        .findings
        .iter()
        .find(|f| f.id == finding_id || f.dedupe_fingerprint.starts_with(&finding_id));
    if let Some(f) = target_finding {
        if json {
            println!("{}", serde_json::to_string_pretty(f).unwrap());
            return 0;
        }
        println!("\n=== EVIDENCE RECORD FOR FINDING {} ===", f.id);
        println!("CVE:               {}", f.cve.as_str());
        println!("Severity:          {:?}", f.severity);
        println!("Affectedness:      {}", f.affectedness.as_str());
        println!("Reachability:      {}", f.reachability.as_str());
        println!("Confidence:        {}", f.confidence.as_str());
        println!("Target Kind:       {:?}", f.target_kind);
        println!(
            "Target File:       {}",
            f.file_path
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "none".into())
        );
        println!("Pattern/Version:   {}", f.detected_version_or_pattern);
        println!("Dedupe Hash:       {}", f.dedupe_fingerprint);
        println!("Supported Checks:  {:?}", f.supported_checks);
        println!("Missing Checks:    {:?}", f.missing_checks);
        println!("Uncertainty:       {:?}\n", f.uncertainty_reasons);
        0
    } else {
        eprintln!("Finding '{}' not found in workspace scan.", finding_id);
        1
    }
}
