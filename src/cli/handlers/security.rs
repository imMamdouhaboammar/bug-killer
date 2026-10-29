use crate::catalog::SecurityCatalog;
use crate::cli::SecurityAction;
use crate::security_guard::SecurityGuard;
use crate::types::{self, ScanProfile, Severity};

pub fn handle_security(action: SecurityAction) -> i32 {
    match action {
        SecurityAction::Scan {
            path,
            profile,
            changed_only,
            staged,
            fail_on,
            osv,
            report_version,
            exit_contract,
            engine,
            json,
        } => {
            let _ = engine;
            let prof = match profile.to_lowercase().as_str() {
                "quick" => ScanProfile::Quick,
                "project" => ScanProfile::Project,
                "ci" => ScanProfile::Ci,
                "deep" => ScanProfile::Deep,
                "research" => ScanProfile::Research,
                "audit" => ScanProfile::Audit,
                _ => ScanProfile::Quick,
            };
            let report = if staged {
                match SecurityGuard::scan_staged(&path, prof) {
                    Ok(report) => report,
                    Err(error) => {
                        eprintln!("[Bug Killer] Staged scan unavailable: {error}");
                        return 3;
                    }
                }
            } else {
                SecurityGuard::scan(&path, prof, changed_only, osv)
            };

            let threshold = match fail_on.as_deref() {
                Some("high") => Severity::High,
                Some("medium") => Severity::Medium,
                Some("low") => Severity::Low,
                _ => Severity::Critical,
            };
            let has_threshold_findings = report
                .findings
                .iter()
                .any(|finding| finding.severity <= threshold);

            if report_version.as_deref() == Some("2") {
                let mut normalized_findings = Vec::new();
                let dummy_sha = "0000000000000000000000000000000000000000000000000000000000000000";
                for f in &report.findings {
                    normalized_findings.push(crate::engine::converter::to_normalized_finding(
                        f,
                        "bug-killer-guard",
                        dummy_sha,
                    ));
                }
                let v2_report = serde_json::json!({
                    "contract_version": "2.0",
                    "report_version": "2.0",
                    "workspace_root": report.workspace_root.display().to_string(),
                    "scan_time": report.scan_time,
                    "scan_profile": format!("{:?}", report.scan_profile),
                    "status": format!("{:?}", report.status),
                    "result_classification": format!("{:?}", report.result_classification),
                    "files_assessed": report.files_assessed,
                    "findings": normalized_findings,
                    "rules_evaluated_count": report.rules_evaluated.len(),
                    "applicable_rules_count": report.applicable_rules.len(),
                    "unsupported_rules_count": report.unsupported_rules.len(),
                    "coverage_complete": report.coverage.is_complete(),
                    "gate_decision": if report.is_clean() { "PASS_IN_SCOPE" } else if !report.findings.is_empty() { "FAIL_FINDINGS" } else { "BLOCKED_INCOMPLETE" }
                });
                if json {
                    println!("{}", serde_json::to_string_pretty(&v2_report).unwrap());
                } else {
                    println!("🛡️  Bug Killer Security Guard V2 Report");
                    println!("   Target: {}", report.workspace_root.display());
                    println!("   Contract: 2.0 | Profile: {:?}", report.scan_profile);
                    println!(
                        "   Gate Decision: {}",
                        v2_report["gate_decision"].as_str().unwrap()
                    );
                    println!("   Findings: {}", report.findings.len());
                    if report.is_clean() {
                        println!("✅ Workspace is verified clean within evaluated coverage.");
                    }
                }
            } else if json {
                println!("{}", serde_json::to_string_pretty(&report).unwrap());
            } else {
                println!("🛡️  Bug Killer Security Guard Scan Report");
                println!("   Target: {}", report.workspace_root.display());
                println!("   Profile: {:?}", report.scan_profile);
                println!("   Status: {:?}", report.status);
                println!("   Result: {:?}", report.result_classification);
                println!("   Files assessed: {}", report.files_assessed);
                println!(
                    "   Rules evaluated: {} | Applicable: {} | Unsupported: {}",
                    report.rules_evaluated.len(),
                    report.applicable_rules.len(),
                    report.unsupported_rules.len()
                );
                println!("   Findings detected: {}", report.findings.len());
                for (idx, f) in report.findings.iter().enumerate() {
                    println!(
                        "     {}. [{:?}] {} ({}): {}",
                        idx + 1,
                        f.severity,
                        f.cve.as_str(),
                        f.cve.title(),
                        f.description
                    );
                }
                if report.is_clean() {
                    println!("✅ Workspace is verified clean within evaluated coverage.");
                }
            }

            if exit_contract.as_deref() == Some("v2") {
                if has_threshold_findings {
                    if !json {
                        eprintln!(
                            "❌ [Exit Contract v2] Security findings meet configured threshold (code 10)."
                        );
                    }
                    10
                } else if !report.coverage.is_complete()
                    || report.files_assessed == 0
                    || report.status != types::ScanStatus::Completed
                {
                    if !json {
                        eprintln!(
                            "⚠️ [Exit Contract v2] Scan coverage is incomplete or unassessed (code 11)."
                        );
                    }
                    11
                } else {
                    0
                }
            } else if has_threshold_findings {
                if !json {
                    eprintln!("❌ Security findings meet the configured severity threshold.");
                }
                1
            } else {
                0
            }
        }

        SecurityAction::Status { path, json } => {
            let status = SecurityGuard::status(&path);
            if json {
                println!("{}", serde_json::to_string_pretty(&status).unwrap());
            } else {
                println!("🛡️  Bug Killer Security Guard Status");
                println!("   Initialized: {}", status.is_initialized);
                println!("   Project: {}", status.project_name);
                println!("   Remediation level: {:?}", status.remediation_level);
                println!(
                    "   Pre-commit gate enabled: {}",
                    status.pre_commit_gate_enabled
                );
                println!(
                    "   Agent cryptographic identity: {}",
                    if status.agent_identity_configured {
                        "configured"
                    } else {
                        "not configured"
                    }
                );
                println!("   Baseline findings: {}", status.baseline_findings_count);
            }
            0
        }

        SecurityAction::Explain {
            finding_id,
            path,
            json,
        } => match SecurityGuard::explain(&finding_id, &path) {
            Some(explanation) => {
                if json {
                    println!("{}", serde_json::to_string_pretty(&explanation).unwrap());
                } else {
                    println!("📖 Security Finding Teardown: {}", explanation.finding_id);
                    println!(
                        "   Rule: {} ({})",
                        explanation.rule_id, explanation.category
                    );
                    if let Some(ref cwe) = explanation.cwe {
                        println!("   CWE: {}", cwe);
                    }
                    println!("   Severity: {:?}", explanation.severity);
                    println!("   Description: {}", explanation.description);
                    println!("   Method: {}", explanation.detection_method);
                    println!(
                        "   Remediation Guidance: {}",
                        explanation.remediation_guidance
                    );
                    println!(
                        "   Verification Requirements: {}",
                        explanation.verification_requirements
                    );
                }
                0
            }
            None => {
                eprintln!("❌ Finding '{}' not found in workspace", finding_id);
                1
            }
        },

        SecurityAction::Fix {
            finding_id,
            path,
            plan: _plan,
            apply,
            receipt,
            json,
        } => {
            if apply {
                match SecurityGuard::plan_fix(&finding_id, &path) {
                    Ok(proposal) => {
                        match SecurityGuard::apply_fix(&proposal, &path, receipt.as_deref()) {
                            Ok(outcome) => {
                                if json {
                                    println!("{}", serde_json::to_string_pretty(&outcome).unwrap());
                                } else {
                                    println!("🛠️  Remediation Outcome for {}", outcome.finding_id);
                                    println!("   Success: {}", outcome.success);
                                    println!("   Status: {}", outcome.verification_status);
                                    println!("   Message: {}", outcome.message);
                                    if let Some(ref b) = outcome.backup_id {
                                        println!("   Backup snapshot: {}", b);
                                    }
                                }
                                if !outcome.success { 1 } else { 0 }
                            }
                            Err(e) => {
                                eprintln!("❌ Remediation application failed: {}", e);
                                1
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("❌ Failed to generate fix plan: {}", e);
                        1
                    }
                }
            } else {
                // Default to plan mode
                match SecurityGuard::plan_fix(&finding_id, &path) {
                    Ok(proposal) => {
                        if json {
                            println!("{}", serde_json::to_string_pretty(&proposal).unwrap());
                        } else {
                            println!("📋 Prospective Repair Plan for {}", proposal.finding_id);
                            println!("   Target: {}", proposal.target_file.display());
                            println!("   Required level: {:?}", proposal.required_level);
                            println!("   Explanation: {}", proposal.explanation);
                            println!("   Diff preview:\n{}", proposal.diff_preview);
                            println!(
                                "\nTo apply this fix, run:\n   bug-killer security fix {} --apply",
                                proposal.finding_id
                            );
                        }
                        0
                    }
                    Err(e) => {
                        eprintln!("❌ Failed to generate fix plan: {}", e);
                        1
                    }
                }
            }
        }

        SecurityAction::Verify { path, json } => {
            let report = SecurityGuard::scan(&path, ScanProfile::Project, false, false);
            let is_clean = report.is_clean();
            if json {
                let out = serde_json::json!({
                    "is_clean": is_clean,
                    "status": report.status,
                    "result_classification": report.result_classification,
                    "findings_count": report.findings.len(),
                    "coverage_complete": report.coverage.is_complete(),
                });
                println!("{}", serde_json::to_string_pretty(&out).unwrap());
            } else {
                println!("🔍 Bug Killer Independent Verification");
                println!("   Status: {:?}", report.status);
                println!("   Result: {:?}", report.result_classification);
                println!("   Coverage complete: {}", report.coverage.is_complete());
                println!("   Findings remaining: {}", report.findings.len());
                if is_clean {
                    println!("✅ All security properties independently verified clean.");
                } else {
                    println!(
                        "❌ Verification failed: Security properties violated or coverage incomplete."
                    );
                }
            }
            if !is_clean { 1 } else { 0 }
        }

        SecurityAction::Guidance {
            task,
            language,
            json,
        } => {
            let guidance = SecurityGuard::guidance(&task, &language);
            if json {
                println!("{}", serde_json::to_string_pretty(&guidance).unwrap());
            } else {
                println!(
                    "🧭 Pre-Generation Security Guidance for: \"{}\"",
                    guidance.task_query
                );
                println!("\n📌 Relevant Catalog Rules & Invariants:");
                for r in &guidance.relevant_rules {
                    println!(
                        "   - [{}] {}: {}",
                        r.rule_id,
                        r.cwe.as_deref().unwrap_or("No CWE"),
                        r.invariant
                    );
                }
                println!("\n✅ Recommended Safe Patterns:");
                for p in &guidance.recommended_safe_patterns {
                    println!("   + {}", p);
                }
                println!("\n🚫 Banned Anti-Patterns:");
                for a in &guidance.banned_anti_patterns {
                    println!("   - {}", a);
                }
                println!("\n🧪 Required Security Tests:");
                for t in &guidance.required_security_tests {
                    println!("   * {}", t);
                }
            }
            0
        }

        SecurityAction::Catalog {
            category,
            status,
            json,
        } => {
            let cat = SecurityCatalog::global();
            let mut rules: Vec<&crate::catalog::CatalogRule> = cat.all_rules().iter().collect();

            if let Some(c) = category {
                rules.retain(|r| r.category_number == c);
            }
            if let Some(ref s) = status {
                let s_upper = s.to_uppercase();
                rules.retain(|r| r.status.as_str() == s_upper);
            }

            if json {
                println!("{}", serde_json::to_string_pretty(&rules).unwrap());
            } else {
                println!(
                    "📚 Bug Killer Security Rule Catalog ({} rules found)",
                    rules.len()
                );
                for r in rules.iter().take(50) {
                    println!(
                        "   [{}] {:?} (Cat {}): {}",
                        r.rule_id, r.status, r.category_number, r.description
                    );
                }
                if rules.len() > 50 {
                    println!(
                        "   ... and {} more rules (use --json to see all)",
                        rules.len() - 50
                    );
                }
            }
            0
        }

        SecurityAction::Coverage {
            path,
            per_rule,
            json,
        } => {
            let report = SecurityGuard::scan(&path, ScanProfile::Quick, false, false);
            let coverage_info = serde_json::json!({
                "workspace": path.display().to_string(),
                "files_assessed": report.files_assessed,
                "coverage_complete": report.coverage.is_complete(),
                "rules_evaluated": report.rules_evaluated.len(),
                "applicable_rules": report.applicable_rules.len(),
                "unsupported_rules": report.unsupported_rules.len(),
                "unexamined_reasons": report.unexamined_reasons,
                "receipts_count": report.receipts.len(),
                "per_rule_coverage": if per_rule { serde_json::to_value(&report.rule_coverage).unwrap_or_default() } else { serde_json::Value::Null }
            });
            if json {
                println!("{}", serde_json::to_string_pretty(&coverage_info).unwrap());
            } else {
                println!("\n=======================================================");
                println!("  📊  WORKSPACE SECURITY COVERAGE REPORT");
                println!("=======================================================");
                println!("Workspace:           {}", path.display());
                println!("Files Assessed:      {}", report.files_assessed);
                println!("Coverage Complete:   {}", report.coverage.is_complete());
                println!("Rules Evaluated:     {}", report.rules_evaluated.len());
                println!("Applicable Rules:    {}", report.applicable_rules.len());
                println!("Unsupported Rules:   {}", report.unsupported_rules.len());
                if per_rule {
                    println!(
                        "\nPer-Rule Coverage Status ({} rules):",
                        report.rule_coverage.len()
                    );
                    for (rule_id, status) in report.rule_coverage.iter().take(25) {
                        println!("  • {:<20} -> {:?}", rule_id, status);
                    }
                    if report.rule_coverage.len() > 25 {
                        println!(
                            "  ... and {} more rules (use --json to see all)",
                            report.rule_coverage.len() - 25
                        );
                    }
                }
            }
            0
        }
    }
}
