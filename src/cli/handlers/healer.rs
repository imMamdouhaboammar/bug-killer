use crate::healer::AutopilotHealer;
use crate::healer::approval::ApprovalManager;
use crate::healer::backup::BackupManager;
use crate::healer::rollback::RollbackManager;
use crate::identity::OperatorIdentity;
use crate::osv::OsvClient;
use crate::rules::RuleEngine;
use crate::scanner::FleetScanner;
use crate::types;
use std::path::PathBuf;

pub fn handle_heal(
    path: PathBuf,
    dry_run: bool,
    apply: bool,
    auto_apply: bool,
    rules: Option<PathBuf>,
    osv: bool,
    allow_untrusted_rules: bool,
) -> i32 {
    if apply || auto_apply {
        eprintln!(
            "Independent operator approval is required; heal --apply/--auto-apply cannot bypass signed approval. Use 'approve' and 'apply'."
        );
        return 4;
    }
    let active_rules = RuleEngine::load_rules(rules.as_deref(), &path);
    let mut report = FleetScanner::scan_directory_with_rules(&path, false, &active_rules);

    if osv {
        let osv_client = OsvClient::new();
        let osv_findings = osv_client.scan_workspace(&path);
        for f in osv_findings {
            if !report.findings.iter().any(|existing| existing.id == f.id) {
                report.findings.push(f);
            }
        }
    }

    let plan = AutopilotHealer::plan_healing_with_rules_and_approval(
        &report,
        &active_rules,
        allow_untrusted_rules,
    );

    println!("\n=======================================================");
    println!("  🎯  BUG KILLER: AUTOPILOT HEALER");
    println!("=======================================================");
    println!("Target:               {}", path.display());
    println!("Active Dynamic Rules: {}", active_rules.len());
    println!(
        "OSV.dev Integration:  {}",
        if osv { "ENABLED" } else { "DISABLED" }
    );
    println!("Vulnerable Findings:  {}", report.findings.len());
    println!("Planned Patches:      {}", plan.len());
    println!(
        "Execution Mode:       {}",
        if dry_run || (!apply && !auto_apply) {
            "PLAN-ONLY (Zero filesystem mutations)"
        } else {
            "AUTHORIZED APPLY (Modifying files with cryptographic backup)"
        }
    );
    println!("-------------------------------------------------------\n");

    if plan.is_empty() {
        println!("ℹ️ No automated file patches applicable or all files already patched.");
        return 0;
    }

    for (idx, action) in plan.iter().enumerate() {
        println!("{}. Action:  {:?}", idx + 1, action.action_type);
        println!("   Target:  {}", action.target_file.display());
        println!("   Diff:    {}", action.diff_description);
        println!("   SHA256:  {}\n", action.original_checksum);
    }

    if dry_run || (!apply && !auto_apply) {
        println!(
            "🔒 Plan-Only Default: No filesystem mutations applied without explicit operator flag."
        );
        println!("To apply these changes with cryptographic non-repudiation:");
        println!("  bug-killer approve <finding-id> {}", path.display());
        return 0;
    }

    eprintln!("Independent operator approval is required. Use 'approve' and 'apply'.");
    4
}

pub fn handle_rollback(backup_id: String, path: PathBuf) -> i32 {
    println!(
        "Attempting cryptographic rollback for snapshot '{}'...",
        backup_id
    );
    match RollbackManager::rollback(&path, &backup_id) {
        Ok(count) => {
            println!(
                "✅ Successfully rolled back {} files from backup snapshot {}.",
                count, backup_id
            );
            0
        }
        Err(e) => {
            eprintln!("❌ Rollback failed: {}", e);
            1
        }
    }
}

pub fn handle_history(path: PathBuf) -> i32 {
    let backups = BackupManager::list_backups(&path);
    println!("\n=======================================================");
    println!("  📜  BUG KILLER: BACKUP SNAPSHOT HISTORY");
    println!("=======================================================");
    if backups.is_empty() {
        println!("Zero backup snapshots recorded in .aegis/backups/");
        return 0;
    }

    for b in backups {
        println!("Snapshot ID:  {}", b.backup_id);
        println!("Created At:   {}", b.created_at);
        println!("Files Backed: {}", b.records.len());
        for r in b.records {
            let hash_prefix = if r.original_sha256.len() >= 12 {
                &r.original_sha256[..12]
            } else {
                &r.original_sha256
            };
            println!("  - {} (SHA256: {})", r.relative_target_path, hash_prefix);
        }
        println!("-------------------------------------------------------");
    }
    0
}

pub fn handle_plan(finding_id: String, path: PathBuf, json: bool) -> i32 {
    let scan_report = FleetScanner::scan_directory(&path, true);
    let target_finding = scan_report
        .findings
        .iter()
        .find(|f| f.id == finding_id || f.dedupe_fingerprint.starts_with(&finding_id));
    if let Some(f) = target_finding {
        let single_report = types::ScanReport {
            findings: vec![f.clone()],
            ..scan_report
        };
        let plan = AutopilotHealer::plan_healing(&single_report);
        if json {
            println!("{}", serde_json::to_string_pretty(&plan).unwrap());
            return 0;
        }
        println!("\n=== REMEDIATION PLAN FOR FINDING {} ===", f.id);
        for action in plan {
            println!("Action Type:   {:?}", action.action_type);
            println!("Target File:   {}", action.target_file.display());
            println!("Diff:          {}", action.diff_description);
            println!("Original Hash: {}", action.original_checksum);
        }
        println!();
        0
    } else {
        eprintln!("Finding '{}' not found in workspace scan.", finding_id);
        1
    }
}

pub fn handle_operator_public_key() -> i32 {
    match OperatorIdentity::load_default() {
        Ok(identity) => {
            println!("{}", identity.public_key_hex());
            0
        }
        Err(error) => {
            eprintln!("Operator signing key is not provisioned: {error}");
            4
        }
    }
}

pub fn handle_approve(
    plan_id: String,
    path: PathBuf,
    approver: String,
    validity_mins: i64,
    json: bool,
) -> i32 {
    let scan_report = FleetScanner::scan_directory(&path, true);
    let target_finding = scan_report
        .findings
        .iter()
        .find(|f| f.id == plan_id || f.dedupe_fingerprint.starts_with(&plan_id));

    let plan = if let Some(f) = target_finding {
        let single_report = types::ScanReport {
            findings: vec![f.clone()],
            ..scan_report
        };
        AutopilotHealer::plan_healing(&single_report)
    } else if plan_id == "all" {
        AutopilotHealer::plan_healing(&scan_report)
    } else {
        eprintln!(
            "Finding '{}' not found. Use 'all' to explicitly approve the entire proposed plan.",
            plan_id
        );
        return 2;
    };

    if plan.is_empty() {
        eprintln!(
            "No prospective patch actions available to approve for plan '{}'",
            plan_id
        );
        return 1;
    }

    let plan_checksum = ApprovalManager::compute_plan_checksum(&plan);
    match ApprovalManager::create_approval_receipt(
        &path,
        &plan_id,
        &plan_checksum,
        &approver,
        validity_mins,
    ) {
        Ok(receipt) => {
            let receipt_file = ApprovalManager::save_receipt(&path, &receipt).unwrap_or_else(|e| {
                eprintln!("Warning: Failed to persist receipt to disk: {}", e);
                path.join(format!("{}.receipt.json", plan_id))
            });

            if json {
                println!("{}", serde_json::to_string_pretty(&receipt).unwrap());
                return 0;
            }

            println!("\n=======================================================");
            println!("  ✍️  OPERATOR APPROVAL RECEIPT ISSUED");
            println!("=======================================================");
            println!("Plan ID:          {}", receipt.plan_id);
            println!("Plan Checksum:    {}", receipt.plan_checksum);
            println!("Approver:         {}", receipt.approver);
            println!("Valid Until:      {}", receipt.valid_until);
            println!("Signature:        {}...\n", &receipt.signature[..24]);
            println!("Receipt saved to: {}", receipt_file.display());
            println!("To apply this plan:");
            println!(
                "  bug-killer apply {} --approval-file {}",
                plan_id,
                receipt_file.display()
            );
            0
        }
        Err(e) => {
            eprintln!("Failed to issue approval receipt: {}", e);
            4
        }
    }
}

pub fn handle_apply(plan_id: String, approval_file: Option<PathBuf>, path: PathBuf) -> i32 {
    let receipt_path = approval_file.unwrap_or_else(|| {
        path.join(".bug-killer")
            .join("approvals")
            .join(format!("{}.receipt.json", plan_id))
    });

    let receipt = match ApprovalManager::load_receipt(&receipt_path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!(
                "Operator approval verification failed: {}. Cannot apply mutations without valid approval receipt.",
                e
            );
            return 4;
        }
    };

    if receipt.plan_id != plan_id {
        eprintln!(
            "Approval receipt plan ID does not match requested plan '{}'; refusing execution.",
            plan_id
        );
        return 4;
    }

    let scan_report = FleetScanner::scan_directory(&path, true);
    let target_finding = scan_report
        .findings
        .iter()
        .find(|f| f.id == plan_id || f.dedupe_fingerprint.starts_with(&plan_id));

    let plan = if let Some(f) = target_finding {
        let single_report = types::ScanReport {
            findings: vec![f.clone()],
            ..scan_report
        };
        AutopilotHealer::plan_healing(&single_report)
    } else if plan_id == "all" {
        AutopilotHealer::plan_healing(&scan_report)
    } else {
        eprintln!(
            "Finding '{}' not found. Use 'all' to explicitly request an entire workspace plan.",
            plan_id
        );
        return 2;
    };

    match ApprovalManager::execute_supervised_healing(&path, &receipt, &plan) {
        Ok((manifest, count)) => {
            println!(
                "\n✅ Successfully applied {} supervised patches under operator approval!",
                count
            );
            println!("📦 Backup Snapshot Created: {}", manifest.backup_id);
            println!(
                "   To rollback if needed: bug-killer rollback {}\n",
                manifest.backup_id
            );
            0
        }
        Err(e) => {
            eprintln!("❌ Supervised execution failed: {}", e);
            4
        }
    }
}
