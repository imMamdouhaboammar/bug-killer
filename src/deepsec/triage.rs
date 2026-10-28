use crate::deepsec::storage::StorageManager;
use crate::deepsec::types::*;
use chrono::Utc;

pub fn triage_findings(project_id: &str, storage: &StorageManager) -> Result<usize, String> {
    let all_records = storage.load_all_file_records(project_id);
    let mut triaged_count = 0;

    for mut rec in all_records {
        if rec.findings.is_empty() {
            continue;
        }

        let mut changed = false;
        for finding in &mut rec.findings {
            if finding.triage.is_some() {
                continue;
            }

            let (priority, exploitability, impact, reasoning) = if let Some(reval) = &finding.revalidation {
                if reval.verdict == RevalidationVerdict::FalsePositive
                    || reval.verdict == RevalidationVerdict::Fixed
                    || reval.verdict == RevalidationVerdict::Duplicate
                {
                    (
                        TriagePriority::Skip,
                        "difficult".to_string(),
                        "low".to_string(),
                        "Skipped: finding marked as fixed, duplicate, or false positive in revalidation".to_string(),
                    )
                } else {
                    classify_finding(finding)
                }
            } else {
                classify_finding(finding)
            };

            finding.triage = Some(Triage {
                priority,
                exploitability,
                impact,
                reasoning,
                triaged_at: Utc::now().to_rfc3339(),
                model: "deterministic-triage-v1".to_string(),
            });

            triaged_count += 1;
            changed = true;
        }

        if changed {
            storage.write_file_record(&rec).map_err(|e| e.to_string())?;
        }
    }

    Ok(triaged_count)
}

fn classify_finding(finding: &Finding) -> (TriagePriority, String, String, String) {
    match finding.severity {
        Severity::Critical => (
            TriagePriority::P0,
            "trivial".to_string(),
            "critical".to_string(),
            "P0: Critical security vulnerability directly exploitable with severe blast radius"
                .to_string(),
        ),
        Severity::High => (
            TriagePriority::P1,
            "moderate".to_string(),
            "high".to_string(),
            "P1: High priority finding with verified security impact requiring prioritized fix"
                .to_string(),
        ),
        Severity::Medium | Severity::HighBug => (
            TriagePriority::P2,
            "moderate".to_string(),
            "medium".to_string(),
            "P2: Medium risk finding or major bug requiring standard sprint remediation".to_string(),
        ),
        Severity::Bug | Severity::Low => (
            TriagePriority::Skip,
            "difficult".to_string(),
            "low".to_string(),
            "Skip: Low risk issue without direct security exploitability".to_string(),
        ),
    }
}
