use crate::deepsec::storage::StorageManager;
use crate::deepsec::types::*;
use colored::Colorize;
use std::fs;
use std::io;
use std::path::Path;
use tabled::{Table, Tabled};

#[derive(Tabled)]
struct TerminalRow {
    #[tabled(rename = "ID")]
    id: String,
    #[tabled(rename = "Severity")]
    severity: String,
    #[tabled(rename = "File")]
    file: String,
    #[tabled(rename = "Lines")]
    lines: String,
    #[tabled(rename = "Category")]
    category: String,
    #[tabled(rename = "Title")]
    title: String,
}

pub fn render_terminal_summary(records: &[FileRecord]) -> String {
    let mut rows = Vec::new();

    for rec in records {
        for finding in &rec.findings {
            let sev_colored = match finding.severity {
                Severity::Critical => "CRITICAL".red().bold().to_string(),
                Severity::High => "HIGH".yellow().bold().to_string(),
                Severity::Medium => "MEDIUM".yellow().to_string(),
                Severity::HighBug => "HIGH_BUG".magenta().bold().to_string(),
                Severity::Bug => "BUG".magenta().to_string(),
                Severity::Low => "LOW".cyan().to_string(),
            };

            let line_span = if finding.line_numbers.is_empty() {
                "-".to_string()
            } else if finding.line_numbers.len() == 1 {
                format!("L{}", finding.line_numbers[0])
            } else {
                format!(
                    "L{}-L{}",
                    finding.line_numbers[0],
                    finding.line_numbers[finding.line_numbers.len() - 1]
                )
            };

            rows.push(TerminalRow {
                id: finding.finding_id[..12.min(finding.finding_id.len())].to_string(),
                severity: sev_colored,
                file: rec.file_path.clone(),
                lines: line_span,
                category: finding.vuln_slug.clone(),
                title: finding.title.clone(),
            });
        }
    }

    if rows.is_empty() {
        return "No security findings discovered.".green().to_string();
    }

    Table::new(rows).to_string()
}

pub fn generate_markdown_report(project_id: &str, storage: &StorageManager) -> String {
    let records = storage.load_all_file_records(project_id);
    let mut out = format!("# DeepSec Security Scan Report: {}\n\n", project_id);

    let mut total_findings = 0;
    let mut critical_count = 0;
    let mut high_count = 0;
    let mut medium_count = 0;

    for rec in &records {
        for f in &rec.findings {
            total_findings += 1;
            match f.severity {
                Severity::Critical => critical_count += 1,
                Severity::High => high_count += 1,
                _ => medium_count += 1,
            }
        }
    }

    out.push_str("## Executive Summary\n\n");
    out.push_str(&format!(
        "- Total Scanned Files with Findings: {}\n",
        records.len()
    ));
    out.push_str(&format!("- Total Verified Findings: {}\n", total_findings));
    out.push_str(&format!("  - CRITICAL: {}\n", critical_count));
    out.push_str(&format!("  - HIGH: {}\n", high_count));
    out.push_str(&format!("  - MEDIUM / OTHER: {}\n\n", medium_count));

    out.push_str("## Findings Inventory\n\n");

    for rec in &records {
        if rec.findings.is_empty() {
            continue;
        }

        out.push_str(&format!("### File: `{}`\n\n", rec.file_path));

        if let Some(git) = &rec.git_info {
            out.push_str("**Recent Authors:** ");
            let authors: Vec<String> = git
                .recent_committers
                .iter()
                .map(|c| format!("{} <{}>", c.name, c.email))
                .collect();
            out.push_str(&authors.join(", "));
            out.push_str("\n\n");
        }

        for finding in &rec.findings {
            let verdict_str = finding
                .revalidation
                .as_ref()
                .map(|r| format!("{:?}", r.verdict))
                .unwrap_or_else(|| "unreviewed".to_string());

            let prio_str = finding
                .triage
                .as_ref()
                .map(|t| format!("{:?}", t.priority))
                .unwrap_or_else(|| "unassigned".to_string());

            out.push_str(&format!(
                "#### [{}] {}\n\n",
                finding.severity.as_str(),
                finding.title
            ));
            out.push_str(&format!("- **Finding ID:** `{}`\n", finding.finding_id));
            out.push_str(&format!("- **Category:** `{}`\n", finding.vuln_slug));
            out.push_str(&format!("- **Lines:** {:?}\n", finding.line_numbers));
            out.push_str(&format!("- **Confidence:** {:?}\n", finding.confidence));
            out.push_str(&format!("- **Triage Priority:** {}\n", prio_str));
            out.push_str(&format!("- **Revalidation Verdict:** {}\n\n", verdict_str));

            out.push_str("**Description:**\n");
            out.push_str(&finding.description);
            out.push_str("\n\n");

            out.push_str("**Recommendation:**\n");
            out.push_str(&finding.recommendation);
            out.push_str("\n\n---\n\n");
        }
    }

    out
}

pub fn export_json(project_id: &str, storage: &StorageManager, out_path: &Path) -> io::Result<()> {
    let records = storage.load_all_file_records(project_id);
    let json_bytes = serde_json::to_vec_pretty(&records)?;
    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(out_path, json_bytes)
}

pub fn export_md_dir(project_id: &str, storage: &StorageManager, out_dir: &Path) -> io::Result<()> {
    let records = storage.load_all_file_records(project_id);
    fs::create_dir_all(out_dir)?;

    for rec in records {
        for finding in rec.findings {
            let sev_dir = out_dir.join(finding.severity.as_str().to_lowercase());
            fs::create_dir_all(&sev_dir)?;

            let filename = format!("{}.md", finding.finding_id);
            let filepath = sev_dir.join(filename);

            let content = format!(
                "# [{}] {}\n\n- **File:** `{}`\n- **Category:** `{}`\n- **Lines:** {:?}\n- **ID:** `{}`\n\n## Description\n{}\n\n## Recommendation\n{}\n",
                finding.severity.as_str(),
                finding.title,
                rec.file_path,
                finding.vuln_slug,
                finding.line_numbers,
                finding.finding_id,
                finding.description,
                finding.recommendation
            );

            fs::write(filepath, content)?;
        }
    }

    Ok(())
}
