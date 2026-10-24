use crate::types::*;
use regex::Regex;
use std::path::Path;
use std::sync::LazyLock;

static RE_UNTRUSTED_EXPR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\$\{\{\s*github\.event\.(issue|pull_request|comment|head_commit)\.(title|body|message)\s*\}\}"#)
        .unwrap()
});
static RE_HEAD_REF: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"\$\{\{\s*github\.head_ref\s*\}\}"#).unwrap());

pub struct CicdScanner;

impl CicdScanner {
    /// Scans a CI/CD workflow YAML file (e.g. .github/workflows/*.yml) for security vulnerabilities.
    pub fn scan_workflow(path: &Path, content: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut in_run_block = false;
        let mut run_indent = 0;

        let has_pr_target = content.contains("pull_request_target:");
        let has_write_all = content.contains("write-all")
            || (content.contains("permissions:")
                && content.contains("actions: write")
                && content.contains("contents: write"));

        // 1. Excessive permissions check (BK-AI-CIC-002)
        if content.contains("permissions: write-all") {
            let mut finding = Finding::new(
                format!("CIC-PERM-{}", path.display()),
                CveId::Custom {
                    id: "BK-AI-CIC-002".to_string(),
                    title: "Overly Broad CI/CD Workflow Permissions ('write-all')".to_string(),
                },
                Severity::High,
                TargetKind::GenericConfigFile,
                Some(path.to_path_buf()),
                Some(1),
                "permissions: write-all",
                "Apply principle of least privilege with explicit read-only permissions by default",
                format!(
                    "Workflow file '{}' grants blanket write-all permissions to GITHUB_TOKEN",
                    path.display()
                ),
                "Declare granular permissions per job (e.g. contents: read, issues: write)",
            );
            finding.detector_id = "cicd-security".to_string();
            finding.category = "2.14 CI/CD, build pipelines and repository automation".to_string();
            finding.affectedness = Affectedness::ConfirmedAffected;
            finding.reachability = Reachability::ConfirmedReachable;
            finding.confidence = Confidence::Confirmed;
            finding.evidence_certainty = EvidenceCertainty::Confirmed;
            findings.push(finding);
        }

        // 2. Dangerous pull_request_target with untrusted checkout (BK-AI-CIC-002)
        if has_pr_target && content.contains("github.event.pull_request.head.sha") && has_write_all
        {
            let mut finding = Finding::new(
                format!("CIC-PRTARGET-{}", path.display()),
                CveId::Custom {
                    id: "BK-AI-CIC-002".to_string(),
                    title:
                        "Dangerous Checkout of Untrusted Pull Request Code with Write Permissions"
                            .to_string(),
                },
                Severity::Critical,
                TargetKind::GenericConfigFile,
                Some(path.to_path_buf()),
                Some(1),
                "pull_request_target with head.sha checkout",
                "Do not check out untrusted pull request code in workflows with write tokens or repository secrets",
                format!(
                    "Workflow '{}' triggers on pull_request_target and checks out head commit with write permissions",
                    path.display()
                ),
                "Switch to pull_request trigger or isolate untrusted build artifacts from privileged publish jobs",
            );
            finding.detector_id = "cicd-security".to_string();
            finding.category = "2.14 CI/CD, build pipelines and repository automation".to_string();
            finding.affectedness = Affectedness::ConfirmedAffected;
            finding.reachability = Reachability::ConfirmedReachable;
            finding.confidence = Confidence::Confirmed;
            finding.evidence_certainty = EvidenceCertainty::Confirmed;
            findings.push(finding);
        }

        // 3. Line-by-line script injection check in run: steps (BK-AI-CIC-001)
        for (line_idx, line) in content.lines().enumerate() {
            let line_num = line_idx + 1;
            let current_indent = line.len() - line.trim_start().len();
            let trimmed = line.trim();

            let is_run_start = trimmed.starts_with("run:") || trimmed.starts_with("- run:");
            if is_run_start {
                in_run_block = true;
                run_indent = current_indent;
            } else if in_run_block
                && current_indent <= run_indent
                && !trimmed.is_empty()
                && !trimmed.starts_with('|')
            {
                in_run_block = false;
            }

            if in_run_block || is_run_start {
                let is_untrusted_title_or_body = RE_UNTRUSTED_EXPR.is_match(line);
                let is_head_ref = RE_HEAD_REF.is_match(line);

                if is_untrusted_title_or_body || is_head_ref {
                    let matched_snippet = if is_untrusted_title_or_body {
                        "github.event.*.(title|body|message) in run:"
                    } else {
                        "github.head_ref in run:"
                    };

                    let mut finding = Finding::new(
                        format!("CIC-INJ-{}-{}", path.display(), line_num),
                        CveId::Custom {
                            id: "BK-AI-CIC-001".to_string(),
                            title: "Untrusted Context Interpolation in GitHub Actions Run Step"
                                .to_string(),
                        },
                        Severity::Critical,
                        TargetKind::GenericConfigFile,
                        Some(path.to_path_buf()),
                        Some(line_num),
                        matched_snippet,
                        "Map context variables to step-level environment variables (env:) before using in shell",
                        format!(
                            "Untrusted GitHub event context directly interpolated into shell command at line {}: {}",
                            line_num, trimmed
                        ),
                        "Pass value via 'env: TITLE: ${{ github.event.issue.title }}' and reference as \"$TITLE\" in bash",
                    );
                    finding.detector_id = "cicd-security".to_string();
                    finding.category =
                        "2.14 CI/CD, build pipelines and repository automation".to_string();
                    finding.affectedness = Affectedness::ConfirmedAffected;
                    finding.reachability = Reachability::ConfirmedReachable;
                    finding.confidence = Confidence::Confirmed;
                    finding.evidence_certainty = EvidenceCertainty::Confirmed;
                    findings.push(finding);
                }
            }
        }

        findings
    }
}
