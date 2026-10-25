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
static RE_ACTIONS_STEP_DEBUG: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)ACTIONS_(STEP|RUNNER)_DEBUG\s*[:=]\s*["']?(true|1)["']?"#).unwrap()
});
static RE_SECRET_EXPR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)\$\{\{\s*secrets[.\['"][^}]+\}\}"#).unwrap());
static RE_PRINT_CMD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(echo|printf|print|printenv|write-host|write-output|console\.log)\b"#)
        .unwrap()
});

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
                run_indent = if trimmed.starts_with("- run:") {
                    current_indent + 2
                } else {
                    current_indent
                };
            } else if in_run_block
                && current_indent <= run_indent
                && !trimmed.is_empty()
                && !trimmed.starts_with('|')
            {
                in_run_block = false;
            }

            // 4. Unpinned third-party actions check (BK-AI-CIC-003)
            let uses_target = if let Some(u) = trimmed.strip_prefix("- uses:") {
                Some(u.trim())
            } else {
                trimmed.strip_prefix("uses:").map(|u| u.trim())
            };

            if let Some(action_ref) = uses_target {
                let clean_ref = action_ref.trim_matches(|c| c == '\'' || c == '"');
                if !clean_ref.starts_with("./") && !clean_ref.starts_with("docker://") {
                    if let Some((action_name, version_tag)) = clean_ref.split_once('@') {
                        let is_pinned_sha = version_tag.len() == 40
                            && version_tag.chars().all(|c| c.is_ascii_hexdigit());
                        if !is_pinned_sha {
                            let mut finding = Finding::new(
                                format!("CIC-UNPINNED-{}-{}", path.display(), line_num),
                                CveId::Custom {
                                    id: "BK-AI-CIC-003".to_string(),
                                    title: "Unpinned Third-Party CI Action (Mutable Tag)".to_string(),
                                },
                                Severity::Medium,
                                TargetKind::GenericConfigFile,
                                Some(path.to_path_buf()),
                                Some(line_num),
                                format!("uses: {}", clean_ref),
                                "Pin third-party GitHub Action to an immutable full-length commit SHA".to_string(),
                                format!(
                                    "Third-party action '{}' uses mutable ref '{}' instead of immutable commit SHA",
                                    action_name, version_tag
                                ),
                                "Pin to full 40-character commit SHA (e.g. 'actions/checkout@8e5e7e5...') with inline comment for version tag".to_string(),
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
            }

            // 5. Debug trace / step logging exposure (BK-AI-CIC-006)
            if RE_ACTIONS_STEP_DEBUG.is_match(line) {
                let mut finding = Finding::new(
                    format!("CIC-DEBUGTRACE-{}-{}", path.display(), line_num),
                    CveId::Custom {
                        id: "BK-AI-CIC-006".to_string(),
                        title: "CI Secret Exposure via Debug Trace / ACTIONS_STEP_DEBUG"
                            .to_string(),
                    },
                    Severity::High,
                    TargetKind::GenericConfigFile,
                    Some(path.to_path_buf()),
                    Some(line_num),
                    trimmed,
                    "Disable ACTIONS_STEP_DEBUG and runner diagnostic logging in CI workflows",
                    format!(
                        "Workflow enables diagnostic step debugging at line {}: '{}', which exposes secrets and decrypted variables in job execution logs",
                        line_num, trimmed
                    ),
                    "Remove ACTIONS_STEP_DEBUG or set it to 'false' to prevent secret leakage in build logs",
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
                    finding.advisory_ids.push("BK-AI-CIC-004".to_string());
                    finding.affectedness = Affectedness::ConfirmedAffected;
                    finding.reachability = Reachability::ConfirmedReachable;
                    finding.confidence = Confidence::Confirmed;
                    finding.evidence_certainty = EvidenceCertainty::Confirmed;
                    findings.push(finding);
                }

                // 6. Echoed or printed secrets in run steps (BK-AI-CIC-006)
                if RE_SECRET_EXPR.is_match(line) && RE_PRINT_CMD.is_match(line) {
                    let mut finding = Finding::new(
                        format!("CIC-SECRETPRINT-{}-{}", path.display(), line_num),
                        CveId::Custom {
                            id: "BK-AI-CIC-006".to_string(),
                            title: "CI Secret Printed or Echoed in Workflow Run Step".to_string(),
                        },
                        Severity::High,
                        TargetKind::GenericConfigFile,
                        Some(path.to_path_buf()),
                        Some(line_num),
                        trimmed,
                        "Avoid echoing or printing repository secrets to standard output or build logs",
                        format!(
                            "Secret expression '${{ secrets.* }}' is echoed or printed at line {}: '{}'",
                            line_num, trimmed
                        ),
                        "Remove commands that echo secrets or pipe them to logging utilities; use trusted actions or masked environment variables",
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
