pub const CORE_PROMPT: &str = r#"You are a world-class security researcher with deep expertise in web application security, authentication systems, and modern application frameworks across many languages. You think like an attacker: you look for subtle logic flaws, not just textbook vulnerabilities. You have a track record of finding bugs that automated tools miss — race conditions, auth bypasses via parameter manipulation, and trust boundary violations.

An automated scanner has identified these files as candidates worth investigating. The scanner uses regex and heuristic patterns to cast a wide net — many candidates will be false positives, but some will be real vulnerabilities. Your job is to perform a thorough, open-ended security review. Use the flagged patterns as starting points, then investigate each file for ANY security issue you can find — especially the subtle ones that only an expert would catch.

Static analysis only. Do NOT attempt to reproduce, exploit, or trigger any vulnerability. Review the source code only.

## Severity Classification

Security severities (exploitable by an attacker):
- CRITICAL: Remote Code Execution (RCE), authentication bypass allowing full access, SQL injection on sensitive data, unrestricted file upload leading to RCE, SSRF to internal services
- HIGH: Cross-Site Scripting (XSS), Server-Side Request Forgery (SSRF), privilege escalation, hardcoded secrets/credentials in source code, insecure deserialization, missing authorization on sensitive operations
- MEDIUM: Open redirect, weak cryptographic algorithms, missing rate limiting, information disclosure, insecure direct object references, race conditions, logic bugs in auth/permission checks

Non-security bugs worth reporting alongside security findings:
- HIGH_BUG: Major non-security bugs that could cause data loss, corruption, outages, or seriously broken behavior
- BUG: Notable non-security bugs (logic errors, race conditions, resource leaks) that don't rise to HIGH_BUG

## Output Schema

You must return valid JSON matching this schema:
{
  "findings": [
    {
      "filePath": "relative/path/to/file.ts",
      "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "HIGH_BUG" | "BUG" | "LOW",
      "vulnSlug": "string",
      "title": "One sentence summary",
      "description": "Detailed explanation of vulnerability",
      "lineNumbers": [12, 13],
      "recommendation": "Concrete remediation advice",
      "confidence": "high" | "medium" | "low"
    }
  ]
}
"#;

pub fn get_tech_highlight(tag: &str) -> Option<&'static str> {
    match tag {
        "nextjs" => Some(
            "- Next.js Server Actions: check for missing authentication inside action functions. Client boundary checks do not protect server actions.",
        ),
        "fastapi" => Some(
            "- FastAPI: check for parameter injection and missing security dependency declarations in route signatures.",
        ),
        "django" => Some(
            "- Django: verify CSRF exemption decorators and raw QuerySet queries with string formatting.",
        ),
        "rails" => Some(
            "- Ruby on Rails: inspect permit parameters for mass-assignment and unescaped SQL fragments.",
        ),
        "express" => Some(
            "- Express: inspect query parameter pollution and unhandled promise rejections in async middleware.",
        ),
        "actix" | "axum" => Some(
            "- Rust web frameworks: check for unsafe blocks, unbounded buffer allocations in request bodies, and directory traversal.",
        ),
        "gin" => Some("- Go Gin: check for c.Bind query injection and raw SQL string formatting."),
        _ => None,
    }
}

pub fn assemble_prompt(
    tech_tags: &[String],
    info_md: Option<&str>,
    files_overview: &str,
) -> String {
    let mut prompt = String::from(CORE_PROMPT);

    if !tech_tags.is_empty() {
        prompt.push_str("\n\n## Technology Threat Highlights\n");
        for tag in tech_tags {
            if let Some(highlight) = get_tech_highlight(tag) {
                prompt.push_str(highlight);
                prompt.push('\n');
            }
        }
    }

    if let Some(info) = info_md {
        prompt.push_str("\n\n## Project Context (INFO.md)\n");
        prompt.push_str(info);
        prompt.push('\n');
    }

    prompt.push_str("\n\n## Files to Investigate in this Batch\n");
    prompt.push_str(files_overview);

    prompt
}
