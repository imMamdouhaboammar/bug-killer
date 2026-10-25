#![allow(dead_code)]

use crate::catalog::SecurityCatalog;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityRuleSummary {
    pub rule_id: String,
    pub cwe: Option<String>,
    pub invariant: String,
    pub guidance: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskSecurityGuidance {
    pub task_query: String,
    pub language: String,
    pub relevant_rules: Vec<SecurityRuleSummary>,
    pub recommended_safe_patterns: Vec<String>,
    pub banned_anti_patterns: Vec<String>,
    pub required_security_tests: Vec<String>,
}

pub struct GuidanceEngine;

impl GuidanceEngine {
    /// Produces task-scoped security guidance before coding begins.
    pub fn generate_guidance(task_query: &str, language: &str) -> TaskSecurityGuidance {
        let catalog = SecurityCatalog::global();
        let query_lower = task_query.to_lowercase();
        let query_words: Vec<&str> = query_lower
            .split(|c: char| !c.is_alphanumeric())
            .filter(|word| !word.is_empty())
            .collect();
        let mut selected_rules = Vec::new();
        let mut safe_patterns = Vec::new();
        let mut anti_patterns = Vec::new();
        let mut required_tests = Vec::new();

        // 1. SQL / Database
        if query_words
            .iter()
            .any(|word| matches!(*word, "sql" | "query" | "database" | "orm"))
        {
            if let Some(r) = catalog.get_rule("BK-AI-INJ-001") {
                selected_rules.push(SecurityRuleSummary {
                    rule_id: r.rule_id.clone(),
                    cwe: r.cwe.clone(),
                    invariant: "All SQL queries must use parameterized placeholders; never string concatenation.".into(),
                    guidance: r.remediation_guidance.clone(),
                });
            }
            safe_patterns.push(
                "Use prepared statements or typed query builders (e.g. sqlx, Prisma, Kysely, PDO)."
                    .into(),
            );
            anti_patterns.push("String interpolation in SQL strings (e.g. `SELECT * FROM users WHERE id = ${id}`).".into());
            required_tests.push("Verify that quotes or SQL fragments in input are treated strictly as data literals.".into());
        }

        // 2. Auth / Account / JWT / Session
        if query_lower.contains("auth")
            || query_lower.contains("login")
            || query_lower.contains("jwt")
            || query_lower.contains("password")
            || query_lower.contains("session")
        {
            if let Some(r) = catalog.get_rule("BK-AI-AUT-001") {
                selected_rules.push(SecurityRuleSummary {
                    rule_id: r.rule_id.clone(),
                    cwe: r.cwe.clone(),
                    invariant: "Protected routes must enforce server-side authentication; never rely on UI route guards alone.".into(),
                    guidance: r.remediation_guidance.clone(),
                });
            }
            if let Some(r) = catalog.get_rule("BK-AI-AUT-004") {
                selected_rules.push(SecurityRuleSummary {
                    rule_id: r.rule_id.clone(),
                    cwe: r.cwe.clone(),
                    invariant: "Passwords must be hashed using Argon2id or bcrypt with unique cryptographic salt.".into(),
                    guidance: r.remediation_guidance.clone(),
                });
            }
            if let Some(r) = catalog.get_rule("BK-AI-AUT-011") {
                selected_rules.push(SecurityRuleSummary {
                    rule_id: r.rule_id.clone(),
                    cwe: r.cwe.clone(),
                    invariant: "Verify JWT signature, expiry (exp), issuer (iss), and audience (aud) before trusting claims.".into(),
                    guidance: r.remediation_guidance.clone(),
                });
            }
            safe_patterns.push(
                "Enforce HttpOnly, Secure, SameSite=Lax/Strict flags on session cookies.".into(),
            );
            anti_patterns.push(
                "Storing plaintext passwords, MD5/SHA1 hashes, or trusting unverified JWT claims."
                    .into(),
            );
            required_tests.push("Verify that unauthenticated requests to protected endpoints return 401 Unauthorized.".into());
        }

        // 3. File upload / filesystem / archive
        if query_lower.contains("upload")
            || query_lower.contains("file")
            || query_lower.contains("path")
            || query_lower.contains("download")
            || query_lower.contains("zip")
            || query_lower.contains("tar")
        {
            if let Some(r) = catalog.get_rule("BK-AI-FIL-001") {
                selected_rules.push(SecurityRuleSummary {
                    rule_id: r.rule_id.clone(),
                    cwe: r.cwe.clone(),
                    invariant: "User-controlled filenames must be canonicalized and checked against a strict base directory boundary.".into(),
                    guidance: r.remediation_guidance.clone(),
                });
            }
            if let Some(r) = catalog.get_rule("BK-AI-FIL-002") {
                selected_rules.push(SecurityRuleSummary {
                    rule_id: r.rule_id.clone(),
                    cwe: r.cwe.clone(),
                    invariant: "Archive extraction must reject entries containing '..' or absolute paths (Zip Slip protection).".into(),
                    guidance: r.remediation_guidance.clone(),
                });
            }
            safe_patterns.push("Generate random UUID file storage keys instead of trusting client-provided filenames.".into());
            anti_patterns.push("Concatenating directory paths with raw user input without canonicalization and boundary verification.".into());
            required_tests
                .push("Verify that paths containing '../../' are rejected with error.".into());
        }

        // 4. AI Agent / LLM / Prompt / MCP
        if query_lower.contains("agent")
            || query_lower.contains("llm")
            || query_lower.contains("prompt")
            || query_lower.contains("mcp")
            || query_lower.contains("tool")
        {
            if let Some(r) = catalog.get_rule("BK-AI-LLM-001") {
                selected_rules.push(SecurityRuleSummary {
                    rule_id: r.rule_id.clone(),
                    cwe: r.cwe.clone(),
                    invariant: "Untrusted user or web content must be quarantined from privileged system prompt instructions.".into(),
                    guidance: r.remediation_guidance.clone(),
                });
            }
            if let Some(r) = catalog.get_rule("BK-AI-LLM-008") {
                selected_rules.push(SecurityRuleSummary {
                    rule_id: r.rule_id.clone(),
                    cwe: r.cwe.clone(),
                    invariant: "AI agent tools must run with least privilege; never grant unrestricted shell execution without gating.".into(),
                    guidance: r.remediation_guidance.clone(),
                });
            }
            safe_patterns.push("Use structured parameter validation (JSON Schema/Zod) and explicit human approval for destructive mutations.".into());
            anti_patterns.push("Allowing model to execute raw bash commands without argument allowlists or isolated sandbox.".into());
            required_tests.push("Verify that simulated prompt injection payloads cannot invoke unauthorized internal tools.".into());
        }

        // 5. Secret / Token / API Key
        if query_lower.contains("secret")
            || query_lower.contains("key")
            || query_lower.contains("token")
            || query_lower.contains("credential")
        {
            if let Some(r) = catalog.get_rule("BK-AI-SEC-001") {
                selected_rules.push(SecurityRuleSummary {
                    rule_id: r.rule_id.clone(),
                    cwe: r.cwe.clone(),
                    invariant: "Zero hardcoded secrets; load credentials from environment variables or secure key vaults.".into(),
                    guidance: r.remediation_guidance.clone(),
                });
            }
            safe_patterns.push("Read credentials exclusively from process environment or secret management service.".into());
            anti_patterns.push(
                "Committing .env files, test credentials, or hardcoded tokens to version control."
                    .into(),
            );
            required_tests.push("Verify that sensitive credentials are never logged or exposed in client responses.".into());
        }

        // Default fallback if no specific keywords triggered
        if selected_rules.is_empty() {
            if let Some(r) = catalog.get_rule("BK-AI-INJ-003") {
                selected_rules.push(SecurityRuleSummary {
                    rule_id: r.rule_id.clone(),
                    cwe: r.cwe.clone(),
                    invariant: "Never construct shell commands via string concatenation; pass arguments as discrete arrays.".into(),
                    guidance: r.remediation_guidance.clone(),
                });
            }
            if let Some(r) = catalog.get_rule("BK-AI-SEC-001") {
                selected_rules.push(SecurityRuleSummary {
                    rule_id: r.rule_id.clone(),
                    cwe: r.cwe.clone(),
                    invariant: "Never commit API keys or private credentials into source code."
                        .into(),
                    guidance: r.remediation_guidance.clone(),
                });
            }
            safe_patterns.push(
                "Enforce strict input validation and boundary sanitization at system entry points."
                    .into(),
            );
            anti_patterns.push("Catching generic exceptions and failing open or logging sensitive user parameters.".into());
            required_tests
                .push("Run Bug Killer security scan to verify zero regression findings.".into());
        }

        TaskSecurityGuidance {
            task_query: task_query.to_string(),
            language: language.to_string(),
            relevant_rules: selected_rules,
            recommended_safe_patterns: safe_patterns,
            banned_anti_patterns: anti_patterns,
            required_security_tests: required_tests,
        }
    }
}
