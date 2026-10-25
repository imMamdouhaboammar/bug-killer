#![allow(dead_code)]

use crate::types::*;
use regex::Regex;
use std::path::Path;
use std::sync::LazyLock;

// ===========================================================================
// Category 15: Infrastructure, Cloud & Defaults (BK-AI-INF-002 to INF-016)
// ===========================================================================

/// BK-AI-INF-002 (CWE-732): Storage bucket/container/DB endpoint accidentally public
static RE_INF_002_PUBLIC_STORAGE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\bacl\s*[:=]\s*["'](?:public-read|public-read-write)["']|\b(?:publicReadAccess|public_read_access)\s*[:=]\s*true\b|\b(?:block_public_acls|block_public_policy|ignore_public_acls|restrict_public_buckets)\s*[:=]\s*false\b|\b(?:public_access|publicAccess)\s*[:=]\s*["'](?:blob|container)["']|\b(?:allow_blob_public_access|allowBlobPublicAccess)\s*[:=]\s*true\b|\b(?:member|members)\s*[:=]\s*(?:\[\s*)?["']all(?:Users|AuthenticatedUsers)["']|["']allUsers["']\s*,|["']allAuthenticatedUsers["']|\b(?:publicly_accessible|public_network_access_enabled)\s*[:=]\s*true\b)"#).unwrap()
});

/// BK-AI-INF-005 (CWE-269): IAM policy permits `*` actions/resources or broad role assumption
static RE_INF_005_WILDCARD_IAM: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\bactions\s*=\s*\[\s*["']\*["']\s*\]|["']?Action["']?\s*[:=]\s*(?:\[\s*)?["']\*["'](?:\s*\])?|\brole\s*[:=]\s*["']roles/(?:owner|editor)["']|["']?Principal["']?\s*[:=]\s*(?:\{[^}]*AWS\s*[:=]\s*["']\*["']|["']\*["'])|\bactions\s*=\s*\[\s*["'][a-zA-Z0-9_-]+:\*["']\s*\])"#).unwrap()
});

/// BK-AI-INF-006 (CWE-284): Security group/network rule opens management/database port to internet
static RE_INF_006_SENSITIVE_PORT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:from_port|to_port|\bport)\s*[:=]\s*(?:22|3389|5432|3306|27017|6379|9200|1433)\b"#).unwrap()
});

/// BK-AI-INF-009 (CWE-306): Database/queue/Redis/Elasticsearch has no authentication in reachable environment
static RE_INF_009_NO_AUTH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:redis(?:\.createClient|\.connect)?\s*\([^)]*password\s*:\s*["']["']|^\s*requirepass\s+["']?["']?\s*$|(?:--protected-mode\s+no|\bprotected-mode\s+no\b)|(?:\bnoauth\s*[:=]\s*true\b|--noauth\b|^\s*auth\s*[:=]\s*false\b)|\bxpack\.security\.enabled\s*[:=]\s*false\b|\b(?:ALLOW_ANONYMOUS_LOGIN|ALLOW_EMPTY_PASSWORD)\s*[:=]\s*["']?(?:yes|true|1)["']?|\b(?:unauthenticated|no_auth)\s*[:=]\s*true\b|\bpassword\s*[:=]\s*["']["'])"#).unwrap()
});

/// BK-AI-INF-011 (CWE-798): Default credentials, sample tokens or test users active after deployment
static RE_INF_011_DEFAULT_CREDS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\b(?:admin:admin|root:root|admin:password|admin:123456|guest:guest)\b|\b(?:POSTGRES_PASSWORD|MYSQL_ROOT_PASSWORD|MONGO_INITDB_ROOT_PASSWORD)\s*=\s*["']?(?:postgres|root|password|123456|admin)["']?|\b(?:default_password|defaultPassword)\s*[:=]\s*["'][^"']+["']|\b(?:use_default_credentials|useDefaultCredentials|enable_test_accounts|enableTestAccounts|test_users_enabled)\s*[:=]\s*true\b)"#).unwrap()
});

/// BK-AI-INF-012 (CWE-1104): Container image uses unverified / latest base tag with stale vulnerable OS packages
static RE_INF_012_FROM_IMAGE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)^FROM\s+(?:--platform=[^\s]+\s+)?([a-zA-Z0-9_\-\./]+)(?::([^\s]+))?(?:\s+as\s+[a-zA-Z0-9_\-]+)?$"#).unwrap()
});

static RE_INF_012_COMPOSE_LATEST: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\bimage:\s*['"]?[a-zA-Z0-9_\-\./]+:latest['"]?"#).unwrap()
});

/// BK-AI-INF-013 (CWE-778): Infrastructure logs/audit disabled for security-critical asset
static RE_INF_013_AUDIT_DISABLED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\b(?:logging_enabled|loggingEnabled|enable_logging|enableLogging)\s*[:=]\s*false\b|\b(?:audit_logs|audit_logging|auditLogging)\s*[:=]\s*false\b|\b(?:enable_cloudtrail|enable_flow_logs|flow_logs_enabled|monitoring_enabled|enable_log_file_validation)\s*[:=]\s*false\b)"#).unwrap()
});

/// BK-AI-INF-014 (CWE-250): K8s workloads lack required securityContext / privilege confinement
static RE_INF_014_K8S_PRIVILEGE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\bprivileged\s*:\s*true\b|\ballowPrivilegeEscalation\s*:\s*true\b|\brunAsUser\s*:\s*0\b|\brunAsNonRoot\s*:\s*false\b|\breadOnlyRootFilesystem\s*:\s*false\b)"#).unwrap()
});

/// BK-AI-INF-015 (CWE-918): Cloud metadata service accessible from untrusted fetch path
static RE_INF_015_IMDS_RISK: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\bhttp_tokens\s*[:=]\s*["']optional["']|\bhttp_put_response_hop_limit\s*[:=]\s*(?:[2-9]|\d{2,})\b)"#).unwrap()
});

/// BK-AI-INF-016 (CWE-552): Backups are unencrypted/public/unrestorable or deletion unsafe
static RE_INF_016_BACKUP_RISK: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\b(?:kms_key_arn|kms_key_id)\s*[:=]\s*(?:null|["']["'])\b|\b(?:backup_encryption|storage_encrypted)\s*[:=]\s*false\b|\bdelete_after\s*[:=]\s*0\b|\benable_retention_lock\s*[:=]\s*false\b|\bretention_period\s*[:=]\s*0\b)"#).unwrap()
});

// ===========================================================================
// Category 14: CI/CD, Build Pipelines & Repo Automation (BK-AI-CIC-005 to 014)
// ===========================================================================

/// BK-AI-CIC-005 (CWE-829): Build/test executes downloaded untrusted shell script without verification
static RE_CIC_005_CURL_PIPE_SHELL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:curl\s+[^|\n;]+|wget\s+[^|\n;]+)\|\s*(?:(?:/bin/)?(?:bash|sh|zsh)|python[23]?|node)\b"#).unwrap()
});

/// BK-AI-CIC-007 (CWE-829): Unsafe artifact/cache reuse between untrusted PR and release job
static RE_CIC_007_CACHE_PR_REF: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\b(?:key|restore-keys)\s*:\s*.*?\$\{\{\s*github\.(?:head_ref|event\.pull_request\.head\.ref)\s*\}\}|\b(?:key|restore-keys)\s*:\s*.*?pr-\$\{\{\s*github\.event\.number\s*\}\})"#).unwrap()
});

/// BK-AI-CIC-008 (CWE-284): Deployment triggered without branch/environment approval controls
static RE_CIC_008_WILDCARD_BRANCH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\bbranches\s*:\s*(?:\[\s*["']\*\*?["']\s*\]|["']\*\*?["'])"#).unwrap()
});

static RE_CIC_008_DEPLOY_NO_APPROVAL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\bdeploy_without_approval\s*[:=]\s*true\b"#).unwrap()
});

/// BK-AI-CIC-009 (CWE-494): Release generated from a different commit than tested/reviewed
static RE_CIC_009_MUTABLE_CHECKOUT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\b(?:git\s+checkout\s+(?:main|master|latest)|git\s+pull(?:\s+origin\s+(?:main|master))?)\b|\bref\s*:\s*["']?(?:main|master|latest)["']?)"#).unwrap()
});

/// BK-AI-CIC-010 (None): Test/security jobs optional, skipped or configured with continue-on-error: true
static RE_CIC_010_CONTINUE_ON_ERROR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\bcontinue-on-error\s*:\s*true\b"#).unwrap()
});

static RE_CIC_010_MASKED_ERROR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:npm\s+test|cargo\s+test|pytest|trivy|snyk|audit)\b[^|\n;]*\|\|\s*(?:true|exit\s+0)\b"#).unwrap()
});

/// BK-AI-CIC-011 (CWE-250): Package scripts execute with privileged token, network and filesystem by default
static RE_CIC_011_INSTALL_CMD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(?:npm\s+(?:install|ci)|yarn\s+install|pnpm\s+install)\b"#).unwrap()
});

static RE_CIC_011_ENABLE_SCRIPTS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\b(?:npm\s+install|npm\s+ci|yarn\s+install|pnpm\s+install)\s+--ignore-scripts=false\b|\b(?:npm|pnpm|yarn)\s+install\s+--foreground-scripts\b|\bexecute_package_scripts\s*[:=]\s*true\b)"#).unwrap()
});

/// BK-AI-CIC-012 (CWE-494): Artifact signing/attestation missing where project trust contract requires it
static RE_CIC_012_PROVENANCE_DISABLED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\b(?:provenance|generate_provenance)\s*[:=]\s*false\b|\b(?:sign_artifact|cosign_sign|sign)\s*[:=]\s*false\b|\bskip_signing\s*[:=]\s*true\b|\b(?:npm\s+publish|docker\s+push|goreleaser\s+release)\b.*?(?:--no-provenance|--provenance=false|--skip=sign)\b)"#).unwrap()
});

/// BK-AI-CIC-013 (CWE-863): PR bot auto-merges without review of changed security boundaries
static RE_CIC_013_AUTOMERGE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\bgh\s+pr\s+merge\b[^\n;]*--auto\b|\b(?:auto-merge|auto_merge|automerge)\s*[:=]\s*true\b|\bpascalgn/automerge-action\b|\balexwilson/enable-github-automerge\b|\bmerge_when_checks_pass\s*[:=]\s*true\b)"#).unwrap()
});

/// BK-AI-CIC-014 (CWE-78): Workflow writes to repo or runs command based on arbitrary external issue/comment content
static RE_CIC_014_UNTRUSTED_EVENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\$\{\{\s*github\.event\.(?:comment\.body|issue\.body|issue\.title|pull_request\.body|pull_request\.title|head_commit\.message)\s*\}\}"#).unwrap()
});

// ===========================================================================
// IacScanner Implementation
// ===========================================================================

pub struct IacScanner;

impl IacScanner {
    /// Determines whether a file path has an extension or name matching IaC/CI-CD targets.
    pub fn is_supported_file(path: &Path) -> bool {
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if name.contains("Dockerfile") || name.contains("Containerfile") {
            return true;
        }
        matches!(
            path.extension().and_then(|ext| ext.to_str()),
            Some("tf" | "yaml" | "yml" | "json" | "toml" | "sh" | "bash" | "js" | "mjs" | "cjs" | "ts" | "py")
        )
    }

    /// Scans source code content for Category 15 (Infrastructure & Cloud Defaults)
    /// and Category 14 (CI/CD Pipelines & Repo Automation) vulnerabilities.
    pub fn scan_source(path: &Path, content: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        let target_kind = match path.extension().and_then(|ext| ext.to_str()) {
            Some("js" | "mjs" | "cjs" | "ts" | "tsx" | "jsx") => TargetKind::NodeSourceFile,
            Some("tf" | "yaml" | "yml" | "json" | "toml") => TargetKind::GenericConfigFile,
            Some("py" | "sh" | "bash") => TargetKind::GenericSourceFile,
            _ => {
                let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if file_name.contains("Dockerfile") || file_name.contains("Containerfile") {
                    TargetKind::Dockerfile
                } else {
                    TargetKind::GenericConfigFile
                }
            }
        };

        let is_shell_file = matches!(
            path.extension().and_then(|e| e.to_str()),
            Some("sh" | "bash")
        );

        let lines: Vec<&str> = content.lines().collect();
        let total_lines = lines.len();

        let mut in_run_block = false;
        let mut run_indent = 0;

        for (idx, line) in lines.iter().enumerate() {
            let line_no = idx + 1;
            let current_indent = line.len() - line.trim_start().len();
            let trimmed = line.trim();

            if trimmed.is_empty() {
                continue;
            }

            // Track run: steps in CI/CD YAML files
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

            let is_shell_execution = is_shell_file || in_run_block || is_run_start;

            // Context window (+/- 6 lines) for correlation
            let window_start = idx.saturating_sub(6);
            let window_end = (idx + 7).min(total_lines);
            let context_window = lines[window_start..window_end].join("\n");

            // Lookahead window (+1 to +10 lines)
            let ahead_start = (idx + 1).min(total_lines);
            let ahead_end = (idx + 11).min(total_lines);
            let lookahead_window = if ahead_start < total_lines {
                lines[ahead_start..ahead_end].join("\n")
            } else {
                String::new()
            };

            // Skip pure comment lines unless they are part of test markers
            if trimmed.starts_with("//")
                || trimmed.starts_with('#')
                || trimmed.starts_with('*')
                || trimmed.starts_with("/*")
            {
                continue;
            }

            // ---------------------------------------------------------------
            // Category 15: Infrastructure, Cloud & Defaults
            // ---------------------------------------------------------------

            // 1. BK-AI-INF-002 (CWE-732): Storage bucket/container/DB endpoint accidentally public
            if RE_INF_002_PUBLIC_STORAGE.is_match(trimmed) {
                findings.push(Self::create_finding(
                    "BK-AI-INF-002",
                    "CWE-732",
                    "Storage bucket/container/DB endpoint accidentally public",
                    Severity::High,
                    "2.15 Containers, cloud, infrastructure and runtime defaults",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Buckets and databases must not have public read/write access or allUsers/allAuthenticatedUsers IAM grants",
                    "Storage bucket, Azure container, or database endpoint configured with public access enabled.",
                    "Set bucket ACL to private, enable public access block, and remove allUsers IAM grants.",
                ));
            }

            // 2. BK-AI-INF-005 (CWE-269): IAM policy permits `*` actions/resources or broad role assumption
            if RE_INF_005_WILDCARD_IAM.is_match(trimmed) {
                findings.push(Self::create_finding(
                    "BK-AI-INF-005",
                    "CWE-269",
                    "IAM policy permits `*` actions/resources or broad role assumption",
                    Severity::High,
                    "2.15 Containers, cloud, infrastructure and runtime defaults",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "IAM policies must not use wildcard '*' actions/resources or broad admin/owner roles without constraints",
                    "IAM policy grants wildcard actions ('*') or broad roles (roles/owner, roles/editor) without privilege constraints.",
                    "Scope IAM permissions to specific least-privilege actions and resources required for the workload.",
                ));
            }

            // 3. BK-AI-INF-006 (CWE-284): Security group/network rule opens management/database port to internet
            if RE_INF_006_SENSITIVE_PORT.is_match(trimmed) {
                let has_internet_cidr = context_window.contains("0.0.0.0/0")
                    || context_window.contains("::/0")
                    || context_window.contains("ALL");
                let is_private_ip = trimmed.contains("10.0.")
                    || trimmed.contains("192.168.")
                    || trimmed.contains("172.16.")
                    || context_window.contains("10.0.0.0/")
                    || context_window.contains("192.168.0.0/")
                    || context_window.contains("172.16.0.0/");
                if has_internet_cidr && !is_private_ip {
                    findings.push(Self::create_finding(
                        "BK-AI-INF-006",
                        "CWE-284",
                        "Security group/network rule opens management/database port to internet",
                        Severity::High,
                        "2.15 Containers, cloud, infrastructure and runtime defaults",
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Ports 22, 3389, 5432, 3306, 27017, 6379, 9200, 1433 must never be exposed to 0.0.0.0/0 or ::/0",
                        "Security group or firewall rule exposes administrative or database port to the public internet (0.0.0.0/0).",
                        "Restrict access to management and database ports to authorized corporate IP CIDRs or private VPC bastions.",
                    ));
                }
            }

            // 4. BK-AI-INF-009 (CWE-306): Database/queue/Redis/Elasticsearch has no authentication in reachable environment
            if RE_INF_009_NO_AUTH.is_match(trimmed) {
                let is_empty_pass = trimmed.contains("password") && (trimmed.contains("\"\"") || trimmed.contains("''"));
                let is_datastore = !is_empty_pass
                    || context_window.contains("redis")
                    || context_window.contains("mongo")
                    || context_window.contains("elastic")
                    || context_window.contains("db")
                    || context_window.contains("database")
                    || context_window.contains("client")
                    || context_window.contains("connect")
                    || context_window.contains("queue");
                if is_datastore {
                    findings.push(Self::create_finding(
                        "BK-AI-INF-009",
                        "CWE-306",
                        "Database/queue/Redis/Elasticsearch has no authentication in reachable environment",
                        Severity::High,
                        "2.15 Containers, cloud, infrastructure and runtime defaults",
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Datastores and queues must enforce authentication with non-empty credentials and protected mode enabled",
                        "Database or in-memory datastore configured with authentication disabled or empty credentials.",
                        "Enable authentication, set strong passwords or secret tokens, and enable protected mode.",
                    ));
                }
            }

            // 5. BK-AI-INF-011 (CWE-798): Default credentials, sample tokens or test users active after deployment
            if RE_INF_011_DEFAULT_CREDS.is_match(trimmed) {
                findings.push(Self::create_finding(
                    "BK-AI-INF-011",
                    "CWE-798",
                    "Default credentials, sample tokens or test users active after deployment",
                    Severity::High,
                    "2.15 Containers, cloud, infrastructure and runtime defaults",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Never ship hardcoded default passwords, demo accounts, or test user flags enabled in production configurations",
                    "Default credentials (e.g. admin:admin, root:root) or active test user accounts detected in configuration.",
                    "Replace default passwords with cryptographically secure random credentials loaded from secrets managers.",
                ));
            }

            // 6. BK-AI-INF-012 (CWE-1104): Container image uses unverified / latest base tag with stale vulnerable OS packages
            if let Some(caps) = RE_INF_012_FROM_IMAGE.captures(trimmed) {
                let img = caps.get(1).map(|m| m.as_str()).unwrap_or("");
                let is_latest = trimmed.contains(":latest");
                let is_untagged = !img.is_empty()
                    && !trimmed.contains(':')
                    && !trimmed.contains('@')
                    && img != "scratch"
                    && !context_window.contains(&format!("as {img}"));
                if is_latest || is_untagged {
                    findings.push(Self::create_finding(
                        "BK-AI-INF-012",
                        "CWE-1104",
                        "Container image uses unverified base tag with stale vulnerable OS packages",
                        Severity::Medium,
                        "2.15 Containers, cloud, infrastructure and runtime defaults",
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Container images must specify pinned version tags or SHA-256 digests; ':latest' and untagged base images are forbidden",
                        "Container image uses unpinned ':latest' tag or untagged base image subject to drift and known vulnerabilities.",
                        "Pin container base images to immutable SHA-256 digests or specific immutable release versions.",
                    ));
                }
            } else if RE_INF_012_COMPOSE_LATEST.is_match(trimmed) {
                findings.push(Self::create_finding(
                    "BK-AI-INF-012",
                    "CWE-1104",
                    "Container image uses unverified base tag with stale vulnerable OS packages",
                    Severity::Medium,
                    "2.15 Containers, cloud, infrastructure and runtime defaults",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Container images must specify pinned version tags or SHA-256 digests; ':latest' and untagged base images are forbidden",
                    "Container compose service specifies ':latest' image tag.",
                    "Pin service image tag to specific stable version or digest.",
                ));
            }

            // 7. BK-AI-INF-013 (CWE-778): Infrastructure logs/audit disabled for security-critical asset
            if RE_INF_013_AUDIT_DISABLED.is_match(trimmed) {
                findings.push(Self::create_finding(
                    "BK-AI-INF-013",
                    "CWE-778",
                    "Infrastructure logs/audit disabled for security-critical asset",
                    Severity::Medium,
                    "2.15 Containers, cloud, infrastructure and runtime defaults",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Security logging, audit trails, and log file validation must be explicitly enabled",
                    "Infrastructure configuration disables audit logs, flow logs, or logging validation.",
                    "Enable audit logging, CloudTrail log file validation, and VPC flow logs.",
                ));
            }

            // 8. BK-AI-INF-014 (CWE-250): K8s workloads lack required securityContext / privilege confinement
            if RE_INF_014_K8S_PRIVILEGE.is_match(trimmed) {
                findings.push(Self::create_finding(
                    "BK-AI-INF-014",
                    "CWE-250",
                    "K8s workloads lack required securityContext / privilege confinement",
                    Severity::High,
                    "2.15 Containers, cloud, infrastructure and runtime defaults",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Workload pods must forbid privilege escalation, disallow root user execution, and enforce read-only root filesystems",
                    "Kubernetes workload configures permissive securityContext (privileged: true, allowPrivilegeEscalation: true, or runAsUser: 0).",
                    "Set privileged: false, allowPrivilegeEscalation: false, runAsNonRoot: true, and readOnlyRootFilesystem: true.",
                ));
            }

            // 9. BK-AI-INF-015 (CWE-918): Cloud metadata service accessible from untrusted fetch path
            if RE_INF_015_IMDS_RISK.is_match(trimmed) {
                findings.push(Self::create_finding(
                    "BK-AI-INF-015",
                    "CWE-918",
                    "Cloud metadata service accessible from untrusted fetch path",
                    Severity::High,
                    "2.15 Containers, cloud, infrastructure and runtime defaults",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Instance metadata must require session tokens (IMDSv2) with hop limit constrained to 1 to block container SSRF",
                    "EC2 instance or launch template configures optional IMDS tokens (IMDSv1) or excessive hop limit (> 1).",
                    "Require IMDSv2 by setting http_tokens = 'required' and constrain http_put_response_hop_limit = 1.",
                ));
            }

            // 10. BK-AI-INF-016 (CWE-552): Backups are unencrypted/public/unrestorable or deletion unsafe
            if RE_INF_016_BACKUP_RISK.is_match(trimmed) {
                findings.push(Self::create_finding(
                    "BK-AI-INF-016",
                    "CWE-552",
                    "Backups are unencrypted/public/unrestorable or deletion unsafe",
                    Severity::High,
                    "2.15 Containers, cloud, infrastructure and runtime defaults",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Backups must be encrypted with valid KMS keys and protected by retention locks against unauthenticated deletion",
                    "Backup vault or lifecycle rule configures null KMS keys, disables encryption, or permits zero-retention deletion.",
                    "Configure managed KMS key encryption and enable backup vault retention lock policies.",
                ));
            }

            // ---------------------------------------------------------------
            // Category 14: CI/CD, Build Pipelines & Repo Automation
            // ---------------------------------------------------------------

            // 11. BK-AI-CIC-005 (CWE-829): Build/test executes downloaded untrusted shell script without verification
            if RE_CIC_005_CURL_PIPE_SHELL.is_match(trimmed) {
                let is_guarded = context_window.contains("sha256sum")
                    || context_window.contains("sha256")
                    || context_window.contains("sha512sum")
                    || context_window.contains("gpg --verify")
                    || context_window.contains("checksum");
                if !is_guarded {
                    findings.push(Self::create_finding(
                        "BK-AI-CIC-005",
                        "CWE-829",
                        "Build/test executes downloaded untrusted shell script without verification",
                        Severity::High,
                        "2.14 CI/CD, build pipelines and repository automation",
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Download installation scripts to disk, verify SHA-256 checksum or GPG signature before execution",
                        "Build or CI pipeline downloads remote shell script and executes it directly via pipe without integrity verification.",
                        "Download script to a temporary file, verify its cryptographic hash against an immutable vendor checksum, and execute the verified file.",
                    ));
                }
            }

            // 12. BK-AI-CIC-007 (CWE-829): Unsafe artifact/cache reuse between untrusted PR and release job
            if RE_CIC_007_CACHE_PR_REF.is_match(trimmed) {
                findings.push(Self::create_finding(
                    "BK-AI-CIC-007",
                    "CWE-829",
                    "Unsafe artifact/cache reuse between untrusted PR and release job",
                    Severity::High,
                    "2.14 CI/CD, build pipelines and repository automation",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Key caches strictly on immutable lockfile hashes and isolate PR caches from production release workflows",
                    "CI/CD workflow configures cache keys or restore-keys bound to pull request head refs or untrusted PR numbers.",
                    "Use lockfile hashes (e.g. hashFiles('**/package-lock.json')) for cache keys and avoid restoring PR branches in release pipelines.",
                ));
            }

            // 13. BK-AI-CIC-008 (CWE-284): Deployment triggered without branch/environment approval controls
            if RE_CIC_008_WILDCARD_BRANCH.is_match(trimmed) {
                let has_deploy = content.contains("deploy")
                    || content.contains("production")
                    || content.contains("release");
                let has_environment_gate = context_window.contains("environment:")
                    || lookahead_window.contains("environment:")
                    || content.contains("environment: production")
                    || content.contains("environment: prod");
                if has_deploy && !has_environment_gate {
                    findings.push(Self::create_finding(
                        "BK-AI-CIC-008",
                        "CWE-284",
                        "Deployment triggered without branch/environment approval controls",
                        Severity::High,
                        "2.14 CI/CD, build pipelines and repository automation",
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Constrain deployment triggers to protected branches (e.g. main) and require deployment environments with manual approval protection",
                        "Deployment workflow triggers on wildcard branches without environment gates or approval checks.",
                        "Scope deployment workflow to protected branches and configure an environment gate with required reviewers.",
                    ));
                }
            } else if RE_CIC_008_DEPLOY_NO_APPROVAL.is_match(trimmed) {
                findings.push(Self::create_finding(
                    "BK-AI-CIC-008",
                    "CWE-284",
                    "Deployment triggered without branch/environment approval controls",
                    Severity::High,
                    "2.14 CI/CD, build pipelines and repository automation",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Constrain deployment triggers to protected branches (e.g. main) and require deployment environments with manual approval protection",
                    "Deployment configured with deploy_without_approval enabled.",
                    "Require manual approval gates or environment protection rules before production deployments.",
                ));
            }

            // 14. BK-AI-CIC-009 (CWE-494): Release generated from a different commit than tested/reviewed
            if (content.contains("release") || content.contains("deploy") || content.contains("publish"))
                && RE_CIC_009_MUTABLE_CHECKOUT.is_match(trimmed)
            {
                findings.push(Self::create_finding(
                    "BK-AI-CIC-009",
                    "CWE-494",
                    "Release generated from a different commit than tested/reviewed",
                    Severity::High,
                    "2.14 CI/CD, build pipelines and repository automation",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Bind release builds to the exact immutable reviewed commit SHA (${{ github.sha }}) rather than moving branch heads (main/master)",
                    "Release workflow checks out mutable branch head (main/master) instead of the exact tested commit SHA.",
                    "Pin checkout step to '${{ github.sha }}' or avoid overriding the default immutable commit reference.",
                ));
            }

            // 15. BK-AI-CIC-010 (None): Test/security jobs optional, skipped or configured with continue-on-error while reported green
            if RE_CIC_010_CONTINUE_ON_ERROR.is_match(trimmed) {
                let is_test_or_security = context_window.contains("test")
                    || context_window.contains("security")
                    || context_window.contains("scan")
                    || context_window.contains("lint")
                    || context_window.contains("clippy")
                    || context_window.contains("trivy")
                    || context_window.contains("snyk")
                    || context_window.contains("audit");
                if is_test_or_security {
                    findings.push(Self::create_finding(
                        "BK-AI-CIC-010",
                        "None",
                        "Test/security jobs optional, skipped or configured with continue-on-error while reported green",
                        Severity::High,
                        "2.14 CI/CD, build pipelines and repository automation",
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Test suites and security gates must block pipeline completion on failure; masking errors with continue-on-error is prohibited",
                        "CI/CD workflow configures continue-on-error: true on test or security scanning job, allowing failures to pass unnoticed.",
                        "Remove continue-on-error: true from test and security scan steps so failures properly fail the pipeline.",
                    ));
                }
            } else if RE_CIC_010_MASKED_ERROR.is_match(trimmed) {
                findings.push(Self::create_finding(
                    "BK-AI-CIC-010",
                    "None",
                    "Test/security jobs optional, skipped or configured with continue-on-error while reported green",
                    Severity::High,
                    "2.14 CI/CD, build pipelines and repository automation",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Test suites and security gates must block pipeline completion on failure; masking errors with continue-on-error or '|| true' is prohibited",
                    "Test or security scanning command suppresses failure codes via '|| true' or '|| exit 0'.",
                    "Remove shell error suppression from test and security scan commands.",
                ));
            }

            // 16. BK-AI-CIC-011 (CWE-250): Package scripts execute with privileged token, network and filesystem by default
            if RE_CIC_011_INSTALL_CMD.is_match(trimmed) {
                let has_token_in_context = context_window.contains("GITHUB_TOKEN")
                    || context_window.contains("AWS_SECRET_ACCESS_KEY")
                    || context_window.contains("NPM_TOKEN");
                let has_ignore_scripts = trimmed.contains("--ignore-scripts")
                    || context_window.contains("--ignore-scripts");
                if has_token_in_context && !has_ignore_scripts {
                    findings.push(Self::create_finding(
                        "BK-AI-CIC-011",
                        "CWE-250",
                        "Package scripts execute with privileged token, network and filesystem by default",
                        Severity::High,
                        "2.14 CI/CD, build pipelines and repository automation",
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Run package installations with --ignore-scripts and avoid passing privileged tokens or cloud credentials to install steps",
                        "Dependency installation executes package lifecycle scripts with sensitive credentials (GITHUB_TOKEN / secrets) exposed in environment.",
                        "Add '--ignore-scripts' to npm/yarn/pnpm install commands and segregate secrets from build lifecycle scripts.",
                    ));
                }
            } else if RE_CIC_011_ENABLE_SCRIPTS.is_match(trimmed) {
                findings.push(Self::create_finding(
                    "BK-AI-CIC-011",
                    "CWE-250",
                    "Package scripts execute with privileged token, network and filesystem by default",
                    Severity::High,
                    "2.14 CI/CD, build pipelines and repository automation",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Run package installations with --ignore-scripts and avoid passing privileged tokens or cloud credentials to install steps",
                    "Package installation explicitly enables script execution or foreground scripts in CI.",
                    "Use --ignore-scripts and run vetted build scripts explicitly.",
                ));
            }

            // 17. BK-AI-CIC-012 (CWE-494): Artifact signing/attestation missing where project trust contract requires it
            if RE_CIC_012_PROVENANCE_DISABLED.is_match(trimmed) {
                findings.push(Self::create_finding(
                    "BK-AI-CIC-012",
                    "CWE-494",
                    "Artifact signing/attestation missing where project trust contract requires it",
                    Severity::High,
                    "2.14 CI/CD, build pipelines and repository automation",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Sign released artifacts and container images with Cosign/Sigstore and generate SLSA build provenance",
                    "Artifact publishing configuration explicitly disables provenance generation or code signing.",
                    "Enable provenance attestation ('provenance: true') and sign artifacts using Cosign or Sigstore.",
                ));
            }

            // 18. BK-AI-CIC-013 (CWE-863): PR bot auto-merges without review of changed security boundaries
            if RE_CIC_013_AUTOMERGE.is_match(trimmed) {
                let has_review_guard = context_window.contains("review")
                    || context_window.contains("APPROVED")
                    || context_window.contains("approved")
                    || context_window.contains("required_reviews");
                let is_zero_reviews = trimmed.contains("required_reviews: 0") || trimmed.contains("required_reviews = 0");
                if !has_review_guard || is_zero_reviews {
                    findings.push(Self::create_finding(
                        "BK-AI-CIC-013",
                        "CWE-863",
                        "PR bot auto-merges without review of changed security boundaries",
                        Severity::High,
                        "2.14 CI/CD, build pipelines and repository automation",
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Disable unattended PR auto-merges without mandatory human code review approvals and branch protection evaluation",
                        "Pull request automation enables unattended auto-merging without requiring approval reviews.",
                        "Require mandatory code reviews and security approvals before enabling automated merging.",
                    ));
                }
            }

            // 19. BK-AI-CIC-014 (CWE-78): Workflow writes to repo based on arbitrary external issue/comment content
            if (is_shell_execution || trimmed.starts_with("run:"))
                && RE_CIC_014_UNTRUSTED_EVENT.is_match(trimmed)
                && !trimmed.starts_with("env:")
            {
                findings.push(Self::create_finding(
                    "BK-AI-CIC-014",
                    "CWE-78",
                    "Workflow writes to repo based on arbitrary external issue/comment content",
                    Severity::High,
                    "2.14 CI/CD, build pipelines and repository automation",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Never evaluate untrusted event payloads directly inside inline run scripts; pass them via intermediate environment variables",
                    "GitHub Actions workflow directly interpolates untrusted external payload (${{ github.event.* }}) into shell execution.",
                    "Map untrusted context values to environment variables and reference them securely via shell variables ($VAR).",
                ));
            }
        }

        findings
    }

    /// Helper to construct standardized Finding instances.
    #[allow(clippy::too_many_arguments)]
    fn create_finding(
        rule_id: &str,
        cwe: &str,
        title: &str,
        severity: Severity,
        category: &str,
        path: &Path,
        target_kind: &TargetKind,
        line_no: usize,
        snippet: &str,
        safe_threshold: &str,
        description: &str,
        remediation: &str,
    ) -> Finding {
        let file_tag = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("source");
        let short_id = rule_id.trim_start_matches("BK-AI-");
        let finding_id = format!("{}-{}-L{}", short_id, file_tag, line_no);

        let mut finding = Finding::new(
            finding_id,
            CveId::Custom {
                id: rule_id.to_string(),
                title: title.to_string(),
            },
            severity,
            target_kind.clone(),
            Some(path.to_path_buf()),
            Some(line_no),
            snippet,
            safe_threshold,
            description,
            remediation,
        );
        finding.detector_id = "iac-security".to_string();
        finding.detector_version = "1.0.0".to_string();
        finding.category = category.to_string();
        finding.affectedness = Affectedness::ConfirmedAffected;
        finding.reachability = Reachability::PotentiallyReachable;
        finding.confidence = Confidence::High;
        finding.evidence_certainty = EvidenceCertainty::StronglySupported;
        if cwe != "None" && !cwe.is_empty() {
            finding.advisory_ids.push(cwe.to_string());
        }
        finding.advisory_ids.push(rule_id.to_string());
        finding.evidence_refs.push(EvidenceRef {
            location: format!("{}:{}", path.display(), line_no),
            line_number: Some(line_no),
            snippet: Some(snippet.trim().to_string()),
            sha256: None,
        });
        finding.compute_dedupe_fingerprint();
        finding
    }
}
