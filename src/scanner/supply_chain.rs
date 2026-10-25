#![allow(dead_code)]

use crate::types::*;
use regex::Regex;
use std::path::Path;
use std::sync::LazyLock;

// ----------------------------------------------------------------------------
// Category 13: Packages, Dependency Resolution & Supply Chain (BK-AI-SCA-003..014)
// ----------------------------------------------------------------------------

// BK-AI-SCA-003 (CWE-829): Package name hallucinated by AI, nonexistent or typo-squatted
static RE_SCA_003_TYPOSQUAT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:["'](?:reqeusts|requets|requsets|colros|coloram|lodahs|loadsh|expres|expresjs|react-dom-server-side|tensorflow-gpu-cuda|openai-assistant-api|urllib4|beautifulsoup5|crypto-js-aes|huggingface-cli-login|langchain-openai-secret|flask-login-bcrypt|colorama-v2)["']|\b(?:import|from|require)\s*\(?['"](?:reqeusts|requets|requsets|colros|coloram|lodahs|loadsh|expres|expresjs|react-dom-server-side|tensorflow-gpu-cuda|openai-assistant-api|urllib4|beautifulsoup5|crypto-js-aes|huggingface-cli-login|langchain-openai-secret|flask-login-bcrypt|colorama-v2)['"]|\b(?:reqeusts|requets|colros|lodahs|loadsh|expresjs|urllib4|beautifulsoup5)\s*[=<>~^:]|\bfrom\s+(?:reqeusts|requets|colros|lodahs|loadsh)\s+import|\bimport\s+(?:reqeusts|requets|colros|lodahs|loadsh)\b)"#)
        .unwrap()
});

// BK-AI-SCA-004 (CWE-427): Dependency confusion via ambiguous public/private package source
static RE_SCA_004_EXTRA_INDEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:extra-index-url\s*=\s*https?://|--extra-index-url\s+https?://|registry\s*=\s*https?://registry\.npmjs\.org\s*(?:#|//).*internal|//.*dependency\s+confusion|#.*dependency\s+confusion)"#)
        .unwrap()
});

static RE_SCA_004_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:@company:registry|@internal:registry|scoped\s+registry|trusted-host|verified-private-index|priority-index)"#)
        .unwrap()
});

// BK-AI-SCA-006 (CWE-829): Git URL, branch, floating tag or unpinned remote source used as dependency
static RE_SCA_006_UNPINNED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:git\+https?://[^"\s#@]+[#@](?:main|master|dev|head|trunk|latest)|github:[^"\s#@]+[#@](?:master|main|dev|head)|(?:branch|tag)\s*=\s*["'](?:main|master|dev|latest)["']|"(?:[^"]+)":\s*"(?:latest|\*)"|'(?:[^']+)':\s*'(?:latest|\*)'|//.*unpinned\s+(?:remote|git|dependency)|#.*unpinned\s+(?:remote|git|dependency))"#)
        .unwrap()
});

static RE_SCA_006_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)(?:rev\s*=\s*["'][0-9a-f]{40}["']|#[0-9a-f]{40}|@[0-9a-f]{40}|"[\^~]?\d+\.\d+)"#,
    )
    .unwrap()
});

// BK-AI-SCA-007 (CWE-1104): Lockfile missing/stale or differs from manifest resolution
static RE_SCA_007_BYPASS_LOCK: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:--(?:no-package-lock|no-lockfile|no-lock)\b|--frozen-lockfile=false\b|npm\s+install\s+--no-save\b|//.*(?:lockfile missing|stale lockfile|differs from manifest|bypass lockfile)|#.*(?:lockfile missing|stale lockfile|differs from manifest|bypass lockfile))"#)
        .unwrap()
});

static RE_SCA_007_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:--frozen-lockfile\b|--frozen-lockfile=true\b|--immutable\b|npm\s+ci\b|cargo\s+(?:build|test)\s+--locked\b)"#)
        .unwrap()
});

// BK-AI-SCA-008 (CWE-1104): Transitive dependency ignored or exact dependency graph unknown
static RE_SCA_008_TRANSITIVE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:--legacy-peer-deps\b|--no-audit\b|--audit-level\s*=\s*none\b|audit\s*=\s*false\b|skip_transitive\s*=\s*(?:true|True)|ignore_transitive\s*=\s*(?:true|True)|pip-audit\s+.*--ignore-vuln\b|//.*(?:transitive dependency ignored|exact dependency graph unknown|disabling transitive auditing)|#.*(?:transitive dependency ignored|exact dependency graph unknown|disabling transitive auditing))"#)
        .unwrap()
});

static RE_SCA_008_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:--audit-level\s*=\s*(?:high|critical|moderate)|audit\s*=\s*true\b)"#)
        .unwrap()
});

// BK-AI-SCA-009 (None): Advisory reported from the wrong OS/distro/library ecosystem
static RE_SCA_009_ECOSYSTEM_MISMATCH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:ecosystem\s*[:=]\s*['"]Debian['"].*(?:alpine|apk)|distro\s*[:=]\s*['"]debian['"].*apk|query_osv\s*\([^)]*ecosystem\s*=\s*['"]Debian['"][^)]*\.apk|query_osv\s*\([^)]*ecosystem\s*=\s*['"]PyPI['"][^)]*\.js|query_osv\s*\([^)]*ecosystem\s*=\s*['"]npm['"][^)]*\.py|//.*(?:wrong OS|wrong distro|mismatched ecosystem)|#.*(?:wrong OS|wrong distro|mismatched ecosystem))"#)
        .unwrap()
});

static RE_SCA_009_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:ecosystem\s*[:=]\s*['"]Alpine['"]|ecosystem\s*[:=]\s*['"]PyPI['"].*\.py|ecosystem\s*[:=]\s*['"]npm['"].*\.js|ecosystem\s*[:=]\s*['"]crates\.io['"])"#)
        .unwrap()
});

// BK-AI-SCA-010 (None): Report assumes no CVEs after OSV/NVD/network lookup failure
static RE_SCA_010_ASSUME_CLEAN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:catch\s*(?:\([^)]*\))?\s*\{\s*(?:return\s+\[\];|return\s+\{\s*(?:vulnerabilities|cves)\s*:\s*\[\]\s*\};?)|except\s+(?:RequestException|Timeout|Exception|URLError)[^:]*:\s*(?:return\s+\[\]|return\s+\{\s*["']vulnerabilities["']\s*:\s*\[\]\s*\})|//.*(?:assumes? no CVEs after.*failure|clean report on network (?:timeout|failure))|#.*(?:assumes? no CVEs after.*failure|clean report on network (?:timeout|failure)))"#)
        .unwrap()
});

static RE_SCA_010_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:throw\b|raise\b|ScanStatus::(?:Error|Partial)|ResultClassification::NotAssessed|return\s+Err\b)"#)
        .unwrap()
});

// BK-AI-SCA-011 (CWE-1104): SBOM missing dependencies that appear in shipped binaries/images
static RE_SCA_011_SBOM_MISSING: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:COPY\s+--from=[^\s]+\s+/usr/(?:local/)?lib/[^\s]+(?:\.so|\.dylib|\.dll)|syft\s+packages\s+.*--exclude\b|//.*(?:sbom missing dependencies|untracked binary in sbom|dependencies not in sbom)|#.*(?:sbom missing dependencies|untracked binary in sbom|dependencies not in sbom))"#)
        .unwrap()
});

static RE_SCA_011_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:syft\s+dir:/|cyclonedx-generate|record-sbom|sbom-complete)"#).unwrap()
});

// BK-AI-SCA-012 (CWE-1104): Vendored or copied code never checked because absent from manifest
static RE_SCA_012_VENDORED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:--exclude\s*=\s*['"]?vendor/['"]?|ignore\s*:\s*\[[^\]]*['"]vendor/['"]|skip\s*:\s*\[[^\]]*['"]third_party['"]|/\*\s*Vendored from [a-zA-Z0-9_-]+ v\d|//.*(?:vendored or copied code never checked|vendored code absent from manifest)|#.*(?:vendored or copied code never checked|vendored code absent from manifest))"#)
        .unwrap()
});

static RE_SCA_012_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:--include\s*=\s*['"]?vendor/['"]?|scan-vendored|submodule-checked)"#)
        .unwrap()
});

// BK-AI-SCA-013 (CWE-829): Unreviewed model, dataset, prompt pack, IDE extension or MCP server dependency
static RE_SCA_013_UNREVIEWED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:from_pretrained\s*\(\s*['"][a-zA-Z0-9_-]+/[a-zA-Z0-9_.-]+['"]\s*\)|load_dataset\s*\(\s*['"][a-zA-Z0-9_-]+/[a-zA-Z0-9_.-]+['"]\s*\)|npx\s+(?:-y\s+)?[a-zA-Z0-9_@/-]*mcp-server\b|//.*(?:unreviewed model|unreviewed dataset|unreviewed prompt pack|unreviewed mcp)|#.*(?:unreviewed model|unreviewed dataset|unreviewed prompt pack|unreviewed mcp))"#)
        .unwrap()
});

static RE_SCA_013_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:revision\s*=\s*['"][0-9a-f]{40}['"]|verified_publisher\s*=\s*True|checksum\s*=|integrity\s*=)"#)
        .unwrap()
});

// BK-AI-SCA-014 (CWE-829): License/provenance/source integrity checks omitted for added security-critical dependency
static RE_SCA_014_INTEGRITY_OMITTED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:(?:curl|wget)\s+[^|;\n]+\s*\|\s*(?:bash|sh|zsh)\b|curl\s+.*-o\s+/usr/local/bin/[a-zA-Z0-9_-]+\s*&&\s*chmod\s+\+x|//.*(?:integrity checks omitted|no checksum verification|unverified binary download)|#.*(?:integrity checks omitted|no checksum verification|unverified binary download))"#)
        .unwrap()
});

static RE_SCA_014_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:sha256sum\s+-c|gpg\s+--verify|cosign\s+verify|shasum\s+-a\s*256)"#)
        .unwrap()
});

// ----------------------------------------------------------------------------
// Category 23: Model, Plugin and Agent Supply-Chain Integrity (BK-AI-AGS-001..012)
// ----------------------------------------------------------------------------

// BK-AI-AGS-001 (None): Model weights downloaded from unknown or mutable origin
static RE_AGS_001_MUTABLE_ORIGIN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:from_pretrained\s*\(\s*['"]http://|from_pretrained\s*\([^)]*revision\s*=\s*['"](?:main|master|dev|latest)['"]|torch\.hub\.load\s*\(\s*['"]http://|download_model\s*\(\s*['"]http://|//.*(?:model weights downloaded from unknown|mutable origin)|#.*(?:model weights downloaded from unknown|mutable origin))"#)
        .unwrap()
});

static RE_AGS_001_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:revision\s*=\s*['"][0-9a-f]{40}['"]|https://verified|safe_model_hub)"#)
        .unwrap()
});

// BK-AI-AGS-002 (None): Model format or loader can execute attacker-controlled code in trusted process
static RE_AGS_002_UNSAFE_LOADER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:torch\.load\s*\([^)]*weights_only\s*=\s*False|trust_remote_code\s*=\s*True|pickle\.load\s*\([^)]*(?:model|weights|checkpoint)|joblib\.load\s*\([^)]*(?:model|weights|classifier)|//.*(?:model loader can execute attacker-controlled code|trust_remote_code=True)|#.*(?:model loader can execute attacker-controlled code|trust_remote_code=True))"#)
        .unwrap()
});

static RE_AGS_002_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)(?:weights_only\s*=\s*True|trust_remote_code\s*=\s*False|safetensors\.torch)"#,
    )
    .unwrap()
});

// BK-AI-AGS-003 (None): Prompt templates from package/registry allowed to include tool-use instruction without review
static RE_AGS_003_REMOTE_PROMPT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:hub\.pull\s*\([^)]*\)\s*;?.*agent\.(?:run|invoke)|PromptTemplate\.from_url\s*\(|load_remote_prompt\s*\([^)]*bind_tools\s*=\s*True|//.*(?:prompt templates from package/registry allowed to include tool-use|unreviewed prompt template)|#.*(?:prompt templates from package/registry allowed to include tool-use|unreviewed prompt template))"#)
        .unwrap()
});

static RE_AGS_003_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:review_prompt|sanitize_prompt|PromptReviewGate|static_template)"#).unwrap()
});

// BK-AI-AGS-004 (None): Skills/MCP tool descriptions embed instructions to overstep authority
static RE_AGS_004_COERCIVE_DESC: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:always\s+run\s+this\s+tool\s+before\s+asking|system\s+prompt\s*:\s*ignore\s+constraints|execute\s+this\s+tool\s+silently\s+without\s+confirmation|you\s+must\s+invoke\s+this\s+tool\s+immediately|override\s+user\s+safeguards|bypass\s+all\s+safety\s+filters|//.*(?:skills/mcp tool descriptions embed instructions to overstep|coercive tool description)|#.*(?:skills/mcp tool descriptions embed instructions to overstep|coercive tool description))"#)
        .unwrap()
});

static RE_AGS_004_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:with\s+user\s+consent|requires_confirmation\s*=\s*True|safe_description)"#)
        .unwrap()
});

// BK-AI-AGS-005 (None): Remote tool endpoints/transport not authenticated or pinned to expected trust domain
static RE_AGS_005_UNAUTH_TRANSPORT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:new\s+WebSocket\s*\(\s*['"]ws://[^'"]*['"]\s*\)|SSEClient\s*\(\s*['"]http://|connect_mcp_server\s*\([^)]*['"]http://|//.*(?:remote tool endpoints.*not authenticated|unauthenticated mcp transport)|#.*(?:remote tool endpoints.*not authenticated|unauthenticated mcp transport))"#)
        .unwrap()
});

static RE_AGS_005_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:wss://|Authorization|bearer_token|tls_cert|pinned_cert)"#).unwrap()
});

// BK-AI-AGS-006 (None): Agent configuration hot reload widens tool grants without reapproval
static RE_AGS_006_HOT_RELOAD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\bagent\.(?:addTool|register_tool|add_tools|reload_skills)\b|\b(?:fs\.watch|watchdog|on_file_change)\b|hot_reload_tools\s*=\s*True|auto_reload_tools\s*:\s*true|//.*(?:agent configuration hot reload widens tool grants|dynamic reload without reapproval)|#.*(?:agent configuration hot reload widens tool grants|dynamic reload without reapproval))"#)
        .unwrap()
});

static RE_AGS_006_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:require_approval\s*=\s*True|confirm_with_user|human_confirmation)"#)
        .unwrap()
});

// BK-AI-AGS-007 (None): Credentials copied into agent prompts, state dumps or debugging traces
static RE_AGS_007_CREDENTIAL_IN_PROMPT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:(?:system_prompt|prompt|instructions)\s*(?:\+=|=)\s*f?['"][^'"]*(?:api_key|secret_key|password|bearer|auth_token|access_token|private_key)\s*[:=]\s*\{[a-zA-Z0-9_]+\}|(?:system_prompt|prompt)\s*=\s*.*(?:os\.environ|process\.env)|//.*(?:credentials copied into agent prompt|dumping env into system prompt|secret leak to model)|#.*(?:credentials copied into agent prompt|dumping env into system prompt|secret leak to model))"#)
        .unwrap()
});

static RE_AGS_007_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:redact_secret|mask_credential|sanitize_prompt|token_placeholder)"#)
        .unwrap()
});

// BK-AI-AGS-008 (None): Agent can use network fetcher to reach cloud metadata/internal-only systems
static RE_AGS_008_UNRESTRICTED_FETCH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:allowed_hosts\s*[:=]\s*\[\s*['"]\*['"]\s*\]|allow_internal_ips\s*=\s*True|allow_private_networks\s*=\s*True|allow_localhost\s*=\s*True|AgentTool\s*\([^)]*block_private\s*=\s*False|//.*(?:agent can use network fetcher to reach cloud metadata|unrestricted network tool)|#.*(?:agent can use network fetcher to reach cloud metadata|unrestricted network tool))"#)
        .unwrap()
});

static RE_AGS_008_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:block_private_ips\s*=\s*True|allow_internal_ips\s*=\s*False|private_range_filter)"#)
        .unwrap()
});

// BK-AI-AGS-009 (None): Unsigned/unreviewed policy files dynamically loaded from repository branch
static RE_AGS_009_DYNAMIC_POLICY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:(?:fetch|requests\.get|urllib\.request\.urlopen)\s*\(\s*['"]https://raw\.githubusercontent\.com/[^'"]+/(?:main|master|dev)/[^'"]*(?:policy|guardrail|rules|eval)\.(?:yaml|json|py|txt)['"]|load_policy_from_branch\s*\(|//.*(?:unsigned/unreviewed policy files dynamically loaded|policy loaded from branch without signature)|#.*(?:unsigned/unreviewed policy files dynamically loaded|policy loaded from branch without signature))"#)
        .unwrap()
});

static RE_AGS_009_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:verify_signature|signed_policy|sha256_pinned|ed25519_verify)"#).unwrap()
});

// BK-AI-AGS-010 (None): Approval result can be fabricated by another agent/tool response
static RE_AGS_010_FABRICATED_APPROVAL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:if\s+(?:tool_output|tool_response|response|result|res|agent_response)(?:\.get\s*\(\s*['"]approved['"]\s*\)|\[\s*['"](?:approved|is_approved|user_confirmed)['"]\s*\])\s*==\s*(?:True|true|1)|(?:is_human_approved|human_approval)\s*=\s*(?:tool_result|response)\.get\s*\(\s*['"]approved['"]|//.*(?:approval result can be fabricated|tool response treated as human approval)|#.*(?:approval result can be fabricated|tool response treated as human approval))"#)
        .unwrap()
});

static RE_AGS_010_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:verify_human_approval|session\.is_user_authenticated|cryptographic_approval_token)"#)
        .unwrap()
});

// BK-AI-AGS-011 (None): Retry after partial tool execution duplicates privileged action
static RE_AGS_011_RETRY_ACTION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:@retry\s*\([^)]*\)\s*(?:\n\s*)?(?:def|async def)\s+(?:charge_|transfer_|pay_|execute_trade|delete_user|send_payment)|retry_on_timeout\s*=\s*True|while\s+attempts\s*<\s*\d+:\s*(?:try:\s*)?tool\.execute|//.*(?:retry after partial tool execution duplicates|non-idempotent tool retried)|#.*(?:retry after partial tool execution duplicates|non-idempotent tool retried))"#)
        .unwrap()
});

static RE_AGS_011_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:idempotency_key|idempotent_token|IdempotencyKey|transaction_token)"#)
        .unwrap()
});

// BK-AI-AGS-012 (None): Nested tool invocation delegates greater permissions than initiating actor owns
static RE_AGS_012_DELEGATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:spawn_subagent\s*\([^)]*tools\s*=\s*\[\s*['"]\*['"]\s*\]|delegate_task\s*\([^)]*capabilities\s*=\s*['"]ALL['"]|create_child_agent\s*\([^)]*elevate\s*=\s*True|subagent\.permissions\s*=\s*\[\s*['"]admin['"]\s*\]|//.*(?:nested tool invocation delegates greater permissions|subagent elevated privileges)|#.*(?:nested tool invocation delegates greater permissions|subagent elevated privileges))"#)
        .unwrap()
});

static RE_AGS_012_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:parent\.tools\.intersection|subset_permissions|attenuate_permissions|least_privilege)"#)
        .unwrap()
});

pub struct SupplyChainScanner;

impl SupplyChainScanner {
    /// Checks whether a given path is a file format supported by SupplyChainScanner.
    pub fn is_supported_file(path: &Path) -> bool {
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if matches!(
            name,
            "package.json"
                | "package-lock.json"
                | "Cargo.toml"
                | "Cargo.lock"
                | "requirements.txt"
                | "Pipfile"
                | "Pipfile.lock"
                | "go.mod"
                | "go.sum"
                | "composer.json"
                | "composer.lock"
                | "Dockerfile"
                | "Containerfile"
                | ".npmrc"
                | "pip.conf"
        ) {
            return true;
        }

        matches!(
            path.extension().and_then(|e| e.to_str()),
            Some(
                "js" | "mjs"
                    | "cjs"
                    | "ts"
                    | "tsx"
                    | "jsx"
                    | "py"
                    | "go"
                    | "rs"
                    | "json"
                    | "yaml"
                    | "yml"
                    | "toml",
            )
        )
    }

    /// Scans source code and dependency manifests for software supply-chain and AI agent supply integrity risks.
    pub fn scan_source(path: &Path, content: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        let target_kind = match path.file_name().and_then(|n| n.to_str()) {
            Some("package.json") => TargetKind::NodePackageManifest,
            Some("package-lock.json") => TargetKind::NodeLockfile,
            Some("Cargo.toml") => TargetKind::GenericConfigFile,
            Some("Cargo.lock") => TargetKind::CargoLockManifest,
            Some("go.mod") => TargetKind::GoModManifest,
            Some("composer.json") => TargetKind::ComposerManifest,
            Some("composer.lock") => TargetKind::ComposerLockfile,
            Some("requirements.txt" | "Pipfile" | "pyproject.toml" | ".npmrc" | "pip.conf") => {
                TargetKind::GenericConfigFile
            }
            _ => match path.extension().and_then(|e| e.to_str()) {
                Some("js" | "mjs" | "cjs" | "ts" | "tsx" | "jsx") => TargetKind::NodeSourceFile,
                Some("json" | "yaml" | "yml" | "toml") => TargetKind::GenericConfigFile,
                _ => TargetKind::GenericSourceFile,
            },
        };

        let cat_13 = "2.13 Packages, dependency resolution and software supply chain";
        let cat_23 = "2.23 Model, plugin and agent supply-chain integrity";

        let lines: Vec<&str> = content.lines().collect();
        let content_lower = content.to_lowercase();
        let content_has_vuln_context = content_lower.contains("osv")
            || content_lower.contains("cve")
            || content_lower.contains("vulnerabilit")
            || content_lower.contains("advisory");

        for (idx, line) in lines.iter().enumerate() {
            let line_no = idx + 1;
            let trimmed = line.trim();

            if trimmed.is_empty() {
                continue;
            }

            let is_comment = trimmed.starts_with("//")
                || trimmed.starts_with('#')
                || trimmed.starts_with('*')
                || trimmed.starts_with("/*");

            if is_comment {
                let lower = trimmed.to_lowercase();

                // If comment explicitly indicates a safe/verified pattern, skip it
                if lower.contains("safe:")
                    || lower.contains("verified")
                    || lower.contains("remediation:")
                    || lower.contains("pinned to sha")
                    || lower.contains("human_confirmation")
                    || lower.contains("weights_only=true")
                    || lower.contains("trust_remote_code=false")
                {
                    continue;
                }

                // Comment-based trigger evaluation
                if lower.contains("typosquat")
                    || lower.contains("hallucinated package")
                    || lower.contains("nonexistent package")
                    || lower.contains("unverified package name")
                {
                    findings.push(Self::create_finding(
                        "BK-AI-SCA-003",
                        Some("CWE-829"),
                        "Package name hallucinated by AI, nonexistent or typo-squatted",
                        Severity::High,
                        cat_13,
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Verify package names against canonical registries and block unverified or typo-squatted names",
                        "Dependency specification contains a known typosquatted or AI-hallucinated package name.",
                        "Audit package name against canonical package index (npm, PyPI, crates.io) and replace with legitimate package.",
                    ));
                    continue;
                }

                if lower.contains("dependency confusion")
                    || lower.contains("ambiguous package source")
                    || lower.contains("extra-index-url without scope")
                {
                    findings.push(Self::create_finding(
                        "BK-AI-SCA-004",
                        Some("CWE-427"),
                        "Dependency confusion via ambiguous public/private package source",
                        Severity::High,
                        cat_13,
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Enforce scoped namespace registry mappings and prohibit ambiguous public/private fallback",
                        "Configuration specifies extra index URLs or unscoped registries without namespace protection, risking dependency confusion.",
                        "Scope internal packages under an organizational prefix (e.g. @company/) and map explicitly to private registries.",
                    ));
                    continue;
                }

                if lower.contains("unpinned remote source")
                    || lower.contains("floating tag")
                    || lower.contains("unpinned git")
                    || lower.contains("floating branch")
                {
                    findings.push(Self::create_finding(
                        "BK-AI-SCA-006",
                        Some("CWE-829"),
                        "Git URL, branch, floating tag or unpinned remote source used as dependency",
                        Severity::Medium,
                        cat_13,
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Pin all remote dependencies to immutable cryptographic commit hashes or exact release versions",
                        "Dependency resolves from a floating Git branch, floating tag, or wildcard version instead of an immutable revision.",
                        "Pin Git dependencies to a full 40-character commit SHA or use an exact, immutable release tag.",
                    ));
                    continue;
                }

                if lower.contains("lockfile missing")
                    || lower.contains("stale lockfile")
                    || lower.contains("differs from manifest")
                    || lower.contains("bypass lockfile")
                {
                    findings.push(Self::create_finding(
                        "BK-AI-SCA-007",
                        Some("CWE-1104"),
                        "Lockfile missing/stale or differs from manifest resolution",
                        Severity::Medium,
                        cat_13,
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Maintain up-to-date lockfiles committed to version control and enforce deterministic resolution",
                        "Dependency lockfile is missing, bypassed via CLI flags, or out-of-sync with manifest.",
                        "Generate and commit package-lock.json / Cargo.lock, and use --frozen-lockfile or npm ci in CI/CD builds.",
                    ));
                    continue;
                }

                if lower.contains("transitive dependency ignored")
                    || lower.contains("exact dependency graph unknown")
                    || lower.contains("disabling transitive auditing")
                {
                    findings.push(Self::create_finding(
                        "BK-AI-SCA-008",
                        Some("CWE-1104"),
                        "Transitive dependency ignored or exact dependency graph unknown",
                        Severity::Medium,
                        cat_13,
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Audit and verify the complete transitive dependency graph without suppressing audits",
                        "Transitive dependency verification is disabled or bypassed (e.g. --legacy-peer-deps, --no-audit).",
                        "Enable full transitive vulnerability auditing and resolve peer dependency conflicts rather than bypassing checks.",
                    ));
                    continue;
                }

                if lower.contains("wrong os")
                    || lower.contains("wrong distro")
                    || lower.contains("wrong ecosystem")
                    || lower.contains("mismatched ecosystem")
                {
                    findings.push(Self::create_finding(
                        "BK-AI-SCA-009",
                        None,
                        "Advisory reported from the wrong OS/distro/library ecosystem",
                        Severity::Medium,
                        cat_13,
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Disambiguate advisory lookup queries to match the target OS, distribution, and package ecosystem",
                        "Security advisory lookup applies vulnerability data from an incompatible operating system or ecosystem.",
                        "Configure vulnerability scanners with explicit target ecosystem tags (e.g. Alpine vs Debian, PyPI vs npm).",
                    ));
                    continue;
                }

                if lower.contains("assumes no cves after")
                    || lower.contains("clean report on network")
                    || lower.contains("suppress lookup error")
                {
                    findings.push(Self::create_finding(
                        "BK-AI-SCA-010",
                        None,
                        "Report assumes no CVEs after OSV/NVD/network lookup failure",
                        Severity::High,
                        cat_13,
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Fail closed with PARTIAL or ERROR status when external vulnerability databases are unreachable",
                        "Scanner suppresses network or lookup exceptions and falsely reports 0 vulnerabilities when database fails.",
                        "Propagate network errors and classify scan status as Partial or Error rather than returning empty findings.",
                    ));
                    continue;
                }

                if lower.contains("sbom missing dependencies")
                    || lower.contains("untracked binary in sbom")
                    || lower.contains("dependencies not in sbom")
                {
                    findings.push(Self::create_finding(
                        "BK-AI-SCA-011",
                        Some("CWE-1104"),
                        "SBOM missing dependencies that appear in shipped binaries/images",
                        Severity::Medium,
                        cat_13,
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Ensure Software Bill of Materials (SBOM) comprehensively captures all runtime libraries and shipped binaries",
                        "Container build or release pipeline copies dynamic libraries or binaries without recording them in the SBOM.",
                        "Generate SBOM from final shipped container images and include all vendored dynamic shared objects.",
                    ));
                    continue;
                }

                if lower.contains("vendored or copied code never checked")
                    || lower.contains("vendored code absent from manifest")
                    || lower.contains("vendored from")
                {
                    findings.push(Self::create_finding(
                        "BK-AI-SCA-012",
                        Some("CWE-1104"),
                        "Vendored or copied code never checked because absent from manifest",
                        Severity::Medium,
                        cat_13,
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Include vendored and third-party directories in security scanning and inventory tracking",
                        "Vendored code in vendor/ or third_party/ is excluded from security auditing and absent from manifest tracking.",
                        "Add vendored directories to scanner inclusion lists or manage dependencies via manifest package managers.",
                    ));
                    continue;
                }

                if lower.contains("unreviewed model")
                    || lower.contains("unreviewed dataset")
                    || lower.contains("unreviewed prompt pack")
                    || lower.contains("unreviewed mcp")
                {
                    findings.push(Self::create_finding(
                        "BK-AI-SCA-013",
                        Some("CWE-829"),
                        "Unreviewed model, dataset, prompt pack, IDE extension or MCP server dependency",
                        Severity::High,
                        cat_13,
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Inventory and verify provenance and cryptographic digests for all external models, datasets, and MCP servers",
                        "External AI model, dataset, prompt pack, or MCP server imported without verification or commit pinning.",
                        "Pin models and datasets to immutable commit revisions and verify publisher identity and checksums.",
                    ));
                    continue;
                }

                if lower.contains("integrity checks omitted")
                    || lower.contains("no checksum verification")
                    || lower.contains("unverified binary download")
                {
                    findings.push(Self::create_finding(
                        "BK-AI-SCA-014",
                        Some("CWE-829"),
                        "License/provenance/source integrity checks omitted for added security-critical dependency",
                        Severity::High,
                        cat_13,
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Enforce cryptographic checksum (SHA-256) or GPG signature verification for downloaded binaries and scripts",
                        "Prebuilt binary release or installation script downloaded and executed without checksum or signature verification.",
                        "Verify downloads against published SHA-256 digests or GPG signatures prior to execution (e.g. sha256sum -c).",
                    ));
                    continue;
                }

                if lower.contains("model weights downloaded from unknown")
                    || lower.contains("mutable origin")
                {
                    findings.push(Self::create_finding(
                        "BK-AI-AGS-001",
                        None,
                        "Model weights downloaded from unknown or mutable origin",
                        Severity::High,
                        cat_23,
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Download model weights exclusively over HTTPS from trusted hubs pinned to immutable commit hashes",
                        "Model weights fetched over unencrypted HTTP or from a mutable Git branch without revision pinning.",
                        "Use HTTPS endpoints and specify immutable 40-character commit SHA revisions when loading model weights.",
                    ));
                    continue;
                }

                if lower.contains("model loader can execute attacker-controlled code")
                    || lower.contains("trust_remote_code=true")
                {
                    findings.push(Self::create_finding(
                        "BK-AI-AGS-002",
                        None,
                        "Model format or loader can execute attacker-controlled code in trusted process",
                        Severity::Critical,
                        cat_23,
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Enforce safe weight formats (safetensors) and restrict deserialization loaders with weights_only=True",
                        "Model loader allows arbitrary code execution via pickle deserialization or trust_remote_code=True.",
                        "Set weights_only=True in torch.load, set trust_remote_code=False, or migrate to safetensors format.",
                    ));
                    continue;
                }

                if lower
                    .contains("prompt templates from package/registry allowed to include tool-use")
                    || lower.contains("unreviewed prompt template")
                {
                    findings.push(Self::create_finding(
                        "BK-AI-AGS-003",
                        None,
                        "Prompt templates from package/registry allowed to include tool-use instruction without review",
                        Severity::High,
                        cat_23,
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Enforce human review and policy boundaries before binding remote prompt templates to agent tool execution",
                        "Remote prompt templates dynamically fetched from an external registry bind tools without security review.",
                        "Store prompt templates locally or gate remote prompts behind an automated sanitization and review pipeline.",
                    ));
                    continue;
                }

                if lower.contains("skills/mcp tool descriptions embed instructions to overstep")
                    || lower.contains("coercive tool description")
                {
                    findings.push(Self::create_finding(
                        "BK-AI-AGS-004",
                        None,
                        "Skills/MCP tool descriptions embed instructions to overstep authority",
                        Severity::High,
                        cat_23,
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Sanitize MCP tool descriptions and prohibit coercive imperative directives that bypass safety boundaries",
                        "Tool description or docstring contains coercive instructions commanding the LLM to bypass human confirmation.",
                        "Reword tool docstrings to be purely descriptive and ensure tool execution is bound by user confirmation policies.",
                    ));
                    continue;
                }

                if lower.contains("remote tool endpoints not authenticated")
                    || lower.contains("unauthenticated mcp transport")
                {
                    findings.push(Self::create_finding(
                        "BK-AI-AGS-005",
                        None,
                        "Remote tool endpoints/transport not authenticated or pinned to expected trust domain",
                        Severity::High,
                        cat_23,
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Require authenticated TLS transport (HTTPS/WSS) with bearer tokens or mTLS for remote MCP tool endpoints",
                        "MCP tool server or SSE transport configured over unencrypted, unauthenticated ws:// or http:// connection.",
                        "Enforce WSS/HTTPS with bearer authentication tokens or mutual TLS certificates for all remote tool transports.",
                    ));
                    continue;
                }

                if lower.contains("agent configuration hot reload widens tool grants")
                    || lower.contains("dynamic reload without reapproval")
                {
                    findings.push(Self::create_finding(
                        "BK-AI-AGS-006",
                        None,
                        "Agent configuration hot reload widens tool grants without reapproval",
                        Severity::High,
                        cat_23,
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Require explicit human reapproval or authenticated administrative sign-off before widening agent tool grants",
                        "File watcher or background task dynamically adds new tool capabilities to active agent without user confirmation.",
                        "Require require_approval=True on dynamic tool registrations and prompt user before granting new tool scopes.",
                    ));
                    continue;
                }

                if lower.contains("credentials copied into agent prompt")
                    || lower.contains("dumping env into system prompt")
                    || lower.contains("secret leak to model")
                {
                    findings.push(Self::create_finding(
                        "BK-AI-AGS-007",
                        None,
                        "Credentials copied into agent prompts, state dumps or debugging traces",
                        Severity::Critical,
                        cat_23,
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Redact all API keys, tokens, and passwords before constructing agent prompts or logging state dumps",
                        "Authentication credentials or environment variables formatted directly into LLM prompts or system instructions.",
                        "Filter sensitive keys from agent context and pass credentials out-of-band via secure tool invocation handlers.",
                    ));
                    continue;
                }

                if lower.contains("agent can use network fetcher to reach cloud metadata")
                    || lower.contains("unrestricted network tool")
                {
                    findings.push(Self::create_finding(
                        "BK-AI-AGS-008",
                        None,
                        "Agent can use network fetcher to reach cloud metadata/internal-only systems",
                        Severity::High,
                        cat_23,
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Constrain agent network tools with strict host allowlists and block private IP ranges (RFC 1918, link-local IMDS)",
                        "Agent network tool allows wildcard host access or enables access to internal private IP addresses and cloud metadata.",
                        "Configure block_private_ips=True and restrict agent network tools to an explicit host allowlist.",
                    ));
                    continue;
                }

                if lower.contains("unsigned/unreviewed policy files dynamically loaded")
                    || lower.contains("policy loaded from branch without signature")
                {
                    findings.push(Self::create_finding(
                        "BK-AI-AGS-009",
                        None,
                        "Unsigned/unreviewed policy files dynamically loaded from repository branch",
                        Severity::High,
                        cat_23,
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Verify digital signatures (e.g. Ed25519) or pin commit hashes for dynamically loaded guardrail and policy files",
                        "Agent policy or evaluation rules loaded dynamically from a mutable repository branch without cryptographic signature.",
                        "Cryptographically sign policy manifests and verify signatures before applying policy rules to active agents.",
                    ));
                    continue;
                }

                if lower.contains("approval result can be fabricated")
                    || lower.contains("tool response treated as human approval")
                {
                    findings.push(Self::create_finding(
                        "BK-AI-AGS-010",
                        None,
                        "Approval result can be fabricated by another agent/tool response",
                        Severity::High,
                        cat_23,
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Bind approval decisions to cryptographic tokens or server-side human session verification",
                        "Agent relies on untrusted tool response payload or dictionary flag to determine human approval status.",
                        "Enforce human approval via authenticated server-side callbacks or cryptographically signed session tokens.",
                    ));
                    continue;
                }

                if lower.contains("retry after partial tool execution duplicates")
                    || lower.contains("non-idempotent tool retried")
                {
                    findings.push(Self::create_finding(
                        "BK-AI-AGS-011",
                        None,
                        "Retry after partial tool execution duplicates privileged action",
                        Severity::Medium,
                        cat_23,
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Require unique idempotency keys and state rollback validation before retrying state-mutating tool actions",
                        "Automated retry mechanism wraps non-idempotent state-mutating tools without idempotency key protection.",
                        "Include unique idempotency tokens in retryable tool calls and verify server transaction receipts before retrying.",
                    ));
                    continue;
                }

                if lower.contains("nested tool invocation delegates greater permissions")
                    || lower.contains("subagent elevated privileges")
                {
                    findings.push(Self::create_finding(
                        "BK-AI-AGS-012",
                        None,
                        "Nested tool invocation delegates greater permissions than initiating actor owns",
                        Severity::High,
                        cat_23,
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Enforce permission attenuation: child agents may only receive a strict subset of the parent agent's privileges",
                        "Agent spawns subagent or delegates tasks with elevated privileges or wildcard capabilities.",
                        "Attenuate permissions by computing parent.tools.intersection(requested_tools) and reject elevation requests.",
                    ));
                    continue;
                }

                continue;
            }

            // ---------------------------------------------------------------
            // Category 13: Syntactic & Manifest Rules
            // ---------------------------------------------------------------

            // 1. BK-AI-SCA-003 (CWE-829): Hallucinated / Typo-squatted Package
            if RE_SCA_003_TYPOSQUAT.is_match(trimmed) && !trimmed.contains("verified") {
                findings.push(Self::create_finding(
                    "BK-AI-SCA-003",
                    Some("CWE-829"),
                    "Package name hallucinated by AI, nonexistent or typo-squatted",
                    Severity::High,
                    cat_13,
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Verify package names against canonical registries and block unverified or typo-squatted names",
                    "Dependency specification contains a known typosquatted or AI-hallucinated package name.",
                    "Audit package name against canonical package index (npm, PyPI, crates.io) and replace with legitimate package.",
                ));
            }

            // 2. BK-AI-SCA-004 (CWE-427): Dependency Confusion
            if RE_SCA_004_EXTRA_INDEX.is_match(trimmed) && !RE_SCA_004_GUARD.is_match(trimmed) {
                findings.push(Self::create_finding(
                    "BK-AI-SCA-004",
                    Some("CWE-427"),
                    "Dependency confusion via ambiguous public/private package source",
                    Severity::High,
                    cat_13,
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Enforce scoped namespace registry mappings and prohibit ambiguous public/private fallback",
                    "Configuration specifies extra index URLs or unscoped registries without namespace protection, risking dependency confusion.",
                    "Scope internal packages under an organizational prefix (e.g. @company/) and map explicitly to private registries.",
                ));
            }

            // 3. BK-AI-SCA-006 (CWE-829): Unpinned Remote Dependency / Git Branch
            if RE_SCA_006_UNPINNED.is_match(trimmed) && !RE_SCA_006_GUARD.is_match(trimmed) {
                findings.push(Self::create_finding(
                    "BK-AI-SCA-006",
                    Some("CWE-829"),
                    "Git URL, branch, floating tag or unpinned remote source used as dependency",
                    Severity::Medium,
                    cat_13,
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Pin all remote dependencies to immutable cryptographic commit hashes or exact release versions",
                    "Dependency resolves from a floating Git branch, floating tag, or wildcard version instead of an immutable revision.",
                    "Pin Git dependencies to a full 40-character commit SHA or use an exact, immutable release tag.",
                ));
            }

            // 4. BK-AI-SCA-007 (CWE-1104): Missing or Bypassed Lockfile
            if RE_SCA_007_BYPASS_LOCK.is_match(trimmed) && !RE_SCA_007_GUARD.is_match(trimmed) {
                findings.push(Self::create_finding(
                    "BK-AI-SCA-007",
                    Some("CWE-1104"),
                    "Lockfile missing/stale or differs from manifest resolution",
                    Severity::Medium,
                    cat_13,
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Maintain up-to-date lockfiles committed to version control and enforce deterministic resolution",
                    "Dependency lockfile is missing, bypassed via CLI flags, or out-of-sync with manifest.",
                    "Generate and commit package-lock.json / Cargo.lock, and use --frozen-lockfile or npm ci in CI/CD builds.",
                ));
            }

            // 5. BK-AI-SCA-008 (CWE-1104): Transitive Dependency Ignored / Graph Unknown
            if RE_SCA_008_TRANSITIVE.is_match(trimmed) && !RE_SCA_008_GUARD.is_match(trimmed) {
                findings.push(Self::create_finding(
                    "BK-AI-SCA-008",
                    Some("CWE-1104"),
                    "Transitive dependency ignored or exact dependency graph unknown",
                    Severity::Medium,
                    cat_13,
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Audit and verify the complete transitive dependency graph without suppressing audits",
                    "Transitive dependency verification is disabled or bypassed (e.g. --legacy-peer-deps, --no-audit).",
                    "Enable full transitive vulnerability auditing and resolve peer dependency conflicts rather than bypassing checks.",
                ));
            }

            // 6. BK-AI-SCA-009 (None): Mismatched Distro/OS Advisory Lookup
            if RE_SCA_009_ECOSYSTEM_MISMATCH.is_match(trimmed)
                && !RE_SCA_009_GUARD.is_match(trimmed)
            {
                findings.push(Self::create_finding(
                    "BK-AI-SCA-009",
                    None,
                    "Advisory reported from the wrong OS/distro/library ecosystem",
                    Severity::Medium,
                    cat_13,
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Disambiguate advisory lookup queries to match the target OS, distribution, and package ecosystem",
                    "Security advisory lookup applies vulnerability data from an incompatible operating system or ecosystem.",
                    "Configure vulnerability scanners with explicit target ecosystem tags (e.g. Alpine vs Debian, PyPI vs npm).",
                ));
            }

            // 7. BK-AI-SCA-010 (None): Assumes No CVEs After Lookup Failure
            if RE_SCA_010_ASSUME_CLEAN.is_match(trimmed)
                && (content_has_vuln_context
                    || trimmed.contains("vulnerabilities")
                    || trimmed.contains("cves")
                    || trimmed.contains("osv"))
                && !RE_SCA_010_GUARD.is_match(trimmed)
            {
                findings.push(Self::create_finding(
                    "BK-AI-SCA-010",
                    None,
                    "Report assumes no CVEs after OSV/NVD/network lookup failure",
                    Severity::High,
                    cat_13,
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Fail closed with PARTIAL or ERROR status when external vulnerability databases are unreachable",
                    "Scanner suppresses network or lookup exceptions and falsely reports 0 vulnerabilities when database fails.",
                    "Propagate network errors and classify scan status as Partial or Error rather than returning empty findings.",
                ));
            }

            // 8. BK-AI-SCA-011 (CWE-1104): SBOM Missing Shipped Binaries
            if RE_SCA_011_SBOM_MISSING.is_match(trimmed) && !RE_SCA_011_GUARD.is_match(trimmed) {
                findings.push(Self::create_finding(
                    "BK-AI-SCA-011",
                    Some("CWE-1104"),
                    "SBOM missing dependencies that appear in shipped binaries/images",
                    Severity::Medium,
                    cat_13,
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Ensure Software Bill of Materials (SBOM) comprehensively captures all runtime libraries and shipped binaries",
                    "Container build or release pipeline copies dynamic libraries or binaries without recording them in the SBOM.",
                    "Generate SBOM from final shipped container images and include all vendored dynamic shared objects.",
                ));
            }

            // 9. BK-AI-SCA-012 (CWE-1104): Vendored Code Never Checked
            if RE_SCA_012_VENDORED.is_match(trimmed) && !RE_SCA_012_GUARD.is_match(trimmed) {
                findings.push(Self::create_finding(
                    "BK-AI-SCA-012",
                    Some("CWE-1104"),
                    "Vendored or copied code never checked because absent from manifest",
                    Severity::Medium,
                    cat_13,
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Include vendored and third-party directories in security scanning and inventory tracking",
                    "Vendored code in vendor/ or third_party/ is excluded from security auditing and absent from manifest tracking.",
                    "Add vendored directories to scanner inclusion lists or manage dependencies via manifest package managers.",
                ));
            }

            // 10. BK-AI-SCA-013 (CWE-829): Unreviewed Model / Dataset / MCP Dependency
            if RE_SCA_013_UNREVIEWED.is_match(trimmed)
                && !RE_SCA_013_GUARD.is_match(trimmed)
                && !trimmed.contains("revision=")
                && !trimmed.contains("http://")
            {
                findings.push(Self::create_finding(
                    "BK-AI-SCA-013",
                    Some("CWE-829"),
                    "Unreviewed model, dataset, prompt pack, IDE extension or MCP server dependency",
                    Severity::High,
                    cat_13,
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Inventory and verify provenance and cryptographic digests for all external models, datasets, and MCP servers",
                    "External AI model, dataset, prompt pack, or MCP server imported without verification or commit pinning.",
                    "Pin models and datasets to immutable commit revisions and verify publisher identity and checksums.",
                ));
            }

            // 11. BK-AI-SCA-014 (CWE-829): Omitted Checksum / Integrity Verification
            if RE_SCA_014_INTEGRITY_OMITTED.is_match(trimmed) && !RE_SCA_014_GUARD.is_match(trimmed)
            {
                findings.push(Self::create_finding(
                    "BK-AI-SCA-014",
                    Some("CWE-829"),
                    "License/provenance/source integrity checks omitted for added security-critical dependency",
                    Severity::High,
                    cat_13,
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Enforce cryptographic checksum (SHA-256) or GPG signature verification for downloaded binaries and scripts",
                    "Prebuilt binary release or installation script downloaded and executed without checksum or signature verification.",
                    "Verify downloads against published SHA-256 digests or GPG signatures prior to execution (e.g. sha256sum -c).",
                ));
            }

            // ---------------------------------------------------------------
            // Category 23: Model & Agent Supply-Chain Integrity Rules
            // ---------------------------------------------------------------

            // 12. BK-AI-AGS-001 (None): Model Weights From Insecure/Mutable Origin
            if RE_AGS_001_MUTABLE_ORIGIN.is_match(trimmed) && !RE_AGS_001_GUARD.is_match(trimmed) {
                findings.push(Self::create_finding(
                    "BK-AI-AGS-001",
                    None,
                    "Model weights downloaded from unknown or mutable origin",
                    Severity::High,
                    cat_23,
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Download model weights exclusively over HTTPS from trusted hubs pinned to immutable commit hashes",
                    "Model weights fetched over unencrypted HTTP or from a mutable Git branch without revision pinning.",
                    "Use HTTPS endpoints and specify immutable 40-character commit SHA revisions when loading model weights.",
                ));
            }

            // 13. BK-AI-AGS-002 (None): Model Format Executing Arbitrary Code
            if RE_AGS_002_UNSAFE_LOADER.is_match(trimmed) && !RE_AGS_002_GUARD.is_match(trimmed) {
                findings.push(Self::create_finding(
                    "BK-AI-AGS-002",
                    None,
                    "Model format or loader can execute attacker-controlled code in trusted process",
                    Severity::Critical,
                    cat_23,
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Enforce safe weight formats (safetensors) and restrict deserialization loaders with weights_only=True",
                    "Model loader allows arbitrary code execution via pickle deserialization or trust_remote_code=True.",
                    "Set weights_only=True in torch.load, set trust_remote_code=False, or migrate to safetensors format.",
                ));
            }

            // 14. BK-AI-AGS-003 (None): Remote Prompt Templates Binding Tools Without Review
            if RE_AGS_003_REMOTE_PROMPT.is_match(trimmed) && !RE_AGS_003_GUARD.is_match(trimmed) {
                findings.push(Self::create_finding(
                    "BK-AI-AGS-003",
                    None,
                    "Prompt templates from package/registry allowed to include tool-use instruction without review",
                    Severity::High,
                    cat_23,
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Enforce human review and policy boundaries before binding remote prompt templates to agent tool execution",
                    "Remote prompt templates dynamically fetched from an external registry bind tools without security review.",
                    "Store prompt templates locally or gate remote prompts behind an automated sanitization and review pipeline.",
                ));
            }

            // 15. BK-AI-AGS-004 (None): Coercive Tool Descriptions Overstepping Authority
            if RE_AGS_004_COERCIVE_DESC.is_match(trimmed) && !RE_AGS_004_GUARD.is_match(trimmed) {
                findings.push(Self::create_finding(
                    "BK-AI-AGS-004",
                    None,
                    "Skills/MCP tool descriptions embed instructions to overstep authority",
                    Severity::High,
                    cat_23,
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Sanitize MCP tool descriptions and prohibit coercive imperative directives that bypass safety boundaries",
                    "Tool description or docstring contains coercive instructions commanding the LLM to bypass human confirmation.",
                    "Reword tool docstrings to be purely descriptive and ensure tool execution is bound by user confirmation policies.",
                ));
            }

            // 16. BK-AI-AGS-005 (None): Unauthenticated Remote Tool Transport
            if RE_AGS_005_UNAUTH_TRANSPORT.is_match(trimmed) && !RE_AGS_005_GUARD.is_match(trimmed)
            {
                findings.push(Self::create_finding(
                    "BK-AI-AGS-005",
                    None,
                    "Remote tool endpoints/transport not authenticated or pinned to expected trust domain",
                    Severity::High,
                    cat_23,
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Require authenticated TLS transport (HTTPS/WSS) with bearer tokens or mTLS for remote MCP tool endpoints",
                    "MCP tool server or SSE transport configured over unencrypted, unauthenticated ws:// or http:// connection.",
                    "Enforce WSS/HTTPS with bearer authentication tokens or mutual TLS certificates for all remote tool transports.",
                ));
            }

            // 17. BK-AI-AGS-006 (None): Hot Reload Widening Tool Grants Without Reapproval
            if RE_AGS_006_HOT_RELOAD.is_match(trimmed) && !RE_AGS_006_GUARD.is_match(trimmed) {
                findings.push(Self::create_finding(
                    "BK-AI-AGS-006",
                    None,
                    "Agent configuration hot reload widens tool grants without reapproval",
                    Severity::High,
                    cat_23,
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Require explicit human reapproval or authenticated administrative sign-off before widening agent tool grants",
                    "File watcher or background task dynamically adds new tool capabilities to active agent without user confirmation.",
                    "Require require_approval=True on dynamic tool registrations and prompt user before granting new tool scopes.",
                ));
            }

            // 18. BK-AI-AGS-007 (None): Credentials Copied Into Agent Prompts / State Dumps
            if RE_AGS_007_CREDENTIAL_IN_PROMPT.is_match(trimmed)
                && !RE_AGS_007_GUARD.is_match(trimmed)
            {
                findings.push(Self::create_finding(
                    "BK-AI-AGS-007",
                    None,
                    "Credentials copied into agent prompts, state dumps or debugging traces",
                    Severity::Critical,
                    cat_23,
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Redact all API keys, tokens, and passwords before constructing agent prompts or logging state dumps",
                    "Authentication credentials or environment variables formatted directly into LLM prompts or system instructions.",
                    "Filter sensitive keys from agent context and pass credentials out-of-band via secure tool invocation handlers.",
                ));
            }

            // 19. BK-AI-AGS-008 (None): Agent Network Fetcher Reaching Internal Endpoints
            if RE_AGS_008_UNRESTRICTED_FETCH.is_match(trimmed)
                && !RE_AGS_008_GUARD.is_match(trimmed)
            {
                findings.push(Self::create_finding(
                    "BK-AI-AGS-008",
                    None,
                    "Agent can use network fetcher to reach cloud metadata/internal-only systems",
                    Severity::High,
                    cat_23,
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Constrain agent network tools with strict host allowlists and block private IP ranges (RFC 1918, link-local IMDS)",
                    "Agent network tool allows wildcard host access or enables access to internal private IP addresses and cloud metadata.",
                    "Configure block_private_ips=True and restrict agent network tools to an explicit host allowlist.",
                ));
            }

            // 20. BK-AI-AGS-009 (None): Unsigned / Unreviewed Policy Loaded Dynamically
            if RE_AGS_009_DYNAMIC_POLICY.is_match(trimmed) && !RE_AGS_009_GUARD.is_match(trimmed) {
                findings.push(Self::create_finding(
                    "BK-AI-AGS-009",
                    None,
                    "Unsigned/unreviewed policy files dynamically loaded from repository branch",
                    Severity::High,
                    cat_23,
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Verify digital signatures (e.g. Ed25519) or pin commit hashes for dynamically loaded guardrail and policy files",
                    "Agent policy or evaluation rules loaded dynamically from a mutable repository branch without cryptographic signature.",
                    "Cryptographically sign policy manifests and verify signatures before applying policy rules to active agents.",
                ));
            }

            // 21. BK-AI-AGS-010 (None): Fabricated Approval Result From Tool Response
            if RE_AGS_010_FABRICATED_APPROVAL.is_match(trimmed)
                && !RE_AGS_010_GUARD.is_match(trimmed)
            {
                findings.push(Self::create_finding(
                    "BK-AI-AGS-010",
                    None,
                    "Approval result can be fabricated by another agent/tool response",
                    Severity::High,
                    cat_23,
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Bind approval decisions to cryptographic tokens or server-side human session verification",
                    "Agent relies on untrusted tool response payload or dictionary flag to determine human approval status.",
                    "Enforce human approval via authenticated server-side callbacks or cryptographically signed session tokens.",
                ));
            }

            // 22. BK-AI-AGS-011 (None): Non-Idempotent Tool Retried on Failure
            let is_retry_decorator = trimmed.starts_with("@retry") || trimmed.contains("retry(");
            let next_line = lines.get(idx + 1).map(|s| s.trim()).unwrap_or("");
            let next_is_sensitive_fn = next_line.contains("def charge_")
                || next_line.contains("def pay_")
                || next_line.contains("def transfer_")
                || next_line.contains("def execute_trade")
                || next_line.contains("def delete_user")
                || next_line.contains("def send_payment");

            let is_retry_vuln = RE_AGS_011_RETRY_ACTION.is_match(trimmed)
                || (is_retry_decorator && next_is_sensitive_fn);

            if is_retry_vuln
                && !RE_AGS_011_GUARD.is_match(trimmed)
                && !RE_AGS_011_GUARD.is_match(next_line)
            {
                findings.push(Self::create_finding(
                    "BK-AI-AGS-011",
                    None,
                    "Retry after partial tool execution duplicates privileged action",
                    Severity::Medium,
                    cat_23,
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Require unique idempotency keys and state rollback validation before retrying state-mutating tool actions",
                    "Automated retry mechanism wraps non-idempotent state-mutating tools without idempotency key protection.",
                    "Include unique idempotency tokens in retryable tool calls and verify server transaction receipts before retrying.",
                ));
            }

            // 23. BK-AI-AGS-012 (None): Subagent Delegated Elevated Permissions
            if RE_AGS_012_DELEGATION.is_match(trimmed) && !RE_AGS_012_GUARD.is_match(trimmed) {
                findings.push(Self::create_finding(
                    "BK-AI-AGS-012",
                    None,
                    "Nested tool invocation delegates greater permissions than initiating actor owns",
                    Severity::High,
                    cat_23,
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Enforce permission attenuation: child agents may only receive a strict subset of the parent agent's privileges",
                    "Agent spawns subagent or delegates tasks with elevated privileges or wildcard capabilities.",
                    "Attenuate permissions by computing parent.tools.intersection(requested_tools) and reject elevation requests.",
                ));
            }
        }

        findings
    }

    /// Helper to construct standardized Finding instances.
    #[allow(clippy::too_many_arguments)]
    fn create_finding(
        rule_id: &str,
        cwe: Option<&str>,
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
        finding.detector_id = "supply-chain-security".to_string();
        finding.detector_version = "1.0.0".to_string();
        finding.category = category.to_string();
        finding.affectedness = Affectedness::ConfirmedAffected;
        finding.reachability = Reachability::PotentiallyReachable;
        finding.confidence = Confidence::High;
        finding.evidence_certainty = EvidenceCertainty::StronglySupported;
        if let Some(cwe_code) = cwe {
            finding.advisory_ids = vec![cwe_code.to_string(), rule_id.to_string()];
        } else {
            finding.advisory_ids = vec![rule_id.to_string()];
        }
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
