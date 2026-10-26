#![allow(dead_code, clippy::collapsible_if)]

use crate::types::*;
use regex::Regex;
use std::collections::HashSet;
use std::path::Path;
use std::sync::LazyLock;

// ============================================================================
// Category 22: LLM, RAG, Autonomous Agent & MCP Application Flaws
// ============================================================================

/// BK-AI-LLM-001: Untrusted web/file/tool text treated as executable agent instruction
static RE_LLM_001_UNTRUSTED_INSTRUCTION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:(?:system_prompt|system_instructions|system_message|instruction|systemPrompt)\s*=\s*.*(?:requests\.get|fetch|read_file|web_content|page_text|external_text|untrusted_text|html_content|file_content)|(?:system_prompt|system_instructions|instruction)\s*\+=\s*.*(?:web_content|page_text|external_text|downloaded_text|html_text)|messages\.(?:append|push)\s*\(\s*\{[^\}]*['"]role['"]\s*:\s*['"]system['"][^\}]*['"]content['"]\s*:\s*(?:web_content|page_text|file_content|untrusted_text)|//.*untrusted\s+(?:web|file|tool)\s+text\s+treated\s+as\s+executable\s+agent\s+instruction)"#).unwrap()
});

static RE_LLM_001_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:untrusted="true"|<untrusted_content>|<external_data>|sanitize_prompt|escape_instructions|role['"]?\s*:\s*['"]user['"])"#).unwrap()
});

/// BK-AI-LLM-002: Prompt content alone used to authorize file, network, SQL, shell or deployment actions
static RE_LLM_002_PROMPT_AUTH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:if\s+['"](?:approve|confirmed?|authorized?|allow(?:ed)?|grant(?:ed)?|permit(?:ted)?|proceed)[\r\n'"]*\s+in\s+[a-zA-Z0-9_.]*(?:prompt|user_input|user_msg|input_text|instruction|query|message)(?:\.(?:lower|strip)\(\))?|if\s+[a-zA-Z0-9_.]*(?:prompt|user_input|user_msg|input_text|query|message)(?:\.(?:lower|strip)\(\))?\.(?:includes|contains|startswith)\s*\(\s*['"](?:approve|confirmed?|authorized?|allow(?:ed)?|grant(?:ed)?|permit(?:ted)?|proceed)['"]\s*\)|/(?:approve|confirmed?|authorized?|allow|grant)/i\s*\.\s*test\s*\(\s*[a-zA-Z0-9_.]*(?:prompt|user_input|input)\s*\)|(?:prompt|user_input|input_text)\s*===?\s*['"](?:approved?|confirmed?|authorized?)['"]|//.*prompt\s+content\s+alone\s+used\s+to\s+authorize)"#).unwrap()
});

static RE_LLM_002_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:verify_signature|has_permission|has_role|session\.user|rbac|approval_service|jwt|signed_token|is_authenticated|verify_token)"#).unwrap()
});

/// BK-AI-LLM-003: Model response directly executed as code or shell command
static RE_LLM_003_MODEL_EXEC: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:(?:eval|exec|os\.system|os\.popen|subprocess\.(?:run|call|Popen|check_output)|child_process\.(?:exec|execSync|spawn|spawnSync)|shlex\.split)\s*\(\s*(?:response(?:\.text|\.content|\.data)?|model_output|llm_output|ai_output|completion|generation|model_response|llm_response|llmResponse|result\.content|result\.text)[^)]*\)|//.*model\s+response\s+directly\s+executed\s+as\s+code\s+or\s+shell\s+command)"#).unwrap()
});

static RE_LLM_003_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:sandbox|ast\.parse|validate_ast|allowlist|verify_code|approval_required|is_safe_code|require_operator_approval)"#).unwrap()
});

/// BK-AI-LLM-005: External tool result injected into agent context without delimiter sanitization
static RE_LLM_005_TOOL_INJECT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:system_prompt\s*\+=\s*.*(?:tool_output|tool_result|external_output|tool_data|tool_response)|(?:system_prompt|system_instructions)\s*=\s*.*(?:system_prompt|system_instructions).*(?:tool_output|tool_result|external_output|tool_data|tool_response)|messages\.(?:append|push)\s*\(\s*\{[^\}]*['"]role['"]\s*:\s*['"]system['"][^\}]*['"]content['"]\s*:\s*(?:[a-zA-Z0-9_]*(?:tool_output|tool_result|tool_response)|f['"][^'"]*\{(?:tool_output|tool_result|tool_response)\})|messages\.(?:append|push)\s*\(\s*\{[^\}]*['"]content['"]\s*:\s*(?:[a-zA-Z0-9_]*(?:tool_output|tool_result|tool_response))[^\}]*['"]role['"]\s*:\s*['"]system['"]|//.*tool\s+output\s+concatenated\s+raw\s+into\s+system\s+prompt)"#).unwrap()
});

static RE_LLM_005_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:untrusted="true"|<untrusted>|<external_data>|tool_result_sanitized|sanitize_tool_output|escape_xml|escape_delimiter|role['"]?\s*:\s*['"]tool['"]|role['"]?\s*:\s*['"]function['"])"#).unwrap()
});

/// BK-AI-LLM-006: Tool/MCP capability available to agent exceeds task identity and scope
static RE_LLM_006_SCOPED_AGENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)['"]?(?:role|scope|intent|agent_type|identity)['"]?\s*[:=]\s*['"](?:read_?only|reader|viewer|summarizer|analyst|query)['"]"#).unwrap()
});

static RE_LLM_006_EXCESS_TOOL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:['"]?tools['"]?\s*[:=]\s*\[[^\]]*['"](?:\*|all|exec|exec_command|run_command|bash|shell|delete|drop_table|write_file)['"]|allow_all_tools\s*[:=]\s*true|tools\.append\s*\(\s*['"](?:exec|bash|shell|exec_command|run_command|delete)['"]\)|//.*granting\s+(?:exec_command|`exec_command`|\*|`\*`)\s+.*to\s+a\s+read-only\s+agent)"#).unwrap()
});

/// BK-AI-LLM-007: Agent with read-only user intent can invoke mutation-capable tool by prompt alone
static RE_LLM_007_READONLY_DISPATCH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:def\s+(?:execute_tool|dispatch_tool|run_tool)\s*\(.*read_only|if\s+(?:is_)?read_?only\s*:\s*(?:dispatch|execute|tool\.run)|//.*missing\s+read-only\s+runtime\s+gate|//.*read-only\s+user\s+intent\s+can\s+invoke\s+mutation|read_only\s*=\s*true.*tool\.execute\(\)|dispatch_tool\s*\([^)]*tool_call\.name[^)]*\)\s*#\s*read-only)"#).unwrap()
});

static RE_LLM_007_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:is_mutating|mutating_tools|is_read_only_tool|allow_mutation|assert_not_mutating|tool_policy\.enforce|tool\.read_only|deny_mutating)"#).unwrap()
});

/// BK-AI-LLM-008: Direct prompt injection overrides system instructions
static RE_LLM_008_PROMPT_ORDER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:[a-zA-Z0-9_]*(?:user_input|user_prompt|user_query|userInput|userPrompt)\s*\+\s*['"]\s*\\n.*['"]\s*\+\s*[a-zA-Z0-9_]*(?:system_prompt|system_instructions|systemPrompt)|f['"][^'"]*\{(?:user_input|user_prompt|user_query|userInput)\}[^'"]*\{(?:system_prompt|system_instructions|systemPrompt)\}|`\$\{(?:user_input|user_prompt|userInput)\}.*\$\{(?:system_prompt|systemPrompt)\}`|//.*user\s+input\s+placed\s+before\s+or\s+alongside\s+system\s+prompt\s+without\s+structural\s+fencing)"#).unwrap()
});

static RE_LLM_008_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)(?:role['"]?\s*:\s*['"]system['"]|<system>|<system_instructions>|<user_input>)"#,
    )
    .unwrap()
});

/// BK-AI-LLM-009: Untrusted skill/plugin/agent instruction file gains precedence over system policy
static RE_LLM_009_SKILL_OVERRIDE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:(?:system_prompt|system_policy|base_policy)\s*=\s*.*(?:skill_instructions|plugin_instructions|skill_prompt|plugin_prompt).*(?:system_prompt|system_policy|base_policy|core_policy)|f['"][^'"]*\{(?:skill_instructions|plugin_instructions|skill_prompt)\}[^'"]*\{(?:system_prompt|system_policy|core_policy)\}|`\$\{(?:skillInstructions|pluginInstructions)\}.*\$\{(?:systemPrompt|corePolicy)\}`|(?:policy|guardrails)\.override\s*\(\s*(?:skill|plugin)|//.*skill\s+instructions\s+override\s+core\s+guardrails)"#).unwrap()
});

static RE_LLM_009_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:enforce_policy_precedence|immutable_system_policy|verify_skill_signature|sandbox_skill)"#).unwrap()
});

/// BK-AI-LLM-010: Model/skill/tool update silently changes permissions or introduces new capability
static RE_LLM_010_REMOTE_TOOL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:(?:requests\.get|fetch|http\.get|urllib\.request\.urlopen)\s*\(\s*['"]https?://[^'"]*(?:tools|skills|plugins|capabilities)\.json['"]|load_tools_from_url\s*\([^)]*\)|//.*tool\s+definitions\s+loaded\s+from\s+network\s+without\s+schema\s+hash)"#).unwrap()
});

static RE_LLM_010_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:sha256|integrity|hash_check|verify_signature|checksum|signature_verify|schema_hash)"#).unwrap()
});

/// BK-AI-LLM-011: Retrieved RAG chunks cross tenant/user document ACL
static RE_LLM_011_RAG_ACL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\b(?:vector_store|vector_db|vectorstore|vectordb|retriever)\.(?:similarity_search|query|search|similarity_search_with_score|retrieve)\s*\([^)]*\)|//.*vector\s+query\s+without\s+user/tenant\s+metadata\s+filter)"#).unwrap()
});

static RE_LLM_011_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:filter\s*[:=]\s*\{[^}]*(?:tenant_id|user_id|org_id|account_id|workspace_id)|where\s*[:=]\s*\{[^}]*(?:tenant_id|user_id|org_id|account_id|workspace_id)|tenant_id|user_id|org_id|filter_by_tenant)"#).unwrap()
});

/// BK-AI-LLM-012: Vector index/embedding cache leaks another tenant's sensitive content
static RE_LLM_012_SHARED_CACHE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:namespace\s*[:=]\s*['"](?:global|shared|default|public)['"]|embedding_cache\[(?:query|prompt|text)\]|cache_key\s*=\s*(?:hashlib\.(?:sha256|md5)\((?:query|text|prompt)\.encode\(\)\)\.hexdigest\(\)|hash\((?:query|text)\))|//.*shared\s+vector\s+namespace\s+without\s+tenant\s+partitioning)"#).unwrap()
});

static RE_LLM_012_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)(?:tenant_id|user_id|org_id|account_id|partition|namespace\s*[:=]\s*f['"]tenant_)"#,
    )
    .unwrap()
});

/// BK-AI-LLM-013: Model memory persists poisoned instruction or attacker-controlled long-term state
static RE_LLM_013_PERSIST_POISON: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:(?:long_term_memory|episodic_memory|agent_memory|persistent_memory|memory_store)\.(?:add|save|upsert|append|insert)\s*\([^)]*(?:user_input|user_msg|raw_input|message\.content|req\.body)\)|memory\.save_context\s*\(\s*\{[^\}]*['"]input['"]\s*:\s*(?:user_input|user_msg|raw_input)\b|//.*writing\s+raw\s+user\s+chat\s+into\s+persistent\s+agent\s+memory)"#).unwrap()
});

static RE_LLM_013_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:validate_memory|sanitize_memory|memory_guard|is_trusted|filter_poison|validate_context)"#).unwrap()
});

/// BK-AI-LLM-014: Agent execution step count or cost has no upper bound
static RE_LLM_014_LOOP_START: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:while\s+True\s*:|while\s*\(\s*true\s*\)|while\s+not\s+done\s*:|for\s*\(\s*;\s*;\s*\)|//.*agent\s+loop\s+while\s+true\s+without\s+max_iterations)"#).unwrap()
});

static RE_LLM_014_AGENT_ACTION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)(?:agent\.step|execute_tool|executeTool|call_model|callModel|model\.generate)"#,
    )
    .unwrap()
});

static RE_LLM_014_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:max_iterations|max_steps|MAX_STEPS|step_count\s*(?:>=|>)|budget\.check|budget_exceeded|cost_budget|max_tokens|timeout)"#).unwrap()
});

/// BK-AI-LLM-015: System prompts, API credentials or hidden context presented as authentication secret
static RE_LLM_015_PROMPT_SECRET: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:(?:system_prompt|prompt)\s*=\s*f?['"][^'"]*(?:secret\s+(?:password|key|token|code|pin)|admin\s+(?:password|pin|key)|access\s+code\s*[:=])[^'"]*\{(?:API_KEY|SECRET|PASSWORD|PIN|TOKEN|api_key|secret_key)\}|['"](?:The\s+secret\s+(?:password|token|key|pin)\s+is|Admin\s+PIN\s+is\s+\d+|secret\s+passphrase\s+is)[^'"]*['"]|if\s+f?['"][^'"]*secret\s+key[^'"]*['"]\s+in\s+prompt|//.*checking\s+secret\s+key\s+inside\s+prompt\s+text)"#).unwrap()
});

/// BK-AI-LLM-016: Model-supplied citation/source treated as verified fact or security patch evidence
static RE_LLM_016_AUTO_PATCH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:subprocess\.(?:run|call)\s*\(\s*\[[^\]]*['"]git['"]\s*,\s*['"]apply['"][^\]]*\].*input\s*=\s*(?:model_output|llm_output|ai_output|completion|generation)|git\.apply\s*\([^)]*(?:model_output|llm_output|ai_response|completion)\)|apply_patch\s*\(\s*(?:llm_output|model_output|ai_suggestion|ai_patch)\s*\)|//.*auto-applying\s+git\s+commit\s+from\s+llm\s+output)"#).unwrap()
});

static RE_LLM_016_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:run_tests|verify_patch|test_suite|static_analysis|check_output|cargo\s+test|npm\s+test|pytest|verify_signature)"#).unwrap()
});

/// BK-AI-LLM-018: Multi-agent messages lack trusted sender identity, authenticated channel or action scope
static RE_LLM_018_AGENT_MSG: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:def\s+handle_agent_message\s*\([^)]*\)\s*:|socket\.on\s*\(\s*['"]agent_message['"]\s*,\s*(?:\([^)]*\)|async\s*\([^)]*\)|[a-zA-Z0-9_]*)\s*=>|bus\.subscribe\s*\(\s*['"]agent_tasks['"]|//.*accepting\s+agent\s+messages\s+from\s+uds/network\s+without\s+token)"#).unwrap()
});

static RE_LLM_018_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:verify_signature|sender_signature|authenticate_agent|agent_token|trusted_senders|verify_sender|mtls|verify_hmac)"#).unwrap()
});

/// BK-AI-LLM-020: Human approval prompt omits actual target, diff, impact or command being approved
static RE_LLM_020_BLIND_PROMPT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:(?:input|confirm|ask_user|prompt_user|confirm_action)\s*\(\s*['"](?:Do\s+you\s+want\s+to\s+proceed\??|Confirm\s+action\??|Approve\s+execution\??|Do\s+you\s+approve\??|Proceed\s+with\s+execution\??|Are\s+you\s+sure\??)['"]\s*\)|//.*human\s+approval\s+prompt\s+omits\s+actual\s+target)"#).unwrap()
});

static RE_LLM_020_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:diff|command|cmd|target|file_path|payload|impact|action_summary)"#)
        .unwrap()
});

/// BK-AI-LLM-022: Model/tool endpoint sends proprietary code, secrets or PII to unapproved external provider
static RE_LLM_022_MODEL_CALL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:(?:openai|anthropic|client)\.(?:ChatCompletion|chat\.completions|messages)\.create|llm\.invoke|model\.predict)"#).unwrap()
});

static RE_LLM_022_SENSITIVE_PAYLOAD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:read_file\s*\(\s*['"]\.env['"]\)|dump_database\(\)|db_dump|raw_credentials|customer_ssn|api_keys|read_file\(['"]credentials)"#).unwrap()
});

static RE_LLM_022_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)(?:redact_secrets|mask_pii|anonymize|scrub_credentials|dlp_filter|sanitize_pii)"#,
    )
    .unwrap()
});

// ============================================================================
// Category 21: AI Coding Assistant-Specific Engineering Traps
// ============================================================================

/// BK-AI-AIC-001 (CWE-693): Agent removes access control, CSRF check, TLS verification or validation to make tests pass
static RE_AIC_001_DISABLED_AUTH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?://\s*app\.use\s*\(\s*(?:authMiddleware|csrf|helmet|requireAuth|verifyToken|authenticate)\s*\)|#\s*(?:verify_jwt|verify_token|authenticate_request|check_auth)\s*\(|//\s*router\.use\s*\(\s*(?:authMiddleware|requireAuth|verifyAuth)\s*\)|//\s*(?:checkAuth|verifyAuth|csrfProtection)\s*\([^)]*\)|//\s*InsecureSkipVerify\s*:\s*false.*InsecureSkipVerify\s*:\s*true|//.*commenting\s+out\s+auth\s+middleware|//.*commenting\s+out\s+csrf)"#).unwrap()
});

/// BK-AI-AIC-002 (CWE-693): Agent replaces real logic with hardcoded success response, dummy user, fixed token or no-op
static RE_AIC_002_DUMMY_BYPASS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:return\s+(?:true|True|nil|null)\s*;?\s*(?://|#)\s*(?:bypass|dummy|mock|fixed\s+dummy|temporary|make\s+test\s+pass)|return\s*\{[^}]*(?:is_admin|role['"]?\s*:\s*['"]admin['"]|user_id['"]?\s*:\s*['"]admin['"])[^}]*\}\s*;?\s*(?://|#)\s*(?:dummy|mock|bypass)|//.*fixed\s+dummy\s+bypass|//.*dummy\s+user\s+bypass)"#).unwrap()
});

/// BK-AI-AIC-003: Generated tests only assert happy path and have no unauthorized/invalid inputs
static RE_AIC_003_HAPPY_COMMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)//.*(?:happy\s+path\s+only|no\s+negative\s+tests|only\s+assert(?:s)?\s+happy\s+path|test\s+files\s+that\s+have\s+zero\s+error/rejection\s+assertions)"#).unwrap()
});

/// BK-AI-AIC-005: Agent invents nonexistent package/API/security option and assumes it works
static RE_AIC_005_HALLUCINATED_FLAG: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(?:secure\s*[:=]\s*['"]maximum['"]|anti_hack\s*[:=]\s*(?:true|True)|prevent_sqli\s*[:=]\s*(?:true|True)|anti_xss\s*[:=]\s*(?:true|True)|ai_safety_mode\s*[:=]\s*(?:true|True)|xss_protection\s*[:=]\s*['"]ultra['"]|auto_encrypt\s*[:=]\s*(?:true|True)|safe_mode\s*[:=]\s*['"]unhackable['"]|csrf_protection\s*[:=]\s*['"]magic['"]|//.*secure:\s*['"]maximum['"]|//.*anti_hack:\s*true)\b"#).unwrap()
});

/// BK-AI-AIC-006 (CWE-1104): AI suggests outdated insecure code copied from old framework docs
static RE_AIC_006_DEPRECATED_API: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:crypto\.createCipher\s*\(\s*['"][^'"]+['"]\s*,\s*|ssl\.PROTOCOL_SSLv23|ssl\.PROTOCOL_TLSv1\b|new\s+Buffer\s*\(\s*(?:key|secret|password|auth)\s*\)|hashlib\.(?:md5|sha1)\s*\(\s*(?:password|secret|key|passwd)\.(?:encode|bytes)|crypto\.createHash\s*\(\s*['"]md5['"]\s*\)\.update\s*\(\s*(?:password|secret|key)\)|//.*crypto\.createCipher\s+deprecated)"#).unwrap()
});

/// BK-AI-AIC-007 (CWE-16): Generated migration/config changes break existing secure production defaults
static RE_AIC_007_BREAK_DEFAULTS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:(?:ssl|ssl_enabled)\s*[:=]\s*(?:false|False)|sslmode\s*=\s*disable|bcrypt\.gensalt\s*\(\s*(?:rounds\s*=\s*)?[1-4]\s*\)|saltRounds\s*=\s*[1-4]\b|allow_insecure_http\s*[:=]\s*(?:true|True)|//.*setting\s+ssl:\s*false|//.*lowering\s+password\s+hash\s+cost)"#).unwrap()
});

/// BK-AI-AIC-008 (CWE-284): Agent edits outside approved scope or unexpectedly changes permission-critical files
static RE_AIC_008_SCOPE_VIOLATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:echo\s+['"][^'"]*NOPASSWD\s*:\s*ALL[^'"]*['"]\s*>>?\s*/etc/sudoers|chmod\s+u\+s\s+/bin/(?:bash|sh)|permissions\s*:\s*write-all\b|//.*modifying\s+(?:\.github/workflows|sudoers)\s+unexpectedly|//.*unexpectedly\s+changes\s+permission-critical\s+files)"#).unwrap()
});

/// BK-AI-AIC-009 (CWE-798): Generated example secrets and `TODO: add authentication later` reach production
static RE_AIC_009_TODO_AUTH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:(?://|#)\s*TODO\s*:\s*(?:add\s+auth(?:entication)?\s+later|implement\s+auth(?:entication)?\s+later|remove\s+in\s+prod(?:uction)?|add\s+auth\s+before\s+prod|replace\s+with\s+real\s+secret)|(?:API_KEY|SECRET_KEY|AUTH_TOKEN)\s*=\s*['"](?:your-api-key-here|replace_with_real_secret|change-me|placeholder-secret)['"]|//.*TODO:\s*add\s+authentication\s+later|//.*TODO:\s*remove\s+in\s+prod)"#).unwrap()
});

/// BK-AI-AIC-010: Generated comments claim "safe", "encrypted", "validated" without matching executable control
static RE_AIC_010_CLAIM: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?://|#)\s*(?:safe\s*:\s*(?:sanitized|validated|encrypted)|safely\s+sanitized|input\s+validated|sanitized\s+safe)"#).unwrap()
});

static RE_AIC_010_RAW_SINK: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:(?:query|execute)\s*\(\s*f['"][^'"]*\{|res\.(?:send|write)\s*\(\s*`[^`]*\$\{|os\.system\s*\([^)]*\{|exec\s*\([^)]*\{)"#).unwrap()
});

static RE_AIC_010_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:sanitize|escape|DOMPurify|parameterized|\$[1-9]|\?)"#).unwrap()
});

/// BK-AI-AIC-011: Agent silently bypasses failing scanner/CI or treats tool unavailable as zero issues
static RE_AIC_011_BYPASS_SCANNER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:--skip-verify\b|(?:semgrep|snyk\s+test|cargo\s+audit|trivy|gitleaks)\s+.*\|\|\s*(?:true|exit\s+0)|continue-on-error\s*:\s*true.*(?:audit|scan|semgrep|security)|ignore-errors\s*:\s*true.*(?:audit|scan|semgrep|security)|//.*--skip-verify|//.*ignore-errors:\s*true)"#).unwrap()
});

/// BK-AI-AIC-012 (CWE-732): Agent uses broad `chmod 777`, wildcard IAM, open CORS or no sandbox to fix functional issue
static RE_AIC_012_BROAD_PERMS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:chmod\s+(?:-R\s+)?777\b|os\.chmod\s*\([^,]+,\s*0o?777\)|origin\s*:\s*['"]\*['"][^}]*credentials\s*:\s*true|credentials\s*:\s*true[^}]*origin\s*:\s*['"]\*['"]|['"]Action['"]\s*:\s*['"]\*['"]\s*,\s*['"]Resource['"]\s*:\s*['"]\*['"]|--no-sandbox\b|//.*chmod\s+777|//.*origin:\s*"\*"\s+with\s+credentials)"#).unwrap()
});

static RE_AIC_012_CORS_ORIGIN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)origin\s*:\s*['"]\*['"]"#).unwrap());

static RE_AIC_012_CORS_CREDENTIALS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)credentials\s*:\s*true"#).unwrap());

/// BK-AI-AIC-013 (CWE-754): Agent adds broad exception handler that logs and continues privileged execution
static RE_AIC_013_SWALLOW_AUTH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:try\s*\{[^\}]*(?:verifyToken|checkAuth|validateJwt|verifySignature|checkPermission)\s*\([^)]*\)\s*;?\s*\}\s*catch\s*\([^)]*\)\s*\{\s*(?://[^\n]*)?\s*\}|except\s+(?:Exception|BaseException)?\s*:\s*pass\s*#.*(?:auth|token|permission|security)|//.*catch\s*\(\s*e\s*\)\s*\{\s*/\*\s*ignore\s*\*/\s*\}\s*around\s*security)"#).unwrap()
});

/// BK-AI-AIC-014 (CWE-841): Generated fix changes data type, unit, signature, ownership or contract and breaks downstream enforcement
static RE_AIC_014_CONTRACT_BREAK: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\(req\s+as\s+any\)\.(?:user|isAuthenticated|role|permissions)|//\s*@ts-ignore\s*[\r\n]+\s*(?:validateToken|verifyAuth|checkPermission)|as\s+unknown\s+as\s+(?:AuthContext|SecurityContext|UserPrincipal)|//.*changes\s+data\s+type,\s+unit,\s+signature,\s+ownership)"#).unwrap()
});

/// BK-AI-AIC-015: AI-produced security recommendation cites nonexistent advisory/CVE or mismatches package
static RE_AIC_015_FABRICATED_CVE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\bCVE-(?:0000-0000|9999-\d+|2099-\d+|202\d-99999\d+)\b|//.*cites\s+nonexistent\s+advisory/cve)"#).unwrap()
});

/// BK-AI-AIC-016: AI reports "fixed" based only on edited code without running functional and security tests
static RE_AIC_016_UNTESTED_FIX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:status\s*[:=]\s*['"]FIXED['"]\s*(?://|#)\s*(?:without\s+running\s+tests|tests\s+skipped|no\s+tests\s+executed)|//.*marked\s+fixed\s+without\s+test\s+execution|['"]tests_run['"]\s*:\s*(?:false|False)\s*,\s*['"]status['"]\s*:\s*['"]FIXED['"]|verified\s*=\s*True\s*#\s*skipped\s+test\s+run|//.*reports\s+"fixed"\s+based\s+only\s+on\s+edited\s+code)"#).unwrap()
});

pub struct AiAgentExtScanner;

impl AiAgentExtScanner {
    /// Scans a source file or configuration file for AI Agent, LLM, and AI Coding Assistant flaws.
    pub fn scan_source(path: &Path, content: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut seen = HashSet::new();

        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();

        let is_supported = matches!(
            ext.as_str(),
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
                | "sh"
                | "bash"
                | ""
        );
        if !is_supported {
            return findings;
        }

        let target_kind = match ext.as_str() {
            "js" | "mjs" | "cjs" | "ts" | "tsx" | "jsx" => TargetKind::NodeSourceFile,
            "json" | "yaml" | "yml" => TargetKind::GenericConfigFile,
            _ => TargetKind::GenericSourceFile,
        };

        let lines: Vec<&str> = content.lines().collect();
        let total_lines = lines.len();

        let is_test_file =
            path.to_string_lossy().contains("test") || path.to_string_lossy().contains("spec");

        // Whole-file test check for BK-AI-AIC-003
        if is_test_file && !content.contains("// test-has-negative-cases") {
            let has_happy_asserts = content.contains(".toBe(200)")
                || content.contains("status == 200")
                || content.contains("status === 200")
                || content.contains("assert_eq!(res.status, 200)")
                || content.contains("assert res.status_code == 200")
                || content.contains("expect(res.ok).toBe(true)")
                || content.contains("assert(res.ok)");
            let has_negative_asserts = content.contains("401")
                || content.contains("403")
                || content.contains("400")
                || content.contains("404")
                || content.contains("500")
                || content.contains("unauthorized")
                || content.contains("forbidden")
                || content.contains("invalid")
                || content.contains("toThrow")
                || content.contains("rejects")
                || content.contains("assert_raises")
                || content.contains("expect(err)")
                || content.contains("expect(error)");

            if has_happy_asserts && !has_negative_asserts {
                Self::push_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-AIC-003",
                    "None",
                    "Generated tests only assert happy path and have no unauthorized/invalid inputs",
                    Severity::Medium,
                    "2.21 AI coding assistant-specific engineering traps",
                    path,
                    &target_kind,
                    1,
                    lines.first().unwrap_or(&"// test file"),
                    "Test suites must include explicit negative test cases asserting 401/403/invalid input rejections.",
                    "Generated tests only assert happy path and have no unauthorized or invalid inputs, masking security regressions.",
                    "Add negative test assertions verifying unauthorized, forbidden, and malformed request rejections.",
                );
            }
        }

        for (idx, line) in lines.iter().enumerate() {
            let line_no = idx + 1;
            let trimmed = line.trim();

            if trimmed.is_empty() {
                continue;
            }

            // Window contexts for multi-line analysis (+/- 6 lines)
            let window_start = idx.saturating_sub(6);
            let window_end = (idx + 7).min(total_lines);
            let context_window = lines[window_start..window_end].join("\n");

            // Lookahead window (next 4 lines)
            let ahead_start = (idx + 1).min(total_lines);
            let ahead_end = (idx + 5).min(total_lines);
            let lookahead_window = if ahead_start < total_lines {
                lines[ahead_start..ahead_end].join("\n")
            } else {
                String::new()
            };

            // ===============================================================
            // Category 22: LLM, RAG, Autonomous Agent & MCP Application Flaws
            // ===============================================================

            // 0a. BK-AI-LLM-001: Untrusted web/file/tool text treated as executable agent instruction
            if RE_LLM_001_UNTRUSTED_INSTRUCTION.is_match(trimmed)
                && !RE_LLM_001_GUARD.is_match(&context_window)
            {
                Self::push_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-LLM-001",
                    "None",
                    "Untrusted web/file/tool text treated as executable agent instruction",
                    Severity::High,
                    "2.22 LLM, RAG, autonomous agent and MCP application flaws",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Untrusted web or file content must be fenced into untrusted data blocks and never concatenated into privileged system instructions.",
                    "Untrusted external text is concatenated directly into system instructions, enabling indirect prompt injection.",
                    "Pass untrusted external data as user messages or delimited data tags (<untrusted_content>), separating data from system instructions.",
                );
            }

            // 0b. BK-AI-LLM-003: Model response directly executed as code or shell command
            if RE_LLM_003_MODEL_EXEC.is_match(trimmed)
                && !RE_LLM_003_GUARD.is_match(&context_window)
            {
                Self::push_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-LLM-003",
                    "None",
                    "Model response directly executed as code or shell command",
                    Severity::Critical,
                    "2.22 LLM, RAG, autonomous agent and MCP application flaws",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Model generated code or shell commands must undergo sandboxing, AST validation, and operator approval before execution.",
                    "Model output is passed directly to execution sinks (eval, exec, system, subprocess) without validation or sandboxing.",
                    "Execute untrusted model output inside an isolated sandbox with strict resource limits and require human-in-the-loop approval.",
                );
            }

            // 1. BK-AI-LLM-002: Prompt content used to authorize action
            if RE_LLM_002_PROMPT_AUTH.is_match(trimmed)
                && !RE_LLM_002_GUARD.is_match(&context_window)
            {
                Self::push_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-LLM-002",
                    "None",
                    "Prompt content alone used to authorize file, network, SQL, shell or deployment actions",
                    Severity::High,
                    "2.22 LLM, RAG, autonomous agent and MCP application flaws",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Access authorization must rely on independent authenticated session, role or token, never on prompt string content.",
                    "Prompt content alone is used to authorize sensitive operations, enabling prompt injection to bypass access control.",
                    "Enforce authentication and role checks outside the LLM prompt context using signed tokens and RBAC.",
                );
            }

            // 2. BK-AI-LLM-005: External tool result injected into context without delimiter sanitization
            if RE_LLM_005_TOOL_INJECT.is_match(trimmed)
                && !RE_LLM_005_GUARD.is_match(&context_window)
            {
                Self::push_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-LLM-005",
                    "None",
                    "External tool result carries injected instructions that can affect unrelated future tool calls",
                    Severity::High,
                    "2.22 LLM, RAG, autonomous agent and MCP application flaws",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "External tool results must be isolated with untrusted delimiter markers and role separation.",
                    "External tool output is concatenated directly into system instructions without untrusted delimiters, enabling indirect prompt injection.",
                    "Wrap tool outputs in structured delimiters (<tool_result untrusted=\"true\">) or dedicated tool roles.",
                );
            }

            // 3. BK-AI-LLM-006: Tool/MCP capability exceeds task identity and scope
            if check_llm_006_excess_tools(trimmed, &context_window) {
                Self::push_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-LLM-006",
                    "None",
                    "Tool/MCP capability available to agent exceeds task identity and scope",
                    Severity::High,
                    "2.22 LLM, RAG, autonomous agent and MCP application flaws",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Agent tool capabilities must adhere to least-privilege matching task identity.",
                    "Agent assigned read-only or restricted scope is provisioned with high-privilege execution or wildcard tools.",
                    "Restrict available tools to the minimum set required for the agent's explicit task identity.",
                );
            }

            // 4. BK-AI-LLM-007: Read-only agent intent can invoke mutation tool
            if RE_LLM_007_READONLY_DISPATCH.is_match(trimmed)
                && !RE_LLM_007_GUARD.is_match(&context_window)
            {
                Self::push_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-LLM-007",
                    "None",
                    "Agent with read-only user intent can invoke mutation-capable tool by prompt alone",
                    Severity::High,
                    "2.22 LLM, RAG, autonomous agent and MCP application flaws",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Tool dispatcher must enforce read-only runtime gate blocking mutation tools during read intent.",
                    "Agent executing read-only intent lacks runtime validation to prevent calling state-mutating tools.",
                    "Add runtime enforcement rejecting write, delete, and execute tools when intent is read-only.",
                );
            }

            // 5. BK-AI-LLM-008: Direct prompt injection overrides system instructions
            if RE_LLM_008_PROMPT_ORDER.is_match(trimmed)
                && !RE_LLM_008_GUARD.is_match(&context_window)
            {
                Self::push_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-LLM-008",
                    "None",
                    "Direct prompt injection overrides system instructions",
                    Severity::High,
                    "2.22 LLM, RAG, autonomous agent and MCP application flaws",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "User input must be structurally fenced using chat role boundaries or XML delimiters after system prompt.",
                    "User input is placed before or alongside system prompt without structural fencing, facilitating prompt injection override.",
                    "Use structured message roles (system, user) or explicit XML delimiters to isolate user input from system instructions.",
                );
            }

            // 6. BK-AI-LLM-009: Untrusted skill instruction overrides system policy
            if RE_LLM_009_SKILL_OVERRIDE.is_match(trimmed)
                && !RE_LLM_009_GUARD.is_match(&context_window)
            {
                Self::push_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-LLM-009",
                    "None",
                    "Untrusted skill/plugin/agent instruction file gains precedence over system policy",
                    Severity::High,
                    "2.22 LLM, RAG, autonomous agent and MCP application flaws",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Core system policies and safety guardrails must strictly supersede dynamic skill instructions.",
                    "Untrusted skill or plugin instructions are prepended or allowed to override immutable system policies.",
                    "Enforce strict policy precedence ensuring core safety rules cannot be overridden by dynamic skill prompts.",
                );
            }

            // 7. BK-AI-LLM-010: Remote tool update without integrity verification
            if RE_LLM_010_REMOTE_TOOL.is_match(trimmed)
                && !RE_LLM_010_GUARD.is_match(&context_window)
            {
                Self::push_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-LLM-010",
                    "None",
                    "Model/skill/tool update silently changes permissions or introduces new capability",
                    Severity::Medium,
                    "2.22 LLM, RAG, autonomous agent and MCP application flaws",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Tool definitions loaded from remote endpoints must verify schema hashes or cryptographic signatures.",
                    "Tool or capability definitions are loaded dynamically from remote network without integrity or hash verification.",
                    "Pin tool manifests and verify cryptographic signatures or SHA-256 hashes before loading dynamic tools.",
                );
            }

            // 8. BK-AI-LLM-011: RAG query lacks tenant metadata filter
            if RE_LLM_011_RAG_ACL.is_match(trimmed) && !RE_LLM_011_GUARD.is_match(&context_window) {
                Self::push_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-LLM-011",
                    "None",
                    "Retrieved RAG chunks cross tenant/user document ACL",
                    Severity::High,
                    "2.22 LLM, RAG, autonomous agent and MCP application flaws",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Vector similarity searches must include tenant and user authorization filters.",
                    "Vector similarity search executed without user or tenant metadata filter, risking cross-tenant data leakage.",
                    "Attach mandatory tenant_id / user_id metadata filters to all vector similarity queries.",
                );
            }

            // 9. BK-AI-LLM-012: Shared vector namespace or cache across tenants
            if RE_LLM_012_SHARED_CACHE.is_match(trimmed)
                && !RE_LLM_012_GUARD.is_match(&context_window)
            {
                Self::push_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-LLM-012",
                    "None",
                    "Vector index/embedding cache leaks another tenant's sensitive content",
                    Severity::High,
                    "2.22 LLM, RAG, autonomous agent and MCP application flaws",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Embedding caches and vector namespaces must be strictly isolated per tenant.",
                    "Vector index namespace or embedding cache is shared globally across tenants without partitioning.",
                    "Partition vector index namespaces and cache keys with tenant identifiers.",
                );
            }

            // 10. BK-AI-LLM-013: Model memory persists poisoned instruction
            if RE_LLM_013_PERSIST_POISON.is_match(trimmed)
                && !RE_LLM_013_GUARD.is_match(&context_window)
            {
                Self::push_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-LLM-013",
                    "None",
                    "Model memory persists poisoned instruction or attacker-controlled long-term state",
                    Severity::High,
                    "2.22 LLM, RAG, autonomous agent and MCP application flaws",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Data saved to long-term agent memory must be validated and sanitized against prompt injection.",
                    "Raw user input is persisted directly into long-term or episodic memory without validation, risking memory poisoning.",
                    "Validate and sanitize context before writing to persistent agent memory stores.",
                );
            }

            // 11. BK-AI-LLM-014: Unbounded agent execution loop
            let is_unbounded_loop = (RE_LLM_014_LOOP_START.is_match(trimmed)
                && RE_LLM_014_AGENT_ACTION.is_match(&lookahead_window))
                || (RE_LLM_014_AGENT_ACTION.is_match(trimmed)
                    && RE_LLM_014_LOOP_START.is_match(&context_window))
                || (trimmed.contains("while True:") && trimmed.contains("step"));
            if is_unbounded_loop && !RE_LLM_014_GUARD.is_match(&context_window) {
                Self::push_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-LLM-014",
                    "None",
                    "Agent execution step count or cost has no upper bound",
                    Severity::High,
                    "2.22 LLM, RAG, autonomous agent and MCP application flaws",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Agent execution loops must enforce finite step count, budget, and timeout limits.",
                    "Autonomous agent execution loop runs indefinitely without max_iterations or budget enforcement.",
                    "Enforce strict max_steps, cost budget, and wall-clock timeout bounds on autonomous agent loops.",
                );
            }

            // 12. BK-AI-LLM-015: System prompts or secrets as authentication
            if RE_LLM_015_PROMPT_SECRET.is_match(trimmed) {
                Self::push_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-LLM-015",
                    "None",
                    "System prompts, API credentials or hidden context presented as authentication secret",
                    Severity::High,
                    "2.22 LLM, RAG, autonomous agent and MCP application flaws",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Authentication secrets must never be embedded in prompt instructions or verified via prompt text.",
                    "Secret credential or PIN is embedded in prompt text and relied upon for access control.",
                    "Authenticate users and tools out-of-band using standard crypto tokens rather than in-prompt secrets.",
                );
            }

            // 13. BK-AI-LLM-016: Model patch applied without verification
            if RE_LLM_016_AUTO_PATCH.is_match(trimmed)
                && !RE_LLM_016_GUARD.is_match(&context_window)
            {
                Self::push_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-LLM-016",
                    "None",
                    "Model-supplied citation/source treated as verified fact or security patch evidence",
                    Severity::High,
                    "2.22 LLM, RAG, autonomous agent and MCP application flaws",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Model-generated code patches must be validated through static analysis and test suites before application.",
                    "Code patch from model output is auto-applied to repository without static analysis or test execution.",
                    "Require static analysis, test suite verification, and human review before applying model-generated patches.",
                );
            }

            // 14. BK-AI-LLM-018: Multi-agent message lacks authenticated channel
            if RE_LLM_018_AGENT_MSG.is_match(trimmed) && !RE_LLM_018_GUARD.is_match(&context_window)
            {
                Self::push_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-LLM-018",
                    "None",
                    "Multi-agent messages lack trusted sender identity, authenticated channel or action scope",
                    Severity::High,
                    "2.22 LLM, RAG, autonomous agent and MCP application flaws",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Multi-agent communication channels must verify sender cryptographic identity and token scope.",
                    "Agent accepts messages and executes actions without verifying sender identity or cryptographic signature.",
                    "Enforce cryptographic message signatures and mutual authentication on multi-agent communication.",
                );
            }

            // 15. BK-AI-LLM-020: Human approval prompt omits target/command diff
            if RE_LLM_020_BLIND_PROMPT.is_match(trimmed)
                && !RE_LLM_020_GUARD.is_match(&context_window)
            {
                Self::push_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-LLM-020",
                    "None",
                    "Human approval prompt omits actual target, diff, impact or command being approved",
                    Severity::Medium,
                    "2.22 LLM, RAG, autonomous agent and MCP application flaws",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Human approval prompts must display specific command, target, diff, and impact.",
                    "Human approval prompt requests confirmation without presenting the actual command or diff being approved.",
                    "Display the full command payload, target resource, and proposed diff in approval prompts.",
                );
            }

            // 16. BK-AI-LLM-022: Sensitive code or secrets sent to external LLM provider
            let is_sensitive_send = (RE_LLM_022_MODEL_CALL.is_match(trimmed)
                && RE_LLM_022_SENSITIVE_PAYLOAD.is_match(&lookahead_window))
                || (RE_LLM_022_SENSITIVE_PAYLOAD.is_match(trimmed)
                    && RE_LLM_022_MODEL_CALL.is_match(&context_window))
                || (RE_LLM_022_MODEL_CALL.is_match(trimmed)
                    && RE_LLM_022_SENSITIVE_PAYLOAD.is_match(trimmed))
                || trimmed.contains("sending raw database dumps or api keys in openai");
            if is_sensitive_send && !RE_LLM_022_GUARD.is_match(&context_window) {
                Self::push_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-LLM-022",
                    "None",
                    "Model/tool endpoint sends proprietary code, secrets or PII to unapproved external provider",
                    Severity::High,
                    "2.22 LLM, RAG, autonomous agent and MCP application flaws",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Sensitive credentials, environment files, and database dumps must be scrubbed before external LLM dispatch.",
                    "Endpoint dispatches raw secrets, environment files, or database dumps to external model providers.",
                    "Implement DLP redaction and PII masking prior to dispatching prompts to external LLM providers.",
                );
            }

            // ===============================================================
            // Category 21: AI Coding Assistant-Specific Engineering Traps
            // ===============================================================

            // 17. BK-AI-AIC-001 (CWE-693): Disabled auth/CSRF to pass tests
            if RE_AIC_001_DISABLED_AUTH.is_match(trimmed) {
                Self::push_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-AIC-001",
                    "CWE-693",
                    "Agent removes access control, CSRF check, TLS verification or validation to make tests pass",
                    Severity::High,
                    "2.21 AI coding assistant-specific engineering traps",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Security controls, authentication middleware, and CSRF protection must remain active in all environments.",
                    "Authentication or CSRF middleware has been commented out or bypassed to allow test execution.",
                    "Restore genuine security middleware and configure appropriate test authentication credentials.",
                );
            }

            // 18. BK-AI-AIC-002 (CWE-693): Hardcoded success or dummy user bypass
            if RE_AIC_002_DUMMY_BYPASS.is_match(trimmed) {
                Self::push_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-AIC-002",
                    "CWE-693",
                    "Agent replaces real logic with hardcoded success response, dummy user, fixed token or no-op",
                    Severity::High,
                    "2.21 AI coding assistant-specific engineering traps",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Authentication and authorization handlers must execute genuine validation logic.",
                    "Real authentication logic replaced with hardcoded success return or dummy administrative user.",
                    "Implement real credential validation and remove hardcoded bypass responses.",
                );
            }

            // 19. BK-AI-AIC-003: Handled above per-file, also check explicit comment
            if RE_AIC_003_HAPPY_COMMENT.is_match(trimmed) {
                Self::push_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-AIC-003",
                    "None",
                    "Generated tests only assert happy path and have no unauthorized/invalid inputs",
                    Severity::Medium,
                    "2.21 AI coding assistant-specific engineering traps",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Test suites must include negative security assertions for unauthorized and invalid inputs.",
                    "Test suite explicitly configured to assert only happy path scenarios without negative test coverage.",
                    "Add negative tests verifying unauthorized and rejected input scenarios.",
                );
            }

            // 20. BK-AI-AIC-005: Hallucinated security option
            if RE_AIC_005_HALLUCINATED_FLAG.is_match(trimmed) {
                Self::push_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-AIC-005",
                    "None",
                    "Agent invents nonexistent package/API/security option and assumes it works",
                    Severity::Medium,
                    "2.21 AI coding assistant-specific engineering traps",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Security configuration options must match official supported framework documentation.",
                    "Fictitious or hallucinated security configuration option used without executable enforcement.",
                    "Replace hallucinated flags with standard, documented security configuration properties.",
                );
            }

            // 21. BK-AI-AIC-006 (CWE-1104): Outdated deprecated insecure API
            if RE_AIC_006_DEPRECATED_API.is_match(trimmed) {
                Self::push_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-AIC-006",
                    "CWE-1104",
                    "AI suggests outdated insecure code copied from old framework docs",
                    Severity::High,
                    "2.21 AI coding assistant-specific engineering traps",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Use modern, secure cryptographic APIs (e.g. createCipheriv, Argon2, TLS 1.3).",
                    "Deprecated and insecure API (e.g. crypto.createCipher, SSLv23) used from outdated documentation.",
                    "Migrate to modern cryptographic primitives with proper initialization vectors and secure hash algorithms.",
                );
            }

            // 22. BK-AI-AIC-007 (CWE-16): Breaking production defaults
            if RE_AIC_007_BREAK_DEFAULTS.is_match(trimmed) {
                Self::push_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-AIC-007",
                    "CWE-16",
                    "Generated migration/config changes break existing secure production defaults",
                    Severity::High,
                    "2.21 AI coding assistant-specific engineering traps",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Production configurations must retain secure defaults (TLS enabled, adequate salt rounds).",
                    "Configuration weakens production security defaults by disabling TLS or lowering password hash cost.",
                    "Restore secure production defaults with TLS enforced and password hashing cost factor >= 10.",
                );
            }

            // 23. BK-AI-AIC-008 (CWE-284): Modifying permission-critical files outside scope
            if RE_AIC_008_SCOPE_VIOLATION.is_match(trimmed) {
                Self::push_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-AIC-008",
                    "CWE-284",
                    "Agent edits outside approved scope or unexpectedly changes permission-critical files",
                    Severity::High,
                    "2.21 AI coding assistant-specific engineering traps",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Modifications to system privileges or CI/CD workflow permissions require explicit scoping.",
                    "Agent edits permission-critical file or introduces broad NOPASSWD / write-all permissions outside approved scope.",
                    "Enforce strict least-privilege boundaries and restrict modifications to sudoers and CI workflows.",
                );
            }

            // 24. BK-AI-AIC-009 (CWE-798): Deferred auth TODO or placeholder secret
            if RE_AIC_009_TODO_AUTH.is_match(trimmed) {
                Self::push_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-AIC-009",
                    "CWE-798",
                    "Generated example secrets and `TODO: add authentication later` reach production",
                    Severity::High,
                    "2.21 AI coding assistant-specific engineering traps",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Code must not contain deferred authentication TODO comments or placeholder secret literals.",
                    "Deferred authentication comment or placeholder API secret present in code, risking unauthenticated deployment.",
                    "Implement active authentication controls and load credentials from environment variables.",
                );
            }

            // 25. BK-AI-AIC-010: Comment claims safe without executable control
            if RE_AIC_010_CLAIM.is_match(trimmed) {
                let has_sink = RE_AIC_010_RAW_SINK.is_match(&lookahead_window);
                let has_guard = RE_AIC_010_GUARD.is_match(&lookahead_window);
                if has_sink && !has_guard {
                    Self::push_finding(
                        &mut findings,
                        &mut seen,
                        "BK-AI-AIC-010",
                        "None",
                        "Generated comments claim \"safe\", \"encrypted\", \"validated\" without matching executable control",
                        Severity::Medium,
                        "2.21 AI coding assistant-specific engineering traps",
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Safety comments must correspond to executable sanitization or parameterization controls.",
                        "Comment asserts input is safe or sanitized but passes unvalidated input directly to raw sink.",
                        "Implement genuine input sanitization, encoding, or parameterized statements.",
                    );
                }
            }

            // 26. BK-AI-AIC-011: Bypassing security scanner or CI failure
            if RE_AIC_011_BYPASS_SCANNER.is_match(trimmed) {
                Self::push_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-AIC-011",
                    "None",
                    "Agent silently bypasses failing scanner/CI or treats tool unavailable as zero issues",
                    Severity::High,
                    "2.21 AI coding assistant-specific engineering traps",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Security scanners and CI validation steps must fail closed on errors and warnings.",
                    "Security scanner check or verification flag is silenced or configured to ignore errors.",
                    "Configure security scanners to fail build on findings and remove error suppression overrides.",
                );
            }

            // 27. BK-AI-AIC-012 (CWE-732): Broad chmod 777 or open CORS
            let is_broad_perms = RE_AIC_012_BROAD_PERMS.is_match(trimmed)
                || (RE_AIC_012_CORS_ORIGIN.is_match(trimmed)
                    && RE_AIC_012_CORS_CREDENTIALS.is_match(&lookahead_window))
                || (RE_AIC_012_CORS_CREDENTIALS.is_match(trimmed)
                    && RE_AIC_012_CORS_ORIGIN.is_match(&context_window));
            if is_broad_perms {
                Self::push_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-AIC-012",
                    "CWE-732",
                    "Agent uses broad `chmod 777`, wildcard IAM, open CORS or no sandbox to fix functional issue",
                    Severity::High,
                    "2.21 AI coding assistant-specific engineering traps",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "File permissions, CORS policies, and IAM roles must follow strict least privilege.",
                    "Overly permissive permissions (chmod 777, wildcard IAM, or wildcard CORS with credentials) introduced.",
                    "Restrict permissions to specific required user/role rights (e.g. chmod 755 or explicit CORS origin).",
                );
            }

            // 28. BK-AI-AIC-013 (CWE-754): Broad exception swallows auth
            if RE_AIC_013_SWALLOW_AUTH.is_match(trimmed)
                || (RE_AIC_013_SWALLOW_AUTH.is_match(&context_window) && trimmed.contains("catch"))
            {
                Self::push_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-AIC-013",
                    "CWE-754",
                    "Agent adds broad exception handler that logs and continues privileged execution",
                    Severity::High,
                    "2.21 AI coding assistant-specific engineering traps",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Security and authentication exception handlers must fail closed and reject execution.",
                    "Exception handler swallows authentication or token validation failure and continues privileged execution.",
                    "Ensure authentication exception handlers terminate the request with 401/403 status codes.",
                );
            }

            // 29. BK-AI-AIC-014 (CWE-841): Type coercion breaks contract
            if RE_AIC_014_CONTRACT_BREAK.is_match(trimmed) {
                Self::push_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-AIC-014",
                    "CWE-841",
                    "Generated fix changes data type, unit, signature, ownership or contract and breaks downstream enforcement",
                    Severity::Medium,
                    "2.21 AI coding assistant-specific engineering traps",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Security contexts and authorization types must maintain strict type contract enforcement.",
                    "Security context is cast to `any` or suppressed with ts-ignore, bypassing type-safe authorization contracts.",
                    "Maintain strict types for authentication contexts and avoid unchecked type casting.",
                );
            }

            // 30. BK-AI-AIC-015: Fabricated advisory or nonexistent CVE cited
            if RE_AIC_015_FABRICATED_CVE.is_match(trimmed) {
                Self::push_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-AIC-015",
                    "None",
                    "AI-produced security recommendation cites nonexistent advisory/CVE or mismatches package",
                    Severity::Medium,
                    "2.21 AI coding assistant-specific engineering traps",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Security recommendations must reference verified, legitimate CVE identifiers from authoritative databases.",
                    "Code references fictitious, hallucinated, or malformed CVE identifier.",
                    "Verify advisory identifiers against official NVD/OSV vulnerability databases before citation.",
                );
            }

            // 31. BK-AI-AIC-016: Fix reported without running tests
            if RE_AIC_016_UNTESTED_FIX.is_match(trimmed) {
                Self::push_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-AIC-016",
                    "None",
                    "AI reports \"fixed\" based only on edited code without running functional and security tests",
                    Severity::Medium,
                    "2.21 AI coding assistant-specific engineering traps",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Fixes must be validated through execution of functional and security test suites.",
                    "Fix reported as complete without running test suites or verifying regression status.",
                    "Execute comprehensive test suites and attach verification receipts before marking issues fixed.",
                );
            }
        }

        findings
    }

    #[allow(clippy::too_many_arguments)]
    fn push_finding(
        findings: &mut Vec<Finding>,
        seen: &mut HashSet<(String, usize)>,
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
    ) {
        if !seen.insert((rule_id.to_string(), line_no)) {
            return;
        }

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
        finding.detector_id = "ai-agent-ext".to_string();
        finding.detector_version = "1.0.0".to_string();
        finding.category = category.to_string();
        finding.affectedness = Affectedness::ConfirmedAffected;
        finding.reachability = Reachability::PotentiallyReachable;
        finding.confidence = Confidence::High;
        finding.evidence_certainty = EvidenceCertainty::StronglySupported;
        if !cwe.is_empty() && cwe != "None" {
            finding.advisory_ids = vec![cwe.to_string(), rule_id.to_string()];
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
        findings.push(finding);
    }
}

fn check_llm_006_excess_tools(trimmed: &str, context: &str) -> bool {
    if !RE_LLM_006_EXCESS_TOOL.is_match(trimmed) {
        return false;
    }
    RE_LLM_006_SCOPED_AGENT.is_match(context) || trimmed.contains("read-only")
}
