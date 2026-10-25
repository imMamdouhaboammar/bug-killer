use bug_killer::types::{self, Severity};
use std::path::Path;

#[path = "../src/scanner/ai_agent_ext.rs"]
mod ai_agent_ext;

use ai_agent_ext::AiAgentExtScanner;

// ============================================================================
// Category 22: LLM, RAG, Autonomous Agent & MCP Application Flaws
// ============================================================================

#[test]
fn test_llm_002_prompt_auth_vulnerable() {
    let snippet = r#"
def handle_action(user_prompt):
    if "approve" in user_prompt.lower():
        execute_deployment()
"#;
    let findings = AiAgentExtScanner::scan_source(Path::new("agent.py"), snippet);
    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-LLM-002")
        .expect("Must detect prompt authorization");
    assert_eq!(f.severity, Severity::High);
    assert_eq!(f.detector_id, "ai-agent-ext");
}

#[test]
fn test_llm_002_prompt_auth_safe() {
    let snippet = r#"
def handle_action(user_prompt, token):
    if verify_token(token) and has_role(session.user, "admin"):
        execute_deployment()
"#;
    let findings = AiAgentExtScanner::scan_source(Path::new("agent.py"), snippet);
    assert!(findings.iter().all(|f| f.cve.as_str() != "BK-AI-LLM-002"));
}

#[test]
fn test_llm_005_tool_injection_vulnerable() {
    let snippet = r#"
async function runLoop(toolResult) {
    system_prompt += tool_output;
    messages.push({ role: "system", content: toolResult });
}
"#;
    let findings = AiAgentExtScanner::scan_source(Path::new("agent.ts"), snippet);
    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-LLM-005")
        .expect("Must detect raw tool injection into system context");
    assert_eq!(f.severity, Severity::High);
}

#[test]
fn test_llm_005_tool_injection_safe() {
    let snippet = r#"
async function runLoop(toolResult) {
    messages.push({
        role: "tool",
        content: `<tool_output untrusted="true">${sanitize_tool_output(toolResult)}</tool_output>`
    });
}
"#;
    let findings = AiAgentExtScanner::scan_source(Path::new("agent.ts"), snippet);
    assert!(findings.iter().all(|f| f.cve.as_str() != "BK-AI-LLM-005"));
}

#[test]
fn test_llm_006_excess_tools_vulnerable() {
    let snippet = r#"
{
  "name": "doc-analyst",
  "role": "reader",
  "tools": ["exec_command", "read_file"]
}
"#;
    let findings = AiAgentExtScanner::scan_source(Path::new("agent_config.json"), snippet);
    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-LLM-006")
        .expect("Must detect exec_command granted to reader agent");
    assert_eq!(f.severity, Severity::High);
}

#[test]
fn test_llm_006_excess_tools_safe() {
    let snippet = r#"
{
  "name": "doc-analyst",
  "role": "reader",
  "tools": ["read_file", "search_docs"]
}
"#;
    let findings = AiAgentExtScanner::scan_source(Path::new("agent_config.json"), snippet);
    assert!(findings.iter().all(|f| f.cve.as_str() != "BK-AI-LLM-006"));
}

#[test]
fn test_llm_007_readonly_mutation_vulnerable() {
    let snippet = r#"
def execute_tool(tool_name, args, read_only=True):
    // read-only intent can invoke mutation
    dispatch_tool(tool_name, args)
"#;
    let findings = AiAgentExtScanner::scan_source(Path::new("dispatcher.py"), snippet);
    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-LLM-007")
        .expect("Must detect missing mutation guard on read-only dispatch");
    assert_eq!(f.severity, Severity::High);
}

#[test]
fn test_llm_007_readonly_mutation_safe() {
    let snippet = r#"
def execute_tool(tool_name, args, read_only=True):
    if read_only and is_mutating(tool_name):
        raise PermissionError("Mutation tool blocked under read-only intent")
    dispatch_tool(tool_name, args)
"#;
    let findings = AiAgentExtScanner::scan_source(Path::new("dispatcher.py"), snippet);
    assert!(findings.iter().all(|f| f.cve.as_str() != "BK-AI-LLM-007"));
}

#[test]
fn test_llm_008_prompt_order_vulnerable() {
    let snippet = r#"
def build_prompt(user_input, system_prompt):
    return user_input + "\n---\n" + system_prompt
"#;
    let findings = AiAgentExtScanner::scan_source(Path::new("prompt.py"), snippet);
    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-LLM-008")
        .expect("Must detect user input placed before system prompt");
    assert_eq!(f.severity, Severity::High);
}

#[test]
fn test_llm_008_prompt_order_safe() {
    let snippet = r#"
def build_prompt(user_input, system_prompt):
    return [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_input}
    ]
"#;
    let findings = AiAgentExtScanner::scan_source(Path::new("prompt.py"), snippet);
    assert!(findings.iter().all(|f| f.cve.as_str() != "BK-AI-LLM-008"));
}

#[test]
fn test_llm_009_skill_override_vulnerable() {
    let snippet = r#"
def init_agent(skill_instructions, base_policy):
    system_prompt = skill_instructions + "\n" + base_policy
    return system_prompt
"#;
    let findings = AiAgentExtScanner::scan_source(Path::new("loader.py"), snippet);
    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-LLM-009")
        .expect("Must detect skill prompt prepended over system policy");
    assert_eq!(f.severity, Severity::High);
}

#[test]
fn test_llm_009_skill_override_safe() {
    let snippet = r#"
def init_agent(skill_instructions, base_policy):
    enforce_policy_precedence(base_policy)
    return base_policy + "\nSkills:\n" + skill_instructions
"#;
    let findings = AiAgentExtScanner::scan_source(Path::new("loader.py"), snippet);
    assert!(findings.iter().all(|f| f.cve.as_str() != "BK-AI-LLM-009"));
}

#[test]
fn test_llm_010_remote_tool_vulnerable() {
    let snippet = r#"
async function setupTools() {
    const res = await fetch("https://hub.example.com/tools.json");
    const tools = await res.json();
    registerTools(tools);
}
"#;
    let findings = AiAgentExtScanner::scan_source(Path::new("agent.ts"), snippet);
    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-LLM-010")
        .expect("Must detect remote tools loaded without integrity check");
    assert_eq!(f.severity, Severity::Medium);
}

#[test]
fn test_llm_010_remote_tool_safe() {
    let snippet = r#"
async function setupTools() {
    const res = await fetch("https://hub.example.com/tools.json");
    const text = await res.text();
    verify_signature(text, expected_sha256);
    registerTools(JSON.parse(text));
}
"#;
    let findings = AiAgentExtScanner::scan_source(Path::new("agent.ts"), snippet);
    assert!(findings.iter().all(|f| f.cve.as_str() != "BK-AI-LLM-010"));
}

#[test]
fn test_llm_011_rag_acl_vulnerable() {
    let snippet = r#"
def retrieve_context(query):
    docs = vector_store.similarity_search(query, k=5)
    return docs
"#;
    let findings = AiAgentExtScanner::scan_source(Path::new("rag.py"), snippet);
    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-LLM-011")
        .expect("Must detect similarity search lacking tenant metadata filter");
    assert_eq!(f.severity, Severity::High);
}

#[test]
fn test_llm_011_rag_acl_safe() {
    let snippet = r#"
def retrieve_context(query, tenant_id):
    docs = vector_store.similarity_search(query, k=5, filter={"tenant_id": tenant_id})
    return docs
"#;
    let findings = AiAgentExtScanner::scan_source(Path::new("rag.py"), snippet);
    assert!(findings.iter().all(|f| f.cve.as_str() != "BK-AI-LLM-011"));
}

#[test]
fn test_llm_012_shared_cache_vulnerable() {
    let snippet = r#"
namespace = "global"
embedding_cache[query] = model.embed(query)
"#;
    let findings = AiAgentExtScanner::scan_source(Path::new("cache.py"), snippet);
    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-LLM-012")
        .expect("Must detect global namespace embedding cache");
    assert_eq!(f.severity, Severity::High);
}

#[test]
fn test_llm_012_shared_cache_safe() {
    let snippet = r#"
namespace = f"tenant_{tenant_id}"
embedding_cache[f"{tenant_id}:{query}"] = model.embed(query)
"#;
    let findings = AiAgentExtScanner::scan_source(Path::new("cache.py"), snippet);
    assert!(findings.iter().all(|f| f.cve.as_str() != "BK-AI-LLM-012"));
}

#[test]
fn test_llm_013_memory_poison_vulnerable() {
    let snippet = r#"
def record_dialogue(user_input):
    long_term_memory.add(user_input)
"#;
    let findings = AiAgentExtScanner::scan_source(Path::new("memory.py"), snippet);
    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-LLM-013")
        .expect("Must detect unvalidated user input saved to long-term memory");
    assert_eq!(f.severity, Severity::High);
}

#[test]
fn test_llm_013_memory_poison_safe() {
    let snippet = r#"
def record_dialogue(user_input):
    clean_entry = memory_guard(sanitize_memory(user_input))
    long_term_memory.add(clean_entry)
"#;
    let findings = AiAgentExtScanner::scan_source(Path::new("memory.py"), snippet);
    assert!(findings.iter().all(|f| f.cve.as_str() != "BK-AI-LLM-013"));
}

#[test]
fn test_llm_014_unbounded_loop_vulnerable() {
    let snippet = r#"
def run_autonomous_agent(task):
    while True:
        agent.step()
"#;
    let findings = AiAgentExtScanner::scan_source(Path::new("runner.py"), snippet);
    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-LLM-014")
        .expect("Must detect unbounded while True agent step loop");
    assert_eq!(f.severity, Severity::High);
}

#[test]
fn test_llm_014_unbounded_loop_safe() {
    let snippet = r#"
def run_autonomous_agent(task, max_steps=50):
    step_count = 0
    while True:
        if step_count >= max_steps or budget.check():
            break
        agent.step()
        step_count += 1
"#;
    let findings = AiAgentExtScanner::scan_source(Path::new("runner.py"), snippet);
    assert!(findings.iter().all(|f| f.cve.as_str() != "BK-AI-LLM-014"));
}

#[test]
fn test_llm_015_prompt_secret_vulnerable() {
    let snippet = r#"
system_prompt = f"The secret password is {API_KEY}. Only execute if provided."
"#;
    let findings = AiAgentExtScanner::scan_source(Path::new("prompt.py"), snippet);
    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-LLM-015")
        .expect("Must detect secret key embedded in prompt text");
    assert_eq!(f.severity, Severity::High);
}

#[test]
fn test_llm_015_prompt_secret_safe() {
    let snippet = r#"
// Secrets sent via headers, prompt contains instructions only
system_prompt = "You are a secure operations assistant. Follow standard authorization policies."
"#;
    let findings = AiAgentExtScanner::scan_source(Path::new("prompt.py"), snippet);
    assert!(findings.iter().all(|f| f.cve.as_str() != "BK-AI-LLM-015"));
}

#[test]
fn test_llm_016_auto_patch_vulnerable() {
    let snippet = r#"
def apply_fix(llm_output):
    subprocess.run(["git", "apply"], input=model_output)
"#;
    let findings = AiAgentExtScanner::scan_source(Path::new("healer.py"), snippet);
    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-LLM-016")
        .expect("Must detect git apply on model output without verification");
    assert_eq!(f.severity, Severity::High);
}

#[test]
fn test_llm_016_auto_patch_safe() {
    let snippet = r#"
def apply_fix(llm_output):
    verify_patch(llm_output)
    run_tests()
    subprocess.run(["git", "apply"], input=llm_output)
"#;
    let findings = AiAgentExtScanner::scan_source(Path::new("healer.py"), snippet);
    assert!(findings.iter().all(|f| f.cve.as_str() != "BK-AI-LLM-016"));
}

#[test]
fn test_llm_018_agent_msg_vulnerable() {
    let snippet = r#"
def handle_agent_message(msg):
    execute_action(msg.action)
"#;
    let findings = AiAgentExtScanner::scan_source(Path::new("router.py"), snippet);
    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-LLM-018")
        .expect("Must detect unauthenticated agent message handler");
    assert_eq!(f.severity, Severity::High);
}

#[test]
fn test_llm_018_agent_msg_safe() {
    let snippet = r#"
def handle_agent_message(msg):
    verify_signature(msg, msg.sender_signature)
    execute_action(msg.action)
"#;
    let findings = AiAgentExtScanner::scan_source(Path::new("router.py"), snippet);
    assert!(findings.iter().all(|f| f.cve.as_str() != "BK-AI-LLM-018"));
}

#[test]
fn test_llm_020_blind_prompt_vulnerable() {
    let snippet = r#"
def request_permission():
    if confirm("Do you want to proceed?"):
        run_task()
"#;
    let findings = AiAgentExtScanner::scan_source(Path::new("cli.py"), snippet);
    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-LLM-020")
        .expect("Must detect approval prompt omitting action target/diff");
    assert_eq!(f.severity, Severity::Medium);
}

#[test]
fn test_llm_020_blind_prompt_safe() {
    let snippet = r#"
def request_permission(cmd, target):
    if confirm(f"Execute command '{cmd}' on target {target}?"):
        run_task()
"#;
    let findings = AiAgentExtScanner::scan_source(Path::new("cli.py"), snippet);
    assert!(findings.iter().all(|f| f.cve.as_str() != "BK-AI-LLM-020"));
}

#[test]
fn test_llm_022_sensitive_send_vulnerable() {
    let snippet = r#"
async function sendToModel() {
    await openai.chat.completions.create({
        messages: [{ role: "user", content: read_file(".env") }]
    });
}
"#;
    let findings = AiAgentExtScanner::scan_source(Path::new("client.ts"), snippet);
    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-LLM-022")
        .expect("Must detect .env content dispatched to external model endpoint");
    assert_eq!(f.severity, Severity::High);
}

#[test]
fn test_llm_022_sensitive_send_safe() {
    let snippet = r#"
async function sendToModel(rawText) {
    const cleanText = redact_secrets(mask_pii(rawText));
    await openai.chat.completions.create({
        messages: [{ role: "user", content: cleanText }]
    });
}
"#;
    let findings = AiAgentExtScanner::scan_source(Path::new("client.ts"), snippet);
    assert!(findings.iter().all(|f| f.cve.as_str() != "BK-AI-LLM-022"));
}

// ============================================================================
// Category 21: AI Coding Assistant-Specific Engineering Traps
// ============================================================================

#[test]
fn test_aic_001_disabled_auth_vulnerable() {
    let snippet = r#"
const app = express();
// app.use(authMiddleware);
// app.use(csrf());
app.post("/api/transfer", transferFunds);
"#;
    let findings = AiAgentExtScanner::scan_source(Path::new("server.js"), snippet);
    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-AIC-001")
        .expect("Must detect commented out auth middleware");
    assert_eq!(f.severity, Severity::High);
    assert!(f.advisory_ids.contains(&"CWE-693".to_string()));
}

#[test]
fn test_aic_001_disabled_auth_safe() {
    let snippet = r#"
const app = express();
app.use(authMiddleware);
app.use(csrf());
app.post("/api/transfer", transferFunds);
"#;
    let findings = AiAgentExtScanner::scan_source(Path::new("server.js"), snippet);
    assert!(findings.iter().all(|f| f.cve.as_str() != "BK-AI-AIC-001"));
}

#[test]
fn test_aic_002_dummy_bypass_vulnerable() {
    let snippet = r#"
function verifyUserRole(user) {
    return true; // fixed dummy bypass
}
"#;
    let findings = AiAgentExtScanner::scan_source(Path::new("auth.js"), snippet);
    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-AIC-002")
        .expect("Must detect hardcoded dummy bypass");
    assert_eq!(f.severity, Severity::High);
    assert!(f.advisory_ids.contains(&"CWE-693".to_string()));
}

#[test]
fn test_aic_002_dummy_bypass_safe() {
    let snippet = r#"
function verifyUserRole(user) {
    return user && user.roles && user.roles.includes("admin");
}
"#;
    let findings = AiAgentExtScanner::scan_source(Path::new("auth.js"), snippet);
    assert!(findings.iter().all(|f| f.cve.as_str() != "BK-AI-AIC-002"));
}

#[test]
fn test_aic_003_happy_path_vulnerable() {
    let snippet = r#"
describe("User API", () => {
    it("returns profile", async () => {
        const res = await request(app).get("/profile");
        expect(res.status).toBe(200);
        expect(res.ok).toBe(true);
    });
});
"#;
    let findings = AiAgentExtScanner::scan_source(Path::new("user.test.ts"), snippet);
    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-AIC-003")
        .expect("Must detect test file with only happy path assertions");
    assert_eq!(f.severity, Severity::Medium);
}

#[test]
fn test_aic_003_happy_path_safe() {
    let snippet = r#"
describe("User API", () => {
    it("returns profile on success", async () => {
        const res = await request(app).get("/profile");
        expect(res.status).toBe(200);
    });
    it("rejects unauthorized request with 401", async () => {
        const res = await request(app).get("/profile");
        expect(res.status).toBe(401);
    });
});
"#;
    let findings = AiAgentExtScanner::scan_source(Path::new("user.test.ts"), snippet);
    assert!(findings.iter().all(|f| f.cve.as_str() != "BK-AI-AIC-003"));
}

#[test]
fn test_aic_005_hallucinated_option_vulnerable() {
    let snippet = r#"
const sessionConfig = {
    secure: "maximum",
    anti_hack: true
};
"#;
    let findings = AiAgentExtScanner::scan_source(Path::new("config.js"), snippet);
    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-AIC-005")
        .expect("Must detect hallucinated security options");
    assert_eq!(f.severity, Severity::Medium);
}

#[test]
fn test_aic_005_hallucinated_option_safe() {
    let snippet = r#"
const sessionConfig = {
    secure: true,
    httpOnly: true,
    sameSite: "strict"
};
"#;
    let findings = AiAgentExtScanner::scan_source(Path::new("config.js"), snippet);
    assert!(findings.iter().all(|f| f.cve.as_str() != "BK-AI-AIC-005"));
}

#[test]
fn test_aic_006_deprecated_api_vulnerable() {
    let snippet = r#"
const crypto = require("crypto");
const cipher = crypto.createCipher("aes192", password);
"#;
    let findings = AiAgentExtScanner::scan_source(Path::new("crypto.js"), snippet);
    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-AIC-006")
        .expect("Must detect deprecated crypto.createCipher");
    assert_eq!(f.severity, Severity::High);
    assert!(f.advisory_ids.contains(&"CWE-1104".to_string()));
}

#[test]
fn test_aic_006_deprecated_api_safe() {
    let snippet = r#"
const crypto = require("crypto");
const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
"#;
    let findings = AiAgentExtScanner::scan_source(Path::new("crypto.js"), snippet);
    assert!(findings.iter().all(|f| f.cve.as_str() != "BK-AI-AIC-006"));
}

#[test]
fn test_aic_007_break_defaults_vulnerable() {
    let snippet = r#"
const dbConfig = {
    host: "db.internal",
    ssl: false,
    saltRounds: 4
};
"#;
    let findings = AiAgentExtScanner::scan_source(Path::new("db.js"), snippet);
    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-AIC-007")
        .expect("Must detect config weakening security defaults");
    assert_eq!(f.severity, Severity::High);
    assert!(f.advisory_ids.contains(&"CWE-16".to_string()));
}

#[test]
fn test_aic_007_break_defaults_safe() {
    let snippet = r#"
const dbConfig = {
    host: "db.internal",
    ssl: true,
    saltRounds: 12
};
"#;
    let findings = AiAgentExtScanner::scan_source(Path::new("db.js"), snippet);
    assert!(findings.iter().all(|f| f.cve.as_str() != "BK-AI-AIC-007"));
}

#[test]
fn test_aic_008_scope_violation_vulnerable() {
    let snippet = r#"
#!/bin/bash
echo "deploy ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
"#;
    let findings = AiAgentExtScanner::scan_source(Path::new("setup.sh"), snippet);
    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-AIC-008")
        .expect("Must detect sudoers NOPASSWD alteration");
    assert_eq!(f.severity, Severity::High);
    assert!(f.advisory_ids.contains(&"CWE-284".to_string()));
}

#[test]
fn test_aic_008_scope_violation_safe() {
    let snippet = r#"
#!/bin/bash
# Controlled user setup without broad privilege escalation
useradd -m -s /bin/bash appuser
"#;
    let findings = AiAgentExtScanner::scan_source(Path::new("setup.sh"), snippet);
    assert!(findings.iter().all(|f| f.cve.as_str() != "BK-AI-AIC-008"));
}

#[test]
fn test_aic_009_todo_auth_vulnerable() {
    let snippet = r#"
// TODO: add authentication later
const API_KEY = "your-api-key-here";
function handleRequest(req, res) {
    serveData(res);
}
"#;
    let findings = AiAgentExtScanner::scan_source(Path::new("handler.js"), snippet);
    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-AIC-009")
        .expect("Must detect deferred authentication TODO");
    assert_eq!(f.severity, Severity::High);
    assert!(f.advisory_ids.contains(&"CWE-798".to_string()));
}

#[test]
fn test_aic_009_todo_auth_safe() {
    let snippet = r#"
const apiKey = process.env.SERVICE_API_KEY;
function handleRequest(req, res) {
    if (req.headers["x-api-key"] !== apiKey) {
        return res.status(401).send();
    }
    serveData(res);
}
"#;
    let findings = AiAgentExtScanner::scan_source(Path::new("handler.js"), snippet);
    assert!(findings.iter().all(|f| f.cve.as_str() != "BK-AI-AIC-009"));
}

#[test]
fn test_aic_010_comment_claims_safe_vulnerable() {
    let snippet = r#"
// safe: sanitized
db.query(f"SELECT * FROM users WHERE id = {user_id}")
"#;
    let findings = AiAgentExtScanner::scan_source(Path::new("query.py"), snippet);
    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-AIC-010")
        .expect("Must detect safe comment masking raw SQL interpolation");
    assert_eq!(f.severity, Severity::Medium);
}

#[test]
fn test_aic_010_comment_claims_safe_safe() {
    let snippet = r#"
// safe: sanitized
const cleanId = sanitize(user_id);
db.query("SELECT * FROM users WHERE id = $1", [cleanId]);
"#;
    let findings = AiAgentExtScanner::scan_source(Path::new("query.js"), snippet);
    assert!(findings.iter().all(|f| f.cve.as_str() != "BK-AI-AIC-010"));
}

#[test]
fn test_aic_011_bypass_scanner_vulnerable() {
    let snippet = r#"
- name: Security Scan
  run: |
    semgrep --config auto . || true
    cargo audit || true
"#;
    let findings = AiAgentExtScanner::scan_source(Path::new("ci.yml"), snippet);
    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-AIC-011")
        .expect("Must detect scanner failure suppressed with || true");
    assert_eq!(f.severity, Severity::High);
}

#[test]
fn test_aic_011_bypass_scanner_safe() {
    let snippet = r#"
- name: Security Scan
  run: |
    semgrep --config auto --error .
    cargo audit
"#;
    let findings = AiAgentExtScanner::scan_source(Path::new("ci.yml"), snippet);
    assert!(findings.iter().all(|f| f.cve.as_str() != "BK-AI-AIC-011"));
}

#[test]
fn test_aic_012_broad_perms_vulnerable() {
    let snippet = r#"
app.use(cors({
    origin: "*",
    credentials: true
}));
"#;
    let findings = AiAgentExtScanner::scan_source(Path::new("server.js"), snippet);
    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-AIC-012")
        .expect("Must detect wildcard origin with credentials");
    assert_eq!(f.severity, Severity::High);
    assert!(f.advisory_ids.contains(&"CWE-732".to_string()));
}

#[test]
fn test_aic_012_broad_perms_safe() {
    let snippet = r#"
app.use(cors({
    origin: "https://app.example.com",
    credentials: true
}));
"#;
    let findings = AiAgentExtScanner::scan_source(Path::new("server.js"), snippet);
    assert!(findings.iter().all(|f| f.cve.as_str() != "BK-AI-AIC-012"));
}

#[test]
fn test_aic_013_swallow_auth_vulnerable() {
    let snippet = r#"
try {
    verifyToken(token);
} catch (e) {
    // ignore
}
grantPrivilegedAccess();
"#;
    let findings = AiAgentExtScanner::scan_source(Path::new("auth.js"), snippet);
    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-AIC-013")
        .expect("Must detect exception swallowing around token verification");
    assert_eq!(f.severity, Severity::High);
    assert!(f.advisory_ids.contains(&"CWE-754".to_string()));
}

#[test]
fn test_aic_013_swallow_auth_safe() {
    let snippet = r#"
try {
    verifyToken(token);
} catch (e) {
    return res.status(401).send("Unauthorized");
}
grantPrivilegedAccess();
"#;
    let findings = AiAgentExtScanner::scan_source(Path::new("auth.js"), snippet);
    assert!(findings.iter().all(|f| f.cve.as_str() != "BK-AI-AIC-013"));
}

#[test]
fn test_aic_014_contract_break_vulnerable() {
    let snippet = r#"
function setUserContext(req) {
    (req as any).user = { id: 1, role: "admin" };
}
"#;
    let findings = AiAgentExtScanner::scan_source(Path::new("context.ts"), snippet);
    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-AIC-014")
        .expect("Must detect type casting bypass on user context");
    assert_eq!(f.severity, Severity::Medium);
    assert!(f.advisory_ids.contains(&"CWE-841".to_string()));
}

#[test]
fn test_aic_014_contract_break_safe() {
    let snippet = r#"
function setUserContext(req: AuthenticatedRequest, user: ValidatedUser) {
    req.user = user;
}
"#;
    let findings = AiAgentExtScanner::scan_source(Path::new("context.ts"), snippet);
    assert!(findings.iter().all(|f| f.cve.as_str() != "BK-AI-AIC-014"));
}

#[test]
fn test_aic_015_fabricated_cve_vulnerable() {
    let snippet = r#"
// Patched per advisory CVE-9999-99999
fixBufferIssue();
"#;
    let findings = AiAgentExtScanner::scan_source(Path::new("patch.js"), snippet);
    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-AIC-015")
        .expect("Must detect fabricated CVE citation");
    assert_eq!(f.severity, Severity::Medium);
}

#[test]
fn test_aic_015_fabricated_cve_safe() {
    let snippet = r#"
// Patched per upstream advisory CVE-2024-3094
fixBufferIssue();
"#;
    let findings = AiAgentExtScanner::scan_source(Path::new("patch.js"), snippet);
    assert!(findings.iter().all(|f| f.cve.as_str() != "BK-AI-AIC-015"));
}

#[test]
fn test_aic_016_untested_fix_vulnerable() {
    let snippet = r#"
const fixResult = {
    issueId: "AUTH-01",
    status: "FIXED" // without running tests
};
"#;
    let findings = AiAgentExtScanner::scan_source(Path::new("report.json"), snippet);
    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-AIC-016")
        .expect("Must detect fix marked complete without running tests");
    assert_eq!(f.severity, Severity::Medium);
}

#[test]
fn test_aic_016_untested_fix_safe() {
    let snippet = r#"
const fixResult = {
    issueId: "AUTH-01",
    status: "FIXED",
    tests_run: true,
    verification: "test_suite_passed"
};
"#;
    let findings = AiAgentExtScanner::scan_source(Path::new("report.json"), snippet);
    assert!(findings.iter().all(|f| f.cve.as_str() != "BK-AI-AIC-016"));
}
