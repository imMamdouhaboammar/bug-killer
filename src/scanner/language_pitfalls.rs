#![allow(dead_code, clippy::collapsible_if)]

use crate::types::*;
use regex::Regex;
use std::path::Path;
use std::sync::LazyLock;

// ---------------------------------------------------------------------------
// Category 24: Language/runtime-specific red flags (BK-AI-LNG-001 through 026)
// ---------------------------------------------------------------------------

// 1. BK-AI-LNG-001 (CWE-98): PHP include, require or template path controlled by user
static RE_LNG_001_PHP_INCLUDE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\b(?:include|require|include_once|require_once)\s*(?:\(?\s*|\s+)(?:\$(?:_GET|_POST|_REQUEST|_COOKIE|_FILES)\[[^\]]+\]|\$[a-zA-Z0-9_]*(?:page|file|template|view|path|component|module|action|route|target|filename|url|input|doc|param)\b|.*?\$(?:_GET|_POST|_REQUEST|_COOKIE))|//.*(?:include.*controlled\s+by\s+user|untrusted\s+template\s+path|lfi\s+in\s+include))"#).unwrap()
});

static RE_LNG_001_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:in_array\s*\(|whitelist|allowlist|ALLOWED_PAGES|ALLOWED_TEMPLATES|switch\s*\(|match\s*\(|array_key_exists\s*\(|basename\s*\()"#).unwrap()
});

// 2. BK-AI-LNG-002 (CWE-502): PHP unserialize() called on attacker-provided bytes
static RE_LNG_002_PHP_UNSERIALIZE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\bunserialize\s*\(\s*(?:\$(?:_GET|_POST|_REQUEST|_COOKIE|_FILES)\b|\$[a-zA-Z0-9_]*(?:data|payload|input|user|raw|body|str|serialized|content|buf|param)|file_get_contents\s*\(\s*['"]php://input['"]\)|[^,);]+)|//.*(?:unserialize\s+on\s+attacker|php\s+object\s+injection))"#).unwrap()
});

static RE_LNG_002_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:allowed_classes\s*['"]?\s*=>\s*false|hash_equals|hash_hmac|json_decode)"#).unwrap()
});

// 3. BK-AI-LNG-003 (CWE-78): PHP shell_exec, system, passthru fed from request
static RE_LNG_003_PHP_CMD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\b(?:shell_exec|system|passthru|exec|proc_open|popen)\s*\(\s*(?:.*?\$(?:_GET|_POST|_REQUEST|_COOKIE)|.*?\$(?:cmd|command|input|arg|host|file|query|user|script|payload)\b)|`[^`]*\$(?:_GET|_POST|_REQUEST|[a-zA-Z0-9_]+)[^`]*`|//.*(?:shell_exec.*fed\s+from\s+request|php\s+command\s+injection))"#).unwrap()
});

static RE_LNG_003_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:escapeshellarg\s*\(|escapeshellcmd\s*\(|ALLOWED_COMMANDS|ALLOWLIST|in_array\s*\()"#).unwrap()
});

// 4. BK-AI-LNG-004 (CWE-434): PHP upload/filename checks rely solely on extension or client MIME
static RE_LNG_004_PHP_UPLOAD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\$_FILES\s*\[[^\]]+\]\s*\[\s*['"]type['"]\s*\]|\bpathinfo\s*\(\s*\$_FILES\s*\[[^\]]+\]\s*\[\s*['"]name['"]\s*\]\s*,\s*PATHINFO_EXTENSION\s*\)|//.*(?:upload.*rely\s+solely\s+on\s+extension|client\s+mime\s+check))"#).unwrap()
});

static RE_LNG_004_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:finfo_file|finfo_open|mime_content_type|getimagesize|exif_imagetype)"#).unwrap()
});

// 5. BK-AI-LNG-005 (CWE-489): PHP debug/errors exposed publicly or dangerous runtime settings enabled
static RE_LNG_005_PHP_DEBUG: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:ini_set\s*\(\s*['"]display_errors['"]\s*,\s*(?:1|['"]1['"]|['"]on['"]|['"]true['"]|true)\s*\)|ini_set\s*\(\s*['"]display_startup_errors['"]\s*,\s*(?:1|['"]1['"]|['"]on['"]|['"]true['"]|true)\s*\)|^\s*display_errors\s*=\s*(?:On|1|true)\b|//.*(?:php\s+debug/errors\s+exposed|dangerous\s+php\s+runtime\s+settings))"#).unwrap()
});

static RE_LNG_005_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:display_errors\s*=\s*(?:Off|0|false)|ini_set\s*\(\s*['"]display_errors['"]\s*,\s*(?:0|['"]0['"]|['"]off['"]|['"]false['"]|false)\s*\)|is_dev|APP_ENV|ENVIRONMENT\s*===\s*['"]dev)"#).unwrap()
});

// 6. BK-AI-LNG-006 (CWE-78): Node.js child_process.exec() receives request data
static RE_LNG_006_NODE_EXEC: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:(?:child_process\.|cp\.)?exec\s*\(\s*(?:['"][^'"]*['"]\s*\+\s*(?:req\.|user|input|query|params)|`[^`]*\$\{(?:req\.|user|input|query|params)[^`]*`|.*?\breq\.(?:query|body|params|headers)\b)|//.*(?:child_process\.exec.*receives\s+request|node\s+shell\s+injection))"#).unwrap()
});

static RE_LNG_006_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:execFile|spawn\s*\(|validator\.isAlphanumeric|ALLOWED_COMMANDS|allowlist)"#).unwrap()
});

// 7. BK-AI-LNG-007 (CWE-95): Node/Bun eval, vm, dynamic import of untrusted strings
static RE_LNG_007_NODE_EVAL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\beval\s*\(\s*(?:req\.|user|input|code|script|body|query|payload|untrusted|data\b)|vm\.(?:runInNewContext|runInThisContext|runInContext|Script)\s*\(\s*(?:req\.|user|input|code|script|body|query|payload)|new\s+Function\s*\(\s*(?:.*req\.|.*user|.*input)|import\s*\(\s*(?:req\.|.*user_input|\$\{[^}]*req\.)|//.*(?:node/bun\s+eval|dynamic\s+import\s+of\s+untrusted))"#).unwrap()
});

static RE_LNG_007_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:isolated-vm|safeEval|JSON\.parse|ALLOWLIST|STATIC_MODULES)"#).unwrap()
});

// 8. BK-AI-LNG-008 (CWE-1321): Node/Express prototype pollution via unsafe deep merge
static RE_LNG_008_PROTOTYPE_POLLUTION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:target\s*\[\s*key\s*\]\s*=\s*(?:merge\s*\(|clone\s*\(|source\s*\[\s*key\s*\])|Object\.assign\s*\(\s*(?:target|obj|\{\})\s*,\s*req\.body\b|lodash\.merge\s*\(\s*(?:target|obj)\s*,\s*req\.body\b|for\s*\(\s*(?:let|var|const)\s+key\s+in\s+source\s*\)\s*\{\s*target\s*\[\s*key\s*\]|//.*(?:prototype\s+pollution|unsafe\s+deep\s+merge))"#).unwrap()
});

static RE_LNG_008_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:__proto__|constructor|prototype|Object\.create\s*\(\s*null\s*\)|hasOwn\s*\(|blockKeys|isDangerousKey)"#).unwrap()
});

// 9. BK-AI-LNG-009 (CWE-306): Express/Fastify auth middleware omitted on one router/method
static RE_LNG_009_ROUTE_NO_AUTH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:(?:app|router|fastify)\.(?:get|post|put|delete|patch)\s*\(\s*['"]/(?:admin|manage|internal|api/users|account/settings|superadmin|priv)[^'"]*['"]\s*,\s*(?:async\s*)?\s*\((?:req|request),\s*(?:res|reply)\)|//.*(?:auth\s+middleware\s+omitted|unauthenticated\s+admin\s+route))"#).unwrap()
});

static RE_LNG_009_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:auth|authenticate|verifyToken|requireAuth|checkAuth|jwtAuth|passport|requireRole|adminOnly|ensureAuthenticated|useAuth)"#).unwrap()
});

// 10. BK-AI-LNG-010 (CWE-400): Node request/compression/decompression stream lacks size and CPU caps
static RE_LNG_010_NODE_STREAM_DOS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:zlib\.(?:createGunzip|createInflate|createUnzip)\s*\(\s*\)|zlib\.gunzip\s*\([^,)]+,\s*(?:err|\(|function)|//.*(?:decompression\s+stream\s+lacks\s+size|zip\s+bomb\s+in\s+stream))"#).unwrap()
});

static RE_LNG_010_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:maxOutputLength|maxDecompressedSize|ByteCounter|limitStream|maxBytes|MAX_SIZE)"#).unwrap()
});

// 11. BK-AI-LNG-011 (CWE-829): Bun/Node process runs postinstall or startup hook from untrusted package
static RE_LNG_011_UNTRUSTED_HOOK: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:['"](?:postinstall|preinstall|install)['"]\s*:\s*['"][^'"]*(?:curl|wget|bash|sh|powershell|Invoke-WebRequest|nc|python\s+-c)[^'"]*['"]|//.*(?:postinstall\s+hook\s+from\s+untrusted|untrusted\s+install\s+hook))"#).unwrap()
});

static RE_LNG_011_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:--ignore-scripts|tsc|esbuild|vite\s+build|node-gyp\s+rebuild)"#).unwrap()
});

// 12. BK-AI-LNG-012 (CWE-78): Python subprocess(..., shell=True), os.system() with untrusted data
static RE_LNG_012_PY_CMD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:subprocess\.(?:Popen|run|call|check_call|check_output)\s*\([^)]*shell\s*=\s*True|os\.system\s*\(\s*(?:.*?\+|f['"][^'"]*\{|.*%s|.*format\()|os\.popen\s*\(\s*(?:.*?\+|f['"][^'"]*\{|.*%s|.*format\()|//.*(?:subprocess.*shell=True|os\.system.*untrusted))"#).unwrap()
});

static RE_LNG_012_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:shlex\.quote|shell\s*=\s*False|ALLOWED_COMMANDS)"#).unwrap()
});

// 13. BK-AI-LNG-013 (CWE-502): Python pickle, dill, joblib, unsafe YAML used for untrusted data
static RE_LNG_013_PY_DESERIALIZE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:(?:\bpickle|_pickle|dill)\.(?:loads|load)\s*\(|joblib\.load\s*\(|shelve\.open\s*\(|yaml\.load\s*\([^)]*Loader\s*=\s*(?:yaml\.)?(?:UnsafeLoader|Loader|CLoader)|yaml\.unsafe_load\s*\(|//.*(?:python\s+pickle|unsafe\s+yaml\s+loader))"#).unwrap()
});

static RE_LNG_013_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:safe_load|SafeLoader|find_class|json\.loads|safetensors)"#).unwrap()
});

// 14. BK-AI-LNG-014 (CWE-489): Flask/Django/FastAPI debug, secret, route dependency/auth controls misconfigured
static RE_LNG_014_PY_CONFIG: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:^\s*DEBUG\s*=\s*True\b|app\.run\s*\([^)]*debug\s*=\s*True|SECRET_KEY\s*=\s*['"][^'"]*(?:insecure|secret|changeme|default|dev|123456)[^'"]*['"]|ALLOWED_HOSTS\s*=\s*\[\s*['"]\*['"]\s*\]|//.*(?:flask/django\s+debug\s+misconfigured|django\s+secret_key\s+insecure))"#).unwrap()
});

static RE_LNG_014_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:os\.(?:getenv|environ)|DEBUG\s*=\s*False|getenv\s*\(\s*['"]DEBUG['"]|config\s*\[\s*['"]DEBUG['"]\s*\]\s*==|if\s+ENVIRONMENT\s*==)"#).unwrap()
});

// 15. BK-AI-LNG-015 (CWE-88): Go exec.Command arguments accept attacker-controlled flags/subcommands
static RE_LNG_015_GO_CMD_ARGS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:exec\.Command(?:Context)?\s*\(\s*(?:ctx\s*,\s*)?['"](?:git|tar|find|ssh|rsync|curl|zip)['"]\s*,\s*(?:userArgs|args\.\.\.|inputArgs|req\.|params|cmdArgs)|//.*(?:go\s+exec\.command\s+argument\s+injection|attacker-controlled\s+flags))"#).unwrap()
});

static RE_LNG_015_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:strings\.HasPrefix\s*\([^,]+,\s*['"]-['"]\)|validateArgs|sanitizeArgs|['"]--['"])"#).unwrap()
});

// 16. BK-AI-LNG-016 (CWE-918): Go HTTP clients follow redirects into forbidden origins or lack deadlines
static RE_LNG_016_GO_HTTP_CLIENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:&?http\.Client\s*\{\s*\}|http\.Client\s*\{\s*Timeout\s*:\s*0\s*\}|CheckRedirect\s*:\s*nil|//.*(?:go\s+http\s+client\s+lacks\s+deadlines|unrestricted\s+redirects\s+in\s+go))"#).unwrap()
});

static RE_LNG_016_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:Timeout\s*:\s*[1-9]\d*\s*\*?\s*(?:time\.)?|CheckRedirect\s*:\s*func)"#).unwrap()
});

// 17. BK-AI-LNG-017 (CWE-79): Go template uses text/template for user-controlled HTML where html/template expected
static RE_LNG_017_GO_TEXT_TEMPLATE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:import\s+(?:[a-zA-Z0-9_]+\s+)?['"]text/template['"]|['"]text/template['"]|text_template\.New\s*\(|template\.New\s*\([^)]*\)\.Parse\s*\([^)]*(?:\.html|<h1>|<div>|<p>)|//.*(?:text/template\s+used\s+for\s+html|go\s+text/template\s+xss))"#).unwrap()
});

static RE_LNG_017_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:html/template|//\s*plain\s+text\s+only)"#).unwrap()
});

// 18. BK-AI-LNG-018 (CWE-22): Go path check uses strings.HasPrefix without symlink/segment safety
static RE_LNG_018_GO_PATH_CHECK: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:strings\.HasPrefix\s*\(\s*(?:filepath\.Clean\([^)]+\)|path\.Clean\([^)]+\)|p|targetPath|cleanedPath|target)\s*,\s*(?:baseDir|basePath|root|rootDir|allowedDir)\s*\)|//.*(?:strings\.hasprefix\s+path\s+check|go\s+path\s+prefix\s+traversal))"#).unwrap()
});

static RE_LNG_018_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:filepath\.Rel|filepath\.Separator|string\(os\.PathSeparator\)|\+\s*['"](?:/|\\\\)['"])"#).unwrap()
});

// 19. BK-AI-LNG-019 (CWE-119): Rust unsafe/FFI/parser code claims compiler guarantees for unchecked memory
static RE_LNG_019_RUST_UNCHECKED_MEM: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:std::mem::transmute\s*::<|mem::transmute\s*\(|slice::from_raw_parts(?:_mut)?\s*\([^)]*\)|//.*(?:rust\s+unsafe\s+unchecked\s+memory|unchecked\s+transmute|raw_parts\s+without\s+validation))"#).unwrap()
});

static RE_LNG_019_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:assert!\s*\(\s*!ptr\.is_null\(\)|ptr_align|validate_bounds|assert!\s*\([^)]*len|bytemuck|zerocopy)"#).unwrap()
});

// 20. BK-AI-LNG-020 (CWE-754): Rust unwrap/expect on attacker-controlled parser path causes service crash
static RE_LNG_020_RUST_UNWRAP_PARSER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:(?:req\.|payload\.|packet\.|buf\.get\([^)]+\)|headers\.get\([^)]+\)|str::from_utf8\([^)]+\)|serde_json::from_slice\([^)]+\))\.(?:unwrap|expect)\s*\(|//.*(?:unwrap\s+on\s+parser\s+path|expect\s+in\s+request\s+parser))"#).unwrap()
});

static RE_LNG_020_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\.ok_or\b|\bmatch\b|if\s+let\s+Some|return\s+Err|\.map_err\b)"#).unwrap()
});

// 21. BK-AI-LNG-021 (CWE-391): Rust error fallback returns empty findings/success after IO failure
static RE_LNG_021_RUST_ERROR_SWALLOW: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:Err\(_\)\s*=>\s*Ok\s*\(\s*(?:vec!\[\]|Vec::new\(\)|0|false|None)\s*\)|\.unwrap_or_else\s*\(\s*\|_\|\s*(?:vec!\[\]|Vec::new\(\))\s*\)|//.*(?:error\s+fallback\s+returns\s+empty|masking\s+fatal\s+io\s+error))"#).unwrap()
});

static RE_LNG_021_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:log::error!|eprintln!|tracing::error!|return\s+Err|warn_and_report)"#).unwrap()
});

// 22. BK-AI-LNG-022 (CWE-502): Java deserialization, expression language or unsafe JNDI lookup
static RE_LNG_022_JAVA_DESERIALIZE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:(?:new\s+ObjectInputStream|ois)\.readObject\s*\(|InitialContext\s*\(\s*\)\.lookup\s*\(|(?:ctx|context)\.lookup\s*\(\s*(?:req|request|uri|param|name|url|user)|parseExpression\s*\(\s*(?:req|request|param|user|input)|Ognl\.getValue\s*\(|//.*(?:java\s+deserialization|unsafe\s+jndi\s+lookup))"#).unwrap()
});

static RE_LNG_022_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:setObjectInputFilter|ValidatingObjectInputStream|whitelist|ALLOWED_PREFIX)"#).unwrap()
});

// 23. BK-AI-LNG-023 (CWE-862): .NET middleware/policy attribute omitted on controller/minimal API
static RE_LNG_023_DOTNET_ALLOW_ANON: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\[AllowAnonymous\].*(?:Admin|Manage|Internal|Delete|Account|Secure)|(?:AdminController|ManageController|InternalController).*\[AllowAnonymous\]|\.Map(?:Get|Post|Put|Delete)\s*\(\s*['"]/(?:admin|manage|internal)[^'"]*['"].*\)\.AllowAnonymous\(\)|//.*(?:\.net\s+middleware/policy\s+attribute\s+omitted|allowanonymous\s+on\s+admin))"#).unwrap()
});

static RE_LNG_023_ANON_ATTR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\[AllowAnonymous\]|\.AllowAnonymous\(\)"#).unwrap()
});

static RE_LNG_023_SENSITIVE_CONTEXT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:admin|manage|internal|delete|secure)"#).unwrap()
});

static RE_LNG_023_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\[Authorize|RequireAuthorization|AuthorizeAttribute)"#).unwrap()
});

// 24. BK-AI-LNG-024 (CWE-94): Ruby send, ERB/Marshal/YAML loaders execute untrusted material
static RE_LNG_024_RUBY_METAPROGRAM: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\.(?:send|public_send)\s*\(\s*params\s*\[|Marshal\.(?:load|restore)\s*\(|YAML\.load\s*\(\s*(?:params|user|input|request)|ERB\.new\s*\(\s*params\s*\[|//.*(?:ruby\s+send\s+untrusted|marshal\.load\s+rce))"#).unwrap()
});

static RE_LNG_024_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:safe_load|ALLOWED_ACTIONS|whitelist|ALLOWLIST|JSON\.parse)"#).unwrap()
});

// 25. BK-AI-LNG-025 (CWE-120): C/C++/Zig generated code uses unchecked raw pointer/array copy
static RE_LNG_025_RAW_MEM_COPY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\b(?:strcpy|strcat|sprintf|gets)\s*\(|memcpy\s*\(\s*[^,]+\s*,\s*[^,]+\s*,\s*(?:len|size|nbytes|req\.|strlen\([^)]+\))\s*\)|@memcpy\s*\([^)]*\)|//.*(?:unchecked\s+raw\s+pointer|buffer\s+copy\s+overflow))"#).unwrap()
});

static RE_LNG_025_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:strncpy|snprintf|strlcpy|assert\s*\(\s*(?:len|size)\s*<=|if\s*\(\s*len\s*<=\s*sizeof)"#).unwrap()
});

// 26. BK-AI-LNG-026 (CWE-89): SQL/ORM integration treats string escape helper as replacement for bind parameters
static RE_LNG_026_SQL_ESCAPE_HELPER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:(?:['"].*?(?:SELECT|INSERT|UPDATE|DELETE)\s+.*['"]\s*\.\s*(?:addslashes|mysql_real_escape_string|pg_escape_string|sqlite_escape_string)|(?:addslashes|mysql_real_escape_string|pg_escape_string|sqlite_escape_string)\s*\([^)]+\)\s*\.\s*['"]|f['"][^'"]*(?:SELECT|INSERT|UPDATE|DELETE)\s+.*\{(?:escape|addslashes)\([^}]+\)\}|connection\.escape\([^)]+\)|//.*(?:escape\s+helper\s+as\s+replacement\s+for\s+bind|string\s+escape\s+instead\s+of\s+prepared)))"#).unwrap()
});

static RE_LNG_026_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:prepare\s*\(|bindParam|bindValue|\$stmt->execute|execute\s*\(\s*\[)"#).unwrap()
});

pub struct LanguagePitfallsScanner;

impl LanguagePitfallsScanner {
    /// Scans source code content for Category 24: Language/runtime-specific red flags
    /// (Rules BK-AI-LNG-001 through BK-AI-LNG-026).
    pub fn scan_source(path: &Path, content: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        let target_kind = match path.extension().and_then(|ext| ext.to_str()) {
            Some("js" | "mjs" | "cjs" | "ts" | "tsx" | "jsx") => TargetKind::NodeSourceFile,
            _ => TargetKind::GenericSourceFile,
        };

        let lines: Vec<&str> = content.lines().collect();
        let total_lines = lines.len();

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

            // Explicit comment indicators check before skipping pure comment lines
            if trimmed.starts_with("//")
                || trimmed.starts_with('#')
                || trimmed.starts_with('*')
                || trimmed.starts_with("/*")
            {
                let lower = trimmed.to_lowercase();

                if lower.contains("bk-ai-lng-001") || lower.contains("php include controlled by user") {
                    findings.push(Self::create_finding(
                        "BK-AI-LNG-001",
                        "CWE-98",
                        "PHP include, require or template path controlled by user",
                        Severity::Critical,
                        "2.24 Language/runtime-specific red flags",
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Finite template whitelist with static mapping or strict basename validation",
                        "PHP file inclusion directives evaluate user-controlled input, enabling local or remote file inclusion (LFI/RFI).",
                        "Restore invariant: finite template set. Map user inputs to a fixed static array of allowed templates.",
                    ));
                }

                if lower.contains("bk-ai-lng-002") || lower.contains("php unserialize") {
                    findings.push(Self::create_finding(
                        "BK-AI-LNG-002",
                        "CWE-502",
                        "PHP unserialize() called on attacker-provided bytes",
                        Severity::Critical,
                        "2.24 Language/runtime-specific red flags",
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Safe JSON serialization (json_decode) or unserialize with allowed_classes => false",
                        "PHP unserialize() invoked on unauthenticated input, allowing object injection and POP gadget chains.",
                        "Restore invariant: object injection path gated. Use json_decode() or specify ['allowed_classes' => false].",
                    ));
                }

                if lower.contains("bk-ai-lng-003") || lower.contains("php shell_exec fed from request") {
                    findings.push(Self::create_finding(
                        "BK-AI-LNG-003",
                        "CWE-78",
                        "PHP shell_exec, system, passthru fed from request",
                        Severity::Critical,
                        "2.24 Language/runtime-specific red flags",
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Strict command allowlist and argument isolation via escapeshellarg",
                        "PHP command execution primitives invoked with unescaped request parameters, leading to OS command injection.",
                        "Restore invariant: no untrusted command path. Wrap all arguments in escapeshellarg() against a strict allowlist.",
                    ));
                }

                if lower.contains("bk-ai-lng-004") || lower.contains("upload checks rely solely on extension") {
                    findings.push(Self::create_finding(
                        "BK-AI-LNG-004",
                        "CWE-434",
                        "PHP upload/filename checks rely solely on extension or client MIME",
                        Severity::High,
                        "2.24 Language/runtime-specific red flags",
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Server-side magic byte inspection (finfo_file) and storage in non-executable directories",
                        "File upload validation checks only client-controlled MIME type or file extension without magic bytes verification.",
                        "Restore invariant: actual content and non-exec storage. Verify MIME types server-side with finfo_file().",
                    ));
                }

                if lower.contains("bk-ai-lng-005") || lower.contains("php debug/errors exposed") {
                    findings.push(Self::create_finding(
                        "BK-AI-LNG-005",
                        "CWE-489",
                        "PHP debug/errors exposed publicly or dangerous runtime settings enabled",
                        Severity::High,
                        "2.24 Language/runtime-specific red flags",
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "display_errors disabled in production and error logging directed to secure files",
                        "PHP display_errors or verbose debug output enabled in production code, exposing sensitive credentials and system details.",
                        "Restore invariant: environment-aware settings. Set display_errors = Off and display_startup_errors = Off in production.",
                    ));
                }

                if lower.contains("bk-ai-lng-006") || lower.contains("child_process.exec receives request") {
                    findings.push(Self::create_finding(
                        "BK-AI-LNG-006",
                        "CWE-78",
                        "Node.js child_process.exec() receives request data",
                        Severity::Critical,
                        "2.24 Language/runtime-specific red flags",
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "child_process.execFile() or spawn() with discrete argument vectors and no shell execution",
                        "Node.js child_process.exec() passes unvalidated HTTP request data to an OS subshell, permitting command injection.",
                        "Restore invariant: no shell injection. Use child_process.execFile() or spawn() with explicit argument arrays.",
                    ));
                }

                if lower.contains("bk-ai-lng-007") || lower.contains("node/bun eval") {
                    findings.push(Self::create_finding(
                        "BK-AI-LNG-007",
                        "CWE-95",
                        "Node/Bun eval, vm, dynamic import of untrusted strings",
                        Severity::Critical,
                        "2.24 Language/runtime-specific red flags",
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Static module imports and structured JSON parsing without dynamic JavaScript evaluation",
                        "Node.js or Bun runtime invokes eval(), vm.runInContext(), or dynamic import() on untrusted strings.",
                        "Restore invariant: trusted code modules only. Replace eval and vm with safe parsers or isolated-vm sandbox.",
                    ));
                }

                if lower.contains("bk-ai-lng-008") || lower.contains("prototype pollution via unsafe merge") {
                    findings.push(Self::create_finding(
                        "BK-AI-LNG-008",
                        "CWE-1321",
                        "Node/Express prototype pollution via unsafe deep merge",
                        Severity::High,
                        "2.24 Language/runtime-specific red flags",
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Object prototype keys (__proto__, constructor, prototype) stripped or Object.create(null) maps",
                        "Recursive merge or property assignment blindly processes user-controlled object keys without filtering __proto__.",
                        "Restore invariant: hostile keys blocked. Sanitize '__proto__', 'constructor', and 'prototype' keys before assigning.",
                    ));
                }

                if lower.contains("bk-ai-lng-009") || lower.contains("auth middleware omitted on router") {
                    findings.push(Self::create_finding(
                        "BK-AI-LNG-009",
                        "CWE-306",
                        "Express/Fastify auth middleware omitted on one router/method",
                        Severity::High,
                        "2.24 Language/runtime-specific red flags",
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Global auth middleware or route-level authentication guards applied to all sensitive endpoints",
                        "Express or Fastify router exposes privileged endpoints (/admin, /manage) without registering authentication middleware.",
                        "Restore invariant: route coverage matrix. Apply auth middleware uniformly at the router level or endpoint handler.",
                    ));
                }

                if lower.contains("bk-ai-lng-010") || lower.contains("decompression stream lacks size") {
                    findings.push(Self::create_finding(
                        "BK-AI-LNG-010",
                        "CWE-400",
                        "Node request/compression/decompression stream lacks size and CPU caps",
                        Severity::Medium,
                        "2.24 Language/runtime-specific red flags",
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Explicit maxOutputLength or decompressed byte counter stream with abort on limit",
                        "Node.js zlib decompression stream consumes untrusted data without decompressed byte caps, risking zip bomb DoS.",
                        "Restore invariant: decompression bomb and abort boundaries. Specify maxOutputLength or pipe through stream size counter.",
                    ));
                }

                if lower.contains("bk-ai-lng-011") || lower.contains("postinstall hook from untrusted") {
                    findings.push(Self::create_finding(
                        "BK-AI-LNG-011",
                        "CWE-829",
                        "Bun/Node process runs postinstall or startup hook from untrusted package",
                        Severity::High,
                        "2.24 Language/runtime-specific red flags",
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "--ignore-scripts flag enabled or strict package script allowlist in lockfile",
                        "Package configuration executes unverified remote scripts via curl/wget pipe to bash during lifecycle hooks.",
                        "Restore invariant: hook provenance and privilege. Disable lifecycle scripts via --ignore-scripts and verify package provenance.",
                    ));
                }

                if lower.contains("bk-ai-lng-012") || lower.contains("subprocess with shell=true") {
                    findings.push(Self::create_finding(
                        "BK-AI-LNG-012",
                        "CWE-78",
                        "Python subprocess(..., shell=True), os.system() with untrusted data",
                        Severity::Critical,
                        "2.24 Language/runtime-specific red flags",
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "subprocess without shell=True and shlex.split() or structured argument sequence",
                        "Python subprocess module invoked with shell=True or os.system() with dynamic string inputs, permitting command injection.",
                        "Restore invariant: safe argument boundary. Pass arguments as a list with shell=False, or use shlex.quote().",
                    ));
                }

                if lower.contains("bk-ai-lng-013") || lower.contains("python pickle unsafe yaml") {
                    findings.push(Self::create_finding(
                        "BK-AI-LNG-013",
                        "CWE-502",
                        "Python pickle, dill, joblib, unsafe YAML used for untrusted data",
                        Severity::Critical,
                        "2.24 Language/runtime-specific red flags",
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Safe serialization formats (json, safetensors, yaml.safe_load)",
                        "Python unpickling or unsafe YAML deserialization invoked on untrusted data, enabling arbitrary code execution.",
                        "Restore invariant: safe data-only parsing. Use yaml.safe_load() and standard JSON or safetensors formats.",
                    ));
                }

                if lower.contains("bk-ai-lng-014") || lower.contains("flask/django debug misconfigured") {
                    findings.push(Self::create_finding(
                        "BK-AI-LNG-014",
                        "CWE-489",
                        "Flask/Django/FastAPI debug, secret, route dependency/auth controls misconfigured",
                        Severity::High,
                        "2.24 Language/runtime-specific red flags",
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Environment-based settings with DEBUG=False in production and secrets loaded from environment",
                        "Web framework configured with hardcoded secrets, wildcard allowed hosts, or debug mode enabled in production.",
                        "Restore invariant: environment-aware secure defaults. Disable DEBUG in production and load secrets from environment.",
                    ));
                }

                if lower.contains("bk-ai-lng-015") || lower.contains("go exec.command argument injection") {
                    findings.push(Self::create_finding(
                        "BK-AI-LNG-015",
                        "CWE-88",
                        "Go exec.Command arguments accept attacker-controlled flags/subcommands",
                        Severity::High,
                        "2.24 Language/runtime-specific red flags",
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Explicit argument validation rejecting leading '-' or using '--' flag termination",
                        "Go exec.Command invokes sensitive binaries with unvalidated user arguments, allowing argument injection.",
                        "Restore invariant: argument grammar constrained. Validate arguments against an allowlist or pass '--' before user args.",
                    ));
                }

                if lower.contains("bk-ai-lng-016") || lower.contains("go http client lacks deadlines") {
                    findings.push(Self::create_finding(
                        "BK-AI-LNG-016",
                        "CWE-918",
                        "Go HTTP clients follow redirects into forbidden origins or lack deadlines",
                        Severity::High,
                        "2.24 Language/runtime-specific red flags",
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Configured Timeout deadline and explicit CheckRedirect policy on http.Client",
                        "Go HTTP client initialized without timeout deadlines or with default redirect policy, leading to resource starvation or SSRF.",
                        "Restore invariant: controlled transport and redirect policy. Set an explicit Timeout and define CheckRedirect callback.",
                    ));
                }

                if lower.contains("bk-ai-lng-017") || lower.contains("go text/template used for html") {
                    findings.push(Self::create_finding(
                        "BK-AI-LNG-017",
                        "CWE-79",
                        "Go template uses text/template for user-controlled HTML where html/template expected",
                        Severity::High,
                        "2.24 Language/runtime-specific red flags",
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Use html/template package for automatic contextual HTML escaping",
                        "Go code uses text/template instead of html/template for rendering HTML templates, resulting in Cross-Site Scripting (XSS).",
                        "Restore invariant: context-aware HTML escaping. Import 'html/template' instead of 'text/template'.",
                    ));
                }

                if lower.contains("bk-ai-lng-018") || lower.contains("go strings.hasprefix path check") {
                    findings.push(Self::create_finding(
                        "BK-AI-LNG-018",
                        "CWE-22",
                        "Go path check uses strings.HasPrefix without symlink/segment safety",
                        Severity::High,
                        "2.24 Language/runtime-specific red flags",
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "filepath.Rel() or checking prefix with trailing filepath.Separator",
                        "Go directory traversal check uses strings.HasPrefix on cleaned paths without trailing separator, allowing prefix collision.",
                        "Restore invariant: canonical path containment. Use filepath.Rel() or append filepath.Separator to the base prefix.",
                    ));
                }

                if lower.contains("bk-ai-lng-019") || lower.contains("rust unsafe unchecked memory") {
                    findings.push(Self::create_finding(
                        "BK-AI-LNG-019",
                        "CWE-119",
                        "Rust unsafe/FFI/parser code claims compiler guarantees for unchecked memory",
                        Severity::Critical,
                        "2.24 Language/runtime-specific red flags",
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Checked conversions (TryFrom, slice validation) and explicit pointer alignment/null checks",
                        "Rust code invokes unsafe memory operations (transmute, slice::from_raw_parts) without validating alignment or bounds.",
                        "Restore invariant: unsafe invariants audited. Enforce strict assertions on pointer non-nullness, alignment, and capacity.",
                    ));
                }

                if lower.contains("bk-ai-lng-020") || lower.contains("rust unwrap on parser path") {
                    findings.push(Self::create_finding(
                        "BK-AI-LNG-020",
                        "CWE-754",
                        "Rust unwrap/expect on attacker-controlled parser path causes service crash",
                        Severity::Medium,
                        "2.24 Language/runtime-specific red flags",
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Error propagation via Result (?) or explicit error handling",
                        "Rust parser or network handler calls unwrap() on untrusted request data, allowing an attacker to panic the service.",
                        "Restore invariant: untrusted input cannot panic process. Use Result propagation (?) or match instead of unwrap().",
                    ));
                }

                if lower.contains("bk-ai-lng-021") || lower.contains("rust error fallback returns empty") {
                    findings.push(Self::create_finding(
                        "BK-AI-LNG-021",
                        "CWE-391",
                        "Rust error fallback returns empty findings/success after IO failure",
                        Severity::Medium,
                        "2.24 Language/runtime-specific red flags",
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Preserve failed/partial error status and log structured diagnostic evidence",
                        "Rust error handler silently converts IO or critical failures into Ok(vec![]) empty success, masking fatal errors.",
                        "Restore invariant: partial/failed status preserved. Propagate the error with Err(e.into()) or return structured status.",
                    ));
                }

                if lower.contains("bk-ai-lng-022") || lower.contains("java deserialization or jndi") {
                    findings.push(Self::create_finding(
                        "BK-AI-LNG-022",
                        "CWE-502",
                        "Java deserialization, expression language or unsafe JNDI lookup",
                        Severity::Critical,
                        "2.24 Language/runtime-specific red flags",
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "ObjectInputFilter (JEP 290) or disabling remote JNDI protocols",
                        "Java application executes unsafe object deserialization (ObjectInputStream.readObject) or unsafe JNDI lookup.",
                        "Restore invariant: external values cannot select code. Implement ObjectInputFilter and restrict JNDI protocols.",
                    ));
                }

                if lower.contains("bk-ai-lng-023") || lower.contains(".net allowanonymous on admin") {
                    findings.push(Self::create_finding(
                        "BK-AI-LNG-023",
                        "CWE-862",
                        ".NET middleware/policy attribute omitted on controller/minimal API",
                        Severity::High,
                        "2.24 Language/runtime-specific red flags",
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "[Authorize] attribute or RequireAuthorization() policy on sensitive endpoints",
                        ".NET privileged controller or endpoint is annotated with [AllowAnonymous], bypassing authentication on sensitive routes.",
                        "Restore invariant: endpoint authorization matrix. Remove [AllowAnonymous] and apply [Authorize(Roles = 'Admin')].",
                    ));
                }

                if lower.contains("bk-ai-lng-024") || lower.contains("ruby send untrusted") {
                    findings.push(Self::create_finding(
                        "BK-AI-LNG-024",
                        "CWE-94",
                        "Ruby send, ERB/Marshal/YAML loaders execute untrusted material",
                        Severity::Critical,
                        "2.24 Language/runtime-specific red flags",
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Strict method allowlists and safe serialization (JSON, YAML.safe_load)",
                        "Ruby application invokes dynamic dispatch (.send) or deserialization (Marshal.load) on user-controlled input.",
                        "Restore invariant: no untrusted metaprogramming boundary. Avoid dynamic send with user inputs and use YAML.safe_load.",
                    ));
                }

                if lower.contains("bk-ai-lng-025") || lower.contains("c/c++ unchecked raw pointer copy") {
                    findings.push(Self::create_finding(
                        "BK-AI-LNG-025",
                        "CWE-120",
                        "C/C++/Zig generated code uses unchecked raw pointer/array copy",
                        Severity::Critical,
                        "2.24 Language/runtime-specific red flags",
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Bounded memory copies (strncpy, snprintf) with prior destination length assertions",
                        "C/C++ or Zig code calls unbounded copy routines (strcpy, sprintf) or memcpy with unchecked length parameters.",
                        "Restore invariant: size and lifetime bounds. Use bounded memory copy routines (snprintf, strncpy) and assert buffer bounds.",
                    ));
                }

                if lower.contains("bk-ai-lng-026") || lower.contains("sql escape helper instead of bind") {
                    findings.push(Self::create_finding(
                        "BK-AI-LNG-026",
                        "CWE-89",
                        "SQL/ORM integration treats string escape helper as replacement for bind parameters",
                        Severity::High,
                        "2.24 Language/runtime-specific red flags",
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Parameterized queries and prepared statements with strict parameter binding",
                        "Application uses string escaping functions (addslashes) instead of parameterized query binding, risking SQL injection.",
                        "Restore invariant: binding at actual query sink. Use prepared statements with parameter placeholders (? or :param).",
                    ));
                }

                continue;
            }

            // ---------------------------------------------------------------
            // Positive code triggers with guard verification
            // ---------------------------------------------------------------

            // 1. BK-AI-LNG-001 (CWE-98): PHP include, require or template path controlled by user
            if RE_LNG_001_PHP_INCLUDE.is_match(trimmed) && !RE_LNG_001_GUARD.is_match(&context_window) {
                findings.push(Self::create_finding(
                    "BK-AI-LNG-001",
                    "CWE-98",
                    "PHP include, require or template path controlled by user",
                    Severity::Critical,
                    "2.24 Language/runtime-specific red flags",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Finite template whitelist with static mapping or strict basename validation",
                    "PHP file inclusion directives evaluate user-controlled input, enabling local or remote file inclusion (LFI/RFI).",
                    "Restore invariant: finite template set. Map user inputs to a fixed static array of allowed templates.",
                ));
            }

            // 2. BK-AI-LNG-002 (CWE-502): PHP unserialize() called on attacker-provided bytes
            if RE_LNG_002_PHP_UNSERIALIZE.is_match(trimmed) && !RE_LNG_002_GUARD.is_match(&context_window) {
                findings.push(Self::create_finding(
                    "BK-AI-LNG-002",
                    "CWE-502",
                    "PHP unserialize() called on attacker-provided bytes",
                    Severity::Critical,
                    "2.24 Language/runtime-specific red flags",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Safe JSON serialization (json_decode) or unserialize with allowed_classes => false",
                    "PHP unserialize() invoked on unauthenticated input, allowing object injection and POP gadget chains.",
                    "Restore invariant: object injection path gated. Use json_decode() or specify ['allowed_classes' => false].",
                ));
            }

            // 3. BK-AI-LNG-003 (CWE-78): PHP shell_exec, system, passthru fed from request
            if RE_LNG_003_PHP_CMD.is_match(trimmed) && !RE_LNG_003_GUARD.is_match(&context_window) {
                findings.push(Self::create_finding(
                    "BK-AI-LNG-003",
                    "CWE-78",
                    "PHP shell_exec, system, passthru fed from request",
                    Severity::Critical,
                    "2.24 Language/runtime-specific red flags",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Strict command allowlist and argument isolation via escapeshellarg",
                    "PHP command execution primitives invoked with unescaped request parameters, leading to OS command injection.",
                    "Restore invariant: no untrusted command path. Wrap all arguments in escapeshellarg() against a strict allowlist.",
                ));
            }

            // 4. BK-AI-LNG-004 (CWE-434): PHP upload/filename checks rely solely on extension or client MIME
            if RE_LNG_004_PHP_UPLOAD.is_match(trimmed) && !RE_LNG_004_GUARD.is_match(&context_window) {
                findings.push(Self::create_finding(
                    "BK-AI-LNG-004",
                    "CWE-434",
                    "PHP upload/filename checks rely solely on extension or client MIME",
                    Severity::High,
                    "2.24 Language/runtime-specific red flags",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Server-side magic byte inspection (finfo_file) and storage in non-executable directories",
                    "File upload validation checks only client-controlled MIME type or file extension without magic bytes verification.",
                    "Restore invariant: actual content and non-exec storage. Verify MIME types server-side with finfo_file().",
                ));
            }

            // 5. BK-AI-LNG-005 (CWE-489): PHP debug/errors exposed publicly or dangerous runtime settings enabled
            if RE_LNG_005_PHP_DEBUG.is_match(trimmed) && !RE_LNG_005_GUARD.is_match(&context_window) {
                findings.push(Self::create_finding(
                    "BK-AI-LNG-005",
                    "CWE-489",
                    "PHP debug/errors exposed publicly or dangerous runtime settings enabled",
                    Severity::High,
                    "2.24 Language/runtime-specific red flags",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "display_errors disabled in production and error logging directed to secure files",
                    "PHP display_errors or verbose debug output enabled in production code, exposing sensitive credentials and system details.",
                    "Restore invariant: environment-aware settings. Set display_errors = Off and display_startup_errors = Off in production.",
                ));
            }

            // 6. BK-AI-LNG-006 (CWE-78): Node.js child_process.exec() receives request data
            if RE_LNG_006_NODE_EXEC.is_match(trimmed) && !RE_LNG_006_GUARD.is_match(&context_window) {
                findings.push(Self::create_finding(
                    "BK-AI-LNG-006",
                    "CWE-78",
                    "Node.js child_process.exec() receives request data",
                    Severity::Critical,
                    "2.24 Language/runtime-specific red flags",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "child_process.execFile() or spawn() with discrete argument vectors and no shell execution",
                    "Node.js child_process.exec() passes unvalidated HTTP request data to an OS subshell, permitting command injection.",
                    "Restore invariant: no shell injection. Use child_process.execFile() or spawn() with explicit argument arrays.",
                ));
            }

            // 7. BK-AI-LNG-007 (CWE-95): Node/Bun eval, vm, dynamic import of untrusted strings
            if RE_LNG_007_NODE_EVAL.is_match(trimmed) && !RE_LNG_007_GUARD.is_match(&context_window) {
                findings.push(Self::create_finding(
                    "BK-AI-LNG-007",
                    "CWE-95",
                    "Node/Bun eval, vm, dynamic import of untrusted strings",
                    Severity::Critical,
                    "2.24 Language/runtime-specific red flags",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Static module imports and structured JSON parsing without dynamic JavaScript evaluation",
                    "Node.js or Bun runtime invokes eval(), vm.runInContext(), or dynamic import() on untrusted strings.",
                    "Restore invariant: trusted code modules only. Replace eval and vm with safe parsers or isolated-vm sandbox.",
                ));
            }

            // 8. BK-AI-LNG-008 (CWE-1321): Node/Express prototype pollution via unsafe deep merge
            if RE_LNG_008_PROTOTYPE_POLLUTION.is_match(trimmed) && !RE_LNG_008_GUARD.is_match(&context_window) {
                findings.push(Self::create_finding(
                    "BK-AI-LNG-008",
                    "CWE-1321",
                    "Node/Express prototype pollution via unsafe deep merge",
                    Severity::High,
                    "2.24 Language/runtime-specific red flags",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Object prototype keys (__proto__, constructor, prototype) stripped or Object.create(null) maps",
                    "Recursive merge or property assignment blindly processes user-controlled object keys without filtering __proto__.",
                    "Restore invariant: hostile keys blocked. Sanitize '__proto__', 'constructor', and 'prototype' keys before assigning.",
                ));
            }

            // 9. BK-AI-LNG-009 (CWE-306): Express/Fastify auth middleware omitted on one router/method
            if RE_LNG_009_ROUTE_NO_AUTH.is_match(trimmed) && !RE_LNG_009_GUARD.is_match(&context_window) {
                findings.push(Self::create_finding(
                    "BK-AI-LNG-009",
                    "CWE-306",
                    "Express/Fastify auth middleware omitted on one router/method",
                    Severity::High,
                    "2.24 Language/runtime-specific red flags",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Global auth middleware or route-level authentication guards applied to all sensitive endpoints",
                    "Express or Fastify router exposes privileged endpoints (/admin, /manage) without registering authentication middleware.",
                    "Restore invariant: route coverage matrix. Apply auth middleware uniformly at the router level or endpoint handler.",
                ));
            }

            // 10. BK-AI-LNG-010 (CWE-400): Node request/compression/decompression stream lacks size and CPU caps
            if RE_LNG_010_NODE_STREAM_DOS.is_match(trimmed) && !RE_LNG_010_GUARD.is_match(&context_window) {
                findings.push(Self::create_finding(
                    "BK-AI-LNG-010",
                    "CWE-400",
                    "Node request/compression/decompression stream lacks size and CPU caps",
                    Severity::Medium,
                    "2.24 Language/runtime-specific red flags",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Explicit maxOutputLength or decompressed byte counter stream with abort on limit",
                    "Node.js zlib decompression stream consumes untrusted data without decompressed byte caps, risking zip bomb DoS.",
                    "Restore invariant: decompression bomb and abort boundaries. Specify maxOutputLength or pipe through stream size counter.",
                ));
            }

            // 11. BK-AI-LNG-011 (CWE-829): Bun/Node process runs postinstall or startup hook from untrusted package
            if RE_LNG_011_UNTRUSTED_HOOK.is_match(trimmed) && !RE_LNG_011_GUARD.is_match(&context_window) {
                findings.push(Self::create_finding(
                    "BK-AI-LNG-011",
                    "CWE-829",
                    "Bun/Node process runs postinstall or startup hook from untrusted package",
                    Severity::High,
                    "2.24 Language/runtime-specific red flags",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "--ignore-scripts flag enabled or strict package script allowlist in lockfile",
                    "Package configuration executes unverified remote scripts via curl/wget pipe to bash during lifecycle hooks.",
                    "Restore invariant: hook provenance and privilege. Disable lifecycle scripts via --ignore-scripts and verify package provenance.",
                ));
            }

            // 12. BK-AI-LNG-012 (CWE-78): Python subprocess(..., shell=True), os.system() with untrusted data
            if RE_LNG_012_PY_CMD.is_match(trimmed) && !RE_LNG_012_GUARD.is_match(&context_window) {
                findings.push(Self::create_finding(
                    "BK-AI-LNG-012",
                    "CWE-78",
                    "Python subprocess(..., shell=True), os.system() with untrusted data",
                    Severity::Critical,
                    "2.24 Language/runtime-specific red flags",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "subprocess without shell=True and shlex.split() or structured argument sequence",
                    "Python subprocess module invoked with shell=True or os.system() with dynamic string inputs, permitting command injection.",
                    "Restore invariant: safe argument boundary. Pass arguments as a list with shell=False, or use shlex.quote().",
                ));
            }

            // 13. BK-AI-LNG-013 (CWE-502): Python pickle, dill, joblib, unsafe YAML used for untrusted data
            if RE_LNG_013_PY_DESERIALIZE.is_match(trimmed) && !RE_LNG_013_GUARD.is_match(&context_window) {
                findings.push(Self::create_finding(
                    "BK-AI-LNG-013",
                    "CWE-502",
                    "Python pickle, dill, joblib, unsafe YAML used for untrusted data",
                    Severity::Critical,
                    "2.24 Language/runtime-specific red flags",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Safe serialization formats (json, safetensors, yaml.safe_load)",
                    "Python unpickling or unsafe YAML deserialization invoked on untrusted data, enabling arbitrary code execution.",
                    "Restore invariant: safe data-only parsing. Use yaml.safe_load() and standard JSON or safetensors formats.",
                ));
            }

            // 14. BK-AI-LNG-014 (CWE-489): Flask/Django/FastAPI debug, secret, route dependency/auth controls misconfigured
            if RE_LNG_014_PY_CONFIG.is_match(trimmed) && !RE_LNG_014_GUARD.is_match(&context_window) {
                findings.push(Self::create_finding(
                    "BK-AI-LNG-014",
                    "CWE-489",
                    "Flask/Django/FastAPI debug, secret, route dependency/auth controls misconfigured",
                    Severity::High,
                    "2.24 Language/runtime-specific red flags",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Environment-based settings with DEBUG=False in production and secrets loaded from environment",
                    "Web framework configured with hardcoded secrets, wildcard allowed hosts, or debug mode enabled in production.",
                    "Restore invariant: environment-aware secure defaults. Disable DEBUG in production and load secrets from environment.",
                ));
            }

            // 15. BK-AI-LNG-015 (CWE-88): Go exec.Command arguments accept attacker-controlled flags/subcommands
            if RE_LNG_015_GO_CMD_ARGS.is_match(trimmed) && !RE_LNG_015_GUARD.is_match(&context_window) {
                findings.push(Self::create_finding(
                    "BK-AI-LNG-015",
                    "CWE-88",
                    "Go exec.Command arguments accept attacker-controlled flags/subcommands",
                    Severity::High,
                    "2.24 Language/runtime-specific red flags",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Explicit argument validation rejecting leading '-' or using '--' flag termination",
                    "Go exec.Command invokes sensitive binaries with unvalidated user arguments, allowing argument injection.",
                    "Restore invariant: argument grammar constrained. Validate arguments against an allowlist or pass '--' before user args.",
                ));
            }

            // 16. BK-AI-LNG-016 (CWE-918): Go HTTP clients follow redirects into forbidden origins or lack deadlines
            if RE_LNG_016_GO_HTTP_CLIENT.is_match(trimmed) && !RE_LNG_016_GUARD.is_match(&context_window) {
                findings.push(Self::create_finding(
                    "BK-AI-LNG-016",
                    "CWE-918",
                    "Go HTTP clients follow redirects into forbidden origins or lack deadlines",
                    Severity::High,
                    "2.24 Language/runtime-specific red flags",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Configured Timeout deadline and explicit CheckRedirect policy on http.Client",
                    "Go HTTP client initialized without timeout deadlines or with default redirect policy, leading to resource starvation or SSRF.",
                    "Restore invariant: controlled transport and redirect policy. Set an explicit Timeout and define CheckRedirect callback.",
                ));
            }

            // 17. BK-AI-LNG-017 (CWE-79): Go template uses text/template for user-controlled HTML where html/template expected
            if RE_LNG_017_GO_TEXT_TEMPLATE.is_match(trimmed) && !RE_LNG_017_GUARD.is_match(&context_window) {
                findings.push(Self::create_finding(
                    "BK-AI-LNG-017",
                    "CWE-79",
                    "Go template uses text/template for user-controlled HTML where html/template expected",
                    Severity::High,
                    "2.24 Language/runtime-specific red flags",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Use html/template package for automatic contextual HTML escaping",
                    "Go code uses text/template instead of html/template for rendering HTML templates, resulting in Cross-Site Scripting (XSS).",
                    "Restore invariant: context-aware HTML escaping. Import 'html/template' instead of 'text/template'.",
                ));
            }

            // 18. BK-AI-LNG-018 (CWE-22): Go path check uses strings.HasPrefix without symlink/segment safety
            if RE_LNG_018_GO_PATH_CHECK.is_match(trimmed) && !RE_LNG_018_GUARD.is_match(&context_window) {
                findings.push(Self::create_finding(
                    "BK-AI-LNG-018",
                    "CWE-22",
                    "Go path check uses strings.HasPrefix without symlink/segment safety",
                    Severity::High,
                    "2.24 Language/runtime-specific red flags",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "filepath.Rel() or checking prefix with trailing filepath.Separator",
                    "Go directory traversal check uses strings.HasPrefix on cleaned paths without trailing separator, allowing prefix collision.",
                    "Restore invariant: canonical path containment. Use filepath.Rel() or append filepath.Separator to the base prefix.",
                ));
            }

            // 19. BK-AI-LNG-019 (CWE-119): Rust unsafe/FFI/parser code claims compiler guarantees for unchecked memory
            if RE_LNG_019_RUST_UNCHECKED_MEM.is_match(trimmed) && !RE_LNG_019_GUARD.is_match(&context_window) {
                findings.push(Self::create_finding(
                    "BK-AI-LNG-019",
                    "CWE-119",
                    "Rust unsafe/FFI/parser code claims compiler guarantees for unchecked memory",
                    Severity::Critical,
                    "2.24 Language/runtime-specific red flags",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Checked conversions (TryFrom, slice validation) and explicit pointer alignment/null checks",
                    "Rust code invokes unsafe memory operations (transmute, slice::from_raw_parts) without validating alignment or bounds.",
                    "Restore invariant: unsafe invariants audited. Enforce strict assertions on pointer non-nullness, alignment, and capacity.",
                ));
            }

            // 20. BK-AI-LNG-020 (CWE-754): Rust unwrap/expect on attacker-controlled parser path causes service crash
            if RE_LNG_020_RUST_UNWRAP_PARSER.is_match(trimmed) && !RE_LNG_020_GUARD.is_match(&context_window) {
                findings.push(Self::create_finding(
                    "BK-AI-LNG-020",
                    "CWE-754",
                    "Rust unwrap/expect on attacker-controlled parser path causes service crash",
                    Severity::Medium,
                    "2.24 Language/runtime-specific red flags",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Error propagation via Result (?) or explicit error handling",
                    "Rust parser or network handler calls unwrap() on untrusted request data, allowing an attacker to panic the service.",
                    "Restore invariant: untrusted input cannot panic process. Use Result propagation (?) or match instead of unwrap().",
                ));
            }

            // 21. BK-AI-LNG-021 (CWE-391): Rust error fallback returns empty findings/success after IO failure
            if RE_LNG_021_RUST_ERROR_SWALLOW.is_match(trimmed) && !RE_LNG_021_GUARD.is_match(&context_window) {
                findings.push(Self::create_finding(
                    "BK-AI-LNG-021",
                    "CWE-391",
                    "Rust error fallback returns empty findings/success after IO failure",
                    Severity::Medium,
                    "2.24 Language/runtime-specific red flags",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Preserve failed/partial error status and log structured diagnostic evidence",
                    "Rust error handler silently converts IO or critical failures into Ok(vec![]) empty success, masking fatal errors.",
                    "Restore invariant: partial/failed status preserved. Propagate the error with Err(e.into()) or return structured status.",
                ));
            }

            // 22. BK-AI-LNG-022 (CWE-502): Java deserialization, expression language or unsafe JNDI lookup
            if RE_LNG_022_JAVA_DESERIALIZE.is_match(trimmed) && !RE_LNG_022_GUARD.is_match(&context_window) {
                findings.push(Self::create_finding(
                    "BK-AI-LNG-022",
                    "CWE-502",
                    "Java deserialization, expression language or unsafe JNDI lookup",
                    Severity::Critical,
                    "2.24 Language/runtime-specific red flags",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "ObjectInputFilter (JEP 290) or disabling remote JNDI protocols",
                    "Java application executes unsafe object deserialization (ObjectInputStream.readObject) or unsafe JNDI lookup.",
                    "Restore invariant: external values cannot select code. Implement ObjectInputFilter and restrict JNDI protocols.",
                ));
            }

            // 23. BK-AI-LNG-023 (CWE-862): .NET middleware/policy attribute omitted on controller/minimal API
            let is_dotnet_anon_match = RE_LNG_023_DOTNET_ALLOW_ANON.is_match(trimmed)
                || (RE_LNG_023_ANON_ATTR.is_match(trimmed) && RE_LNG_023_SENSITIVE_CONTEXT.is_match(&context_window));
            if is_dotnet_anon_match && !RE_LNG_023_GUARD.is_match(&context_window) {
                findings.push(Self::create_finding(
                    "BK-AI-LNG-023",
                    "CWE-862",
                    ".NET middleware/policy attribute omitted on controller/minimal API",
                    Severity::High,
                    "2.24 Language/runtime-specific red flags",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "[Authorize] attribute or RequireAuthorization() policy on sensitive endpoints",
                    ".NET privileged controller or endpoint is annotated with [AllowAnonymous], bypassing authentication on sensitive routes.",
                    "Restore invariant: endpoint authorization matrix. Remove [AllowAnonymous] and apply [Authorize(Roles = 'Admin')].",
                ));
            }

            // 24. BK-AI-LNG-024 (CWE-94): Ruby send, ERB/Marshal/YAML loaders execute untrusted material
            if RE_LNG_024_RUBY_METAPROGRAM.is_match(trimmed) && !RE_LNG_024_GUARD.is_match(&context_window) {
                findings.push(Self::create_finding(
                    "BK-AI-LNG-024",
                    "CWE-94",
                    "Ruby send, ERB/Marshal/YAML loaders execute untrusted material",
                    Severity::Critical,
                    "2.24 Language/runtime-specific red flags",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Strict method allowlists and safe serialization (JSON, YAML.safe_load)",
                    "Ruby application invokes dynamic dispatch (.send) or deserialization (Marshal.load) on user-controlled input.",
                    "Restore invariant: no untrusted metaprogramming boundary. Avoid dynamic send with user inputs and use YAML.safe_load.",
                ));
            }

            // 25. BK-AI-LNG-025 (CWE-120): C/C++/Zig generated code uses unchecked raw pointer/array copy
            if RE_LNG_025_RAW_MEM_COPY.is_match(trimmed) && !RE_LNG_025_GUARD.is_match(&context_window) {
                findings.push(Self::create_finding(
                    "BK-AI-LNG-025",
                    "CWE-120",
                    "C/C++/Zig generated code uses unchecked raw pointer/array copy",
                    Severity::Critical,
                    "2.24 Language/runtime-specific red flags",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Bounded memory copies (strncpy, snprintf) with prior destination length assertions",
                    "C/C++ or Zig code calls unbounded copy routines (strcpy, sprintf) or memcpy with unchecked length parameters.",
                    "Restore invariant: size and lifetime bounds. Use bounded memory copy routines (snprintf, strncpy) and assert buffer bounds.",
                ));
            }

            // 26. BK-AI-LNG-026 (CWE-89): SQL/ORM integration treats string escape helper as replacement for bind parameters
            if RE_LNG_026_SQL_ESCAPE_HELPER.is_match(trimmed) && !RE_LNG_026_GUARD.is_match(&context_window) {
                findings.push(Self::create_finding(
                    "BK-AI-LNG-026",
                    "CWE-89",
                    "SQL/ORM integration treats string escape helper as replacement for bind parameters",
                    Severity::High,
                    "2.24 Language/runtime-specific red flags",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Parameterized queries and prepared statements with strict parameter binding",
                    "Application uses string escaping functions (addslashes) instead of parameterized query binding, risking SQL injection.",
                    "Restore invariant: binding at actual query sink. Use prepared statements with parameter placeholders (? or :param).",
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
        finding.detector_id = "language-pitfalls".to_string();
        finding.detector_version = "1.0.0".to_string();
        finding.category = category.to_string();
        finding.affectedness = Affectedness::ConfirmedAffected;
        finding.reachability = Reachability::PotentiallyReachable;
        finding.confidence = Confidence::High;
        finding.evidence_certainty = EvidenceCertainty::StronglySupported;
        finding.advisory_ids = vec![cwe.to_string(), rule_id.to_string()];
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
