#![allow(dead_code, clippy::collapsible_if)]

use crate::types::*;
use regex::Regex;
use std::collections::HashSet;
use std::path::Path;
use std::sync::LazyLock;

// ============================================================================
// Category 18: Native Code, FFI and Memory Safety (BK-AI-MEM-004 to BK-AI-MEM-012)
// ============================================================================

/// BK-AI-MEM-004 (CWE-476): Null/dangling pointer dereference reachable from malformed input
static RE_MEM_004_NULL_DEREF: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:unsafe\s*\{[^\}]*\*|^\*[a-zA-Z0-9_]+|=\s*\*[a-zA-Z0-9_]+|\(\*[a-zA-Z0-9_]+\)|\bchar\s*\*\s*[a-zA-Z0-9_]+\s*=\s*(?:malloc|calloc|fopen|getenv)\s*\([^)]*\)\s*;(?:\s*\*|\s*[a-zA-Z0-9_]+\s*->)|\*[a-zA-Z0-9_]+\s*=\s*.*//.*deref|//.*(?:null\s+pointer\s+dereference|dangling\s+pointer|\*ptr\s+without\s+null|unchecked\s+pointer\s+deref))"#).unwrap()
});
static RE_MEM_004_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:if\s*\([^)]*==\s*(?:NULL|nullptr)|if\s*\([^)]*!=\s*(?:NULL|nullptr)|if\s*\(\s*![a-zA-Z0-9_]+\s*\)|if\s*\(\s*[a-zA-Z0-9_]+\s*\)|assert\s*\([^)]*!=\s*(?:NULL|nullptr)|\.is_null\(\)|assert!\s*\(![a-zA-Z0-9_]+\.is_null\(\)|NonNull::new|Option<)"#).unwrap()
});

/// BK-AI-MEM-005 (CWE-120): Stack/heap buffer copy lacks verified bounds
static RE_MEM_005_BUFFER_COPY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\bstrcpy\s*\(|\bstrcat\s*\(|\bsprintf\s*\(\s*[^,]+,\s*["'][^"']*\%s|\bvsprintf\s*\(|\balloca\s*\(|\bgets\s*\(|//.*(?:stack/heap\s+buffer\s+copy\s+lacks\s+verified\s+bounds|buffer\s+copy\s+lacks\s+verified\s+bounds|unbounded\s+buffer\s+copy|alloca\s+without\s+bounds))"#).unwrap()
});
static RE_MEM_005_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:strncpy|strlcpy|snprintf|vsnprintf|memcpy_s|strcpy_s|strlcat|sizeof\s*\([^)]*\)\s*>\s*strlen|strlen\([^)]*\)\s*<\s*sizeof|if\s*\([^)]*len\s*<=\s*MAX)"#).unwrap()
});

/// BK-AI-MEM-006 (CWE-119): `unsafe` Rust or FFI uses unchecked slice/pointer conversion
static RE_MEM_006_SLICE_CONV: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:(?:std::)?slice::from_raw_parts(?:_mut)?\s*\(|(?:std::)?str::from_utf8_unchecked\s*\(|\bVec::from_raw_parts\s*\(|//.*(?:unchecked\s+slice/pointer\s+conversion|std::slice::from_raw_parts\s+without\s+len|unchecked\s+slice\s+conversion))"#).unwrap()
});
static RE_MEM_006_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:assert!\s*\([^)]*len|ensure!\s*\([^)]*len|if\s+.*len\s*<=\s*|if\s+.*len\s*>\s*|checked_len|is_valid_len|verify_bounds|\.is_null\(\))"#).unwrap()
});

/// BK-AI-MEM-007 (CWE-170 / CWE-120): C/C++ string encoding or truncation produces security control mismatch
static RE_MEM_007_STRNCPY_TRUNC: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\bstrncpy\s*\(\s*([a-zA-Z0-9_]+)\s*,|//.*(?:strncpy\s+without\s+explicit\s+null|string\s+encoding\s+or\s+truncation|unterminated\s+strncpy))"#).unwrap()
});
static RE_MEM_007_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\[\s*(?:sizeof\s*\([^)]*\)\s*-\s*1|\d+)\s*\]\s*=\s*(?:'\\0'|0|\bNULL\b)|strlcpy|snprintf)"#).unwrap()
});

/// BK-AI-MEM-008 (CWE-250): Untrusted native decoder or plugin runs in privileged host process
static RE_MEM_008_NATIVE_LOAD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\bdlopen\s*\(\s*(?:[a-zA-Z0-9_]*(?:plugin|path|user|input|untrusted|decoder|module|addon|name)|argv|req)[^)]*\)|\bLoadLibrary(?:A|W)?\s*\(\s*(?:[a-zA-Z0-9_]*(?:plugin|path|user|input|untrusted|decoder|module|addon|name)|argv|req)[^)]*\)|\blibloading::Library::new\s*\(\s*(?:[a-zA-Z0-9_]*(?:plugin|path|user|input|untrusted|decoder|module)|req)[^)]*\)|//.*(?:untrusted\s+native\s+decoder|dlopen.*in\s+privileged|plugin\s+runs\s+in\s+privileged))"#).unwrap()
});
static RE_MEM_008_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:verify_signature|verify_plugin|is_whitelisted|drop_privileges|sandbox|seccomp|trusted_dir|allowed_plugins|verify_hash)"#).unwrap()
});

/// BK-AI-MEM-009 (CWE-755): Rust/Go panic or C++ exception crosses foreign function boundary unsafely
static RE_MEM_009_FFI_PANIC: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:pub\s+(?:unsafe\s+)?extern\s+["']C["']\s+fn\s+[a-zA-Z0-9_]+|//export\s+[a-zA-Z0-9_]+|//.*(?:panic.*crosses.*foreign.*function|extern\s+["']C["'].*without.*catch_unwind))"#).unwrap()
});
static RE_MEM_009_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:catch_unwind|AssertUnwindSafe|recover\(\)|no_panic)"#).unwrap()
});

/// BK-AI-MEM-010 (CWE-693): Compiler/hardening flags removed to silence warnings or fix build
static RE_MEM_010_FLAGS_REMOVED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:-fno-stack-protector|-z\s+execstack|/GS-|/NXCOMPAT:NO|/DYNAMICBASE:NO|-D_FORTIFY_SOURCE=0|CAutoProtect\s*=\s*(?:OFF|false|0)\b|//.*(?:compiler/hardening\s+flags\s+removed|hardening\s+flags\s+disabled|-fno-stack-protector))"#).unwrap()
});
static RE_MEM_010_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:-fstack-protector|-z\s+noexecstack|/GS\b|/NXCOMPAT\b|/DYNAMICBASE\b|-D_FORTIFY_SOURCE=2|CAutoProtect\s*=\s*ON)"#).unwrap()
});

/// BK-AI-MEM-011 (CWE-401): Zig/C++ allocator mismatch or forgotten cleanup leaks secret-bearing memory
static RE_MEM_011_ALLOC_MISMATCH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:free\s*\(\s*(?:[a-zA-Z0-9_]*(?:key|secret|password|token|privkey|seed)[a-zA-Z0-9_]*)\s*\)|new\s+[^;\[\]]+;\s*.*?\bfree\s*\(|malloc\s*\([^)]*\);\s*.*?\bdelete\s+|(?:new\s+[a-zA-Z0-9_]+\[[^\]]+\];.*?\bdelete\s+[a-zA-Z0-9_]+;)|//.*(?:allocator\s+mismatch|unzeroed\s+key\s+buffer|leaks\s+secret-bearing\s+memory|forgotten\s+cleanup\s+leaks\s+secret))"#).unwrap()
});
static RE_MEM_011_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:explicit_bzero|sodium_memzero|SecureZeroMemory|zeroize|memset_s|ZeroizeOnDrop|unique_ptr|shared_ptr|delete\[\])"#).unwrap()
});

/// BK-AI-MEM-012 (CWE-20 / CWE-190): Binary parser trusts declared lengths and integer casts
static RE_MEM_012_UNTRUSTED_LEN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:(?:malloc|alloca|Vec::with_capacity)\s*\(\s*(?:reader\.)?read_u(?:16|32|64)\s*\(\s*\)|vec!\[\s*0(?:u8)?\s*;\s*[^\]]+as\s*usize\s*\]|let\s+(?:mut\s+)?[a-zA-Z0-9_]*\s*=\s*vec!\[\s*0(?:u8)?\s*;\s*|//.*(?:binary\s+parser\s+trusts\s+declared\s+length|read_u32.*used\s+directly\s+for\s+allocation|integer\s+cast\s+without\s+bounds))"#).unwrap()
});
static RE_MEM_012_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:if\s+.*len\s*>\s*MAX|if\s*\(.*len\s*>\s*MAX|len\s*<=\s*MAX|len\.min\(|checked_mul|ensure!\s*\(.*len\s*<=|MAX_ALLOWED|MAX_BUFFER_SIZE)"#).unwrap()
});

// ============================================================================
// Category 25: Mobile, Desktop, Electron and Local Apps (BK-AI-MOB-001 to BK-AI-MOB-010)
// ============================================================================

/// BK-AI-MOB-001 (CWE-798): Client mobile/desktop bundle contains long-lived cloud API/admin keys
static RE_MOB_001_CLOUD_KEY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:(?:AWS_SECRET_ACCESS_KEY|FIREBASE_ADMIN_KEY|FIREBASE_SERVICE_ACCOUNT|SUPABASE_SERVICE_ROLE_KEY|CLOUDFLARE_API_KEY|STRIPE_SECRET_KEY)\s*[:=]\s*["'][^"']{16,}["']|["'](?:aws_secret|firebase_admin_key|service_role_key|master_key)["']\s*[:=]\s*["'][^"']{20,}["']|//.*(?:client.*bundle.*contains.*cloud.*key|embedding.*AWS_SECRET_ACCESS_KEY|mobile.*bundle.*contains.*admin.*key))"#).unwrap()
});
static RE_MOB_001_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:process\.env\.|System\.getenv|SecretsManager|getSecret|backendProxy|Keychain|KeyStore)"#).unwrap()
});

/// BK-AI-MOB-002 (CWE-922 / CWE-312): Sensitive token stored in plaintext local preferences/file
static RE_MOB_002_PLAINTEXT_PREFS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:UserDefaults\.standard\.set\s*\([^,]+,\s*forKey:\s*["'][^"']*(?:token|jwt|auth|password|secret|session)[^"']*["']\)|(?:editor|prefs|sharedPreferences)\.putString\s*\(\s*["'][^"']*(?:token|jwt|auth|password|secret|session)[^"']*["']|localStorage\.setItem\s*\(\s*["'][^"']*(?:token|jwt|auth|password|secret|session|bearer)[^"']*["']|//.*(?:sensitive\s+token\s+stored\s+in\s+plaintext|UserDefaults.*without.*keychain|SharedPreferences.*jwt|localStorage\.setItem\(["']auth_token["']\)))"#).unwrap()
});
static RE_MOB_002_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:Keychain|KeyStore|EncryptedSharedPreferences|SecureStore|keytar|flutter_secure_storage|expo-secure-store|encrypt)"#).unwrap()
});

/// BK-AI-MOB-003 (CWE-926 / CWE-284): Android exported activity/service/provider reachable without intended permission
static RE_MOB_003_ANDROID_EXPORTED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:android:exported\s*=\s*["']true["']|//.*(?:android\s+exported.*without\s+permission|exported\s+activity.*without\s+intended\s+permission)|<!--.*exported.*without.*permission.*-->)"#).unwrap()
});
static RE_MOB_003_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)(?:android:permission\s*=\s*["'][^"']+["']|android:exported\s*=\s*["']false["'])"#,
    )
    .unwrap()
});

/// BK-AI-MOB-004 (CWE-939): Deep-link or custom protocol handler accepts unsafe URL/command
static RE_MOB_004_DEEP_LINK: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:app\.setAsDefaultProtocolClient\s*\(|(?:shell\.openExternal|Runtime\.getRuntime\(\)\.exec|startActivity)\s*\(\s*(?:url|deepLink|intentUrl|intent\.data|uri)\s*\)|//.*(?:deep-link.*accepts.*unsafe|custom\s+protocol\s+handler.*accepts\s+unsafe|deep-link.*executes.*without\s+validation))"#).unwrap()
});
static RE_MOB_004_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:allowed_hosts|isValidUrl|url\.host|uri\.scheme|whitelist|validateDeepLink|isSafeUrl|isAllowedUrl)"#).unwrap()
});

/// BK-AI-MOB-005 (CWE-250 / CWE-94): Electron renderer has Node integration/unsafe context isolation policy
static RE_MOB_005_ELECTRON_ISOLATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\bnodeIntegration\s*:\s*true\b|\bcontextIsolation\s*:\s*false\b|\benableRemoteModule\s*:\s*true\b|//.*(?:electron\s+renderer\s+has\s+node\s+integration|nodeIntegration:\s*true|contextIsolation:\s*false))"#).unwrap()
});
static RE_MOB_005_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:nodeIntegration\s*:\s*false|contextIsolation\s*:\s*true)"#).unwrap()
});

/// BK-AI-MOB-006 (CWE-78): Electron IPC main process blindly executes renderer-supplied command
static RE_MOB_006_IPC_EXEC: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:ipcMain\.(?:on|handle)|//.*(?:electron\s+ipc\s+main.*blindly\s+executes|ipcMain.*exec\(cmd\)|renderer-supplied\s+command))"#).unwrap()
});
static RE_MOB_006_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:allowedCommands|isCommandAllowed|whitelist\.includes|sanitizeCommand|commandMap\[)"#).unwrap()
});

/// BK-AI-MOB-007 (CWE-295): Mobile/desktop TLS trust all certificates or disables hostname verification
static RE_MOB_007_TLS_INSECURE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\brejectUnauthorized\s*:\s*false\b|\btrustAllCerts\s*=\s*true\b|\bAllowAllHostnameVerifier\b|\bsetHostnameVerifier\s*\(\s*(?:SSLSocketFactory\.)?ALLOW_ALL_HOSTNAME_VERIFIER\b|checkServerTrusted\s*\([^)]*\)\s*\{\s*(?:\/\/[^\n]*)?\s*\}|\bhandler\.proceed\s*\(\s*\)\s*;?\s*//.*(?:ssl|cert)|//.*(?:trust\s+all\s+certificates|disables\s+hostname\s+verification|rejectUnauthorized:\s*false))"#).unwrap()
});
static RE_MOB_007_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:rejectUnauthorized\s*:\s*true|CertificatePinner|cert_pinning|DefaultHostnameVerifier|handler\.cancel\(\))"#).unwrap()
});

/// BK-AI-MOB-008 (CWE-922 / CWE-276): Local database/files contain private content accessible to another user/process
static RE_MOB_008_WORLD_ACCESSIBLE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\bMODE_WORLD_READABLE\b|\bMODE_WORLD_WRITEABLE\b|\bchmod(?:Sync)?\s*\([^,]+,\s*(?:0o?777|0o?666)\s*\)|\bsetPermissions\s*\([^)]*(?:WORLD_READABLE|WORLD_WRITEABLE)\)|//.*(?:local\s+database.*contain\s+private\s+content\s+accessible|world-readable|world-writable\s+permissions|mode_world_readable))"#).unwrap()
});
static RE_MOB_008_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:MODE_PRIVATE|0o600|0o700|FileMode\(0600\)|FileMode\(0700\)|SQLITE_OPEN_PRIVATECACHE)"#).unwrap()
});

/// BK-AI-MOB-009 (CWE-494): Untrusted app updates or executable plugins have no origin verification
static RE_MOB_009_UNTRUSTED_UPDATES: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:autoUpdater\.setFeedURL|updater\.setUpdateUrl|downloadUpdate|//.*(?:untrusted\s+app\s+updates|executable\s+plugins\s+have\s+no\s+origin\s+verification|autoUpdater.*without.*signature|feed\s+url\s+over\s+http))"#).unwrap()
});
static RE_MOB_009_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)(?:https://|verifySignature|codesign|checksum|ed25519|publicKey|signatureVerified)"#,
    )
    .unwrap()
});

/// BK-AI-MOB-010 (CWE-200): Clipboard, screen capture, crash reports or notifications expose secret values
static RE_MOB_010_CLIPBOARD_SECRET: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:(?:Clipboard|clipboard|UIPasteboard\.general)\.(?:setString|writeText|setValue|string\s*=)\s*\([^)]*(?:token|password|secret|auth|apikey|api_key|otp|pin|credit_card)|Notification\.Builder\s*\([^)]*\)\s*.*?(?:setContentText|setText)\s*\([^)]*(?:password|token|otp|pin)|//.*(?:clipboard.*expose\s+secret\s+values|clipboard\.setString\(secretToken\)|missing\s+FLAG_SECURE))"#).unwrap()
});
static RE_MOB_010_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:FLAG_SECURE|sanitizeSecret|isSensitive:\s*true|clearClipboardAfter|maskSecret|clear_after_timeout)"#).unwrap()
});

// ============================================================================
// Category 21: AI Coding Assistant-Specific Traps (BK-AI-AIC-004)
// ============================================================================

/// BK-AI-AIC-004 (CWE-1059): Tests are rewritten/weakened after a failure instead of diagnosing cause
static RE_AIC_004_WEAKENED_TESTS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:assert\s+(?:True|1\s*==\s*1|True\s*==\s*True)\b|expect\s*\(\s*true\s*\)\.to(?:Be|Equal)\s*\(\s*true\s*\)|assert\s*\(\s*(?:true|1)\s*\)\s*;?\s*//.*(?:bypass|weaken|pass)|def\s+test_[a-zA-Z0-9_]+\s*\([^)]*\)\s*:\s*(?:pass|\.\.\.)\s*(?:#.*(?:fix|failing|temporarily))?|it\.skip\s*\(\s*["'][^"']*["']\s*,\s*.*//.*tests?\s+failing|//.*(?:tests?\s+are\s+rewritten/weakened|test\s+weakened\s+after\s+a?\s*failure|replacing\s+assertions\s+with\s+assert\s+True)|#.*(?:tests?\s+are\s+rewritten/weakened|test\s+weakened\s+after\s+a?\s*failure))"#).unwrap()
});
static RE_AIC_004_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:assert_eq!|assertEquals|expect\([^)]+\)\.toBe\s*\(\s*(?:false|\d+|['"][^'"]*['"])|assert\s+[a-zA-Z0-9_.]+\s*==|assert\s+[a-zA-Z0-9_.]+\s*in\s+|assert\s+len\([a-zA-Z0-9_.]+\))"#).unwrap()
});

// ============================================================================
// Category 22: LLM, RAG, Autonomous Agent and MCP Application Flaws (BK-AI-LLM-019 & 021)
// ============================================================================

/// BK-AI-LLM-019 (CWE-862): Agent chain allows one agent's unchecked proposal to become another agent's privileged command
static RE_LLM_019_AGENT_CHAIN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:(?:privileged_agent|executor|system_agent|admin_agent|agent_b|agentB)\.(?:execute|run|dispatch)\s*\(\s*(?:[a-zA-Z0-9_]*(?:proposal|output|plan)|(?:planner|agent_a|agentA|subagent|assistant)\.[a-zA-Z0-9_]+)[^)]*\)|tools\.execute\s*\(\s*agent\.generate_plan\([^)]*\)\s*\)|//.*(?:agent\s+chain\s+allows\s+one\s+agent's\s+unchecked\s+proposal|unchecked\s+proposal.*privileged\s+command|agentB\.execute\(agentA\.get_output\(\)\)))"#).unwrap()
});
static RE_LLM_019_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:require_human_confirmation|human_approval|policy_gate|validate_proposal|verify_agent_action|confirm_with_operator|can_execute_privileged|approval_required)"#).unwrap()
});

/// BK-AI-LLM-021 (CWE-613): Agent continues acting after revocation, stop request, timeout or ownership change
static RE_LLM_021_UNSTOPPABLE_AGENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:while\s+(?:True|true|!done|isRunning|agent\.has_next\(\))\s*:|async\s+function\s+runAgentLoop|while\s*\(\s*true\s*\)|await\s+[a-zA-Z0-9_]*agent\.(?:step|run_turn|execute_next)|[a-zA-Z0-9_]*agent\.(?:step|run_turn|execute_next)\s*\(|//.*(?:agent\s+continues\s+acting\s+after\s+revocation|agent\s+execution\s+loop\s+lacks.*(?:cancellation|abort_signal)|missing\s+abort_signal\.is_aborted))"#).unwrap()
});
static RE_LLM_021_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:abort_signal\.is_aborted|signal\.aborted|is_cancelled\(\)|ctx\.is_done\(\)|ctx\.deadline\(\)|check_revocation\(\)|is_stopped|timeout_expired|abort_signal)"#).unwrap()
});

// ============================================================================
// Scanner Implementation
// ============================================================================

pub struct NativeDesktopScanner;

impl NativeDesktopScanner {
    /// Scans source code content for Native, Desktop, Mobile, AI Trap, and Agent flaws.
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
            "c" | "cpp"
                | "cc"
                | "cxx"
                | "h"
                | "hpp"
                | "hxx"
                | "rs"
                | "zig"
                | "go"
                | "swift"
                | "kt"
                | "kts"
                | "java"
                | "m"
                | "mm"
                | "js"
                | "mjs"
                | "cjs"
                | "ts"
                | "tsx"
                | "jsx"
                | "py"
                | "xml"
                | "plist"
                | "json"
                | "yaml"
                | "yml"
                | "gradle"
                | "cmake"
                | "txt"
                | "toml"
                | "sh"
                | "bash"
                | "mk"
                | ""
        );
        if !is_supported {
            return findings;
        }

        let target_kind = match ext.as_str() {
            "js" | "mjs" | "cjs" | "ts" | "tsx" | "jsx" => TargetKind::NodeSourceFile,
            "json" | "yaml" | "yml" | "xml" | "plist" | "toml" => TargetKind::GenericConfigFile,
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

            let is_comment = trimmed.starts_with("//")
                || trimmed.starts_with('#')
                || trimmed.starts_with("/*")
                || trimmed.starts_with("*/")
                || trimmed.starts_with("* ")
                || trimmed == "*"
                || trimmed.starts_with("<!--");

            if is_comment {
                let lower = trimmed.to_lowercase();

                // Category 18: Native code comments
                if lower.contains("null pointer dereference")
                    || lower.contains("dangling pointer")
                    || lower.contains("*ptr without null")
                    || lower.contains("unchecked pointer deref")
                {
                    Self::push_finding(
                        &mut findings,
                        &mut seen,
                        "BK-AI-MEM-004",
                        &["CWE-476"],
                        "Null/dangling pointer dereference reachable from malformed input",
                        Severity::High,
                        "2.18 Native code, FFI and memory safety",
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Verify pointer non-null invariants before dereference",
                        "Code comment indicates unchecked null or dangling pointer dereference.",
                        "Perform explicit null checks ('if (ptr == NULL)' or 'if (!ptr.is_null())') prior to dereferencing raw pointers.",
                    );
                }

                if lower.contains("buffer copy lacks verified bounds")
                    || lower.contains("stack buffer copy lacks bounds")
                    || lower.contains("unbounded buffer copy")
                    || lower.contains("alloca without bounds")
                {
                    Self::push_finding(
                        &mut findings,
                        &mut seen,
                        "BK-AI-MEM-005",
                        &["CWE-120"],
                        "Stack/heap buffer copy lacks verified bounds",
                        Severity::Critical,
                        "2.18 Native code, FFI and memory safety",
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Enforce bounded copies using size-limited primitives or explicit bounds verification",
                        "Code comment indicates unbounded buffer copy or dynamic stack allocation without verified bounds.",
                        "Replace with bounded alternatives (snprintf, strlcpy, memcpy_s) and validate bounds before copying.",
                    );
                }

                if lower.contains("unchecked slice/pointer conversion")
                    || lower.contains("slice::from_raw_parts without len")
                    || lower.contains("unchecked slice conversion")
                {
                    Self::push_finding(
                        &mut findings,
                        &mut seen,
                        "BK-AI-MEM-006",
                        &["CWE-119"],
                        "`unsafe` Rust or FFI uses unchecked slice/pointer conversion",
                        Severity::High,
                        "2.18 Native code, FFI and memory safety",
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Validate pointer validity, non-null status, and slice length prior to raw parts reconstruction",
                        "Code comment indicates unchecked slice or pointer conversion from raw parts.",
                        "Verify that pointer is non-null, aligned, and length does not exceed allocated memory range before calling slice::from_raw_parts.",
                    );
                }

                if lower.contains("strncpy without explicit null")
                    || lower.contains("string encoding or truncation")
                    || lower.contains("unterminated strncpy")
                {
                    Self::push_finding(
                        &mut findings,
                        &mut seen,
                        "BK-AI-MEM-007",
                        &["CWE-170", "CWE-120"],
                        "C/C++ string encoding or truncation produces security control mismatch",
                        Severity::High,
                        "2.18 Native code, FFI and memory safety",
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Ensure null termination after strncpy or use strlcpy/snprintf",
                        "Code comment indicates strncpy truncation or lack of explicit null termination.",
                        "Explicitly set dest[sizeof(dest) - 1] = '\\0' or replace with snprintf / strlcpy.",
                    );
                }

                if lower.contains("untrusted native decoder")
                    || lower.contains("dlopen in privileged")
                    || lower.contains("plugin runs in privileged")
                {
                    Self::push_finding(
                        &mut findings,
                        &mut seen,
                        "BK-AI-MEM-008",
                        &["CWE-250"],
                        "Untrusted native decoder or plugin runs in privileged host process",
                        Severity::Critical,
                        "2.18 Native code, FFI and memory safety",
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Isolate native decoders in sandboxed worker processes and verify cryptographic signatures",
                        "Code comment indicates dynamic library loading inside privileged service without sandboxing.",
                        "Isolate plugin execution in separate unprivileged processes (sandboxes) and verify digital signatures before loading.",
                    );
                }

                if lower.contains("panic crosses foreign function")
                    || lower.contains("extern \"c\" fn without catch_unwind")
                    || lower.contains("panic crosses ffi")
                {
                    Self::push_finding(
                        &mut findings,
                        &mut seen,
                        "BK-AI-MEM-009",
                        &["CWE-755"],
                        "Rust/Go panic or C++ exception crosses foreign function boundary unsafely",
                        Severity::High,
                        "2.18 Native code, FFI and memory safety",
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Wrap all FFI boundary functions in catch_unwind or panic recovery to prevent unwinding into foreign frames",
                        "Code comment indicates panic or exception crossing foreign function boundary without catch_unwind.",
                        "Wrap the body of extern \"C\" functions with std::panic::catch_unwind and return error codes instead of panicking.",
                    );
                }

                if lower.contains("compiler/hardening flags removed")
                    || lower.contains("hardening flags disabled")
                    || lower.contains("-fno-stack-protector")
                {
                    Self::push_finding(
                        &mut findings,
                        &mut seen,
                        "BK-AI-MEM-010",
                        &["CWE-693"],
                        "Compiler/hardening flags removed to silence warnings or fix build",
                        Severity::High,
                        "2.18 Native code, FFI and memory safety",
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Retain all platform and compiler security hardening flags (stack protector, ASLR, DEP, FORTIFY_SOURCE)",
                        "Code comment indicates build flags disable stack protection, ASLR, or executable stack mitigations.",
                        "Enable standard compiler protections: -fstack-protector-strong, -D_FORTIFY_SOURCE=2, and non-executable stack flags.",
                    );
                }

                if lower.contains("allocator mismatch")
                    || lower.contains("unzeroed key buffer")
                    || lower.contains("leaks secret-bearing memory")
                    || lower.contains("forgotten cleanup leaks secret")
                {
                    Self::push_finding(
                        &mut findings,
                        &mut seen,
                        "BK-AI-MEM-011",
                        &["CWE-401"],
                        "Zig/C++ allocator mismatch or forgotten cleanup leaks secret-bearing memory",
                        Severity::High,
                        "2.18 Native code, FFI and memory safety",
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Use matched allocators and cryptographically zero memory containing secrets before deallocation",
                        "Code comment indicates allocator mismatch or failure to zero secret-bearing buffers before free.",
                        "Pair allocations with matching deallocators and use explicit_bzero or zeroize before deallocating keys.",
                    );
                }

                if lower.contains("binary parser trusts declared length")
                    || lower.contains("read_u32 used directly for allocation")
                    || lower.contains("integer cast without bounds")
                {
                    Self::push_finding(
                        &mut findings,
                        &mut seen,
                        "BK-AI-MEM-012",
                        &["CWE-20", "CWE-190"],
                        "Binary parser trusts declared lengths and integer casts",
                        Severity::High,
                        "2.18 Native code, FFI and memory safety",
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Cap binary-parsed lengths against strict maximum allocation limits before allocating",
                        "Code comment indicates binary parser allocates memory based on untrusted header length without bounds checking.",
                        "Enforce a maximum allowable buffer size (e.g., len <= MAX_PACKET_SIZE) before allocating memory.",
                    );
                }

                // Category 25: Mobile & Desktop comments
                if lower.contains("client bundle contains cloud key")
                    || lower.contains("embedding aws_secret_access_key")
                    || lower.contains("mobile bundle contains admin key")
                {
                    Self::push_finding(
                        &mut findings,
                        &mut seen,
                        "BK-AI-MOB-001",
                        &["CWE-798"],
                        "Client mobile/desktop bundle contains long-lived cloud API/admin keys",
                        Severity::Critical,
                        "2.25 Mobile, desktop, electron and local apps",
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Do not package administrative cloud credentials into client mobile or desktop application bundles",
                        "Code comment indicates cloud administrative credentials embedded into client bundle.",
                        "Move privileged operations to backend API services; client apps must only hold short-lived scoped tokens.",
                    );
                }

                if lower.contains("sensitive token stored in plaintext")
                    || lower.contains("userdefaults without keychain")
                    || lower.contains("sharedpreferences jwt")
                    || lower.contains("localstorage.setitem(\"auth_token\")")
                {
                    Self::push_finding(
                        &mut findings,
                        &mut seen,
                        "BK-AI-MOB-002",
                        &["CWE-922", "CWE-312"],
                        "Sensitive token stored in plaintext local preferences/file",
                        Severity::High,
                        "2.25 Mobile, desktop, electron and local apps",
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Store authentication credentials and tokens exclusively in hardware-backed secure storage (Keychain, KeyStore)",
                        "Code comment indicates sensitive authentication tokens stored unencrypted in local preferences.",
                        "Migrate sensitive credentials to OS Keychain (iOS/macOS), EncryptedSharedPreferences/KeyStore (Android), or keytar (Electron).",
                    );
                }

                if lower.contains("android exported without permission")
                    || lower.contains("exported activity without intended permission")
                {
                    Self::push_finding(
                        &mut findings,
                        &mut seen,
                        "BK-AI-MOB-003",
                        &["CWE-926", "CWE-284"],
                        "Android exported activity/service/provider reachable without intended permission",
                        Severity::High,
                        "2.25 Mobile, desktop, electron and local apps",
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Set android:exported=\"false\" or enforce signature-level android:permission on exposed components",
                        "Code comment indicates Android component exported to all applications without permission check.",
                        "Set android:exported=\"false\" for internal components or add android:permission to guard exported entry points.",
                    );
                }

                if lower.contains("deep-link accepts unsafe")
                    || lower.contains("custom protocol handler accepts unsafe")
                    || lower.contains("deep-link executes without validation")
                {
                    Self::push_finding(
                        &mut findings,
                        &mut seen,
                        "BK-AI-MOB-004",
                        &["CWE-939"],
                        "Deep-link or custom protocol handler accepts unsafe URL/command",
                        Severity::High,
                        "2.25 Mobile, desktop, electron and local apps",
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Validate deep link URLs against strict host, path, and parameter allowlists before execution",
                        "Code comment indicates deep-link or custom URI scheme handler executing arbitrary intent parameters.",
                        "Validate deep link host, scheme, and query parameters against an allowlist before taking any action.",
                    );
                }

                if lower.contains("electron renderer has node integration")
                    || lower.contains("nodeintegration: true")
                    || lower.contains("contextisolation: false")
                {
                    Self::push_finding(
                        &mut findings,
                        &mut seen,
                        "BK-AI-MOB-005",
                        &["CWE-250", "CWE-94"],
                        "Electron renderer has Node integration/unsafe context isolation policy",
                        Severity::Critical,
                        "2.25 Mobile, desktop, electron and local apps",
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Enforce nodeIntegration: false, contextIsolation: true, and sandbox: true in Electron webPreferences",
                        "Code comment indicates Electron window configuration disables context isolation or enables node integration.",
                        "Set 'nodeIntegration: false', 'contextIsolation: true', and expose only safe APIs via preload contextBridge.",
                    );
                }

                if lower.contains("electron ipc main blindly executes")
                    || lower.contains("ipcmain exec(cmd)")
                    || lower.contains("renderer-supplied command")
                {
                    Self::push_finding(
                        &mut findings,
                        &mut seen,
                        "BK-AI-MOB-006",
                        &["CWE-78"],
                        "Electron IPC main process blindly executes renderer-supplied command",
                        Severity::Critical,
                        "2.25 Mobile, desktop, electron and local apps",
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Do not accept arbitrary command strings over IPC; validate actions against a fixed strict allowlist",
                        "Code comment indicates Electron IPC handler executing renderer strings directly in shell.",
                        "Map IPC actions to fixed predefined commands with validated parameters rather than accepting raw shell command strings.",
                    );
                }

                if lower.contains("trust all certificates")
                    || lower.contains("disables hostname verification")
                    || lower.contains("rejectunauthorized: false")
                {
                    Self::push_finding(
                        &mut findings,
                        &mut seen,
                        "BK-AI-MOB-007",
                        &["CWE-295"],
                        "Mobile/desktop TLS trust all certificates or disables hostname verification",
                        Severity::Critical,
                        "2.25 Mobile, desktop, electron and local apps",
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Enforce full TLS certificate validation and hostname verification with certificate pinning",
                        "Code comment indicates TLS certificate or hostname verification is disabled in client app.",
                        "Enable standard TLS verification ('rejectUnauthorized: true') and implement certificate pinning for API endpoints.",
                    );
                }

                if lower.contains("local database contain private content accessible")
                    || lower.contains("world-readable")
                    || lower.contains("world-writable permissions")
                    || lower.contains("mode_world_readable")
                {
                    Self::push_finding(
                        &mut findings,
                        &mut seen,
                        "BK-AI-MOB-008",
                        &["CWE-922", "CWE-276"],
                        "Local database/files contain private content accessible to another user/process",
                        Severity::High,
                        "2.25 Mobile, desktop, electron and local apps",
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Create local files and databases with owner-only access permissions (0600 / MODE_PRIVATE)",
                        "Code comment indicates local files or databases created with world-readable permissions.",
                        "Set file permissions to MODE_PRIVATE (0600/0700) to restrict access strictly to the application owner.",
                    );
                }

                if lower.contains("untrusted app updates")
                    || lower.contains("executable plugins have no origin verification")
                    || lower.contains("autoupdater without signature")
                    || lower.contains("feed url over http")
                {
                    Self::push_finding(
                        &mut findings,
                        &mut seen,
                        "BK-AI-MOB-009",
                        &["CWE-494"],
                        "Untrusted app updates or executable plugins have no origin verification",
                        Severity::Critical,
                        "2.25 Mobile, desktop, electron and local apps",
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Deliver application updates over HTTPS with mandatory cryptographic signature verification",
                        "Code comment indicates application updater fetches updates over unencrypted HTTP without signature verification.",
                        "Enforce HTTPS for updater feed URLs and verify cryptographic digital signatures before applying updates.",
                    );
                }

                if lower.contains("clipboard expose secret values")
                    || lower.contains("clipboard.setstring(secrettoken)")
                    || lower.contains("missing flag_secure")
                {
                    Self::push_finding(
                        &mut findings,
                        &mut seen,
                        "BK-AI-MOB-010",
                        &["CWE-200"],
                        "Clipboard, screen capture, crash reports or notifications expose secret values",
                        Severity::High,
                        "2.25 Mobile, desktop, electron and local apps",
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Do not write sensitive authentication tokens to global clipboard or omit FLAG_SECURE on sensitive windows",
                        "Code comment indicates sensitive credentials exposed via system clipboard or insecure notifications.",
                        "Avoid copying secrets to the clipboard, mark sensitive UI with FLAG_SECURE, and sanitize notifications.",
                    );
                }

                // Category 21: AI Coding Assistant comments
                if lower.contains("tests are rewritten/weakened")
                    || lower.contains("test weakened after failure")
                    || lower.contains("test weakened after a failure")
                    || lower.contains("replacing assertions with assert true")
                {
                    Self::push_finding(
                        &mut findings,
                        &mut seen,
                        "BK-AI-AIC-004",
                        &["CWE-1059"],
                        "Tests are rewritten/weakened after a failure instead of diagnosing cause",
                        Severity::High,
                        "2.21 AI coding assistant-specific engineering traps",
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Do not weaken test oracles or assertions to bypass test failures; diagnose the root cause",
                        "Code comment indicates test assertions were deliberately weakened or replaced with trivial passes.",
                        "Retain strict test assertions and fix the underlying implementation rather than weakening the test oracle.",
                    );
                }

                // Category 22: LLM & Agent comments
                if lower.contains("agent chain allows one agent's unchecked proposal")
                    || lower.contains("unchecked proposal privileged command")
                    || lower.contains("agentb.execute(agenta.get_output())")
                {
                    Self::push_finding(
                        &mut findings,
                        &mut seen,
                        "BK-AI-LLM-019",
                        &["CWE-862"],
                        "Agent chain allows one agent's unchecked proposal to become another agent's privileged command",
                        Severity::High,
                        "2.22 LLM, RAG, autonomous agent and MCP application flaws",
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Enforce human-in-the-loop or authorization policy gates between agent proposal and privileged execution",
                        "Code comment indicates upstream agent proposals executed by privileged downstream agent without authorization.",
                        "Require human operator approval or cryptographic policy validation before executing privileged commands suggested by upstream agents.",
                    );
                }

                if lower.contains("agent continues acting after revocation")
                    || lower.contains("agent execution loop lacks cancellation")
                    || lower.contains("agent execution loop lacks abort_signal")
                    || lower.contains("missing abort_signal.is_aborted")
                {
                    Self::push_finding(
                        &mut findings,
                        &mut seen,
                        "BK-AI-LLM-021",
                        &["CWE-613"],
                        "Agent continues acting after revocation, stop request, timeout or ownership change",
                        Severity::High,
                        "2.22 LLM, RAG, autonomous agent and MCP application flaws",
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Check cancellation signal, timeout deadline, and revocation status in every agent iteration loop",
                        "Code comment indicates agent execution loop continues running without checking abort signal or token revocation.",
                        "Check 'abort_signal.is_aborted()' and verify active session authorization at each turn of the execution loop.",
                    );
                }

                continue;
            }

            // ===============================================================
            // Category 18: Native Code, FFI and Memory Safety
            // ===============================================================

            // BK-AI-MEM-004: Null/dangling pointer dereference
            if RE_MEM_004_NULL_DEREF.is_match(trimmed)
                && !RE_MEM_004_GUARD.is_match(&context_window)
            {
                Self::push_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-MEM-004",
                    &["CWE-476"],
                    "Null/dangling pointer dereference reachable from malformed input",
                    Severity::High,
                    "2.18 Native code, FFI and memory safety",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Verify pointer non-null invariants before dereference",
                    "Raw pointer dereference without null check or allocation validation can cause denial of service or arbitrary code execution.",
                    "Perform explicit null checks ('if (ptr == NULL)' or 'if (!ptr.is_null())') prior to dereferencing raw pointers.",
                );
            }

            // BK-AI-MEM-005: Stack/heap buffer copy lacks verified bounds
            if RE_MEM_005_BUFFER_COPY.is_match(trimmed)
                && !RE_MEM_005_GUARD.is_match(&context_window)
            {
                Self::push_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-MEM-005",
                    &["CWE-120"],
                    "Stack/heap buffer copy lacks verified bounds",
                    Severity::Critical,
                    "2.18 Native code, FFI and memory safety",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Enforce bounded copies using size-limited primitives or explicit bounds verification",
                    "Unbounded memory copy function (strcpy, strcat, sprintf, alloca) can overflow destination buffers.",
                    "Replace with bounded alternatives (snprintf, strlcpy, memcpy_s) and validate bounds before copying.",
                );
            }

            // BK-AI-MEM-006: `unsafe` Rust or FFI uses unchecked slice/pointer conversion
            if RE_MEM_006_SLICE_CONV.is_match(trimmed)
                && !RE_MEM_006_GUARD.is_match(&context_window)
            {
                Self::push_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-MEM-006",
                    &["CWE-119"],
                    "`unsafe` Rust or FFI uses unchecked slice/pointer conversion",
                    Severity::High,
                    "2.18 Native code, FFI and memory safety",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Validate pointer validity, non-null status, and slice length prior to raw parts reconstruction",
                    "Constructing slice or string from raw pointer and length without explicit bounds check allows out-of-bounds memory access.",
                    "Verify that pointer is non-null, aligned, and length does not exceed allocated memory range before calling slice::from_raw_parts.",
                );
            }

            // BK-AI-MEM-007: C/C++ string encoding or truncation produces security control mismatch
            if RE_MEM_007_STRNCPY_TRUNC.is_match(trimmed)
                && !RE_MEM_007_GUARD.is_match(&context_window)
            {
                Self::push_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-MEM-007",
                    &["CWE-170", "CWE-120"],
                    "C/C++ string encoding or truncation produces security control mismatch",
                    Severity::High,
                    "2.18 Native code, FFI and memory safety",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Ensure null termination after strncpy or use strlcpy/snprintf",
                    "strncpy does not guarantee NUL termination when source length equals or exceeds buffer size, causing buffer over-read.",
                    "Explicitly set dest[sizeof(dest) - 1] = '\\0' or replace with snprintf / strlcpy.",
                );
            }

            // BK-AI-MEM-008: Untrusted native decoder or plugin runs in privileged host process
            if RE_MEM_008_NATIVE_LOAD.is_match(trimmed)
                && !RE_MEM_008_GUARD.is_match(&context_window)
            {
                Self::push_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-MEM-008",
                    &["CWE-250"],
                    "Untrusted native decoder or plugin runs in privileged host process",
                    Severity::Critical,
                    "2.18 Native code, FFI and memory safety",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Isolate native decoders in sandboxed worker processes and verify cryptographic signatures",
                    "Native dynamic libraries or plugins loaded into privileged host process without sandboxing or signature verification.",
                    "Isolate plugin execution in separate unprivileged processes (sandboxes) and verify digital signatures before loading.",
                );
            }

            // BK-AI-MEM-009: Rust/Go panic or C++ exception crosses foreign function boundary unsafely
            if RE_MEM_009_FFI_PANIC.is_match(trimmed) && !RE_MEM_009_GUARD.is_match(&context_window)
            {
                Self::push_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-MEM-009",
                    &["CWE-755"],
                    "Rust/Go panic or C++ exception crosses foreign function boundary unsafely",
                    Severity::High,
                    "2.18 Native code, FFI and memory safety",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Wrap all FFI boundary functions in catch_unwind or panic recovery to prevent unwinding into foreign frames",
                    "Rust panics unwinding across extern \"C\" boundaries cause undefined behavior (abort or stack corruption).",
                    "Wrap the body of extern \"C\" functions with std::panic::catch_unwind and return error codes instead of panicking.",
                );
            }

            // BK-AI-MEM-010: Compiler/hardening flags removed to silence warnings or fix build
            if RE_MEM_010_FLAGS_REMOVED.is_match(trimmed)
                && !RE_MEM_010_GUARD.is_match(&context_window)
            {
                Self::push_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-MEM-010",
                    &["CWE-693"],
                    "Compiler/hardening flags removed to silence warnings or fix build",
                    Severity::High,
                    "2.18 Native code, FFI and memory safety",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Retain all platform and compiler security hardening flags (stack protector, ASLR, DEP, FORTIFY_SOURCE)",
                    "Build configuration explicitly disables essential security hardening flags (-fno-stack-protector, execstack, /GS-).",
                    "Enable standard compiler protections: -fstack-protector-strong, -D_FORTIFY_SOURCE=2, and non-executable stack flags.",
                );
            }

            // BK-AI-MEM-011: Zig/C++ allocator mismatch or forgotten cleanup leaks secret-bearing memory
            if RE_MEM_011_ALLOC_MISMATCH.is_match(trimmed)
                && !RE_MEM_011_GUARD.is_match(&context_window)
            {
                Self::push_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-MEM-011",
                    &["CWE-401"],
                    "Zig/C++ allocator mismatch or forgotten cleanup leaks secret-bearing memory",
                    Severity::High,
                    "2.18 Native code, FFI and memory safety",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Use matched allocators and cryptographically zero memory containing secrets before deallocation",
                    "Allocator mismatch or deallocating secret-bearing buffers without zeroing contents.",
                    "Pair allocations with matching deallocators and use explicit_bzero or zeroize before deallocating keys.",
                );
            }

            // BK-AI-MEM-012: Binary parser trusts declared lengths and integer casts
            if RE_MEM_012_UNTRUSTED_LEN.is_match(trimmed)
                && !RE_MEM_012_GUARD.is_match(&context_window)
            {
                Self::push_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-MEM-012",
                    &["CWE-20", "CWE-190"],
                    "Binary parser trusts declared lengths and integer casts",
                    Severity::High,
                    "2.18 Native code, FFI and memory safety",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Cap binary-parsed lengths against strict maximum allocation limits before allocating",
                    "Binary parser uses declared header length directly for memory allocation without upper limit check.",
                    "Enforce a maximum allowable buffer size (e.g., len <= MAX_PACKET_SIZE) before allocating memory.",
                );
            }

            // ===============================================================
            // Category 25: Mobile, Desktop, Electron and Local Apps
            // ===============================================================

            // BK-AI-MOB-001: Client mobile/desktop bundle contains long-lived cloud API/admin keys
            if RE_MOB_001_CLOUD_KEY.is_match(trimmed) && !RE_MOB_001_GUARD.is_match(&context_window)
            {
                Self::push_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-MOB-001",
                    &["CWE-798"],
                    "Client mobile/desktop bundle contains long-lived cloud API/admin keys",
                    Severity::Critical,
                    "2.25 Mobile, desktop, electron and local apps",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Do not package administrative cloud credentials into client mobile or desktop application bundles",
                    "Client application bundle contains hardcoded cloud administrative credentials.",
                    "Move privileged operations to backend API services; client apps must only hold short-lived scoped tokens.",
                );
            }

            // BK-AI-MOB-002: Sensitive token stored in plaintext local preferences/file
            if RE_MOB_002_PLAINTEXT_PREFS.is_match(trimmed)
                && !RE_MOB_002_GUARD.is_match(&context_window)
            {
                Self::push_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-MOB-002",
                    &["CWE-922", "CWE-312"],
                    "Sensitive token stored in plaintext local preferences/file",
                    Severity::High,
                    "2.25 Mobile, desktop, electron and local apps",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Store authentication credentials and tokens exclusively in hardware-backed secure storage (Keychain, KeyStore)",
                    "Sensitive token stored in unencrypted preferences or local storage instead of platform Keychain/KeyStore.",
                    "Migrate sensitive credentials to OS Keychain (iOS/macOS), EncryptedSharedPreferences/KeyStore (Android), or keytar (Electron).",
                );
            }

            // BK-AI-MOB-003: Android exported activity/service/provider reachable without intended permission
            if RE_MOB_003_ANDROID_EXPORTED.is_match(trimmed)
                && !RE_MOB_003_GUARD.is_match(&context_window)
            {
                Self::push_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-MOB-003",
                    &["CWE-926", "CWE-284"],
                    "Android exported activity/service/provider reachable without intended permission",
                    Severity::High,
                    "2.25 Mobile, desktop, electron and local apps",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Set android:exported=\"false\" or enforce signature-level android:permission on exposed components",
                    "Android component is exported to all apps without requiring a permission attribute.",
                    "Set android:exported=\"false\" for internal components or add android:permission to guard exported entry points.",
                );
            }

            // BK-AI-MOB-004: Deep-link or custom protocol handler accepts unsafe URL/command
            if RE_MOB_004_DEEP_LINK.is_match(trimmed) && !RE_MOB_004_GUARD.is_match(&context_window)
            {
                Self::push_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-MOB-004",
                    &["CWE-939"],
                    "Deep-link or custom protocol handler accepts unsafe URL/command",
                    Severity::High,
                    "2.25 Mobile, desktop, electron and local apps",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Validate deep link URLs against strict host, path, and parameter allowlists before execution",
                    "Deep-link or protocol handler passes untrusted input directly to external command or webview.",
                    "Validate deep link host, scheme, and query parameters against an allowlist before taking any action.",
                );
            }

            // BK-AI-MOB-005: Electron renderer has Node integration/unsafe context isolation policy
            if RE_MOB_005_ELECTRON_ISOLATION.is_match(trimmed)
                && !RE_MOB_005_GUARD.is_match(&context_window)
            {
                Self::push_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-MOB-005",
                    &["CWE-250", "CWE-94"],
                    "Electron renderer has Node integration/unsafe context isolation policy",
                    Severity::Critical,
                    "2.25 Mobile, desktop, electron and local apps",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Enforce nodeIntegration: false, contextIsolation: true, and sandbox: true in Electron webPreferences",
                    "Electron window enables Node integration or disables context isolation, allowing RCE from renderer.",
                    "Set 'nodeIntegration: false', 'contextIsolation: true', and expose only safe APIs via preload contextBridge.",
                );
            }

            // BK-AI-MOB-006: Electron IPC main process blindly executes renderer-supplied command
            if (trimmed.contains("ipcMain.on")
                || trimmed.contains("ipcMain.handle")
                || RE_MOB_006_IPC_EXEC.is_match(trimmed))
                && (context_window.contains("exec(")
                    || context_window.contains("spawn(")
                    || context_window.contains("execSync("))
                && !RE_MOB_006_GUARD.is_match(&context_window)
            {
                Self::push_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-MOB-006",
                    &["CWE-78"],
                    "Electron IPC main process blindly executes renderer-supplied command",
                    Severity::Critical,
                    "2.25 Mobile, desktop, electron and local apps",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Do not accept arbitrary command strings over IPC; validate actions against a fixed strict allowlist",
                    "Electron IPC handler in main process executes shell commands directly from renderer messages.",
                    "Map IPC actions to fixed predefined commands with validated parameters rather than accepting raw shell command strings.",
                );
            }

            // BK-AI-MOB-007: Mobile/desktop TLS trust all certificates or disables hostname verification
            if RE_MOB_007_TLS_INSECURE.is_match(trimmed)
                && !RE_MOB_007_GUARD.is_match(&context_window)
            {
                Self::push_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-MOB-007",
                    &["CWE-295"],
                    "Mobile/desktop TLS trust all certificates or disables hostname verification",
                    Severity::Critical,
                    "2.25 Mobile, desktop, electron and local apps",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Enforce full TLS certificate validation and hostname verification with certificate pinning",
                    "TLS certificate or hostname verification is disabled, exposing client traffic to MITM attacks.",
                    "Enable standard TLS verification ('rejectUnauthorized: true') and implement certificate pinning for API endpoints.",
                );
            }

            // BK-AI-MOB-008: Local database/files contain private content accessible to another user/process
            if RE_MOB_008_WORLD_ACCESSIBLE.is_match(trimmed)
                && !RE_MOB_008_GUARD.is_match(&context_window)
            {
                Self::push_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-MOB-008",
                    &["CWE-922", "CWE-276"],
                    "Local database/files contain private content accessible to another user/process",
                    Severity::High,
                    "2.25 Mobile, desktop, electron and local apps",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Create local files and databases with owner-only access permissions (0600 / MODE_PRIVATE)",
                    "File or database created with world-readable or world-writable permissions, exposing data to other local processes.",
                    "Set file permissions to MODE_PRIVATE (0600/0700) to restrict access strictly to the application owner.",
                );
            }

            // BK-AI-MOB-009: Untrusted app updates or executable plugins have no origin verification
            if (trimmed.contains("autoUpdater.setFeedURL")
                || trimmed.contains("updater.setUpdateUrl")
                || RE_MOB_009_UNTRUSTED_UPDATES.is_match(trimmed))
                && (context_window.contains("http://")
                    || trimmed.to_lowercase().contains("untrusted app updates"))
                && !RE_MOB_009_GUARD.is_match(&context_window)
            {
                Self::push_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-MOB-009",
                    &["CWE-494"],
                    "Untrusted app updates or executable plugins have no origin verification",
                    Severity::Critical,
                    "2.25 Mobile, desktop, electron and local apps",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Deliver application updates over HTTPS with mandatory cryptographic signature verification",
                    "App updates are fetched over insecure HTTP or without signature verification.",
                    "Enforce HTTPS for updater feed URLs and verify cryptographic digital signatures before applying updates.",
                );
            }

            // BK-AI-MOB-010: Clipboard, screen capture, crash reports or notifications expose secret values
            if RE_MOB_010_CLIPBOARD_SECRET.is_match(trimmed)
                && !RE_MOB_010_GUARD.is_match(&context_window)
            {
                Self::push_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-MOB-010",
                    &["CWE-200"],
                    "Clipboard, screen capture, crash reports or notifications expose secret values",
                    Severity::High,
                    "2.25 Mobile, desktop, electron and local apps",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Do not write sensitive authentication tokens to global clipboard or omit FLAG_SECURE on sensitive windows",
                    "Sensitive token or credential written to shared system clipboard or cleartext notification.",
                    "Avoid copying secrets to the clipboard, mark sensitive UI with FLAG_SECURE, and sanitize notifications.",
                );
            }

            // ===============================================================
            // Category 21: AI Coding Assistant-Specific Traps
            // ===============================================================

            // BK-AI-AIC-004: Tests rewritten/weakened after failure
            if RE_AIC_004_WEAKENED_TESTS.is_match(trimmed)
                && !RE_AIC_004_GUARD.is_match(&context_window)
            {
                Self::push_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-AIC-004",
                    &["CWE-1059"],
                    "Tests are rewritten/weakened after a failure instead of diagnosing cause",
                    Severity::High,
                    "2.21 AI coding assistant-specific engineering traps",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Do not weaken test oracles or assertions to bypass test failures; diagnose the root cause",
                    "Test assertion was weakened or replaced with a trivial tautology (assert True) to bypass a failure.",
                    "Retain strict test assertions and fix the underlying implementation rather than weakening the test oracle.",
                );
            }

            // ===============================================================
            // Category 22: LLM, RAG, Autonomous Agent and MCP Application Flaws
            // ===============================================================

            // BK-AI-LLM-019: Agent chain allows unchecked proposal to become privileged command
            if RE_LLM_019_AGENT_CHAIN.is_match(trimmed)
                && !RE_LLM_019_GUARD.is_match(&context_window)
            {
                Self::push_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-LLM-019",
                    &["CWE-862"],
                    "Agent chain allows one agent's unchecked proposal to become another agent's privileged command",
                    Severity::High,
                    "2.22 LLM, RAG, autonomous agent and MCP application flaws",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Enforce human-in-the-loop or authorization policy gates between agent proposal and privileged execution",
                    "Downstream privileged agent directly executes unchecked proposals from upstream agent without authorization gate.",
                    "Require human operator approval or cryptographic policy validation before executing privileged commands suggested by upstream agents.",
                );
            }

            // BK-AI-LLM-021: Agent continues acting after revocation, stop request, timeout
            if (trimmed.starts_with("while True:")
                || trimmed.starts_with("while true:")
                || trimmed.starts_with("while (true)")
                || trimmed.starts_with("while (!done)"))
                && (context_window.contains(".step(")
                    || context_window.contains(".run_turn(")
                    || context_window.contains(".execute_next("))
                && !RE_LLM_021_GUARD.is_match(&context_window)
            {
                Self::push_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-LLM-021",
                    &["CWE-613"],
                    "Agent continues acting after revocation, stop request, timeout or ownership change",
                    Severity::High,
                    "2.22 LLM, RAG, autonomous agent and MCP application flaws",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Check cancellation signal, timeout deadline, and revocation status in every agent iteration loop",
                    "Agent execution loop does not check abort signals or token revocation between execution turns.",
                    "Check 'abort_signal.is_aborted()' and verify active session authorization at each turn of the execution loop.",
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
        cwes: &[&str],
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
        finding.detector_id = "native-desktop".to_string();
        finding.detector_version = "1.0.0".to_string();
        finding.category = category.to_string();
        finding.affectedness = Affectedness::ConfirmedAffected;
        finding.reachability = Reachability::PotentiallyReachable;
        finding.confidence = Confidence::High;
        finding.evidence_certainty = EvidenceCertainty::StronglySupported;
        let mut advisory_ids: Vec<String> = cwes.iter().map(|c| c.to_string()).collect();
        advisory_ids.push(rule_id.to_string());
        finding.advisory_ids = advisory_ids;
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
