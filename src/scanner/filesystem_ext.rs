#![allow(dead_code, clippy::collapsible_if)]

use crate::types::*;
use regex::Regex;
use std::collections::HashSet;
use std::path::Path;
use std::sync::LazyLock;

// ----------------------------------------------------------------------------
// Category 7: Filesystem, Uploads, Archives and Path Traversal Regular Expressions
// ----------------------------------------------------------------------------

// 1. BK-AI-FIL-003: Zip/Tar extraction writes outside destination (Zip Slip)
static RE_FIL_003_ZIP_SLIP_ENTRY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:fs\.(?:createWriteStream|writeFileSync|writeFile)|path\.(?:join|resolve)|zip\.extractEntryTo)\s*\([^)]*\b(?:entry|header|item|member)\.(?:entryName|name|path)\b"#).unwrap()
});

static RE_FIL_003_EXTRACTALL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(?:tarfile|tar|zip_file|zipfile|zf|archive)\.extractall\s*\("#).unwrap()
});

static RE_FIL_003_SAFE_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:startsWith|\.indexOf\s*\([^)]*\)\s*===?\s*0|commonpath|path\.relative|is_safe_path|sanitize_path|filter\s*=\s*['"](?:data|tar)['"]|\.includes\s*\(\s*['"]\.\.['"]\s*\)|resolve_path)"#).unwrap()
});

// 2. BK-AI-FIL-004: Unsafe archive decompression creates resource exhaustion (zip bomb)
static RE_FIL_004_UNBOUNDED_PIPE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\.pipe\s*\(\s*zlib\.(?:createGunzip|createInflate|createUnzip)\s*\([^)]*\)\s*\)"#).unwrap()
});

static RE_FIL_004_SYNC_DECOMPRESS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:zlib\.(?:gunzipSync|inflateSync|unzipSync)|(?:gzip|zlib|bz2)\.decompress)\s*\(\s*(?:req\.|request\.|data|payload|content|buf|file|stream)\b"#).unwrap()
});

static RE_FIL_004_SAFE_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:maxSize|max_size|MAX_SIZE|MAX_BYTES|maxOutputLength|max_length|byteCount|totalSize|sizeLimit|threshold|MAX_FILE_SIZE|uncompressed_size)"#).unwrap()
});

// 3. BK-AI-FIL-005: Uploaded file extension trusted as content type or executable disposition
static RE_FIL_005_EXT_TRUST: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:(?:ALLOWED_EXTENSIONS|allowedExts?|validExtensions)\.(?:includes|contains)\s*\([^)]*(?:ext|extension|file\.originalname)\)|(?:file|upload|req\.file)\.originalname\.(?:split\(['"]\.['"]\)|endsWith|includes)\b|mime\.(?:lookup|getType)\s*\(\s*(?:req\.file|file)\.originalname\s*\)|mimetypes\.guess_type\s*\(\s*(?:uploaded_file|file)\.filename\s*\))"#).unwrap()
});

static RE_FIL_005_SAFE_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:file-type|fileTypeFromBuffer|fileTypeFromFile|python-magic|magic\.from_buffer|magic_bytes|validate_magic|magicNumber|sniff)"#).unwrap()
});

// 4. BK-AI-FIL-006: User upload stored in executable/public directory with unsafe permissions
static RE_FIL_006_PUBLIC_DEST: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:destination\s*:\s*['"](?:\./)?(?:public|static|wwwroot|html|dist|assets|webroot)(?:/.*)?['"]|destination\s*:\s*path\.join\([^)]*['"](?:public|static|wwwroot|html)['"]|cb\s*\(\s*null\s*,\s*['"](?:\./)?(?:public|static|wwwroot|html|assets)(?:/.*)?['"]\s*\))"#).unwrap()
});

static RE_FIL_006_UNSAFE_PERMS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:fs\.(?:chmod|chmodSync)|os\.chmod)\s*\([^,]+,\s*(?:0o?777|0777|511)\s*\)"#).unwrap()
});

static RE_FIL_006_SAFE_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:0o?600|0o?644|private_uploads|s3|cloudStorage|storage/private)"#).unwrap()
});

// 5. BK-AI-FIL-007: Filename allows path separators, control chars or Unicode normalization escape
static RE_FIL_007_RAW_FILENAME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:path\.(?:join|resolve)|os\.path\.join)\s*\([^,]+,\s*(?:req\.(?:query|body|params)\.[a-zA-Z0-9_]*filename|req\.file\.originalname|file\.originalname|request\.(?:args|form|values|FILES)\[['"][a-zA-Z0-9_]*filename['"]\])\s*\)"#).unwrap()
});

static RE_FIL_007_WRITE_RAW_NAME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)fs\.(?:writeFileSync|writeFile|createWriteStream)\s*\(\s*path\.(?:join|resolve)\([^)]*(?:req\.file\.originalname|req\.(?:query|body)\.filename)\)"#).unwrap()
});

static RE_FIL_007_SAFE_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:basename|secure_filename|sanitize_filename|replace\s*\(\s*\/\[\^|\.includes\s*\(\s*['"]\.\.['"]\s*\)|check_traversal)"#).unwrap()
});

// 6. BK-AI-FIL-009: Insecure temporary/backup files persist secrets or become publicly readable
static RE_FIL_009_MKTEMP: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\btempfile\.mktemp\s*\("#).unwrap()
});

static RE_FIL_009_TMP_SECRET: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)['"]/tmp/[a-zA-Z0-9_\-\.]*(?:backup|secret|key|token|cred|dump|passwd|shadow|id_rsa)[a-zA-Z0-9_\-\.]*['"]"#).unwrap()
});

static RE_FIL_009_FS_TMP_SECRET: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)fs\.(?:writeFileSync|writeFile)\s*\(\s*['"]/tmp/(?:backup|key|secret|dump)"#).unwrap()
});

static RE_FIL_009_BAK_FILE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\bfilename\s*\+\s*['"]\.bak['"]|['"][^'"]*\.(?:bak|backup)['"]\s*,\s*(?:data|content|secret))"#).unwrap()
});

static RE_FIL_009_SAFE_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:NamedTemporaryFile|TemporaryDirectory|mkdtemp|randomBytes|0o?600)"#).unwrap()
});

// 7. BK-AI-FIL-010: Unsafe file overwrite, truncation or deletion from arbitrary user-supplied path
static RE_FIL_010_UNSAFE_UNLINK: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:fs\.(?:unlink|unlinkSync|rm|rmSync|rmdir|rmdirSync|truncate|truncateSync))\s*\(\s*(?:req\.(?:query|body|params)\.[a-zA-Z0-9_]+|userPath|targetPath)\b"#).unwrap()
});

static RE_FIL_010_OS_REMOVE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:os\.(?:remove|unlink|rmdir)|shutil\.rmtree)\s*\(\s*(?:request\.(?:args|json|form)\[['"][a-zA-Z0-9_]+['"]\]|user_path|file_path)\b"#).unwrap()
});

static RE_FIL_010_SAFE_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:allowedFiles|allowlist|isPathInside|startsWith\s*\(\s*(?:SAFE_DIR|BASE_DIR|STORAGE_DIR)|resolveSafePath)"#).unwrap()
});

// 8. BK-AI-FIL-011: TOCTOU between file validation and opening/replacement
static RE_FIL_011_TOCTOU_EXISTS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is)if\s*\(\s*(?:fs\.)?existsSync\s*\(\s*([a-zA-Z0-9_]+)\s*\)\s*\)\s*\{([^}]{1,300})"#).unwrap()
});

static RE_FIL_011_TOCTOU_ACCESS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is)(?:fs\.)?access\s*\(\s*([a-zA-Z0-9_]+)[^)]*\)\s*,\s*(?:async\s*)?\([^)]*\)\s*=>\s*\{([^}]{1,300})"#).unwrap()
});

static RE_FIL_011_TOCTOU_PY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is)if\s+os\.path\.exists\s*\(\s*([a-zA-Z0-9_]+)\s*\)\s*:\s*([^\n\r]+(?:\r?\n[ \t]+[^\n\r]+){1,5})"#).unwrap()
});

static RE_FIL_011_SAFE_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:O_EXCL|['"]wx['"])"#).unwrap()
});

// 9. BK-AI-FIL-012: Files served/downloaded without proper per-object authorization
static RE_FIL_012_DOWNLOAD_UNAUTH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is)(?:app|router)\.(?:get|post)\s*\(\s*['"][^'"]*(?:download|file|files|doc|document)[^'"]*['"]\s*,\s*(?:async\s*)?(?:\([^)]*\)|function\s*\([^)]*\))\s*=>?\s*\{[^}]*(?:res\.download|res\.sendFile|send_file)\s*\([^)]*req\.(?:params|query|body)"#).unwrap()
});

static RE_FIL_012_LINE_DOWNLOAD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)res\.(?:download|sendFile)\s*\(\s*path\.(?:join|resolve)\([^)]*req\.(?:params|query)\.[a-zA-Z0-9_]+"#).unwrap()
});

static RE_FIL_012_SAFE_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:req\.user|file\.ownerId|user\.id|userId|checkPermission|requireAuth|hasAccess|isAuthorized|authenticate)"#).unwrap()
});

// 10. BK-AI-FIL-013: Uploaded SVG/HTML/PDF rendered inline without appropriate isolation
static RE_FIL_013_SVG_HEADER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)res\.setHeader\s*\(\s*['"]Content-Type['"]\s*,\s*['"](?:image/svg\+xml|text/html)['"]\s*\)"#).unwrap()
});

static RE_FIL_013_SVG_TYPE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)res\.type\s*\(\s*['"](?:svg|image/svg\+xml|html)['"]\s*\)\.send\s*\("#).unwrap()
});

static RE_FIL_013_SEND_FILE_SVG: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)send_file\s*\([^)]*\.svg['"][^)]*\)"#).unwrap()
});

static RE_FIL_013_SAFE_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:Content-Disposition['"]\s*,\s*['"]attachment|as_attachment\s*=\s*True|Content-Security-Policy['"]\s*,\s*['"]default-src\s+'none'|DOMPurify\.sanitize)"#).unwrap()
});

// 11. BK-AI-FIL-014: File parser accepts unbounded content/recursive structure
static RE_FIL_014_PARSER_UNBOUNDED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:xml2js\.Parser\s*\(\s*\{[^}]*noent\s*:\s*true|libxml(?:js)?\.parseXml\s*\([^)]*\{[^}]*(?:noent|dtdload)\s*:\s*true|yaml\.load\s*\([^)]*\{[^}]*maxAliases\s*:\s*(?:-1|0|Infinity))"#).unwrap()
});

static RE_FIL_014_PY_XML_UNGUARDED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:xml\.etree\.ElementTree|xml\.dom\.minidom|xml\.sax)\.parse\s*\("#).unwrap()
});

static RE_FIL_014_SAFE_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:defusedxml|noent\s*:\s*false|disallow-doctype|resolve_entities\s*=\s*False|maxDepth|maxAliases\s*:\s*[1-9]\d*|safe_load)"#).unwrap()
});

// ----------------------------------------------------------------------------
// Category 1: Injection and Interpreter Boundaries Regular Expressions
// ----------------------------------------------------------------------------

// 12. BK-AI-INJ-002: Dynamic SQL identifiers, ordering, or table names without a finite allowlist
static RE_INJ_002_ORDER_BY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:SELECT|FROM|UPDATE|DELETE|JOIN)\s+[^;]*\b(?:ORDER\s+BY|GROUP\s+BY)\s+(?:\$\{[^}]*(?:req\.|params|query|sort|order)|['"]\s*\+\s*(?:req\.|query|sort|order|col)|f["'][^"']*\{[^}]*(?:sort|order|col|param))"#).unwrap()
});

static RE_INJ_002_KNEX_ORDER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\.(?:orderBy|groupBy)\s*\(\s*(?:req\.(?:query|body|params)\.[a-zA-Z0-9_]+|sort(?:By)?|col(?:umn)?)\s*\)"#).unwrap()
});

static RE_INJ_002_DYNAMIC_TABLE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:FROM|JOIN|TABLE)\s+(?:\$\{[^}]*(?:req\.|params|table)|['"]\s*\+\s*(?:req\.|table|user_input))"#).unwrap()
});

static RE_INJ_002_SAFE_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:ALLOWED_COLUMNS|ALLOWED_SORT|ALLOWLIST|validColumns|ALLOWED_TABLES|\.includes\s*\(\s*(?:sort|order|table)|\.contains\s*\(\s*(?:sort|order|table)|\.has\s*\(\s*(?:sort|order|table)|match\s+(?:sort|order|table))"#).unwrap()
});

// 13. BK-AI-INJ-004: Command-line argument injection despite use of a subprocess argument array
static RE_INJ_004_NODE_EXECFILE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:execFile|spawn)\s*\(\s*['"](?:git|ssh|tar|curl|find|rsync|hg|svn)['"]\s*,\s*\[[^\]]*(?:req\.(?:query|body|params)|userInput|branch|repoUrl|target|flag)\b"#).unwrap()
});

static RE_INJ_004_PY_SUBPROCESS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)subprocess\.(?:run|Popen|check_output|call)\s*\(\s*\[['"](?:git|ssh|tar|curl|find|rsync)['"]\s*,[^\]]*(?:request\.(?:args|json|form)|user_[a-zA-Z0-9_]+|user[A-Z0-9_][a-zA-Z0-9_]*|sys\.argv)\b"#).unwrap()
});

static RE_INJ_004_SAFE_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:['"]--['"]|\.startsWith\s*\(\s*['"]-['"]\s*\)|!/^-/|check_flag|sanitize_arg)"#).unwrap()
});

// 14. BK-AI-INJ-005: OS command execution via helper/wrapper/library omitted from basic grep rules
static RE_INJ_005_CHILD_PROCESS_EXEC: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:child_process\.)?(?:exec|execSync)\s*\(\s*(?:`[^`]*\$\{[^}]+\}|f["'][^"']*\{[^}]+\}|['"][^'"]*['"]\s*\+\s*[a-zA-Z0-9_]+)"#).unwrap()
});

static RE_INJ_005_OS_SYSTEM: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:os\.system|os\.popen)\s*\(\s*(?:f["'][^"']*\{|['"][^'"]*['"]\s*\+|cmd|command)\b"#).unwrap()
});

static RE_INJ_005_SUBPROCESS_SHELL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)subprocess\.(?:run|Popen|call|check_call|check_output)\s*\([^)]*shell\s*=\s*True"#).unwrap()
});

static RE_INJ_005_SHELLJS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)shell\.(?:exec)\s*\(\s*(?:`[^`]*\$\{|f["'][^"']*\{|cmd|command)\b"#).unwrap()
});

// 15. BK-AI-INJ-008: Server-side template expressions compiled from user data
static RE_INJ_008_JINJA: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)jinja2\.Template\s*\(\s*(?:request\.|req\.|user_input|tpl|template|custom_template)\b"#).unwrap()
});

static RE_INJ_008_ENV_STRING: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)Environment\s*\([^)]*\)\.from_string\s*\(\s*(?:request\.|req\.|user_input|tpl|template)\b"#).unwrap()
});

static RE_INJ_008_JS_COMPILE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:ejs\.render|Handlebars\.compile|_\.template|nunjucks\.renderString)\s*\(\s*(?:req\.(?:body|query|params)|request\.|user_input|template_str|tpl)\b"#).unwrap()
});

// 16. BK-AI-INJ-009: Template escape bypass (`safe`, raw output) applied to untrusted values
static RE_INJ_009_SAFE_PIPE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\{\{\s*(?:req\.|request\.|user|input|comment|bio|param|msg|content)[^}|]*\|\s*(?:safe|raw)\s*\}\}"#).unwrap()
});

static RE_INJ_009_MARKUP_CALL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:markupsafe\.)?Markup\s*\(\s*(?:req\.|request\.|user|f["']|["'].*\+)"#).unwrap()
});

static RE_INJ_009_MARK_SAFE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)mark_safe\s*\(\s*(?:req\.|request\.|user|f["']|["'].*\+)"#).unwrap()
});

static RE_INJ_009_BLADE_RAW: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\{!!\s*\$(?:req|request|user|input|comment|bio|msg)[^!]*!!\}"#).unwrap()
});

static RE_INJ_009_EJS_RAW: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"<%-\s*(?:req\.|request\.|user|input|comment|bio)[^%]*%>"#).unwrap()
});

// 17. BK-AI-INJ-010: XPath/XQuery expression assembled from inputs
static RE_INJ_010_XPATH_CONCAT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:xpath\.select|doc\.xpath|root\.xpath|xpath\.evaluate)\s*\(\s*(?:`[^`]*//[^`]*\$\{[^}]+\}|['"][^'"]*//[^'"]*['"]\s*\+\s*(?:req\.|request\.|user|input|name|id)|f["'].*?//.*?\{[^}]+\})"#).unwrap()
});

static RE_INJ_010_SAFE_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:variables\s*:|parameter_map|variable_resolver|xpath_params)"#).unwrap()
});

// 18. BK-AI-INJ-011: LDAP filter/DN assembled without context-specific escaping
static RE_INJ_011_LDAP_SEARCH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:client\.search|conn\.search|ldapClient\.search)\s*\([^)]*filter\s*:\s*(?:`[^`]*\([&|!]?\(?[a-zA-Z0-9_]+=\$\{[^}]+\}\)|['"][^'"]*\([&|!]?\(?[a-zA-Z0-9_]+=)"#).unwrap()
});

static RE_INJ_011_FILTER_VAR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:search_filter|ldap_filter|filter)\s*[:=]\s*(?:`[^`]*\([&|!]?\(?[a-zA-Z0-9_]+=\$\{[^}]+\}\)|f["'][^"']*\([&|!]?\(?[a-zA-Z0-9_]+=\{[^}]+\}\)|['"][^'']*\([&|!]?\(?[a-zA-Z0-9_]+=)"#).unwrap()
});

static RE_INJ_011_LDAP_QUERY_ARG: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)client\.search\s*\(\s*(?:`[^`]*\([&|!]?\(?[a-zA-Z0-9_]+=\$\{|['"][^'"]*\([&|!]?\(?[a-zA-Z0-9_]+=)"#).unwrap()
});

static RE_INJ_011_SAFE_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:escapeLDAPFilter|escape_filter_chars|parseFilter|escape_dn_chars)"#).unwrap()
});

// 19. BK-AI-INJ-012: NoSQL query/operator injection from user-controlled objects
static RE_INJ_012_NOSQL_QUERY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:[A-Z][a-zA-Z0-9_]*|db\.[a-zA-Z0-9_]+)\.(?:find|findOne|countDocuments|update|updateOne|deleteOne)\s*\(\s*\{[^}]*\b(?:username|password|email|token|user_id|id)\s*:\s*(?:req\.(?:body|query|params)\.[a-zA-Z0-9_]+)\b"#).unwrap()
});

static RE_INJ_012_COLLECTION_QUERY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)collection\.(?:find|find_one)\s*\(\s*\{[^}]*(?:username|password|email)\s*:\s*(?:request\.(?:json|args|form)\[['"][a-zA-Z0-9_]+['"]\])"#).unwrap()
});

static RE_INJ_012_SAFE_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:typeof\s+req\.(?:body|query)\.[a-zA-Z0-9_]+\s*===?\s*['"]string['"]|String\s*\(\s*req\.(?:body|query)|mongo-sanitize|sanitize\s*\(\s*req\.body|z\.string\(\))"#).unwrap()
});

// 20. BK-AI-INJ-013: CRLF injection into HTTP response headers or logs
static RE_INJ_013_SET_HEADER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:res|response)\.(?:setHeader|header|append)\s*\(\s*['"][a-zA-Z0-9_\-]+['"]\s*,\s*(?:req\.(?:query|body|params|headers)\.[a-zA-Z0-9_]+|userInput|headerVal)\b"#).unwrap()
});

static RE_INJ_013_HEADERS_ASSIGN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:response|res)\.headers\[['"][a-zA-Z0-9_\-]+['"]\]\s*=\s*(?:request\.(?:args|form|headers)|req\.(?:query|body))\b"#).unwrap()
});

static RE_INJ_013_LOG_CONCAT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)logger\.(?:info|warn|error|debug)\s*\(\s*(?:['"][^'"]*['"]\s*\+\s*req\.(?:query|body|params)|`[^`]*\$\{[^}]*req\.(?:query|body|params))"#).unwrap()
});

static RE_INJ_013_SAFE_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\.replace\s*\(\s*/[\\r\\n|\[\\r\\n\]]+/[gims]*|\.strip\s*\(\s*['"][\\r\\n]+['"]\s*\)|sanitizeHeader|encodeURIComponent)"#).unwrap()
});

// 21. BK-AI-INJ-016: Trusting generic `sanitize()` or `escape()` without checking target context
static RE_INJ_016_SCRIPT_SANITIZE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is)<script\b[^>]*>[^<]*(?:escape|sanitize|sanitizeHtml)\s*\([^)]*\)[^<]*</script>"#).unwrap()
});

static RE_INJ_016_SQL_SANITIZE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:SELECT|INSERT|UPDATE|DELETE)\s+[^;]*\+\s*(?:sanitize|escape|validator\.escape)\s*\("#).unwrap()
});

static RE_INJ_016_SHELL_SANITIZE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:(?:exec|execSync|system|spawn)\s*\([^)]*|(?:cmd|command|shell_cmd)\s*=\s*['"][^'"]*['"]\s*)\+\s*(?:sanitize|escape|validator\.escape)\s*\("#).unwrap()
});

static RE_INJ_016_HREF_ESCAPE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)href=['"]?\$\{\s*(?:escape|validator\.escape)\s*\([^)]*\)\s*\}['"]?"#).unwrap()
});

static RE_INJ_016_SAFE_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:JSON\.stringify|encodeURIComponent|\$[1-9]|\?|execFile)"#).unwrap()
});

// ----------------------------------------------------------------------------
// FilesystemExtScanner
// ----------------------------------------------------------------------------

pub struct FilesystemExtScanner;

impl FilesystemExtScanner {
    /// Scans source code content for Category 7 (Filesystem & Archives) and remaining
    /// Category 1 (Injection) vulnerability rules:
    ///
    /// Filesystem Rules (Category 7):
    /// - BK-AI-FIL-003 (CWE-22): Zip/Tar extraction writes outside destination (Zip Slip)
    /// - BK-AI-FIL-004 (CWE-400): Unsafe archive decompression / zip bomb
    /// - BK-AI-FIL-005 (CWE-434): Uploaded file extension trusted as content type or executable disposition
    /// - BK-AI-FIL-006 (CWE-434): User upload stored in executable/public directory or with 0777 permissions
    /// - BK-AI-FIL-007 (CWE-22): Filename allows path separators (`../`, `..\\`) or control characters
    /// - BK-AI-FIL-009 (CWE-552): Insecure temporary/backup files (`/tmp/backup.key`, `tempfile.mktemp()`)
    /// - BK-AI-FIL-010 (CWE-73): Unsafe file overwrite or deletion from arbitrary user-supplied path
    /// - BK-AI-FIL-011 (CWE-367): TOCTOU between file validation and opening/replacement
    /// - BK-AI-FIL-012 (CWE-639): Files served/downloaded without proper authorization check
    /// - BK-AI-FIL-013 (CWE-79): Uploaded SVG/HTML rendered inline without `Content-Disposition: attachment` or CSP
    /// - BK-AI-FIL-014 (CWE-400): File parser accepts unbounded content / recursive structure
    ///
    /// Injection Rules (Category 1):
    /// - BK-AI-INJ-002 (CWE-89): Dynamic SQL identifiers, ordering without allowlist
    /// - BK-AI-INJ-004 (CWE-88): Command-line argument injection despite subprocess array
    /// - BK-AI-INJ-005 (CWE-78): OS command execution via helper/wrapper/library
    /// - BK-AI-INJ-008 (CWE-1336): Server-side template expressions compiled from user data
    /// - BK-AI-INJ-009 (CWE-79): Template escape bypass (`| safe`, `Markup()`, `raw` applied to untrusted values)
    /// - BK-AI-INJ-010 (CWE-643): XPath/XQuery expression assembled from inputs without parameterization
    /// - BK-AI-INJ-011 (CWE-90): LDAP filter/DN assembled without escaping
    /// - BK-AI-INJ-012 (CWE-943): NoSQL query/operator injection from user objects
    /// - BK-AI-INJ-013 (CWE-113): CRLF injection into HTTP response headers or logs
    /// - BK-AI-INJ-016 (CWE-116): Trusting generic `sanitize()` or `escape()` without checking target context
    pub fn scan_source(path: &Path, content: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut seen = HashSet::new();

        let target_kind = match path.extension().and_then(|ext| ext.to_str()) {
            Some("js" | "mjs" | "cjs" | "ts" | "tsx" | "jsx") => TargetKind::NodeSourceFile,
            _ => TargetKind::GenericSourceFile,
        };

        let file_tag = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("source");

        let lines: Vec<&str> = content.lines().collect();

        let byte_to_line = |byte_offset: usize| -> usize {
            content[..byte_offset].bytes().filter(|&b| b == b'\n').count() + 1
        };

        // File-level contextual indicators
        let has_magic_guard = content.contains("file-type")
            || content.contains("fileTypeFromBuffer")
            || content.contains("fileTypeFromFile")
            || content.contains("python-magic")
            || content.contains("magic.from_buffer")
            || content.contains("magic_bytes")
            || content.contains("validate_magic");

        let has_defusedxml = content.contains("defusedxml");
        let has_nosql_sanitize = content.contains("mongo-sanitize") || content.contains("mongoSanitize");
        let has_auth_guard = content.contains("requireAuth")
            || content.contains("authenticate")
            || content.contains("checkPermission")
            || content.contains("req.user")
            || content.contains("current_user");

        let has_svg_disposition_guard = content.contains("Content-Disposition")
            || content.contains("attachment")
            || content.contains("as_attachment=True")
            || content.contains("default-src 'none'")
            || content.contains("DOMPurify.sanitize");

        let has_zip_guard = content.contains("startsWith")
            || content.contains("is_safe_path")
            || content.contains("commonpath")
            || content.contains("path.relative");

        let has_sql_allowlist_guard = content.contains("ALLOWED_COLUMNS")
            || content.contains("ALLOWED_SORT")
            || content.contains("ALLOWLIST")
            || content.contains("validColumns")
            || content.contains("ALLOWED_TABLES")
            || content.contains("allowedColumns");

        let has_ldap_escape_guard = content.contains("escapeLDAPFilter")
            || content.contains("escape_filter_chars")
            || content.contains("parseFilter")
            || content.contains("escape_dn_chars");

        // --------------------------------------------------------------------
        // Pass 1: Line-by-Line Surface Analysis
        // --------------------------------------------------------------------
        for (idx, line) in lines.iter().enumerate() {
            let line_no = idx + 1;
            let trimmed = line.trim();

            if trimmed.is_empty()
                || trimmed.starts_with("//")
                || trimmed.starts_with('#')
                || trimmed.starts_with('*')
            {
                continue;
            }

            // 1. BK-AI-FIL-003: Zip/Tar extraction writes outside destination (Zip Slip)
            let is_extractall_vuln = RE_FIL_003_EXTRACTALL.is_match(trimmed) && !RE_FIL_003_SAFE_GUARD.is_match(trimmed);
            let is_zip_slip_entry_vuln = RE_FIL_003_ZIP_SLIP_ENTRY.is_match(trimmed)
                && !RE_FIL_003_SAFE_GUARD.is_match(trimmed)
                && !has_zip_guard;
            if is_extractall_vuln || is_zip_slip_entry_vuln {
                Self::record_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-FIL-003",
                    "CWE-22",
                    "Zip/Tar Archive Extraction Path Traversal (Zip Slip)",
                    Severity::Critical,
                    &target_kind,
                    path,
                    file_tag,
                    line_no,
                    trimmed,
                    "Verify extracted file paths reside strictly within destination boundary before writing",
                    format!(
                        "Archive extraction at line {} does not verify entry path boundaries. Malicious archives containing '../' can overwrite arbitrary files.",
                        line_no
                    ),
                    "Restore invariant: archive members independently constrained",
                );
            }

            // 2. BK-AI-FIL-004: Unsafe archive decompression creates resource exhaustion (zip bomb)
            if (RE_FIL_004_UNBOUNDED_PIPE.is_match(trimmed) || RE_FIL_004_SYNC_DECOMPRESS.is_match(trimmed))
                && !RE_FIL_004_SAFE_GUARD.is_match(trimmed)
            {
                Self::record_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-FIL-004",
                    "CWE-400",
                    "Unsafe Archive Decompression Resource Exhaustion (Zip Bomb)",
                    Severity::High,
                    &target_kind,
                    path,
                    file_tag,
                    line_no,
                    trimmed,
                    "Enforce strict decompression size limits, maximum uncompressed byte quotas, and entry count limits",
                    format!(
                        "Archive or stream decompression at line {} lacks decompression quotas or size thresholds. Decompressing recursive archives can exhaust disk or memory.",
                        line_no
                    ),
                    "Restore invariant: decompressed size/item/time limits enforced",
                );
            }

            // 3. BK-AI-FIL-005: Uploaded file extension trusted as content type or executable disposition
            if RE_FIL_005_EXT_TRUST.is_match(trimmed)
                && !RE_FIL_005_SAFE_GUARD.is_match(trimmed)
                && !has_magic_guard
            {
                Self::record_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-FIL-005",
                    "CWE-434",
                    "Uploaded File Extension Trusted as Content Type or Executable Disposition",
                    Severity::High,
                    &target_kind,
                    path,
                    file_tag,
                    line_no,
                    trimmed,
                    "Validate uploaded file contents using magic byte inspection (e.g. file-type) rather than client extensions",
                    format!(
                        "File upload handling at line {} trusts user-supplied extension or MIME type without inspecting file content magic bytes.",
                        line_no
                    ),
                    "Restore invariant: content/magic/storage policy validated",
                );
            }

            // 4. BK-AI-FIL-006: User upload stored in executable/public directory with unsafe permissions
            if (RE_FIL_006_PUBLIC_DEST.is_match(trimmed) || RE_FIL_006_UNSAFE_PERMS.is_match(trimmed))
                && !RE_FIL_006_SAFE_GUARD.is_match(trimmed)
            {
                Self::record_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-FIL-006",
                    "CWE-434",
                    "User Upload Stored in Executable/Public Directory or Unsafe Permissions",
                    Severity::High,
                    &target_kind,
                    path,
                    file_tag,
                    line_no,
                    trimmed,
                    "Store uploads outside public web root and apply restrictive non-executable permissions (e.g. 0644 or 0600)",
                    format!(
                        "Upload storage configured at line {} writes into public webroot or applies over-permissive permissions (0777), risking direct script execution.",
                        line_no
                    ),
                    "Restore invariant: isolated non-executable storage",
                );
            }

            // 5. BK-AI-FIL-007: Filename allows path separators, control chars or Unicode normalization escape
            if (RE_FIL_007_RAW_FILENAME.is_match(trimmed) || RE_FIL_007_WRITE_RAW_NAME.is_match(trimmed))
                && !RE_FIL_007_SAFE_GUARD.is_match(trimmed)
            {
                Self::record_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-FIL-007",
                    "CWE-22",
                    "Filename Allows Path Traversal Separators or Control Characters",
                    Severity::High,
                    &target_kind,
                    path,
                    file_tag,
                    line_no,
                    trimmed,
                    "Sanitize filenames using path.basename, secure_filename, or strip all non-alphanumeric characters",
                    format!(
                        "Raw user-supplied filename passed to filesystem path resolution at line {}. Attackers can inject '../' path separators to escape target directories.",
                        line_no
                    ),
                    "Restore invariant: normalized safe generated storage identity",
                );
            }

            // 6. BK-AI-FIL-009: Insecure temporary/backup files persist secrets or become publicly readable
            if (RE_FIL_009_MKTEMP.is_match(trimmed)
                || RE_FIL_009_TMP_SECRET.is_match(trimmed)
                || RE_FIL_009_FS_TMP_SECRET.is_match(trimmed)
                || RE_FIL_009_BAK_FILE.is_match(trimmed))
                && !RE_FIL_009_SAFE_GUARD.is_match(trimmed)
            {
                Self::record_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-FIL-009",
                    "CWE-552",
                    "Insecure Temporary or Backup Files Persist Secrets or Permissive Permissions",
                    Severity::High,
                    &target_kind,
                    path,
                    file_tag,
                    line_no,
                    trimmed,
                    "Use cryptographically randomized temporary files with restrictive permissions (0600) via mkdtemp or NamedTemporaryFile",
                    format!(
                        "Insecure temporary file or backup path detected at line {}. Predictable paths or permissive permissions in /tmp can expose secrets.",
                        line_no
                    ),
                    "Restore invariant: permissions and lifecycle verified",
                );
            }

            // 7. BK-AI-FIL-010: Unsafe file overwrite, truncation or deletion from arbitrary user-supplied path
            if (RE_FIL_010_UNSAFE_UNLINK.is_match(trimmed) || RE_FIL_010_OS_REMOVE.is_match(trimmed))
                && !RE_FIL_010_SAFE_GUARD.is_match(trimmed)
            {
                Self::record_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-FIL-010",
                    "CWE-73",
                    "Unsafe File Overwrite or Deletion from Arbitrary User-Supplied Path",
                    Severity::High,
                    &target_kind,
                    path,
                    file_tag,
                    line_no,
                    trimmed,
                    "Validate file deletion and truncation paths against an explicit allowlist or canonical base directory",
                    format!(
                        "File deletion or modification operation at line {} accepts user-controlled path parameters directly without boundary validation.",
                        line_no
                    ),
                    "Restore invariant: explicit authorized target set",
                );
            }

            // 9. BK-AI-FIL-012: Files served/downloaded without proper per-object authorization (line level)
            if RE_FIL_012_LINE_DOWNLOAD.is_match(trimmed)
                && !RE_FIL_012_SAFE_GUARD.is_match(trimmed)
                && !has_auth_guard
            {
                Self::record_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-FIL-012",
                    "CWE-639",
                    "Files Served or Downloaded Without Proper Per-Object Authorization",
                    Severity::High,
                    &target_kind,
                    path,
                    file_tag,
                    line_no,
                    trimmed,
                    "Verify requesting user identity and ownership permissions prior to serving or downloading stored files",
                    format!(
                        "File download or sendFile operation at line {} serves files directly based on user input without authorization checks.",
                        line_no
                    ),
                    "Restore invariant: tenant/user request isolation",
                );
            }

            // 10. BK-AI-FIL-013: Uploaded SVG/HTML/PDF rendered inline without appropriate isolation
            if (RE_FIL_013_SVG_HEADER.is_match(trimmed)
                || RE_FIL_013_SVG_TYPE.is_match(trimmed)
                || RE_FIL_013_SEND_FILE_SVG.is_match(trimmed))
                && !RE_FIL_013_SAFE_GUARD.is_match(trimmed)
                && !has_svg_disposition_guard
            {
                Self::record_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-FIL-013",
                    "CWE-79",
                    "Uploaded SVG/HTML Rendered Inline Without Attachment or Strict CSP",
                    Severity::High,
                    &target_kind,
                    path,
                    file_tag,
                    line_no,
                    trimmed,
                    "Force 'Content-Disposition: attachment' or serve SVG/HTML uploads under an isolated domain with restrictive CSP",
                    format!(
                        "SVG/HTML content served inline at line {} without attachment disposition or CSP sandbox. Embedded scripts in SVG will execute in origin context.",
                        line_no
                    ),
                    "Restore invariant: response disposition/sandbox policy",
                );
            }

            // 11. BK-AI-FIL-014: File parser accepts unbounded content/recursive structure
            if (RE_FIL_014_PARSER_UNBOUNDED.is_match(trimmed) || RE_FIL_014_PY_XML_UNGUARDED.is_match(trimmed))
                && !RE_FIL_014_SAFE_GUARD.is_match(trimmed)
                && !has_defusedxml
            {
                Self::record_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-FIL-014",
                    "CWE-400",
                    "File Parser Accepts Unbounded Content or Unconstrained Recursive Structure",
                    Severity::High,
                    &target_kind,
                    path,
                    file_tag,
                    line_no,
                    trimmed,
                    "Use defusedxml, disable external entity resolution (noent: false), and enforce maximum parser recursion limits",
                    format!(
                        "XML/YAML parser configured at line {} allows external entities or unbounded aliases, enabling billion laughs / XML entity expansion attacks.",
                        line_no
                    ),
                    "Restore invariant: byte, nesting, CPU and memory limits",
                );
            }

            // 12. BK-AI-INJ-002: Dynamic SQL identifiers, ordering, or table names without a finite allowlist
            if (RE_INJ_002_ORDER_BY.is_match(trimmed)
                || RE_INJ_002_KNEX_ORDER.is_match(trimmed)
                || RE_INJ_002_DYNAMIC_TABLE.is_match(trimmed))
                && !RE_INJ_002_SAFE_GUARD.is_match(trimmed)
                && !has_sql_allowlist_guard
            {
                Self::record_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-INJ-002",
                    "CWE-89",
                    "Dynamic SQL Identifiers or Ordering Clause Assembled Without Allowlist",
                    Severity::High,
                    &target_kind,
                    path,
                    file_tag,
                    line_no,
                    trimmed,
                    "Validate dynamic column names, order directions, and table identifiers against a static allowlist before query interpolation",
                    format!(
                        "Dynamic SQL query assembly at line {} interpolates user-controlled identifiers or ORDER BY clauses without allowlist validation.",
                        line_no
                    ),
                    "Restore invariant: identifier selection cannot become arbitrary SQL",
                );
            }

            // 13. BK-AI-INJ-004: Command-line argument injection despite use of a subprocess argument array
            if (RE_INJ_004_NODE_EXECFILE.is_match(trimmed) || RE_INJ_004_PY_SUBPROCESS.is_match(trimmed))
                && !RE_INJ_004_SAFE_GUARD.is_match(trimmed)
            {
                Self::record_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-INJ-004",
                    "CWE-88",
                    "Command-Line Argument Injection in Subprocess Array Argument Position",
                    Severity::High,
                    &target_kind,
                    path,
                    file_tag,
                    line_no,
                    trimmed,
                    "Insert '--' end-of-options delimiter before user arguments or reject inputs starting with '-'",
                    format!(
                        "Subprocess invocation at line {} accepts user input directly into CLI command argument positions without '--' flag separation.",
                        line_no
                    ),
                    "Restore invariant: untrusted input cannot become a command option",
                );
            }

            // 14. BK-AI-INJ-005: OS command execution via helper/wrapper/library omitted from basic grep rules
            if RE_INJ_005_CHILD_PROCESS_EXEC.is_match(trimmed)
                || RE_INJ_005_OS_SYSTEM.is_match(trimmed)
                || RE_INJ_005_SUBPROCESS_SHELL.is_match(trimmed)
                || RE_INJ_005_SHELLJS.is_match(trimmed)
            {
                Self::record_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-INJ-005",
                    "CWE-78",
                    "OS Command Execution via Helper/Wrapper/Library Sink",
                    Severity::Critical,
                    &target_kind,
                    path,
                    file_tag,
                    line_no,
                    trimmed,
                    "Avoid shell execution wrappers; use execFile or spawn with fixed argument arrays and shell: false",
                    format!(
                        "OS command execution wrapper invoked at line {} with dynamic command string or shell=True, exposing system to arbitrary command execution.",
                        line_no
                    ),
                    "Restore invariant: all configured sink aliases included",
                );
            }

            // 15. BK-AI-INJ-008: Server-side template expressions compiled from user data
            if RE_INJ_008_JINJA.is_match(trimmed)
                || RE_INJ_008_ENV_STRING.is_match(trimmed)
                || RE_INJ_008_JS_COMPILE.is_match(trimmed)
            {
                Self::record_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-INJ-008",
                    "CWE-1336",
                    "Server-Side Template Expressions Compiled Directly from User Data",
                    Severity::Critical,
                    &target_kind,
                    path,
                    file_tag,
                    line_no,
                    trimmed,
                    "Compile and render static template files rather than compiling dynamic template strings from user input",
                    format!(
                        "Template expression compiled dynamically from user-controlled input at line {}, enabling Server-Side Template Injection (SSTI).",
                        line_no
                    ),
                    "Restore invariant: template is fixed; data stays data",
                );
            }

            // 16. BK-AI-INJ-009: Template escape bypass (`safe`, raw output) applied to untrusted values
            if RE_INJ_009_SAFE_PIPE.is_match(trimmed)
                || RE_INJ_009_MARKUP_CALL.is_match(trimmed)
                || RE_INJ_009_MARK_SAFE.is_match(trimmed)
                || RE_INJ_009_BLADE_RAW.is_match(trimmed)
                || RE_INJ_009_EJS_RAW.is_match(trimmed)
            {
                Self::record_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-INJ-009",
                    "CWE-79",
                    "Template Auto-Escape Bypass Applied to Untrusted Values",
                    Severity::High,
                    &target_kind,
                    path,
                    file_tag,
                    line_no,
                    trimmed,
                    "Retain automatic template escaping or sanitize inputs with an HTML parser sanitizer before rendering raw output",
                    format!(
                        "Template escape bypass ('safe', 'raw', Markup, or <%- %>) applied to untrusted value at line {}, creating Cross-Site Scripting (XSS).",
                        line_no
                    ),
                    "Restore invariant: context-appropriate encoding at sink",
                );
            }

            // 17. BK-AI-INJ-010: XPath/XQuery expression assembled from inputs
            if RE_INJ_010_XPATH_CONCAT.is_match(trimmed) && !RE_INJ_010_SAFE_GUARD.is_match(trimmed) {
                Self::record_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-INJ-010",
                    "CWE-643",
                    "XPath/XQuery Expression Assembled Directly from Untrusted Inputs",
                    Severity::High,
                    &target_kind,
                    path,
                    file_tag,
                    line_no,
                    trimmed,
                    "Use parameterized XPath expressions or variable maps rather than string concatenation or interpolation",
                    format!(
                        "XPath query assembled at line {} using string concatenation or template literals, enabling XPath injection.",
                        line_no
                    ),
                    "Restore invariant: untrusted values cannot change query structure",
                );
            }

            // 18. BK-AI-INJ-011: LDAP filter/DN assembled without context-specific escaping
            if (RE_INJ_011_LDAP_SEARCH.is_match(trimmed)
                || RE_INJ_011_FILTER_VAR.is_match(trimmed)
                || RE_INJ_011_LDAP_QUERY_ARG.is_match(trimmed))
                && !RE_INJ_011_SAFE_GUARD.is_match(trimmed)
                && !has_ldap_escape_guard
            {
                Self::record_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-INJ-011",
                    "CWE-90",
                    "LDAP Search Filter or DN Assembled Without Context-Specific Escaping",
                    Severity::High,
                    &target_kind,
                    path,
                    file_tag,
                    line_no,
                    trimmed,
                    "Sanitize and escape LDAP special characters (e.g. *, (, ), \\, NUL) using escapeLDAPFilter before query assembly",
                    format!(
                        "LDAP filter assembled with unescaped user input at line {}, allowing LDAP filter injection and directory enumeration.",
                        line_no
                    ),
                    "Restore invariant: LDAP grammar preserved",
                );
            }

            // 19. BK-AI-INJ-012: NoSQL query/operator injection from user-controlled objects
            if (RE_INJ_012_NOSQL_QUERY.is_match(trimmed) || RE_INJ_012_COLLECTION_QUERY.is_match(trimmed))
                && !RE_INJ_012_SAFE_GUARD.is_match(trimmed)
                && !has_nosql_sanitize
            {
                Self::record_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-INJ-012",
                    "CWE-943",
                    "NoSQL Query or Operator Injection from Unsanitized User-Controlled Objects",
                    Severity::High,
                    &target_kind,
                    path,
                    file_tag,
                    line_no,
                    trimmed,
                    "Sanitize query objects using mongo-sanitize or explicitly cast inputs to primitive strings (e.g. String(val))",
                    format!(
                        "NoSQL query predicate at line {} binds user-supplied object directly without type validation, allowing $ne / $gt operator injection.",
                        line_no
                    ),
                    "Restore invariant: inputs cannot introduce operators or predicates",
                );
            }

            // 20. BK-AI-INJ-013: CRLF injection into HTTP response headers or logs
            if (RE_INJ_013_SET_HEADER.is_match(trimmed)
                || RE_INJ_013_HEADERS_ASSIGN.is_match(trimmed)
                || RE_INJ_013_LOG_CONCAT.is_match(trimmed))
                && !RE_INJ_013_SAFE_GUARD.is_match(trimmed)
            {
                Self::record_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-INJ-013",
                    "CWE-113",
                    "CRLF Injection into HTTP Response Headers or Log Stream",
                    Severity::Medium,
                    &target_kind,
                    path,
                    file_tag,
                    line_no,
                    trimmed,
                    "Strip carriage returns and line feeds (\\r, \\n) from user inputs before setting response headers or writing logs",
                    format!(
                        "HTTP header or log output at line {} receives unvalidated user input without CRLF stripping, risking HTTP response splitting and log forgery.",
                        line_no
                    ),
                    "Restore invariant: line terminators rejected or safely encoded",
                );
            }

            // 21. BK-AI-INJ-016: Trusting generic `sanitize()` or `escape()` without checking target context
            if (RE_INJ_016_SQL_SANITIZE.is_match(trimmed)
                || RE_INJ_016_SHELL_SANITIZE.is_match(trimmed)
                || RE_INJ_016_HREF_ESCAPE.is_match(trimmed))
                && !RE_INJ_016_SAFE_GUARD.is_match(trimmed)
            {
                Self::record_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-INJ-016",
                    "CWE-116",
                    "Trusting Generic Sanitize or Escape Helper Without Target Context Validation",
                    Severity::Medium,
                    &target_kind,
                    path,
                    file_tag,
                    line_no,
                    trimmed,
                    "Use context-appropriate encoders (e.g. parameterized SQL queries, argument arrays, encodeURIComponent) rather than generic string sanitizers",
                    format!(
                        "Generic escape or sanitize function used in inappropriate target context (SQL, shell, or href attribute) at line {}.",
                        line_no
                    ),
                    "Restore invariant: sanitizer appropriate to exact sink, charset and decoding order",
                );
            }
        }

        // --------------------------------------------------------------------
        // Pass 2: Multi-Line Contextual Analysis
        // --------------------------------------------------------------------

        // 8. BK-AI-FIL-011: TOCTOU between file validation and opening/replacement
        if !RE_FIL_011_SAFE_GUARD.is_match(content) {
            for cap in RE_FIL_011_TOCTOU_EXISTS.captures_iter(content) {
                let var_name = &cap[1];
                let body = &cap[2];
                if (body.contains("readFileSync")
                    || body.contains("writeFileSync")
                    || body.contains("unlinkSync")
                    || body.contains("openSync"))
                    && body.contains(var_name)
                {
                    let m = cap.get(0).unwrap();
                    let line_no = byte_to_line(m.start());
                    let snippet = m.as_str().lines().next().unwrap_or(m.as_str()).trim();
                    Self::record_finding(
                        &mut findings,
                        &mut seen,
                        "BK-AI-FIL-011",
                        "CWE-367",
                        "Time-of-Check to Time-of-Use (TOCTOU) File Race Condition",
                        Severity::Medium,
                        &target_kind,
                        path,
                        file_tag,
                        line_no,
                        snippet,
                        "Perform atomic file operations (e.g. fs.open with 'wx' or O_EXCL) and handle ENOENT / EEXIST errors directly",
                        format!(
                            "TOCTOU race condition detected starting at line {}. Checking file existence before opening or unlinking allows symlink / file swap races.",
                            line_no
                        ),
                        "Restore invariant: atomic or handle-based enforcement",
                    );
                }
            }

            for cap in RE_FIL_011_TOCTOU_ACCESS.captures_iter(content) {
                let var_name = &cap[1];
                let body = &cap[2];
                if (body.contains("readFile")
                    || body.contains("writeFile")
                    || body.contains("unlink"))
                    && body.contains(var_name)
                {
                    let m = cap.get(0).unwrap();
                    let line_no = byte_to_line(m.start());
                    let snippet = m.as_str().lines().next().unwrap_or(m.as_str()).trim();
                    Self::record_finding(
                        &mut findings,
                        &mut seen,
                        "BK-AI-FIL-011",
                        "CWE-367",
                        "Time-of-Check to Time-of-Use (TOCTOU) File Race Condition",
                        Severity::Medium,
                        &target_kind,
                        path,
                        file_tag,
                        line_no,
                        snippet,
                        "Perform atomic file operations (e.g. fs.open with 'wx' or O_EXCL) and handle ENOENT / EEXIST errors directly",
                        format!(
                            "TOCTOU race condition detected starting at line {}. Checking file access before opening allows race conditions.",
                            line_no
                        ),
                        "Restore invariant: atomic or handle-based enforcement",
                    );
                }
            }

            for cap in RE_FIL_011_TOCTOU_PY.captures_iter(content) {
                let var_name = &cap[1];
                let body = &cap[2];
                if (body.contains("with open") || body.contains("os.remove") || body.contains("os.unlink"))
                    && body.contains(var_name)
                {
                    let m = cap.get(0).unwrap();
                    let line_no = byte_to_line(m.start());
                    let snippet = m.as_str().lines().next().unwrap_or(m.as_str()).trim();
                    Self::record_finding(
                        &mut findings,
                        &mut seen,
                        "BK-AI-FIL-011",
                        "CWE-367",
                        "Time-of-Check to Time-of-Use (TOCTOU) File Race Condition",
                        Severity::Medium,
                        &target_kind,
                        path,
                        file_tag,
                        line_no,
                        snippet,
                        "Perform atomic file operations and catch FileNotFoundError rather than testing existence beforehand",
                        format!(
                            "TOCTOU race condition detected in Python script at line {}. Checking os.path.exists before file manipulation is vulnerable to races.",
                            line_no
                        ),
                        "Restore invariant: atomic or handle-based enforcement",
                    );
                }
            }
        }

        // 9b. BK-AI-FIL-012: Files served/downloaded without proper per-object authorization (multiline route)
        if !has_auth_guard {
            for m in RE_FIL_012_DOWNLOAD_UNAUTH.find_iter(content) {
                if !RE_FIL_012_SAFE_GUARD.is_match(m.as_str()) {
                    let line_no = byte_to_line(m.start());
                    let snippet = m.as_str().lines().next().unwrap_or(m.as_str()).trim();
                    Self::record_finding(
                        &mut findings,
                        &mut seen,
                        "BK-AI-FIL-012",
                        "CWE-639",
                        "Files Served or Downloaded Without Proper Per-Object Authorization",
                        Severity::High,
                        &target_kind,
                        path,
                        file_tag,
                        line_no,
                        snippet,
                        "Verify requesting user identity and ownership permissions prior to serving or downloading stored files",
                        format!(
                            "File download route starting at line {} serves user-specified files without per-object authorization checks.",
                            line_no
                        ),
                        "Restore invariant: tenant/user request isolation",
                    );
                }
            }
        }

        // 21b. BK-AI-INJ-016: Trusting generic sanitize() inside script blocks
        for m in RE_INJ_016_SCRIPT_SANITIZE.find_iter(content) {
            if !RE_INJ_016_SAFE_GUARD.is_match(m.as_str()) {
                let line_no = byte_to_line(m.start());
                let snippet = m.as_str().lines().next().unwrap_or(m.as_str()).trim();
                Self::record_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-INJ-016",
                    "CWE-116",
                    "Trusting Generic Sanitize or Escape Helper Without Target Context Validation",
                    Severity::Medium,
                    &target_kind,
                    path,
                    file_tag,
                    line_no,
                    snippet,
                    "Use JSON.stringify or safe serialization inside script blocks rather than HTML sanitizers",
                    format!(
                        "Generic HTML escape/sanitize function used within <script> block at line {}. HTML entity escaping does not prevent JavaScript execution.",
                        line_no
                    ),
                    "Restore invariant: sanitizer appropriate to exact sink, charset and decoding order",
                );
            }
        }

        findings
    }

    #[allow(clippy::too_many_arguments)]
    fn record_finding(
        findings: &mut Vec<Finding>,
        seen: &mut HashSet<(String, usize)>,
        rule_id: &str,
        cwe: &str,
        title: &str,
        severity: Severity,
        target_kind: &TargetKind,
        path: &Path,
        file_tag: &str,
        line_no: usize,
        snippet: &str,
        safe_threshold: &str,
        description: impl Into<String>,
        suggested_remediation: &str,
    ) {
        if !seen.insert((rule_id.to_string(), line_no)) {
            return;
        }

        let short_id = if let Some(stripped) = rule_id.strip_prefix("BK-AI-") {
            stripped
        } else {
            rule_id
        };
        let id = format!("{}-{}-{}", short_id, file_tag, line_no);

        let mut finding = Finding::new(
            id,
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
            description.into(),
            suggested_remediation,
        );

        finding.detector_id = "filesystem-ext".to_string();
        finding.detector_version = "1.0.0".to_string();
        finding.category = if rule_id.starts_with("BK-AI-FIL") {
            "2.7 Filesystem, uploads, archives and path traversal".to_string()
        } else {
            "2.1 Injection and interpreter boundaries".to_string()
        };
        finding.affectedness = Affectedness::ConfirmedAffected;
        finding.reachability = Reachability::PotentiallyReachable;
        finding.confidence = Confidence::High;
        finding.evidence_certainty = EvidenceCertainty::StronglySupported;
        finding.advisory_ids = vec![cwe.to_string(), rule_id.to_string()];
        finding.evidence_refs.push(EvidenceRef {
            location: format!("{}:{}", path.display(), line_no),
            line_number: Some(line_no),
            snippet: Some(snippet.to_string()),
            sha256: None,
        });
        finding.compute_dedupe_fingerprint();
        findings.push(finding);
    }
}
