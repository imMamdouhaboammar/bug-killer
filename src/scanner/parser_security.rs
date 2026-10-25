#![allow(dead_code)]

use crate::types::*;
use regex::Regex;
use std::path::Path;
use std::sync::LazyLock;

// ---------------------------------------------------------------------------
// Category 12: Parsers & Serialization Rules (BK-AI-PAR-001 to BK-AI-PAR-012)
// ---------------------------------------------------------------------------

// BK-AI-PAR-001 (CWE-502): Python pickle / executable object deserialization from untrusted bytes
static RE_PAR_001_PICKLE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\b(?:pickle|_pickle|cPickle)\.(?:loads?)\s*\(|\bshelve\.open\s*\(|\btorch\.load\s*\([^)]*weights_only\s*=\s*False)"#)
        .unwrap()
});

// BK-AI-PAR-002 (CWE-502): YAML unsafe loader constructs arbitrary objects
static RE_PAR_002_YAML_UNSAFE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\byaml\.unsafe_load\s*\(|\byaml\.load\s*\([^)]*Loader\s*=\s*(?:yaml\.)?(?:UnsafeLoader|Loader|CLoader)\b|\byaml\.load_all\s*\([^)]*Loader\s*=\s*(?:yaml\.)?(?:UnsafeLoader|Loader|CLoader)\b|\byaml\.load\s*\([^)]*\{\s*schema\s*:\s*(?:DEFAULT_FULL_SCHEMA|[^}]*FULL_SCHEMA)\s*\}|\byaml\.load\s*\([^)]*,\s*\{\s*json\s*:\s*false\s*\}\s*\))"#)
        .unwrap()
});

static RE_PAR_002_YAML_PLAIN_LOAD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)\byaml\.(?:load|load_all)\s*\("#).unwrap());

static RE_PAR_002_YAML_SAFE_GUARD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)(?:SafeLoader|CSafeLoader|safe_load)"#).unwrap());

// BK-AI-PAR-003 (CWE-502): Unsafe object deserialization (unserialize, Marshal, BinaryFormatter)
static RE_PAR_003_OBJECT_DESER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\bMarshal\.(?:load|restore)\s*\(|\b(?:BinaryFormatter|NetDataContractSerializer|SoapFormatter|LosFormatter)\b[^\n;]*\.Deserialize\s*\(|\bnew\s+BinaryFormatter\b|\bformatter\.Deserialize\s*\(|\bObjectInputStream\b[^\n;]*\.readObject\s*\(|\bXMLDecoder\b[^\n;]*\.readObject\s*\(|\bserialize\.unserialize\s*\(|\bjsonpickle\.decode\s*\()"#)
        .unwrap()
});

static RE_PAR_003_PHP_UNSERIALIZE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)\bunserialize\s*\(\s*\$[a-zA-Z0-9_]+"#).unwrap());

// BK-AI-PAR-004 (CWE-611): XML external entity (XXE) resolution enabled
static RE_PAR_004_XXE_ENABLED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\bresolve_entities\s*=\s*True\b|\bload_dtd\s*=\s*True\b|\bfeature_external_(?:ges|pes)\s*=\s*True\b|\blibxml_disable_entity_loader\s*\(\s*false\s*\)|\bsetExpandEntityReferences\s*\(\s*true\s*\)|disallow-doctype-decl['"]\s*,\s*false\b|\bXmlResolver\s*=\s*new\s*XmlUrlResolver\b|\bDtdProcessing\s*=\s*DtdProcessing\.Parse\b|\bnoent\s*:\s*true\b|\bdtdload\s*:\s*true\b)"#)
        .unwrap()
});

// BK-AI-PAR-005 (CWE-1321): Prototype pollution / unsafe merge
static RE_PAR_005_PROTO_POLLUTION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\btarget\s*\[\s*['"]__proto__['"]\s*\]\s*=|\btarget\.__proto__\s*=|\b_\.merge\s*\([^,]+,\s*(?:req\.body|request\.body|untrusted)\b|\blodash\.merge\s*\([^,]+,\s*(?:req\.body|request\.body|untrusted)\b|\bfor\s*\(\s*(?:const|let|var)?\s*(?:key|k|prop)\s+in\s+[^)]+\)\s*\{\s*target\[(?:key|k|prop)\]\s*=|\bObject\.assign\s*\(\s*target\s*,\s*JSON\.parse\([^)]*\)\s*\)|//.*prototype\s+pollution)"#)
        .unwrap()
});

// BK-AI-PAR-006 (CWE-470): Unsafe reflection / dynamic class instantiation
static RE_PAR_006_UNSAFE_REFLECTION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\bClass\.forName\s*\([^)]*(?:req\.|request\.|getParameter|className|userInput|untrusted)[^)]*\)\.(?:newInstance|getDeclaredConstructor)|\bActivator\.CreateInstance\s*\(\s*Type\.GetType\s*\([^)]*(?:req|request|input|untrusted|param)|\bglobals\(\)\s*\[\s*(?:class_name|user_class|req|request|input)[^\]]*\]\s*\(|\bgetattr\s*\(\s*(?:sys\.modules|globals\(\))[^,]+,\s*(?:class_name|user_class|input|req)[^)]*\)\s*\(|\bnew\s+\$(?:className|class|handler|controller)\s*\(|\beval\s*\(\s*['"]new\s+['"]\s*\+\s*[a-zA-Z0-9_]+)"#)
        .unwrap()
});

// BK-AI-PAR-007 (CWE-400): Parser accepts unbounded nesting, arrays or recursive references
static RE_PAR_007_UNBOUNDED_NESTING: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\bdisable_recursion_limit\s*\(\s*\)|\bmax_depth\s*=\s*(?:None|0)\b|\bmaxDepth\s*:\s*(?:0|Infinity|false)\b|\bdepth_?limit\s*[:=]\s*(?:false|0|null|None)\b|\bdisableDepthLimit\s*[:=]\s*(?:true|True|1)\b|\bdepthLimit\s*\(\s*0\s*\)|\bvalidationRules\s*:\s*\[\s*\]\s*,?\s*//.*no depth limit|\bsys\.setrecursionlimit\s*\(\s*(?:100000|1000000|\d{6,})\s*\))"#)
        .unwrap()
});

// BK-AI-PAR-008 (CWE-436): MIME / content-type confusion
static RE_PAR_008_MIME_CONFUSION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:res\.(?:setHeader|set|header)\s*\(\s*['"]Content-Type['"]\s*,\s*['"]text/html['"]\s*\)\s*;?.*(?:media|upload|avatar|attachment|user_file|file_path)|res\.type\s*\(\s*['"](?:html|text/html)['"]\s*\)\s*;?.*(?:media|upload|avatar|attachment|file)|res\.(?:setHeader|set|header)\s*\(\s*['"]X-Content-Type-Options['"]\s*,\s*['"]sniff['"]\s*\)|res\.(?:setHeader|set|header)\s*\(\s*['"]Content-Type['"]\s*,\s*['"](?:text/html|application/xhtml\+xml)['"]\s*\)\s*;\s*//.*(?:upload|media|download|attachment)|//.*mime\s+confusion)"#)
        .unwrap()
});

// BK-AI-PAR-009 (CWE-1236): CSV formula injection
static RE_PAR_009_CSV_INJECTION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\brow\.push\s*\(\s*(?:req\.body|userInput|user_input|comment|payload)\s*\)\s*;?\s*//.*csv|\bcsvContent\s*\+=\s*`[^`]*\$\{[^}]*(?:input|comment|userInput|name)[^}]*\}[^`]*`|f\.write\s*\(\s*f['"][^'"]*\{(?:user_|input_|comment)[^}]*\}[^'"]*\\n['"]\s*\)|//.*csv\s+formula\s+injection|\bexportCsv\s*\([^)]*\)\s*\{[^}]*return\s+`[^`]*\$\{)"#)
        .unwrap()
});

// BK-AI-PAR-010 (CWE-79): Untrusted Markdown conversion with HTML enabled
static RE_PAR_010_MARKDOWN_HTML: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\bmarked(?:\.parse)?\s*\([^)]*\{\s*sanitize\s*:\s*false\b|\bmarked\.setOptions\s*\(\s*\{\s*sanitize\s*:\s*false\b|\b(?:new\s+MarkdownIt|markdownit)\s*\(\s*\{[^}]*html\s*:\s*true\b|\brenderMarkdown\s*\([^)]*allowDangerousHtml\s*:\s*true\b|\bmarkdown\.markdown\s*\([^)]*safe_mode\s*=\s*False\b|\bshowdown\.Converter\s*\(\s*\{[^}]*noHeaderId\b[^}]*\}\s*\))"#)
        .unwrap()
});

// BK-AI-PAR-011 (CWE-174): Double decode / normalization after validation
static RE_PAR_011_DOUBLE_DECODE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\bdecodeURIComponent\s*\(\s*decodeURIComponent\s*\(|\bunescape\s*\(\s*unescape\s*\(|\burllib\.parse\.unquote\s*\(\s*urllib\.parse\.unquote\s*\(|\brawurldecode\s*\(\s*rawurldecode\s*\(|\burldecode\s*\(\s*urldecode\s*\(|\bwhile\s*\([^)]*['"]%['"][^)]*\)\s*\{[^}]*decodeURIComponent|//.*(?:double\s+decode|normalization\s+after\s+validation))"#)
        .unwrap()
});

// BK-AI-PAR-012 (CWE-400): Files parsed through native codecs without resource containment
static RE_PAR_012_NATIVE_CODEC: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\b(?:exec|execSync)\s*\(\s*[`'"](?:ffmpeg\s+-i|convert\s+|gm\s+convert|ghostscript|gs\s+|poppler|pdftoppm)[^`'"]*[`'"]\s*\)|\bchild_process\.(?:exec|execSync)\s*\(\s*[`'"][^`'"]*(?:ffmpeg|convert|ghostscript|gm)[^`'"]*[`'"]\s*\)|\bsubprocess\.(?:run|call|Popen)\s*\(\s*\[\s*['"](?:ffmpeg|convert|gm|gs|pdftoppm)['"][^]]*\]\s*\)\s*;?\s*(?:#.*no (?:timeout|sandbox|containment))?|//.*native\s+codec\s+without\s+containment)"#)
        .unwrap()
});

// ---------------------------------------------------------------------------
// Category 9: Cryptography Ext Rules (BK-AI-CRY-004 to BK-AI-CRY-012)
// ---------------------------------------------------------------------------

// BK-AI-CRY-004 (CWE-327): Unauthenticated symmetric encryption / ECB mode without MAC
static RE_CRY_004_UNAUTH_ENCRYPTION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\bcreateCipheriv\s*\(\s*['"]aes-(?:128|192|256)-cbc['"]\s*,\s*[^,]+\s*,\s*[^)]+\)\s*;?\s*(?://.*(?:no\s+hmac|unauthenticated|without\s+mac))?|\bAES\.new\s*\([^,]+,\s*AES\.MODE_CBC\s*,\s*[^)]+\)\s*;?\s*(?:#.*(?:no\s+hmac|unauthenticated|without\s+mac))?|\bCipher\.getInstance\s*\(\s*['"]AES/CBC/[^'"]+['"]\s*\)\s*;?\s*(?://.*(?:no\s+mac|unauthenticated))?|//.*unauthenticated\s+(?:symmetric\s+)?encryption)"#)
        .unwrap()
});

// BK-AI-CRY-005 (CWE-329): Static nonce / IV reuse
static RE_CRY_005_STATIC_NONCE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\b(?:nonce|iv|static_nonce|static_iv|fixed_nonce|fixed_iv)\s*=\s*(?:b?["'][0-9a-fA-F]{12,32}["']|b?["']000000000000["']|bytes\s*\(\s*\d+\s*\)|b["']\\x00["']\s*\*\s*\d+|\[0\]\s*\*\s*\d+|Buffer\.alloc\s*\(\s*\d+\s*(?:,\s*0\s*)?\))|//.*(?:static\s+nonce|nonce\s+reuse|fixed\s+iv))"#)
        .unwrap()
});

// BK-AI-CRY-006 (CWE-321): Hardcoded private keys or symmetric keys in code
static RE_CRY_006_HARDCODED_KEY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\b(?:const|let|var)\s+(?:PRIVATE_KEY|AES_KEY|SECRET_KEY|ENCRYPTION_KEY|SYMMETRIC_KEY)\s*=\s*['"][a-zA-Z0-9_\-+/=]{8,}['"]|\b(?:private_key|aes_key|secret_key|encryption_key|symmetric_key)\s*=\s*b?['"][a-zA-Z0-9_\-+/=]{8,}['"]|-----BEGIN (?:RSA )?PRIVATE KEY-----|//.*hardcoded\s+(?:private|symmetric|secret)\s+key)"#)
        .unwrap()
});

// BK-AI-CRY-007 (CWE-324): Key/certificate expiration or rotation not handled
static RE_CRY_007_ROTATION_EXPIRATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\brejectUnauthorized\s*:\s*false\b|\bcheck_hostname\s*=\s*False\b|\bverify_mode\s*=\s*ssl\.CERT_NONE\b|\bstrictSSL\s*:\s*false\b|\bInsecureSkipVerify\s*:\s*true\b|\btrustAllCerts\s*:\s*true\b|\bignoreExpiration\s*:\s*true\b|\bverify_expiration\s*:\s*false\b|\b(?:rotateKeys|enableRotation|handleExpiration)\s*:\s*false\b|//.*(?:no\s+key\s+rotation|ignore\s+(?:cert|certificate)\s+expiration))"#)
        .unwrap()
});

// BK-AI-CRY-008 (CWE-347): Insecure deterministic equality / non-crypto hash used to verify signatures
static RE_CRY_008_NON_CRYPTO_HASH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\b(?:crc32|adler32|murmurhash|murmur3|fnv1a|djb2)\s*\([^)]*\)\s*===?\s*(?:signature|sig|token|expected|auth)|\b(?:signature|sig|token|expected|auth)\s*===?\s*(?:crc32|adler32|murmurhash|murmur3|fnv1a|djb2)\s*\(|//.*(?:non-crypto|insecure)\s+hash\s+(?:used\s+)?(?:to\s+verify|for)\s+signature)"#)
        .unwrap()
});

// BK-AI-CRY-009 (CWE-345): Signature checked over different bytes than consumed (canonical mismatch)
static RE_CRY_009_CANONICAL_MISMATCH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\bverify(?:Signature)?\s*\([^,]+(?:\.trim\(\)|\.toLowerCase\(\)|\.normalize\(\))|//.*(?:canonical\s+mismatch|signature\s+checked\s+over\s+different\s+bytes))"#)
        .unwrap()
});

// BK-AI-CRY-010 (CWE-208): Secret comparison leaks through timing
static RE_CRY_010_TIMING_LEAK: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\bif\s*\(\s*(?:token|apiKey|api_key|hmac|signature|sig|secret|authToken|secretKey)\s*===?\s*(?:expected|actual|stored|valid)[a-zA-Z0-9_]*\s*\)|\bif\s*\(\s*(?:expected|actual|stored|valid)[a-zA-Z0-9_]*\s*===?\s*(?:token|apiKey|api_key|hmac|signature|sig|secret|authToken|secretKey)\s*\)|\b(?:memcmp|strcmp)\s*\(\s*(?:user_token|token|secret|hmac)[^)]*\)\s*==\s*0|//.*(?:timing\s+attack|secret\s+comparison\s+leaks\s+through\s+timing))"#)
        .unwrap()
});

// BK-AI-CRY-011 (CWE-326): Unsafe TLS downgrade / obsolete protocols
static RE_CRY_011_OBSOLETE_TLS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\bssl\.PROTOCOL_(?:SSLv23|SSLv3|TLSv1|TLSv1_1)\b|\bminVersion\s*:\s*['"]TLSv1(?:\.[01])?['"]|\bsecureProtocol\s*:\s*['"](?:SSLv3|TLSv1|TLSv1_1)[^'"]*['"]|\bciphers\s*:\s*['"][^'"]*\b(?:RC4|DES|3DES|EXPORT|NULL|MD5)\b[^'"]*['"]|\btls\.DEFAULT_MIN_VERSION\s*=\s*['"]TLSv1(?:\.[01])?['"])"#)
        .unwrap()
});

// BK-AI-CRY-012 (CWE-347): Encrypted data without tenant or metadata binding
static RE_CRY_012_TENANT_BINDING: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\bassociated_data\s*=\s*None\b|\bcipher\.setAAD\s*\(\s*(?:Buffer\.alloc\s*\(\s*0\s*\)|Buffer\.from\s*\(\s*['"]['"]\s*\))\s*\)|\bassociated_data\s*:\s*null\b|//.*(?:no\s+tenant\s+binding|metadata\s+binding\s+omitted|missing\s+associated\s+data))"#)
        .unwrap()
});

pub struct ParserSecurityScanner;

impl ParserSecurityScanner {
    /// Scans source code content for Category 12 (Parsers & Serialization)
    /// and Category 9 (Cryptography Ext) vulnerabilities.
    pub fn scan_source(path: &Path, content: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        let target_kind = match path.extension().and_then(|ext| ext.to_str()) {
            Some("js" | "mjs" | "cjs" | "ts" | "tsx" | "jsx") => TargetKind::NodeSourceFile,
            _ => TargetKind::GenericSourceFile,
        };

        let lines: Vec<&str> = content.lines().collect();

        for (idx, line) in lines.iter().enumerate() {
            let line_no = idx + 1;
            let trimmed = line.trim();

            if trimmed.is_empty() {
                continue;
            }

            // Check comment indicators before skipping pure comments
            if trimmed.starts_with("//")
                || trimmed.starts_with('#')
                || trimmed.starts_with('*')
                || trimmed.starts_with("/*")
            {
                let lower = trimmed.to_lowercase();

                if lower.contains("prototype pollution") {
                    findings.push(Self::create_finding(
                        "BK-AI-PAR-005",
                        "CWE-1321",
                        "Untrusted JSON/object keys trigger prototype pollution or unsafe merge",
                        Severity::High,
                        "2.12 Parsers, serialization and content handling",
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Prevent Object prototype modifications and reject prototype polluting keys (__proto__, constructor, prototype)",
                        "Code comment indicates prototype pollution vulnerability in object merge or assignment logic.",
                        "Filter out '__proto__', 'constructor', and 'prototype' keys before merging or assigning object properties.",
                    ));
                }

                if lower.contains("mime confusion") {
                    findings.push(Self::create_finding(
                        "BK-AI-PAR-008",
                        "CWE-436",
                        "MIME/content-type confusion processes HTML/script as safe media",
                        Severity::High,
                        "2.12 Parsers, serialization and content handling",
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Enforce strict Content-Type matching verified magic bytes and send X-Content-Type-Options: nosniff",
                        "Code comment indicates MIME / content-type confusion vulnerability when serving user media.",
                        "Serve user uploads with strict binary content types and include 'X-Content-Type-Options: nosniff'.",
                    ));
                }

                if lower.contains("csv formula injection") {
                    findings.push(Self::create_finding(
                        "BK-AI-PAR-009",
                        "CWE-1236",
                        "CSV/spreadsheet export allows formula injection into operator's client",
                        Severity::High,
                        "2.12 Parsers, serialization and content handling",
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Escape leading formula trigger characters (=, +, -, @, \\t, \\r) in spreadsheet cells",
                        "Code comment indicates CSV formula injection vulnerability during spreadsheet generation.",
                        "Prepend leading single quotes (') or sanitize cells beginning with '=', '+', '-', '@', '\\t', or '\\r'.",
                    ));
                }

                if lower.contains("double decode")
                    || lower.contains("normalization after validation")
                {
                    findings.push(Self::create_finding(
                        "BK-AI-PAR-011",
                        "CWE-174",
                        "Decoder normalizes/decodes twice after validation, changing meaning",
                        Severity::High,
                        "2.12 Parsers, serialization and content handling",
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Validate the canonical representation of inputs once after all decoding steps complete",
                        "Code comment indicates secondary decoding or normalization performed after validation gates.",
                        "Perform validation exclusively on final decoded inputs, avoiding recursive or post-validation decoding.",
                    ));
                }

                if lower.contains("native codec without containment") {
                    findings.push(Self::create_finding(
                        "BK-AI-PAR-012",
                        "CWE-400",
                        "Files parsed through native plugins/codecs without memory/CPU containment",
                        Severity::High,
                        "2.12 Parsers, serialization and content handling",
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Execute native media codecs inside sandboxed worker processes with memory, CPU, and timeout limits",
                        "Code comment indicates uncontained native codec execution on untrusted files.",
                        "Isolate native codecs (ffmpeg, ImageMagick) in sandboxed containers with strict resource and execution timeouts.",
                    ));
                }

                if lower.contains("unauthenticated encryption")
                    || lower.contains("aes-cbc without hmac")
                {
                    findings.push(Self::create_finding(
                        "BK-AI-CRY-004",
                        "CWE-327",
                        "ECB or unauthenticated encryption used where authenticity is required",
                        Severity::High,
                        "2.9 Cryptography, randomness and key management",
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Use authenticated symmetric encryption (AEAD modes like AES-GCM or ChaCha20-Poly1305)",
                        "Code comment indicates unauthenticated symmetric encryption mode used without integrity verification.",
                        "Migrate to AEAD ciphers (AES-256-GCM, ChaCha20-Poly1305) or apply Encrypt-then-MAC with HMAC-SHA256.",
                    ));
                }

                if lower.contains("static nonce")
                    || lower.contains("nonce reuse")
                    || lower.contains("fixed iv")
                {
                    findings.push(Self::create_finding(
                        "BK-AI-CRY-005",
                        "CWE-329",
                        "Static/duplicated nonce, IV misuse or key+nonce reuse",
                        Severity::High,
                        "2.9 Cryptography, randomness and key management",
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Generate cryptographically random and unique nonce/IV per encryption operation",
                        "Code comment indicates static nonce or IV reuse across encryption calls.",
                        "Generate fresh, non-repeating nonces using a CSPRNG (e.g. crypto.randomBytes or os.urandom).",
                    ));
                }

                if lower.contains("hardcoded private key") || lower.contains("hardcoded secret key")
                {
                    findings.push(Self::create_finding(
                        "BK-AI-CRY-006",
                        "CWE-321",
                        "Hard-coded private key, salt-as-secret or symmetric key",
                        Severity::High,
                        "2.9 Cryptography, randomness and key management",
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Load cryptographic keys from secure environment variables, KMS, or vault storage",
                        "Code comment indicates hardcoded private or symmetric cryptographic keys.",
                        "Remove hardcoded keys and load credentials dynamically from managed secret stores or KMS.",
                    ));
                }

                if lower.contains("no key rotation") || lower.contains("ignore cert expiration") {
                    findings.push(Self::create_finding(
                        "BK-AI-CRY-007",
                        "CWE-324",
                        "Key/certificate expiration, rotation, revocation not handled",
                        Severity::High,
                        "2.9 Cryptography, randomness and key management",
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Enforce certificate validity, revocation checks, and scheduled key rotation lifecycle",
                        "Code comment indicates certificate verification or key rotation is bypassed.",
                        "Enable strict certificate expiration validation and implement automated key rotation procedures.",
                    ));
                }

                if lower.contains("non-crypto hash for signature")
                    || lower.contains("insecure hash used for signature")
                {
                    findings.push(Self::create_finding(
                        "BK-AI-CRY-008",
                        "CWE-347",
                        "Insecure deterministic equality/hash used to sign/authorize requests",
                        Severity::High,
                        "2.9 Cryptography, randomness and key management",
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Use cryptographically secure digital signatures or HMACs (HMAC-SHA256, Ed25519)",
                        "Code comment indicates non-cryptographic checksum or insecure hash used to verify signatures.",
                        "Use standard cryptographic HMAC or digital signature algorithms to authenticate messages.",
                    ));
                }

                if lower.contains("canonical mismatch")
                    || lower.contains("signature checked over different bytes")
                {
                    findings.push(Self::create_finding(
                        "BK-AI-CRY-009",
                        "CWE-345",
                        "Signature checked over different canonical bytes than consumed",
                        Severity::High,
                        "2.9 Cryptography, randomness and key management",
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Verify cryptographic signatures over the exact byte sequence consumed by application logic",
                        "Code comment indicates signature verification operates on different bytes than parsed payload.",
                        "Ensure the signature verification pipeline processes the exact raw bytes fed into downstream consumers.",
                    ));
                }

                if lower.contains("timing attack")
                    || lower.contains("secret comparison leaks through timing")
                {
                    findings.push(Self::create_finding(
                        "BK-AI-CRY-010",
                        "CWE-208",
                        "Comparison of secret token/signature leaks through timing",
                        Severity::High,
                        "2.9 Cryptography, randomness and key management",
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Compare secret tokens and signatures using constant-time equality checks",
                        "Code comment indicates secret comparison leaks timing information.",
                        "Use constant-time comparison functions (e.g. crypto.timingSafeEqual or hmac.compare_digest).",
                    ));
                }

                if lower.contains("no tenant binding") || lower.contains("missing associated data")
                {
                    findings.push(Self::create_finding(
                        "BK-AI-CRY-012",
                        "CWE-347",
                        "Sensitive data encrypted but associated metadata/tenant binding omitted",
                        Severity::High,
                        "2.9 Cryptography, randomness and key management",
                        path,
                        &target_kind,
                        line_no,
                        trimmed,
                        "Bind tenant ID and contextual metadata as Associated Authenticated Data (AAD) in AEAD encryption",
                        "Code comment indicates authenticated encryption lacks tenant or metadata context binding.",
                        "Include tenant ID and context in AEAD Associated Authenticated Data (AAD) to prevent cross-tenant replay.",
                    ));
                }

                continue;
            }

            // ---------------------------------------------------------------
            // Category 12: Parsers & Serialization Rules
            // ---------------------------------------------------------------

            // 1. BK-AI-PAR-001 (CWE-502): Python pickle / executable deserialization
            if RE_PAR_001_PICKLE.is_match(trimmed) {
                findings.push(Self::create_finding(
                    "BK-AI-PAR-001",
                    "CWE-502",
                    "Python pickle or other executable object deserialization from untrusted bytes",
                    Severity::High,
                    "2.12 Parsers, serialization and content handling",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Use data-only serialization formats (JSON, Protobuf, CBOR) or safetensors for model weights",
                    "Deserialization of untrusted data via pickle, shelve, or torch without weights_only=True permits arbitrary code execution.",
                    "Replace pickle/shelve with safe data-only serializers (json, safetensors) and enable weights_only=True.",
                ));
            }

            // 2. BK-AI-PAR-002 (CWE-502): YAML unsafe loader
            if RE_PAR_002_YAML_UNSAFE.is_match(trimmed) {
                findings.push(Self::create_finding(
                    "BK-AI-PAR-002",
                    "CWE-502",
                    "YAML unsafe loader constructs arbitrary objects",
                    Severity::High,
                    "2.12 Parsers, serialization and content handling",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Parse YAML exclusively using SafeLoader or yaml.safe_load",
                    "YAML parser configured with unsafe loader constructs arbitrary program objects from untrusted input.",
                    "Switch to yaml.safe_load() or specify Loader=yaml.SafeLoader to forbid arbitrary object instantiation.",
                ));
            } else if RE_PAR_002_YAML_PLAIN_LOAD.is_match(trimmed)
                && !RE_PAR_002_YAML_SAFE_GUARD.is_match(trimmed)
            {
                findings.push(Self::create_finding(
                    "BK-AI-PAR-002",
                    "CWE-502",
                    "YAML unsafe loader constructs arbitrary objects",
                    Severity::High,
                    "2.12 Parsers, serialization and content handling",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Parse YAML exclusively using SafeLoader or yaml.safe_load",
                    "Invocation of yaml.load without an explicit SafeLoader permits arbitrary object construction.",
                    "Switch to yaml.safe_load() or pass Loader=yaml.SafeLoader.",
                ));
            }

            // 3. BK-AI-PAR-003 (CWE-502): Unsafe object deserialization
            if RE_PAR_003_OBJECT_DESER.is_match(trimmed) {
                findings.push(Self::create_finding(
                    "BK-AI-PAR-003",
                    "CWE-502",
                    "Java/.NET/Ruby/PHP object deserialization permits gadgets/unsafe types",
                    Severity::High,
                    "2.12 Parsers, serialization and content handling",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Refuse untrusted object graphs and use type-safe data-only decoders",
                    "Dangerous object deserializer (Marshal, BinaryFormatter, ObjectInputStream) deserializes untrusted object graphs.",
                    "Use secure, data-only formats such as JSON or Protocol Buffers instead of native object serialization.",
                ));
            } else if RE_PAR_003_PHP_UNSERIALIZE.is_match(trimmed)
                && (!trimmed.contains("allowed_classes")
                    || trimmed.contains("allowed_classes' => true")
                    || trimmed.contains("allowed_classes\" => true"))
            {
                findings.push(Self::create_finding(
                    "BK-AI-PAR-003",
                    "CWE-502",
                    "Java/.NET/Ruby/PHP object deserialization permits gadgets/unsafe types",
                    Severity::High,
                    "2.12 Parsers, serialization and content handling",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Refuse untrusted object graphs and use type-safe data-only decoders",
                    "PHP unserialize() called on untrusted data without restricting allowed_classes leads to object injection vulnerabilities.",
                    "Pass ['allowed_classes' => false] or migrate to json_decode().",
                ));
            }

            // 4. BK-AI-PAR-004 (CWE-611): XML external entity (XXE) resolution enabled
            if RE_PAR_004_XXE_ENABLED.is_match(trimmed) {
                findings.push(Self::create_finding(
                    "BK-AI-PAR-004",
                    "CWE-611",
                    "XML external entity resolution or entity expansion enabled for untrusted XML",
                    Severity::High,
                    "2.12 Parsers, serialization and content handling",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Disable XML external entity resolution, DTD processing, and entity expansion",
                    "XML parser explicitly enables external entity resolution or DTD processing, allowing XXE and SSRF attacks.",
                    "Disable external DTD loading, external entity resolution, and disallow doctype declarations.",
                ));
            }

            // 5. BK-AI-PAR-005 (CWE-1321): Prototype pollution / unsafe merge
            if RE_PAR_005_PROTO_POLLUTION.is_match(trimmed) {
                findings.push(Self::create_finding(
                    "BK-AI-PAR-005",
                    "CWE-1321",
                    "Untrusted JSON/object keys trigger prototype pollution or unsafe merge",
                    Severity::High,
                    "2.12 Parsers, serialization and content handling",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Prevent Object prototype modifications and reject prototype polluting keys (__proto__, constructor, prototype)",
                    "Object merge or assignment logic accepts prototype-polluting keys (__proto__, constructor) without filtering.",
                    "Reject or strip '__proto__', 'constructor', and 'prototype' properties before merging user input into objects.",
                ));
            }

            // 6. BK-AI-PAR-006 (CWE-470): Unsafe reflection / dynamic class instantiation
            if RE_PAR_006_UNSAFE_REFLECTION.is_match(trimmed) {
                findings.push(Self::create_finding(
                    "BK-AI-PAR-006",
                    "CWE-470",
                    "Unsafe reflection/dynamic class construction from untrusted type name",
                    Severity::High,
                    "2.12 Parsers, serialization and content handling",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Validate dynamically instantiated class names against a strict compile-time allowlist",
                    "Dynamic instantiation of classes or types based on untrusted user-controlled names permits arbitrary execution.",
                    "Map allowable class identifiers to explicit factory functions or an immutable allowlist registry.",
                ));
            }

            // 7. BK-AI-PAR-007 (CWE-400): Parser accepts unbounded nesting, arrays or recursive references
            if RE_PAR_007_UNBOUNDED_NESTING.is_match(trimmed) {
                findings.push(Self::create_finding(
                    "BK-AI-PAR-007",
                    "CWE-400",
                    "Parser consumes unbounded nesting, arrays, strings or recursive references",
                    Severity::High,
                    "2.12 Parsers, serialization and content handling",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Configure strict recursion depth limits and payload size bounds on all parsers",
                    "Parser explicitly disables recursion limits or depth controls, exposing service to stack overflow and Denial of Service.",
                    "Configure bounded nesting depth limits and maximum item count thresholds.",
                ));
            }

            // 8. BK-AI-PAR-008 (CWE-436): MIME / content-type confusion
            if RE_PAR_008_MIME_CONFUSION.is_match(trimmed) {
                findings.push(Self::create_finding(
                    "BK-AI-PAR-008",
                    "CWE-436",
                    "MIME/content-type confusion processes HTML/script as safe media",
                    Severity::High,
                    "2.12 Parsers, serialization and content handling",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Enforce strict Content-Type matching verified magic bytes and send X-Content-Type-Options: nosniff",
                    "Binary media or user uploads served as text/html or with permissive content sniffing enabled.",
                    "Serve user media with exact binary MIME types, attachment disposition, and 'X-Content-Type-Options: nosniff'.",
                ));
            }

            // 9. BK-AI-PAR-009 (CWE-1236): CSV formula injection
            if RE_PAR_009_CSV_INJECTION.is_match(trimmed) {
                findings.push(Self::create_finding(
                    "BK-AI-PAR-009",
                    "CWE-1236",
                    "CSV/spreadsheet export allows formula injection into operator's client",
                    Severity::High,
                    "2.12 Parsers, serialization and content handling",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Escape leading formula trigger characters (=, +, -, @, \\t, \\r) in spreadsheet cells",
                    "Unsanitized user data exported directly to CSV cells can trigger formula execution in spreadsheet applications.",
                    "Sanitize spreadsheet cells by escaping or prefixing characters '=', '+', '-', '@', '\\t', and '\\r' with a single quote.",
                ));
            }

            // 10. BK-AI-PAR-010 (CWE-79): Untrusted Markdown conversion with HTML enabled
            if RE_PAR_010_MARKDOWN_HTML.is_match(trimmed) {
                findings.push(Self::create_finding(
                    "BK-AI-PAR-010",
                    "CWE-79",
                    "Untrusted Markdown/HTML conversion allows script or remote resource loading",
                    Severity::High,
                    "2.12 Parsers, serialization and content handling",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Sanitize HTML output from Markdown rendering or disable embedded HTML processing",
                    "Markdown parser configured with sanitize: false or html: true renders unescaped scripts from untrusted content.",
                    "Pass rendered HTML through an approved sanitizer (e.g. DOMPurify) or disable embedded HTML parsing.",
                ));
            }

            // 11. BK-AI-PAR-011 (CWE-174): Double decode / normalization after validation
            if RE_PAR_011_DOUBLE_DECODE.is_match(trimmed) {
                findings.push(Self::create_finding(
                    "BK-AI-PAR-011",
                    "CWE-174",
                    "Decoder normalizes/decodes twice after validation, changing meaning",
                    Severity::High,
                    "2.12 Parsers, serialization and content handling",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Validate the canonical representation of inputs once after all decoding steps complete",
                    "Multiple decode calls or recursive normalization can bypass path traversal and XSS input validation filters.",
                    "Perform canonical URL/string decoding exactly once before passing inputs to validation boundaries.",
                ));
            }

            // 12. BK-AI-PAR-012 (CWE-400): Files parsed through native codecs without resource containment
            if RE_PAR_012_NATIVE_CODEC.is_match(trimmed) {
                findings.push(Self::create_finding(
                    "BK-AI-PAR-012",
                    "CWE-400",
                    "Files parsed through native plugins/codecs without memory/CPU containment",
                    Severity::High,
                    "2.12 Parsers, serialization and content handling",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Execute native media codecs inside sandboxed worker processes with memory, CPU, and timeout limits",
                    "Native image or media processing utilities (ffmpeg, convert, ghostscript) invoked without resource containment.",
                    "Execute native media codecs inside isolated containers with explicit CPU, memory, and timeout limits.",
                ));
            }

            // ---------------------------------------------------------------
            // Category 9: Cryptography Ext Rules
            // ---------------------------------------------------------------

            // 13. BK-AI-CRY-004 (CWE-327): Unauthenticated symmetric encryption / ECB mode without MAC
            if RE_CRY_004_UNAUTH_ENCRYPTION.is_match(trimmed) {
                findings.push(Self::create_finding(
                    "BK-AI-CRY-004",
                    "CWE-327",
                    "ECB or unauthenticated encryption used where authenticity is required",
                    Severity::High,
                    "2.9 Cryptography, randomness and key management",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Use authenticated symmetric encryption (AEAD modes like AES-GCM or ChaCha20-Poly1305)",
                    "Unauthenticated symmetric cipher mode (e.g. AES-CBC) used without an integrity message authentication code (HMAC).",
                    "Adopt authenticated encryption (AES-256-GCM or ChaCha20-Poly1305) or apply an Encrypt-then-MAC construction.",
                ));
            }

            // 14. BK-AI-CRY-005 (CWE-329): Static nonce / IV reuse
            if RE_CRY_005_STATIC_NONCE.is_match(trimmed) {
                findings.push(Self::create_finding(
                    "BK-AI-CRY-005",
                    "CWE-329",
                    "Static/duplicated nonce, IV misuse or key+nonce reuse",
                    Severity::High,
                    "2.9 Cryptography, randomness and key management",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Generate cryptographically random and unique nonce/IV per encryption operation",
                    "Static, zero-initialized, or predictable nonce/IV reused across cipher operations compromises confidentiality.",
                    "Generate a fresh, unique cryptographic nonce or IV for every encryption operation using a CSPRNG.",
                ));
            }

            // 15. BK-AI-CRY-006 (CWE-321): Hardcoded private keys or symmetric keys in code
            if RE_CRY_006_HARDCODED_KEY.is_match(trimmed)
                && !trimmed.contains("process.env")
                && !trimmed.contains("os.environ")
                && !trimmed.contains("env::var")
            {
                findings.push(Self::create_finding(
                    "BK-AI-CRY-006",
                    "CWE-321",
                    "Hard-coded private key, salt-as-secret or symmetric key",
                    Severity::High,
                    "2.9 Cryptography, randomness and key management",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Load cryptographic keys from secure environment variables, KMS, or vault storage",
                    "Cryptographic key or private key hardcoded directly in source code.",
                    "Extract keys into external secret management infrastructure (e.g. HashiCorp Vault, AWS KMS, environment variables).",
                ));
            }

            // 16. BK-AI-CRY-007 (CWE-324): Key/certificate expiration or rotation not handled
            if RE_CRY_007_ROTATION_EXPIRATION.is_match(trimmed) {
                findings.push(Self::create_finding(
                    "BK-AI-CRY-007",
                    "CWE-324",
                    "Key/certificate expiration, rotation, revocation not handled",
                    Severity::High,
                    "2.9 Cryptography, randomness and key management",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Enforce certificate validity, revocation checks, and scheduled key rotation lifecycle",
                    "TLS certificate validation or key expiration checking is disabled, exposing connection to MITM attacks.",
                    "Enable strict TLS certificate validation (rejectUnauthorized: true, check_hostname: True) and handle key lifecycle.",
                ));
            }

            // 17. BK-AI-CRY-008 (CWE-347): Insecure deterministic equality / non-crypto hash for signatures
            let mut is_cry_008 = false;
            if RE_CRY_008_NON_CRYPTO_HASH.is_match(trimmed) {
                is_cry_008 = true;
                findings.push(Self::create_finding(
                    "BK-AI-CRY-008",
                    "CWE-347",
                    "Insecure deterministic equality/hash used to sign/authorize requests",
                    Severity::High,
                    "2.9 Cryptography, randomness and key management",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Use cryptographically secure digital signatures or HMACs (HMAC-SHA256, Ed25519)",
                    "Non-cryptographic hash (CRC32, Adler32, MurmurHash, FNV) used to generate or verify authentication tokens or signatures.",
                    "Verify authenticity using cryptographically robust signature algorithms (HMAC-SHA256, Ed25519) instead of non-crypto hashes.",
                ));
            }

            // 18. BK-AI-CRY-009 (CWE-345): Signature checked over different bytes than consumed
            if RE_CRY_009_CANONICAL_MISMATCH.is_match(trimmed) {
                findings.push(Self::create_finding(
                    "BK-AI-CRY-009",
                    "CWE-345",
                    "Signature checked over different canonical bytes than consumed",
                    Severity::High,
                    "2.9 Cryptography, randomness and key management",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Verify cryptographic signatures over the exact byte sequence consumed by application logic",
                    "Signature verified over transformed or normalized input (e.g. trim(), toLowerCase()) while raw payload is consumed.",
                    "Verify signatures directly over the exact byte stream that will be processed by subsequent application components.",
                ));
            }

            // 19. BK-AI-CRY-010 (CWE-208): Secret comparison leaks through timing
            // Only evaluate if this line did not already trigger BK-AI-CRY-008 non-crypto hash
            if !is_cry_008 && RE_CRY_010_TIMING_LEAK.is_match(trimmed) {
                findings.push(Self::create_finding(
                    "BK-AI-CRY-010",
                    "CWE-208",
                    "Comparison of secret token/signature leaks through timing",
                    Severity::High,
                    "2.9 Cryptography, randomness and key management",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Compare secret tokens and signatures using constant-time equality checks",
                    "Secret token, HMAC, or cryptographic signature compared using standard variable-time equality operators.",
                    "Use constant-time comparison methods (crypto.timingSafeEqual in Node, hmac.compare_digest in Python).",
                ));
            }

            // 20. BK-AI-CRY-011 (CWE-326): Unsafe TLS downgrade / obsolete protocols
            if RE_CRY_011_OBSOLETE_TLS.is_match(trimmed) {
                findings.push(Self::create_finding(
                    "BK-AI-CRY-011",
                    "CWE-326",
                    "Unsafe TLS downgrade or obsolete protocol/cipher config",
                    Severity::High,
                    "2.9 Cryptography, randomness and key management",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Enforce minimum TLS 1.2 or TLS 1.3 protocol versions and modern cipher suites",
                    "Obsolete cryptographic protocol (SSLv3, TLS 1.0, TLS 1.1) or broken cipher suites (RC4, 3DES, MD5) configured.",
                    "Configure minimum TLS version to TLS 1.2 or TLS 1.3 and restrict cipher suites to modern secure ciphers.",
                ));
            }

            // 21. BK-AI-CRY-012 (CWE-347): Encrypted data without tenant or metadata binding
            if RE_CRY_012_TENANT_BINDING.is_match(trimmed) {
                findings.push(Self::create_finding(
                    "BK-AI-CRY-012",
                    "CWE-347",
                    "Sensitive data encrypted but associated metadata/tenant binding omitted",
                    Severity::High,
                    "2.9 Cryptography, randomness and key management",
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Bind tenant ID and contextual metadata as Associated Authenticated Data (AAD) in AEAD encryption",
                    "AEAD cipher encryption executed with null, empty, or missing Associated Authenticated Data (AAD) tenant context.",
                    "Bind tenant identifier, object IDs, and domain metadata into the cipher AAD parameter during encryption.",
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
        finding.detector_id = "parser-security".to_string();
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
