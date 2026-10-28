use regex::Regex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoiseTier {
    Precise,
    Normal,
    Noisy,
}

impl NoiseTier {
    pub fn score(&self) -> u32 {
        match self {
            NoiseTier::Precise => 0,
            NoiseTier::Normal => 1,
            NoiseTier::Noisy => 2,
        }
    }
}

pub struct Matcher {
    pub vuln_slug: &'static str,
    pub label: &'static str,
    pub file_extensions: Vec<&'static str>,
    pub patterns: Vec<Regex>,
    pub noise_tier: NoiseTier,
    pub requires_tech: Option<Vec<&'static str>>,
}

pub struct MatcherRegistry {
    matchers: Vec<Matcher>,
}

impl Default for MatcherRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl MatcherRegistry {
    pub fn new() -> Self {
        let mut reg = Self {
            matchers: Vec::new(),
        };
        reg.register_builtins();
        reg
    }

    pub fn register(&mut self, matcher: Matcher) {
        self.matchers.push(matcher);
    }

    pub fn matchers(&self) -> &[Matcher] {
        &self.matchers
    }

    pub fn get_by_slug(&self, slug: &str) -> Option<&Matcher> {
        self.matchers.iter().find(|m| m.vuln_slug == slug)
    }

    fn register_builtins(&mut self) {
        self.matchers.push(Matcher {
            vuln_slug: "sql-injection",
            label: "SQL Raw Concatenation / Interpolation",
            file_extensions: vec!["ts", "js", "py", "go", "rs", "php", "rb"],
            patterns: vec![
                Regex::new(r#"(?i)(SELECT|INSERT|UPDATE|DELETE|DROP)\s+.*(\+|\$|\$\{).*?"#).unwrap(),
                Regex::new(r#"(?i)(SELECT|INSERT|UPDATE|DELETE|DROP)\s+.*(\+|\$|\%s|\{.*\}).*FROM"#).unwrap(),
                Regex::new(r#"(?i)\.query\s*\(\s*`[^`]*\$\{.+?\}"#).unwrap(),
                Regex::new(r#"(?i)\.execute\s*\(\s*f["'].*?\{.+?\}.*?["']\s*\)"#).unwrap(),
                Regex::new(r#"(?i)(db|conn|cursor)\.(raw|exec|query|execute)\s*\(\s*["'].*?\+.*?\)"#).unwrap(),
            ],
            noise_tier: NoiseTier::Precise,
            requires_tech: None,
        });

        self.matchers.push(Matcher {
            vuln_slug: "rce",
            label: "Command Execution / Evaluation",
            file_extensions: vec!["ts", "js", "py", "go", "rs", "php", "rb"],
            patterns: vec![
                Regex::new(r#"(?i)\b(exec|execSync|spawn|spawnSync)\s*\([^)]*(\+|\$|\$\{)"#).unwrap(),
                Regex::new(r#"(?i)\b(child_process|subprocess)\.(Popen|call|run|check_output)\s*\([^)]*shell\s*=\s*True"#).unwrap(),
                Regex::new(r#"(?i)\beval\s*\(\s*[^)]+\)"#).unwrap(),
                Regex::new(r#"(?i)\b(system|passthru|shell_exec)\s*\([^)]+\)"#).unwrap(),
            ],
            noise_tier: NoiseTier::Precise,
            requires_tech: None,
        });

        self.matchers.push(Matcher {
            vuln_slug: "ssrf",
            label: "Server-Side Request Forgery with Untrusted Target",
            file_extensions: vec!["ts", "js", "py", "go", "rs", "php", "rb"],
            patterns: vec![
                Regex::new(r#"(?i)(fetch|axios|got|urllib|requests\.get|http\.Get)\s*\(\s*(req\.|params\.|url|input|target)"#).unwrap(),
                Regex::new(r#"(?i)requests\.(get|post)\s*\(\s*(request\.|url|target|dest)"#).unwrap(),
            ],
            noise_tier: NoiseTier::Normal,
            requires_tech: None,
        });

        self.matchers.push(Matcher {
            vuln_slug: "path-traversal",
            label: "Arbitrary File Path Access",
            file_extensions: vec!["ts", "js", "py", "go", "rs", "php", "rb"],
            patterns: vec![
                Regex::new(r#"(?i)(fs\.readFile|fs\.createReadStream|open|os\.Open)\s*\([^)]*(\+|path\.join\([^)]*req\.)"#).unwrap(),
                Regex::new(r#"(?i)(sendFile|download)\s*\(\s*req\.(query|params|body)"#).unwrap(),
            ],
            noise_tier: NoiseTier::Normal,
            requires_tech: None,
        });

        self.matchers.push(Matcher {
            vuln_slug: "secrets-exposure",
            label: "Hardcoded API Keys or Credentials",
            file_extensions: vec!["ts", "js", "py", "go", "rs", "php", "rb", "json", "yaml", "env"],
            patterns: vec![
                Regex::new(r#"(?i)(AKIA[0-9A-Z]{16})"#).unwrap(),
                Regex::new(r#"ghp_[A-Za-z0-9_]{36}"#).unwrap(),
                Regex::new(r#"-----BEGIN (RSA|EC|PRIVATE) KEY-----"#).unwrap(),
                Regex::new(r#"(?i)(password|secret|api_key|token)\s*[:=]\s*["'][A-Za-z0-9_\-\.]{12,}["']"#).unwrap(),
            ],
            noise_tier: NoiseTier::Precise,
            requires_tech: None,
        });

        self.matchers.push(Matcher {
            vuln_slug: "xss",
            label: "Unescaped HTML Injection / DOM XSS",
            file_extensions: vec!["ts", "tsx", "js", "jsx", "vue", "html"],
            patterns: vec![
                Regex::new(r#"dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html:\s*[^}]+\}"#).unwrap(),
                Regex::new(r#"\.innerHTML\s*=\s*[^;]+"#).unwrap(),
                Regex::new(r#"v-html\s*=\s*["'][^"']+["']"#).unwrap(),
            ],
            noise_tier: NoiseTier::Normal,
            requires_tech: None,
        });

        self.matchers.push(Matcher {
            vuln_slug: "auth-bypass",
            label: "Authentication Bypass or Inverted Permission Check",
            file_extensions: vec!["ts", "js", "py", "go", "rs", "php"],
            patterns: vec![
                Regex::new(r#"(?i)if\s*\(!auth\.can\(|\.isAllowed\s*==\s*false|\.hasPermission\s*!=\s*true"#).unwrap(),
                Regex::new(r#"(?i)(skip_auth|bypass_auth|disable_auth)\s*[:=]\s*true"#).unwrap(),
                Regex::new(r#"(?i)NODE_ENV\s*!==\s*["']production["'].*return\s+next\(\)"#).unwrap(),
            ],
            noise_tier: NoiseTier::Normal,
            requires_tech: None,
        });

        self.matchers.push(Matcher {
            vuln_slug: "missing-auth",
            label: "Public Unauthenticated Sensitive Endpoint",
            file_extensions: vec!["ts", "js", "py", "go", "rs"],
            patterns: vec![
                Regex::new(r#"(?i)@(Public|AllowAnonymous|PermitAll)"#).unwrap(),
                Regex::new(r#"(?i)(app|router)\.(post|put|delete)\s*\(\s*["']/(admin|internal|api/v1/user)"#).unwrap(),
            ],
            noise_tier: NoiseTier::Noisy,
            requires_tech: None,
        });

        self.matchers.push(Matcher {
            vuln_slug: "dangerous-html",
            label: "Server-Rendered Raw HTML Injection",
            file_extensions: vec!["ts", "js", "py", "php", "erb"],
            patterns: vec![
                Regex::new(r#"(?i)(res\.send|response\.write)\s*\(\s*["']<[^>]+>\s*\+"#).unwrap(),
                Regex::new(r#"(?i)render_template_string\s*\([^)]*format\("#).unwrap(),
            ],
            noise_tier: NoiseTier::Normal,
            requires_tech: None,
        });

        self.matchers.push(Matcher {
            vuln_slug: "insecure-crypto",
            label: "Weak Hash or Symmetric Cipher Mode",
            file_extensions: vec!["ts", "js", "py", "go", "rs"],
            patterns: vec![
                Regex::new(r#"(?i)(createHash|hashlib)\s*\(\s*["'](md5|sha1)["']"#).unwrap(),
                Regex::new(r#"(?i)(aes-128-ecb|aes-256-ecb|MODE_ECB)"#).unwrap(),
            ],
            noise_tier: NoiseTier::Precise,
            requires_tech: None,
        });

        self.matchers.push(Matcher {
            vuln_slug: "open-redirect",
            label: "Unvalidated Location Header Redirect",
            file_extensions: vec!["ts", "js", "py", "go", "rs", "php"],
            patterns: vec![
                Regex::new(r#"(?i)(redirect|writeHead\(302)\s*\(\s*req\.(query|params)\.(url|redirect|target|next)"#).unwrap(),
                Regex::new(r#"(?i)HttpResponseRedirect\s*\(\s*request\.(GET|POST)\[["'](next|url)["']\]"#).unwrap(),
            ],
            noise_tier: NoiseTier::Normal,
            requires_tech: None,
        });

        self.matchers.push(Matcher {
            vuln_slug: "jwt-handling",
            label: "Insecure JWT Signing or Algorithm Header Trust",
            file_extensions: vec!["ts", "js", "py", "go", "rs"],
            patterns: vec![
                Regex::new(r#"(?i)jwt\.verify\s*\([^)]*algorithms\s*:\s*\[[^\]]*["']none["']"#).unwrap(),
                Regex::new(r#"(?i)jwt\.decode\s*\([^)]*verify\s*=\s*False"#).unwrap(),
            ],
            noise_tier: NoiseTier::Precise,
            requires_tech: None,
        });

        self.matchers.push(Matcher {
            vuln_slug: "rate-limit-bypass",
            label: "Authentication Route Without Rate Limiting",
            file_extensions: vec!["ts", "js", "py", "go", "rs"],
            patterns: vec![
                Regex::new(r#"(?i)(login|signin|reset-password|forgot-password)\s*\(.*req"#).unwrap(),
            ],
            noise_tier: NoiseTier::Noisy,
            requires_tech: None,
        });

        self.matchers.push(Matcher {
            vuln_slug: "expensive-api-abuse",
            label: "Unprotected Expensive AI / Billing API Invocation",
            file_extensions: vec!["ts", "js", "py", "go", "rs"],
            patterns: vec![
                Regex::new(r#"(?i)(openai|anthropic|stripe)\.(chat|completions|charges|paymentIntents)\.create"#).unwrap(),
            ],
            noise_tier: NoiseTier::Normal,
            requires_tech: None,
        });

        self.matchers.push(Matcher {
            vuln_slug: "cross-tenant-id",
            label: "Direct Object Query without Tenant Filtering",
            file_extensions: vec!["ts", "js", "py", "go", "rs"],
            patterns: vec![
                Regex::new(r#"(?i)findByPk\s*\(\s*req\.(params|query)\.id\s*\)"#).unwrap(),
                Regex::new(r#"(?i)findUnique\s*\(\s*\{\s*where:\s*\{\s*id:\s*req\."#).unwrap(),
            ],
            noise_tier: NoiseTier::Normal,
            requires_tech: None,
        });
    }
}
