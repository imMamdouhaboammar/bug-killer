use ast_grep_core::{Doc, NodeMatch};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::engine::protocol::NormalizedSeverity;
use crate::structural::language::StructuralLanguage;

/// Definition of an ast-grep structural search rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructuralRule {
    pub rule_id: String,
    pub language: StructuralLanguage,
    pub pattern: String,
    pub cwe: String,
    pub severity: NormalizedSeverity,
    pub message: String,
    pub fix_pattern: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub additional_patterns: Vec<String>,
}

impl StructuralRule {
    pub fn new(
        rule_id: impl Into<String>,
        language: StructuralLanguage,
        pattern: impl Into<String>,
        cwe: impl Into<String>,
        severity: NormalizedSeverity,
        message: impl Into<String>,
        fix_pattern: Option<String>,
    ) -> Self {
        Self {
            rule_id: rule_id.into(),
            language,
            pattern: pattern.into(),
            cwe: cwe.into(),
            severity,
            message: message.into(),
            fix_pattern,
            additional_patterns: Vec::new(),
        }
    }

    /// Adds an additional pattern variation for this rule.
    pub fn with_additional_pattern(mut self, pattern: impl Into<String>) -> Self {
        self.additional_patterns.push(pattern.into());
        self
    }

    /// Returns all ast-grep patterns defined for this rule.
    pub fn all_patterns(&self) -> Vec<&str> {
        let mut patterns = Vec::with_capacity(1 + self.additional_patterns.len());
        patterns.push(self.pattern.as_str());
        for p in &self.additional_patterns {
            patterns.push(p.as_str());
        }
        patterns
    }

    /// Secondary semantic validator on an ast-grep match.
    /// Eliminates false positives (e.g. env var reads, placeholders, static literals in dynamic evals).
    pub fn validates_match<D: Doc>(&self, node_match: &NodeMatch<'_, D>) -> bool {
        match self.rule_id.as_str() {
            "BK-AI-SEC-001" => Self::validate_secret_match(node_match),
            "BK-AI-LNG-001" => Self::validate_eval_match(node_match),
            "BK-AI-INJ-002" => Self::validate_command_injection_match(node_match),
            _ => true,
        }
    }

    fn validate_secret_match<D: Doc>(node_match: &NodeMatch<'_, D>) -> bool {
        let env = node_match.get_env();
        let var_node = env.get_match("VAR");
        let val_node = env.get_match("VAL");

        if let (Some(var), Some(val)) = (var_node, val_node) {
            let var_name = var.text().to_ascii_lowercase();
            let val_text = val.text();
            let val_kind = val.kind();

            // 1. Variable name must indicate a secret / credential
            let is_secret_var = var_name.contains("api_key")
                || var_name.contains("apikey")
                || var_name.contains("secret")
                || var_name.contains("password")
                || var_name.contains("token")
                || var_name.contains("auth_key")
                || var_name.contains("access_key")
                || var_name.contains("private_key");

            if !is_secret_var {
                return false;
            }

            // 2. Anti-slop: if reading from environment or external config, it is safe!
            if val_text.contains("os.environ")
                || val_text.contains("os.getenv")
                || val_text.contains("process.env")
                || val_text.contains("env::var")
                || val_text.contains("getenv(")
            {
                return false;
            }

            // 3. Must be an actual string literal, not a function call or identifier
            let is_literal_string = val_kind == "string"
                || val_kind == "string_literal"
                || (val_text.starts_with('"') && val_text.ends_with('"'))
                || (val_text.starts_with('\'') && val_text.ends_with('\''));

            if !is_literal_string {
                return false;
            }

            // 4. Strip quotes and check for dummy/empty/placeholder tokens
            let inner = val_text.trim_matches(|c| c == '"' || c == '\'');
            if inner.trim().is_empty()
                || inner.eq_ignore_ascii_case("your_api_key_here")
                || inner.eq_ignore_ascii_case("placeholder")
                || inner.eq_ignore_ascii_case("todo")
                || inner.eq_ignore_ascii_case("changeme")
            {
                return false;
            }

            // Meaningful secret literal length
            inner.len() >= 6
        } else {
            true
        }
    }

    fn validate_eval_match<D: Doc>(node_match: &NodeMatch<'_, D>) -> bool {
        let env = node_match.get_env();
        if let Some(arg) = env.get_match("ARG") {
            let arg_kind = arg.kind();
            let arg_text = arg.text();

            // If the argument is a plain string literal without f-string interpolation,
            // it is static code and not dynamic eval injection.
            let is_fstring = arg_text.starts_with("f\"")
                || arg_text.starts_with("f'")
                || arg.children().any(|c| c.kind() == "interpolation");

            if (arg_kind == "string" || arg_kind == "string_literal") && !is_fstring {
                return false;
            }

            true
        } else {
            true
        }
    }

    fn validate_command_injection_match<D: Doc>(node_match: &NodeMatch<'_, D>) -> bool {
        let text = node_match.text();
        // Safe if shell=False is explicitly specified
        if text.contains("shell=False") {
            return false;
        }
        true
    }
}

/// Catalog rule pack collection containing migrated high-value structural rules.
#[derive(Debug, Clone)]
pub struct RulePack {
    pub rules: Vec<StructuralRule>,
}

impl RulePack {
    pub fn new(rules: Vec<StructuralRule>) -> Self {
        Self { rules }
    }

    /// Constructs the default migrated high-value catalog rule pack.
    pub fn default_migrated_rules() -> Self {
        let mut rules = Vec::new();

        // 1. BK-AI-INJ-001 (SQL Injection)
        let sql_inj = StructuralRule::new(
            "BK-AI-INJ-001",
            StructuralLanguage::Python,
            "$OBJ.execute(f\"$$$STR\")",
            "CWE-89",
            NormalizedSeverity::High,
            "SQL query constructed via dynamic string interpolation/formatting passed directly to execution",
            Some("$OBJ.execute(\"SELECT ... %s\", (param,))".to_string()),
        )
        .with_additional_pattern("execute(f\"$$$STR\")")
        .with_additional_pattern("$OBJ.execute($$$A + $$$B)")
        .with_additional_pattern("execute($$$A + $$$B)")
        .with_additional_pattern("$OBJ.execute($STR.format($$$ARGS))")
        .with_additional_pattern("execute($STR.format($$$ARGS))")
        .with_additional_pattern("$OBJ.execute($STR % $$$ARGS)")
        .with_additional_pattern("execute($STR % $$$ARGS)");
        rules.push(sql_inj);

        // 2. BK-AI-INJ-002 (Command Injection)
        let cmd_inj = StructuralRule::new(
            "BK-AI-INJ-002",
            StructuralLanguage::Python,
            "subprocess.run($CMD, shell=True)",
            "CWE-78",
            NormalizedSeverity::Critical,
            "Command execution with shell=True and dynamic arguments enables shell injection",
            Some("subprocess.run([\"cmd\", arg], shell=False)".to_string()),
        )
        .with_additional_pattern("subprocess.run($CMD, $A, shell=True)")
        .with_additional_pattern("subprocess.run($CMD, shell=True, $A)")
        .with_additional_pattern("subprocess.Popen($CMD, shell=True)")
        .with_additional_pattern("subprocess.Popen($CMD, $A, shell=True)")
        .with_additional_pattern("subprocess.Popen($CMD, shell=True, $A)")
        .with_additional_pattern("subprocess.call($CMD, shell=True)")
        .with_additional_pattern("subprocess.call($CMD, $A, shell=True)")
        .with_additional_pattern("subprocess.check_output($CMD, shell=True)")
        .with_additional_pattern("subprocess.check_output($CMD, $A, shell=True)");
        rules.push(cmd_inj);

        // 3. BK-AI-SEC-001 (Hardcoded Secret Assignment)
        let sec_rule = StructuralRule::new(
            "BK-AI-SEC-001",
            StructuralLanguage::Python,
            "$VAR = $VAL",
            "CWE-798",
            NormalizedSeverity::High,
            "Hardcoded sensitive secret or API key credential assigned directly in source code",
            Some("$VAR = os.environ.get(\"SECRET_KEY\")".to_string()),
        );
        rules.push(sec_rule);

        // 4. BK-AI-LNG-001 (Insecure Dynamic Eval)
        let eval_rule = StructuralRule::new(
            "BK-AI-LNG-001",
            StructuralLanguage::Python,
            "eval($ARG)",
            "CWE-95",
            NormalizedSeverity::High,
            "Dynamic evaluation of untrusted expression via eval() or exec()",
            None,
        )
        .with_additional_pattern("exec($ARG)");
        rules.push(eval_rule);

        Self { rules }
    }

    /// Computes deterministic SHA256 digest of all rules in this pack.
    pub fn pack_hash(&self) -> String {
        let mut hasher = Sha256::new();
        for r in &self.rules {
            hasher.update(r.rule_id.as_bytes());
            hasher.update(r.language.as_str().as_bytes());
            hasher.update(r.pattern.as_bytes());
            hasher.update(r.cwe.as_bytes());
            for p in &r.additional_patterns {
                hasher.update(p.as_bytes());
            }
        }
        crate::to_hex(hasher.finalize())
    }

    /// Finds all rules applicable to the given language.
    pub fn rules_for_language(&self, lang: StructuralLanguage) -> Vec<&StructuralRule> {
        self.rules.iter().filter(|r| r.language == lang).collect()
    }
}

impl Default for RulePack {
    fn default() -> Self {
        Self::default_migrated_rules()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_pack_hash_stability() {
        let pack1 = RulePack::default_migrated_rules();
        let pack2 = RulePack::default_migrated_rules();
        assert_eq!(pack1.pack_hash(), pack2.pack_hash());
        assert_eq!(pack1.pack_hash().len(), 64);
    }

    #[test]
    fn test_rule_pack_contains_all_migrated_rules() {
        let pack = RulePack::default_migrated_rules();
        let rule_ids: Vec<&str> = pack.rules.iter().map(|r| r.rule_id.as_str()).collect();
        assert!(rule_ids.contains(&"BK-AI-INJ-001"));
        assert!(rule_ids.contains(&"BK-AI-INJ-002"));
        assert!(rule_ids.contains(&"BK-AI-SEC-001"));
        assert!(rule_ids.contains(&"BK-AI-LNG-001"));
    }
}
