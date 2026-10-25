use std::fmt;
use std::path::Path;
use std::str::FromStr;

use ast_grep_language::SupportLang;
use serde::{Deserialize, Serialize};

/// Programming languages supported by the Bug Killer structural analysis engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StructuralLanguage {
    Python,
    JavaScript,
    TypeScript,
    Php,
    Go,
    Rust,
}

impl StructuralLanguage {
    /// Returns all supported structural languages.
    pub const fn all() -> &'static [StructuralLanguage] {
        &[
            StructuralLanguage::Python,
            StructuralLanguage::JavaScript,
            StructuralLanguage::TypeScript,
            StructuralLanguage::Php,
            StructuralLanguage::Go,
            StructuralLanguage::Rust,
        ]
    }

    /// Pinned tree-sitter grammar SemVer version for reproducible AST parsing.
    pub fn grammar_version(&self) -> &'static str {
        match self {
            StructuralLanguage::Python => "0.25.0",
            StructuralLanguage::JavaScript => "0.25.0",
            StructuralLanguage::TypeScript => "0.23.2",
            StructuralLanguage::Php => "0.24.2",
            StructuralLanguage::Go => "0.25.0",
            StructuralLanguage::Rust => "0.24.2",
        }
    }

    /// Unique identifier for the grammar and pinned version.
    pub fn grammar_id(&self) -> &'static str {
        match self {
            StructuralLanguage::Python => "tree-sitter-python@0.25.0",
            StructuralLanguage::JavaScript => "tree-sitter-javascript@0.25.0",
            StructuralLanguage::TypeScript => "tree-sitter-typescript@0.23.2",
            StructuralLanguage::Php => "tree-sitter-php@0.24.2",
            StructuralLanguage::Go => "tree-sitter-go@0.25.0",
            StructuralLanguage::Rust => "tree-sitter-rust@0.24.2",
        }
    }

    /// Maps to the corresponding `ast-grep-language` `SupportLang`.
    pub fn to_support_lang(&self) -> SupportLang {
        match self {
            StructuralLanguage::Python => SupportLang::Python,
            StructuralLanguage::JavaScript => SupportLang::JavaScript,
            StructuralLanguage::TypeScript => SupportLang::TypeScript,
            StructuralLanguage::Php => SupportLang::Php,
            StructuralLanguage::Go => SupportLang::Go,
            StructuralLanguage::Rust => SupportLang::Rust,
        }
    }

    /// Canonical lowercase name of the language.
    pub fn as_str(&self) -> &'static str {
        match self {
            StructuralLanguage::Python => "python",
            StructuralLanguage::JavaScript => "javascript",
            StructuralLanguage::TypeScript => "typescript",
            StructuralLanguage::Php => "php",
            StructuralLanguage::Go => "go",
            StructuralLanguage::Rust => "rust",
        }
    }

    /// Detects language from a file path based on standard extensions.
    pub fn detect_from_path(path: &Path) -> Option<Self> {
        let ext = path.extension()?.to_str()?.to_ascii_lowercase();
        match ext.as_str() {
            "py" | "pyi" | "pyw" => Some(StructuralLanguage::Python),
            "js" | "mjs" | "cjs" | "jsx" => Some(StructuralLanguage::JavaScript),
            "ts" | "mts" | "cts" | "tsx" => Some(StructuralLanguage::TypeScript),
            "php" | "phtml" | "php4" | "php5" | "php7" | "phps" => Some(StructuralLanguage::Php),
            "go" => Some(StructuralLanguage::Go),
            "rs" => Some(StructuralLanguage::Rust),
            _ => None,
        }
    }

    /// Detects language from a script's shebang line (`#!...`).
    pub fn detect_from_shebang(content: &str) -> Option<Self> {
        let first_line = content.lines().next()?;
        let trimmed = first_line.trim();
        if !trimmed.starts_with("#!") {
            return None;
        }

        let shebang_lower = trimmed.to_ascii_lowercase();
        if shebang_lower.contains("python") {
            Some(StructuralLanguage::Python)
        } else if shebang_lower.contains("node") || shebang_lower.contains("bun") {
            Some(StructuralLanguage::JavaScript)
        } else if shebang_lower.contains("ts-node") || shebang_lower.contains("deno") {
            Some(StructuralLanguage::TypeScript)
        } else if shebang_lower.contains("php") {
            Some(StructuralLanguage::Php)
        } else {
            None
        }
    }

    /// Combined detection: checks file path extension first, falling back to shebang inspection.
    pub fn detect(path: &Path, content: Option<&str>) -> Option<Self> {
        if let Some(lang) = Self::detect_from_path(path) {
            return Some(lang);
        }
        if let Some(src) = content {
            return Self::detect_from_shebang(src);
        }
        None
    }
}

impl fmt::Display for StructuralLanguage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for StructuralLanguage {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "python" | "py" => Ok(StructuralLanguage::Python),
            "javascript" | "js" | "jsx" | "node" => Ok(StructuralLanguage::JavaScript),
            "typescript" | "ts" | "tsx" => Ok(StructuralLanguage::TypeScript),
            "php" => Ok(StructuralLanguage::Php),
            "go" | "golang" => Ok(StructuralLanguage::Go),
            "rust" | "rs" => Ok(StructuralLanguage::Rust),
            _ => Err(format!("Unsupported structural language: '{}'", s)),
        }
    }
}

impl From<StructuralLanguage> for SupportLang {
    fn from(lang: StructuralLanguage) -> Self {
        lang.to_support_lang()
    }
}

impl TryFrom<SupportLang> for StructuralLanguage {
    type Error = String;

    fn try_from(lang: SupportLang) -> Result<Self, Self::Error> {
        match lang {
            SupportLang::Python => Ok(StructuralLanguage::Python),
            SupportLang::JavaScript => Ok(StructuralLanguage::JavaScript),
            SupportLang::TypeScript | SupportLang::Tsx => Ok(StructuralLanguage::TypeScript),
            SupportLang::Php => Ok(StructuralLanguage::Php),
            SupportLang::Go => Ok(StructuralLanguage::Go),
            SupportLang::Rust => Ok(StructuralLanguage::Rust),
            other => Err(format!(
                "ast-grep language {:?} is not in the active structural suite",
                other
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_detect_from_path() {
        assert_eq!(
            StructuralLanguage::detect_from_path(&PathBuf::from("service.py")),
            Some(StructuralLanguage::Python)
        );
        assert_eq!(
            StructuralLanguage::detect_from_path(&PathBuf::from("client.ts")),
            Some(StructuralLanguage::TypeScript)
        );
        assert_eq!(
            StructuralLanguage::detect_from_path(&PathBuf::from("web.js")),
            Some(StructuralLanguage::JavaScript)
        );
        assert_eq!(
            StructuralLanguage::detect_from_path(&PathBuf::from("index.php")),
            Some(StructuralLanguage::Php)
        );
        assert_eq!(
            StructuralLanguage::detect_from_path(&PathBuf::from("main.go")),
            Some(StructuralLanguage::Go)
        );
        assert_eq!(
            StructuralLanguage::detect_from_path(&PathBuf::from("lib.rs")),
            Some(StructuralLanguage::Rust)
        );
        assert_eq!(
            StructuralLanguage::detect_from_path(&PathBuf::from("file.txt")),
            None
        );
    }

    #[test]
    fn test_detect_from_shebang() {
        assert_eq!(
            StructuralLanguage::detect_from_shebang("#!/usr/bin/env python3\nprint('hi')"),
            Some(StructuralLanguage::Python)
        );
        assert_eq!(
            StructuralLanguage::detect_from_shebang("#!/usr/bin/env node\nconsole.log(1)"),
            Some(StructuralLanguage::JavaScript)
        );
        assert_eq!(
            StructuralLanguage::detect_from_shebang("#!/usr/bin/env php\n<?php echo 1;"),
            Some(StructuralLanguage::Php)
        );
        assert_eq!(
            StructuralLanguage::detect_from_shebang("#!/bin/bash\necho 1"),
            None
        );
    }

    #[test]
    fn test_pinned_grammars() {
        for lang in StructuralLanguage::all() {
            assert!(!lang.grammar_version().is_empty());
            assert!(lang.grammar_id().contains('@'));
            let support_lang = lang.to_support_lang();
            let back = StructuralLanguage::try_from(support_lang).expect("Roundtrip");
            assert_eq!(*lang, back);
        }
    }
}
