use ast_grep_core::{Doc, Node};
use serde::{Deserialize, Serialize};

use crate::engine::protocol::SourceSpanV1;

/// Precise line and column coordinates of an AST node finding.
/// 1-based indexing: `start_line >= 1`, `start_column >= 1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FindingTargetSpan {
    pub start_line: u32,
    pub end_line: u32,
    pub start_column: u32,
    pub end_column: u32,
}

impl FindingTargetSpan {
    /// Creates a new `FindingTargetSpan`.
    pub fn new(start_line: u32, end_line: u32, start_column: u32, end_column: u32) -> Self {
        Self {
            start_line,
            end_line,
            start_column,
            end_column,
        }
    }

    /// Computes precise 1-based line and character column span from an `ast-grep` AST node.
    pub fn from_node<D: Doc>(node: &Node<'_, D>) -> Self {
        let start = node.start_pos();
        let end = node.end_pos();

        // ast-grep's start_pos.line() is 0-indexed; convert to 1-indexed.
        let start_line = (start.line() + 1) as u32;
        let end_line = (end.line() + 1) as u32;

        // ast-grep's column(&node) is 0-indexed character offset within the line; convert to 1-indexed.
        let start_column = (start.column(node) + 1) as u32;
        let end_column = (end.column(node) + 1) as u32;

        Self {
            start_line,
            end_line,
            start_column,
            end_column,
        }
    }

    /// Converts this span into a schema-compliant `SourceSpanV1`.
    pub fn to_source_span_v1(&self) -> SourceSpanV1 {
        SourceSpanV1 {
            start_line: self.start_line,
            end_line: self.end_line,
            start_column: Some(self.start_column),
            end_column: Some(self.end_column),
        }
    }
}

impl From<FindingTargetSpan> for SourceSpanV1 {
    fn from(span: FindingTargetSpan) -> Self {
        span.to_source_span_v1()
    }
}

impl From<&FindingTargetSpan> for SourceSpanV1 {
    fn from(span: &FindingTargetSpan) -> Self {
        span.to_source_span_v1()
    }
}

impl TryFrom<&SourceSpanV1> for FindingTargetSpan {
    type Error = &'static str;

    fn try_from(span: &SourceSpanV1) -> Result<Self, Self::Error> {
        let start_column = span.start_column.unwrap_or(1);
        let end_column = span.end_column.unwrap_or(1);
        Ok(Self {
            start_line: span.start_line,
            end_line: span.end_line,
            start_column,
            end_column,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ast_grep_core::tree_sitter::LanguageExt;
    use ast_grep_language::SupportLang;

    #[test]
    fn test_finding_target_span_computation() {
        let lang = SupportLang::Python;
        let code = "x = 42\ny = foo(x)\n";
        let root = lang.ast_grep(code);
        let match_node = root.root().find("y = foo(x)").expect("find match");

        let span = FindingTargetSpan::from_node(&match_node);
        assert_eq!(span.start_line, 2);
        assert_eq!(span.end_line, 2);
        assert_eq!(span.start_column, 1);
        assert_eq!(span.end_column, 11);

        let v1 = span.to_source_span_v1();
        assert_eq!(v1.start_line, 2);
        assert_eq!(v1.end_line, 2);
        assert_eq!(v1.start_column, Some(1));
        assert_eq!(v1.end_column, Some(11));
    }
}
