use crate::engine::protocol::{AnalysisRequest, AnalysisResponse};
use crate::engine::runner::{AnalysisError, CancellationToken};
use crate::types::{ScanProfile, TargetKind};

/// Capabilities advertised by an engine adapter for capability negotiation and sandbox enforcement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterCapabilities {
    pub requires_network: bool,
    pub requires_mutation: bool,
    pub is_isolated: bool,
    pub supports_cancellation: bool,
}

impl Default for AdapterCapabilities {
    fn default() -> Self {
        Self {
            requires_network: false,
            requires_mutation: false,
            is_isolated: true,
            supports_cancellation: true,
        }
    }
}

/// Unified trait implemented by all security engine adapters (Builtin, ast-grep, Tree-sitter, Joern, OSV, etc.).
pub trait AnalyzerAdapter: Send + Sync {
    /// Machine-readable identifier of the engine adapter (e.g. "builtin-scanner", "ast-grep-adapter").
    fn engine_id(&self) -> &str;

    /// SemVer version string of the engine adapter.
    fn engine_version(&self) -> &str;

    /// Scan profiles supported by this adapter.
    fn supported_profiles(&self) -> &[ScanProfile];

    /// Programming languages or file extensions handled by this adapter.
    fn supported_languages(&self) -> &[&str];

    /// Target kinds analyzed by this adapter.
    fn supported_target_kinds(&self) -> &[TargetKind];

    /// Specific check/rule IDs supported by this adapter. Empty if generic.
    fn supported_checks(&self) -> &[&str] {
        &[]
    }

    /// Capabilities and permission requirements of this adapter.
    fn capabilities(&self) -> AdapterCapabilities {
        AdapterCapabilities::default()
    }

    /// Checks if the adapter supports the given scan profile.
    fn can_handle_profile(&self, profile: ScanProfile) -> bool {
        self.supported_profiles().contains(&profile)
    }

    /// Checks if the adapter supports the given programming language.
    fn can_handle_language(&self, lang: &str) -> bool {
        self.supported_languages()
            .iter()
            .any(|l| l.eq_ignore_ascii_case(lang))
    }

    /// Checks if the adapter supports the given target kind.
    fn can_handle_target(&self, target_kind: &TargetKind) -> bool {
        self.supported_target_kinds().contains(target_kind)
    }

    /// Executes the analysis request against the target snapshot, observing budgets and cancellation.
    fn analyze(
        &self,
        request: &AnalysisRequest,
        cancel_token: &CancellationToken,
    ) -> Result<AnalysisResponse, AnalysisError>;
}
