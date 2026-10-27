pub mod adapter;
pub mod builtin;
pub mod converter;
pub mod protocol;
pub mod registry;
pub mod runner;
pub mod scope;
pub mod snapshot;

pub use adapter::{AdapterCapabilities, AnalyzerAdapter};
pub use builtin::BuiltinScannerAdapter;
pub use converter::{
    from_normalized_finding, from_normalized_receipt, to_normalized_finding, to_normalized_receipt,
};
pub use protocol::{
    AnalysisRequest, AnalysisResponse, CoverageReceiptStatus, CoverageReceiptV1, DiagnosticV1,
    EngineDescriptor, EnginePermissions, EngineStatus, EvidenceCertaintyV1, EvidenceItemKind,
    EvidenceItemV1, FindingKind, FindingStatus, FindingV1, NormalizedCoverageReceipt,
    NormalizedFinding, NormalizedRepairPlan, NormalizedSeverity, NormalizedTargetKind, ProofMethod,
    ProofV1, ProposedActionKind, ProposedActionV1, ReceiptCounts, ReceiptReasonCode,
    RepairApprovalV1, RepairPlanStatus, RepairPlanV1, RepairRiskLevel, RequiredVerificationV1,
    ResourceBudgets, ResourceUsage, SourceSpanV1, TargetDescriptor, VerificationKind,
};
pub use registry::EngineRegistry;
pub use runner::{AnalysisError, CancellationToken, IsolatedRunner};
pub use scope::{ResearchScope, ScopeError};
pub use snapshot::{InventoryStatus, SnapshotFileEntry, SnapshotInventory, TargetSnapshot};
