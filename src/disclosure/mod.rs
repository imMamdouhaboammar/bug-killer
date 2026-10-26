//! Bug Killer Responsible Disclosure Engine (Milestone M6).
//!
//! Conforms strictly to Chapter 12 and Card M6.1:
//! - Lifecycle state machine with mandatory operator review gate (ADR-010)
//! - Sensitive credential redaction (tokens, cloud keys, passwords, private IPs, database URIs, SSH keys)
//! - Cryptographic operator approval receipts with replay protection (ADR-008)
//! - GitHub Private Vulnerability Reporting (PVR) markdown and JSON draft generation
//! - Append-only tamper-evident audit logging for private disclosure events
//! - Zero outbound network calls during draft authoring (offline invariant)

pub mod approval;
pub mod audit;
pub mod draft;
pub mod redact;
pub mod state;

pub use approval::{DisclosureApprovalManager, DisclosureApprovalReceipt};
pub use audit::{DisclosureAction, DisclosureAuditEvent, DisclosureAuditLogger};
pub use draft::{
    AffectedTarget, ContactChannel, DisclosureDraftBuilder, DisclosurePacket, DisclosureSeverity,
    DisclosureValidationError, ReporterInfo, RootCause, SafeReproduction, SecurityImpact,
    SuggestedMitigation,
};
pub use redact::{RedactionEntry, RedactionManifest, Redactor, SensitivityCategory};
pub use state::{DisclosureLifecycleState, DisclosureStateError};
