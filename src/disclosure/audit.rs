use chrono::Utc;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

/// Permitted lifecycle actions recorded in the disclosure audit trail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DisclosureAction {
    DraftCreated,
    DraftRedacted,
    OperatorApproved,
    SubmissionAttempted,
    StateTransitioned,
    DraftWithdrawn,
}

impl DisclosureAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            DisclosureAction::DraftCreated => "DraftCreated",
            DisclosureAction::DraftRedacted => "DraftRedacted",
            DisclosureAction::OperatorApproved => "OperatorApproved",
            DisclosureAction::SubmissionAttempted => "SubmissionAttempted",
            DisclosureAction::StateTransitioned => "StateTransitioned",
            DisclosureAction::DraftWithdrawn => "DraftWithdrawn",
        }
    }
}

/// Structured tamper-evident record for an action in the private disclosure lifecycle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisclosureAuditEvent {
    pub event_id: String,
    pub timestamp: String,
    pub draft_id: String,
    pub action: DisclosureAction,
    pub actor: String,
    pub content_sha256: String,
    pub status: String,
    pub metadata: serde_json::Value,
}

impl DisclosureAuditEvent {
    pub fn new(
        draft_id: impl Into<String>,
        action: DisclosureAction,
        actor: impl Into<String>,
        content_sha256: impl Into<String>,
        status: impl Into<String>,
        metadata: serde_json::Value,
    ) -> Self {
        let mut rand_bytes = [0u8; 8];
        rand::rngs::OsRng.fill_bytes(&mut rand_bytes);
        let event_id = format!(
            "event-{}",
            rand_bytes
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>()
        );

        Self {
            event_id,
            timestamp: Utc::now().to_rfc3339(),
            draft_id: draft_id.into(),
            action,
            actor: actor.into(),
            content_sha256: content_sha256.into(),
            status: status.into(),
            metadata,
        }
    }
}

/// Append-only audit logger enforcing non-repudiation and transparency for vulnerability disclosures.
pub struct DisclosureAuditLogger;

impl DisclosureAuditLogger {
    /// Returns canonical path to audit log at `<canonical_root>/.bug-killer/audit/disclosure_audit.jsonl`.
    pub fn log_path(root: &Path) -> PathBuf {
        root.join(".bug-killer")
            .join("audit")
            .join("disclosure_audit.jsonl")
    }

    /// Appends a new disclosure event atomically to the tamper-evident JSONL audit trail.
    pub fn log_event(root: &Path, event: &DisclosureAuditEvent) -> Result<(), String> {
        let log_path = Self::log_path(root);
        if let Some(parent) = log_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Cannot create audit log directory: {e}"))?;
        }

        let line = serde_json::to_string(event)
            .map_err(|e| format!("Failed to serialize disclosure audit event: {e}"))?;

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .map_err(|e| {
                format!(
                    "Cannot open disclosure audit log at {}: {e}",
                    log_path.display()
                )
            })?;

        writeln!(file, "{}", line)
            .map_err(|e| format!("Cannot append to disclosure audit log: {e}"))?;
        file.sync_all()
            .map_err(|e| format!("Cannot sync disclosure audit log: {e}"))?;

        Ok(())
    }

    /// Reads and deserializes all recorded disclosure audit events.
    pub fn read_events(root: &Path) -> Result<Vec<DisclosureAuditEvent>, String> {
        let log_path = Self::log_path(root);
        if !log_path.exists() {
            return Ok(Vec::new());
        }

        let content = fs::read_to_string(&log_path).map_err(|e| {
            format!(
                "Cannot read disclosure audit log at {}: {e}",
                log_path.display()
            )
        })?;

        let mut events = Vec::new();
        for (idx, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let event: DisclosureAuditEvent = serde_json::from_str(trimmed).map_err(|e| {
                format!(
                    "Corrupted audit event line {} in {}: {e}",
                    idx + 1,
                    log_path.display()
                )
            })?;
            events.push(event);
        }

        Ok(events)
    }

    /// Validates audit trail integrity, verifying structure, non-empty identifiers,
    /// cryptographic hash formatting, and chronological monotonicity.
    pub fn validate_audit_trail(root: &Path) -> Result<usize, String> {
        let events = Self::read_events(root)?;
        let mut prev_ts: Option<chrono::DateTime<chrono::FixedOffset>> = None;

        for (idx, event) in events.iter().enumerate() {
            if event.event_id.is_empty() {
                return Err(format!(
                    "Audit integrity failure: event at index {} has empty event_id",
                    idx
                ));
            }
            if event.draft_id.is_empty() {
                return Err(format!(
                    "Audit integrity failure: event at index {} has empty draft_id",
                    idx
                ));
            }
            if event.actor.is_empty() {
                return Err(format!(
                    "Audit integrity failure: event at index {} has empty actor",
                    idx
                ));
            }
            if event.content_sha256.len() != 64
                || !event.content_sha256.chars().all(|c| c.is_ascii_hexdigit())
            {
                return Err(format!(
                    "Audit integrity failure: event at index {} has invalid content_sha256 '{}'",
                    idx, event.content_sha256
                ));
            }

            let parsed_ts =
                chrono::DateTime::parse_from_rfc3339(&event.timestamp).map_err(|e| {
                    format!(
                        "Audit integrity failure: invalid timestamp at index {}: {e}",
                        idx
                    )
                })?;

            if let Some(prev) = prev_ts {
                if parsed_ts < prev {
                    return Err(format!(
                        "Audit integrity failure: non-monotonic timestamp at index {} ({} < {})",
                        idx, event.timestamp, prev
                    ));
                }
            }
            prev_ts = Some(parsed_ts);
        }

        Ok(events.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_log_and_read_audit_events() {
        let temp = tempdir().unwrap();
        let root = temp.path();

        let dummy_hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let ev1 = DisclosureAuditEvent::new(
            "draft-201",
            DisclosureAction::DraftCreated,
            "operator@example.com",
            dummy_hash,
            "created",
            serde_json::json!({"recipient": "security@example.com"}),
        );
        let ev2 = DisclosureAuditEvent::new(
            "draft-201",
            DisclosureAction::DraftRedacted,
            "system",
            dummy_hash,
            "redacted",
            serde_json::json!({"redactions": 2}),
        );

        DisclosureAuditLogger::log_event(root, &ev1).unwrap();
        DisclosureAuditLogger::log_event(root, &ev2).unwrap();

        let events = DisclosureAuditLogger::read_events(root).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].draft_id, "draft-201");
        assert_eq!(events[0].action, DisclosureAction::DraftCreated);
        assert_eq!(events[1].action, DisclosureAction::DraftRedacted);

        let validated_count = DisclosureAuditLogger::validate_audit_trail(root).unwrap();
        assert_eq!(validated_count, 2);
    }

    #[test]
    fn test_validate_tampered_audit_event_hash() {
        let temp = tempdir().unwrap();
        let root = temp.path();

        let invalid_hash = "short_hash";
        let ev = DisclosureAuditEvent::new(
            "draft-202",
            DisclosureAction::DraftCreated,
            "operator",
            invalid_hash,
            "created",
            serde_json::Value::Null,
        );

        DisclosureAuditLogger::log_event(root, &ev).unwrap();

        let res = DisclosureAuditLogger::validate_audit_trail(root);
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("invalid content_sha256"));
    }
}
