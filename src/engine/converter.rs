use std::path::PathBuf;

use crate::engine::protocol::{
    CoverageReceiptStatus, CoverageReceiptV1, EngineDescriptor, EvidenceCertaintyV1,
    EvidenceItemKind, EvidenceItemV1, FindingKind, FindingStatus, NormalizedCoverageReceipt,
    NormalizedFinding, NormalizedSeverity, NormalizedTargetKind, ProofMethod, ProofV1,
    ReceiptCounts, ReceiptReasonCode, SourceSpanV1, TargetDescriptor,
};
use crate::types::{
    Affectedness, Confidence, CoverageReceipt, CoverageStatus, CveId, EvidenceCertainty,
    EvidenceRef, ExploitabilitySignal, Finding, OperatorStatus, Reachability, Severity, TargetKind,
};

/// Converts a legacy `Finding` into a schema-compliant `FindingV1` (`NormalizedFinding`).
pub fn to_normalized_finding(
    legacy: &Finding,
    run_id: &str,
    snapshot_sha256: &str,
) -> NormalizedFinding {
    let severity = match legacy.severity {
        Severity::Critical => NormalizedSeverity::Critical,
        Severity::High => NormalizedSeverity::High,
        Severity::Medium => NormalizedSeverity::Medium,
        Severity::Low => NormalizedSeverity::Low,
    };

    let evidence_certainty = match legacy.evidence_certainty {
        EvidenceCertainty::Confirmed => EvidenceCertaintyV1::Confirmed,
        EvidenceCertainty::StronglySupported => EvidenceCertaintyV1::StronglySupported,
        EvidenceCertainty::Suspected => EvidenceCertaintyV1::Suspected,
        EvidenceCertainty::PatternIndicator => EvidenceCertaintyV1::PatternIndicator,
        EvidenceCertainty::Unknown => EvidenceCertaintyV1::Unknown,
    };

    let status = match legacy.affectedness {
        Affectedness::ConfirmedAffected => {
            if legacy.evidence_certainty == EvidenceCertainty::Confirmed {
                FindingStatus::Verified
            } else {
                FindingStatus::Suspected
            }
        }
        Affectedness::LikelyAffected | Affectedness::PotentiallyAffected => {
            FindingStatus::Suspected
        }
        Affectedness::NotAffectedWithEvidence => FindingStatus::FalsePositive,
        Affectedness::Unknown | Affectedness::NotAssessed => FindingStatus::Inconclusive,
    };

    let kind = if !legacy.advisory_ids.is_empty()
        || matches!(
            legacy.cve,
            CveId::Php2ShellOom(_) | CveId::Php2ShellStale(_) | CveId::Node2ShellBrotli(_)
        ) {
        FindingKind::KnownAdvisory
    } else if legacy.category == "RESEARCH" {
        FindingKind::ResearchCandidate
    } else {
        FindingKind::Catalog
    };

    let target_kind = match legacy.target_kind {
        TargetKind::PhpRuntime | TargetKind::NodeRuntime | TargetKind::BinaryExecutable => {
            NormalizedTargetKind::Binary
        }
        TargetKind::ComposerManifest
        | TargetKind::ComposerLockfile
        | TargetKind::NodePackageManifest
        | TargetKind::NodeLockfile
        | TargetKind::GoModManifest
        | TargetKind::JavaPomManifest
        | TargetKind::DotnetCsprojManifest
        | TargetKind::RubyGemfileManifest
        | TargetKind::PythonPoetryManifest
        | TargetKind::CargoLockManifest => NormalizedTargetKind::Package,
        TargetKind::NginxConfig
        | TargetKind::ApacheConfig
        | TargetKind::CaddyConfig
        | TargetKind::Dockerfile
        | TargetKind::EnvironmentFile
        | TargetKind::GenericConfigFile
        | TargetKind::McpServerConfig => NormalizedTargetKind::Config,
        _ => NormalizedTargetKind::File,
    };

    let target_path = legacy
        .file_path
        .as_ref()
        .map(|p| p.to_string_lossy().to_string());
    let target_span = legacy.line_number.map(|line| SourceSpanV1 {
        start_line: line as u32,
        end_line: line as u32,
        start_column: None,
        end_column: None,
    });

    let target = TargetDescriptor {
        target_id: if legacy.asset_id.is_empty() {
            legacy
                .file_path
                .as_ref()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|| "unknown-target".to_string())
        } else {
            legacy.asset_id.clone()
        },
        kind: target_kind,
        path: target_path,
        package_purl: None,
        version: if legacy.detected_version_or_pattern.is_empty() {
            None
        } else {
            Some(legacy.detected_version_or_pattern.clone())
        },
        span: target_span,
    };

    let mut evidence = Vec::new();
    if legacy.evidence_refs.is_empty() {
        evidence.push(EvidenceItemV1 {
            kind: EvidenceItemKind::SourceSpan,
            artifact_sha256: snapshot_sha256.to_string(),
            description: if legacy.description.is_empty() {
                "Evidence from scanner observation".to_string()
            } else {
                legacy.description.chars().take(2000).collect()
            },
            reference: None,
            limitations: Vec::new(),
        });
    } else {
        for er in &legacy.evidence_refs {
            evidence.push(EvidenceItemV1 {
                kind: EvidenceItemKind::SourceSpan,
                artifact_sha256: er
                    .sha256
                    .clone()
                    .unwrap_or_else(|| snapshot_sha256.to_string()),
                description: er
                    .snippet
                    .clone()
                    .unwrap_or_else(|| format!("Evidence at {}", er.location))
                    .chars()
                    .take(2000)
                    .collect(),
                reference: Some(er.location.clone()),
                limitations: Vec::new(),
            });
        }
    }

    let proof = if evidence_certainty == EvidenceCertaintyV1::Confirmed {
        Some(ProofV1 {
            method: ProofMethod::StaticInvariant,
            artifact_sha256: snapshot_sha256.to_string(),
            reproduced_on_snapshot: snapshot_sha256.to_string(),
            limitations: Vec::new(),
        })
    } else {
        None
    };

    let title = if legacy.cve.title().trim().is_empty() {
        if legacy.description.trim().is_empty() {
            "Detected vulnerability".to_string()
        } else {
            legacy.description.chars().take(300).collect()
        }
    } else {
        legacy.cve.title().chars().take(300).collect()
    };

    // Serialize full legacy state in extensions for 100% roundtrip restoration
    let mut extensions = serde_json::Map::new();
    extensions.insert(
        "legacy_id".to_string(),
        serde_json::Value::String(legacy.id.clone()),
    );
    extensions.insert(
        "legacy_cve_raw".to_string(),
        serde_json::to_value(&legacy.cve).unwrap_or_default(),
    );
    extensions.insert(
        "legacy_target_kind_raw".to_string(),
        serde_json::to_value(&legacy.target_kind).unwrap_or_default(),
    );
    extensions.insert(
        "detected_version_or_pattern".to_string(),
        serde_json::Value::String(legacy.detected_version_or_pattern.clone()),
    );
    extensions.insert(
        "safe_threshold".to_string(),
        serde_json::Value::String(legacy.safe_threshold.clone()),
    );
    extensions.insert(
        "suggested_remediation".to_string(),
        serde_json::Value::String(legacy.suggested_remediation.clone()),
    );
    extensions.insert(
        "asset_id".to_string(),
        serde_json::Value::String(legacy.asset_id.clone()),
    );
    extensions.insert(
        "category".to_string(),
        serde_json::Value::String(legacy.category.clone()),
    );
    extensions.insert(
        "component_identity".to_string(),
        serde_json::Value::String(legacy.component_identity.clone()),
    );
    if let Some(ref v) = legacy.installed_build {
        extensions.insert(
            "installed_build".to_string(),
            serde_json::Value::String(v.clone()),
        );
    }
    if let Some(ref v) = legacy.package_source {
        extensions.insert(
            "package_source".to_string(),
            serde_json::Value::String(v.clone()),
        );
    }
    if let Some(ref v) = legacy.vendor_advisory {
        extensions.insert(
            "vendor_advisory".to_string(),
            serde_json::Value::String(v.clone()),
        );
    }
    if let Some(ref v) = legacy.vendor_fix_state {
        extensions.insert(
            "vendor_fix_state".to_string(),
            serde_json::Value::String(v.clone()),
        );
    }
    if let Some(ref v) = legacy.runtime_process_identity {
        extensions.insert(
            "runtime_process_identity".to_string(),
            serde_json::Value::String(v.clone()),
        );
    }
    extensions.insert(
        "evidence_digest".to_string(),
        serde_json::Value::String(legacy.evidence_digest.clone()),
    );
    extensions.insert(
        "evidence_refs".to_string(),
        serde_json::to_value(&legacy.evidence_refs).unwrap_or_default(),
    );
    extensions.insert(
        "affectedness".to_string(),
        serde_json::to_value(legacy.affectedness).unwrap_or_default(),
    );
    extensions.insert(
        "reachability".to_string(),
        serde_json::to_value(legacy.reachability).unwrap_or_default(),
    );
    extensions.insert(
        "confidence".to_string(),
        serde_json::to_value(legacy.confidence).unwrap_or_default(),
    );
    extensions.insert(
        "exploitability_signal".to_string(),
        serde_json::to_value(legacy.exploitability_signal).unwrap_or_default(),
    );
    extensions.insert(
        "impact".to_string(),
        serde_json::Value::String(legacy.impact.clone()),
    );
    extensions.insert(
        "supported_checks".to_string(),
        serde_json::to_value(&legacy.supported_checks).unwrap_or_default(),
    );
    extensions.insert(
        "missing_checks".to_string(),
        serde_json::to_value(&legacy.missing_checks).unwrap_or_default(),
    );
    extensions.insert(
        "proposed_remediation_ids".to_string(),
        serde_json::to_value(&legacy.proposed_remediation_ids).unwrap_or_default(),
    );
    extensions.insert(
        "operator_status".to_string(),
        serde_json::to_value(legacy.operator_status).unwrap_or_default(),
    );
    extensions.insert(
        "dedupe_fingerprint".to_string(),
        serde_json::Value::String(legacy.dedupe_fingerprint.clone()),
    );

    NormalizedFinding {
        schema_version: "1.0".to_string(),
        run_id: run_id.to_string(),
        finding_id: if legacy.id.is_empty() {
            legacy.dedupe_fingerprint.clone()
        } else {
            legacy.id.clone()
        },
        fingerprint: if legacy.dedupe_fingerprint.is_empty() {
            None
        } else {
            Some(legacy.dedupe_fingerprint.clone())
        },
        kind,
        status,
        title,
        summary: if legacy.description.is_empty() {
            None
        } else {
            Some(legacy.description.chars().take(5000).collect())
        },
        severity,
        evidence_certainty,
        rule_id: if legacy.detector_id.is_empty() {
            None
        } else {
            Some(legacy.detector_id.clone())
        },
        weakness_ids: Vec::new(),
        advisory_ids: legacy.advisory_ids.clone(),
        engine: EngineDescriptor {
            id: if legacy.detector_id.is_empty() {
                "builtin-scanner".to_string()
            } else {
                legacy.detector_id.clone()
            },
            version: if legacy.detector_version.is_empty() {
                "1.0.0".to_string()
            } else {
                legacy.detector_version.clone()
            },
            rule_pack_sha256: None,
        },
        target,
        source_snapshot_sha256: snapshot_sha256.to_string(),
        evidence,
        proof,
        coverage_receipt_ids: Vec::new(),
        uncertainty_reasons: legacy.uncertainty_reasons.clone(),
        remediation_plan_id: None,
        created_at: if legacy.observation_time.is_empty() {
            chrono::Utc::now().to_rfc3339()
        } else {
            legacy.observation_time.clone()
        },
        updated_at: None,
        extensions,
    }
}

/// Converts a normalized `FindingV1` back into legacy `Finding`, restoring all essential fields.
#[allow(clippy::field_reassign_with_default)]
pub fn from_normalized_finding(normalized: &NormalizedFinding) -> Finding {
    let mut finding = Finding::default();

    // 1. Direct fields from normalized
    finding.id = normalized.finding_id.clone();
    if let Some(ref fp) = normalized.fingerprint {
        finding.dedupe_fingerprint = fp.clone();
    }
    finding.detector_id = normalized.engine.id.clone();
    finding.detector_version = normalized.engine.version.clone();
    finding.observation_time = normalized.created_at.clone();
    finding.advisory_ids = normalized.advisory_ids.clone();
    finding.uncertainty_reasons = normalized.uncertainty_reasons.clone();

    if let Some(ref summary) = normalized.summary {
        finding.description = summary.clone();
    } else {
        finding.description = normalized.title.clone();
    }

    finding.severity = match normalized.severity {
        NormalizedSeverity::Critical => Severity::Critical,
        NormalizedSeverity::High => Severity::High,
        NormalizedSeverity::Medium => Severity::Medium,
        NormalizedSeverity::Low | NormalizedSeverity::Info | NormalizedSeverity::Unknown => {
            Severity::Low
        }
    };

    finding.evidence_certainty = match normalized.evidence_certainty {
        EvidenceCertaintyV1::Confirmed => EvidenceCertainty::Confirmed,
        EvidenceCertaintyV1::StronglySupported => EvidenceCertainty::StronglySupported,
        EvidenceCertaintyV1::Suspected => EvidenceCertainty::Suspected,
        EvidenceCertaintyV1::PatternIndicator => EvidenceCertainty::PatternIndicator,
        EvidenceCertaintyV1::Unknown => EvidenceCertainty::Unknown,
    };

    finding.file_path = normalized.target.path.as_ref().map(PathBuf::from);
    finding.line_number = normalized
        .target
        .span
        .as_ref()
        .map(|s| s.start_line as usize);
    finding.asset_id = normalized.target.target_id.clone();

    finding.cve = CveId::Custom {
        id: normalized
            .rule_id
            .clone()
            .unwrap_or_else(|| normalized.finding_id.clone()),
        title: normalized.title.clone(),
    };

    // 2. Restore exact legacy fields if available in extensions
    if let Some(serde_json::Value::String(id)) = normalized.extensions.get("legacy_id") {
        finding.id = id.clone();
    }
    if let Some(cve_raw) = normalized.extensions.get("legacy_cve_raw") {
        if let Ok(cve) = serde_json::from_value::<CveId>(cve_raw.clone()) {
            finding.cve = cve;
        }
    }
    if let Some(tk_raw) = normalized.extensions.get("legacy_target_kind_raw") {
        if let Ok(tk) = serde_json::from_value::<TargetKind>(tk_raw.clone()) {
            finding.target_kind = tk;
        }
    }
    if let Some(serde_json::Value::String(s)) =
        normalized.extensions.get("detected_version_or_pattern")
    {
        finding.detected_version_or_pattern = s.clone();
    }
    if let Some(serde_json::Value::String(s)) = normalized.extensions.get("safe_threshold") {
        finding.safe_threshold = s.clone();
    }
    if let Some(serde_json::Value::String(s)) = normalized.extensions.get("suggested_remediation") {
        finding.suggested_remediation = s.clone();
    }
    if let Some(serde_json::Value::String(s)) = normalized.extensions.get("category") {
        finding.category = s.clone();
    }
    if let Some(serde_json::Value::String(s)) = normalized.extensions.get("component_identity") {
        finding.component_identity = s.clone();
    }
    if let Some(serde_json::Value::String(s)) = normalized.extensions.get("installed_build") {
        finding.installed_build = Some(s.clone());
    }
    if let Some(serde_json::Value::String(s)) = normalized.extensions.get("package_source") {
        finding.package_source = Some(s.clone());
    }
    if let Some(serde_json::Value::String(s)) = normalized.extensions.get("vendor_advisory") {
        finding.vendor_advisory = Some(s.clone());
    }
    if let Some(serde_json::Value::String(s)) = normalized.extensions.get("vendor_fix_state") {
        finding.vendor_fix_state = Some(s.clone());
    }
    if let Some(serde_json::Value::String(s)) =
        normalized.extensions.get("runtime_process_identity")
    {
        finding.runtime_process_identity = Some(s.clone());
    }
    if let Some(serde_json::Value::String(s)) = normalized.extensions.get("evidence_digest") {
        finding.evidence_digest = s.clone();
    }
    if let Some(ev_refs) = normalized.extensions.get("evidence_refs") {
        if let Ok(refs) = serde_json::from_value::<Vec<EvidenceRef>>(ev_refs.clone()) {
            finding.evidence_refs = refs;
        }
    }
    if let Some(aff_val) = normalized.extensions.get("affectedness") {
        if let Ok(aff) = serde_json::from_value::<Affectedness>(aff_val.clone()) {
            finding.affectedness = aff;
        }
    }
    if let Some(r_val) = normalized.extensions.get("reachability") {
        if let Ok(reach) = serde_json::from_value::<Reachability>(r_val.clone()) {
            finding.reachability = reach;
        }
    }
    if let Some(c_val) = normalized.extensions.get("confidence") {
        if let Ok(conf) = serde_json::from_value::<Confidence>(c_val.clone()) {
            finding.confidence = conf;
        }
    }
    if let Some(e_val) = normalized.extensions.get("exploitability_signal") {
        if let Ok(exp) = serde_json::from_value::<ExploitabilitySignal>(e_val.clone()) {
            finding.exploitability_signal = exp;
        }
    }
    if let Some(serde_json::Value::String(s)) = normalized.extensions.get("impact") {
        finding.impact = s.clone();
    }
    if let Some(checks) = normalized.extensions.get("supported_checks") {
        if let Ok(vec) = serde_json::from_value::<Vec<String>>(checks.clone()) {
            finding.supported_checks = vec;
        }
    }
    if let Some(checks) = normalized.extensions.get("missing_checks") {
        if let Ok(vec) = serde_json::from_value::<Vec<String>>(checks.clone()) {
            finding.missing_checks = vec;
        }
    }
    if let Some(rems) = normalized.extensions.get("proposed_remediation_ids") {
        if let Ok(vec) = serde_json::from_value::<Vec<String>>(rems.clone()) {
            finding.proposed_remediation_ids = vec;
        }
    }
    if let Some(op_val) = normalized.extensions.get("operator_status") {
        if let Ok(op) = serde_json::from_value::<OperatorStatus>(op_val.clone()) {
            finding.operator_status = op;
        }
    }
    if let Some(serde_json::Value::String(fp)) = normalized.extensions.get("dedupe_fingerprint") {
        finding.dedupe_fingerprint = fp.clone();
    }

    if finding.dedupe_fingerprint.is_empty() {
        finding.compute_dedupe_fingerprint();
    }

    finding
}

/// Converts a legacy `CoverageReceipt` into a schema-compliant `CoverageReceiptV1`.
pub fn to_normalized_receipt(
    legacy: &CoverageReceipt,
    run_id: &str,
    snapshot_sha256: &str,
) -> NormalizedCoverageReceipt {
    let (status, reason_codes) = match legacy.status {
        CoverageStatus::Complete => (CoverageReceiptStatus::Evaluated, Vec::new()),
        CoverageStatus::Partial | CoverageStatus::ScanIncomplete => (
            CoverageReceiptStatus::Partial,
            vec![ReceiptReasonCode::Other],
        ),
        CoverageStatus::Unsupported => (
            CoverageReceiptStatus::Unsupported,
            vec![ReceiptReasonCode::UnsupportedLanguage],
        ),
        CoverageStatus::NotRun => (
            CoverageReceiptStatus::NotRun,
            vec![ReceiptReasonCode::EngineMissing],
        ),
        CoverageStatus::Error => (
            CoverageReceiptStatus::Error,
            vec![ReceiptReasonCode::ReadError],
        ),
    };

    let details: Vec<String> = legacy
        .errors
        .iter()
        .chain(legacy.skipped_reasons.iter())
        .cloned()
        .collect();

    CoverageReceiptV1 {
        schema_version: "1.0".to_string(),
        receipt_id: format!("receipt-{}-{}", legacy.scanner_id, legacy.target_id),
        run_id: run_id.to_string(),
        engine_id: legacy.scanner_id.clone(),
        engine_version: legacy.scanner_version.clone(),
        check_id: legacy.scanner_id.clone(),
        target_id: legacy.target_id.clone(),
        snapshot_sha256: snapshot_sha256.to_string(),
        status,
        counts: ReceiptCounts {
            items_discovered: legacy.items_examined + legacy.skipped_reasons.len() as u64,
            items_examined: legacy.items_examined,
            items_excluded: 0,
            items_skipped: legacy.skipped_reasons.len() as u64,
        },
        reason_codes,
        details,
        started_at: legacy.completed_at.clone(),
        completed_at: legacy.completed_at.clone(),
        required_by_policy: Some(false),
        artifact_digests: Vec::new(),
        previous_receipt_id: None,
    }
}

/// Converts a normalized `CoverageReceiptV1` back into legacy `CoverageReceipt`.
pub fn from_normalized_receipt(normalized: &NormalizedCoverageReceipt) -> CoverageReceipt {
    let status = match normalized.status {
        CoverageReceiptStatus::Evaluated | CoverageReceiptStatus::NotApplicable => {
            CoverageStatus::Complete
        }
        CoverageReceiptStatus::Partial => CoverageStatus::Partial,
        CoverageReceiptStatus::Unsupported => CoverageStatus::Unsupported,
        CoverageReceiptStatus::NotRun => CoverageStatus::NotRun,
        CoverageReceiptStatus::Error => CoverageStatus::Error,
    };

    CoverageReceipt {
        scanner_id: normalized.engine_id.clone(),
        scanner_version: normalized.engine_version.clone(),
        target_id: normalized.target_id.clone(),
        status,
        items_examined: normalized.counts.items_examined,
        skipped_reasons: normalized.details.clone(),
        errors: Vec::new(),
        completed_at: normalized.completed_at.clone(),
    }
}
