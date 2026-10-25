use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use crate::engine::adapter::AnalyzerAdapter;
use crate::engine::protocol::{
    AnalysisRequest, AnalysisResponse, CoverageReceiptStatus, CoverageReceiptV1, DiagnosticV1,
    EngineStatus, ReceiptCounts, ReceiptReasonCode, ResourceUsage,
};
use thiserror::Error;

/// Cancellation token to signal cooperative or preemptive interruption of analysis.
#[derive(Debug, Clone, Default)]
pub struct CancellationToken {
    cancelled: Arc<AtomicBool>,
}

impl CancellationToken {
    pub fn new() -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }
}

/// Typed analysis errors adhering to Milestone M1.1 specifications.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AnalysisError {
    #[error("Analysis timed out after {0} seconds")]
    Timeout(u64),

    #[error("Analysis cancelled by token")]
    Cancelled,

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Malformed engine output: {0}")]
    MalformedOutput(String),

    #[error("Unsupported language: {0}")]
    UnsupportedLanguage(String),

    #[error("Output limit exceeded: {actual_bytes} bytes > {max_bytes} bytes")]
    OutputLimitExceeded { actual_bytes: usize, max_bytes: u64 },

    #[error("Memory budget exceeded: {actual_mb} MB > {max_mb} MB")]
    MemoryBudgetExceeded { actual_mb: u64, max_mb: u64 },

    #[error("Engine adapter '{0}' not found")]
    AdapterNotFound(String),

    #[error("Invalid analysis request: {0}")]
    InvalidRequest(String),

    #[error("Execution failed: {0}")]
    ExecutionFailed(String),
}

impl AnalysisError {
    /// Transforms an execution failure/timeout into an honest, schema-compliant partial response.
    pub fn to_partial_response(
        &self,
        request: &AnalysisRequest,
        engine_id: &str,
        engine_version: &str,
    ) -> AnalysisResponse {
        let (status, receipt_status, reason_code, diag_code) = match self {
            AnalysisError::Timeout(_) => (
                EngineStatus::Partial,
                CoverageReceiptStatus::Partial,
                ReceiptReasonCode::Timeout,
                "TIMEOUT",
            ),
            AnalysisError::Cancelled => (
                EngineStatus::Cancelled,
                CoverageReceiptStatus::NotRun,
                ReceiptReasonCode::Cancelled,
                "CANCELLED",
            ),
            AnalysisError::PermissionDenied(_) => (
                EngineStatus::Blocked,
                CoverageReceiptStatus::Error,
                ReceiptReasonCode::AuthBlocked,
                "PERMISSION_DENIED",
            ),
            AnalysisError::UnsupportedLanguage(_) => (
                EngineStatus::Partial,
                CoverageReceiptStatus::Unsupported,
                ReceiptReasonCode::UnsupportedLanguage,
                "UNSUPPORTED_LANGUAGE",
            ),
            AnalysisError::OutputLimitExceeded { .. } => (
                EngineStatus::Error,
                CoverageReceiptStatus::Error,
                ReceiptReasonCode::BudgetExceeded,
                "OUTPUT_LIMIT_EXCEEDED",
            ),
            AnalysisError::MemoryBudgetExceeded { .. } => (
                EngineStatus::Error,
                CoverageReceiptStatus::Error,
                ReceiptReasonCode::BudgetExceeded,
                "MEMORY_LIMIT_EXCEEDED",
            ),
            _ => (
                EngineStatus::Error,
                CoverageReceiptStatus::Error,
                ReceiptReasonCode::Other,
                "EXECUTION_ERROR",
            ),
        };

        let now = chrono::Utc::now().to_rfc3339();
        let receipts = request
            .target_ids
            .iter()
            .enumerate()
            .map(|(i, target_id)| CoverageReceiptV1 {
                schema_version: "1.0".to_string(),
                receipt_id: format!("receipt-{}-{}", request.run_id, i),
                run_id: request.run_id.clone(),
                engine_id: engine_id.to_string(),
                engine_version: engine_version.to_string(),
                check_id: request
                    .check_ids
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "ALL".to_string()),
                target_id: target_id.clone(),
                snapshot_sha256: request.snapshot_sha256.clone(),
                status: receipt_status,
                counts: ReceiptCounts::default(),
                reason_codes: vec![reason_code],
                details: vec![self.to_string()],
                started_at: now.clone(),
                completed_at: now.clone(),
                required_by_policy: Some(false),
                artifact_digests: Vec::new(),
                previous_receipt_id: None,
            })
            .collect();

        AnalysisResponse {
            schema_version: "1.0".to_string(),
            run_id: request.run_id.clone(),
            engine_id: engine_id.to_string(),
            engine_version: engine_version.to_string(),
            snapshot_sha256: request.snapshot_sha256.clone(),
            status,
            findings: Vec::new(),
            receipts,
            diagnostics: vec![DiagnosticV1 {
                code: diag_code.to_string(),
                message: self.to_string(),
                target_id: None,
            }],
            resources: ResourceUsage::default(),
            completed_at: now,
        }
    }
}

/// Isolated runner that enforces timeouts, output bounds, permissions, and cancellation.
pub struct IsolatedRunner;

impl IsolatedRunner {
    pub fn run(
        adapter: &Arc<dyn AnalyzerAdapter>,
        request: &AnalysisRequest,
        cancel_token: &CancellationToken,
    ) -> Result<AnalysisResponse, AnalysisError> {
        // 1. Strict request schema validation
        request.validate().map_err(AnalysisError::InvalidRequest)?;

        // 2. Cancellation check
        if cancel_token.is_cancelled() {
            return Err(AnalysisError::Cancelled);
        }

        // 3. Permission enforcement
        let caps = adapter.capabilities();
        if caps.requires_network && !request.permissions.allow_network {
            return Err(AnalysisError::PermissionDenied(format!(
                "Adapter '{}' requires network access, but permissions.allow_network is false",
                adapter.engine_id()
            )));
        }
        if caps.requires_mutation && !request.permissions.allow_mutation {
            return Err(AnalysisError::PermissionDenied(format!(
                "Adapter '{}' requires mutation privilege, but permissions.allow_mutation is false",
                adapter.engine_id()
            )));
        }

        // 4. Profile validation
        if !adapter.can_handle_profile(request.profile) {
            return Err(AnalysisError::ExecutionFailed(format!(
                "Adapter '{}' does not support scan profile {:?}",
                adapter.engine_id(),
                request.profile
            )));
        }

        // 5. Execution in bounded worker thread with timeout & cancellation polling
        let (tx, rx) = mpsc::channel();
        let adapter_clone = Arc::clone(adapter);
        let request_clone = request.clone();
        let cancel_token_clone = cancel_token.clone();

        std::thread::spawn(move || {
            let result = adapter_clone.analyze(&request_clone, &cancel_token_clone);
            let _ = tx.send(result);
        });

        let timeout_duration = Duration::from_secs(request.budgets.timeout_seconds);
        let start_time = Instant::now();
        let poll_interval = Duration::from_millis(25);

        loop {
            if cancel_token.is_cancelled() {
                return Err(AnalysisError::Cancelled);
            }

            if start_time.elapsed() >= timeout_duration {
                return Err(AnalysisError::Timeout(request.budgets.timeout_seconds));
            }

            match rx.recv_timeout(poll_interval) {
                Ok(result) => {
                    let response = result?;

                    // Validate output limits
                    let serialized = serde_json::to_vec(&response)
                        .map_err(|e| AnalysisError::MalformedOutput(e.to_string()))?;
                    if serialized.len() as u64 > request.budgets.max_output_bytes {
                        return Err(AnalysisError::OutputLimitExceeded {
                            actual_bytes: serialized.len(),
                            max_bytes: request.budgets.max_output_bytes,
                        });
                    }

                    // Validate response schema compliance
                    response
                        .validate()
                        .map_err(AnalysisError::MalformedOutput)?;

                    return Ok(response);
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    // Continue polling loop to check cancellation and timeout
                    continue;
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(AnalysisError::ExecutionFailed(
                        "Worker thread terminated unexpectedly or panicked".to_string(),
                    ));
                }
            }
        }
    }
}
