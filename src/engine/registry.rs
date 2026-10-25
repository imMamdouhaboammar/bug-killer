use std::collections::HashMap;
use std::sync::Arc;

use crate::engine::adapter::AnalyzerAdapter;
use crate::engine::protocol::{AnalysisRequest, AnalysisResponse, EngineStatus};
use crate::engine::runner::{AnalysisError, CancellationToken, IsolatedRunner};
use crate::types::ScanProfile;

/// Engine registry that manages and dispatches registered analyzer adapters.
#[derive(Default, Clone)]
pub struct EngineRegistry {
    adapters: HashMap<String, Arc<dyn AnalyzerAdapter>>,
}

impl EngineRegistry {
    pub fn new() -> Self {
        Self {
            adapters: HashMap::new(),
        }
    }

    /// Registers a new analyzer adapter with the registry.
    pub fn register(&mut self, adapter: Arc<dyn AnalyzerAdapter>) {
        self.adapters
            .insert(adapter.engine_id().to_string(), adapter);
    }

    /// Retrieves an adapter by its unique engine ID.
    pub fn get(&self, engine_id: &str) -> Option<Arc<dyn AnalyzerAdapter>> {
        self.adapters.get(engine_id).cloned()
    }

    /// Lists all currently registered engine adapters.
    pub fn list(&self) -> Vec<Arc<dyn AnalyzerAdapter>> {
        self.adapters.values().cloned().collect()
    }

    /// Finds all adapters capable of executing under the given scan profile.
    pub fn find_for_profile(&self, profile: ScanProfile) -> Vec<Arc<dyn AnalyzerAdapter>> {
        self.adapters
            .values()
            .filter(|a| a.can_handle_profile(profile))
            .cloned()
            .collect()
    }

    /// Dispatches an analysis request to the targeted adapter, enforcing permissions, budgets, and cancellation.
    pub fn dispatch(
        &self,
        request: &AnalysisRequest,
        cancel_token: &CancellationToken,
    ) -> Result<AnalysisResponse, AnalysisError> {
        let adapter = self
            .get(&request.engine_id)
            .ok_or_else(|| AnalysisError::AdapterNotFound(request.engine_id.clone()))?;

        // 1. Permission checks
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

        // 2. Profile compatibility check
        if !adapter.can_handle_profile(request.profile) {
            return Err(AnalysisError::ExecutionFailed(format!(
                "Adapter '{}' does not support scan profile {:?}",
                adapter.engine_id(),
                request.profile
            )));
        }

        IsolatedRunner::run(&adapter, request, cancel_token)
    }

    /// Resilient dispatch that catches non-fatal execution interruptions (timeout, cancellation, blocked permissions)
    /// and turns them into schema-compliant partial responses with honest receipts.
    pub fn dispatch_resilient(
        &self,
        request: &AnalysisRequest,
        cancel_token: &CancellationToken,
    ) -> Result<AnalysisResponse, AnalysisError> {
        let adapter_opt = self.get(&request.engine_id);
        let version = adapter_opt
            .as_ref()
            .map(|a| a.engine_version())
            .unwrap_or("1.0.0");

        match self.dispatch(request, cancel_token) {
            Ok(resp) => Ok(resp),
            Err(AnalysisError::Timeout(secs)) => Ok(AnalysisError::Timeout(secs)
                .to_partial_response(request, &request.engine_id, version)),
            Err(AnalysisError::Cancelled) => Ok(AnalysisError::Cancelled.to_partial_response(
                request,
                &request.engine_id,
                version,
            )),
            Err(AnalysisError::PermissionDenied(ref reason)) => {
                let mut resp = AnalysisError::PermissionDenied(reason.clone()).to_partial_response(
                    request,
                    &request.engine_id,
                    version,
                );
                resp.status = EngineStatus::Blocked;
                Ok(resp)
            }
            Err(err) => Err(err),
        }
    }
}
