use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;

static SECRET_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(sk-[a-zA-Z0-9_\-]{20,}|ghp_[a-zA-Z0-9]{30,}|AKIA[0-9A-Z]{16}|Bearer\s+[A-Za-z0-9\-\._~\+\/]+=*)").unwrap()
});

static USER_HOME_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(/Users/[a-zA-Z0-9_\-]+|/home/[a-zA-Z0-9_\-]+)").unwrap());

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyPolicy {
    pub allow_remote_data_export: bool,
    pub redact_paths: bool,
    pub redact_secrets: bool,
    pub redact_source_code: bool,
    pub allowed_providers: Vec<String>,
}

impl Default for PrivacyPolicy {
    fn default() -> Self {
        Self {
            allow_remote_data_export: false,
            redact_paths: true,
            redact_secrets: true,
            redact_source_code: false,
            allowed_providers: vec!["local".into(), "ollama".into(), "deterministic".into()],
        }
    }
}

impl PrivacyPolicy {
    pub fn new_approved_export(allowed_remote: Vec<String>) -> Self {
        Self {
            allow_remote_data_export: true,
            redact_paths: true,
            redact_secrets: true,
            redact_source_code: false,
            allowed_providers: allowed_remote,
        }
    }

    pub fn sanitize_text(&self, text: &str) -> String {
        let mut sanitized = text.to_string();
        if self.redact_secrets {
            sanitized = SECRET_PATTERN
                .replace_all(&sanitized, "[REDACTED_SECRET]")
                .to_string();
        }
        if self.redact_paths {
            sanitized = USER_HOME_PATTERN
                .replace_all(&sanitized, "$$WORKSPACE_ROOT")
                .to_string();
        }
        sanitized
    }

    pub fn validate_export(&self, provider: &str, is_local: bool) -> Result<(), String> {
        if is_local {
            return Ok(());
        }
        if !self.allow_remote_data_export {
            return Err(format!(
                "Policy Denied: Remote data export is prohibited by default (allow_remote_data_export=false). Provider '{}' requires an approved export profile.",
                provider
            ));
        }
        let prov_lower = provider.to_lowercase();
        if !self
            .allowed_providers
            .iter()
            .any(|p| p.to_lowercase() == prov_lower)
        {
            return Err(format!(
                "Policy Denied: Provider '{}' is not present in approved export providers allowlist: {:?}",
                provider, self.allowed_providers
            ));
        }
        Ok(())
    }
}
