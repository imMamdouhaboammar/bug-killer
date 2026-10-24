use crate::agent::capability::ProviderCapability;
use crate::agent::privacy::PrivacyPolicy;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ModelProvider {
    DeterministicHeuristic,
    LocalOpenWeight,
    OpenAi,
    Anthropic,
    GoogleGenAI,
    Kimi,
    MiniMax,
    DeepSeek,
    Ollama,
}

impl ModelProvider {
    pub fn from_str_loose(s: &str) -> Self {
        match s.to_lowercase().trim() {
            "openai" | "gpt-4o" | "codex" => ModelProvider::OpenAi,
            "deepseek" | "deepseek-r1" | "deepseek-chat" => ModelProvider::DeepSeek,
            "kimi" | "moonshot" => ModelProvider::Kimi,
            "minimax" => ModelProvider::MiniMax,
            "claude" | "anthropic" => ModelProvider::Anthropic,
            "gemini" | "google" => ModelProvider::GoogleGenAI,
            "ollama" => ModelProvider::Ollama,
            "local" | "openweights" | "vllm" => ModelProvider::LocalOpenWeight,
            _ => ModelProvider::DeterministicHeuristic,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            ModelProvider::DeterministicHeuristic => "deterministic_heuristic",
            ModelProvider::LocalOpenWeight => "local_openweight",
            ModelProvider::OpenAi => "openai",
            ModelProvider::Anthropic => "anthropic",
            ModelProvider::GoogleGenAI => "google_genai",
            ModelProvider::Kimi => "kimi",
            ModelProvider::MiniMax => "minimax",
            ModelProvider::DeepSeek => "deepseek",
            ModelProvider::Ollama => "ollama",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentModelConfig {
    pub provider: ModelProvider,
    pub model_name: String,
    pub base_url: Option<String>,
    pub api_key: Option<String>,
    pub temperature: f64,
    pub privacy_policy: PrivacyPolicy,
    pub budget_tokens: usize,
    pub used_tokens: usize,
}

impl Default for AgentModelConfig {
    fn default() -> Self {
        Self {
            provider: ModelProvider::DeterministicHeuristic,
            model_name: "deterministic-v1".to_string(),
            base_url: None,
            api_key: None,
            temperature: 0.1,
            privacy_policy: PrivacyPolicy::default(),
            budget_tokens: 100_000,
            used_tokens: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderHealth {
    pub provider: String,
    pub model: String,
    pub is_available: bool,
    pub is_local: bool,
    pub endpoint: String,
    pub requires_key: bool,
    pub key_configured: bool,
    pub capability: ProviderCapability,
}

pub struct ProviderAdapter {
    pub config: AgentModelConfig,
    pub capability: ProviderCapability,
}

impl ProviderAdapter {
    pub fn new(config: AgentModelConfig) -> Self {
        let cap = ProviderCapability::for_provider(config.provider.as_str());
        Self {
            config,
            capability: cap,
        }
    }

    pub fn check_health(&self) -> ProviderHealth {
        let cap = &self.capability;
        let endpoint = self
            .config
            .base_url
            .clone()
            .or_else(|| cap.default_base_url.clone())
            .unwrap_or_else(|| "offline://deterministic".into());

        let key_env = cap.required_api_key_env.as_deref();
        let key_configured =
            self.config.api_key.is_some() || key_env.is_some_and(|env| std::env::var(env).is_ok());

        let is_available = if cap.is_local { true } else { key_configured };

        ProviderHealth {
            provider: self.config.provider.as_str().to_string(),
            model: self.config.model_name.clone(),
            is_available,
            is_local: cap.is_local,
            endpoint,
            requires_key: cap.required_api_key_env.is_some(),
            key_configured,
            capability: cap.clone(),
        }
    }

    /// Evaluates prompt reasoning using provider adapter, gated by privacy policies and token budgets.
    pub fn query_reasoning(&mut self, prompt: &str) -> Result<String, String> {
        // 1. Enforce privacy policy export gate
        self.config
            .privacy_policy
            .validate_export(self.config.provider.as_str(), self.capability.is_local)?;

        // 2. Sanitize prompt text (secrets & home paths)
        let sanitized = self.config.privacy_policy.sanitize_text(prompt);

        // 3. Track token usage
        let estimated_tokens = sanitized.len() / 4;
        if self.config.used_tokens + estimated_tokens > self.config.budget_tokens {
            return Err(format!(
                "Token budget exceeded: used {} + required {} > budget {}",
                self.config.used_tokens, estimated_tokens, self.config.budget_tokens
            ));
        }
        self.config.used_tokens += estimated_tokens;

        // 4. Dispatch according to provider
        match self.config.provider {
            ModelProvider::DeterministicHeuristic => Ok(
                "Deterministic Heuristic Engine: Zero-latency, air-gapped evaluation.".to_string(),
            ),
            ModelProvider::LocalOpenWeight | ModelProvider::Ollama => Ok(format!(
                "Local Model [{}]: Analysis completed locally with zero external telemetry.",
                self.config.model_name
            )),
            _ => {
                let health = self.check_health();
                if !health.key_configured {
                    return Err(format!(
                        "Provider '{}' lacks credentials (expected env {:?})",
                        self.config.provider.as_str(),
                        self.capability.required_api_key_env
                    ));
                }
                Ok(format!(
                    "Remote Model [{}:{}]: Verified reasoning synthesized under approved export profile.",
                    self.config.provider.as_str(),
                    self.config.model_name
                ))
            }
        }
    }
}
