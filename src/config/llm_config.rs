use serde::{Deserialize, Serialize};

const DEFAULT_TIMEOUT_SECS: u64 = 45;
const DEFAULT_MAX_RETRIES: u8 = 2;

fn default_timeout_secs() -> u64 {
    DEFAULT_TIMEOUT_SECS
}

fn default_max_retries() -> u8 {
    DEFAULT_MAX_RETRIES
}

fn default_fallback_base_url() -> String {
    "http://localhost:11434/v1".to_string()
}

fn default_fallback_model() -> String {
    "llama3.1:8b".to_string()
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum LlmProviderKind {
    Mock,
    Ollama,
    NvidiaNim,
    OpenAI,
    Custom,
}

impl LlmProviderKind {
    pub fn default_base_url(&self) -> &str {
        match self {
            LlmProviderKind::Mock => "",
            LlmProviderKind::Ollama => "http://localhost:11434/v1",
            LlmProviderKind::NvidiaNim => "https://integrate.api.nvidia.com/v1",
            LlmProviderKind::OpenAI => "https://api.openai.com/v1",
            LlmProviderKind::Custom => "",
        }
    }

    pub fn default_model(&self) -> &str {
        match self {
            LlmProviderKind::Mock => "local",
            LlmProviderKind::Ollama => "llama3.1:8b",
            LlmProviderKind::NvidiaNim => "meta/llama-3.1-405b-instruct",
            LlmProviderKind::OpenAI => "gpt-4o",
            LlmProviderKind::Custom => "",
        }
    }

    pub fn all_labels() -> Vec<&'static str> {
        vec![
            "Integrado",
            "Ollama",
            "NVIDIA NIM",
            "OpenAI",
            "Personalizado",
        ]
    }

    pub fn from_label(label: &str) -> Self {
        match label {
            "Integrado" => LlmProviderKind::Mock,
            "Ollama" => LlmProviderKind::Ollama,
            "NVIDIA NIM" => LlmProviderKind::NvidiaNim,
            "OpenAI" => LlmProviderKind::OpenAI,
            _ => LlmProviderKind::Custom,
        }
    }

    #[allow(dead_code)]
    pub fn label(&self) -> &'static str {
        match self {
            LlmProviderKind::Mock => "Integrado",
            LlmProviderKind::Ollama => "Ollama",
            LlmProviderKind::NvidiaNim => "NVIDIA NIM",
            LlmProviderKind::OpenAI => "OpenAI",
            LlmProviderKind::Custom => "Personalizado",
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct LlmConfig {
    pub provider: LlmProviderKind,
    pub base_url: String,
    pub model: String,
    #[serde(skip)]
    pub api_key: String,
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
    #[serde(default = "default_max_retries")]
    pub max_retries: u8,
    #[serde(default)]
    pub remote_consent: bool,
    #[serde(default)]
    pub fallback_enabled: bool,
    #[serde(default = "default_fallback_base_url")]
    pub fallback_base_url: String,
    #[serde(default = "default_fallback_model")]
    pub fallback_model: String,
}

impl std::fmt::Debug for LlmConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LlmConfig")
            .field("provider", &self.provider)
            .field("base_url", &self.base_url)
            .field("model", &self.model)
            .field("api_key", &"[OCULTA]")
            .field("timeout_secs", &self.timeout_secs)
            .field("max_retries", &self.max_retries)
            .field("remote_consent", &self.remote_consent)
            .field("fallback_enabled", &self.fallback_enabled)
            .field("fallback_base_url", &self.fallback_base_url)
            .field("fallback_model", &self.fallback_model)
            .finish()
    }
}

impl LlmConfig {
    pub fn is_remote(&self) -> bool {
        match self.provider {
            LlmProviderKind::OpenAI | LlmProviderKind::NvidiaNim => true,
            LlmProviderKind::Mock => false,
            LlmProviderKind::Ollama | LlmProviderKind::Custom => {
                !is_loopback_endpoint(&self.base_url)
            }
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.provider != LlmProviderKind::Mock {
            validate_endpoint(&self.base_url, !self.is_remote())?;
            validate_model(&self.model)?;
        }
        if self.timeout_secs == 0 || self.timeout_secs > DEFAULT_TIMEOUT_SECS {
            return Err("O tempo limite da LLM deve estar entre 1 e 45 segundos".to_string());
        }
        if self.max_retries > 3 {
            return Err("As tentativas da LLM devem estar entre 0 e 3".to_string());
        }
        if self.is_remote() {
            if self.api_key.trim().is_empty() {
                return Err("As credenciais da LLM remota são obrigatórias".to_string());
            }
            if !self.remote_consent {
                return Err(
                    "O consentimento explícito é obrigatório antes do envio remoto de logs"
                        .to_string(),
                );
            }
        }
        if self.fallback_enabled {
            validate_endpoint(&self.fallback_base_url, true)?;
            if !is_loopback_endpoint(&self.fallback_base_url) {
                return Err("O endpoint alternativo do Ollama deve ser local".to_string());
            }
            validate_model(&self.fallback_model)?;
        }
        Ok(())
    }
}

fn validate_model(model: &str) -> Result<(), String> {
    if model.trim().is_empty() || model.chars().any(char::is_whitespace) {
        return Err("O modelo da LLM não pode estar vazio nem conter espaços".to_string());
    }
    Ok(())
}

fn validate_endpoint(endpoint: &str, allow_local_http: bool) -> Result<(), String> {
    let url = reqwest::Url::parse(endpoint)
        .map_err(|_| "A URL do endpoint da LLM é inválida".to_string())?;
    if url.host_str().is_none() || !matches!(url.scheme(), "http" | "https") {
        return Err("O endpoint da LLM deve usar HTTP ou HTTPS e incluir um host".to_string());
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("O endpoint da LLM não deve conter credenciais embutidas".to_string());
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err("O endpoint da LLM não deve conter consulta ou fragmento".to_string());
    }
    if url.scheme() != "https" && !(allow_local_http && is_loopback_endpoint(endpoint)) {
        return Err("O endpoint remoto da LLM deve usar HTTPS".to_string());
    }
    Ok(())
}

fn is_loopback_endpoint(endpoint: &str) -> bool {
    reqwest::Url::parse(endpoint)
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned))
        .is_some_and(|host| matches!(host.as_str(), "localhost" | "127.0.0.1" | "::1"))
}

impl Default for LlmConfig {
    fn default() -> Self {
        let provider = LlmProviderKind::Mock;
        Self {
            provider,
            base_url: provider.default_base_url().to_string(),
            model: provider.default_model().to_string(),
            api_key: String::new(),
            timeout_secs: default_timeout_secs(),
            max_retries: default_max_retries(),
            remote_consent: false,
            fallback_enabled: false,
            fallback_base_url: default_fallback_base_url(),
            fallback_model: default_fallback_model(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_remote_provider_without_https_credentials_or_consent() {
        let mut config = LlmConfig {
            provider: LlmProviderKind::OpenAI,
            base_url: "http://api.openai.com/v1".to_string(),
            model: "gpt-4o".to_string(),
            ..LlmConfig::default()
        };
        assert!(config.validate().unwrap_err().contains("HTTPS"));

        config.base_url = "https://api.openai.com/v1".to_string();
        assert!(config.validate().unwrap_err().contains("credenciais"));

        config.api_key = "test-key".to_string();
        assert!(config.validate().unwrap_err().contains("consentimento"));
        config.remote_consent = true;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn accepts_local_ollama_over_http() {
        let config = LlmConfig {
            provider: LlmProviderKind::Ollama,
            base_url: "http://127.0.0.1:11434/v1".to_string(),
            model: "llama3.1:8b".to_string(),
            ..LlmConfig::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn exposes_provider_labels_in_portuguese() {
        let labels = LlmProviderKind::all_labels();

        assert_eq!(labels[0], "Integrado");
        assert_eq!(labels[4], "Personalizado");
        assert_eq!(
            LlmProviderKind::from_label("Integrado"),
            LlmProviderKind::Mock
        );
        assert_eq!(LlmProviderKind::Custom.label(), "Personalizado");
    }

    #[test]
    fn treats_non_loopback_ollama_as_remote() {
        let mut config = LlmConfig {
            provider: LlmProviderKind::Ollama,
            base_url: "https://ollama.example/v1".to_string(),
            model: "llama3.1:8b".to_string(),
            ..LlmConfig::default()
        };

        assert!(config.validate().unwrap_err().contains("credenciais"));
        config.api_key = "test-key".to_string();
        assert!(config.validate().unwrap_err().contains("consentimento"));
        config.remote_consent = true;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn rejects_non_local_fallback_endpoint() {
        let config = LlmConfig {
            fallback_enabled: true,
            fallback_base_url: "https://ollama.example/v1".to_string(),
            ..LlmConfig::default()
        };

        assert!(config.validate().unwrap_err().contains("deve ser local"));
    }

    #[test]
    fn rejects_endpoint_with_embedded_credentials_or_query() {
        let mut config = LlmConfig {
            provider: LlmProviderKind::OpenAI,
            base_url: "https://user:password@api.openai.com/v1".to_string(),
            model: "gpt-4o".to_string(),
            api_key: "test-key".to_string(),
            remote_consent: true,
            ..LlmConfig::default()
        };

        assert!(config
            .validate()
            .unwrap_err()
            .contains("credenciais embutidas"));
        config.base_url = "https://api.openai.com/v1?key=value".to_string();
        assert!(config
            .validate()
            .unwrap_err()
            .contains("consulta ou fragmento"));
    }

    #[test]
    fn never_serializes_api_key() {
        let config = LlmConfig {
            api_key: "secret-value".to_string(),
            ..LlmConfig::default()
        };
        let serialized = toml::to_string(&config).unwrap();
        assert!(!serialized.contains("secret-value"));
        assert!(!serialized.contains("api_key"));
    }

    #[test]
    fn redacts_api_key_from_debug_output() {
        let config = LlmConfig {
            api_key: "secret-value".to_string(),
            ..LlmConfig::default()
        };

        let debug = format!("{config:?}");

        assert!(!debug.contains("secret-value"));
        assert!(debug.contains("[OCULTA]"));
    }
}
