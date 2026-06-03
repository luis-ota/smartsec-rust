use serde::{Deserialize, Serialize};

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
            LlmProviderKind::Mock => "mock",
            LlmProviderKind::Ollama => "llama3",
            LlmProviderKind::NvidiaNim => "meta/llama-3.1-405b-instruct",
            LlmProviderKind::OpenAI => "gpt-4o",
            LlmProviderKind::Custom => "",
        }
    }

    pub fn all_labels() -> Vec<&'static str> {
        vec!["Mock", "Ollama", "NVIDIA NIM", "OpenAI", "Custom"]
    }

    pub fn from_label(label: &str) -> Self {
        match label {
            "Mock" => LlmProviderKind::Mock,
            "Ollama" => LlmProviderKind::Ollama,
            "NVIDIA NIM" => LlmProviderKind::NvidiaNim,
            "OpenAI" => LlmProviderKind::OpenAI,
            _ => LlmProviderKind::Custom,
        }
    }

    #[allow(dead_code)]
    pub fn label(&self) -> &'static str {
        match self {
            LlmProviderKind::Mock => "Mock",
            LlmProviderKind::Ollama => "Ollama",
            LlmProviderKind::NvidiaNim => "NVIDIA NIM",
            LlmProviderKind::OpenAI => "OpenAI",
            LlmProviderKind::Custom => "Custom",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LlmConfig {
    pub provider: LlmProviderKind,
    pub base_url: String,
    pub model: String,
    pub api_key: String,
}

impl Default for LlmConfig {
    fn default() -> Self {
        let provider = LlmProviderKind::Mock;
        Self {
            provider,
            base_url: provider.default_base_url().to_string(),
            model: provider.default_model().to_string(),
            api_key: String::new(),
        }
    }
}
