use crate::config::execution_type::ExecutionType;
use crate::config::llm_config::LlmConfig;
use crate::config::nuclei_config::NucleiConfig;
use anyhow::Result;
use std::path::PathBuf;

#[derive(Clone, Debug)]
pub struct Configuration {
    pub target_url: String,
    pub active_tools: Vec<String>,
    pub provider_mode: String,
    pub execution_type: ExecutionType,
    pub llm: LlmConfig,
    pub use_real_nuclei: bool,
    pub nuclei: NucleiConfig,
}

impl Configuration {
    pub fn load(_args: &[String]) -> Result<Self> {
        let persisted = crate::config::persistence::load_config_file();
        Ok(Self {
            target_url: persisted.target_url.clone(),
            active_tools: persisted.active_tools.clone(),
            provider_mode: format!("{:?}", persisted.llm.provider),
            execution_type: persisted.execution_type,
            llm: persisted.llm.clone(),
            use_real_nuclei: persisted.use_real_nuclei,
            nuclei: persisted.nuclei.clone(),
        })
    }

    pub fn validate_target(&self) -> Result<(), String> {
        if self.target_url.is_empty() {
            return Err("Target URL is empty".to_string());
        }
        let normalized =
            if self.target_url.starts_with("http://") || self.target_url.starts_with("https://") {
                self.target_url.clone()
            } else {
                format!("http://{}", self.target_url)
            };
        if !(normalized.starts_with("http://") || normalized.starts_with("https://")) {
            return Err("Invalid URL: must start with http:// or https://".to_string());
        }
        let without_scheme = normalized
            .trim_start_matches("http://")
            .trim_start_matches("https://")
            .split('/')
            .next()
            .unwrap_or("");
        let host = without_scheme.split(':').next().unwrap_or("");
        if host.is_empty() {
            return Err("Invalid URL: missing host".to_string());
        }
        Ok(())
    }

    pub fn save(&self) {
        crate::config::persistence::save_config_file(
            &crate::config::persistence::PersistedConfig::from(self),
        );
        if !self.llm.api_key.is_empty()
            && self.llm.provider != crate::config::llm_config::LlmProviderKind::Mock
        {
            let _ = crate::config::persistence::save_api_key(&self.llm.api_key);
        }
    }

    pub fn config_dir() -> PathBuf {
        let base = dirs::config_dir().unwrap_or_else(|| PathBuf::from("."));
        base.join("smartsec")
    }
}

impl Default for Configuration {
    fn default() -> Self {
        crate::config::persistence::load_config_file().into()
    }
}

impl From<crate::config::persistence::PersistedConfig> for Configuration {
    fn from(p: crate::config::persistence::PersistedConfig) -> Self {
        let mut llm = p.llm.clone();
        if llm.api_key.is_empty()
            && llm.provider != crate::config::llm_config::LlmProviderKind::Mock
        {
            if let Ok(key) = crate::config::persistence::load_api_key() {
                llm.api_key = key;
            }
        }
        Self {
            target_url: p.target_url,
            active_tools: p.active_tools,
            provider_mode: format!("{:?}", llm.provider),
            execution_type: p.execution_type,
            llm,
            use_real_nuclei: p.use_real_nuclei,
            nuclei: p.nuclei,
        }
    }
}
