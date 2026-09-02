use crate::config::execution_type::ExecutionType;
use crate::config::llm_config::LlmConfig;
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
}

impl Configuration {
    pub fn load(_args: &[String]) -> Result<Self> {
        let config = Self::load_unvalidated();
        config.llm.validate().map_err(anyhow::Error::msg)?;
        Ok(config)
    }

    pub fn load_unvalidated() -> Self {
        crate::config::persistence::load_config_file().into()
    }

    pub fn load_from_path(path: &std::path::Path) -> Result<Self> {
        let config = crate::config::persistence::load_config_file_from(path)
            .map_err(anyhow::Error::msg)?;
        let config: Self = config.into();
        Ok(config)
    }

    pub fn validate_target(&self) -> Result<(), String> {
        let target = self.target_url.trim();
        if target.is_empty() || target.chars().any(char::is_whitespace) {
            return Err("o alvo não pode estar vazio nem conter espaços".to_string());
        }
        if target.contains("://") && !target.starts_with("http://") && !target.starts_with("https://") {
            return Err("o alvo deve usar HTTP ou HTTPS".to_string());
        }
        let normalized = if target.starts_with("http://") || target.starts_with("https://") {
            target.to_owned()
        } else {
            format!("http://{target}")
        };
        let url = reqwest::Url::parse(&normalized)
            .map_err(|_| "o alvo deve ser um IP, domínio ou URL válido".to_string())?;
        let host = url
            .host_str()
            .filter(|host| !host.is_empty())
            .ok_or_else(|| "o alvo deve conter um host válido".to_string())?;
        if host.parse::<std::net::IpAddr>().is_err()
            && (host.starts_with('.')
                || host.ends_with('.')
                || host.contains("..")
                || host.split('.').any(|part| {
                    part.is_empty()
                        || part.starts_with('-')
                        || part.ends_with('-')
                        || !part.chars().all(|character| character.is_ascii_alphanumeric() || character == '-')
                }))
        {
            return Err("o alvo deve ser um IP, domínio ou URL válido".to_string());
        }
        Ok(())
    }

    pub fn save(&self) -> Result<()> {
        self.llm.validate().map_err(anyhow::Error::msg)?;
        if self.llm.is_remote() {
            crate::config::persistence::save_api_key(&self.llm.api_key)?;
        }
        crate::config::persistence::save_config_file(
            &crate::config::persistence::PersistedConfig::from(self),
        )?;
        Ok(())
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
        if llm.api_key.is_empty() && llm.is_remote() {
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
        }
    }
}
