use crate::config::execution_type::ExecutionType;
use crate::config::llm_config::LlmConfig;
use anyhow::Result;
use std::path::PathBuf;

#[derive(Clone, Debug)]
pub struct Configuration {
    pub target_url: String,
    pub execution_type: ExecutionType,
    pub llm: LlmConfig,
    pub use_real_nmap: bool,
}

impl Configuration {
    pub fn load(_args: &[String]) -> Result<Self> {
        let persisted = crate::config::persistence::load_config_file();
        Ok(Self {
            target_url: persisted.target_url.clone(),
            execution_type: persisted.execution_type,
            llm: persisted.llm.clone(),
            use_real_nmap: persisted.use_real_nmap,
        })
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

    #[allow(dead_code)]
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
            execution_type: p.execution_type,
            llm,
            use_real_nmap: p.use_real_nmap,
        }
    }
}
