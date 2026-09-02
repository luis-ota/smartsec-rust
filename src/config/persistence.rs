use crate::config::execution_type::ExecutionType;
use crate::config::llm_config::LlmConfig;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PersistedConfig {
    pub target_url: String,
    #[serde(default)]
    pub active_tools: Vec<String>,
    pub execution_type: ExecutionType,
    pub llm: LlmConfig,
    pub use_real_nuclei: bool,
    #[serde(default)]
    pub demo_mode: bool,
}

impl Default for PersistedConfig {
    fn default() -> Self {
        Self {
            target_url: String::new(),
            active_tools: Vec::new(),
            execution_type: ExecutionType::Assisted,
            llm: LlmConfig::default(),
            use_real_nuclei: false,
            demo_mode: false,
        }
    }
}

fn config_path() -> PathBuf {
    let base = dirs::config_dir().unwrap_or_else(|| PathBuf::from("."));
    base.join("smartsec").join("config.toml")
}

pub fn load_config_file() -> PersistedConfig {
    let path = config_path();
    if path.exists() {
        if let Ok(content) = fs::read_to_string(&path) {
            if let Ok(cfg) = toml::from_str(&content) {
                return cfg;
            }
        }
    }
    PersistedConfig::default()
}

pub fn load_config_file_from(path: &std::path::Path) -> Result<PersistedConfig, String> {
    let content = fs::read_to_string(path)
        .map_err(|error| format!("não foi possível ler o arquivo de configuração: {error}"))?;
    toml::from_str(&content)
        .map_err(|error| format!("configuração TOML inválida: {error}"))
}

pub fn save_config_file(cfg: &PersistedConfig) -> std::io::Result<()> {
    let path = config_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut cfg_no_key = cfg.clone();
    cfg_no_key.llm.api_key = String::new();
    let content = toml::to_string_pretty(&cfg_no_key).map_err(std::io::Error::other)?;
    fs::write(&path, content)
}

const KEYRING_SERVICE: &str = "smartsec";
const KEYRING_USERNAME: &str = "llm-api-key";

pub fn save_api_key(key: &str) -> Result<(), keyring::Error> {
    let entry = keyring::Entry::new(KEYRING_SERVICE, KEYRING_USERNAME)?;
    if key.is_empty() {
        let _ = entry.delete_credential();
    } else {
        entry.set_password(key)?;
    }
    Ok(())
}

pub fn load_api_key() -> Result<String, keyring::Error> {
    let entry = keyring::Entry::new(KEYRING_SERVICE, KEYRING_USERNAME)?;
    entry.get_password()
}

impl From<crate::config::Configuration> for PersistedConfig {
    fn from(c: crate::config::Configuration) -> Self {
        Self {
            target_url: c.target_url,
            active_tools: c.active_tools,
            execution_type: c.execution_type,
            llm: c.llm,
            use_real_nuclei: c.use_real_nuclei,
            demo_mode: c.demo_mode,
        }
    }
}

impl From<&crate::config::Configuration> for PersistedConfig {
    fn from(c: &crate::config::Configuration) -> Self {
        Self {
            target_url: c.target_url.clone(),
            active_tools: c.active_tools.clone(),
            execution_type: c.execution_type,
            llm: c.llm.clone(),
            use_real_nuclei: c.use_real_nuclei,
            demo_mode: c.demo_mode,
        }
    }
}
