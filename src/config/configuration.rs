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
    pub demo_mode: bool,
    pub output_file: Option<String>,
    pub show_help: bool,
    pub show_version: bool,
}

impl Configuration {
    pub fn load(args: &[String]) -> Result<Self> {
        let persisted = crate::config::persistence::load_config_file();
        let mut config = Self {
            target_url: persisted.target_url.clone(),
            active_tools: persisted.active_tools.clone(),
            provider_mode: format!("{:?}", persisted.llm.provider),
            execution_type: persisted.execution_type,
            llm: persisted.llm.clone(),
            use_real_nuclei: persisted.use_real_nuclei,
            demo_mode: false,
            output_file: None,
            show_help: false,
            show_version: false,
        };

        config.parse_args(args)?;
        Ok(config)
    }

    pub fn parse_args(&mut self, args: &[String]) -> Result<()> {
        let mut i = 0;
        while i < args.len() {
            match args[i].as_str() {
                "-h" | "--help" => {
                    self.show_help = true;
                }
                "-v" | "--version" => {
                    self.show_version = true;
                }
                "-a" | "--auto" => {
                    self.execution_type = ExecutionType::Auto;
                }
                "-d" | "--demo" => {
                    self.demo_mode = true;
                }
                "-u" | "--url" => {
                    if i + 1 < args.len() {
                        i += 1;
                        self.target_url = args[i].clone();
                    }
                }
                "-p" | "--provider" => {
                    if i + 1 < args.len() {
                        i += 1;
                        let provider_str = args[i].to_lowercase();
                        match provider_str.as_str() {
                            "mock" => {
                                self.llm.provider = crate::config::llm_config::LlmProviderKind::Mock;
                            }
                            "ollama" => {
                                self.llm.provider = crate::config::llm_config::LlmProviderKind::Ollama;
                            }
                            "openai" => {
                                self.llm.provider = crate::config::llm_config::LlmProviderKind::OpenAi;
                            }
                            _ => {}
                        }
                        self.provider_mode = format!("{:?}", self.llm.provider);
                    }
                }
                "-o" | "--output" => {
                    if i + 1 < args.len() {
                        i += 1;
                        self.output_file = Some(args[i].clone());
                    }
                }
                _ => {}
            }
            i += 1;
        }
        Ok(())
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
            demo_mode: false,
            output_file: None,
            show_help: false,
            show_version: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cli_url_and_auto() {
        let args = vec!["--url".to_string(), "http://example.com".to_string(), "--auto".to_string()];
        let mut config = Configuration::default();
        config.parse_args(&args).unwrap();
        assert_eq!(config.target_url, "http://example.com");
        assert_eq!(config.execution_type, ExecutionType::Auto);
    }

    #[test]
    fn parse_cli_short_flags() {
        let args = vec![
            "-u".to_string(), "http://test.local".to_string(),
            "-a".to_string(),
            "-d".to_string(),
            "-o".to_string(), "out.md".to_string(),
        ];
        let mut config = Configuration::default();
        config.parse_args(&args).unwrap();
        assert_eq!(config.target_url, "http://test.local");
        assert_eq!(config.execution_type, ExecutionType::Auto);
        assert!(config.demo_mode);
        assert_eq!(config.output_file, Some("out.md".to_string()));
    }

    #[test]
    fn parse_cli_help_and_version() {
        let args_help = vec!["--help".to_string()];
        let mut config1 = Configuration::default();
        config1.parse_args(&args_help).unwrap();
        assert!(config1.show_help);

        let args_ver = vec!["-v".to_string()];
        let mut config2 = Configuration::default();
        config2.parse_args(&args_ver).unwrap();
        assert!(config2.show_version);
    }

    #[test]
    fn parse_cli_provider() {
        let args = vec!["-p".to_string(), "ollama".to_string()];
        let mut config = Configuration::default();
        config.parse_args(&args).unwrap();
        assert_eq!(config.llm.provider, crate::config::llm_config::LlmProviderKind::Ollama);
    }
}
