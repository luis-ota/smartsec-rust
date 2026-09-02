use crate::config::execution_type::ExecutionType;
use crate::config::llm_config::LlmConfig;
use anyhow::Result;
use std::path::PathBuf;

fn next_argument(args: &[String], index: &mut usize, name: &str) -> Result<String> {
    *index += 1;
    args.get(*index)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("o argumento {name} exige um valor"))
}

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
        let config = Self::load_unvalidated();
        let mut config = config;
        config.parse_args(args)?;
        config.llm.validate().map_err(anyhow::Error::msg)?;
        Ok(config)
    }

    pub fn load_unvalidated() -> Self {
        crate::config::persistence::load_config_file().into()
    }

    pub fn load_from_path(path: &std::path::Path) -> Result<Self> {
        let config =
            crate::config::persistence::load_config_file_from(path).map_err(anyhow::Error::msg)?;
        let config: Self = config.into();
        Ok(config)
    }

    pub fn parse_args(&mut self, args: &[String]) -> Result<()> {
        let mut index = 0;
        while index < args.len() {
            match args[index].as_str() {
                "-h" | "--help" => self.show_help = true,
                "-v" | "--version" => self.show_version = true,
                "-a" | "--auto" => self.execution_type = ExecutionType::Auto,
                "-d" | "--demo" => self.demo_mode = true,
                "-u" | "--url" => self.target_url = next_argument(args, &mut index, "--url")?,
                "-o" | "--output" => {
                    self.output_file = Some(next_argument(args, &mut index, "--output")?);
                }
                "-p" | "--provider" => {
                    let provider = next_argument(args, &mut index, "--provider")?;
                    self.llm.provider = match provider.to_ascii_lowercase().as_str() {
                        "mock" => crate::config::llm_config::LlmProviderKind::Mock,
                        "ollama" => crate::config::llm_config::LlmProviderKind::Ollama,
                        "openai" => crate::config::llm_config::LlmProviderKind::OpenAI,
                        "nvidia-nim" => crate::config::llm_config::LlmProviderKind::NvidiaNim,
                        "custom" => crate::config::llm_config::LlmProviderKind::Custom,
                        _ => anyhow::bail!("provedor de IA desconhecido: {provider}"),
                    };
                    self.provider_mode = format!("{:?}", self.llm.provider);
                }
                other => anyhow::bail!("argumento desconhecido: {other}"),
            }
            index += 1;
        }
        Ok(())
    }

    pub fn validate_target(&self) -> Result<(), String> {
        let target = self.target_url.trim();
        if target.is_empty() || target.chars().any(char::is_whitespace) {
            return Err("o alvo não pode estar vazio nem conter espaços".to_string());
        }
        if target.contains("://")
            && !target.starts_with("http://")
            && !target.starts_with("https://")
        {
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
                        || !part
                            .chars()
                            .all(|character| character.is_ascii_alphanumeric() || character == '-')
                }))
        {
            return Err("o alvo deve ser um IP, domínio ou URL válido".to_string());
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
            demo_mode: p.demo_mode,
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
        let args = vec![
            "--url".to_string(),
            "http://example.com".to_string(),
            "--auto".to_string(),
        ];
        let mut config = Configuration::default();
        config.parse_args(&args).unwrap();
        assert_eq!(config.target_url, "http://example.com");
        assert_eq!(config.execution_type, ExecutionType::Auto);
    }

    #[test]
    fn parse_cli_short_flags() {
        let args = vec![
            "-u".to_string(),
            "http://test.local".to_string(),
            "-a".to_string(),
            "-d".to_string(),
            "-o".to_string(),
            "out.md".to_string(),
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
        assert_eq!(
            config.llm.provider,
            crate::config::llm_config::LlmProviderKind::Ollama
        );
    }
}
