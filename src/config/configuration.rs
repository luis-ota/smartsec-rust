use crate::config::execution_type::ExecutionType;
use crate::config::llm_config::LlmConfig;
use crate::tools::manifest::ToolManifest;
use crate::tools::registry::ToolRegistry;
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
    pub nuclei_templates_path: Option<String>,
    pub nuclei_templates_commit: Option<String>,
    /// Ferramentas adicionais declaradas em `[[tools]]` no TOML.
    pub tools: Vec<ToolManifest>,
    pub output_file: Option<String>,
    pub output_dir: Option<String>,
    /// Limiar da regra automática de interrupção (REQ05): quantidade de
    /// vulnerabilidades críticas que interrompe a varredura. `0` desativa.
    pub max_critical_findings: usize,
    /// Diretório do projeto analisado pelo agente de código (issue #76).
    ///
    /// `None` significa "diretório atual": o SmartSec é uma CLI e espera ser
    /// iniciado no workdir da aplicação auditada. Mesmo quando ausente, o valor
    /// efetivo é canonicalizado e registrado no log estruturado e no relatório,
    /// para que a auditoria saiba qual árvore foi lida.
    pub project_dir: Option<String>,
    pub show_help: bool,
    pub show_version: bool,
}

impl Configuration {
    pub fn load(args: &[String]) -> Result<Self> {
        let config = Self::load_unvalidated();
        let mut config = config;
        config.parse_args(args)?;
        config.llm.validate().map_err(anyhow::Error::msg)?;
        config.validate_tools().map_err(anyhow::Error::msg)?;
        Ok(config)
    }

    pub fn load_unvalidated() -> Self {
        crate::config::persistence::load_config_file().into()
    }

    /// Carrega a configuração para a TUI **sem** abortar quando ela é inválida.
    ///
    /// A TUI precisa abrir justamente para permitir corrigir o que está
    /// errado: abortar deixa o operador sem caminho, porque a tela que
    /// resolve o problema é a própria que não abre. O modo headless continua
    /// validando e falhando, por [`Self::load`].
    ///
    /// Devolve a configuração e a lista de problemas encontrados, para que a
    /// interface consiga exibi-los em vez de imprimi-los e sair.
    pub fn load_for_tui() -> Result<(Self, Vec<String>), String> {
        let mut config = Self::load_unvalidated();
        config
            .parse_args(&[])
            .map_err(|error| format!("{error:#}"))?;
        let problems = config.validation_problems();
        Ok((config, problems))
    }

    /// Lista os problemas de configuração **sem** interrompê-los.
    ///
    /// Reúne os dois pontos que abortam o fluxo — a LLM e as ferramentas
    /// registradas — na ordem em que o operador precisa corrigir. A ordem
    /// importa: sem chave de LLM remota não há análise, e sem ferramenta
    /// válida não há varredura, mas a segunda correção depende da primeira
    /// quando o operador ainda nem chegou a configurá-la.
    pub fn validation_problems(&self) -> Vec<String> {
        let mut problems = Vec::new();
        if let Err(error) = self.llm.validate() {
            problems.push(format!("IA: {error}"));
        }
        if let Err(error) = self.validate_tools() {
            problems.push(format!("Ferramentas: {error}"));
        }
        problems
    }

    pub fn load_from_path(path: &std::path::Path) -> Result<Self> {
        let config =
            crate::config::persistence::load_config_file_from(path).map_err(anyhow::Error::msg)?;
        let config: Self = config.into();
        config.validate_tools().map_err(anyhow::Error::msg)?;
        Ok(config)
    }

    /// Valida as ferramentas registradas em `[[tools]]` contra o catálogo,
    /// produzindo erro acionável em pt-BR quando a configuração é inválida.
    pub fn validate_tools(&self) -> Result<(), String> {
        ToolRegistry::with_configured(&self.tools)
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    pub fn parse_args(&mut self, args: &[String]) -> Result<()> {
        let mut index = 0;
        while index < args.len() {
            match args[index].as_str() {
                "-h" | "--help" => self.show_help = true,
                "-v" | "--version" => self.show_version = true,
                "-a" | "--auto" => self.execution_type = ExecutionType::Auto,
                "-u" | "--url" => self.target_url = next_argument(args, &mut index, "--url")?,
                "-o" | "--output" => {
                    self.output_file = Some(next_argument(args, &mut index, "--output")?);
                }
                "--output-dir" => {
                    self.output_dir = Some(next_argument(args, &mut index, "--output-dir")?);
                }
                "--max-critical-findings" => {
                    let value = next_argument(args, &mut index, "--max-critical-findings")?;
                    self.max_critical_findings = value
                        .trim()
                        .parse()
                        .map_err(|_| {
                            anyhow::anyhow!(
                                "--max-critical-findings exige um número inteiro de 0 em diante (0 desativa a regra)"
                            )
                        })?;
                }
                "--project" => {
                    self.project_dir = Some(next_argument(args, &mut index, "--project")?);
                }
                "-p" | "--provider" => {
                    let provider = next_argument(args, &mut index, "--provider")?;
                    self.llm.provider = match provider.to_ascii_lowercase().as_str() {
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

    pub fn save(&self) -> Result<(), String> {
        crate::config::persistence::save_config_file(
            &crate::config::persistence::PersistedConfig::from(self),
        )
        .map_err(|error| format!("não foi possível salvar a configuração: {error}"))?;
        crate::config::persistence::save_api_key(&self.llm.api_key)
            .map_err(|error| format!("não foi possível atualizar a chave no keyring: {error}"))?;
        Ok(())
    }

    pub fn config_dir() -> PathBuf {
        let base = dirs::config_dir().unwrap_or_else(|| PathBuf::from("."));
        base.join("smartsec")
    }

    /// Diretório do projeto analisado, com padrão no diretório atual.
    ///
    /// O caminho devolvido é o que o agente de código vai canonicalizar e abrir
    /// como raiz do sandbox; a validação real acontece em
    /// `code_agent::workspace::Workspace::open`, que exige um diretório
    /// existente e legível.
    pub fn effective_project_dir(&self) -> PathBuf {
        self.project_dir
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map_or_else(|| PathBuf::from("."), PathBuf::from)
    }
}

impl Default for Configuration {
    fn default() -> Self {
        crate::config::persistence::PersistedConfig::default().into()
    }
}

impl From<crate::config::persistence::PersistedConfig> for Configuration {
    fn from(p: crate::config::persistence::PersistedConfig) -> Self {
        let mut llm = p.llm.clone();
        if llm.base_url.is_empty() {
            llm.base_url = llm.provider.default_base_url().to_string();
        }
        if llm.model.is_empty()
            || (llm.provider == crate::config::llm_config::LlmProviderKind::Ollama
                && llm.model == "local")
        {
            llm.model = llm.provider.default_model().to_string();
        }
        if llm.api_key.is_empty() {
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
            nuclei_templates_path: p.nuclei_templates_path,
            nuclei_templates_commit: p.nuclei_templates_commit,
            tools: p.tools,
            output_file: p.output_file,
            output_dir: p.output_dir,
            max_critical_findings: p.max_critical_findings,
            project_dir: p.project_dir,
            show_help: false,
            show_version: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::llm_config::LlmProviderKind;

    /// Criterio de aceite 1: uma configuracao de IA remota sem chave precisa
    /// ser **um aviso**, nao um erro fatal. E a tela de Configurar IA que
    /// resolve o problema, entao abortar nela deixa o operador sem caminho.
    #[test]
    fn remote_llm_without_credentials_is_a_problem_not_a_failure() {
        let config = LlmConfig {
            provider: LlmProviderKind::OpenAI,
            base_url: "https://api.openai.com/v1".to_string(),
            model: "gpt-4o".to_string(),
            api_key: String::new(),
            remote_consent: true,
            ..LlmConfig::default()
        };

        assert!(config.validate().is_err(), "o headless precisa recusar");

        let problems = Configuration {
            target_url: "http://alvo.local".to_string(),
            llm: config,
            ..Configuration::default()
        }
        .validation_problems();

        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(problems[0].contains("credenciais"), "{problems:?}");
    }

    /// Uma configuracao valida nao produz aviso nenhum: sem isso, a TUI
    /// anunciaria um problema que nao existe.
    #[test]
    fn a_valid_configuration_produces_no_problem() {
        let config = Configuration {
            target_url: "http://alvo.local".to_string(),
            ..Configuration::default()
        };

        assert!(config.validation_problems().is_empty());
    }

    /// A lista junta a IA e as ferramentas, porque abortar em qualquer uma
    /// delas produzia a mesma TUI fechada.
    #[test]
    fn problems_from_several_sources_are_all_reported() {
        let config = Configuration {
            target_url: "http://alvo.local".to_string(),
            llm: LlmConfig {
                provider: LlmProviderKind::OpenAI,
                base_url: "https://api.openai.com/v1".to_string(),
                model: "gpt-4o".to_string(),
                api_key: String::new(),
                remote_consent: true,
                ..LlmConfig::default()
            },
            tools: vec![ToolManifest {
                name: "ScannerQuebrado".to_string(),
                description: "Scanner".to_string(),
                category: "DAST".to_string(),
                image: "exemplo/quebrado:1".to_string(),
                version: "1.0".to_string(),
                runner: "runner-inexistente".to_string(),
                parser: "generic-text".to_string(),
                command_template: vec!["scan".to_string(), "{target}".to_string()],
                output_format: "text".to_string(),
                enabled: true,
            }],
            ..Configuration::default()
        };

        let problems = config.validation_problems();

        assert!(problems.len() >= 2, "{problems:?}");
        assert!(
            problems.iter().any(|p| p.starts_with("IA:")),
            "{problems:?}"
        );
        assert!(
            problems.iter().any(|p| p.starts_with("Ferramentas:")),
            "{problems:?}"
        );
    }

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
            "-o".to_string(),
            "out.md".to_string(),
        ];
        let mut config = Configuration::default();
        config.parse_args(&args).unwrap();
        assert_eq!(config.target_url, "http://test.local");
        assert_eq!(config.execution_type, ExecutionType::Auto);
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

    #[test]
    fn minimal_toml_uses_provider_defaults() {
        let persisted: crate::config::persistence::PersistedConfig =
            toml::from_str("target_url = \"http://test.local\"\n[llm]\nprovider = \"ollama\"\n")
                .unwrap();
        assert_eq!(persisted.execution_type, ExecutionType::Assisted);
        let config = Configuration::from(persisted);
        assert_eq!(config.target_url, "http://test.local");
        assert_eq!(
            config.llm.provider,
            crate::config::llm_config::LlmProviderKind::Ollama
        );
        assert_eq!(config.llm.base_url, "http://localhost:11434/v1");
        assert_eq!(config.llm.model, "llama3.2:1b");
        assert!(config.llm.validate().is_ok());
    }

    #[test]
    fn loads_tools_declared_in_the_toml() {
        let path =
            std::env::temp_dir().join(format!("smartsec-tools-valid-{}.toml", std::process::id()));
        std::fs::write(
            &path,
            "target_url = \"http://test.local\"\n\
             [llm]\nprovider = \"ollama\"\n\
             [[tools]]\n\
             name = \"ScannerExemplo\"\n\
             description = \"Scanner de servidores web\"\n\
             category = \"DAST\"\n\
             image = \"example/scanner:1\"\n\
             version = \"1.0\"\n\
             runner = \"generic\"\n\
             parser = \"generic-text\"\n\
             command_template = [\"zap\", \"-host\", \"{target}\"]\n\
             output_format = \"text\"\n",
        )
        .unwrap();

        let config = Configuration::load_from_path(&path).unwrap();

        assert_eq!(config.tools.len(), 1);
        assert_eq!(config.tools[0].name, "ScannerExemplo");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn malformed_toml_in_the_tools_section_is_reported() {
        let path = std::env::temp_dir().join(format!(
            "smartsec-tools-malformed-{}.toml",
            std::process::id()
        ));
        std::fs::write(
            &path,
            "target_url = \"http://test.local\"\n\
             [llm]\nprovider = \"ollama\"\n\
             [[tools]]\n\
             name = \"ScannerExemplo\n\
             runner = \"generic\"\n",
        )
        .unwrap();

        let error = Configuration::load_from_path(&path)
            .unwrap_err()
            .to_string();

        assert!(error.contains("configuração TOML inválida"), "{error}");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn invalid_tool_configuration_fails_with_actionable_message() {
        let path = std::env::temp_dir().join(format!(
            "smartsec-tools-invalid-{}.toml",
            std::process::id()
        ));
        std::fs::write(
            &path,
            "target_url = \"http://test.local\"\n\
             [llm]\nprovider = \"ollama\"\n\
             [[tools]]\n\
             name = \"Nmap\"\n\
             description = \"Duplicada\"\n\
             category = \"RECON\"\n\
             image = \"example/nmap:1\"\n\
             version = \"1.0\"\n\
             runner = \"generic\"\n\
             parser = \"generic-text\"\n\
             command_template = [\"nmap\", \"{target}\"]\n\
             output_format = \"text\"\n",
        )
        .unwrap();

        let error = Configuration::load_from_path(&path)
            .unwrap_err()
            .to_string();

        assert!(error.contains("duplicada"), "{error}");
        assert!(error.contains("Nmap"), "{error}");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn explicit_llm_values_are_preserved() {
        let persisted: crate::config::persistence::PersistedConfig = toml::from_str(
            "target_url = \"http://test.local\"\nexecution_type = \"Auto\"\n\
             [llm]\nprovider = \"OpenAI\"\nbase_url = \"https://api.openai.com/v1\"\n\
             model = \"gpt-4o\"\n",
        )
        .unwrap();
        let config = Configuration::from(persisted);
        assert_eq!(config.execution_type, ExecutionType::Auto);
        assert_eq!(config.llm.base_url, "https://api.openai.com/v1");
        assert_eq!(config.llm.model, "gpt-4o");
    }
}
