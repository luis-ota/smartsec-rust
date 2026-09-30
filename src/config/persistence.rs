use crate::config::execution_type::ExecutionType;
use crate::config::llm_config::LlmConfig;
use crate::tools::manifest::ToolManifest;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PersistedConfig {
    pub target_url: String,
    #[serde(default)]
    pub active_tools: Vec<String>,
    #[serde(default)]
    pub execution_type: ExecutionType,
    pub llm: LlmConfig,
    #[serde(default)]
    pub nuclei_templates_path: Option<String>,
    #[serde(default)]
    pub nuclei_templates_commit: Option<String>,
    #[serde(default)]
    pub tools: Vec<ToolManifest>,
    #[serde(default)]
    pub output_file: Option<String>,
    #[serde(default)]
    pub output_dir: Option<String>,
}

impl Default for PersistedConfig {
    fn default() -> Self {
        Self {
            target_url: String::new(),
            active_tools: Vec::new(),
            execution_type: ExecutionType::Assisted,
            llm: LlmConfig::default(),
            nuclei_templates_path: None,
            nuclei_templates_commit: None,
            tools: Vec::new(),
            output_file: None,
            output_dir: None,
        }
    }
}

fn config_path() -> PathBuf {
    let base = dirs::config_dir().unwrap_or_else(|| PathBuf::from("."));
    base.join("smartsec").join("config.toml")
}

/// Carrega a configuração global.
///
/// Um arquivo ausente continua devolvendo os padrões. Um arquivo existente com
/// TOML inválido é um erro: devolver `default()` silenciosamente faria a
/// ferramenta perder alvo, ferramentas e provedor sem nenhuma mensagem. O
/// arquivo nunca é sobrescrito por esta leitura.
///
/// A configuração vinda do arquivo global é sempre um piso: `main.rs`
/// sobrepõe `target_url` e as ferramentas selecionadas pela CLI.
pub fn load_config_file() -> PersistedConfig {
    match try_load_config_file() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("[ERRO] {error}");
            PersistedConfig::default()
        }
    }
}

/// Igual a [`load_config_file`], mas devolve o erro em vez de imprimi-lo.
///
/// Permite que a TUI e os testes decidam como apresentar a falha.
pub fn try_load_config_file() -> Result<PersistedConfig, String> {
    try_load_config_file_at(&config_path())
}

/// Núcleo da carga, parametrizado pelo caminho para permitir teste direto.
///
/// Arquivo ausente usa os padrões; arquivo presente e inválido é erro.
fn try_load_config_file_at(path: &std::path::Path) -> Result<PersistedConfig, String> {
    // Arquivo ausente não é erro: os padrões valem.
    if !path.exists() {
        return Ok(PersistedConfig::default());
    }
    let content = fs::read_to_string(path).map_err(|error| {
        format!(
            "não foi possível ler a configuração global em '{}': {error}",
            path.display()
        )
    })?;
    toml::from_str(&content).map_err(|error| {
        format!(
            "a configuração global em '{}' é um TOML inválido: {error}. Corrija o arquivo ou remova-o; nenhuma configuração foi sobrescrita.",
            path.display()
        )
    })
}

pub fn load_config_file_from(path: &std::path::Path) -> Result<PersistedConfig, String> {
    let content = fs::read_to_string(path)
        .map_err(|error| format!("não foi possível ler o arquivo de configuração: {error}"))?;
    toml::from_str(&content).map_err(|error| format!("configuração TOML inválida: {error}"))
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
            nuclei_templates_path: c.nuclei_templates_path.clone(),
            nuclei_templates_commit: c.nuclei_templates_commit.clone(),
            tools: c.tools,
            output_file: c.output_file,
            output_dir: c.output_dir,
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
            nuclei_templates_path: c.nuclei_templates_path.clone(),
            nuclei_templates_commit: c.nuclei_templates_commit.clone(),
            tools: c.tools.clone(),
            output_file: c.output_file.clone(),
            output_dir: c.output_dir.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// Arquivo temporário isolado, removido ao fim do teste.
    struct TempConfig(PathBuf);

    impl TempConfig {
        fn new(label: &str) -> Self {
            let unique = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "smartsec-config-{label}-{}-{unique}",
                std::process::id()
            ));
            Self(path)
        }

        fn write(&self, content: &str) {
            fs::write(&self.0, content).expect("o arquivo de configuração deve ser escrito");
        }
    }

    impl Drop for TempConfig {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }

    #[test]
    fn arquivo_ausente_usa_os_padroes_sem_erro() {
        let path = TempConfig::new("ausente");

        let config = try_load_config_file_at(&path.0).expect("arquivo ausente não é erro");

        let defaults = PersistedConfig::default();
        assert_eq!(config.target_url, defaults.target_url);
        assert_eq!(config.active_tools, defaults.active_tools);
        assert_eq!(config.execution_type, defaults.execution_type);
        assert_eq!(config.llm.provider, defaults.llm.provider);
        assert!(config.tools.is_empty());
        assert!(config.output_file.is_none());
        assert!(config.output_dir.is_none());
    }

    #[test]
    fn arquivo_valido_e_carregado_com_todos_os_campos() {
        let path = TempConfig::new("valido");
        path.write(
            "target_url = \"http://alvo.local:3000\"\n\
             active_tools = [\"Nmap\", \"Nikto\"]\n\
             [llm]\nprovider = \"ollama\"\nmodel = \"llama3\"\n\
             [[tools]]\n\
             name = \"ZAP\"\n\
             description = \"Scanner\"\n\
             category = \"DAST\"\n\
             image = \"example/zap:1\"\n\
             version = \"1.0\"\n\
             runner = \"generic\"\n\
             parser = \"generic-text\"\n\
             command_template = [\"zap\", \"{target}\"]\n\
             output_format = \"text\"\n",
        );

        let config = try_load_config_file_at(&path.0).expect("o TOML válido deve carregar");

        assert_eq!(config.target_url, "http://alvo.local:3000");
        assert_eq!(config.active_tools, vec!["Nmap", "Nikto"]);
        assert_eq!(config.tools.len(), 1);
        assert_eq!(config.tools[0].name, "ZAP");
    }

    #[test]
    fn arquivo_invalido_falha_citando_o_caminho_e_a_causa() {
        let path = TempConfig::new("invalido");
        path.write("target_url = \"http://alvo.local\nactive_tools = [");

        let error = try_load_config_file_at(&path.0).unwrap_err();

        assert!(error.contains("TOML inválido"), "{error}");
        assert!(
            error.contains("nenhuma configuração foi sobrescrita"),
            "{error}"
        );
        assert!(
            error.contains(&path.0.display().to_string()),
            "o erro precisa citar o caminho.\n{error}"
        );
    }

    #[test]
    fn arquivo_invalido_nao_sobrescreve_o_conteudo_original() {
        let path = TempConfig::new("preservado");
        let original = "target_url = \"http://alvo.local\nactive_tools = [";
        path.write(original);

        let _ = try_load_config_file_at(&path.0);

        assert_eq!(
            fs::read_to_string(&path.0).expect("o arquivo deve continuar legível"),
            original,
            "a leitura não pode alterar o arquivo do usuário"
        );
    }

    #[test]
    fn a_chave_de_ferramentas_com_erro_de_sintaxe_e_apontada() {
        let path = TempConfig::new("tools-invalido");
        path.write(
            "target_url = \"http://alvo.local\"\n\
             [[tools]]\n\
             name = \"ZAP\n\
             runner = \"generic\"\n",
        );

        let error = try_load_config_file_at(&path.0).unwrap_err();

        assert!(error.contains("TOML inválido"), "{error}");
        assert!(error.contains("ZAP"), "{error}");
    }

    #[test]
    fn load_config_file_mantem_a_configuracao_em_arquivo_valido() {
        // `load_config_file` mantém a assinatura histórica e imprime o aviso
        // quando falha; com arquivo válido precisa devolver a configuração.
        let path = TempConfig::new("global-valido");
        path.write("target_url = \"http://alvo.local\"\n[llm]\nprovider = \"ollama\"\n");

        let config = try_load_config_file_at(&path.0).expect("arquivo válido deve carregar");

        assert_eq!(config.target_url, "http://alvo.local");
    }
}
