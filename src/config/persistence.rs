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
    /// Limiar da regra automática de interrupção (REQ05). Ausente ou `0`
    /// mantém a regra desativada.
    #[serde(default)]
    pub max_critical_findings: usize,
    /// Diretório do projeto analisado pelo agente de código (issue #76).
    #[serde(default)]
    pub project_dir: Option<String>,
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
            max_critical_findings: 0,
            project_dir: None,
        }
    }
}

pub fn config_path() -> PathBuf {
    let base = dirs::config_dir().unwrap_or_else(|| PathBuf::from("."));
    base.join("smartsec").join("config.toml")
}

/// Carrega a configuração global: arquivo ausente devolve os padrões; TOML
/// inválido é erro, porque cair em `default()` em silêncio faria perder alvo,
/// ferramentas e provedor. A leitura nunca sobrescreve o arquivo, e a CLI
/// sobrepõe `target_url` e as ferramentas escolhidas.
pub fn load_config_file() -> PersistedConfig {
    match try_load_config_file() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("[ERRO] {error}");
            PersistedConfig::default()
        }
    }
}

/// Igual a [`load_config_file`], mas devolve o erro em vez de imprimi-lo, para
/// a TUI e os testes decidirem como apresentar a falha.
pub fn try_load_config_file() -> Result<PersistedConfig, String> {
    try_load_config_file_at(&config_path())
}

/// Núcleo da carga, parametrizado pelo caminho para permitir teste direto.
fn try_load_config_file_at(path: &std::path::Path) -> Result<PersistedConfig, String> {
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
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
        }
    }
    let mut cfg_no_key = cfg.clone();
    cfg_no_key.llm.api_key = String::new();
    let content = toml::to_string_pretty(&cfg_no_key).map_err(std::io::Error::other)?;
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)?;
        file.write_all(content.as_bytes())?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        fs::write(&path, content)
    }
}

pub(crate) const KEYRING_SERVICE: &str = "smartsec";
pub(crate) const KEYRING_USERNAME: &str = "llm-api-key";

pub fn config_file_exists_at(path: &std::path::Path) -> bool {
    path.exists()
}

/// Cofre usado pelo SmartSec.
///
/// No Linux, o `Login` é o keyring que o PAM desbloqueia no login. O
/// `Default keyring` não tem prompter em TTY e ficava permanentemente
/// bloqueado em sessões sem ambiente gráfico. Fora do Linux, o backend nativo
/// continua usando o cofre padrão.
fn keyring_entry() -> Result<keyring::Entry, keyring::Error> {
    #[cfg(target_os = "linux")]
    {
        keyring::Entry::new_with_target("Login", KEYRING_SERVICE, KEYRING_USERNAME)
    }
    #[cfg(not(target_os = "linux"))]
    {
        keyring::Entry::new(KEYRING_SERVICE, KEYRING_USERNAME)
    }
}

pub fn save_api_key(key: &str) -> Result<(), keyring::Error> {
    let entry = keyring_entry()?;
    if key.is_empty() {
        match entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => {}
            Err(error) => return Err(error),
        }
    } else {
        entry.set_password(key)?;
    }
    Ok(())
}

pub fn load_api_key() -> Result<String, keyring::Error> {
    let entry = keyring_entry()?;
    entry.get_password()
}

/// Remove a chave. Ausência não é erro: `auth remove` é idempotente.
pub fn delete_api_key() -> Result<(), keyring::Error> {
    let entry = keyring_entry()?;
    match entry.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(error) => Err(error),
    }
}

/// Distingue chave ausente de cofre bloqueado ou indisponível.
#[derive(Clone, PartialEq, Eq)]
pub enum ApiKeyStatus {
    Available(String),
    Missing,
    Locked(String),
    Unavailable(String),
}

impl std::fmt::Debug for ApiKeyStatus {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Available(_) => formatter.write_str("Available([OCULTA])"),
            Self::Missing => formatter.write_str("Missing"),
            Self::Locked(reason) => formatter.debug_tuple("Locked").field(reason).finish(),
            Self::Unavailable(reason) => {
                formatter.debug_tuple("Unavailable").field(reason).finish()
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CredentialStoreError {
    Missing,
    Locked(String),
    Unavailable(String),
}

impl std::fmt::Display for CredentialStoreError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing => {
                write!(
                    formatter,
                    "nenhuma chave da API está cadastrada no cofre do sistema"
                )
            }
            Self::Locked(reason) | Self::Unavailable(reason) => write!(formatter, "{reason}"),
        }
    }
}

impl std::error::Error for CredentialStoreError {}

impl From<keyring::Error> for CredentialStoreError {
    fn from(error: keyring::Error) -> Self {
        match error {
            keyring::Error::NoEntry => Self::Missing,
            error => {
                let detail = error.to_string();
                if detail.to_lowercase().contains("locked") {
                    Self::Locked("o cofre de segredos do sistema está bloqueado".to_string())
                } else {
                    Self::Unavailable(format!(
                        "não foi possível acessar o cofre de segredos do sistema: {detail}"
                    ))
                }
            }
        }
    }
}

fn status_from_load(result: Result<String, CredentialStoreError>) -> ApiKeyStatus {
    match result {
        Ok(key) if !key.trim().is_empty() => ApiKeyStatus::Available(key),
        Ok(_) | Err(CredentialStoreError::Missing) => ApiKeyStatus::Missing,
        Err(CredentialStoreError::Locked(reason)) => ApiKeyStatus::Locked(reason),
        Err(CredentialStoreError::Unavailable(reason)) => ApiKeyStatus::Unavailable(reason),
    }
}

/// Fronteira injetável entre o subcomando `auth` e o cofre do sistema.
///
/// O binário usa `SystemCredentialStore`; os testes usam uma implementação em
/// memória e nunca tocam no keyring real.
pub trait CredentialStore {
    fn save(&self, key: &str) -> Result<(), CredentialStoreError>;
    fn load(&self) -> Result<String, CredentialStoreError>;
    fn delete(&self) -> Result<(), CredentialStoreError>;

    fn status(&self) -> ApiKeyStatus {
        status_from_load(self.load())
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemCredentialStore;

impl CredentialStore for SystemCredentialStore {
    fn save(&self, key: &str) -> Result<(), CredentialStoreError> {
        save_api_key(key).map_err(CredentialStoreError::from)
    }

    fn load(&self) -> Result<String, CredentialStoreError> {
        load_api_key().map_err(CredentialStoreError::from)
    }

    fn delete(&self) -> Result<(), CredentialStoreError> {
        delete_api_key().map_err(CredentialStoreError::from)
    }

    fn status(&self) -> ApiKeyStatus {
        api_key_status()
    }
}

pub fn api_key_status() -> ApiKeyStatus {
    status_from_load(load_api_key().map_err(CredentialStoreError::from))
}

#[cfg(test)]
pub(crate) struct InMemoryCredentialStore {
    key: std::sync::Mutex<Option<String>>,
    failure: std::sync::Mutex<Option<CredentialStoreError>>,
}

#[cfg(test)]
impl InMemoryCredentialStore {
    pub(crate) fn new() -> Self {
        Self {
            key: std::sync::Mutex::new(None),
            failure: std::sync::Mutex::new(None),
        }
    }

    pub(crate) fn with_failure(error: CredentialStoreError) -> Self {
        Self {
            key: std::sync::Mutex::new(None),
            failure: std::sync::Mutex::new(Some(error)),
        }
    }

    pub(crate) fn stored_key(&self) -> Option<String> {
        self.key
            .lock()
            .expect("o mutex da chave de teste não pode envenenar")
            .clone()
    }

    fn fail(&self) -> Result<(), CredentialStoreError> {
        match self
            .failure
            .lock()
            .expect("o mutex de falha de teste não pode envenenar")
            .clone()
        {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
impl CredentialStore for InMemoryCredentialStore {
    fn save(&self, key: &str) -> Result<(), CredentialStoreError> {
        self.fail()?;
        *self
            .key
            .lock()
            .expect("o mutex da chave de teste não pode envenenar") = Some(key.to_string());
        Ok(())
    }

    fn load(&self) -> Result<String, CredentialStoreError> {
        self.fail()?;
        self.key
            .lock()
            .expect("o mutex da chave de teste não pode envenenar")
            .clone()
            .ok_or(CredentialStoreError::Missing)
    }

    fn delete(&self) -> Result<(), CredentialStoreError> {
        self.fail()?;
        *self
            .key
            .lock()
            .expect("o mutex da chave de teste não pode envenenar") = None;
        Ok(())
    }
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
            max_critical_findings: c.max_critical_findings,
            project_dir: c.project_dir.clone(),
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
            max_critical_findings: c.max_critical_findings,
            project_dir: c.project_dir.clone(),
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

    #[test]
    fn in_memory_store_covers_set_status_and_remove() {
        let store = InMemoryCredentialStore::new();
        assert_eq!(store.status(), ApiKeyStatus::Missing);

        store
            .save("chave-de-teste")
            .expect("a gravação deve funcionar");
        assert_eq!(
            store.status(),
            ApiKeyStatus::Available("chave-de-teste".to_string())
        );

        store.delete().expect("a remoção deve funcionar");
        assert_eq!(store.status(), ApiKeyStatus::Missing);
        store
            .delete()
            .expect("remover uma chave ausente precisa ser idempotente");
    }

    #[test]
    fn a_locked_store_is_reported_as_locked_not_missing() {
        let store = InMemoryCredentialStore::with_failure(CredentialStoreError::Locked(
            "o cofre de segredos do sistema está bloqueado".to_string(),
        ));

        assert_eq!(
            store.status(),
            ApiKeyStatus::Locked("o cofre de segredos do sistema está bloqueado".to_string())
        );
        assert!(store
            .save("chave-de-teste")
            .unwrap_err()
            .to_string()
            .contains("bloqueado"));
    }

    #[test]
    fn an_empty_stored_key_counts_as_missing() {
        let store = InMemoryCredentialStore::new();
        store.save("   ").expect("a gravação deve funcionar");

        assert_eq!(store.status(), ApiKeyStatus::Missing);
    }

    #[test]
    fn no_entry_from_the_keyring_becomes_missing() {
        assert_eq!(
            CredentialStoreError::from(keyring::Error::NoEntry),
            CredentialStoreError::Missing
        );
    }
}
