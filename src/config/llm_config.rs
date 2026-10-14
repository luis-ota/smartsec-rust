use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};

const DEFAULT_TIMEOUT_SECS: u64 = 45;
const DEFAULT_MAX_RETRIES: u8 = 2;

/// Endpoint padrão do `llama-server`. A porta 11434 era a do Ollama: trocar de
/// runtime sem trocar a porta deixaria o SmartSec falando com um servidor morto.
const LLAMA_CPP_BASE_URL: &str = "http://localhost:8080/v1";

/// GGUF assumido quando a configuração não traz `model`: o `llama-server`
/// identifica o modelo pelo arquivo de `-m`, e não por uma tag de registry.
/// Segue o modelo do TCC_SPEC (Llama 3.1 8B) na quantização Q4_K_M.
const LLAMA_CPP_MODEL: &str = "Meta-Llama-3.1-8B-Instruct-Q4_K_M.gguf";

fn default_timeout_secs() -> u64 {
    DEFAULT_TIMEOUT_SECS
}

fn default_max_retries() -> u8 {
    DEFAULT_MAX_RETRIES
}

fn default_fallback_base_url() -> String {
    LLAMA_CPP_BASE_URL.to_string()
}

fn default_fallback_model() -> String {
    LLAMA_CPP_MODEL.to_string()
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize)]
pub enum LlmProviderKind {
    LlamaCpp,
    NvidiaNim,
    OpenAI,
    Custom,
}

/// Reduz a grafia a uma chave comparável: sem caixa e sem separadores. A TUI
/// grava o rótulo que o operador leu na tela, e ele precisa voltar pela leitura.
fn provider_key(raw: &str) -> String {
    raw.chars()
        .filter(char::is_ascii_alphanumeric)
        .flat_map(char::to_lowercase)
        .collect()
}

fn provider_from_key(key: &str) -> Option<LlmProviderKind> {
    match key {
        "llamacpp" | "llama" | "ollama" | "mock" => Some(LlmProviderKind::LlamaCpp),
        "nvidianim" | "nim" => Some(LlmProviderKind::NvidiaNim),
        "openai" => Some(LlmProviderKind::OpenAI),
        "custom" | "personalizado" => Some(LlmProviderKind::Custom),
        _ => None,
    }
}

impl<'de> Deserialize<'de> for LlmProviderKind {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Self::parse(&raw).map_err(D::Error::custom)
    }
}

impl LlmProviderKind {
    pub fn default_base_url(&self) -> &str {
        match self {
            LlmProviderKind::LlamaCpp => LLAMA_CPP_BASE_URL,
            LlmProviderKind::NvidiaNim => "https://integrate.api.nvidia.com/v1",
            LlmProviderKind::OpenAI => "https://api.openai.com/v1",
            LlmProviderKind::Custom => "",
        }
    }

    pub fn default_model(&self) -> &str {
        match self {
            LlmProviderKind::LlamaCpp => LLAMA_CPP_MODEL,
            LlmProviderKind::NvidiaNim => "meta/llama-3.1-405b-instruct",
            LlmProviderKind::OpenAI => "gpt-4o",
            LlmProviderKind::Custom => "",
        }
    }

    /// Ordem apresentada na TUI: API primeiro, servidor local por último porque
    /// inferência local consome a máquina de quem instala.
    pub fn all_labels() -> Vec<&'static str> {
        vec!["Personalizado", "OpenAI", "NVIDIA NIM", "llama.cpp"]
    }

    /// Posição na lista de [`Self::all_labels`], derivada para não dessincronizar
    /// quando a ordem muda.
    pub fn index(&self) -> usize {
        let key = provider_key(self.label());
        Self::all_labels()
            .iter()
            .position(|label| provider_key(label) == key)
            .unwrap_or(0)
    }

    /// Interpreta a grafia vinda da CLI ou do TOML, aceitando o rótulo da TUI,
    /// o nome canônico e as grafias históricas, sem diferenciar caixa nem
    /// separadores.
    pub fn parse(raw: &str) -> Result<Self, String> {
        provider_from_key(&provider_key(raw)).ok_or_else(|| {
            format!(
                "provedor de IA desconhecido: \"{raw}\"; use {}, {}, {} ou {}",
                Self::LlamaCpp.label(),
                Self::NvidiaNim.label(),
                Self::OpenAI.label(),
                Self::Custom.label()
            )
        })
    }

    pub fn from_label(label: &str) -> Self {
        provider_from_key(&provider_key(label)).unwrap_or(LlmProviderKind::Custom)
    }

    pub fn label(&self) -> &'static str {
        match self {
            LlmProviderKind::LlamaCpp => "llama.cpp",
            LlmProviderKind::NvidiaNim => "NVIDIA NIM",
            LlmProviderKind::OpenAI => "OpenAI",
            LlmProviderKind::Custom => "Personalizado",
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct LlmConfig {
    pub provider: LlmProviderKind,
    #[serde(default)]
    pub base_url: String,
    #[serde(default)]
    pub model: String,
    #[serde(skip)]
    pub api_key: String,
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
    #[serde(default = "default_max_retries")]
    pub max_retries: u8,
    #[serde(default)]
    pub remote_consent: bool,
    #[serde(default)]
    pub fallback_enabled: bool,
    #[serde(default = "default_fallback_base_url")]
    pub fallback_base_url: String,
    #[serde(default = "default_fallback_model")]
    pub fallback_model: String,
}

impl std::fmt::Debug for LlmConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LlmConfig")
            .field("provider", &self.provider)
            .field("base_url", &self.base_url)
            .field("model", &self.model)
            .field("api_key", &"[OCULTA]")
            .field("timeout_secs", &self.timeout_secs)
            .field("max_retries", &self.max_retries)
            .field("remote_consent", &self.remote_consent)
            .field("fallback_enabled", &self.fallback_enabled)
            .field("fallback_base_url", &self.fallback_base_url)
            .field("fallback_model", &self.fallback_model)
            .finish()
    }
}

impl LlmConfig {
    pub fn is_remote(&self) -> bool {
        match self.provider {
            LlmProviderKind::OpenAI | LlmProviderKind::NvidiaNim => true,
            LlmProviderKind::LlamaCpp | LlmProviderKind::Custom => {
                !is_loopback_endpoint(&self.base_url)
            }
        }
    }

    /// Verdadeiro quando há provedor de IA. Vazio é instalação nova e não é erro:
    /// a varredura funciona com a análise determinística no lugar do modelo.
    pub fn is_configured(&self) -> bool {
        !self.base_url.trim().is_empty()
    }

    pub fn validate(&self) -> Result<(), String> {
        if !self.is_configured() {
            return Ok(());
        }
        validate_endpoint(&self.base_url, !self.is_remote())?;
        validate_model(&self.model)?;
        if self.timeout_secs == 0 || self.timeout_secs > DEFAULT_TIMEOUT_SECS {
            return Err("O tempo limite da LLM deve estar entre 1 e 45 segundos".to_string());
        }
        if self.max_retries > 3 {
            return Err("As tentativas da LLM devem estar entre 0 e 3".to_string());
        }
        if self.is_remote() {
            if self.api_key.trim().is_empty() {
                return Err("As credenciais da LLM remota são obrigatórias".to_string());
            }
            if !self.remote_consent {
                return Err(
                    "O consentimento explícito é obrigatório antes do envio remoto de logs"
                        .to_string(),
                );
            }
        }
        if self.fallback_enabled {
            validate_endpoint(&self.fallback_base_url, true)?;
            if !is_loopback_endpoint(&self.fallback_base_url) {
                return Err(
                    "O endpoint alternativo local precisa ser local (llama.cpp)".to_string()
                );
            }
            validate_model(&self.fallback_model)?;
        }
        Ok(())
    }
}

fn validate_model(model: &str) -> Result<(), String> {
    if model.trim().is_empty() || model.chars().any(char::is_whitespace) {
        return Err("O modelo da LLM não pode estar vazio nem conter espaços".to_string());
    }
    Ok(())
}

fn validate_endpoint(endpoint: &str, allow_local_http: bool) -> Result<(), String> {
    let url = reqwest::Url::parse(endpoint)
        .map_err(|_| "A URL do endpoint da LLM é inválida".to_string())?;
    if url.host_str().is_none() || !matches!(url.scheme(), "http" | "https") {
        return Err("O endpoint da LLM deve usar HTTP ou HTTPS e incluir um host".to_string());
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("O endpoint da LLM não deve conter credenciais embutidas".to_string());
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err("O endpoint da LLM não deve conter consulta ou fragmento".to_string());
    }
    if url.scheme() != "https" && !(allow_local_http && is_loopback_endpoint(endpoint)) {
        return Err("O endpoint remoto da LLM deve usar HTTPS".to_string());
    }
    Ok(())
}

fn is_loopback_endpoint(endpoint: &str) -> bool {
    reqwest::Url::parse(endpoint)
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned))
        .is_some_and(|host| matches!(host.as_str(), "localhost" | "127.0.0.1" | "::1"))
}

#[cfg(test)]
pub(crate) fn remote_de_teste() -> LlmConfig {
    LlmConfig {
        provider: LlmProviderKind::Custom,
        base_url: "https://api.exemplo.test/v1".to_string(),
        model: "modelo-de-teste".to_string(),
        api_key: "chave-de-teste".to_string(),
        remote_consent: true,
        ..LlmConfig::default()
    }
}

#[cfg(test)]
pub(crate) fn local_de_teste() -> LlmConfig {
    let provider = LlmProviderKind::LlamaCpp;
    LlmConfig {
        provider,
        base_url: provider.default_base_url().to_string(),
        model: provider.default_model().to_string(),
        ..LlmConfig::default()
    }
}

impl Default for LlmConfig {
    /// API remota por padrão: servidor local queima a máquina de quem instala e
    /// só entra por escolha explícita.
    fn default() -> Self {
        let provider = LlmProviderKind::Custom;
        Self {
            provider,
            base_url: provider.default_base_url().to_string(),
            model: provider.default_model().to_string(),
            api_key: String::new(),
            timeout_secs: default_timeout_secs(),
            max_retries: default_max_retries(),
            remote_consent: false,
            fallback_enabled: false,
            fallback_base_url: default_fallback_base_url(),
            fallback_model: default_fallback_model(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_remote_provider_without_https_credentials_or_consent() {
        let mut config = LlmConfig {
            provider: LlmProviderKind::OpenAI,
            base_url: "http://api.openai.com/v1".to_string(),
            model: "gpt-4o".to_string(),
            ..LlmConfig::default()
        };
        assert!(config.validate().unwrap_err().contains("HTTPS"));

        config.base_url = "https://api.openai.com/v1".to_string();
        assert!(config.validate().unwrap_err().contains("credenciais"));

        config.api_key = "test-key".to_string();
        assert!(config.validate().unwrap_err().contains("consentimento"));
        config.remote_consent = true;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn accepts_local_llama_cpp_over_http() {
        let config = LlmConfig {
            provider: LlmProviderKind::LlamaCpp,
            base_url: "http://127.0.0.1:8080/v1".to_string(),
            model: LLAMA_CPP_MODEL.to_string(),
            ..LlmConfig::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn exposes_provider_labels_in_portuguese() {
        let labels = LlmProviderKind::all_labels();

        assert_eq!(
            labels,
            ["Personalizado", "OpenAI", "NVIDIA NIM", "llama.cpp"]
        );
        assert!(!labels.contains(&"Integrado"));
        assert_eq!(LlmProviderKind::Custom.label(), "Personalizado");
    }

    #[test]
    fn o_indice_de_um_provedor_segue_a_ordem_apresentada() {
        let labels = LlmProviderKind::all_labels();
        for provider in [
            LlmProviderKind::LlamaCpp,
            LlmProviderKind::NvidiaNim,
            LlmProviderKind::OpenAI,
            LlmProviderKind::Custom,
        ] {
            let esperado = labels
                .iter()
                .position(|label| LlmProviderKind::from_label(label) == provider)
                .expect("provedor presente na lista");
            assert_eq!(provider.index(), esperado, "{}", provider.label());
        }
        assert_eq!(LlmProviderKind::LlamaCpp.index(), labels.len() - 1);
    }

    /// Regressão da grafia salva pela TUI: `provider = "Personalizado"` era rejeitado
    /// na leitura, porque só o alias minúsculo estava registrado.
    #[test]
    fn accepts_the_label_the_tui_writes_in_every_casing_and_separator() {
        let cases = [
            ("Personalizado", LlmProviderKind::Custom),
            ("personalizado", LlmProviderKind::Custom),
            ("PERSONALIZADO", LlmProviderKind::Custom),
            ("Custom", LlmProviderKind::Custom),
            ("llama.cpp", LlmProviderKind::LlamaCpp),
            ("LlamaCpp", LlmProviderKind::LlamaCpp),
            ("LLAMA_CPP", LlmProviderKind::LlamaCpp),
            ("nvidia nim", LlmProviderKind::NvidiaNim),
            ("NVIDIA-NIM", LlmProviderKind::NvidiaNim),
            ("NvidiaNim", LlmProviderKind::NvidiaNim),
            ("OpenAI", LlmProviderKind::OpenAI),
            ("openai", LlmProviderKind::OpenAI),
        ];
        for (spelling, expected) in cases {
            let provider: LlmProviderKind = toml::from_str(&format!("provider = \"{spelling}\""))
                .and_then(|value: toml::Value| value["provider"].clone().try_into())
                .unwrap_or_else(|error| panic!("grafia \"{spelling}\" rejeitada: {error}"));
            assert_eq!(provider, expected, "grafia {spelling}");
        }
    }

    /// As grafias anteriores continuam válidas: uma configuração já gravada em disco
    /// não pode deixar de carregar por causa do rótulo novo.
    #[test]
    fn deserializes_legacy_mock_provider_as_local_llama_cpp() {
        let provider: LlmProviderKind = toml::from_str("provider = \"Mock\"")
            .and_then(|value: toml::Value| value["provider"].clone().try_into())
            .unwrap();

        assert_eq!(provider, LlmProviderKind::LlamaCpp);
    }

    #[test]
    fn deserializes_cli_spellings_as_provider_aliases() {
        let cases = [
            ("ollama", LlmProviderKind::LlamaCpp),
            ("openai", LlmProviderKind::OpenAI),
            ("nvidia-nim", LlmProviderKind::NvidiaNim),
            ("nvidia_nim", LlmProviderKind::NvidiaNim),
            ("custom", LlmProviderKind::Custom),
        ];
        for (spelling, expected) in cases {
            let document = format!("provider = \"{spelling}\"");
            let provider: LlmProviderKind = toml::from_str(&document)
                .and_then(|value: toml::Value| value["provider"].clone().try_into())
                .unwrap();
            assert_eq!(provider, expected, "grafia {spelling}");
        }
    }

    #[test]
    fn reports_an_unknown_provider_with_the_valid_spellings() {
        let error = toml::from_str::<LlmConfig>("provider = \"gemini\"").unwrap_err();

        assert!(error.to_string().contains("gemini"), "{error}");
        assert!(error.to_string().contains("llama.cpp"), "{error}");
    }

    #[test]
    fn serializes_canonical_variant_names() {
        let cases = [
            (LlmProviderKind::LlamaCpp, "LlamaCpp"),
            (LlmProviderKind::NvidiaNim, "NvidiaNim"),
            (LlmProviderKind::OpenAI, "OpenAI"),
            (LlmProviderKind::Custom, "Custom"),
        ];
        for (provider, expected) in cases {
            let value = toml::Value::try_from(provider).unwrap();
            assert_eq!(value.as_str(), Some(expected));
        }
    }

    #[test]
    fn parses_llm_section_without_endpoint_fields() {
        let config: LlmConfig = toml::from_str("provider = \"llama.cpp\"").unwrap();
        assert_eq!(config.provider, LlmProviderKind::LlamaCpp);
        assert!(config.base_url.is_empty());
        assert!(config.model.is_empty());
    }

    #[test]
    fn treats_non_loopback_llama_cpp_as_remote() {
        let mut config = LlmConfig {
            provider: LlmProviderKind::LlamaCpp,
            base_url: "https://llama.example/v1".to_string(),
            model: LLAMA_CPP_MODEL.to_string(),
            ..LlmConfig::default()
        };

        assert!(config.validate().unwrap_err().contains("credenciais"));
        config.api_key = "test-key".to_string();
        assert!(config.validate().unwrap_err().contains("consentimento"));
        config.remote_consent = true;
        assert!(config.validate().is_ok());
    }

    /// Migração de Ollama para llama.cpp: porta e modelo precisam acompanhar o
    /// runtime novo, senão o padrão aponta para um servidor que não sobe mais.
    #[test]
    fn o_provedor_local_aponta_para_o_llama_cpp_do_spec() {
        let provider = LlmProviderKind::LlamaCpp;

        assert_eq!(provider.default_base_url(), "http://localhost:8080/v1");
        assert_eq!(provider.default_model(), LLAMA_CPP_MODEL);
        assert!(provider.default_model().contains("Llama-3.1-8B"));
        assert!(!provider.default_model().contains(' '));
        // O padrao do LlmConfig e API remota: o servidor local so entra por
        // escolha explicita, porque inferencia local consome a maquina.
        assert_ne!(LlmConfig::default().provider, LlmProviderKind::LlamaCpp);
        assert!(!LlmConfig::default().is_configured());
        assert!(LlmConfig::default().validate().is_ok());
        assert_eq!(
            LlmConfig::default().fallback_base_url,
            "http://localhost:8080/v1"
        );
    }

    /// O rótulo da TUI e o do arquivo precisam ser o mesmo caminho: a tela grava
    /// `label()` e a tela seguinte relê por ele.
    #[test]
    fn every_tui_label_round_trips_through_its_kind() {
        for label in LlmProviderKind::all_labels() {
            let kind = LlmProviderKind::from_label(label);
            assert_eq!(kind.label(), label, "rótulo {label}");
            assert_eq!(
                LlmProviderKind::from_label(label),
                kind,
                "grafia de {label}"
            );
        }
    }

    #[test]
    fn rejects_non_local_fallback_endpoint() {
        let config = LlmConfig {
            fallback_enabled: true,
            fallback_base_url: "https://llama.example/v1".to_string(),
            ..local_de_teste()
        };

        assert!(config.validate().unwrap_err().contains("local"));
    }

    #[test]
    fn rejects_endpoint_with_embedded_credentials_or_query() {
        let mut config = LlmConfig {
            provider: LlmProviderKind::OpenAI,
            base_url: "https://user:password@api.openai.com/v1".to_string(),
            model: "gpt-4o".to_string(),
            api_key: "test-key".to_string(),
            remote_consent: true,
            ..LlmConfig::default()
        };

        assert!(config
            .validate()
            .unwrap_err()
            .contains("credenciais embutidas"));
        config.base_url = "https://api.openai.com/v1?key=value".to_string();
        assert!(config
            .validate()
            .unwrap_err()
            .contains("consulta ou fragmento"));
    }

    #[test]
    fn never_serializes_api_key() {
        let config = LlmConfig {
            api_key: "secret-value".to_string(),
            ..LlmConfig::default()
        };
        let serialized = toml::to_string(&config).unwrap();
        assert!(!serialized.contains("secret-value"));
        assert!(!serialized.contains("api_key"));
    }

    #[test]
    fn redacts_api_key_from_debug_output() {
        let config = LlmConfig {
            api_key: "secret-value".to_string(),
            ..LlmConfig::default()
        };

        let debug = format!("{config:?}");

        assert!(!debug.contains("secret-value"));
        assert!(debug.contains("[OCULTA]"));
    }
}
