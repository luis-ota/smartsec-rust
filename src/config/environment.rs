use crate::config::llm_config::LlmConfig;
use async_trait::async_trait;

/// Sondagem de ambiente do assistente de primeira execução.
///
/// Tudo que depende da máquina é descrito aqui como um relatório de partes, e o
/// texto que o operador lê é derivado desse relatório por [`EnvironmentReport::findings`].
/// Nenhum teste precisa de rede, keyring ou Podman: basta montar o relatório.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnvironmentReport {
    pub local_llm: Option<LocalEndpoint>,
    pub keyring: KeyringAvailability,
    pub podman: PodmanMode,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalEndpoint {
    pub name: String,
    pub base_url: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyringAvailability {
    Available,
    Unavailable(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PodmanMode {
    Rootless,
    Rootful,
    Absent,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FindingLevel {
    Info,
    Attention,
    Blocker,
}

/// Um item do relatório já escrito para o operador.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnvironmentFinding {
    pub title: String,
    pub detail: String,
    pub level: FindingLevel,
}

impl EnvironmentReport {
    pub fn findings(&self) -> Vec<EnvironmentFinding> {
        vec![
            self.local_llm_finding(),
            self.keyring_finding(),
            self.podman_finding(),
        ]
    }

    fn local_llm_finding(&self) -> EnvironmentFinding {
        match &self.local_llm {
            Some(endpoint) => EnvironmentFinding {
                title: "IA local disponível".to_string(),
                detail: format!(
                    "{} responde em {} · a análise por IA pode rodar sem sair desta máquina",
                    endpoint.name, endpoint.base_url
                ),
                level: FindingLevel::Info,
            },
            None => EnvironmentFinding {
                title: "Nenhuma IA local encontrada".to_string(),
                detail: "nada respondeu em localhost:8080 (llama.cpp) nem em localhost:11434 (Ollama); sem provedor remoto a análise por IA fica indisponível".to_string(),
                level: FindingLevel::Attention,
            },
        }
    }

    fn keyring_finding(&self) -> EnvironmentFinding {
        match &self.keyring {
            KeyringAvailability::Available => EnvironmentFinding {
                title: "Cofre de segredos disponível".to_string(),
                detail: "a chave do provedor remoto pode ser gravada no keyring do sistema, nunca no arquivo de configuração".to_string(),
                level: FindingLevel::Info,
            },
            KeyringAvailability::Unavailable(reason) => EnvironmentFinding {
                title: "Cofre de segredos indisponível".to_string(),
                detail: format!(
                    "chaves de provedores remotos não poderão ser salvas nesta máquina: {reason}"
                ),
                level: FindingLevel::Blocker,
            },
        }
    }

    fn podman_finding(&self) -> EnvironmentFinding {
        match self.podman {
            PodmanMode::Rootless => EnvironmentFinding {
                title: "Podman rootless disponível".to_string(),
                detail: "as ferramentas rodam em contêineres sem privilégio de administrador (RNF01)".to_string(),
                level: FindingLevel::Info,
            },
            PodmanMode::Rootful => EnvironmentFinding {
                title: "Podman em modo rootful".to_string(),
                detail: "o projeto exige Podman rootless (RNF01); os contêineres das ferramentas aqui rodariam com privilégio elevado".to_string(),
                level: FindingLevel::Attention,
            },
            PodmanMode::Absent => EnvironmentFinding {
                title: "Podman não encontrado".to_string(),
                detail: "sem Podman as ferramentas de segurança não executam; instale antes da primeira varredura".to_string(),
                level: FindingLevel::Blocker,
            },
        }
    }

    /// Impede provedores remotos quando o cofre de segredos não aceita gravação:
    /// sem chave persistida, a configuração remota só funcionaria nesta sessão.
    pub fn blocks_remote_provider(&self) -> bool {
        matches!(self.keyring, KeyringAvailability::Unavailable(_))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConnectionCheck {
    NotRun,
    Running,
    Succeeded(String),
    Failed(String),
}

/// Fonte das respostas de ambiente e do teste de conexão.
///
/// A implementação real fala com a máquina; a de teste devolve valores prontos.
#[async_trait]
pub trait OnboardingProbe: Send + Sync {
    async fn environment(&self) -> EnvironmentReport;
    async fn connection(&self, llm: &LlmConfig) -> ConnectionCheck;
}

pub const LLAMA_CPP_MODELS_URL: &str = "http://localhost:8080/v1/models";
pub const OLLAMA_ROOT_URL: &str = "http://localhost:11434";

/// Implementação real da sondagem.
pub struct SystemOnboardingProbe {
    client: reqwest::Client,
}

impl SystemOnboardingProbe {
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(1500))
            .build()
            .unwrap_or_default();
        Self { client }
    }

    async fn responds(&self, url: &str) -> bool {
        self.client.get(url).send().await.is_ok()
    }

    async fn detect_local_llm(&self) -> Option<LocalEndpoint> {
        for (name, probe_url, base_url) in [
            (
                "llama.cpp",
                LLAMA_CPP_MODELS_URL,
                "http://localhost:8080/v1",
            ),
            ("Ollama", OLLAMA_ROOT_URL, "http://localhost:11434/v1"),
        ] {
            if self.responds(probe_url).await {
                return Some(LocalEndpoint {
                    name: name.to_string(),
                    base_url: base_url.to_string(),
                });
            }
        }
        None
    }

    async fn detect_keyring(&self) -> KeyringAvailability {
        // `NoEntry` significa que o serviço existe e só não há chave ainda: o
        // cofre está disponível, que é o que a tela precisa saber.
        match keyring::Entry::new(
            crate::config::persistence::KEYRING_SERVICE,
            crate::config::persistence::KEYRING_USERNAME,
        ) {
            Ok(entry) => match entry.get_password() {
                Ok(_) | Err(keyring::Error::NoEntry) => KeyringAvailability::Available,
                Err(error) => KeyringAvailability::Unavailable(error.to_string()),
            },
            Err(error) => KeyringAvailability::Unavailable(error.to_string()),
        }
    }

    async fn detect_podman(&self) -> PodmanMode {
        let output = tokio::process::Command::new("podman")
            .args(["info", "--format", "{{.Host.Security.Rootless}}"])
            .output()
            .await;
        match output {
            Ok(output) if output.status.success() => {
                if String::from_utf8_lossy(&output.stdout).trim() == "true" {
                    PodmanMode::Rootless
                } else {
                    PodmanMode::Rootful
                }
            }
            _ => PodmanMode::Absent,
        }
    }

    async fn check_connection(&self, llm: &LlmConfig) -> ConnectionCheck {
        let url = format!("{}/models", llm.base_url.trim_end_matches('/'));
        let mut request = self
            .client
            .get(&url)
            .timeout(std::time::Duration::from_secs(5));
        if !llm.api_key.trim().is_empty() {
            request = request.bearer_auth(llm.api_key.trim());
        }
        match request.send().await {
            Ok(response) => connection_from_status(&url, response.status().as_u16()),
            Err(error) if error.is_timeout() => {
                ConnectionCheck::Failed(format!("{url} não respondeu dentro do prazo"))
            }
            Err(error) => {
                ConnectionCheck::Failed(format!("não foi possível falar com {url}: {error}"))
            }
        }
    }
}

/// Traduz o status HTTP em causa acionável.
///
/// Separado da chamada para que a mensagem que o operador lê seja verificável
/// sem rede: um "erro" genérico esconderia o que ele precisa corrigir.
fn connection_from_status(url: &str, status: u16) -> ConnectionCheck {
    if (200..300).contains(&status) {
        return ConnectionCheck::Succeeded(format!("{url} respondeu e a chave foi aceita"));
    }
    let hint = match status {
        401 | 403 => "chave recusada; confira a credencial do provedor",
        404 => "endpoint sem lista de modelos; confira a URL base, incluindo o sufixo /v1",
        429 => "limite de requisições do provedor atingido; tente de novo em instantes",
        _ => "a chamada mínima foi recusada pelo provedor",
    };
    ConnectionCheck::Failed(format!("{url} respondeu {status}: {hint}"))
}

impl Default for SystemOnboardingProbe {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl OnboardingProbe for SystemOnboardingProbe {
    async fn environment(&self) -> EnvironmentReport {
        let (local_llm, keyring, podman) = tokio::join!(
            self.detect_local_llm(),
            self.detect_keyring(),
            self.detect_podman()
        );
        EnvironmentReport {
            local_llm,
            keyring,
            podman,
        }
    }

    async fn connection(&self, llm: &LlmConfig) -> ConnectionCheck {
        self.check_connection(llm).await
    }
}

/// Sondagem de mentira para os testes: nada de rede, keyring ou Podman.
#[cfg(test)]
pub struct FixedOnboardingProbe {
    pub report: EnvironmentReport,
    pub check: ConnectionCheck,
}

#[cfg(test)]
#[async_trait]
impl OnboardingProbe for FixedOnboardingProbe {
    async fn environment(&self) -> EnvironmentReport {
        self.report.clone()
    }

    async fn connection(&self, _llm: &LlmConfig) -> ConnectionCheck {
        self.check.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(
        local_llm: Option<LocalEndpoint>,
        keyring: KeyringAvailability,
        podman: PodmanMode,
    ) -> EnvironmentReport {
        EnvironmentReport {
            local_llm,
            keyring,
            podman,
        }
    }

    fn local() -> LocalEndpoint {
        LocalEndpoint {
            name: "llama.cpp".to_string(),
            base_url: "http://localhost:8080/v1".to_string(),
        }
    }

    #[test]
    fn a_maquina_completa_nao_levanta_nenhum_bloqueio() {
        let findings = report(
            Some(local()),
            KeyringAvailability::Available,
            PodmanMode::Rootless,
        )
        .findings();

        assert_eq!(findings.len(), 3);
        assert!(findings.iter().all(|item| item.level == FindingLevel::Info));
        assert!(findings.iter().any(|item| item
            .detail
            .contains("llama.cpp responde em http://localhost:8080/v1")));
    }

    #[test]
    fn keyring_indisponivel_avisa_que_a_chave_nao_pode_ser_salva() {
        let findings = report(
            None,
            KeyringAvailability::Unavailable("nenhum serviço de segredos ativo".to_string()),
            PodmanMode::Rootless,
        )
        .findings();

        let keyring = findings
            .iter()
            .find(|item| item.title.contains("Cofre"))
            .expect("o cofre de segredos precisa ser avaliado");
        assert_eq!(keyring.level, FindingLevel::Blocker);
        assert!(
            keyring.detail.contains("não poderão ser salvas"),
            "{keyring:?}"
        );
        assert!(keyring.detail.contains("nenhum serviço de segredos ativo"));
    }

    #[test]
    fn keyring_indisponivel_bloqueia_o_provedor_remoto_sem_quebrar_a_ia_local() {
        let environment = report(
            Some(local()),
            KeyringAvailability::Unavailable("sem serviço".to_string()),
            PodmanMode::Rootless,
        );

        assert!(environment.blocks_remote_provider());
    }

    #[test]
    fn ausencia_de_ia_local_e_de_podman_avisa_com_o_que_falta() {
        let findings = report(None, KeyringAvailability::Available, PodmanMode::Absent).findings();

        let ia = findings
            .iter()
            .find(|item| item.title.contains("IA local"))
            .expect("a IA local precisa ser avaliada");
        assert_eq!(ia.level, FindingLevel::Attention);
        assert!(ia.detail.contains("localhost:8080"), "{ia:?}");
        assert!(ia.detail.contains("localhost:11434"), "{ia:?}");

        let podman = findings
            .iter()
            .find(|item| item.title.contains("Podman"))
            .expect("o Podman precisa ser avaliado");
        assert_eq!(podman.level, FindingLevel::Blocker);
    }

    #[test]
    fn o_teste_de_conexao_diz_a_causa_da_falha_em_portugues() {
        let unauthorized = connection_from_status("https://api.exemplo/v1/models", 401);
        assert!(
            matches!(&unauthorized, ConnectionCheck::Failed(detail) if detail.contains("chave recusada") && detail.contains("401")),
            "{unauthorized:?}"
        );

        let not_found = connection_from_status("https://api.exemplo/v1/models", 404);
        assert!(
            matches!(&not_found, ConnectionCheck::Failed(detail) if detail.contains("URL base")),
            "{not_found:?}"
        );

        let rate_limited = connection_from_status("https://api.exemplo/v1/models", 429);
        assert!(
            matches!(&rate_limited, ConnectionCheck::Failed(detail) if detail.contains("429")),
            "{rate_limited:?}"
        );

        let ok = connection_from_status("http://localhost:8080/v1/models", 200);
        assert!(
            matches!(&ok, ConnectionCheck::Succeeded(detail) if detail.contains("aceita")),
            "{ok:?}"
        );
    }

    #[test]
    fn podman_rootful_e_apontado_como_divergencia_do_requisito() {
        let findings = report(
            Some(local()),
            KeyringAvailability::Available,
            PodmanMode::Rootful,
        )
        .findings();

        let podman = findings
            .iter()
            .find(|item| item.title.contains("Podman"))
            .expect("o Podman precisa ser avaliado");
        assert_eq!(podman.level, FindingLevel::Attention);
        assert!(podman.detail.contains("RNF01"), "{podman:?}");
    }
}
