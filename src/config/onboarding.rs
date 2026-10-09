use crate::config::configuration::Configuration;
use crate::config::environment::{ConnectionCheck, EnvironmentReport};

/// Etapas do assistente de primeira execução.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OnboardingStep {
    Environment,
    Provider,
    Credential,
    Consent,
    Connection,
}

impl OnboardingStep {
    pub const fn label(self) -> &'static str {
        match self {
            OnboardingStep::Environment => "ambiente",
            OnboardingStep::Provider => "provedor",
            OnboardingStep::Credential => "credencial",
            OnboardingStep::Consent => "consentimento",
            OnboardingStep::Connection => "teste de conexão",
        }
    }

    pub const fn total() -> usize {
        5
    }

    pub const fn number(self) -> usize {
        match self {
            OnboardingStep::Environment => 1,
            OnboardingStep::Provider => 2,
            OnboardingStep::Credential => 3,
            OnboardingStep::Consent => 4,
            OnboardingStep::Connection => 5,
        }
    }
}

/// Estado do assistente. Só guarda decisões; a configuração efetiva continua
/// morando no rascunho da tela de configurações, que é o mesmo já validado.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OnboardingState {
    pub step: OnboardingStep,
    pub environment: Option<EnvironmentReport>,
    pub consent: Option<bool>,
    pub connection: ConnectionCheck,
    pub error: Option<String>,
    pub notice: Option<String>,
}

impl Default for OnboardingState {
    fn default() -> Self {
        Self {
            step: OnboardingStep::Environment,
            environment: None,
            consent: None,
            connection: ConnectionCheck::NotRun,
            error: None,
            notice: None,
        }
    }
}

impl OnboardingState {
    pub fn start() -> Self {
        Self::default()
    }

    pub fn deliver_environment(&mut self, report: EnvironmentReport) {
        self.environment = Some(report);
    }

    pub fn deliver_connection(&mut self, check: ConnectionCheck) {
        self.connection = check;
    }

    pub fn remote_blocked(&self) -> bool {
        self.environment
            .as_ref()
            .is_some_and(EnvironmentReport::blocks_remote_provider)
    }

    /// Avança uma etapa. O provedor remoto acrescenta credencial e consentimento;
    /// recusar o consentimento devolve o fluxo para o modelo local.
    pub fn advance(&mut self, remote: bool) {
        self.error = None;
        self.step = match (self.step, remote) {
            (OnboardingStep::Environment, _) => OnboardingStep::Provider,
            (OnboardingStep::Provider, true) => OnboardingStep::Credential,
            (OnboardingStep::Provider, false) => OnboardingStep::Connection,
            (OnboardingStep::Credential, _) => OnboardingStep::Consent,
            (OnboardingStep::Consent, _) => OnboardingStep::Connection,
            (OnboardingStep::Connection, _) => OnboardingStep::Connection,
        };
    }

    pub fn retreat(&mut self) {
        self.error = None;
        self.step = match self.step {
            OnboardingStep::Environment => OnboardingStep::Environment,
            OnboardingStep::Provider => OnboardingStep::Environment,
            OnboardingStep::Credential => OnboardingStep::Provider,
            OnboardingStep::Consent => OnboardingStep::Credential,
            OnboardingStep::Connection => {
                if self.consent == Some(false) {
                    OnboardingStep::Connection
                } else {
                    OnboardingStep::Consent
                }
            }
        };
    }

    pub fn answer_consent(&mut self, granted: bool) {
        self.consent = Some(granted);
    }

    /// O caminho remoto é fechado com aviso explícito quando o cofre de segredos
    /// não aceita gravar a chave: sem chave persistida a configuração remota
    /// valeria só nesta sessão (RNF10 e higiene de credencial).
    pub fn refuse_remote(&mut self, reason: &str) {
        self.consent = Some(false);
        self.notice = Some(format!(
            "Envio remoto bloqueado: {reason}. A análise usará o modelo local desta máquina."
        ));
        self.step = OnboardingStep::Connection;
    }

    /// Impede salvar antes do fim: quem abandona no meio não grava nada.
    pub fn ensure_complete(&self) -> Result<(), String> {
        if self.step == OnboardingStep::Connection {
            return Ok(());
        }
        Err(format!(
            "o assistente inicial está na etapa {} e não grava configuração incompleta",
            self.step.label()
        ))
    }

    pub fn status(&self) -> String {
        if let Some(error) = &self.error {
            return error.clone();
        }
        if let Some(notice) = &self.notice {
            return notice.clone();
        }
        format!(
            "Passo {}/{} · {}{}",
            self.step.number(),
            OnboardingStep::total(),
            self.step.label(),
            if self.environment.is_none() {
                " · verificando o ambiente"
            } else {
                ""
            }
        )
    }

    pub fn consent_prompt(&self) -> &'static str {
        "Ao aceitar, saem desta máquina: o alvo analisado, os logs das ferramentas de segurança, os achados com suas evidências e o código do projeto escolhido. Segredos encontrados são mascarados antes do envio."
    }
}

/// Gravação da configuração concluída.
///
/// Separada do fluxo para que o teste observe quantas gravações acontecem sem
/// tocar o arquivo do usuário nem o keyring.
pub trait OnboardingPersister: Send {
    fn save(&self, config: &Configuration) -> Result<(), String>;
}

pub struct SystemOnboardingPersister;

impl OnboardingPersister for SystemOnboardingPersister {
    fn save(&self, config: &Configuration) -> Result<(), String> {
        config.save()
    }
}

pub const KEYRING_BLOCK_REMOTE: &str = "o cofre de segredos do sistema recusou gravar a chave";
pub const CONSENT_REFUSED: &str = "você recusou o envio dos logs para fora desta máquina";

/// Primeira execução é a ausência do arquivo global de configuração.
///
/// Separado da leitura do disco para que a decisão seja verificável sem tocar
/// o arquivo do usuário.
pub fn is_first_run(config_exists: bool) -> bool {
    !config_exists
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::environment::{
        EnvironmentReport, KeyringAvailability, LocalEndpoint, PodmanMode,
    };

    fn report(keyring: KeyringAvailability) -> EnvironmentReport {
        EnvironmentReport {
            local_llm: Some(LocalEndpoint {
                name: "llama.cpp".to_string(),
                base_url: "http://localhost:8080/v1".to_string(),
            }),
            keyring,
            podman: PodmanMode::Rootless,
        }
    }

    struct RecordingPersister {
        saves: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    impl OnboardingPersister for RecordingPersister {
        fn save(&self, _config: &Configuration) -> Result<(), String> {
            self.saves.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }
    }

    #[test]
    fn ambiente_e_roteado_para_o_provedor() {
        let mut onboarding = OnboardingState::start();

        onboarding.advance(false);

        assert_eq!(onboarding.step, OnboardingStep::Provider);
    }

    #[test]
    fn provedor_remoto_acrescenta_credencial_e_consentimento() {
        let mut onboarding = OnboardingState::start();

        onboarding.advance(true);
        assert_eq!(onboarding.step, OnboardingStep::Provider);
        onboarding.advance(true);
        assert_eq!(onboarding.step, OnboardingStep::Credential);
        onboarding.advance(true);
        assert_eq!(onboarding.step, OnboardingStep::Consent);
        onboarding.answer_consent(true);
        onboarding.advance(true);
        assert_eq!(onboarding.step, OnboardingStep::Connection);
    }

    #[test]
    fn provedor_local_pula_credencial_e_consentimento() {
        let mut onboarding = OnboardingState::start();

        onboarding.advance(false);
        onboarding.advance(false);

        assert_eq!(onboarding.step, OnboardingStep::Connection);
    }

    #[test]
    fn recusa_de_consentimento_encerra_o_assistente_no_modelo_local() {
        let mut onboarding = OnboardingState::start();
        onboarding.advance(true);
        onboarding.advance(true);
        onboarding.advance(true);
        assert_eq!(onboarding.step, OnboardingStep::Consent);

        onboarding.refuse_remote(CONSENT_REFUSED);

        assert_eq!(onboarding.consent, Some(false));
        assert!(onboarding.ensure_complete().is_ok());
        assert!(
            onboarding
                .notice
                .as_deref()
                .is_some_and(|notice| notice.contains("modelo local")),
            "{:?}",
            onboarding.notice
        );
    }

    #[test]
    fn keyring_indisponivel_registra_bloqueio_do_caminho_remoto() {
        let mut onboarding = OnboardingState::start();
        onboarding.deliver_environment(report(KeyringAvailability::Unavailable(
            "sem serviço de segredos".to_string(),
        )));

        assert!(onboarding.remote_blocked());
        onboarding.refuse_remote(KEYRING_BLOCK_REMOTE);

        assert_eq!(onboarding.consent, Some(false));
        assert_eq!(onboarding.step, OnboardingStep::Connection);
        assert!(onboarding
            .notice
            .as_deref()
            .is_some_and(|notice| notice.contains("cofre de segredos")));
    }

    #[test]
    fn keyring_disponivel_nao_bloqueia_o_caminho_remoto() {
        let mut onboarding = OnboardingState::start();
        onboarding.deliver_environment(report(KeyringAvailability::Available));

        assert!(!onboarding.remote_blocked());
    }

    #[test]
    fn onboarding_incompleto_nao_grava_configuracao() {
        let saves = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let persister = RecordingPersister {
            saves: saves.clone(),
        };
        let mut onboarding = OnboardingState::start();
        onboarding.advance(true);
        onboarding.advance(true);

        if onboarding.ensure_complete().is_ok() {
            persister.save(&Configuration::default()).unwrap();
        }

        assert_eq!(saves.load(std::sync::atomic::Ordering::SeqCst), 0);
        let error = onboarding.ensure_complete().unwrap_err();
        assert!(
            error.contains("não grava configuração incompleta"),
            "{error}"
        );
    }

    #[test]
    fn onboarding_concluido_grava_uma_vez() {
        let saves = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let persister = RecordingPersister {
            saves: saves.clone(),
        };
        let mut onboarding = OnboardingState::start();
        onboarding.advance(false);
        onboarding.advance(false);

        onboarding
            .ensure_complete()
            .expect("o assistente local chega ao fim em duas etapas");
        persister.save(&Configuration::default()).unwrap();

        assert_eq!(saves.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[test]
    fn o_texto_de_consentimento_diz_o_que_sai_da_maquina() {
        let onboarding = OnboardingState::start();

        for item in [
            "alvo analisado",
            "logs das ferramentas",
            "achados",
            "código do projeto",
            "mascarados",
        ] {
            assert!(
                onboarding.consent_prompt().contains(item),
                "faltou {item}: {}",
                onboarding.consent_prompt()
            );
        }
    }

    #[test]
    fn recuar_da_etapa_de_teste_volta_para_a_de_consentimento() {
        let mut onboarding = OnboardingState::start();
        onboarding.advance(true);
        onboarding.advance(true);
        onboarding.advance(true);
        onboarding.answer_consent(true);
        onboarding.advance(true);

        onboarding.retreat();

        assert_eq!(onboarding.step, OnboardingStep::Consent);
    }

    #[test]
    fn ambiente_ainda_nao_avaliado_aparece_na_linha_de_status() {
        let onboarding = OnboardingState::start();

        assert!(onboarding.status().contains("verificando o ambiente"));
    }
}
