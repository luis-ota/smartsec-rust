use crate::config::environment::{
    ConnectionCheck, EnvironmentReport, OnboardingProbe, SystemOnboardingProbe,
};
use crate::config::llm_config::LlmProviderKind;
use crate::config::onboarding::{
    OnboardingState, OnboardingStep, CONSENT_REFUSED, KEYRING_BLOCK_REMOTE,
};
use crate::tui::interaction::FocusTarget;
use crate::tui::state::AppState;
use std::sync::Arc;
use tokio::sync::mpsc;

const KEYRING_NOTICE: &str = "Cofre de segredos indisponível: chaves de provedores remotos não poderão ser salvas; o assistente manterá o modelo local.";

/// Resposta vinda da sondagem assíncrona do ambiente ou do teste de conexão.
pub enum OnboardingEvent {
    Environment(EnvironmentReport),
    Connection(ConnectionCheck),
}

impl AppState {
    /// Abre o assistente de primeira execução com a sondagem do sistema real.
    pub fn start_onboarding(&mut self) {
        let probe = self
            .onboarding_probe
            .clone()
            .unwrap_or_else(|| Arc::new(SystemOnboardingProbe::new()));
        self.start_onboarding_with(probe);
    }

    /// Só existe para teste: a sondagem de produção fala com a rede, com o
    /// keyring e com o Podman da máquina.
    #[cfg(test)]
    pub(crate) fn set_onboarding_probe(&mut self, probe: Arc<dyn OnboardingProbe>) {
        self.onboarding_probe = Some(probe);
    }

    /// Só existe para teste: o gravador de produção escreve no arquivo do
    /// usuário e no keyring do sistema.
    #[cfg(test)]
    pub(crate) fn set_onboarding_persister(
        &mut self,
        persister: Box<dyn crate::config::onboarding::OnboardingPersister>,
    ) {
        self.onboarding_persister = persister;
    }

    /// Abre o assistente. A sondagem em si sai em [`Self::spawn_onboarding_probe`],
    /// fora do caminho de renderização.
    pub fn start_onboarding_with(&mut self, probe: Arc<dyn OnboardingProbe>) {
        self.onboarding = Some(OnboardingState::start());
        self.onboarding_probe = Some(probe);
        self.onboarding_cursor = 0;
        self.onboarding_error = None;
        self.onboarding_probe_pending = true;
        self.reset_settings_draft();
        self.focus = FocusTarget::OnboardingList;
    }

    /// Dispara uma única vez a sondagem do ambiente, em task própria.
    pub fn spawn_onboarding_probe(&mut self) {
        if !self.onboarding_probe_pending {
            return;
        }
        let Some(probe) = self.onboarding_probe.clone() else {
            return;
        };
        self.onboarding_probe_pending = false;
        let (sender, receiver) = mpsc::channel(4);
        self.onboarding_sender = Some(sender.clone());
        self.onboarding_events = Some(receiver);
        self.onboarding_task = Some(tokio::spawn(async move {
            let report = probe.environment().await;
            let _ = sender.send(OnboardingEvent::Environment(report)).await;
        }));
    }

    pub fn onboarding_open(&self) -> bool {
        self.onboarding.is_some()
    }

    pub fn onboarding_step(&self) -> Option<OnboardingStep> {
        self.onboarding.as_ref().map(|onboarding| onboarding.step)
    }

    /// Sai do assistente sem gravar nada: o rascunho volta ao que está em vigor.
    pub fn cancel_onboarding(&mut self) {
        self.onboarding = None;
        self.onboarding_cursor = 0;
        self.onboarding_events = None;
        self.onboarding_sender = None;
        self.onboarding_task = None;
        self.onboarding_probe_pending = false;
        self.reset_settings_draft();
        self.focus = FocusTarget::SplashTarget;
    }

    /// Volta uma etapa, descartando a decisão daquela etapa.
    pub fn onboarding_retreat(&mut self) {
        if let Some(onboarding) = self.onboarding.as_mut() {
            onboarding.retreat();
        }
        self.onboarding_cursor = 0;
        self.onboarding_error = None;
    }

    /// Aciona o item escolhido da lista do passo atual.
    pub fn onboarding_activate(&mut self, index: usize) {
        let Some(step) = self.onboarding_step() else {
            return;
        };
        self.onboarding_cursor = index;
        match step {
            OnboardingStep::Environment => self.onboarding_forward(),
            OnboardingStep::Provider => {
                let labels = LlmProviderKind::all_labels();
                if index < labels.len() {
                    self.set_provider_index(index);
                } else {
                    self.onboarding_forward();
                }
            }
            OnboardingStep::Credential => {
                let blocked = self
                    .onboarding
                    .as_ref()
                    .is_some_and(OnboardingState::remote_blocked);
                if blocked {
                    self.onboarding_refuse(KEYRING_BLOCK_REMOTE);
                } else {
                    self.onboarding_forward();
                }
            }
            OnboardingStep::Consent if index == 0 => {
                if let Some(onboarding) = self.onboarding.as_mut() {
                    onboarding.answer_consent(true);
                }
                self.settings_remote_consent = true;
                self.onboarding_forward();
            }
            OnboardingStep::Consent => self.onboarding_refuse(CONSENT_REFUSED),
            OnboardingStep::Connection => match index {
                0 => self.test_onboarding_connection(),
                _ => self.onboarding_complete(),
            },
        }
        self.focus = FocusTarget::OnboardingList;
    }

    /// Avança no fluxo com o provedor atualmente escolhido no rascunho.
    pub fn onboarding_forward(&mut self) {
        let remote = self.settings_connection_is_remote();
        if let Some(onboarding) = self.onboarding.as_mut() {
            onboarding.advance(remote);
        }
        self.onboarding_cursor = 0;
        self.onboarding_error = None;
    }

    /// Fecha o caminho remoto e devolve o rascunho ao modelo local.
    pub fn onboarding_refuse(&mut self, reason: &str) {
        if let Some(onboarding) = self.onboarding.as_mut() {
            onboarding.refuse_remote(reason);
        }
        self.force_local_provider();
        self.onboarding_cursor = 0;
    }

    /// Escolhe o provedor e preenche endpoint e modelo padrão dele.
    pub fn set_provider_index(&mut self, index: usize) {
        let labels = LlmProviderKind::all_labels();
        self.settings_provider_idx = index.min(labels.len().saturating_sub(1));
        let provider = LlmProviderKind::from_label(labels[self.settings_provider_idx]);
        self.settings_input_base_url = provider.default_base_url().to_string();
        self.settings_input_model = provider.default_model().to_string();
        self.settings_error = None;
        self.settings_api_key_touched = false;
    }

    /// Apaga a credencial digitada: ela só existia para o caminho remoto
    /// que acabou de ser recusado.
    fn force_local_provider(&mut self) {
        self.set_provider_index(local_provider_index());
        self.settings_remote_consent = false;
        self.settings_input_api_key.clear();
        self.settings_api_key_touched = true;
    }

    /// Pede uma chamada mínima ao provedor para confirmar credencial e endpoint.
    pub fn test_onboarding_connection(&mut self) {
        let Some(probe) = self.onboarding_probe.clone() else {
            return;
        };
        let Some(sender) = self.onboarding_sender.clone() else {
            return;
        };
        let llm = self
            .settings_candidate()
            .map(|candidate| candidate.llm)
            .unwrap_or_else(|_| self.config.llm.clone());
        if let Some(onboarding) = self.onboarding.as_mut() {
            onboarding.deliver_connection(ConnectionCheck::Running);
        }
        self.onboarding_task = Some(tokio::spawn(async move {
            let check = probe.connection(&llm).await;
            let _ = sender.send(OnboardingEvent::Connection(check)).await;
        }));
    }

    /// Conclui o assistente, mostrando a falha sem fechar a tela.
    pub fn onboarding_complete(&mut self) {
        if let Err(error) = self.complete_onboarding() {
            self.onboarding_error = Some(error);
        }
    }

    /// Grava a configuração concluída pelo assistente.
    ///
    /// Só grava com o assistente nas etapas finais: um caminho incompleto
    /// devolve erro e não toca no arquivo do usuário nem no keyring.
    pub fn complete_onboarding(&mut self) -> Result<(), String> {
        let Some(onboarding) = self.onboarding.as_ref() else {
            return Err("o assistente inicial não está aberto".to_string());
        };
        onboarding.ensure_complete()?;
        let candidate = self.settings_candidate()?;
        self.onboarding_persister.save(&candidate)?;
        self.commit_settings(candidate);
        self.onboarding = None;
        self.onboarding_cursor = 0;
        self.focus = FocusTarget::SplashTarget;
        Ok(())
    }

    pub(crate) async fn poll_onboarding_events(&mut self) {
        let Some(mut receiver) = self.onboarding_events.take() else {
            return;
        };
        while let Ok(event) = receiver.try_recv() {
            let Some(onboarding) = self.onboarding.as_mut() else {
                break;
            };
            match event {
                OnboardingEvent::Environment(report) => {
                    let blocked = report.blocks_remote_provider();
                    onboarding.deliver_environment(report);
                    if blocked {
                        onboarding.notice = Some(KEYRING_NOTICE.to_string());
                    }
                }
                OnboardingEvent::Connection(check) => onboarding.deliver_connection(check),
            }
        }
        self.onboarding_events = Some(receiver);
    }
}

/// Índice do provedor local na lista de rótulos.
///
/// Localizado pelo endpoint loopback em vez de posição fixa: a ordem dos
/// provedores evolui e o assistente precisa continuar escolhendo o local.
fn local_provider_index() -> usize {
    LlmProviderKind::all_labels()
        .iter()
        .position(|label| {
            LlmProviderKind::from_label(label)
                .default_base_url()
                .starts_with("http://localhost")
        })
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::environment::{
        FixedOnboardingProbe, KeyringAvailability, LocalEndpoint, PodmanMode,
    };
    use crate::config::onboarding::OnboardingStep;
    use crate::config::Configuration;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Clone)]
    struct RecordingPersister {
        saves: Arc<AtomicUsize>,
        last: Arc<std::sync::Mutex<Option<Configuration>>>,
    }

    impl crate::config::onboarding::OnboardingPersister for RecordingPersister {
        fn save(&self, config: &Configuration) -> Result<(), String> {
            self.saves.fetch_add(1, Ordering::SeqCst);
            *self.last.lock().unwrap() = Some(config.clone());
            Ok(())
        }
    }

    fn app() -> AppState {
        let mut app =
            AppState::new(Configuration::default()).expect("configuração de teste válida");
        // Todo `AppState` de teste nasce com o gravador de memória: o gravador
        // real escreveria em `~/.config/smartsec/config.toml` e no keyring real.
        app.set_onboarding_persister(Box::new(RecordingPersister {
            saves: Arc::new(AtomicUsize::new(0)),
            last: Arc::new(std::sync::Mutex::new(None)),
        }));
        app
    }

    fn local_endpoint() -> LocalEndpoint {
        LocalEndpoint {
            name: "llama.cpp".to_string(),
            base_url: "http://localhost:8080/v1".to_string(),
        }
    }

    fn report(keyring: KeyringAvailability) -> EnvironmentReport {
        EnvironmentReport {
            local_llm: Some(local_endpoint()),
            keyring,
            podman: PodmanMode::Rootless,
        }
    }

    /// Reabrir o assistente não pode repetir a sondagem: rede, keyring e Podman
    /// são consultados uma vez por sessão.
    #[tokio::test]
    async fn a_sondagem_so_dispara_uma_vez_por_sessao_do_assistente() {
        let mut app = app();
        start(&mut app, report(KeyringAvailability::Available)).await;
        let report_after_first = app
            .onboarding
            .as_ref()
            .and_then(|state| state.environment.clone());

        settle(&mut app).await;

        assert_eq!(
            app.onboarding
                .as_ref()
                .and_then(|state| state.environment.clone()),
            report_after_first
        );
    }

    /// Índice de um provedor cujo endpoint padrão sai da máquina.
    fn remote_provider_index() -> usize {
        LlmProviderKind::all_labels()
            .iter()
            .position(|label| {
                !LlmProviderKind::from_label(label)
                    .default_base_url()
                    .starts_with("http://localhost")
            })
            .expect("a lista de provedores tem um caminho remoto")
    }

    /// Índice da opção "Continuar" da etapa de provedor.
    fn provider_continue() -> usize {
        LlmProviderKind::all_labels().len()
    }

    /// Drena a task da sondagem sem depender de tempo de parede.
    async fn settle(app: &mut AppState) {
        for _ in 0..8 {
            app.spawn_onboarding_probe();
            tokio::task::yield_now().await;
            app.poll_onboarding_events().await;
        }
    }

    async fn start(app: &mut AppState, report: EnvironmentReport) {
        app.start_onboarding_with(Arc::new(FixedOnboardingProbe {
            report,
            check: ConnectionCheck::Succeeded("resposta ok".to_string()),
        }));
        settle(app).await;
    }

    /// Primeiro acesso: sem configuração global o assistente abre sozinho.
    #[test]
    fn primeiro_acesso_mostra_o_assistente() {
        assert!(crate::config::onboarding::is_first_run(false));
    }

    /// Segundo acesso: com o arquivo global presente, ninguém é interrompido.
    #[test]
    fn segundo_acesso_nao_mostra_o_assistente() {
        assert!(!crate::config::onboarding::is_first_run(true));
    }

    #[tokio::test]
    async fn o_assistente_comeca_pela_etapa_de_ambiente() {
        let mut app = app();
        start(&mut app, report(KeyringAvailability::Available)).await;

        assert!(app.onboarding_open());
        assert_eq!(app.onboarding_step(), Some(OnboardingStep::Environment));
        let local_llm = app
            .onboarding
            .as_ref()
            .and_then(|state| state.environment.as_ref())
            .and_then(|found| found.local_llm.clone());
        assert_eq!(
            local_llm,
            Some(local_endpoint()),
            "a sondagem precisa entregar o que achou antes de perguntar algo"
        );
    }

    #[tokio::test]
    async fn keyring_indisponivel_avisa_e_nao_quebra_o_assistente() {
        let mut app = app();
        start(
            &mut app,
            report(KeyringAvailability::Unavailable(
                "nenhum serviço de segredos ativo".to_string(),
            )),
        )
        .await;

        let notice = app
            .onboarding
            .as_ref()
            .and_then(|state| state.notice.clone())
            .expect("a indisponibilidade do cofre precisa aparecer");
        assert!(notice.contains("não poderão ser salvas"), "{notice}");
        assert_eq!(app.onboarding_step(), Some(OnboardingStep::Environment));

        // O operador ainda consegue avançar: o bloqueio impede o remoto, não o
        // caminho local.
        app.onboarding_activate(0);
        assert_eq!(app.onboarding_step(), Some(OnboardingStep::Provider));
    }

    #[tokio::test]
    async fn keyring_indisponivel_fecha_o_caminho_remoto_na_etapa_de_credencial() {
        let mut app = app();
        start(
            &mut app,
            report(KeyringAvailability::Unavailable("sem serviço".to_string())),
        )
        .await;
        app.onboarding_activate(0);
        app.onboarding_activate(remote_provider_index());
        app.onboarding_activate(provider_continue());
        assert_eq!(app.onboarding_step(), Some(OnboardingStep::Credential));

        app.onboarding_activate(0);

        assert_eq!(
            app.onboarding_step(),
            Some(OnboardingStep::Connection),
            "sem cofre de segredos o assistente não pode seguir para o remoto"
        );
        assert!(!app.settings_connection_is_remote());
        assert!(app.settings_input_api_key.is_empty());
    }

    #[tokio::test]
    async fn recusa_de_consentimento_bloqueia_o_provedor_remoto() {
        let mut app = app();
        start(&mut app, report(KeyringAvailability::Available)).await;
        app.onboarding_activate(0);
        app.onboarding_activate(remote_provider_index());
        app.onboarding_activate(provider_continue());
        app.settings_input_api_key = "chave-digitada".to_string();
        app.settings_api_key_touched = true;
        app.onboarding_activate(0);
        assert_eq!(app.onboarding_step(), Some(OnboardingStep::Consent));

        app.onboarding_activate(1);

        assert!(!app.settings_connection_is_remote());
        assert!(!app.settings_remote_consent);
        assert!(
            app.settings_input_api_key.is_empty(),
            "a credencial remota não pode sobreviver a um caminho recusado"
        );
        assert_eq!(app.onboarding_step(), Some(OnboardingStep::Connection));
    }

    #[tokio::test]
    async fn consentimento_aceito_segue_para_o_teste_de_conexao() {
        let mut app = app();
        start(&mut app, report(KeyringAvailability::Available)).await;
        app.onboarding_activate(0);
        app.onboarding_activate(remote_provider_index());
        app.onboarding_activate(provider_continue());
        app.onboarding_activate(0);
        app.settings_input_api_key = "chave-digitada".to_string();
        app.settings_api_key_touched = true;

        app.onboarding_activate(0);

        assert!(app.settings_remote_consent);
        assert!(app.settings_connection_is_remote());
        assert_eq!(app.onboarding_step(), Some(OnboardingStep::Connection));
    }

    #[tokio::test]
    async fn onboarding_incompleto_nao_grava_configuracao() {
        let mut app = app();
        let saves = Arc::new(AtomicUsize::new(0));
        app.set_onboarding_persister(Box::new(RecordingPersister {
            saves: saves.clone(),
            last: Arc::new(std::sync::Mutex::new(None)),
        }));
        start(&mut app, report(KeyringAvailability::Available)).await;
        app.onboarding_activate(0);

        let error = app.complete_onboarding().unwrap_err();

        assert!(
            error.contains("não grava configuração incompleta"),
            "{error}"
        );
        assert_eq!(saves.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn sair_do_assistente_nao_grava_nada_e_descarta_o_rascunho() {
        let mut app = app();
        let saves = Arc::new(AtomicUsize::new(0));
        app.set_onboarding_persister(Box::new(RecordingPersister {
            saves: saves.clone(),
            last: Arc::new(std::sync::Mutex::new(None)),
        }));
        start(&mut app, report(KeyringAvailability::Available)).await;
        app.onboarding_activate(0);
        app.onboarding_activate(2);
        let chosen = app.settings_input_base_url.clone();

        app.cancel_onboarding();

        assert!(!app.onboarding_open());
        assert_eq!(saves.load(Ordering::SeqCst), 0);
        assert_eq!(
            app.settings_input_base_url, app.config.llm.base_url,
            "o rascunho descartado não pode virar configuração em vigor"
        );
        assert_ne!(app.settings_input_base_url, chosen);
    }

    #[tokio::test]
    async fn o_assistente_concluido_grava_pelo_persistor_injetado() {
        let mut app = app();
        let saves = Arc::new(AtomicUsize::new(0));
        let last = Arc::new(std::sync::Mutex::new(None));
        app.set_onboarding_persister(Box::new(RecordingPersister {
            saves: saves.clone(),
            last: last.clone(),
        }));
        start(&mut app, report(KeyringAvailability::Available)).await;
        app.onboarding_activate(0);
        // Provedor de API: credencial e consentimento antes da conexão.
        app.onboarding_activate(0);
        app.onboarding_activate(provider_continue());
        app.onboarding_activate(0);
        app.onboarding_activate(0);
        assert_eq!(app.onboarding_step(), Some(OnboardingStep::Connection));

        app.complete_onboarding().unwrap();

        assert_eq!(saves.load(Ordering::SeqCst), 1);
        let saved = last
            .lock()
            .unwrap()
            .clone()
            .expect("algo precisa ter sido salvo");
        assert_eq!(saved.llm.model, app.config.llm.model);
        assert!(!app.onboarding_open());
        assert!(app.config_warning.is_none());
    }

    #[tokio::test]
    async fn o_teste_de_conexao_mostra_a_resposta_da_sondagem_injetada() {
        let mut app = app();
        app.start_onboarding_with(Arc::new(FixedOnboardingProbe {
            report: report(KeyringAvailability::Available),
            check: ConnectionCheck::Failed(
                "https://api.exemplo/v1/models respondeu 401: chave recusada".to_string(),
            ),
        }));
        settle(&mut app).await;
        app.onboarding_activate(0);
        app.onboarding_activate(0);
        app.onboarding_activate(provider_continue());

        app.test_onboarding_connection();
        settle(&mut app).await;

        assert_eq!(
            app.onboarding
                .as_ref()
                .map(|state| state.connection.clone()),
            Some(ConnectionCheck::Failed(
                "https://api.exemplo/v1/models respondeu 401: chave recusada".to_string()
            ))
        );
    }
}
