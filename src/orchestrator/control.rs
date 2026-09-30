//! Canal de controle compartilhado entre a interface e o executor Podman
//! (REQ14) e a regra automática de interrupção (REQ05).
//!
//! A pausa, a retomada e o cancelamento deixam de ser bandeiras locais: eles
//! atravessam o `Orchestrator` e chegam ao `PodmanExecutor`, que age sobre o
//! container real (`podman pause`, `podman unpause`, `podman stop` seguido de
//! `podman rm --force`). O canal é um `watch` de valor enum, para que o
//! executor sempre observe o estado mais recente, inclusive quando a ordem
//! chega enquanto o `create` ou o `start` ainda está em voo.
//!
//! O módulo não depende de nenhum outro do projeto, para poder ser reusado
//! isoladamente pelos testes de integração do executor.

use std::sync::Arc;
use tokio::sync::watch;

/// Identificador da regra automática que interrompeu a varredura.
pub const RULE_MAX_CRITICAL_FINDINGS: &str = "max_critical_findings";
/// Identificador do cancelamento solicitado pelo usuário na TUI.
pub const RULE_USER_CANCELLED: &str = "cancelado_pelo_usuario";
/// Identificador do cancelamento provocado por sinal do sistema.
pub const RULE_SYSTEM_SIGNAL: &str = "cancelado_por_sinal";

/// Estado do container em execução, controlado pela interface.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum RunControl {
    /// O scanner segue executando normalmente.
    #[default]
    Running,
    /// O container está pausado (`podman pause`) e o pipeline aguarda.
    Paused,
    /// O cancelamento foi solicitado: o container deve ser encerrado e removido.
    Cancelled,
}

impl RunControl {
    /// Rótulo em pt-BR do estado, para tela e relatório.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Running => "executando",
            Self::Paused => "pausado",
            Self::Cancelled => "cancelado",
        }
    }
}

/// Motivo auditável de uma interrupção (REQ05 e REQ14).
///
/// `ScanMetadata` é desserializado de históricos antigos, por isso todo campo
/// novo é `#[serde(default)]`: um log gravado antes desta feature continua
/// legível, com o motivo vazio.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct InterruptionReason {
    /// Regra ou origem: `max_critical_findings`, `cancelado_pelo_usuario` ou
    /// `cancelado_por_sinal`.
    pub rule: String,
    /// Texto em pt-BR pronto para relatório e tela.
    pub message: String,
    /// Ferramenta em execução quando a interrupção ocorreu, se houver.
    #[serde(default)]
    pub tool: Option<String>,
    /// Quantidade de achados críticos observada quando a regra disparou.
    #[serde(default)]
    pub critical_count: usize,
    /// Limiar configurado que a regra ultrapassou.
    #[serde(default)]
    pub threshold: Option<usize>,
    /// Momento da interrupção em ISO 8601.
    #[serde(default)]
    pub recorded_at: String,
}

impl InterruptionReason {
    /// Motivo do cancelamento pedido pelo usuário na TUI.
    pub fn user_cancelled() -> Self {
        Self {
            rule: RULE_USER_CANCELLED.to_string(),
            message: "Execução cancelada pelo usuário".to_string(),
            tool: None,
            critical_count: 0,
            threshold: None,
            recorded_at: now_iso8601(),
        }
    }

    /// Motivo do cancelamento provocado por SIGINT/SIGTERM no modo headless.
    pub fn system_signal(label: &str) -> Self {
        Self {
            rule: RULE_SYSTEM_SIGNAL.to_string(),
            message: format!(
                "Execução cancelada pelo sinal {label}; o relatório e o log estruturado foram preservados"
            ),
            tool: None,
            critical_count: 0,
            threshold: None,
            recorded_at: now_iso8601(),
        }
    }

    /// Motivo do disparo da regra automática por quantidade de críticos.
    pub fn max_critical_findings(critical_count: usize, threshold: usize, tool: &str) -> Self {
        Self {
            rule: RULE_MAX_CRITICAL_FINDINGS.to_string(),
            message: format!(
                "Regra automática de interrupção: {critical_count} vulnerabilidades críticas em {tool} atingiram o limite de {threshold}"
            ),
            tool: Some(tool.to_string()),
            critical_count,
            threshold: Some(threshold),
            recorded_at: now_iso8601(),
        }
    }
}

fn now_iso8601() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// Canal de controle compartilhado (REQ14).
///
/// Clonar o canal preserva a mesma sessão de controle: a interface, o
/// orquestrador e o executor enxergam exatamente o mesmo estado. O motivo da
/// interrupção viaja junto, porque a TUI e a task de execução têm orquestradores
/// distintos ligados apenas por este canal.
#[derive(Clone, Debug)]
pub struct ControlChannel {
    sender: Arc<watch::Sender<RunControl>>,
    reason: Arc<std::sync::Mutex<Option<InterruptionReason>>>,
}

impl Default for ControlChannel {
    fn default() -> Self {
        Self::new()
    }
}

impl ControlChannel {
    pub fn new() -> Self {
        let (sender, _) = watch::channel(RunControl::Running);
        Self {
            sender: Arc::new(sender),
            reason: Arc::new(std::sync::Mutex::new(None)),
        }
    }

    /// Assina o canal com o estado corrente; o assinante nunca perde uma
    /// pausa ou um cancelamento enviado antes da assinatura.
    pub fn subscribe(&self) -> watch::Receiver<RunControl> {
        self.sender.subscribe()
    }

    /// Estado mais recente sem marcar o valor como visto.
    pub fn snapshot(&self) -> RunControl {
        *self.sender.borrow()
    }

    pub fn is_cancelled(&self) -> bool {
        self.snapshot() == RunControl::Cancelled
    }

    pub fn is_paused(&self) -> bool {
        self.snapshot() == RunControl::Paused
    }

    /// Estado corrente rotulado, em pt-BR.
    pub fn label(&self) -> &'static str {
        self.snapshot().label()
    }

    /// Solicita a pausa. Repetir a pausa é inofensivo: o `watch` só notifica
    /// quando o valor muda de fato.
    pub fn pause(&self) {
        self.sender.send_replace(RunControl::Paused);
    }

    /// Solicita a retomada. Retomar uma execução que não está pausada também
    /// é inofensivo.
    pub fn resume(&self) {
        self.sender.send_replace(RunControl::Running);
    }

    /// Solicita o cancelamento cooperativo. O cancelamento é terminal: um
    /// cancelamento anterior não pode ser desfeito por uma retomada.
    pub fn cancel(&self) {
        self.sender.send_replace(RunControl::Cancelled);
    }

    /// Grava o motivo da interrupção uma única vez, preservando o primeiro.
    ///
    /// O primeiro evento é o que explica por que a varredura parou; os
    /// seguintes (sinal depois do clique, por exemplo) são consequência.
    pub fn record_interruption(&self, reason: InterruptionReason) {
        let Ok(mut stored) = self.reason.lock() else {
            return;
        };
        if stored.is_none() {
            *stored = Some(reason);
        }
    }

    /// Motivo registrado, se houver.
    pub fn interruption(&self) -> Option<InterruptionReason> {
        self.reason.lock().ok().and_then(|stored| stored.clone())
    }

    /// Mantém o pipeline aguardando enquanto a execução estiver pausada.
    ///
    /// O cancelamento tem precedência sobre a pausa: ao chegar durante uma
    /// pausa, o pipeline retoma apenas para o executor observar o cancelamento.
    pub async fn wait_while_paused(&self) -> RunControl {
        let mut receiver = self.subscribe();
        loop {
            match *receiver.borrow_and_update() {
                RunControl::Paused => {}
                state => return state,
            }
            if receiver.changed().await.is_err() {
                return RunControl::Cancelled;
            }
        }
    }
}

/// Sinal do sistema que cancelou a execução headless.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InterruptSignal {
    Sigint,
    Sigterm,
}

impl InterruptSignal {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Sigint => "SIGINT",
            Self::Sigterm => "SIGTERM",
        }
    }

    /// Código de saída do modo headless para este sinal.
    ///
    /// Adota a convenção POSIX `128 + número do sinal` (130 para SIGINT e 143
    /// para SIGTERM), já interpretada por shells e pelo GitHub Actions. Um
    /// cancelamento pedido pelo operador não é erro interno (`2`) nem sucesso
    /// (`0`) nem achado crítico (`1`).
    pub const fn exit_code(self) -> i32 {
        match self {
            Self::Sigint => 130,
            Self::Sigterm => 143,
        }
    }
}

/// Observa SIGINT/SIGTERM e cancela a execução pelo canal de controle.
///
/// O primeiro sinal é cooperativo: o container é encerrado, o log estruturado e
/// o relatório são gravados e só então o processo sai. Um segundo sinal
/// encerra o processo imediatamente, para que o operador não fique preso a um
/// Podman travado — nesse caso a auditoria pode não ser gravada.
pub struct SignalWatcher {
    received: watch::Receiver<Option<InterruptSignal>>,
}

impl SignalWatcher {
    pub fn install(control: ControlChannel) -> Self {
        let (sender, received) = watch::channel(None);
        tokio::spawn(async move {
            #[cfg(unix)]
            {
                let mut interrupt =
                    match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
                    {
                        Ok(stream) => stream,
                        Err(_) => return,
                    };
                let mut terminate =
                    match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    {
                        Ok(stream) => stream,
                        Err(_) => return,
                    };
                loop {
                    let detected = tokio::select! {
                        _ = interrupt.recv() => InterruptSignal::Sigint,
                        _ = terminate.recv() => InterruptSignal::Sigterm,
                    };
                    if sender.borrow().is_some() {
                        // Segundo sinal: o operador insiste, o processo sai agora.
                        std::process::exit(InterruptSignal::Sigterm.exit_code());
                    }
                    let _ = sender.send(Some(detected));
                    control
                        .record_interruption(InterruptionReason::system_signal(detected.label()));
                    control.cancel();
                }
            }
            #[cfg(not(unix))]
            {
                let _ = (sender, control);
            }
        });
        Self { received }
    }

    /// Primeiro sinal recebido, se algum.
    pub fn received(&self) -> Option<InterruptSignal> {
        *self.received.borrow()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn pause_resume_and_cancel_travel_through_the_shared_channel() {
        let control = ControlChannel::new();
        let mut executor_side = control.subscribe();

        assert_eq!(control.snapshot(), RunControl::Running);
        assert!(!control.is_paused());

        control.pause();
        assert_eq!(*executor_side.borrow(), RunControl::Paused);
        assert!(
            executor_side.has_changed().unwrap(),
            "o executor vê a pausa"
        );
        control.resume();
        assert_eq!(*executor_side.borrow_and_update(), RunControl::Running);

        control.cancel();
        assert!(control.is_cancelled());
        assert_eq!(*executor_side.borrow_and_update(), RunControl::Cancelled);
    }

    #[tokio::test]
    async fn a_late_subscriber_never_misses_an_order() {
        let control = ControlChannel::new();
        control.pause();

        // O executor que assina depois do `create` ainda enxerga a pausa.
        let late = control.subscribe();
        assert_eq!(*late.borrow(), RunControl::Paused);
    }

    #[tokio::test]
    async fn repeated_pause_and_resume_are_idempotent() {
        let control = ControlChannel::new();
        let mut receiver = control.subscribe();

        control.pause();
        assert_eq!(*receiver.borrow_and_update(), RunControl::Paused);
        // Pausar de novo não muda o estado pedido: o controlador do container
        // decide, pelo estado já aplicado, se o `podman pause` é reemitido.
        control.pause();
        assert_eq!(*receiver.borrow_and_update(), RunControl::Paused);
        control.resume();
        control.resume();
        assert_eq!(*receiver.borrow_and_update(), RunControl::Running);
        assert_eq!(control.snapshot().label(), "executando");
    }

    #[test]
    fn the_interruption_reason_travels_with_the_shared_channel() {
        let control = ControlChannel::new();
        // A TUI e a task de execução são referências distintas ao mesmo canal.
        let task_side = control.clone();
        assert!(task_side.interruption().is_none());

        control.record_interruption(InterruptionReason::user_cancelled());
        control.record_interruption(InterruptionReason::system_signal("SIGINT"));

        let reason = task_side
            .interruption()
            .expect("o motivo precisa atravessar o canal");
        assert_eq!(reason.rule, RULE_USER_CANCELLED);
        assert_eq!(
            control.interruption().map(|reason| reason.rule),
            Some(RULE_USER_CANCELLED.to_string()),
            "o primeiro motivo é o que explica o cancelamento"
        );
    }

    #[tokio::test]
    async fn the_pipeline_waits_while_paused_and_returns_on_cancel() {
        let control = ControlChannel::new();
        control.pause();
        // Outra referência ao mesmo canal: é a sessão de controle que importa,
        // não a instância do orchestrator.
        let waiter = control.clone();

        let handle = tokio::spawn(async move { waiter.wait_while_paused().await });
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!handle.is_finished(), "a pausa precisa segurar o pipeline");

        control.resume();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), handle)
                .await
                .expect("a retomada precisa liberar o pipeline")
                .unwrap(),
            RunControl::Running
        );
    }

    #[tokio::test]
    async fn cancel_wins_over_pause_in_the_pipeline() {
        let control = ControlChannel::new();
        control.pause();
        // Outra referência ao mesmo canal: é a sessão de controle que importa,
        // não a instância do orchestrator.
        let waiter = control.clone();
        let handle = tokio::spawn(async move { waiter.wait_while_paused().await });

        control.cancel();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), handle)
                .await
                .expect("o cancelamento não pode ficar preso na pausa")
                .unwrap(),
            RunControl::Cancelled
        );
    }

    #[test]
    fn cancellation_exit_codes_follow_the_posix_convention() {
        assert_eq!(InterruptSignal::Sigint.exit_code(), 130);
        assert_eq!(InterruptSignal::Sigterm.exit_code(), 143);
        assert_eq!(InterruptSignal::Sigint.label(), "SIGINT");
        assert_eq!(InterruptSignal::Sigterm.label(), "SIGTERM");
    }
}
