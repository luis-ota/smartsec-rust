use tokio::sync::mpsc::UnboundedSender;

use crate::code_agent::agent::ToolCallRecord;

/// Uma linha de atividade observável durante a fase do agente de código.
///
/// O relatório final chega tarde demais: entre "Iniciar" e o resultado há
/// dezenas de chamadas de ferramenta, e uma tela parada nesse intervalo é
/// indistinguível de um travamento.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CodeAgentEvent {
    Started {
        total_findings: usize,
        project_dir: String,
    },
    /// Uma chamada de ferramenta começou, antes de esperar o provedor.
    ToolInvoked {
        finding_index: usize,
        iteration: usize,
        tool: String,
        arguments: String,
    },
    /// A chamada terminou, com o desfecho e o resumo do que a ferramenta leu.
    ToolCompleted(ToolCallRecord),
    /// A fase terminou para um achado, com ou sem localização.
    FindingFinished {
        finding_index: usize,
        located: bool,
        tool_calls: usize,
    },
    Finished {
        located: usize,
        total: usize,
        unavailable_reason: Option<String>,
    },
}

pub type EventSender = UnboundedSender<CodeAgentEvent>;

/// Envia um evento sem travar o agente quando a TUI já foi encerrada.
pub fn emit(sender: Option<&EventSender>, event: CodeAgentEvent) {
    if let Some(sender) = sender {
        let _ = sender.send(event);
    }
}
