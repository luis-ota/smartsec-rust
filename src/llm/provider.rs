use crate::llm::tool_calling::{ToolTurn, ToolTurnRequest};
use async_trait::async_trait;

#[async_trait]
pub trait LLMProvider: Send + Sync {
    async fn execute_prompt(&self, prompt: &str, model: &str) -> Result<String, anyhow::Error>;

    /// Declara se o provedor implementa o turno com ferramentas.
    ///
    /// O padrão é `false` de propósito: um provedor que não sabe conversar em
    /// tool calling precisa se declarar incapaz **antes** de qualquer chamada.
    /// Sem isso, o agente de código tentaria o turno, receberia texto solto sem
    /// chamadas de ferramenta e poderia apresentar como observação do código
    /// algo que o modelo inventou sem nunca ter lido um arquivo.
    fn supports_tool_calling(&self) -> bool {
        false
    }

    /// Executa um turno do agente de código com as ferramentas registradas.
    ///
    /// A implementação padrão recusa com a mensagem usada pelo fallback
    /// determinístico, de modo que nenhum caminho precise adivinhar o motivo.
    async fn execute_tool_turn(
        &self,
        _request: &ToolTurnRequest,
    ) -> Result<ToolTurn, anyhow::Error> {
        Err(anyhow::anyhow!("o provedor não implementa tool calling",))
    }
}
