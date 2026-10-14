use crate::llm::tool_calling::{ToolTurn, ToolTurnRequest};
use async_trait::async_trait;

#[async_trait]
pub trait LLMProvider: Send + Sync {
    async fn execute_prompt(&self, prompt: &str, model: &str) -> Result<String, anyhow::Error>;

    /// Declara se o provedor implementa o turno com ferramentas.
    ///
    /// O padrão é `false` de propósito: um provedor sem tool calling precisa se
    /// declarar incapaz **antes** de qualquer chamada, senão o agente receberia
    /// texto solto e poderia apresentar como observação algo nunca lido.
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

    /// Embeddings para a recuperação do agente de explicação; o padrão recusa,
    /// e quem chama cai na busca lexical.
    async fn embed(
        &self,
        _inputs: &[String],
        _model: &str,
    ) -> Result<Vec<Vec<f32>>, anyhow::Error> {
        Err(anyhow::anyhow!("o provedor não implementa embeddings",))
    }
}
