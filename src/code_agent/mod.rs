//! Agente de código: sandbox read-only, ferramentas locais e o laço de
//! tool calling que localiza a origem dos achados no projeto analisado.
//!
//! O módulo é a única superfície pela qual o SmartSec lê o código do alvo.
//! Toda leitura passa pelo sandbox de `workspace`, que canonicaliza o caminho e
//! exige contenção na raiz, e pelas ferramentas de `tools`, que nunca escrevem
//! no projeto analisado.

pub mod agent;
pub mod tools;
pub mod workspace;

/// Limite padrão de leitura por arquivo, em bytes.
pub const DEFAULT_MAX_FILE_BYTES: usize = 64 * 1024;

/// Limites operacionais do agente de código.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodeAgentLimits {
    /// Tamanho máximo lido por arquivo, em bytes.
    pub max_file_bytes: usize,
    /// Número máximo de resultados devolvidos por busca.
    pub max_search_results: usize,
    /// Número máximo de iterações do loop de tool calling.
    pub max_iterations: usize,
    /// Timeout da análise por achado, em segundos.
    pub analysis_timeout_secs: u64,
    /// Timeout de execução de `run_command`, em segundos.
    pub command_timeout_secs: u64,
}

impl Default for CodeAgentLimits {
    fn default() -> Self {
        Self {
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
            max_search_results: 50,
            max_iterations: 12,
            analysis_timeout_secs: 45,
            command_timeout_secs: 10,
        }
    }
}
