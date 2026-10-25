//! Agente de código: sandbox read-only, ferramentas locais e o laço de
//! tool calling que localiza a origem dos achados no projeto analisado.
//!
//! O módulo é a única superfície pela qual o SmartSec lê o código do alvo: toda
//! leitura passa pelo sandbox de `workspace`, que canonicaliza o caminho e exige
//! contenção na raiz, e pelas ferramentas de `tools`, que nunca escrevem no
//! projeto analisado.

pub mod agent;
pub mod audit_trail;
pub mod progress;
pub mod tools;
pub mod workspace;

/// Limite padrão de leitura por arquivo, em bytes.
pub const DEFAULT_MAX_FILE_BYTES: usize = 64 * 1024;

/// Teto de entradas devolvidas por `list_dir`. Medido: `list_dir` na raiz de um
/// projeto com `target/` devolveu 19.788 bytes e o provedor respondeu 413.
pub const DEFAULT_MAX_LIST_ENTRIES: usize = 200;

/// Teto de bytes de qualquer saída de ferramenta, aplicado depois do teto
/// específico da ferramenta.
pub const DEFAULT_MAX_TOOL_OUTPUT_BYTES: usize = 16 * 1024;

/// Teto padrão de resultados por busca.
pub const DEFAULT_MAX_SEARCH_RESULTS: usize = 50;

/// Orçamento global de chamadas de ferramenta por fase de código.
///
/// A fase roda uma vez por scan, com dezenas de achados: um teto por achado não
/// impede o total de explodir. Medido: 1.970 chamadas em 184 achados.
pub const DEFAULT_MAX_TOTAL_TOOL_CALLS: usize = 120;

/// Orçamento global de tempo da fase de código, em segundos.
pub const DEFAULT_SCAN_TIMEOUT_SECS: u64 = 180;

/// Limites operacionais do agente de código.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodeAgentLimits {
    /// Tamanho máximo lido por arquivo, em bytes.
    pub max_file_bytes: usize,
    /// Número máximo de resultados devolvidos por busca.
    pub max_search_results: usize,
    /// Número máximo de entradas devolvidas por `list_dir`.
    pub max_list_entries: usize,
    /// Teto de bytes da saída de qualquer ferramenta.
    pub max_tool_output_bytes: usize,
    /// Número máximo de iterações do loop de tool calling por achado.
    pub max_iterations: usize,
    /// Timeout da análise por achado, em segundos.
    pub analysis_timeout_secs: u64,
    /// Timeout de execução de `run_command`, em segundos.
    pub command_timeout_secs: u64,
    /// Teto global de chamadas de ferramenta da fase inteira.
    pub max_total_tool_calls: usize,
    /// Teto global de tempo da fase inteira, em segundos.
    pub scan_timeout_secs: u64,
}

impl Default for CodeAgentLimits {
    fn default() -> Self {
        Self {
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
            max_search_results: DEFAULT_MAX_SEARCH_RESULTS,
            max_list_entries: DEFAULT_MAX_LIST_ENTRIES,
            max_tool_output_bytes: DEFAULT_MAX_TOOL_OUTPUT_BYTES,
            max_iterations: 5,
            analysis_timeout_secs: 45,
            command_timeout_secs: 10,
            max_total_tool_calls: DEFAULT_MAX_TOTAL_TOOL_CALLS,
            scan_timeout_secs: DEFAULT_SCAN_TIMEOUT_SECS,
        }
    }
}
