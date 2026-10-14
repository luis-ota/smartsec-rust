use crate::llm::openai_provider::OpenAIProvider;

/// Provedor local `llama.cpp`.
///
/// O `llama-server` expõe a API compatível com OpenAI, então a implementação é a
/// mesma; o que muda é o endpoint e a credencial, que aqui é opcional.
pub fn llama_cpp_provider(
    base_url: &str,
    api_key: &str,
    timeout_secs: u64,
    max_retries: u8,
) -> OpenAIProvider {
    OpenAIProvider {
        base_url: base_url.to_string(),
        api_key: api_key.to_string(),
        timeout_secs,
        max_retries,
        send_auth: !api_key.is_empty(),
        retry_base_delay: crate::llm::openai_provider::DEFAULT_RETRY_BASE_DELAY,
    }
}
