use crate::llm::openai_provider::OpenAIProvider;

#[allow(dead_code)]
pub fn ollama_provider(
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
    }
}

#[allow(dead_code)]
pub fn ollama_model() -> &'static str {
    "llama3.1:8b"
}
