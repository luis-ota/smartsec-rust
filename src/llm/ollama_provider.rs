use crate::llm::openai_provider::OpenAIProvider;

#[allow(dead_code)]
pub fn ollama_provider(base_url: &str, timeout_secs: u64, max_retries: u8) -> OpenAIProvider {
    OpenAIProvider {
        base_url: base_url.to_string(),
        api_key: String::new(),
        timeout_secs,
        max_retries,
        send_auth: false,
    }
}

#[allow(dead_code)]
pub fn ollama_model() -> &'static str {
    "llama3.1:8b"
}
