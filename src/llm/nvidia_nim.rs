use crate::llm::openai_provider::OpenAIProvider;

#[allow(dead_code)]
pub fn nvidia_nim_provider(api_key: &str, timeout_secs: u64, max_retries: u8) -> OpenAIProvider {
    OpenAIProvider {
        base_url: "https://integrate.api.nvidia.com/v1".to_string(),
        api_key: api_key.to_string(),
        timeout_secs,
        max_retries,
        send_auth: true,
    }
}

#[allow(dead_code)]
pub fn nvidia_nim_model() -> &'static str {
    "meta/llama-3.1-405b-instruct"
}
