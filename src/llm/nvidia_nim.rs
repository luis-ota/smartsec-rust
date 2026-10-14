use crate::llm::openai_provider::OpenAIProvider;

pub fn nvidia_nim_provider(api_key: &str, timeout_secs: u64, max_retries: u8) -> OpenAIProvider {
    OpenAIProvider {
        base_url: "https://integrate.api.nvidia.com/v1".to_string(),
        api_key: api_key.to_string(),
        timeout_secs,
        max_retries,
        send_auth: true,
        retry_base_delay: crate::llm::openai_provider::DEFAULT_RETRY_BASE_DELAY,
    }
}
