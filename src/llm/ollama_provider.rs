use crate::llm::openai_provider::OpenAIProvider;

#[allow(dead_code)]
pub fn ollama_provider(base_url: &str) -> OpenAIProvider {
    OpenAIProvider {
        base_url: base_url.to_string(),
        api_key: "ollama".to_string(),
    }
}

#[allow(dead_code)]
pub fn ollama_model() -> &'static str {
    "llama3"
}
