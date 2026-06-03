use async_trait::async_trait;

#[async_trait]
#[allow(dead_code)]
pub trait LLMProvider: Send + Sync {
    async fn execute_prompt(&self, prompt: &str, model: &str) -> Result<String, anyhow::Error>;
}
