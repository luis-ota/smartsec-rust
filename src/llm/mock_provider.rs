use crate::llm::LLMProvider;
use async_trait::async_trait;

#[allow(dead_code)]
pub struct MockProvider;

#[async_trait]
impl LLMProvider for MockProvider {
    async fn execute_prompt(&self, _prompt: &str, _model: &str) -> Result<String, anyhow::Error> {
        Ok("[MOCK] AI analysis simulated. In production, this would contain LLM-generated insights about the security scan results.".to_string())
    }
}
