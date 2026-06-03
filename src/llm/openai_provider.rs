use crate::llm::LLMProvider;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
#[allow(dead_code)]
struct ChatRequest {
    model: String,
    messages: Vec<ChatMessage>,
    temperature: f32,
}

#[derive(Serialize, Deserialize)]
#[allow(dead_code)]
struct ChatMessage {
    role: String,
    content: String,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct ChatResponse {
    choices: Vec<ChatChoice>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct ChatChoice {
    message: ChatMessage,
}

#[allow(dead_code)]
pub struct OpenAIProvider {
    pub base_url: String,
    pub api_key: String,
}

#[async_trait]
impl LLMProvider for OpenAIProvider {
    async fn execute_prompt(&self, prompt: &str, model: &str) -> Result<String, anyhow::Error> {
        let client = reqwest::Client::new();
        let url = format!("{}/chat/completions", self.base_url.trim_end_matches('/'));

        let body = ChatRequest {
            model: model.to_string(),
            messages: vec![ChatMessage {
                role: "user".to_string(),
                content: prompt.to_string(),
            }],
            temperature: 0.7,
        };

        let resp = client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!("LLM API error {}: {}", status, text));
        }

        let chat_resp: ChatResponse = resp.json().await?;

        if let Some(choice) = chat_resp.choices.first() {
            Ok(choice.message.content.clone())
        } else {
            Err(anyhow::anyhow!("No response from LLM"))
        }
    }
}
