use crate::llm::LLMProvider;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::Duration;

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
    pub timeout_secs: u64,
    pub max_retries: u8,
    pub send_auth: bool,
}

#[async_trait]
impl LLMProvider for OpenAIProvider {
    async fn execute_prompt(&self, prompt: &str, model: &str) -> Result<String, anyhow::Error> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(self.timeout_secs))
            .build()?;
        let url = format!("{}/chat/completions", self.base_url.trim_end_matches('/'));

        let body = ChatRequest {
            model: model.to_string(),
            messages: vec![ChatMessage {
                role: "user".to_string(),
                content: prompt.to_string(),
            }],
            temperature: 0.7,
        };

        for attempt in 0..=self.max_retries {
            let mut request = client
                .post(&url)
                .header("Content-Type", "application/json")
                .json(&body);
            if self.send_auth {
                request = request.bearer_auth(&self.api_key);
            }

            match request.send().await {
                Ok(response) if response.status().is_success() => {
                    let chat_response: ChatResponse = response.json().await?;
                    return chat_response
                        .choices
                        .first()
                        .map(|choice| choice.message.content.clone())
                        .ok_or_else(|| anyhow::anyhow!("No response from LLM"));
                }
                Ok(response) => {
                    let status = response.status();
                    let retryable = status.is_server_error()
                        || status == reqwest::StatusCode::TOO_MANY_REQUESTS;
                    if !retryable || attempt == self.max_retries {
                        return Err(anyhow::anyhow!("LLM API returned status {status}"));
                    }
                }
                Err(error) if attempt == self.max_retries => return Err(error.into()),
                Err(_) => {}
            }
        }

        unreachable!("retry loop always returns on its last attempt")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    async fn mock_server(
        responses: Vec<(&'static str, &'static str)>,
    ) -> (String, tokio::task::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let mut requests = Vec::new();
            for (status, body) in responses {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut buffer = vec![0; 8192];
                let size = stream.read(&mut buffer).await.unwrap();
                requests.push(String::from_utf8_lossy(&buffer[..size]).into_owned());
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).await.unwrap();
                stream.shutdown().await.unwrap();
            }
            requests
        });
        (format!("http://{address}/v1"), handle)
    }

    fn provider(base_url: String) -> OpenAIProvider {
        OpenAIProvider {
            base_url,
            api_key: "test-token".to_string(),
            timeout_secs: 2,
            max_retries: 0,
            send_auth: true,
        }
    }

    #[tokio::test]
    async fn sends_openai_request_to_http_mock() {
        let body = "{\"choices\":[{\"message\":{\"role\":\"assistant\",\"content\":\"ok\"}}]}";
        let (base_url, server) = mock_server(vec![("200 OK", body)]).await;

        let result = provider(base_url)
            .execute_prompt("inspect logs", "gpt-4o")
            .await
            .unwrap();
        let requests = server.await.unwrap();

        assert_eq!(result, "ok");
        assert!(requests[0].contains("POST /v1/chat/completions"));
        assert!(requests[0].contains("authorization: Bearer test-token"));
        assert!(requests[0].contains("\"model\":\"gpt-4o\""));
    }

    #[tokio::test]
    async fn retries_transient_server_error_with_limit() {
        let success =
            "{\"choices\":[{\"message\":{\"role\":\"assistant\",\"content\":\"recovered\"}}]}";
        let (base_url, server) = mock_server(vec![
            ("503 Service Unavailable", "busy"),
            ("200 OK", success),
        ])
        .await;
        let mut client = provider(base_url);
        client.max_retries = 1;

        let result = client.execute_prompt("logs", "gpt-4o").await.unwrap();
        let requests = server.await.unwrap();

        assert_eq!(result, "recovered");
        assert_eq!(requests.len(), 2);
    }

    #[tokio::test]
    async fn aborts_request_at_configured_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(2)).await;
        });
        let mut client = provider(format!("http://{address}/v1"));
        client.timeout_secs = 1;

        let error = client.execute_prompt("logs", "gpt-4o").await.unwrap_err();

        assert!(error
            .downcast_ref::<reqwest::Error>()
            .is_some_and(reqwest::Error::is_timeout));
        server.abort();
    }

    #[tokio::test]
    async fn excludes_remote_error_body_from_error() {
        let (base_url, server) = mock_server(vec![(
            "401 Unauthorized",
            "request echoed secret-token and sensitive logs",
        )])
        .await;

        let error = provider(base_url)
            .execute_prompt("sensitive logs", "gpt-4o")
            .await
            .unwrap_err()
            .to_string();
        server.await.unwrap();

        assert!(error.contains("401 Unauthorized"));
        assert!(!error.contains("secret-token"));
        assert!(!error.contains("sensitive logs"));
    }
}
