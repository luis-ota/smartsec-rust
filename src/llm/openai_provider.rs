use crate::llm::tool_calling::{ToolCall, ToolTurn, ToolTurnRequest};
use crate::llm::LLMProvider;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::Duration;

#[derive(Serialize)]
struct ChatRequest {
    model: String,
    messages: Vec<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tools: Option<Vec<Value>>,
    temperature: f32,
}

#[derive(Deserialize)]
struct ChatResponse {
    choices: Vec<ChatChoice>,
}

#[derive(Deserialize)]
struct ChatChoice {
    message: ChatMessage,
}

#[derive(Clone, Deserialize)]
struct ChatMessage {
    #[serde(default)]
    #[allow(dead_code)]
    role: String,
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    tool_calls: Option<Vec<RawToolCall>>,
}

#[derive(Clone, Deserialize)]
struct RawToolCall {
    #[serde(default)]
    id: String,
    function: RawToolCallFunction,
}

#[derive(Clone, Deserialize)]
struct RawToolCallFunction {
    name: String,
    #[serde(default)]
    arguments: String,
}

pub struct OpenAIProvider {
    pub base_url: String,
    pub api_key: String,
    pub timeout_secs: u64,
    pub max_retries: u8,
    pub send_auth: bool,
}

impl OpenAIProvider {
    /// Monta o corpo da requisição. Sem ferramentas declaradas, o campo
    /// `tools` é omitido para que o caminho de análise de logs continue
    /// idêntico ao anterior (e aceito por provedores sem tool calling).
    fn chat_body(
        model: &str,
        messages: Vec<Value>,
        tools: Option<Vec<Value>>,
    ) -> ChatRequest {
        ChatRequest {
            model: model.to_string(),
            messages,
            tools,
            temperature: 0.7,
        }
    }

    /// Envia o corpo ao endpoint de chat, com retentativa limitada, e devolve
    /// o texto da primeira escolha.
    async fn post_chat(&self, body: &ChatRequest) -> Result<String, anyhow::Error> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(self.timeout_secs))
            .build()?;
        let url = format!("{}/chat/completions", self.base_url.trim_end_matches('/'));

        for attempt in 0..=self.max_retries {
            let mut request = client
                .post(&url)
                .header("Content-Type", "application/json")
                .json(body);
            if self.send_auth {
                request = request.bearer_auth(&self.api_key);
            }

            match request.send().await {
                Ok(answer) if answer.status().is_success() => {
                    let chat_response: ChatResponse = answer.json().await?;
                    return chat_response
                        .choices
                        .first()
                        .map(|choice| choice.message.content.clone().unwrap_or_default())
                        .ok_or_else(|| anyhow::anyhow!("A LLM não retornou uma resposta"));
                }
                Ok(answer) => {
                    let status = answer.status();
                    let retryable = status.is_server_error()
                        || status == reqwest::StatusCode::TOO_MANY_REQUESTS;
                    if !retryable || attempt == self.max_retries {
                        return Err(anyhow::anyhow!("A API da LLM retornou o status {status}"));
                    }
                }
                Err(error) if attempt == self.max_retries => return Err(error.into()),
                Err(_) => {}
            }
        }

        unreachable!("o laço de tentativas sempre retorna na última tentativa")
    }
}

#[async_trait]
impl LLMProvider for OpenAIProvider {
    async fn execute_prompt(&self, prompt: &str, model: &str) -> Result<String, anyhow::Error> {
        let body = Self::chat_body(
            model,
            vec![serde_json::json!({
                "role": "user",
                "content": prompt,
            })],
            None,
        );
        self.post_chat(&body).await
    }

    /// O endpoint Chat Completions do padrão OpenAI é aceito por Ollama,
    /// NVIDIA NIM e provedores `custom`, então a mesma implementação do
    /// caminho de análise também conduz o turno com ferramentas.
    fn supports_tool_calling(&self) -> bool {
        true
    }

    async fn execute_tool_turn(
        &self,
        request: &ToolTurnRequest,
    ) -> Result<ToolTurn, anyhow::Error> {
        let body = Self::chat_body(
            &request.model,
            request.to_wire(),
            Some(request.tools_to_wire()),
        );
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(self.timeout_secs))
            .build()?;
        let url = format!("{}/chat/completions", self.base_url.trim_end_matches('/'));
        let mut turn = ToolTurn::default();

        for attempt in 0..=self.max_retries {
            let mut http = client
                .post(&url)
                .header("Content-Type", "application/json")
                .json(&body);
            if self.send_auth {
                http = http.bearer_auth(&self.api_key);
            }
            match http.send().await {
                Ok(answer) if answer.status().is_success() => {
                    let chat_response: ChatResponse = answer.json().await?;
                    let message = chat_response
                        .choices
                        .first()
                        .ok_or_else(|| anyhow::anyhow!("A LLM não retornou uma resposta"))?
                        .message
                        .clone();
                    turn.content = message.content.unwrap_or_default();
                    turn.tool_calls = message
                        .tool_calls
                        .unwrap_or_default()
                        .into_iter()
                        .enumerate()
                        .map(|(index, call)| ToolCall {
                            id: if call.id.trim().is_empty() {
                                format!("call-{index}")
                            } else {
                                call.id
                            },
                            name: call.function.name,
                            arguments: parse_arguments(&call.function.arguments),
                        })
                        .collect();
                    return Ok(turn);
                }
                Ok(answer) => {
                    let status = answer.status();
                    let retryable = status.is_server_error()
                        || status == reqwest::StatusCode::TOO_MANY_REQUESTS;
                    if !retryable || attempt == self.max_retries {
                        return Err(anyhow::anyhow!(
                            "A API da LLM retornou o status {status}"
                        ));
                    }
                }
                Err(error) if attempt == self.max_retries => return Err(error.into()),
                Err(_) => {}
            }
        }

        unreachable!("o laço de tentativas sempre retorna na última tentativa")
    }
}

/// Converte os argumentos serializados pelo modelo em JSON estruturado.
///
/// JSON inválido vira objeto vazio em vez de erro: a validação de contrato
/// pertence ao registro de ferramentas, que responde com recusa acionável
/// ("exige o argumento de texto \"path\"") em vez de derrubar o turno inteiro.
fn parse_arguments(raw: &str) -> Value {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Value::Object(serde_json::Map::new());
    }
    serde_json::from_str(trimmed).unwrap_or_else(|_| Value::Object(serde_json::Map::new()))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Servidor HTTP local que responde com o par `(status, corpo)` de cada
    /// requisição recebida. Reutilizado pelos testes do serviço de análise.
    pub(crate) async fn mock_server(
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

    pub(crate) fn provider(base_url: String) -> OpenAIProvider {
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
        let body = "{\"choices\":[{\"message\":{\"role\":\"assistant\",\"content\":\"análise concluída\"}}]}";
        let (base_url, server) = mock_server(vec![("200 OK", body)]).await;

        let result = provider(base_url)
            .execute_prompt("inspect logs", "gpt-4o")
            .await
            .unwrap();
        let requests = server.await.unwrap();

        assert_eq!(result, "análise concluída");
        assert!(requests[0].contains("POST /v1/chat/completions"));
        assert!(requests[0].contains("authorization: Bearer test-token"));
        assert!(requests[0].contains("\"model\":\"gpt-4o\""));
    }

    #[tokio::test]
    async fn retries_transient_server_error_with_limit() {
        let success = "{\"choices\":[{\"message\":{\"role\":\"assistant\",\"content\":\"serviço recuperado\"}}]}";
        let (base_url, server) = mock_server(vec![
            ("503 Service Unavailable", "busy"),
            ("200 OK", success),
        ])
        .await;
        let mut client = provider(base_url);
        client.max_retries = 1;

        let result = client.execute_prompt("logs", "gpt-4o").await.unwrap();
        let requests = server.await.unwrap();

        assert_eq!(result, "serviço recuperado");
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
