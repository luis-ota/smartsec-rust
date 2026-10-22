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
    /// `required` enquanto o agente exige exploração; omitido nos demais
    /// turnos para preservar o payload que os provedores já aceitam.
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_choice: Option<&'static str>,
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

#[derive(Serialize)]
struct EmbeddingsRequest<'a> {
    model: &'a str,
    input: &'a [String],
}

#[derive(Deserialize)]
struct EmbeddingsResponse {
    data: Vec<EmbeddingDatum>,
}

#[derive(Deserialize)]
struct EmbeddingDatum {
    embedding: Vec<f32>,
}

pub struct OpenAIProvider {
    pub base_url: String,
    pub api_key: String,
    pub timeout_secs: u64,
    pub max_retries: u8,
    pub send_auth: bool,
    /// Intervalo inicial do backoff exponencial entre retentativas.
    pub retry_base_delay: Duration,
}

/// Base do backoff exponencial.
pub const DEFAULT_RETRY_BASE_DELAY: Duration = Duration::from_millis(500);

/// Teto da espera entre retentativas, para que a espera não consuma o prazo da
/// análise inteira antes da segunda tentativa.
/// Groq free tier pede 15–20s; o teto fica abaixo dos 45s da análise.
const RETRY_MAX_DELAY: Duration = Duration::from_secs(20);

impl OpenAIProvider {
    /// Monta o corpo da requisição. Sem ferramentas declaradas, o campo `tools`
    /// é omitido, para o caminho de análise de logs seguir como antes.
    fn chat_body(
        model: &str,
        messages: Vec<Value>,
        tools: Option<Vec<Value>>,
        tool_choice: Option<&'static str>,
    ) -> ChatRequest {
        ChatRequest {
            model: model.to_string(),
            messages,
            tools,
            tool_choice,
            temperature: 0.7,
        }
    }

    /// Envia o corpo ao endpoint de chat, com retentativa limitada, e devolve
    /// o texto da primeira escolha.
    async fn post_chat(&self, body: &ChatRequest) -> Result<String, anyhow::Error> {
        let chat_response = self.post_with_retry(body).await?;
        chat_response
            .choices
            .first()
            .map(|choice| choice.message.content.clone().unwrap_or_default())
            .ok_or_else(|| anyhow::anyhow!("A LLM não retornou uma resposta"))
    }

    /// Executa a requisição, repetindo apenas o que faz sentido repetir. Nenhuma
    /// retentativa sai sem esperar: reenviar o mesmo payload no mesmo instante
    /// consome o orçamento de tokens por minuto que acabou de estourar.
    async fn post_with_retry(&self, body: &ChatRequest) -> Result<ChatResponse, anyhow::Error> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(self.timeout_secs))
            .build()?;
        let url = format!("{}/chat/completions", self.base_url.trim_end_matches('/'));
        let mut backoff = self.retry_base_delay;
        let mut last_rate_limit: Option<Option<Duration>> = None;

        for attempt in 0..=self.max_retries {
            let mut request = client
                .post(&url)
                .header("Content-Type", "application/json")
                .json(body);
            if self.send_auth {
                request = request.bearer_auth(&self.api_key);
            }

            let answer = match request.send().await {
                Ok(answer) => answer,
                Err(error) if attempt == self.max_retries => return Err(error.into()),
                Err(_) => {
                    tokio::time::sleep(jittered(backoff)).await;
                    backoff = next_backoff(backoff);
                    continue;
                }
            };

            if answer.status().is_success() {
                return Ok(answer.json().await?);
            }

            let status = answer.status();
            let retry_after = retry_after_of(&answer);
            let rate_limited = status == reqwest::StatusCode::TOO_MANY_REQUESTS;
            // Sem o corpo, "400 Bad Request" não diz o que corrigir.
            let detail = if rate_limited {
                None
            } else {
                Some(answer.text().await.unwrap_or_default())
            };
            if rate_limited {
                last_rate_limit = Some(retry_after);
            } else if !status.is_server_error() {
                return Err(anyhow::anyhow!(
                    "A API da LLM retornou o status {status}{}",
                    error_detail(detail.as_deref())
                ));
            }
            if attempt == self.max_retries {
                return Err(match last_rate_limit {
                    Some(asked) => {
                        anyhow::anyhow!(rate_limit_message(attempt + 1, asked))
                    }
                    None => anyhow::anyhow!(
                        "A API da LLM retornou o status {status} após {} tentativa(s){}",
                        attempt + 1,
                        error_detail(detail.as_deref())
                    ),
                });
            }
            if let Some(asked) = retry_after.filter(|delay| *delay > RETRY_MAX_DELAY) {
                return Err(anyhow::anyhow!(rate_limit_message(
                    attempt + 1,
                    Some(asked)
                )));
            }

            let delay = retry_after.unwrap_or_else(|| jittered(backoff));
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            backoff = next_backoff(backoff);
        }

        unreachable!("o laço de tentativas sempre retorna na última tentativa")
    }
}

fn next_backoff(current: Duration) -> Duration {
    (current * 2).min(RETRY_MAX_DELAY)
}

/// Espera entre 50% e 100% do backoff, para que dois clientes que receberam 429
/// no mesmo segundo não voltem juntos; um LCG do relógio dispensa dependência.
fn jittered(base: Duration) -> Duration {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(1, |elapsed| u64::from(elapsed.subsec_nanos()).max(1));
    let mut state = nanos | 1;
    state = state
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    let half = u64::try_from(base.as_nanos() / 2).unwrap_or(u64::MAX);
    Duration::from_nanos(half + state % half.saturating_add(1))
}

/// Resume o corpo de erro do provedor sem repetir payloads enormes.
fn error_detail(body: Option<&str>) -> String {
    let Some(body) = body else {
        return String::new();
    };
    let text = crate::utils::redaction::sanitize_diagnostic(body.trim());
    if text.is_empty() {
        return String::new();
    }
    let mut chars = text.chars();
    let truncated: String = chars.by_ref().take(300).collect();
    if chars.next().is_some() {
        format!(": {truncated}…")
    } else {
        format!(": {truncated}")
    }
}

/// Lê `Retry-After` em segundos, ignorando formatos que não são numéricos.
fn retry_after_of(answer: &reqwest::Response) -> Option<Duration> {
    answer
        .headers()
        .get(reqwest::header::RETRY_AFTER)?
        .to_str()
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()
        .map(Duration::from_secs)
}

/// Mensagem de limite de uso no formato que resolve o problema: o que esgotou,
/// o que o provedor pediu e o que fazer agora.
fn rate_limit_message(attempts: u8, retry_after: Option<Duration>) -> String {
    let requested = retry_after.map_or_else(
        || "o provedor não informou por quanto tempo esperar".to_string(),
        |delay| format!("o provedor pediu {}s de espera", delay.as_secs()),
    );
    format!(
        "o provedor recusou a requisição por limite de uso (status 429) em {attempts} \
         tentativa(s): {requested}; aguarde o período indicado, reduza o tamanho do \
         payload ou use o provedor local (llama.cpp)"
    )
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
            None,
        );
        self.post_chat(&body).await
    }

    /// O endpoint Chat Completions do padrão OpenAI é aceito por llama.cpp,
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
            request.force_tool_call.then_some("required"),
        );
        let chat_response = self.post_with_retry(&body).await?;
        let message = chat_response
            .choices
            .first()
            .ok_or_else(|| anyhow::anyhow!("A LLM não retornou uma resposta"))?
            .message
            .clone();
        Ok(ToolTurn {
            content: message.content.unwrap_or_default(),
            tool_calls: message
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
                .collect(),
        })
    }

    /// Embeddings do endpoint `/embeddings`; uma tentativa só — a falha vira
    /// recuperação lexical, com o motivo registrado pelo serviço.
    async fn embed(&self, inputs: &[String], model: &str) -> Result<Vec<Vec<f32>>, anyhow::Error> {
        if inputs.is_empty() {
            return Ok(Vec::new());
        }
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(self.timeout_secs))
            .build()?;
        let url = format!("{}/embeddings", self.base_url.trim_end_matches('/'));
        let mut request = client
            .post(&url)
            .header("Content-Type", "application/json")
            .json(&EmbeddingsRequest {
                model,
                input: inputs,
            });
        if self.send_auth {
            request = request.bearer_auth(&self.api_key);
        }
        let answer = request.send().await?;
        if !answer.status().is_success() {
            return Err(anyhow::anyhow!(
                "a API de embeddings retornou o status {}",
                answer.status()
            ));
        }
        let parsed: EmbeddingsResponse = answer.json().await?;
        let vectors: Vec<Vec<f32>> = parsed
            .data
            .into_iter()
            .map(|datum| datum.embedding)
            .collect();
        if vectors.len() != inputs.len() {
            return Err(anyhow::anyhow!(
                "a API de embeddings devolveu {} vetor(es) para {} entrada(s)",
                vectors.len(),
                inputs.len()
            ));
        }
        Ok(vectors)
    }
}

/// Converte os argumentos serializados pelo modelo em JSON estruturado.
///
/// JSON inválido vira objeto vazio em vez de erro: a validação de contrato
/// pertence ao registro de ferramentas, que recusa com mensagem acionável em vez
/// de derrubar o turno inteiro.
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
    use crate::code_agent::tools::ToolSpec;
    use crate::llm::tool_calling::{ToolMessage, ToolTurnRequest};
    use serde_json::json;
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
            retry_base_delay: DEFAULT_RETRY_BASE_DELAY,
        }
    }

    /// Servidor que responde `status` com `extra_headers` em toda requisição e
    /// devolve o instante de cada uma, para que o teste prove que houve espera
    /// entre as tentativas.
    async fn throttle_server(
        status: &'static str,
        extra_headers: &'static str,
        responses: usize,
    ) -> (String, tokio::task::JoinHandle<Vec<std::time::Instant>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let body = r#"{"error":"corpo-remoto-que-nao-pode-vazar"}"#;
            let mut arrivals = Vec::with_capacity(responses);
            for _ in 0..responses {
                let (mut stream, _) = listener.accept().await.unwrap();
                arrivals.push(std::time::Instant::now());
                let mut buffer = vec![0; 8192];
                let _ = stream.read(&mut buffer).await;
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\n{extra_headers}\
                     Connection: close\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).await.unwrap();
                stream.shutdown().await.unwrap();
            }
            arrivals
        });
        (format!("http://{address}/v1"), handle)
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
        assert!(
            !requests[0].contains("tool_choice"),
            "o caminho de análise não declara ferramentas nem escolha: {}",
            requests[0]
        );
    }

    fn tool_turn_request(force_tool_call: bool) -> ToolTurnRequest {
        ToolTurnRequest {
            model: "gpt-4o".to_string(),
            messages: vec![ToolMessage::User("localize a origem".to_string())],
            tools: vec![ToolSpec {
                name: "list_dir".to_string(),
                description: "Lista um diretório".to_string(),
                parameters: json!({"type": "object", "properties": {}}),
            }],
            force_tool_call,
        }
    }

    /// Sem `tool_choice: required`, o modelo responde a recusa sem explorar —
    /// foi assim que a fase devolveu zero chamadas contra a NIM.
    #[tokio::test]
    async fn a_forced_turn_demands_a_tool_call_and_the_wire_says_so() {
        let body = "{\"choices\":[{\"message\":{\"role\":\"assistant\",\"content\":\"\",\"tool_calls\":[{\"id\":\"c1\",\"type\":\"function\",\"function\":{\"name\":\"list_dir\",\"arguments\":\"{\\\"path\\\":\\\".\\\"}\"}}]}}]}";
        let (base_url, server) = mock_server(vec![("200 OK", body)]).await;

        let turn = provider(base_url)
            .execute_tool_turn(&tool_turn_request(true))
            .await
            .unwrap();
        let requests = server.await.unwrap();

        assert!(
            requests[0].contains("\"tool_choice\":\"required\""),
            "{}",
            requests[0]
        );
        assert_eq!(turn.tool_calls.len(), 1);
        assert_eq!(turn.tool_calls[0].name, "list_dir");
    }

    /// Depois da primeira ferramenta o turno volta a aceitar resposta final:
    /// forçar para sempre impediria o modelo de concluir.
    #[tokio::test]
    async fn an_unforced_turn_omits_tool_choice() {
        let body = "{\"choices\":[{\"message\":{\"role\":\"assistant\",\"content\":\"{\\\"localizacao\\\": null}\"}}]}";
        let (base_url, server) = mock_server(vec![("200 OK", body)]).await;

        let turn = provider(base_url)
            .execute_tool_turn(&tool_turn_request(false))
            .await
            .unwrap();
        let requests = server.await.unwrap();

        assert!(!requests[0].contains("tool_choice"), "{}", requests[0]);
        assert!(turn.tool_calls.is_empty());
    }

    #[tokio::test]
    async fn embeddings_are_parsed_and_the_request_carries_the_model() {
        let body = "{\"data\":[{\"embedding\":[0.5,0.25]},{\"embedding\":[0.1,0.9]}]}";
        let (base_url, server) = mock_server(vec![("200 OK", body)]).await;
        let inputs = vec!["primeiro".to_string(), "segundo".to_string()];

        let vectors = provider(base_url)
            .embed(&inputs, "text-embedding-3-small")
            .await
            .unwrap();
        let requests = server.await.unwrap();

        assert!(
            requests[0].contains("POST /v1/embeddings"),
            "{}",
            requests[0]
        );
        assert!(
            requests[0].contains("\"model\":\"text-embedding-3-small\""),
            "{}",
            requests[0]
        );
        assert_eq!(vectors, vec![vec![0.5, 0.25], vec![0.1, 0.9]]);
    }

    #[tokio::test]
    async fn an_embeddings_failure_or_a_count_mismatch_is_an_error() {
        let (base_url, server) = mock_server(vec![("500 Internal Server Error", "{}")]).await;
        let error = provider(base_url)
            .embed(&["x".to_string()], "m")
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("500"), "{error}");
        server.await.unwrap();

        let body = "{\"data\":[{\"embedding\":[1.0]}]}";
        let (base_url, server) = mock_server(vec![("200 OK", body)]).await;
        let error = provider(base_url)
            .embed(&["x".to_string(), "y".to_string()], "m")
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("1 vetor(es) para 2 entrada(s)"), "{error}");
        server.await.unwrap();

        assert!(provider("http://unused".to_string())
            .embed(&[], "m")
            .await
            .unwrap()
            .is_empty());
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

    /// Regressão do 429: a retentativa saía no mesmo instante, com o payload
    /// idêntico, e queimava o orçamento de tokens por minuto que acabara de estourar
    /// (Groq free: 7.000 tokens/min de entrada). O teste exige três coisas — o número
    /// de tentativas, uma espera real entre elas e um erro que diz o que fazer.
    #[tokio::test]
    async fn rate_limit_retries_after_waiting_and_explains_itself() {
        let (base_url, server) = throttle_server("429 Too Many Requests", "", 3).await;
        let mut client = provider(base_url);
        client.max_retries = 2;
        client.retry_base_delay = Duration::from_millis(100);

        let error = client
            .execute_prompt("logs", "gpt-4o")
            .await
            .unwrap_err()
            .to_string();
        let arrivals = server.await.unwrap();

        assert_eq!(
            arrivals.len(),
            3,
            "duas retentativas depois da primeira falha"
        );
        assert!(
            arrivals[1].duration_since(arrivals[0]) >= Duration::from_millis(50),
            "a segunda tentativa saiu sem esperar: {:?}",
            arrivals
        );
        assert!(
            arrivals[2].duration_since(arrivals[1]) >= Duration::from_millis(100),
            "o backoff não cresceu entre as tentativas: {:?}",
            arrivals
        );
        assert!(error.contains("429"), "{error}");
        assert!(error.contains("limite de uso"), "{error}");
        assert!(error.contains("3 tentativa(s)"), "{error}");
        assert!(error.contains("llama.cpp"), "{error}");
        assert!(
            !error.contains("corpo-remoto"),
            "o corpo remoto não entra no erro"
        );
    }

    /// O provedor diz por quanto tempo esperar e isso tem precedência sobre o
    /// backoff próprio: insistir antes da hora recusa de novo.
    #[tokio::test]
    async fn rate_limit_respects_the_retry_after_header() {
        let (base_url, server) =
            throttle_server("429 Too Many Requests", "Retry-After: 1\r\n", 2).await;
        let mut client = provider(base_url);
        client.max_retries = 1;
        client.retry_base_delay = Duration::from_millis(10);

        let error = client
            .execute_prompt("logs", "gpt-4o")
            .await
            .unwrap_err()
            .to_string();
        let arrivals = server.await.unwrap();

        assert_eq!(arrivals.len(), 2);
        assert!(arrivals[1].duration_since(arrivals[0]) >= Duration::from_secs(1));
        assert!(error.contains("1s de espera"), "{error}");
    }

    /// Um `Retry-After` maior do que o prazo da análise não pode virar espera: a
    /// resposta precisa dizer isso, não dormir até o deadline do agente de código.
    #[tokio::test]
    async fn a_retry_after_beyond_the_wait_ceiling_stops_immediately() {
        let (base_url, server) =
            throttle_server("429 Too Many Requests", "Retry-After: 3600\r\n", 1).await;
        let mut client = provider(base_url);
        client.max_retries = 3;
        client.retry_base_delay = Duration::from_millis(10);

        let error = client
            .execute_prompt("logs", "gpt-4o")
            .await
            .unwrap_err()
            .to_string();
        let arrivals = server.await.unwrap();

        assert_eq!(arrivals.len(), 1, "não pode repetir antes da hora");
        assert!(error.contains("3600s de espera"), "{error}");
    }

    /// O jitter precisa manter a espera dentro de [50%, 100%] do backoff: menor
    /// que isso deixa de ser espera, maior que isso alonga a análise sem motivo.
    #[test]
    fn jittered_delay_stays_inside_half_the_backoff() {
        for base in [
            Duration::from_millis(1),
            Duration::from_millis(80),
            Duration::from_secs(2),
        ] {
            let half = base / 2;
            for _ in 0..64 {
                let delay = jittered(base);
                assert!(delay >= half, "{delay:?} abaixo de {half:?}");
                assert!(delay <= base, "{delay:?} acima de {base:?}");
            }
        }
        assert!(jittered(Duration::ZERO).is_zero());
        assert!(next_backoff(Duration::from_millis(40)) == Duration::from_millis(80));
        assert_eq!(next_backoff(RETRY_MAX_DELAY), RETRY_MAX_DELAY);
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
