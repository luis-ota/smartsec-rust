use crate::config::llm_config::LlmConfig;
use crate::config::llm_config::LlmProviderKind;
use crate::domain::vulnerability::Vulnerability;
use crate::llm::nvidia_nim::nvidia_nim_provider;
use crate::llm::ollama_provider::ollama_provider;
use crate::llm::openai_provider::OpenAIProvider;
use crate::llm::LLMProvider;
use std::time::{Duration, Instant};

/// Provedor que efetivamente respondeu a uma requisição, para auditoria.
#[derive(Debug)]
pub(crate) struct ProviderOutcome {
    pub response: String,
    pub provider: String,
    pub model: String,
    pub fallback_used: bool,
    /// Erro do provedor principal quando a alternativa local respondeu.
    ///
    /// Sem este campo o log estruturado registraria `llm_fallback_used: true`
    /// sem explicar **por que** o provedor configurado foi abandonado, e a
    /// queda passaria a parecer uma escolha em vez de uma falha.
    pub primary_error: Option<String>,
}

pub struct AIAgent {
    #[allow(dead_code)]
    pub provider: Box<dyn LLMProvider>,
    fallback_provider: Option<Box<dyn LLMProvider>>,
    fallback_model: String,
    /// Rótulo em português do provedor principal configurado.
    provider_label: String,
    /// Rótulo em português do provedor alternativo local.
    fallback_provider_label: String,
    remote_allowed: bool,
    configuration_error: Option<String>,
    #[allow(dead_code)]
    pub model: String,
    pub last_analysis: String,
    #[allow(dead_code)]
    pub execution_history: Vec<String>,
}

impl AIAgent {
    pub fn from_config(cfg: &LlmConfig) -> Self {
        let provider: Box<dyn LLMProvider> = match cfg.provider {
            LlmProviderKind::Ollama => Box::new(ollama_provider(
                &cfg.base_url,
                &cfg.api_key,
                cfg.timeout_secs,
                cfg.max_retries,
            )),
            LlmProviderKind::NvidiaNim => Box::new(nvidia_nim_provider(
                &cfg.api_key,
                cfg.timeout_secs,
                cfg.max_retries,
            )),
            LlmProviderKind::OpenAI => Box::new(OpenAIProvider {
                base_url: cfg.base_url.clone(),
                api_key: cfg.api_key.clone(),
                timeout_secs: cfg.timeout_secs,
                max_retries: cfg.max_retries,
                send_auth: true,
            }),
            LlmProviderKind::Custom => Box::new(OpenAIProvider {
                base_url: cfg.base_url.clone(),
                api_key: cfg.api_key.clone(),
                timeout_secs: cfg.timeout_secs,
                max_retries: cfg.max_retries,
                send_auth: !cfg.api_key.is_empty(),
            }),
        };
        let fallback_provider = cfg.fallback_enabled.then(|| {
            Box::new(ollama_provider(
                &cfg.fallback_base_url,
                "",
                cfg.timeout_secs,
                cfg.max_retries,
            )) as Box<dyn LLMProvider>
        });
        Self {
            provider,
            fallback_provider,
            fallback_model: cfg.fallback_model.clone(),
            provider_label: cfg.provider.label().to_string(),
            fallback_provider_label: LlmProviderKind::Ollama.label().to_string(),
            remote_allowed: !cfg.is_remote() || cfg.remote_consent,
            configuration_error: cfg.validate().err(),
            model: cfg.model.clone(),
            last_analysis: String::new(),
            execution_history: Vec::new(),
        }
    }

    /// Rótulo em português do provedor configurado, para auditoria.
    pub fn configured_provider_label(&self) -> String {
        self.provider_label.clone()
    }

    /// Provedor configurado como `dyn LLMProvider`, para a fase do agente de
    /// código (issue #76).
    ///
    /// O provedor é devolvido por referência viva, e não clonado, porque o agente
    /// de código conversa em vários turnos com o mesmo provedor: clonar exigiria
    /// `Clone` no trait e duplicaria estado de sessão em cada achado.
    pub fn provider_handle(&self) -> &dyn LLMProvider {
        self.provider.as_ref()
    }

    /// `true` quando o provedor configurado pode receber dados do alvo.
    ///
    /// O agente de código usa este sinal **antes** de qualquer chamada, e não
    /// apenas para bloquear a requisição: sem ele, um provedor remoto sem
    /// consentimento receberia trechos do código do alvo auditado, o que RNF10
    /// proíbe de forma mais estrita do que proíbe o envio de logs, porque o
    /// código é o ativo protegido do cliente.
    pub fn allows_target_data(&self) -> bool {
        self.remote_allowed && self.configuration_error.is_none()
    }

    /// Constrói um agente com provedores injetados. Restrito a testes: existe
    /// para exercitar a cadeia principal/alternativa sem rede e sem mock no
    /// fluxo real.
    #[cfg(test)]
    pub(crate) fn for_test(
        provider: Box<dyn LLMProvider>,
        fallback_provider: Option<Box<dyn LLMProvider>>,
        fallback_model: &str,
        model: &str,
        provider_label: &str,
    ) -> Self {
        Self {
            provider,
            fallback_provider,
            fallback_model: fallback_model.to_string(),
            provider_label: provider_label.to_string(),
            fallback_provider_label: LlmProviderKind::Ollama.label().to_string(),
            remote_allowed: true,
            configuration_error: None,
            model: model.to_string(),
            last_analysis: String::new(),
            execution_history: Vec::new(),
        }
    }

    #[allow(dead_code)]
    pub fn filter_false_positives(vulns: &[Vulnerability]) -> Vec<&Vulnerability> {
        vulns.iter().collect()
    }

    #[allow(dead_code)]
    pub async fn generate_didactic(&self, vuln: &Vulnerability) -> String {
        let prompt = format!(
            "Explique a vulnerabilidade a seguir em português brasileiro para uma pessoa desenvolvedora iniciante. Preserve a severidade informada e apresente: 1) o que é, 2) um exemplo de fluxo de ataque e 3) estratégias de defesa.\n\nTítulo: {}\nSeveridade: {}\nFerramenta: {}\nDescrição: {}",
            vuln.title,
            vuln.severity.label_pt_br(),
            vuln.tool,
            vuln.description
        );
        if self.configuration_error.is_some() || !self.remote_allowed {
            return vuln.didactic.to_string();
        }
        match self.provider.execute_prompt(&prompt, &self.model).await {
            Ok(response) => {
                let response = Self::parse_llm_response(&response);
                Self::validated_portuguese(&response).unwrap_or_else(|| vuln.didactic.to_string())
            }
            Err(_) => vuln.didactic.to_string(),
        }
    }

    pub(crate) fn parse_llm_response(raw: &str) -> String {
        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(raw) {
            if let Some(content) = parsed.get("analysis").and_then(|v| v.as_str()) {
                return content.to_string();
            }
            if let Some(content) = parsed.get("content").and_then(|v| v.as_str()) {
                return content.to_string();
            }
            if let Some(content) = parsed
                .get("choices")
                .and_then(|v| v.get(0))
                .and_then(|v| v.get("message"))
                .and_then(|v| v.get("content"))
                .and_then(|v| v.as_str())
            {
                return content.to_string();
            }
        }
        raw.to_string()
    }

    pub(crate) fn validated_guidance(raw: &str) -> Option<String> {
        let lower = raw.to_lowercase();
        let severity_terms = [
            "critical",
            "high",
            "medium",
            "low",
            "severity",
            "crític",
            "critico",
            "crítico",
            "gravidade",
            "severidade",
        ];
        if severity_terms.iter().any(|term| lower.contains(term)) {
            return None;
        }
        Self::validated_portuguese(raw)
    }

    fn validated_portuguese(raw: &str) -> Option<String> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return None;
        }
        let lower = format!(" {} ", trimmed.to_lowercase());
        let english_markers = [
            " vulnerability ",
            " vulnerabilities ",
            " recommendation ",
            " recommendations ",
            " based on ",
            " security header",
            " the following ",
        ];
        if english_markers.iter().any(|term| lower.contains(term)) {
            return None;
        }
        let portuguese_markers = [
            " para ",
            " uma ",
            " os ",
            " as ",
            " de ",
            " do ",
            " da ",
            " valide",
            " revise",
            " aplique",
            " correção",
            " segurança",
        ];
        if !portuguese_markers.iter().any(|term| lower.contains(term)) {
            return None;
        }
        Some(crate::utils::redaction::sanitize_text(trimmed))
    }

    /// Executa o prompt na cadeia principal -> alternativa local dentro de um
    /// orçamento de tempo único.
    ///
    /// O prazo (RNF04) é contado uma vez e **dividido**: o provedor principal
    /// recebe `primary_share` e a alternativa local fica com o restante. Sem
    /// essa divisão, um provedor principal que trava consumiria os 45 segundos
    /// inteiros — o mesmo valor de `timeout_secs` validado pela configuração —
    /// e a alternativa local jamais seria llamada, tornando o fallback (RNF06)
    /// decorativo no caminho que mais importa, que é a queda do provedor.
    ///
    /// O retorno identifica qual provedor respondeu e carrega o erro do
    /// principal, porque o resultado persistido precisa distinguir "a
    /// alternativa respondeu" de "a alternativa nunca foi tentada".
    pub(crate) async fn execute_with_fallback(
        &mut self,
        prompt: &str,
        deadline: Duration,
    ) -> Result<ProviderOutcome, anyhow::Error> {
        if let Some(error) = &self.configuration_error {
            return Err(anyhow::anyhow!("configuração inválida da LLM: {error}"));
        }
        let started = Instant::now();
        let primary_result = if self.remote_allowed {
            execute_within(
                primary_budget(deadline),
                self.provider.execute_prompt(prompt, &self.model),
            )
            .await
        } else {
            Err(anyhow::anyhow!(
                "solicitação remota bloqueada por falta de consentimento explícito"
            ))
        };

        match primary_result {
            Ok(response) => Ok(ProviderOutcome {
                response,
                provider: self.provider_label.clone(),
                model: self.model.clone(),
                fallback_used: false,
                primary_error: None,
            }),
            Err(primary_error) => {
                self.execution_history
                    .push(format!("A LLM principal falhou: {primary_error}"));
                let reason = primary_error.to_string();
                let Some(fallback) = &self.fallback_provider else {
                    return Err(primary_error);
                };
                let remaining = prompt_limit(deadline, started);
                if remaining.is_zero() {
                    return Err(primary_error);
                }
                self.execution_history
                    .push("Usando o Ollama local configurado como alternativa".to_string());
                match execute_within(remaining, fallback.execute_prompt(prompt, &self.fallback_model)).await {
                    Ok(response) => Ok(ProviderOutcome {
                        response,
                        provider: self.fallback_provider_label.clone(),
                        model: self.fallback_model.clone(),
                        fallback_used: true,
                        primary_error: Some(reason),
                    }),
                    Err(fallback_error) => Err(anyhow::anyhow!(
                        "a LLM principal falhou ({primary_error}); a alternativa local falhou ({fallback_error})"
                    )),
                }
            }
        }
    }

    pub(crate) fn local_analysis(vulns: &[Vulnerability]) -> String {
        let count = |severity| vulns.iter().filter(|v| v.severity == severity).count();
        let crit = count(crate::domain::Severity::Critical);
        let high = count(crate::domain::Severity::High);
        let medium = count(crate::domain::Severity::Medium);
        let low = count(crate::domain::Severity::Low);
        let info = count(crate::domain::Severity::Info);
        let priority = if crit > 0 {
            "Corrija imediatamente os achados críticos."
        } else if high > 0 {
            "Priorize a correção dos achados de gravidade alta."
        } else if medium > 0 {
            "Planeje a correção dos achados de gravidade média."
        } else if low > 0 {
            "Revise os achados de gravidade baixa e aplique hardening quando pertinente."
        } else if info > 0 {
            "Os achados são informativos; valide a exposição e aplique hardening quando pertinente."
        } else {
            "Nenhum achado foi identificado nesta execução."
        };
        format!(
            "Análise concluída: {} achados ({} críticos, {} altos, {} médios, {} baixos e {} informativos).\n{}",
            vulns.len(), crit, high, medium, low, info, priority
        )
    }
}

/// Tempo restante do orçamento da análise para uma nova tentativa.
fn prompt_limit(deadline: Duration, started: Instant) -> Duration {
    deadline.saturating_sub(started.elapsed())
}

/// Fatia do orçamento reservada ao provedor principal.
///
/// A alternativa local fica com o que sobrar, o que é o mínimo necessário para
/// ela conseguir responder. Com o padrão de 45 s, o principal recebe 33 s e a
/// alternativa 12 s; a soma continua sendo o teto de RNF04.
/// Fração do orçamento reservada ao provedor principal: 3/4.
///
/// O restante fica com a alternativa local. Ver `primary_budget`.
pub(crate) const PRIMARY_BUDGET_NUMERATOR: u32 = 3;
pub(crate) const PRIMARY_BUDGET_DENOMINATOR: u32 = 4;

pub(crate) fn primary_budget(deadline: Duration) -> Duration {
    deadline
        .checked_div(PRIMARY_BUDGET_DENOMINATOR)
        .map(|part| part * PRIMARY_BUDGET_NUMERATOR)
        .unwrap_or(deadline)
}

/// Aplica o orçamento de tempo da análise a uma chamada de provedor.
async fn execute_within<F, T>(limit: Duration, future: F) -> Result<T, anyhow::Error>
where
    F: std::future::Future<Output = Result<T, anyhow::Error>>,
{
    match tokio::time::timeout(limit, future).await {
        Ok(result) => result,
        Err(_) => Err(anyhow::anyhow!(
            "a chamada excedeu o tempo limite de {} s da análise",
            limit.as_secs()
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::vulnerability::FindingSource;
    use crate::domain::Severity;
    use async_trait::async_trait;

    struct FailingProvider;

    #[async_trait]
    impl LLMProvider for FailingProvider {
        async fn execute_prompt(
            &self,
            _prompt: &str,
            _model: &str,
        ) -> Result<String, anyhow::Error> {
            Err(anyhow::anyhow!("provedor indisponível"))
        }
    }

    struct SuccessfulProvider;

    struct RespondingProvider(&'static str);

    fn finding(severity: Severity) -> Vulnerability {
        Vulnerability {
            title: "Achado de teste".to_string(),
            severity,
            description: "Descrição".to_string(),
            tool: "Nuclei".to_string(),
            recommendation: "Revise".to_string(),
            didactic: "Explicação".to_string(),
            source: FindingSource::Real,
            target: "http://target.local".to_string(),
            evidence: "evidência".to_string(),
            detected_at: "2026-09-04T14:00:00Z".to_string(),
            origins: Vec::new(),
            enrichment: None,
            severity_conflict: None,
            ..Default::default()
        }
    }

    #[async_trait]
    impl LLMProvider for SuccessfulProvider {
        async fn execute_prompt(
            &self,
            _prompt: &str,
            model: &str,
        ) -> Result<String, anyhow::Error> {
            Ok(format!("resposta alternativa do modelo {model}"))
        }
    }

    #[async_trait]
    impl LLMProvider for RespondingProvider {
        async fn execute_prompt(
            &self,
            _prompt: &str,
            _model: &str,
        ) -> Result<String, anyhow::Error> {
            Ok(self.0.to_string())
        }
    }

    #[test]
    fn local_analysis_counts_info_without_recommending_critical_fix() {
        let analysis = AIAgent::local_analysis(&[finding(Severity::Info)]);

        assert!(analysis.contains("1 informativos"));
        assert!(analysis.contains("Os achados são informativos"));
        assert!(!analysis.contains("Corrija imediatamente"));
    }

    #[tokio::test]
    async fn uses_and_records_configured_local_fallback() {
        let mut agent = AIAgent::for_test(
            Box::new(FailingProvider),
            Some(Box::new(SuccessfulProvider)),
            "llama3.1:8b",
            "gpt-4o",
            "OpenAI",
        );

        let outcome = agent
            .execute_with_fallback("logs", Duration::from_secs(45))
            .await
            .unwrap();

        assert_eq!(
            outcome.response,
            "resposta alternativa do modelo llama3.1:8b"
        );
        assert!(outcome.fallback_used);
        assert_eq!(outcome.provider, "Ollama");
        assert_eq!(outcome.model, "llama3.1:8b");
        // A causa da queda do principal viaja com o resultado, para que o log
        // estruturado não registre um fallback sem explicação.
        assert!(outcome
            .primary_error
            .as_deref()
            .is_some_and(|reason| reason.contains("provedor indisponível")));
        assert!(agent
            .execution_history
            .iter()
            .any(|entry| entry.contains("LLM principal falhou")));
        assert!(agent
            .execution_history
            .iter()
            .any(|entry| entry.contains("Ollama local configurado")));
    }

    #[tokio::test]
    async fn reports_the_primary_provider_when_it_answers() {
        let mut agent = AIAgent::for_test(
            Box::new(RespondingProvider("resposta do provedor principal")),
            None,
            "llama3.1:8b",
            "gpt-4o",
            "OpenAI",
        );

        let outcome = agent
            .execute_with_fallback("logs", Duration::from_secs(45))
            .await
            .unwrap();

        assert_eq!(outcome.response, "resposta do provedor principal");
        assert!(!outcome.fallback_used);
        assert_eq!(outcome.provider, "OpenAI");
        assert_eq!(outcome.model, "gpt-4o");
        assert!(outcome.primary_error.is_none());
    }

    #[tokio::test]
    async fn invalid_configuration_short_circuits_without_calling_any_provider() {
        let config = LlmConfig {
            provider: LlmProviderKind::OpenAI,
            base_url: "https://api.openai.com/v1".to_string(),
            model: String::new(),
            api_key: "test-key".to_string(),
            remote_consent: true,
            ..LlmConfig::default()
        };
        let mut agent = AIAgent::from_config(&config);

        let error = agent
            .execute_with_fallback("logs", Duration::from_secs(45))
            .await
            .unwrap_err()
            .to_string();

        assert!(error.contains("configuração inválida"), "{error}");
    }
}
