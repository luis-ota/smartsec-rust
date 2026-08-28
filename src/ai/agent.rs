use crate::config::llm_config::LlmConfig;
use crate::config::llm_config::LlmProviderKind;
use crate::domain::vulnerability::Vulnerability;
use crate::llm::mock_provider::MockProvider;
use crate::llm::nvidia_nim::nvidia_nim_provider;
use crate::llm::ollama_provider::ollama_provider;
use crate::llm::openai_provider::OpenAIProvider;
use crate::llm::LLMProvider;

pub struct AIAgent {
    #[allow(dead_code)]
    pub provider: Box<dyn LLMProvider>,
    fallback_provider: Option<Box<dyn LLMProvider>>,
    fallback_model: String,
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
            LlmProviderKind::Mock => Box::new(MockProvider),
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
            remote_allowed: !cfg.is_remote() || cfg.remote_consent,
            configuration_error: cfg.validate().err(),
            model: cfg.model.clone(),
            last_analysis: String::new(),
            execution_history: Vec::new(),
        }
    }

    pub async fn analyze_logs(&mut self, vulns: &[Vulnerability]) -> String {
        let prompt = format!(
            "You are a senior security analyst. Analyze these vulnerabilities and provide a concise summary with priorities:\n{}",
            vulns
                .iter()
                .map(|v| format!("- [{}] {} ({})", v.severity.label(), v.title, v.tool))
                .collect::<Vec<_>>()
                .join("\n")
        );

        let result = match self.execute_with_fallback(&prompt).await {
            Ok(response) => Self::parse_llm_response(&response),
            Err(error) => {
                self.execution_history
                    .push(format!("Análise por LLM indisponível: {error}"));
                Self::local_analysis(vulns)
            }
        };
        self.last_analysis = result.clone();
        result
    }

    #[allow(dead_code)]
    pub fn filter_false_positives(vulns: &[Vulnerability]) -> Vec<&Vulnerability> {
        vulns.iter().collect()
    }

    #[allow(dead_code)]
    pub async fn generate_didactic(&self, vuln: &Vulnerability) -> String {
        let prompt = format!(
            "Explain the following security vulnerability in an educational way for a junior developer:\n\nTitle: {}\nSeverity: {}\nTool: {}\nDescription: {}\n\nProvide: 1) what it is, 2) attack flow example, 3) defense strategies.",
            vuln.title, vuln.severity.label(), vuln.tool, vuln.description
        );
        if self.configuration_error.is_some() || !self.remote_allowed {
            return vuln.didactic.to_string();
        }
        match self.provider.execute_prompt(&prompt, &self.model).await {
            Ok(r) => Self::parse_llm_response(&r),
            Err(_) => vuln.didactic.to_string(),
        }
    }

    fn parse_llm_response(raw: &str) -> String {
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

    async fn execute_with_fallback(&mut self, prompt: &str) -> Result<String, anyhow::Error> {
        if let Some(error) = &self.configuration_error {
            return Err(anyhow::anyhow!("configuração inválida da LLM: {error}"));
        }
        let primary_result = if self.remote_allowed {
            self.provider.execute_prompt(prompt, &self.model).await
        } else {
            Err(anyhow::anyhow!(
                "solicitação remota bloqueada por falta de consentimento explícito"
            ))
        };

        match primary_result {
            Ok(response) => Ok(response),
            Err(primary_error) => {
                self.execution_history
                    .push(format!("A LLM principal falhou: {primary_error}"));
                let Some(fallback) = &self.fallback_provider else {
                    return Err(primary_error);
                };
                self.execution_history
                    .push("Usando o Ollama local configurado como alternativa".to_string());
                fallback
                    .execute_prompt(prompt, &self.fallback_model)
                    .await
                    .map_err(|fallback_error| {
                        anyhow::anyhow!(
                            "a LLM principal falhou ({primary_error}); a alternativa local falhou ({fallback_error})"
                        )
                    })
            }
        }
    }

    fn local_analysis(vulns: &[Vulnerability]) -> String {
        let crit = vulns
            .iter()
            .filter(|v| v.severity == crate::domain::Severity::Critical)
            .count();
        let high = vulns
            .iter()
            .filter(|v| v.severity == crate::domain::Severity::High)
            .count();
        format!(
            "Analysis complete: {} critical and {} high severity vulnerabilities detected.\nImmediate remediation recommended for critical findings.\nReview authentication, input validation, and dependency surface first.",
            crit, high
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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

    #[async_trait]
    impl LLMProvider for SuccessfulProvider {
        async fn execute_prompt(
            &self,
            _prompt: &str,
            model: &str,
        ) -> Result<String, anyhow::Error> {
            Ok(format!("fallback response from {model}"))
        }
    }

    #[tokio::test]
    async fn blocks_remote_analysis_without_explicit_consent() {
        let config = LlmConfig {
            provider: LlmProviderKind::OpenAI,
            base_url: "https://127.0.0.1:9/v1".to_string(),
            model: "gpt-4o".to_string(),
            api_key: "test-key".to_string(),
            remote_consent: false,
            ..LlmConfig::default()
        };
        let mut agent = AIAgent::from_config(&config);

        let result = agent.analyze_logs(&[]).await;

        assert!(result.contains("Analysis complete"));
        assert!(agent
            .execution_history
            .iter()
            .any(|entry| entry.contains("consentimento")));
    }

    #[tokio::test]
    async fn uses_and_records_configured_local_fallback() {
        let mut agent = AIAgent {
            provider: Box::new(FailingProvider),
            fallback_provider: Some(Box::new(SuccessfulProvider)),
            fallback_model: "llama3.1:8b".to_string(),
            remote_allowed: true,
            configuration_error: None,
            model: "gpt-4o".to_string(),
            last_analysis: String::new(),
            execution_history: Vec::new(),
        };

        let response = agent.execute_with_fallback("logs").await.unwrap();

        assert_eq!(response, "fallback response from llama3.1:8b");
        assert!(agent
            .execution_history
            .iter()
            .any(|entry| entry.contains("LLM principal falhou")));
        assert!(agent
            .execution_history
            .iter()
            .any(|entry| entry.contains("Ollama local configurado")));
    }
}
