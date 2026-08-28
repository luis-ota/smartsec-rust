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
        Self {
            provider,
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

        let result = match self.provider.execute_prompt(&prompt, &self.model).await {
            Ok(r) => Self::parse_llm_response(&r),
            Err(_) => Self::mock_analysis(vulns),
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

    fn mock_analysis(vulns: &[Vulnerability]) -> String {
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
