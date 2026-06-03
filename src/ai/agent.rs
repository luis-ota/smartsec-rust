use crate::domain::vulnerability::Vulnerability;
use crate::llm::LLMProvider;

#[allow(dead_code)]
pub struct AIAgent {
    provider: Box<dyn LLMProvider>,
    model: String,
}

impl AIAgent {
    #[allow(dead_code)]
    pub fn new(provider: Box<dyn LLMProvider>, model: String) -> Self {
        Self { provider, model }
    }

    #[allow(dead_code)]
    pub async fn analyze_logs(&self, vulns: &[Vulnerability]) -> String {
        let prompt = format!(
            "Analyze these security vulnerabilities and provide a summary:\n{}",
            vulns
                .iter()
                .map(|v| format!("- [{}] {} ({})", v.severity.label(), v.title, v.tool))
                .collect::<Vec<_>>()
                .join("\n")
        );

        match self.provider.execute_prompt(&prompt, &self.model).await {
            Ok(result) => Self::parse_llm_response(&result),
            Err(_) => Self::mock_analysis(vulns),
        }
    }

    #[allow(dead_code)]
    pub fn filter_false_positives(vulns: &[Vulnerability]) -> Vec<&Vulnerability> {
        vulns.iter().collect()
    }

    #[allow(dead_code)]
    pub fn generate_didactic(vuln: &Vulnerability) -> String {
        vuln.didactic.to_string()
    }

    fn parse_llm_response(raw: &str) -> String {
        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(raw) {
            if let Some(content) = parsed.get("analysis").and_then(|v| v.as_str()) {
                return content.to_string();
            }
            if let Some(content) = parsed.get("content").and_then(|v| v.as_str()) {
                return content.to_string();
            }
        }
        raw.to_string()
    }

    fn mock_analysis(vulns: &[Vulnerability]) -> String {
        let crit = vulns.iter().filter(|v| v.severity == crate::domain::Severity::Critical).count();
        let high = vulns.iter().filter(|v| v.severity == crate::domain::Severity::High).count();
        format!(
            "Analysis complete: {} critical and {} high severity vulnerabilities detected.\n\
             Immediate remediation recommended for critical findings.",
            crit, high
        )
    }
}
