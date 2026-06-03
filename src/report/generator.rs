use crate::config::Configuration;
use crate::domain::vulnerability::Vulnerability;

pub struct ReportGenerator;

impl ReportGenerator {
    pub fn compile_report(config: &Configuration, vulns: &[Vulnerability]) -> String {
        let mut md = String::new();
        md.push_str("# SmartSec - Relatório de Análise de Segurança\n\n");
        md.push_str(&format!("**URL Alvo:** {}\n\n", config.target_url));
        md.push_str(&format!("**Modo:** {}\n\n", config.execution_type));
        md.push_str("## Resumo\n\n");
        md.push_str(&format!("- Total de vulnerabilidades: {}\n", vulns.len()));
        let crit = vulns
            .iter()
            .filter(|v| v.severity == crate::domain::Severity::Critical)
            .count();
        let high = vulns
            .iter()
            .filter(|v| v.severity == crate::domain::Severity::High)
            .count();
        let med = vulns
            .iter()
            .filter(|v| v.severity == crate::domain::Severity::Medium)
            .count();
        let low = vulns
            .iter()
            .filter(|v| v.severity == crate::domain::Severity::Low)
            .count();
        md.push_str(&format!(
            "- Critical: {}\n- High: {}\n- Medium: {}\n- Low: {}\n\n",
            crit, high, med, low
        ));
        md.push_str("## Pontos Críticos\n\n");
        for v in vulns {
            if v.severity == crate::domain::Severity::Critical
                || v.severity == crate::domain::Severity::High
            {
                md.push_str(&format!("### [{}] {}\n\n", v.severity.label(), v.title));
                md.push_str(&format!("{}\n\n", v.description));
                md.push_str(&format!("**Ferramenta:** {}\n\n", v.tool));
                md.push_str(&format!("**Recomendação:** {}\n\n", v.recommendation));
            }
        }
        md.push_str("## Todas as Vulnerabilidades\n\n");
        for v in vulns {
            md.push_str(&format!(
                "- [{}] {} - {}\n",
                v.severity.label(),
                v.title,
                v.tool
            ));
        }
        md
    }

    #[allow(dead_code)]
    pub fn export_to_markdown(content: &str, path: &str) -> Result<(), std::io::Error> {
        std::fs::write(path, content)
    }

    #[allow(dead_code)]
    pub fn export_to_pdf(_content: &str, _path: &str) -> Result<(), anyhow::Error> {
        Err(anyhow::anyhow!("PDF export not yet implemented"))
    }
}
