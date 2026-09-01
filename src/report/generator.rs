use crate::config::Configuration;
use crate::orchestrator::decision::DecisionRecord;
use crate::domain::vulnerability::Vulnerability;

pub struct ReportGenerator;

impl ReportGenerator {
    pub fn compile_report(
        config: &Configuration,
        vulns: &[Vulnerability],
        decisions: &[DecisionRecord],
    ) -> String {
        let mut md = String::new();
        md.push_str("# SmartSec - Relatório de Análise de Segurança\n\n");
        md.push_str(&format!("**URL Alvo:** {}\n\n", config.target_url));
        md.push_str(&format!("**Modo:** {}\n\n", config.execution_type));
        if !decisions.is_empty() {
            md.push_str("## Decisões Dinâmicas\n\n");
            for decision in decisions {
                md.push_str(&format!("### {}\n\n", decision.summary()));
                md.push_str(&format!("- Modelo: {}\n", decision.model));
                md.push_str(&format!("- Justificativa: {}\n", decision.justification));
                md.push_str(&format!("- Parâmetros: {}\n", decision.parameters.iter().map(|(k, v)| format!("{}={}", k, v)).collect::<Vec<_>>().join(", ")));
                if !decision.evidence.is_empty() {
                    md.push_str("- Evidências:\n");
                    for item in &decision.evidence {
                        md.push_str(&format!("  - {}\n", item));
                    }
                }
                md.push('\n');
            }
        }
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
                append_details(&mut md, v);
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
        let detailed: Vec<_> = vulns
            .iter()
            .filter(|vulnerability| vulnerability.details.is_some())
            .collect();
        if !detailed.is_empty() {
            md.push_str("\n## Evidências técnicas\n\n");
            for vulnerability in detailed {
                md.push_str(&format!("### {}\n\n", vulnerability.title));
                append_details(&mut md, vulnerability);
            }
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

fn append_details(md: &mut String, vulnerability: &Vulnerability) {
    let Some(details) = &vulnerability.details else {
        return;
    };
    md.push_str(&format!(
        "**Alvo:** {}\n\n**Porta/protocolo:** {}/{}\n\n",
        details.host, details.port, details.protocol
    ));
    if let Some(service) = &details.service {
        md.push_str(&format!("**Serviço:** {service}\n\n"));
    }
    if let Some(version) = &details.version {
        md.push_str(&format!("**Versão do serviço:** {version}\n\n"));
    }
    md.push_str(&format!(
        "**Versão da ferramenta:** {}\n\n**Evidência:** {}\n\n",
        details.tool_version, details.evidence
    ));
}
