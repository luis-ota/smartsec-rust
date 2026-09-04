use crate::config::Configuration;
use crate::domain::vulnerability::Vulnerability;
use crate::orchestrator::decision::DecisionRecord;

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
        md.push_str("**Dados:** REAL\n\n");
        if !decisions.is_empty() {
            md.push_str("## Decisões Dinâmicas\n\n");
            for decision in decisions {
                md.push_str(&format!("### {}\n\n", decision.summary()));
                md.push_str(&format!("- Modelo: {}\n", decision.model));
                md.push_str(&format!("- Justificativa: {}\n", decision.justification));
                md.push_str(&format!("- Parâmetros: {:?}\n", decision.parameters));
                md.push_str(&format!("- Evidências: {:?}\n\n", decision.evidence));
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
        let info = vulns
            .iter()
            .filter(|v| v.severity == crate::domain::Severity::Info)
            .count();
        md.push_str(&format!(
            "- Critical: {}\n- High: {}\n- Medium: {}\n- Low: {}\n- Info: {}\n\n",
            crit, high, med, low, info
        ));
        md.push_str("## Pontos Críticos\n\n");
        for v in vulns {
            if v.severity == crate::domain::Severity::Critical
                || v.severity == crate::domain::Severity::High
            {
                md.push_str(&format!("### [{}] {}\n\n", v.severity.label(), v.title));
                md.push_str(&format!("{}\n\n", v.description));
                md.push_str(&format!("**Ferramenta:** {}\n\n", v.tool));
                append_provenance(&mut md, v);
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
        md.push_str("\n## Proveniência dos achados\n\n");
        for vulnerability in vulns {
            append_provenance(&mut md, vulnerability);
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

fn append_provenance(md: &mut String, vulnerability: &Vulnerability) {
    md.push_str(&format!(
        "**Origem:** {}\n\n**Alvo:** {}\n\n**Evidência:** {}\n\n**Timestamp:** {}\n\n",
        vulnerability.source,
        vulnerability.target,
        vulnerability.evidence,
        vulnerability.detected_at
    ));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::vulnerability::FindingSource;
    use crate::domain::Severity;

    #[test]
    fn report_counts_informational_findings() {
        let finding = Vulnerability {
            title: "Porta aberta".to_string(),
            severity: Severity::Info,
            description: "Descrição".to_string(),
            tool: "Nmap".to_string(),
            recommendation: "Revise".to_string(),
            didactic: "Explicação".to_string(),
            source: FindingSource::Real,
            target: "http://target.local".to_string(),
            evidence: "porta 3000".to_string(),
            detected_at: "2026-09-04T14:00:00Z".to_string(),
        };

        let report = ReportGenerator::compile_report(&Configuration::default(), &[finding], &[]);

        assert!(report.contains("- Total de vulnerabilidades: 1"));
        assert!(report.contains("- Info: 1"));
    }
}
