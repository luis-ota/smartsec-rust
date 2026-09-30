use crate::config::Configuration;
use crate::domain::vulnerability::Vulnerability;
use crate::orchestrator::decision::DecisionRecord;
use crate::orchestrator::enrichment::EnrichmentSummary;
use crate::orchestrator::nvd::cache_dir;

pub struct ReportGenerator;

impl ReportGenerator {
    /// Relatório sem contexto de enriquecimento.
    ///
    /// Mantido para os testes e para consumidores que ainda não enrichecem os
    /// achados; delega para [`compile_report_with_enrichment`](Self::compile_report_with_enrichment).
    #[allow(dead_code)]
    pub fn compile_report(
        config: &Configuration,
        vulns: &[Vulnerability],
        decisions: &[DecisionRecord],
    ) -> String {
        Self::compile_report_with_enrichment(
            config,
            vulns,
            decisions,
            &EnrichmentSummary::default(),
        )
    }

    /// Monta o relatório incluindo a correlação e o enriquecimento CVE/NVD.
    ///
    /// A indisponibilidade da NVD **não** impede este relatório: ela aparece
    /// como seção com a causa, e o restante do documento sai normalmente.
    pub fn compile_report_with_enrichment(
        config: &Configuration,
        vulns: &[Vulnerability],
        decisions: &[DecisionRecord],
        enrichment: &EnrichmentSummary,
    ) -> String {
        let vulns = vulns
            .iter()
            .map(Vulnerability::sanitized)
            .collect::<Vec<_>>();
        let mut md = String::new();
        md.push_str("# SmartSec - Relatório de Análise de Segurança\n\n");
        md.push_str(&format!(
            "**URL Alvo:** {}\n\n",
            crate::utils::redaction::sanitize_url(&config.target_url)
        ));
        md.push_str(&format!("**Modo:** {}\n\n", config.execution_type));
        md.push_str("**Dados:** REAL\n\n");
        append_enrichment_section(&mut md, enrichment);
        if !decisions.is_empty() {
            md.push_str("## Decisões Dinâmicas\n\n");
            for decision in decisions {
                let decision = decision.sanitized();
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
            "- Críticas: {}\n- Altas: {}\n- Médias: {}\n- Baixas: {}\n- Informativas: {}\n\n",
            crit, high, med, low, info
        ));
        md.push_str("## Pontos Críticos\n\n");
        for v in &vulns {
            if v.severity == crate::domain::Severity::Critical
                || v.severity == crate::domain::Severity::High
            {
                md.push_str(&format!(
                    "### [{}] {}\n\n",
                    v.severity.label_pt_br(),
                    v.title
                ));
                md.push_str(&format!("{}\n\n", v.description));
                md.push_str(&format!("**Ferramenta:** {}\n\n", v.tool));
                append_provenance(&mut md, v);
                md.push_str(&format!("**Recomendação:** {}\n\n", v.recommendation));
            }
        }
        md.push_str("## Todas as Vulnerabilidades\n\n");
        for v in &vulns {
            md.push_str(&format!(
                "- [{}] {} - {}\n",
                v.severity.label_pt_br(),
                v.title,
                v.tool
            ));
        }
        md.push_str("\n## Proveniência dos achados\n\n");
        for vulnerability in &vulns {
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
        Err(anyhow::anyhow!(
            "a exportação para PDF ainda não foi implementada"
        ))
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
    // Toda origem do mesmo problema é listada: o merge agrega e não descarta.
    for origin in &vulnerability.origins {
        md.push_str(&format!(
            "- Origem correlacionada — ferramenta: {} · severidade: {} · evidência: {} · detectada em: {}\n",
            origin.tool,
            origin.severity.label_pt_br(),
            origin.evidence,
            origin.detected_at
        ));
    }
    if !vulnerability.origins.is_empty() {
        md.push('\n');
    }
    if let Some(enrichment) = vulnerability.enrichment.as_ref() {
        md.push_str(&format!(
            "**Contexto NVD:** {}, CVSS base {}, severidade NVD {}, versão CVSS {}, referência {}, consultado em {}{}\n\n",
            enrichment.cve_id,
            enrichment
                .cvss_base_score
                .map_or_else(|| "não pontuado".to_string(), |score| format!("{score:.1}")),
            enrichment
                .cvss_severity
                .map_or("NÃO INFORMADA", |severity| severity.label_pt_br()),
            enrichment.cvss_version.as_deref().unwrap_or("não informada"),
            enrichment.reference.as_deref().unwrap_or("não informada"),
            enrichment.queried_at,
            if enrichment.from_cache {
                " (cache local)"
            } else {
                ""
            }
        ));
        if let Some(vector) = enrichment.cvss_vector.as_deref() {
            md.push_str(&format!("**Vetor CVSS:** {vector}\n\n"));
        }
    }
    if let Some(conflict) = vulnerability.severity_conflict.as_ref() {
        md.push_str(&format!(
            "**Divergência de severidade:** {}\n\n",
            conflict.detail
        ));
    }
}

/// Seção de correlação e enriquecimento CVE/NVD.
///
/// Quando a NVD está indisponível, a causa é impressa: o relatório base sai
/// igual e o leitor sabe por que o contexto não foi obtido.
fn append_enrichment_section(md: &mut String, enrichment: &EnrichmentSummary) {
    if enrichment.correlation.input_count == 0 && !enrichment.is_degraded() {
        return;
    }
    md.push_str("## Correlação e enriquecimento CVE/NVD\n\n");
    md.push_str(&format!(
        "- {}\n- {}\n",
        enrichment.correlation.summary_pt_br(),
        enrichment.nvd.summary_pt_br()
    ));
    md.push_str(&format!(
        "- Cache local da NVD: `{}` com validade de {} dias.\n",
        cache_dir().display(),
        crate::orchestrator::nvd::cache_ttl_days()
    ));
    md.push_str(&format!(
        "- Limite de taxa respeitado: {}.\n",
        crate::orchestrator::nvd::rate_limit_pt_br()
    ));
    if enrichment.nvd.is_degraded() {
        md.push_str(
            "- **Nota:** a indisponibilidade da NVD não altera a severidade de nenhum achado e não impede a emissão deste relatório.\n",
        );
    }
    md.push('\n');
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
            origins: Vec::new(),
            enrichment: None,
            severity_conflict: None,
        };

        let report = ReportGenerator::compile_report(&Configuration::default(), &[finding], &[]);

        assert!(report.contains("- Total de vulnerabilidades: 1"));
        assert!(report.contains("- Informativas: 1"));
    }

    #[test]
    fn report_never_contains_credentials_or_raw_http_payloads() {
        let config = Configuration {
            target_url: "https://user:secret@target.local/path?token=secret".to_string(),
            ..Configuration::default()
        };
        let finding = Vulnerability {
            title: "Cabeçalhos".to_string(),
            severity: Severity::High,
            description: "request: Authorization: Bearer secret".to_string(),
            tool: "Nuclei".to_string(),
            recommendation: "Remova o segredo".to_string(),
            didactic: "response: Set-Cookie: token=secret".to_string(),
            source: FindingSource::Real,
            target: "https://target.local/path?token=secret".to_string(),
            evidence: "request: GET /private?token=secret".to_string(),
            detected_at: "2026-09-06T12:00:00Z".to_string(),
            origins: Vec::new(),
            enrichment: None,
            severity_conflict: None,
        };

        let report = ReportGenerator::compile_report(&config, &[finding], &[]);

        assert!(!report.contains("secret"));
        assert!(!report.contains("?token="));
        assert!(!report.contains("request:"));
        assert!(!report.contains("response:"));
        assert!(report.contains("[REDACTED]"));
    }
}
