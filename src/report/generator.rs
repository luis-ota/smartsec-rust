use crate::config::Configuration;
use crate::domain::vulnerability::Vulnerability;
use crate::orchestrator::decision::DecisionRecord;

pub struct ReportGenerator;

impl ReportGenerator {
    pub fn compile_report(
        config: &Configuration,
        vulns: &[Vulnerability],
        decisions: &[DecisionRecord],
        project_dir: Option<&std::path::Path>,
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
        // O diretório do projeto entra no cabeçalho mesmo quando nenhum achado
        // foi localizado: ele declara **qual árvore foi analisada**, e um
        // relatório que não diz isso deixa a auditoria sem forma de saber se a
        // fase de código rodou sobre o repositório certo.
        if let Some(project_dir) = project_dir {
            md.push_str(&format!(
                "**Projeto analisado:** {}\n\n",
                crate::utils::redaction::sanitize_text(&project_dir.display().to_string())
            ));
        }
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
                append_code_analysis(&mut md, v);
                append_provenance(&mut md, v);
                md.push_str(&format!("**Recomendação:** {}\n\n", v.recommendation));
            }
        }
        md.push_str("## Todas as Vulnerabilidades\n\n");
        for v in &vulns {
            md.push_str(&format!(
                "- [{}] {} - {} - código: {}\n",
                v.severity.label_pt_br(),
                v.title,
                v.tool,
                code_location_label(v)
            ));
        }
        append_code_analysis_section(&mut md, &vulns);
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

/// Rótulo da origem no código, ou o texto honesto de "não determinada".
fn code_location_label(vulnerability: &Vulnerability) -> String {
    vulnerability
        .code_location
        .as_ref()
        .map_or_else(
            || crate::code_agent::agent::UNDETERMINED_LABEL.to_string(),
            ToString::to_string,
        )
}

/// Escreve a localização e os passos de correção de um achado.
///
/// A severidade não aparece aqui de propósito: o agente de código aponta onde
/// corrigir e nunca reclassifica (TCC_SPEC, seção 7).
fn append_code_analysis(md: &mut String, vulnerability: &Vulnerability) {
    let Some(location) = vulnerability.code_location.as_ref() else {
        return;
    };
    md.push_str(&format!(
        "**Origem no código:** {}:{}\n\n",
        location.file, location.line
    ));
    if !vulnerability.code_remediation.is_empty() {
        md.push_str("**Correção sugerida no código:**\n\n");
        for step in &vulnerability.code_remediation {
            md.push_str(&format!("- {step}\n"));
        }
        md.push('\n');
    }
}

/// Seção dedicada à análise do código.
///
/// A seção lista **todos** os achados, inclusive os sem origem, com o motivo da
/// recusa quando houver. Omitir os não localizados faria o relatório parecer
/// mais preciso do que foi: o número de achados sem origem é informação de
/// auditoria, não ruído.
fn append_code_analysis_section(md: &mut String, vulns: &[Vulnerability]) {
    let located = vulns
        .iter()
        .filter(|v| v.code_location.is_some())
        .count();
    md.push_str("\n## Localização no código\n\n");
    md.push_str(&format!(
        "- Achados com origem localizada: {located} de {}\n\n",
        vulns.len()
    ));
    for vulnerability in vulns {
        md.push_str(&format!(
            "### [{}] {}\n\n",
            vulnerability.severity.label_pt_br(),
            vulnerability.title
        ));
        match vulnerability.code_location.as_ref() {
            Some(location) => {
                md.push_str(&format!(
                    "**Arquivo:** `{}` · **Linha:** {}\n\n",
                    location.file, location.line
                ));
                if !location.snippet.is_empty() {
                    md.push_str(&format!("```\n{}\n```\n\n", location.snippet));
                }
            }
            None => md.push_str(&format!(
                "**Arquivo:** {} · **Linha:** —\n\n",
                crate::code_agent::agent::UNDETERMINED_LABEL
            )),
        }
        if vulnerability.code_remediation.is_empty() {
            md.push_str("**Correção sugerida:** não determinada.\n\n");
        } else {
            md.push_str("**Correção sugerida:**\n\n");
            for step in &vulnerability.code_remediation {
                md.push_str(&format!("- {step}\n"));
            }
            md.push('\n');
        }
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
        ..Default::default()
        };

        let report = ReportGenerator::compile_report(&Configuration::default(), &[finding], &[], None);

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
        ..Default::default()
        };

        let report = ReportGenerator::compile_report(&config, &[finding], &[], None);

        assert!(!report.contains("secret"));
        assert!(!report.contains("?token="));
        assert!(!report.contains("request:"));
        assert!(!report.contains("response:"));
        assert!(report.contains("[REDACTED]"));
    }
}
