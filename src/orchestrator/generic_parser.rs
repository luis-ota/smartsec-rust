use crate::domain::severity::Severity;
use crate::domain::vulnerability::{FindingSource, Vulnerability};
use std::collections::HashSet;

const TITLE_LIMIT: usize = 120;
const EVIDENCE_LIMIT: usize = 300;

fn now_iso8601() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn truncate(value: &str, limit: usize) -> String {
    if value.chars().count() <= limit {
        return value.to_string();
    }
    let mut truncated: String = value.chars().take(limit).collect();
    truncated.push('…');
    truncated
}

fn is_diagnostic(line: &str) -> bool {
    line.starts_with("[ERRO]")
}

/// Parser `generic-text`: extrai achados informativos simples do texto.
///
/// Cada linha não vazia e não diagnóstica vira um achado `Info` real com
/// proveniência completa. Linhas repetidas são deduplicadas.
pub fn parse_generic_findings_with_errors(
    output: &str,
    target: &str,
    tool: &str,
) -> (Vec<Vulnerability>, Vec<String>) {
    let mut findings = Vec::new();
    let mut seen = HashSet::new();
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || is_diagnostic(trimmed) {
            continue;
        }
        if !seen.insert(trimmed.to_string()) {
            continue;
        }
        let title = truncate(trimmed, TITLE_LIMIT);
        findings.push(Vulnerability {
            title,
            severity: Severity::Info,
            description: format!(
                "A ferramenta {tool} reportou a linha a seguir durante a varredura: {}",
                truncate(trimmed, EVIDENCE_LIMIT)
            ),
            tool: tool.to_string(),
            recommendation: "Valide manualmente o achado informativo e confirme o impacto antes de agir."
                .to_string(),
            didactic: format!(
                "Este conteúdo foi extraído da saída textual da ferramenta {tool}. Achados informativos descrevem comportamento observado e precisam de validação humana antes de virarem uma correção."
            ),
            source: FindingSource::Real,
            target: target.to_string(),
            evidence: format!("{tool} linha={}", truncate(trimmed, EVIDENCE_LIMIT)),
            detected_at: now_iso8601(),
        });
    }
    (findings, Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_informative_findings_and_deduplicates_lines() {
        let output = "Servidor expõe /admin sem autenticação\n\nServidor expõe /admin sem autenticação\n[ERRO] falha\n";

        let (findings, errors) =
            parse_generic_findings_with_errors(output, "http://alvo.local", "Nikto");

        assert!(errors.is_empty());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info);
        assert_eq!(findings[0].tool, "Nikto");
        assert_eq!(findings[0].source, FindingSource::Real);
        assert!(findings[0].title.contains("/admin"));
    }

    #[test]
    fn ignores_empty_and_diagnostic_output() {
        let (findings, _) =
            parse_generic_findings_with_errors("[ERRO] Podman falhou", "alvo", "Nikto");

        assert!(findings.is_empty());
    }
}
