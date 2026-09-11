use crate::domain::severity::Severity;
use crate::domain::vulnerability::{FindingSource, Vulnerability};
use crate::utils::redaction::sanitize_evidence_component;
use serde::Deserialize;
use std::collections::HashSet;

#[derive(Deserialize, Debug)]
struct NucleiResult {
    #[serde(rename = "template-id")]
    template_id: String,
    info: NucleiInfo,
    #[serde(rename = "matched-at")]
    matched_at: Option<String>,
    #[serde(rename = "matcher-name")]
    matcher_name: Option<String>,
    host: Option<String>,
    url: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
}

#[derive(Deserialize, Debug)]
struct NucleiInfo {
    severity: Option<String>,
    #[allow(dead_code)]
    tags: Option<Vec<String>>,
}

fn now_iso8601() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// Parseia a saída JSONL do Nuclei e retorna achados reais com proveniência completa.
///
/// Todos os achados produzidos têm `source: FindingSource::Real`.
/// Nenhum `Box::leak` é utilizado; todos os campos são `String`.
#[allow(dead_code)]
pub fn parse_nuclei_findings(jsonl_output: &str, target: &str) -> Vec<Vulnerability> {
    parse_nuclei_findings_with_errors(jsonl_output, target).0
}

/// Retorna os achados e os erros de cada linha JSONL inválida. Uma linha inválida
/// nunca é tratada como execução bem-sucedida silenciosamente.
pub fn parse_nuclei_findings_with_errors(
    jsonl_output: &str,
    target: &str,
) -> (Vec<Vulnerability>, Vec<String>) {
    let mut vulns = Vec::new();
    let mut errors = Vec::new();
    let mut seen = HashSet::new();
    let detected_at = now_iso8601();

    for line in jsonl_output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let result = match serde_json::from_str::<NucleiResult>(trimmed) {
            Ok(result) => result,
            Err(error) => {
                errors.push(format!("linha Nuclei inválida: {error}"));
                continue;
            }
        };

        let info = result.info;
        let template_id = result.template_id;
        let endpoint = result
            .matched_at
            .clone()
            .or_else(|| result.url.clone())
            .or_else(|| result.host.clone())
            .unwrap_or_else(|| target.to_string());
        let matcher = result.matcher_name.clone().unwrap_or_default();

        let dedup_key = format!("{}\u{1f}{}\u{1f}{}", template_id, matcher, endpoint);
        if !seen.insert(dedup_key) {
            continue;
        }

        let severity = match info
            .severity
            .as_deref()
            .unwrap_or_default()
            .to_ascii_lowercase()
            .as_str()
        {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" => Severity::Medium,
            "low" => Severity::Low,
            _ => Severity::Info,
        };

        let matched_at = result.matched_at.as_deref().unwrap_or(&endpoint);

        let title = localized_nuclei_title(&template_id, &matcher);
        let matcher_label = if matcher.is_empty() {
            "verificação principal"
        } else {
            &matcher
        };
        let description = format!(
            "O template {template_id} do Nuclei correspondeu à regra {matcher_label} no endpoint {matched_at}."
        );

        let recommendation = format!(
            "Revise a configuração associada ao template {template_id}, aplique a correção pertinente e valide novamente o endpoint {matched_at}."
        );

        let didactic = format!(
            "O Nuclei identificou uma correspondência do template {template_id}.\n\nSeveridade registrada pelo scanner: {}\nVerificador: {matcher_label}\nEndpoint: {matched_at}\n\nO achado foi produzido por um template versionado do Nuclei. Confirme a evidência no ambiente autorizado, aplique a correção pertinente e execute uma nova varredura.",
            severity.label_pt_br(),
        );

        let tags = if !result.tags.is_empty() {
            result.tags
        } else {
            info.tags.unwrap_or_default()
        };
        let safe_template = sanitize_evidence_component(&template_id);
        let safe_matcher =
            sanitize_evidence_component(if matcher.is_empty() { "n/a" } else { &matcher });
        let safe_endpoint = sanitize_evidence_component(matched_at);
        let safe_host = sanitize_evidence_component(result.host.as_deref().unwrap_or("n/a"));
        let safe_url = sanitize_evidence_component(result.url.as_deref().unwrap_or("n/a"));
        let safe_tags = tags
            .iter()
            .map(|tag| sanitize_evidence_component(tag))
            .collect::<Vec<_>>()
            .join(",");

        vulns.push(Vulnerability {
            title,
            severity,
            description,
            tool: "Nuclei".to_string(),
            recommendation,
            didactic,
            source: FindingSource::Real,
            target: target.to_string(),
            evidence: format!(
                "template: {safe_template} | matcher: {safe_matcher} | endpoint: {safe_endpoint} | host: {safe_host} | url: {safe_url} | tags: {safe_tags}"
            ),
            detected_at: detected_at.clone(),
        });
    }

    (vulns, errors)
}

pub(crate) fn localized_nuclei_title(template_id: &str, matcher: &str) -> String {
    if template_id == "http-missing-security-headers" {
        return format!(
            "Cabeçalho de segurança ausente — {}",
            if matcher.is_empty() {
                "não especificado"
            } else {
                matcher
            }
        );
    }
    if template_id.to_ascii_lowercase().starts_with("cve-") {
        return format!("Possível vulnerabilidade detectada — {template_id}");
    }
    format!("Achado identificado pelo Nuclei — {template_id}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::vulnerability::FindingSource;

    fn sample_nuclei_jsonl() -> &'static str {
        r#"{"template-id":"CVE-2021-44228","info":{"name":"Log4Shell RCE","description":"Apache Log4j2 JNDI injection vulnerability","severity":"critical","tags":["cve","rce"]},"matched-at":"http://target:8080/","matcher-name":"jndi-injection","host":"target"}"#
    }

    #[test]
    fn parsed_findings_are_real() {
        let vulns = parse_nuclei_findings(sample_nuclei_jsonl(), "http://target:8080");
        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0].source, FindingSource::Real);
    }

    #[test]
    fn parsed_findings_have_target() {
        let target = "http://target:8080";
        let vulns = parse_nuclei_findings(sample_nuclei_jsonl(), target);
        assert_eq!(vulns[0].target, target);
    }

    #[test]
    fn parsed_findings_have_evidence() {
        let vulns = parse_nuclei_findings(sample_nuclei_jsonl(), "http://target:8080");
        assert!(!vulns[0].evidence.is_empty());
    }

    #[test]
    fn empty_input_returns_no_findings() {
        let vulns = parse_nuclei_findings("", "http://target");
        assert!(vulns.is_empty());
    }

    #[test]
    fn dedup_prevents_duplicate_findings() {
        let line = sample_nuclei_jsonl();
        let double = format!("{}\n{}", line, line);
        let vulns = parse_nuclei_findings(&double, "http://target");
        assert_eq!(vulns.len(), 1, "Duplicatas devem ser removidas");
    }

    #[test]
    fn no_box_leak_in_parsed_findings() {
        // Verifica indiretamente: se o código compilar com Strings (não &'static str),
        // o teste de movimentação abaixo deve funcionar sem problemas de lifetime.
        let vulns = parse_nuclei_findings(sample_nuclei_jsonl(), "http://target");
        let moved: Vec<String> = vulns.into_iter().map(|v| v.title).collect();
        assert!(!moved.is_empty());
    }

    #[test]
    fn optional_fields_unicode_unknown_severity_and_endpoint_deduplication() {
        let input = concat!(
            r#"{"template-id":"t","info":{"name":"Falha 🚨","description":"áéíóú","severity":"new-level","tags":["web"]},"host":"exemplo.test","url":"https://exemplo.test/a","matched-at":"https://exemplo.test/a","matcher-name":"m"}"#,
            "\n",
            r#"{"template-id":"t","info":{"name":"Falha 🚨","severity":"high"},"matched-at":"https://exemplo.test/b","matcher-name":"m"}"#,
            "\n",
            r#"{"template-id":"t","info":{"name":"Falha 🚨","severity":"high"},"matched-at":"https://exemplo.test/a","matcher-name":"m"}"#,
            "\n",
            r#"{"template-id":"minimal","info":{"name":"Opcional","severity":"info"},"host":"exemplo.test"}"#,
        );
        let (findings, errors) = parse_nuclei_findings_with_errors(input, "https://exemplo.test");
        assert!(errors.is_empty());
        assert_eq!(findings.len(), 3);
        assert_eq!(findings[0].severity, Severity::Info);
        assert!(findings[0].evidence.contains("template: t"));
        assert!(findings[0].evidence.contains("matcher: m"));
        assert!(findings[0].evidence.contains("web"));
        assert!(findings[1].evidence.contains("/b"));
        assert_eq!(findings[0].title, "Achado identificado pelo Nuclei — t");
        assert!(findings[0]
            .description
            .starts_with("O template t do Nuclei"));
    }

    #[test]
    fn evidence_excludes_raw_http_payloads_and_sensitive_query_values() {
        let input = r#"{"template-id":"headers","info":{"name":"Cabeçalhos ausentes","severity":"info","tags":["headers"]},"host":"target.local","url":"https://target.local/path?token=segredo","matched-at":"https://target.local/path?token=segredo","matcher-name":"csp","request":"Authorization: Bearer segredo","response":"Set-Cookie: session=segredo"}"#;

        let findings = parse_nuclei_findings(input, "https://target.local");

        assert_eq!(findings.len(), 1);
        assert!(findings[0].evidence.contains("template: headers"));
        assert!(findings[0].evidence.contains("matcher: csp"));
        assert!(!findings[0].evidence.contains("request"));
        assert!(!findings[0].evidence.contains("response"));
        assert!(!findings[0].evidence.contains("segredo"));
        assert!(!findings[0].evidence.contains("?token="));
        assert!(findings[0].recommendation.starts_with("Revise"));
        assert!(findings[0].didactic.starts_with("O Nuclei identificou"));
    }

    #[test]
    fn localizes_known_template_and_keeps_scanner_severity() {
        let input = r#"{"template-id":"http-missing-security-headers","info":{"name":"HTTP Missing Security Headers","description":"Missing headers","severity":"info"},"matched-at":"https://target.local","matcher-name":"content-security-policy"}"#;

        let findings = parse_nuclei_findings(input, "https://target.local");

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info);
        assert_eq!(
            findings[0].title,
            "Cabeçalho de segurança ausente — content-security-policy"
        );
        assert!(!findings[0].description.contains("Missing"));
        assert!(findings[0]
            .didactic
            .contains("Severidade registrada pelo scanner: INFORMATIVA"));
    }

    #[test]
    fn invalid_jsonl_lines_are_reported() {
        let (findings, errors) = parse_nuclei_findings_with_errors("not-json\n{}", "target");
        assert!(findings.is_empty());
        assert_eq!(errors.len(), 2);
    }
}
