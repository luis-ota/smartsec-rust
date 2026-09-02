use crate::domain::severity::Severity;
use crate::domain::vulnerability::Vulnerability;
use serde::Deserialize;
use std::collections::HashSet;

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct NucleiFinding {
    pub vulnerability: Vulnerability,
    pub template_id: String,
    pub matcher: Option<String>,
    pub host: Option<String>,
    pub url: Option<String>,
    pub endpoint: String,
    pub tags: Vec<String>,
    pub evidence: Option<String>,
    pub reported_severity: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NucleiParseError {
    pub line: usize,
    pub message: String,
}

#[derive(Default)]
pub struct NucleiParseReport {
    pub findings: Vec<NucleiFinding>,
    pub errors: Vec<NucleiParseError>,
}

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
    #[serde(rename = "extracted-results", default)]
    extracted_results: Vec<String>,
    response: Option<String>,
}

#[derive(Deserialize, Debug)]
struct NucleiInfo {
    name: Option<String>,
    description: Option<String>,
    severity: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
}

pub fn parse_nuclei_findings(jsonl_output: &str) -> NucleiParseReport {
    let mut report = NucleiParseReport::default();
    let mut seen = HashSet::new();

    for (index, line) in jsonl_output.lines().enumerate() {
        let line_number = index + 1;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let result = match serde_json::from_str::<NucleiResult>(trimmed) {
            Ok(result) => result,
            Err(error) => {
                report.errors.push(NucleiParseError {
                    line: line_number,
                    message: format!("JSONL inválido do Nuclei: {error}"),
                });
                continue;
            }
        };

        if result.template_id.trim().is_empty() {
            report.errors.push(NucleiParseError {
                line: line_number,
                message: "Resultado do Nuclei sem ID de template".to_owned(),
            });
            continue;
        }

        let endpoint = result
            .matched_at
            .as_deref()
            .or(result.url.as_deref())
            .or(result.host.as_deref())
            .unwrap_or("endpoint desconhecido")
            .to_owned();
        let dedup_key = (
            result.template_id.clone(),
            result.matcher_name.clone(),
            endpoint.clone(),
        );
        if !seen.insert(dedup_key) {
            continue;
        }

        let name = result
            .info
            .name
            .as_deref()
            .filter(|name| !name.trim().is_empty())
            .unwrap_or(&result.template_id);
        let title = match result.matcher_name.as_deref() {
            Some(matcher) if !matcher.trim().is_empty() => format!("{name} - {matcher}"),
            _ => name.to_owned(),
        };
        let description = result
            .info
            .description
            .as_deref()
            .filter(|description| !description.trim().is_empty())
            .map(|description| truncate_chars(description, 300))
            .unwrap_or_else(|| "O template não forneceu uma descrição.".to_owned());
        let severity = parse_severity(result.info.severity.as_deref());
        let reported_severity = result.info.severity.clone();
        let severity_text = reported_severity.as_deref().unwrap_or("desconhecida");
        let recommendation = format!(
            "Revise o achado do template '{}' no endpoint '{}' e aplique a correção indicada pelo fornecedor.",
            result.template_id, endpoint
        );
        let didactic = format!(
            "O Nuclei identificou: {name}\n\nSeveridade informada: {severity_text}\nEndpoint: {endpoint}\nDescrição: {description}\n\nValide a evidência e repita a varredura após a correção."
        );
        let evidence = if result.extracted_results.is_empty() {
            result.response.filter(|response| !response.is_empty())
        } else {
            Some(result.extracted_results.join("\n"))
        };

        report.findings.push(NucleiFinding {
            vulnerability: Vulnerability {
                details: None,
                title: Box::leak(title.into_boxed_str()),
                severity,
                description: Box::leak(description.into_boxed_str()),
                tool: "Nuclei",
                recommendation: Box::leak(recommendation.into_boxed_str()),
                didactic: Box::leak(didactic.into_boxed_str()),
            },
            template_id: result.template_id,
            matcher: result.matcher_name,
            host: result.host,
            url: result.url,
            endpoint,
            tags: result.info.tags,
            evidence,
            reported_severity,
        });
    }

    report
}

fn parse_severity(severity: Option<&str>) -> Severity {
    match severity.map(str::to_ascii_lowercase).as_deref() {
        Some("critical") => Severity::Critical,
        Some("high") => Severity::High,
        Some("medium") => Severity::Medium,
        Some("low") => Severity::Low,
        Some("info") | Some("unknown") | None | Some(_) => Severity::Info,
    }
}

fn truncate_chars(value: &str, maximum: usize) -> String {
    value.chars().take(maximum).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_real_jsonl_and_preserves_nuclei_fields() {
        let report = parse_nuclei_findings(include_str!("../../tests/fixtures/nuclei/real.jsonl"));

        assert!(report.errors.is_empty());
        assert_eq!(report.findings.len(), 2);
        let finding = &report.findings[0];
        assert_eq!(finding.template_id, "missing-hsts");
        assert_eq!(
            finding.matcher.as_deref(),
            Some("strict-transport-security")
        );
        assert_eq!(finding.host.as_deref(), Some("https://exemplo.test"));
        assert_eq!(finding.url.as_deref(), Some("https://exemplo.test/login"));
        assert_eq!(finding.tags, ["headers", "misconfig"]);
        assert!(finding.evidence.as_deref().unwrap().contains("max-age"));
    }

    #[test]
    fn keeps_distinct_endpoints_and_deduplicates_exact_matches() {
        let report = parse_nuclei_findings(include_str!("../../tests/fixtures/nuclei/real.jsonl"));

        assert_eq!(report.findings.len(), 2);
        assert_ne!(report.findings[0].endpoint, report.findings[1].endpoint);
    }

    #[test]
    fn accepts_partial_fields_unicode_and_unknown_severity() {
        let report =
            parse_nuclei_findings(include_str!("../../tests/fixtures/nuclei/partial.jsonl"));

        assert!(report.errors.is_empty());
        assert_eq!(report.findings.len(), 2);
        assert_eq!(report.findings[0].vulnerability.severity, Severity::Info);
        assert_eq!(
            report.findings[0].reported_severity.as_deref(),
            Some("novo")
        );
        assert!(report.findings[0].vulnerability.description.ends_with('ç'));
        assert_eq!(
            report.findings[1].vulnerability.description,
            "O template não forneceu uma descrição."
        );
    }

    #[test]
    fn reports_invalid_lines_and_keeps_valid_partial_output() {
        let report =
            parse_nuclei_findings(include_str!("../../tests/fixtures/nuclei/invalid.jsonl"));

        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.errors.len(), 2);
        assert_eq!(report.errors[0].line, 1);
        assert!(report.errors[0].message.contains("JSONL inválido"));
    }
}
