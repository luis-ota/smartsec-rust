use crate::domain::severity::Severity;
use crate::domain::vulnerability::{FindingSource, Vulnerability};
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
    name: Option<String>,
    description: Option<String>,
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

        let name = info.name.unwrap_or_else(|| template_id.clone());
        let description_text = info.description.unwrap_or_default();
        let matched_at = result.matched_at.as_deref().unwrap_or(&endpoint);

        let title = format!("{} - {}", name, matcher);

        let description = if description_text.chars().count() > 300 {
            description_text.chars().take(300).collect()
        } else {
            description_text.clone()
        };

        let recommendation = format!(
            "Review and implement the missing security measure: {}. Apply recommended fixes for {}.",
            name, matched_at
        );

        let didactic = format!(
            "Nuclei identified: {}\n\nSeverity: {}\nMatched at: {}\nDescription: {}\n\nThis finding was detected by the Nuclei scanner using template-based vulnerability detection. Nuclei runs community-curated templates that check for known CVEs, misconfigurations, and security weaknesses.\n\nRecommendation: Apply the recommended fix and verify with a rescan.",
            name,
            info.severity.as_deref().unwrap_or("info"),
            matched_at,
            description_text
        );

        let evidence = format!(
            "nuclei matched-at: {} | matcher: {}",
            matched_at,
            if matcher.is_empty() { "n/a" } else { &matcher }
        );
        let tags = if !result.tags.is_empty() {
            result.tags
        } else {
            info.tags.unwrap_or_default()
        };
        let raw_evidence = trimmed.to_string();

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
                "{evidence} | host: {} | url: {} | tags: {} | raw: {raw_evidence}",
                result.host.as_deref().unwrap_or("n/a"),
                result.url.as_deref().unwrap_or("n/a"),
                tags.join(",")
            ),
            detected_at: detected_at.clone(),
        });
    }

    (vulns, errors)
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
        assert!(findings[0].evidence.contains("Falha"));
        assert!(findings[0].evidence.contains("web"));
        assert!(findings[1].evidence.contains("/b"));
        assert!(findings[0].description.contains('🚨') || findings[0].title.contains('🚨'));
    }

    #[test]
    fn invalid_jsonl_lines_are_reported() {
        let (findings, errors) = parse_nuclei_findings_with_errors("not-json\n{}", "target");
        assert!(findings.is_empty());
        assert_eq!(errors.len(), 2);
    }
}
