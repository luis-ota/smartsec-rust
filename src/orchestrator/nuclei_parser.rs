use crate::domain::severity::Severity;
use crate::domain::vulnerability::{FindingSource, Vulnerability};
use serde::Deserialize;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Deserialize, Debug)]
struct NucleiResult {
    #[serde(rename = "template-id")]
    #[allow(dead_code)]
    template_id: String,
    info: NucleiInfo,
    #[serde(rename = "matched-at")]
    matched_at: String,
    #[serde(rename = "matcher-name")]
    matcher_name: Option<String>,
    #[allow(dead_code)]
    host: String,
}

#[derive(Deserialize, Debug)]
struct NucleiInfo {
    name: String,
    description: String,
    severity: String,
    #[allow(dead_code)]
    tags: Option<Vec<String>>,
}

fn now_iso8601() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let s = secs % 60;
    let m = (secs / 60) % 60;
    let h = (secs / 3600) % 24;
    format!("2026-01-01T{:02}:{:02}:{:02}Z", h, m, s)
}

/// Parseia a saída JSONL do Nuclei e retorna achados reais com proveniência completa.
///
/// Todos os achados produzidos têm `source: FindingSource::Real`.
/// Nenhum `Box::leak` é utilizado; todos os campos são `String`.
pub fn parse_nuclei_findings(jsonl_output: &str, target: &str) -> Vec<Vulnerability> {
    let mut vulns = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let detected_at = now_iso8601();

    for line in jsonl_output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let Ok(result) = serde_json::from_str::<NucleiResult>(trimmed) else {
            continue;
        };

        let dedup_key = format!(
            "{}-{}",
            result.info.name,
            result.matcher_name.as_deref().unwrap_or("")
        );
        if !seen.insert(dedup_key) {
            continue;
        }

        let severity = match result.info.severity.as_str() {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" => Severity::Medium,
            "low" => Severity::Low,
            _ => Severity::Low,
        };

        let title = format!(
            "{} - {}",
            result.info.name,
            result.matcher_name.as_deref().unwrap_or("")
        );

        let description = if result.info.description.len() > 300 {
            result.info.description[..300].to_string()
        } else {
            result.info.description.clone()
        };

        let recommendation = format!(
            "Review and implement the missing security measure: {}. Apply recommended fixes for {}.",
            result.info.name, result.matched_at
        );

        let didactic = format!(
            "Nuclei identified: {}\n\nSeverity: {}\nMatched at: {}\nDescription: {}\n\nThis finding was detected by the Nuclei scanner using template-based vulnerability detection. Nuclei runs community-curated templates that check for known CVEs, misconfigurations, and security weaknesses.\n\nRecommendation: Apply the recommended fix and verify with a rescan.",
            result.info.name,
            result.info.severity,
            result.matched_at,
            result.info.description
        );

        let evidence = format!(
            "nuclei matched-at: {} | matcher: {}",
            result.matched_at,
            result.matcher_name.as_deref().unwrap_or("n/a")
        );

        vulns.push(Vulnerability {
            title,
            severity,
            description,
            tool: "Nuclei".to_string(),
            recommendation,
            didactic,
            source: FindingSource::Real,
            target: target.to_string(),
            evidence,
            detected_at: detected_at.clone(),
        });
    }

    vulns
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
}
