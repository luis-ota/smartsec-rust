use crate::domain::severity::Severity;
use crate::domain::vulnerability::Vulnerability;
use serde::Deserialize;

#[derive(Deserialize, Debug)]
struct NucleiResult {
    #[serde(rename = "template-id")]
    #[allow(dead_code)]
    template_id: String,
    info: NucleiInfo,
    #[serde(rename = "matched-at")]
    #[allow(dead_code)]
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

pub fn parse_nuclei_findings(jsonl_output: &str) -> Vec<Vulnerability> {
    let mut vulns = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

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
        let title_static: &'static str = Box::leak(title.into_boxed_str());

        let desc = if result.info.description.len() > 300 {
            result.info.description[..300].to_string()
        } else {
            result.info.description.clone()
        };
        let desc_static: &'static str = Box::leak(desc.into_boxed_str());

        let rec = format!(
            "Review and implement the missing security measure: {}. Apply recommended fixes for {}.",
            result.info.name,
            result.matched_at
        );
        let rec_static: &'static str = Box::leak(rec.into_boxed_str());

        let didactic = format!(
            "Nuclei identified: {}\n\nSeverity: {}\nMatched at: {}\nDescription: {}\n\nThis finding was detected by the Nuclei scanner using template-based vulnerability detection. Nuclei runs community-curated templates that check for known CVEs, misconfigurations, and security weaknesses.\n\nRecommendation: Apply the recommended fix and verify with a rescan.",
            result.info.name,
            result.info.severity,
            result.matched_at,
            result.info.description
        );
        let didactic_static: &'static str = Box::leak(didactic.into_boxed_str());

        vulns.push(Vulnerability {
            details: None,
            title: title_static,
            severity,
            description: desc_static,
            tool: "Nuclei",
            recommendation: rec_static,
            didactic: didactic_static,
        });
    }

    vulns
}
