use crate::orchestrator::nmap_parser::{parse_nmap_ports, NmapPortFinding};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum DecisionSource {
    Ai,
    Fallback,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Ord, PartialOrd)]
pub enum NucleiTemplateProfile {
    HttpMisconfiguration,
    HttpExposedPanels,
    SshExposure,
    DatabaseExposure,
    Generic,
}

impl NucleiTemplateProfile {
    pub fn template_paths(&self) -> Vec<&'static str> {
        match self {
            Self::HttpMisconfiguration => vec!["http/misconfiguration/"],
            Self::HttpExposedPanels => vec!["http/exposed-panels/"],
            Self::SshExposure => vec!["network/"],
            Self::DatabaseExposure => vec!["network/"],
            Self::Generic => vec!["http/misconfiguration/"],
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::HttpMisconfiguration => "http-misconfiguration",
            Self::HttpExposedPanels => "http-exposed-panels",
            Self::SshExposure => "ssh-exposure",
            Self::DatabaseExposure => "database-exposure",
            Self::Generic => "generic",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct NucleiPlan {
    pub should_run: bool,
    pub profiles: Vec<NucleiTemplateProfile>,
    pub concurrency: u16,
    pub timeout_seconds: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DecisionRecord {
    pub source: DecisionSource,
    pub model: String,
    pub justification: String,
    pub parameters: BTreeMap<String, String>,
    pub evidence: Vec<String>,
    pub plan: NucleiPlan,
}

#[derive(Deserialize)]
struct AiPlanResponse {
    should_run: Option<bool>,
    profiles: Option<Vec<String>>,
    concurrency: Option<u16>,
    timeout_seconds: Option<u16>,
}

pub fn decide_nuclei_plan(
    target: &str,
    nmap_xml: Option<&str>,
    ai_response: Option<&str>,
    model: &str,
) -> DecisionRecord {
    let signal = analyze_nmap_signal(target, nmap_xml.unwrap_or_default());
    let fallback_plan = fallback_plan(&signal, target);

    if let Some(raw) = ai_response {
        if let Ok(parsed) = serde_json::from_str::<AiPlanResponse>(extract_json_object(raw)) {
            if let Ok(plan) = validate_ai_plan(&signal, &parsed, target) {
                return build_record(
                    DecisionSource::Ai,
                    model,
                    plan,
                    "Plano proposto pela IA e aceito pela política segura.".to_string(),
                    &signal,
                );
            }
        }
    }

    build_record(
        DecisionSource::Fallback,
        model,
        fallback_plan,
        fallback_justification(&signal, target),
        &signal,
    )
}

fn build_record(
    source: DecisionSource,
    model: &str,
    plan: NucleiPlan,
    justification: String,
    signal: &NmapSignal,
) -> DecisionRecord {
    let mut parameters = BTreeMap::new();
    parameters.insert("should_run".to_string(), plan.should_run.to_string());
    parameters.insert("concurrency".to_string(), plan.concurrency.to_string());
    parameters.insert(
        "timeout_seconds".to_string(),
        plan.timeout_seconds.to_string(),
    );
    parameters.insert("templates".to_string(), plan.template_paths().join(","));

    DecisionRecord {
        source,
        model: model.to_string(),
        justification,
        parameters,
        evidence: signal.evidence_lines(),
        plan,
    }
}

#[derive(Clone, Debug)]
struct NmapSignal {
    ports: Vec<NmapPortFinding>,
}

impl NmapSignal {
    fn evidence_lines(&self) -> Vec<String> {
        let mut lines = Vec::new();
        for port in &self.ports {
            let service = port.service.as_deref().unwrap_or("desconhecido");
            let product = port.product.as_deref().unwrap_or("");
            let version = port.version.as_deref().unwrap_or("");
            lines.push(format!(
                "porta {} {} {} {}",
                port.port, service, product, version
            ));
        }
        lines
    }
}

fn analyze_nmap_signal(target: &str, nmap_xml: &str) -> NmapSignal {
    let ports = parse_nmap_ports(nmap_xml);
    if !ports.is_empty() {
        return NmapSignal { ports };
    }

    NmapSignal {
        ports: fallback_ports_from_target(target),
    }
}

fn fallback_ports_from_target(target: &str) -> Vec<NmapPortFinding> {
    let target_lower = target.to_lowercase();
    if target_lower.contains(":22") || target_lower.contains("ssh") {
        return vec![NmapPortFinding {
            port: "22".to_string(),
            service: Some("ssh".to_string()),
            product: Some("OpenSSH".to_string()),
            version: None,
        }];
    }
    if target_lower.starts_with("http://")
        || target_lower.starts_with("https://")
        || target_lower.contains(":80")
        || target_lower.contains(":443")
        || target_lower.contains(":8080")
        || target_lower.contains(":8443")
    {
        return vec![NmapPortFinding {
            port: "80".to_string(),
            service: Some("http".to_string()),
            product: Some("generic-web".to_string()),
            version: None,
        }];
    }

    vec![NmapPortFinding {
        port: "80".to_string(),
        service: Some("http".to_string()),
        product: Some("generic-web".to_string()),
        version: None,
    }]
}

fn fallback_plan(signal: &NmapSignal, target: &str) -> NucleiPlan {
    let profiles = profiles_for_signal(signal, target);
    let (concurrency, timeout_seconds) = if profiles
        .contains(&NucleiTemplateProfile::HttpMisconfiguration)
        || profiles.contains(&NucleiTemplateProfile::HttpExposedPanels)
    {
        (20, 3)
    } else {
        (8, 2)
    };

    NucleiPlan {
        should_run: !profiles.is_empty(),
        profiles,
        concurrency,
        timeout_seconds,
    }
}

fn extract_json_object(raw: &str) -> &str {
    let trimmed = raw.trim();
    let unfenced = trimmed
        .strip_prefix("```json")
        .or_else(|| trimmed.strip_prefix("```"))
        .map(str::trim_start)
        .and_then(|rest| rest.strip_suffix("```").map(str::trim_end))
        .unwrap_or(trimmed);
    match (unfenced.find('{'), unfenced.rfind('}')) {
        (Some(start), Some(end)) if start <= end => &unfenced[start..=end],
        _ => unfenced,
    }
}

fn validate_ai_plan(
    signal: &NmapSignal,
    parsed: &AiPlanResponse,
    target: &str,
) -> Result<NucleiPlan, String> {
    let requested_profiles = parsed
        .profiles
        .as_ref()
        .ok_or_else(|| "plano da IA sem perfis".to_string())?;

    let allowed_profiles = allowed_profiles_for_signal(signal, target);
    if requested_profiles.is_empty() {
        return Err("o plano da IA não solicitou nenhum perfil".to_string());
    }

    let mut validated_profiles = BTreeSet::new();
    for profile in requested_profiles {
        let mapped = map_profile(profile)
            .ok_or_else(|| format!("perfil do Nuclei não suportado: {profile}"))?;
        if !allowed_profiles.contains(&mapped) {
            return Err(format!("perfil não permitido pela política: {profile}"));
        }
        validated_profiles.insert(mapped);
    }

    let should_run = parsed.should_run.unwrap_or(true);
    if !should_run && !signal.ports.is_empty() {
        return Err("o plano da IA tentou ignorar o Nuclei apesar das portas abertas".to_string());
    }

    let concurrency = parsed.concurrency.unwrap_or(20);
    let timeout_seconds = parsed.timeout_seconds.unwrap_or(3);
    if !(1..=50).contains(&concurrency) {
        return Err("concorrência fora da política segura".to_string());
    }
    if !(1..=10).contains(&timeout_seconds) {
        return Err("tempo limite fora da política segura".to_string());
    }

    Ok(NucleiPlan {
        should_run,
        profiles: validated_profiles.into_iter().collect(),
        concurrency,
        timeout_seconds,
    })
}

fn allowed_profiles_for_signal(
    signal: &NmapSignal,
    target: &str,
) -> BTreeSet<NucleiTemplateProfile> {
    let mut profiles = BTreeSet::new();
    for port in &signal.ports {
        if is_web_port(port) {
            profiles.insert(NucleiTemplateProfile::HttpMisconfiguration);
            profiles.insert(NucleiTemplateProfile::HttpExposedPanels);
        }
        if is_ssh_port(port) {
            profiles.insert(NucleiTemplateProfile::SshExposure);
        }
        if is_database_port(port) {
            profiles.insert(NucleiTemplateProfile::DatabaseExposure);
        }
    }

    if profiles.is_empty() {
        profiles.extend(profiles_for_target(target));
    }

    if profiles.is_empty() {
        profiles.insert(NucleiTemplateProfile::Generic);
    }

    profiles
}

fn profiles_for_signal(signal: &NmapSignal, target: &str) -> Vec<NucleiTemplateProfile> {
    allowed_profiles_for_signal(signal, target)
        .into_iter()
        .collect()
}

fn profiles_for_target(target: &str) -> BTreeSet<NucleiTemplateProfile> {
    let lower = target.to_lowercase();
    let mut profiles = BTreeSet::new();
    if lower.starts_with("http://")
        || lower.starts_with("https://")
        || lower.contains(":80")
        || lower.contains(":443")
        || lower.contains(":8080")
        || lower.contains(":8443")
    {
        profiles.insert(NucleiTemplateProfile::HttpMisconfiguration);
        profiles.insert(NucleiTemplateProfile::HttpExposedPanels);
    }
    if lower.contains(":22") || lower.contains("ssh") {
        profiles.insert(NucleiTemplateProfile::SshExposure);
    }
    profiles
}

fn map_profile(profile: &str) -> Option<NucleiTemplateProfile> {
    match profile.trim().to_lowercase().as_str() {
        "http_misconfiguration" | "http-misconfiguration" | "misconfiguration" => {
            Some(NucleiTemplateProfile::HttpMisconfiguration)
        }
        "http_exposed_panels" | "http-exposed-panels" | "exposed-panels" => {
            Some(NucleiTemplateProfile::HttpExposedPanels)
        }
        "ssh_exposure" | "ssh-exposure" | "ssh" => Some(NucleiTemplateProfile::SshExposure),
        "database_exposure" | "database-exposure" | "database" => {
            Some(NucleiTemplateProfile::DatabaseExposure)
        }
        "generic" => Some(NucleiTemplateProfile::Generic),
        _ => None,
    }
}

fn is_web_port(port: &NmapPortFinding) -> bool {
    matches!(port.port.as_str(), "80" | "443" | "8080" | "8443")
        || port
            .service
            .as_deref()
            .map(|s| s.contains("http") || s.contains("ssl"))
            .unwrap_or(false)
}

fn is_ssh_port(port: &NmapPortFinding) -> bool {
    port.port == "22"
        || port
            .service
            .as_deref()
            .map(|s| s.contains("ssh"))
            .unwrap_or(false)
}

fn is_database_port(port: &NmapPortFinding) -> bool {
    matches!(
        port.port.as_str(),
        "3306" | "5432" | "6379" | "27017" | "1433"
    ) || port
        .service
        .as_deref()
        .map(|s| {
            s.contains("mysql")
                || s.contains("postgres")
                || s.contains("redis")
                || s.contains("mongodb")
                || s.contains("mssql")
        })
        .unwrap_or(false)
}

fn fallback_justification(signal: &NmapSignal, target: &str) -> String {
    if signal.ports.is_empty() {
        return format!(
            "Fallback determinístico sem sinais úteis do Nmap; usando perfil derivado do alvo {}.",
            target
        );
    }

    let ports = signal
        .ports
        .iter()
        .map(|port| port.port.as_str())
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "Fallback determinístico com base nos portos abertos detectados: {}.",
        ports
    )
}

impl NucleiPlan {
    pub fn template_paths(&self) -> Vec<&'static str> {
        let mut paths = Vec::new();
        for profile in &self.profiles {
            for path in profile.template_paths() {
                if !paths.contains(&path) {
                    paths.push(path);
                }
            }
        }
        paths
    }
}

impl DecisionRecord {
    pub fn sanitized(&self) -> Self {
        Self {
            source: self.source.clone(),
            model: crate::utils::redaction::sanitize_text(&self.model),
            justification: crate::utils::redaction::sanitize_text(&self.justification),
            parameters: self
                .parameters
                .iter()
                .map(|(key, value)| {
                    (
                        crate::utils::redaction::sanitize_text(key),
                        crate::utils::redaction::sanitize_text(value),
                    )
                })
                .collect(),
            evidence: self
                .evidence
                .iter()
                .map(|line| crate::utils::redaction::sanitize_text(line))
                .collect(),
            plan: self.plan.clone(),
        }
    }

    pub fn summary(&self) -> String {
        let templates = self
            .plan
            .template_paths()
            .into_iter()
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "{} plano={} templates={} concorrência={} tempo-limite={}s",
            match self.source {
                DecisionSource::Ai => "IA",
                DecisionSource::Fallback => "política local",
            },
            self.plan
                .profiles
                .iter()
                .map(NucleiTemplateProfile::label)
                .collect::<Vec<_>>()
                .join("+"),
            templates,
            self.plan.concurrency,
            self.plan.timeout_seconds
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{decide_nuclei_plan, DecisionSource, NucleiTemplateProfile};

    #[test]
    fn fallback_produces_distinct_plans_for_distinct_nmap_logs() {
        let ssh_xml = r#"
<nmaprun>
  <host>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" />
        <service name="ssh" product="OpenSSH" version="9.6p1" />
      </port>
    </ports>
  </host>
</nmaprun>
"#;
        let web_xml = r#"
<nmaprun>
  <host>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open" />
        <service name="http" product="nginx" version="1.24.0" />
      </port>
      <port protocol="tcp" portid="443">
        <state state="open" />
        <service name="https" product="nginx" version="1.24.0" />
      </port>
    </ports>
  </host>
</nmaprun>
"#;

        let ssh = decide_nuclei_plan("10.0.0.1", Some(ssh_xml), None, "mock");
        let web = decide_nuclei_plan("10.0.0.1", Some(web_xml), None, "mock");

        assert_eq!(ssh.source, DecisionSource::Fallback);
        assert_eq!(web.source, DecisionSource::Fallback);
        assert_eq!(ssh.plan.profiles, vec![NucleiTemplateProfile::SshExposure]);
        assert!(web
            .plan
            .profiles
            .contains(&NucleiTemplateProfile::HttpMisconfiguration));
        assert!(web
            .plan
            .profiles
            .contains(&NucleiTemplateProfile::HttpExposedPanels));
        assert_ne!(ssh.plan.profiles, web.plan.profiles);
        assert_ne!(ssh.plan.concurrency, web.plan.concurrency);
    }

    #[test]
    fn invalid_ai_plan_falls_back_to_deterministic_policy() {
        let xml = r#"
<nmaprun>
  <host>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open" />
        <service name="http" product="nginx" version="1.24.0" />
      </port>
    </ports>
  </host>
</nmaprun>
"#;

        let record = decide_nuclei_plan(
            "https://example.local",
            Some(xml),
            Some(r#"{"profiles":["exec rm -rf /"]}"#),
            "gpt-5",
        );

        assert_eq!(record.source, DecisionSource::Fallback);
        assert!(record
            .plan
            .profiles
            .contains(&NucleiTemplateProfile::HttpMisconfiguration));
    }

    #[test]
    fn valid_ai_plan_is_accepted_when_policy_allows_it() {
        let xml = r#"
<nmaprun>
  <host>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open" />
        <service name="http" product="nginx" version="1.24.0" />
      </port>
    </ports>
  </host>
</nmaprun>
"#;

        let record = decide_nuclei_plan(
            "https://example.local",
            Some(xml),
            Some(
                r#"{"should_run":true,"profiles":["http-misconfiguration","http-exposed-panels"],"concurrency":12,"timeout_seconds":4,"justification":"Target has HTTP exposure"}"#,
            ),
            "gpt-5",
        );

        assert_eq!(record.source, DecisionSource::Ai);
        assert_eq!(record.plan.concurrency, 12);
        assert_eq!(record.plan.timeout_seconds, 4);
        assert!(record
            .plan
            .profiles
            .contains(&NucleiTemplateProfile::HttpMisconfiguration));
        assert!(record
            .plan
            .profiles
            .contains(&NucleiTemplateProfile::HttpExposedPanels));
    }

    #[test]
    fn fenced_or_wrapped_ai_plan_is_extracted_before_parsing() {
        let xml = r#"
<nmaprun>
  <host>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open" />
        <service name="http" product="nginx" version="1.24.0" />
      </port>
    </ports>
  </host>
</nmaprun>
"#;

        let fenced = "```json\n{\"should_run\":true,\"profiles\":[\"http-misconfiguration\"],\"concurrency\":10,\"timeout_seconds\":5}\n```";
        let record = decide_nuclei_plan("https://example.local", Some(xml), Some(fenced), "gpt-5");
        assert_eq!(record.source, DecisionSource::Ai);
        assert_eq!(record.plan.concurrency, 10);
        assert_eq!(record.plan.timeout_seconds, 5);

        let wrapped = "Plano sugerido:\n{\"should_run\":true,\"profiles\":[\"http-exposed-panels\"],\"concurrency\":8,\"timeout_seconds\":4}\nFim.";
        let record = decide_nuclei_plan("https://example.local", Some(xml), Some(wrapped), "gpt-5");
        assert_eq!(record.source, DecisionSource::Ai);
        assert!(record
            .plan
            .profiles
            .contains(&NucleiTemplateProfile::HttpExposedPanels));
    }
}
