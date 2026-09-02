use crate::domain::security_tool::SecurityToolRunner;
use crate::orchestrator::decision::{NucleiPlan, NucleiTemplateProfile};

pub struct NucleiTool;

pub const NUCLEI_VERSION: &str = "v3.4.10";
pub const NUCLEI_IMAGE: &str = "docker.io/projectdiscovery/nuclei@sha256:2a11faa83464d769a888f1abb9396d5b4d8640619dfc6310086bf5c0d4003481";
pub const NUCLEI_TEMPLATES_COMMIT: &str = "b98e6097cb84e73e7a480436062d685a8f898824";

fn split_host_port(target: &str) -> (String, Option<String>) {
    let mut t = target.trim().to_string();
    for prefix in ["http://", "https://", "HTTP://", "HTTPS://"] {
        if let Some(rest) = t.strip_prefix(prefix) {
            t = rest.to_string();
            break;
        }
    }
    if let Some(idx) = t.find('/') {
        t.truncate(idx);
    }
    if t.is_empty() {
        return ("127.0.0.1".to_string(), None);
    }
    if let Some(idx) = t.rfind(':') {
        let host = t[..idx].to_string();
        let port = t[idx + 1..].to_string();
        if port.chars().all(|c| c.is_ascii_digit()) && !host.is_empty() {
            return (host, Some(port));
        }
    }
    (t, None)
}

#[async_trait::async_trait]
impl SecurityToolRunner for NucleiTool {
    fn tool_name(&self) -> &str {
        "Nuclei"
    }

    fn configure_command(&self, target: &str) -> String {
        self.configure_command_with_plan(target, &Self::default_plan())
    }

    async fn parse_output(&self, target: &str) -> Result<String, anyhow::Error> {
        self.parse_output_with_plan(target, &Self::default_plan())
            .await
    }
}

impl NucleiTool {
    pub fn default_plan() -> NucleiPlan {
        NucleiPlan {
            should_run: true,
            profiles: vec![
                NucleiTemplateProfile::HttpMisconfiguration,
                NucleiTemplateProfile::HttpExposedPanels,
            ],
            concurrency: 20,
            timeout_seconds: 3,
        }
    }

    pub fn configure_command_with_plan(&self, target: &str, plan: &NucleiPlan) -> String {
        let (host, port) = split_host_port(target);
        let target_arg = match port {
            Some(ref p) => format!("{}:{}", host, p),
            None => host,
        };
        let mut args = vec![
            "nuclei".to_string(),
            "-u".to_string(),
            target_arg,
            "-jsonl".to_string(),
            "-silent".to_string(),
        ];

        for template in plan.template_paths() {
            args.push("-t".to_string());
            args.push(format!("/root/nuclei-templates/{template}"));
        }

        args.push("-c".to_string());
        args.push(plan.concurrency.to_string());
        args.push("-timeout".to_string());
        args.push(plan.timeout_seconds.to_string());

        args.join(" ")
    }

    pub async fn parse_output_with_plan(
        &self,
        _target: &str,
        _plan: &NucleiPlan,
    ) -> Result<String, anyhow::Error> {
        Err(anyhow::anyhow!(
            "Nuclei real exige execução pelo executor Podman; binário no host não é permitido"
        ))
    }
}

impl NucleiTool {
    #[allow(dead_code)]
    pub fn container_arguments(target: &str) -> Vec<String> {
        Self::container_arguments_with_plan(target, &Self::default_plan())
    }

    pub fn container_arguments_with_plan(target: &str, plan: &NucleiPlan) -> Vec<String> {
        let (host, port) = split_host_port(target);
        let target_arg = match port {
            Some(port) => format!("{host}:{port}"),
            None => host,
        };
        let mut args = vec![
            "-u".to_owned(),
            target_arg,
            "-jsonl".to_owned(),
            "-silent".to_owned(),
            "-c".to_owned(),
            plan.concurrency.to_string(),
            "-timeout".to_owned(),
            plan.timeout_seconds.to_string(),
            "-disable-update-check".to_owned(),
        ];
        for template in plan.template_paths() {
            args.push("-t".to_owned());
            args.push(format!("/root/nuclei-templates/{template}"));
        }
        args
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_container_arguments_without_a_host_shell() {
        let arguments = NucleiTool::container_arguments("https://example.test:8443/path");

        assert_eq!(
            arguments,
            [
                "-u",
                "example.test:8443",
                "-jsonl",
                "-silent",
                "-c",
                "20",
                "-timeout",
                "3",
                "-disable-update-check",
                "-t",
                "/root/nuclei-templates/http/misconfiguration/",
                "-t",
                "/root/nuclei-templates/http/exposed-panels/"
            ]
        );
    }

    #[test]
    fn applies_the_validated_plan_to_container_arguments() {
        let plan = NucleiPlan {
            should_run: true,
            profiles: vec![NucleiTemplateProfile::SshExposure],
            concurrency: 7,
            timeout_seconds: 9,
        };
        let arguments = NucleiTool::container_arguments_with_plan("10.0.0.1", &plan);
        assert!(arguments.windows(2).any(|pair| pair == ["-c", "7"]));
        assert!(arguments.windows(2).any(|pair| pair == ["-timeout", "9"]));
        assert!(arguments.iter().any(|arg| arg.contains("network/")));
        assert!(NUCLEI_IMAGE.contains("@sha256:"));
    }
}
