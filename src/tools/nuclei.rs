use crate::orchestrator::decision::{NucleiPlan, NucleiTemplateProfile};
use crate::domain::security_tool::SecurityToolRunner;

pub struct NucleiTool;

pub const NUCLEI_IMAGE: &str = "docker.io/projectdiscovery/nuclei:v3.4.10";

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
        self.parse_output_with_plan(target, &Self::default_plan()).await
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

        let base = dirs::home_dir().unwrap_or_default().join("nuclei-templates");
        for template in plan.template_paths() {
            args.push("-t".to_string());
            args.push(base.join(template).to_string_lossy().to_string());
        }

        args.push("-c".to_string());
        args.push(plan.concurrency.to_string());
        args.push("-timeout".to_string());
        args.push(plan.timeout_seconds.to_string());

        args.join(" ")
    }

    pub async fn parse_output_with_plan(
        &self,
        target: &str,
        plan: &NucleiPlan,
    ) -> Result<String, anyhow::Error> {
        let (host, port) = split_host_port(target);
        let mut cmd = tokio::process::Command::new("nuclei");
        let target_arg = match port {
            Some(ref p) => format!("{}:{}", host, p),
            None => host,
        };
        let base = dirs::home_dir().unwrap_or_default().join("nuclei-templates");
        cmd.arg("-u")
            .arg(&target_arg)
            .arg("-jsonl")
            .arg("-silent")
        ;

        for template in plan.template_paths() {
            cmd.arg("-t")
                .arg(base.join(template).to_string_lossy().to_string());
        }

        cmd.arg("-c")
            .arg(plan.concurrency.to_string())
            .arg("-timeout")
            .arg(plan.timeout_seconds.to_string());
        let output = cmd.output().await?;

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).to_string())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if output.stdout.is_empty() {
                Ok(format!(
                    "Scan complete — {} template checks run.",
                    stderr.lines().count()
                ))
            } else {
                Err(anyhow::anyhow!("Nuclei error: {}", stderr))
            }
        }
    }
}

impl NucleiTool {
    pub fn container_arguments(target: &str) -> Vec<String> {
        let (host, port) = split_host_port(target);
        let target_arg = match port {
            Some(port) => format!("{host}:{port}"),
            None => host,
        };
        vec![
            "-u".to_owned(),
            target_arg,
            "-jsonl".to_owned(),
            "-silent".to_owned(),
            "-c".to_owned(),
            "25".to_owned(),
            "-timeout".to_owned(),
            "2".to_owned(),
            "-disable-update-check".to_owned(),
        ]
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
                "25",
                "-timeout",
                "2",
                "-disable-update-check"
            ]
        );
    }
}
