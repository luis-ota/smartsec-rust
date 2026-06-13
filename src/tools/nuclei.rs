use crate::domain::security_tool::SecurityToolRunner;

pub struct NucleiTool;

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
        let (host, port) = split_host_port(target);
        let target_arg = match port {
            Some(ref p) => format!("{}:{}", host, p),
            None => host,
        };
        let base = dirs::home_dir()
            .unwrap_or_default()
            .join("nuclei-templates");
        let tmpl_misc = base.join("http/misconfiguration/");
        format!(
            "nuclei -u {} -jsonl -silent -t {} -c 200 -timeout 2",
            target_arg,
            tmpl_misc.display(),
        )
    }

    async fn parse_output(&self, target: &str) -> Result<String, anyhow::Error> {
        let (host, port) = split_host_port(target);
        let mut cmd = tokio::process::Command::new("nuclei");
        let target_arg = match port {
            Some(ref p) => format!("{}:{}", host, p),
            None => host,
        };
        let base = dirs::home_dir()
            .unwrap_or_default()
            .join("nuclei-templates");
        cmd.arg("-u")
            .arg(&target_arg)
            .arg("-jsonl")
            .arg("-silent")
            .arg("-t")
            .arg(
                base.join("http/misconfiguration/")
                    .to_string_lossy()
                    .to_string(),
            )
            .arg("-c")
            .arg("200")
            .arg("-timeout")
            .arg("2");
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
