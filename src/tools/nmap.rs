use crate::domain::security_tool::SecurityToolRunner;

pub struct NmapTool;

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
impl SecurityToolRunner for NmapTool {
    fn tool_name(&self) -> &str {
        "Nmap"
    }

    fn configure_command(&self, target: &str) -> String {
        let (host, port) = split_host_port(target);
        match port {
            Some(p) => format!("nmap -sV -sC -oX - -p {} {}", p, host),
            None => format!("nmap -sV -sC -oX - {}", host),
        }
    }

    async fn parse_output(&self, target: &str) -> Result<String, anyhow::Error> {
        let (host, port) = split_host_port(target);
        let mut cmd = tokio::process::Command::new("nmap");
        cmd.arg("-sV").arg("-sC").arg("-oX").arg("-");
        if let Some(p) = &port {
            cmd.arg("-p").arg(p);
        }
        cmd.arg(&host);
        let output = cmd.output().await?;

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).to_string())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(anyhow::anyhow!("Nmap failed: {}", stderr))
        }
    }
}

pub struct NmapToolSync;

#[allow(dead_code)]
impl NmapToolSync {
    pub async fn run(target: &str) -> Result<String, anyhow::Error> {
        let nmap = NmapTool;
        nmap.parse_output(target).await
    }
}
