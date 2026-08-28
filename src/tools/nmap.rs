use crate::domain::security_tool::SecurityToolRunner;

pub struct NmapTool;

pub const NMAP_IMAGE: &str = "docker.io/instrumentisto/nmap:7.95";
pub const NMAP_VERSION: &str = "7.95";

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
        format!("nmap {}", Self::container_arguments(target).join(" "))
    }

    async fn parse_output(&self, target: &str) -> Result<String, anyhow::Error> {
        let _ = target;
        Err(anyhow::anyhow!(
            "O Nmap real deve ser executado pelo executor Podman"
        ))
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

impl NmapTool {
    pub fn container_arguments(target: &str) -> Vec<String> {
        let (host, port) = split_host_port(target);
        let mut arguments = vec![
            "-sT".to_owned(),
            "-sV".to_owned(),
            "-oX".to_owned(),
            "-".to_owned(),
        ];
        if let Some(port) = port {
            arguments.extend(["-p".to_owned(), port]);
        }
        arguments.push(host);
        arguments
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_container_arguments_without_a_host_shell() {
        let arguments = NmapTool::container_arguments("https://example.test:8443/path");

        assert_eq!(
            arguments,
            ["-sT", "-sV", "-oX", "-", "-p", "8443", "example.test"]
        );
    }

    #[test]
    fn records_the_command_executed_in_the_container() {
        let tool = NmapTool;

        assert_eq!(
            tool.configure_command("example.test"),
            "nmap -sT -sV -oX - example.test"
        );
    }

    #[tokio::test]
    async fn refuses_direct_host_execution() {
        let error = NmapTool.parse_output("example.test").await.unwrap_err();

        assert!(error.to_string().contains("executor Podman"));
    }
}
