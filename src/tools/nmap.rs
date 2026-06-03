use crate::domain::security_tool::SecurityTool;

#[allow(dead_code)]
pub struct NmapTool;

#[async_trait::async_trait]
impl SecurityTool for NmapTool {
    fn tool_name(&self) -> &str {
        "Nmap"
    }

    fn configure_command(&self, target: &str) -> String {
        format!("nmap -sV -sC -oX - {}", target)
    }

    async fn parse_output(&self, target: &str) -> Result<String, anyhow::Error> {
        let output = tokio::process::Command::new("nmap")
            .args(["-sV", "-sC", "-oX", "-", target])
            .output()
            .await?;

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).to_string())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(anyhow::anyhow!("Nmap failed: {}", stderr))
        }
    }
}

#[allow(dead_code)]
pub struct NmapToolSync;

impl NmapToolSync {
    #[allow(dead_code)]
    pub async fn run(target: &str) -> Result<String, anyhow::Error> {
        let nmap = NmapTool;
        nmap.parse_output(target).await
    }
}
