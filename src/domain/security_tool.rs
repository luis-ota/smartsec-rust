use async_trait::async_trait;

#[derive(Clone, Debug)]
pub struct ToolInfo {
    pub name: &'static str,
    pub description: &'static str,
    pub category: &'static str,
}

impl ToolInfo {
    pub fn all() -> Vec<Self> {
        vec![
            ToolInfo { name: "ZAP", description: "OWASP ZAP - Web app scanner", category: "DAST" },
            ToolInfo { name: "Nikto", description: "Web server scanner", category: "DAST" },
            ToolInfo { name: "SQLMap", description: "SQL injection detector", category: "DAST" },
            ToolInfo { name: "Nmap", description: "Network port scanner", category: "Recon" },
            ToolInfo { name: "BurpSuite", description: "Web vulnerability scanner", category: "DAST" },
            ToolInfo { name: "Trivy", description: "Container/IaC scanner", category: "SCA" },
            ToolInfo { name: "Snyk", description: "Dependency vulnerability scanner", category: "SCA" },
            ToolInfo { name: "Bandit", description: "Python security linter", category: "SAST" },
        ]
    }

    #[allow(dead_code)]
    pub fn is_nmap(&self) -> bool {
        self.name == "Nmap"
    }
}

#[async_trait]
#[allow(dead_code)]
pub trait SecurityTool: Send + Sync {
    fn tool_name(&self) -> &str;
    fn configure_command(&self, target: &str) -> String;
    async fn parse_output(&self, target: &str) -> Result<String, anyhow::Error>;
}
