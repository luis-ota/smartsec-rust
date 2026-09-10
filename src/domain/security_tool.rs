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
            ToolInfo {
                name: "Nmap",
                description: "Mapeamento de hosts, portas e serviços",
                category: "RECON",
            },
            ToolInfo {
                name: "Nuclei",
                description: "Scanner de vulnerabilidades (CVEs)",
                category: "DAST",
            },
        ]
    }

    pub fn is_nuclei(&self) -> bool {
        self.name == "Nuclei"
    }

    pub fn is_nmap(&self) -> bool {
        self.name == "Nmap"
    }
}

#[derive(Clone, Debug)]
pub struct SecurityTool {
    #[allow(dead_code)]
    pub tool_name: String,
    #[allow(dead_code)]
    pub arguments: String,
    pub executed_at: String,
    pub output: String,
    pub stderr: String,
    pub status: String,
    pub duration_ms: u128,
    pub image: Option<String>,
    #[allow(dead_code)]
    pub tool_version: Option<String>,
    pub execution_error: Option<String>,
    pub podman_trace: Vec<String>,
}

impl SecurityTool {
    pub fn new(tool_name: &str, arguments: &str) -> Self {
        Self {
            tool_name: tool_name.to_string(),
            arguments: arguments.to_string(),
            executed_at: chrono_like_now(),
            output: String::new(),
            stderr: String::new(),
            status: "not_started".to_string(),
            duration_ms: 0,
            image: None,
            tool_version: None,
            execution_error: None,
            podman_trace: Vec::new(),
        }
    }

    #[allow(dead_code)]
    pub fn with_output(mut self, output: String) -> Self {
        self.output = output;
        self
    }
}

fn chrono_like_now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

#[async_trait]
pub trait SecurityToolRunner: Send + Sync {
    #[allow(dead_code)]
    fn tool_name(&self) -> &str;
    fn configure_command(&self, target: &str) -> String;
    async fn parse_output(&self, target: &str) -> Result<String, anyhow::Error>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn official_catalog_contains_nmap() {
        let tools = ToolInfo::all();

        let nmap = tools.iter().find(|tool| tool.is_nmap()).unwrap();
        assert_eq!(nmap.name, "Nmap");
        assert_eq!(nmap.category, "RECON");
    }
}
