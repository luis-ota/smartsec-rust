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
                name: "ZAP",
                description: "OWASP ZAP - Web app scanner",
                category: "DAST",
            },
            ToolInfo {
                name: "Nikto",
                description: "Web server scanner",
                category: "DAST",
            },
            ToolInfo {
                name: "SQLMap",
                description: "SQL injection detector",
                category: "DAST",
            },
            ToolInfo {
                name: "Nuclei",
                description: "Vulnerability scanner (CVEs)",
                category: "DAST",
            },
            ToolInfo {
                name: "BurpSuite",
                description: "Web vulnerability scanner",
                category: "DAST",
            },
            ToolInfo {
                name: "Trivy",
                description: "Container/IaC scanner",
                category: "SCA",
            },
            ToolInfo {
                name: "Snyk",
                description: "Dependency vulnerability scanner",
                category: "SCA",
            },
            ToolInfo {
                name: "Bandit",
                description: "Python security linter",
                category: "SAST",
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
    #[allow(dead_code)]
    pub tool_version: Option<String>,
    pub execution_error: Option<String>,
}

impl SecurityTool {
    pub fn new(tool_name: &str, arguments: &str) -> Self {
        Self {
            tool_name: tool_name.to_string(),
            arguments: arguments.to_string(),
            executed_at: chrono_like_now(),
            output: String::new(),
            tool_version: None,
            execution_error: None,
        }
    }

    #[allow(dead_code)]
    pub fn with_output(mut self, output: String) -> Self {
        self.output = output;
        self
    }
}

fn chrono_like_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs();
    let mins = (secs / 60) % 60;
    let hours = (secs / 3600) % 24;
    format!("2026-01-01T{:02}:{:02}:00Z", hours, mins)
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
