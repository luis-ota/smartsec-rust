use crate::domain::security_tool::SecurityTool;

#[allow(dead_code)]
pub struct MockTool {
    pub name: &'static str,
    pub description: &'static str,
}

#[async_trait::async_trait]
impl SecurityTool for MockTool {
    fn tool_name(&self) -> &str {
        self.name
    }

    fn configure_command(&self, target: &str) -> String {
        format!("echo '[MOCK] {} scanning {}'", self.name, target)
    }

    async fn parse_output(&self, _target: &str) -> Result<String, anyhow::Error> {
        Ok(format!("[MOCK] {} scan completed (simulated)", self.name))
    }
}
