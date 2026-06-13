use crate::domain::security_tool::SecurityToolRunner;

pub struct MockTool {
    pub name: &'static str,
    pub description: &'static str,
}

#[async_trait::async_trait]
impl SecurityToolRunner for MockTool {
    fn tool_name(&self) -> &str {
        self.name
    }

    fn configure_command(&self, target: &str) -> String {
        format!(
            "echo '[{}] {} ({}) scanning {}'",
            self.name, self.name, self.description, target
        )
    }

    async fn parse_output(&self, _target: &str) -> Result<String, anyhow::Error> {
        Ok(format!(
            "[{}] {} ({}) scan completed",
            self.name, self.name, self.description
        ))
    }
}
