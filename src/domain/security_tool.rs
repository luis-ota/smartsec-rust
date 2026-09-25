use async_trait::async_trait;

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
