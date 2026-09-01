use crate::ai::agent::AIAgent;
use crate::config::Configuration;
use crate::domain::security_tool::{SecurityTool, SecurityToolRunner, ToolInfo};
use crate::domain::vulnerability::Vulnerability;
use crate::orchestrator::decision::{decide_nuclei_plan, DecisionRecord};
use crate::tools::mocks::MockTool;
use crate::tools::nmap::NmapTool;
use crate::tools::nuclei::NucleiTool;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct Orchestrator {
    pub config: Configuration,
    pub agent: AIAgent,
    pub sandbox: Box<dyn crate::orchestrator::sandbox::SandboxManager>,
    pub execution_history: Vec<SecurityTool>,
    pub decision_history: Vec<DecisionRecord>,
    pub findings: Vec<Vulnerability>,
    pub paused: bool,
    pub cancelled: bool,
    pub last_log: String,
    latest_nmap_output: Option<String>,
}

impl Orchestrator {
    pub fn new(config: Configuration) -> Self {
        let agent = AIAgent::from_config(&config.llm);
        let sandbox: Box<dyn crate::orchestrator::sandbox::SandboxManager> =
            Box::new(crate::orchestrator::sandbox::MockSandbox);
        Self {
            config,
            agent,
            sandbox,
            execution_history: Vec::new(),
            decision_history: Vec::new(),
            findings: Vec::new(),
            paused: false,
            cancelled: false,
            last_log: String::new(),
            latest_nmap_output: None,
        }
    }

    pub fn agent_handle(&self) -> AIAgent {
        AIAgent::from_config(&self.config.llm)
    }

    pub fn container_id(&self) -> String {
        let dur = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let secs = dur.as_secs();
        format!("smartsec-{:x}", secs)
    }

    #[allow(dead_code)]
    pub fn status(&self) -> &str {
        if self.cancelled {
            "cancelled"
        } else if self.paused {
            "paused"
        } else if self.findings.is_empty() {
            "idle"
        } else {
            "complete"
        }
    }

    pub fn pause_execution(&mut self) {
        self.paused = true;
    }

    pub fn resume_execution(&mut self) {
        self.paused = false;
    }

    pub fn cancel_execution(&mut self) {
        self.cancelled = true;
    }

    pub fn reset_run_state(&mut self) {
        self.execution_history.clear();
        self.decision_history.clear();
        self.findings.clear();
        self.latest_nmap_output = None;
    }

    pub fn determine_next_step(&self) -> String {
        if self
            .findings
            .iter()
            .any(|v| v.severity == crate::domain::Severity::Critical)
        {
            "alert".to_string()
        } else {
            "report".to_string()
        }
    }

    pub async fn execute_tool(&mut self, tool_info: &ToolInfo, target: &str) -> SecurityTool {
        if tool_info.is_nmap() {
            return self.execute_nmap(tool_info, target).await;
        }

        if tool_info.is_nuclei() && self.config.use_real_nuclei {
            return self.execute_nuclei_with_plan(tool_info, target).await;
        }

        let runner: Box<dyn SecurityToolRunner> = Box::new(MockTool {
            name: tool_info.name,
            description: tool_info.description,
        });

        let arguments = runner.configure_command(target);
        let mut exec = SecurityTool::new(tool_info.name, &arguments);
        exec.executed_at = chrono_like_now();

        let container_id = self
            .sandbox
            .create_isolated_environment(tool_info.category)
            .unwrap_or_else(|_| format!("fallback-{}", tool_info.name.to_lowercase()));
        let _ = self.sandbox.run_command(&container_id, &arguments);
        let _ = self.sandbox.destroy_environment(&container_id);

        match runner.parse_output(target).await {
            Ok(output) => {
                exec.output = output;
            }
            Err(e) => {
                exec.output = format!("[ERROR] {}", e);
            }
        }

        self.execution_history.push(exec.clone());
        exec
    }

    async fn execute_nmap(&mut self, tool_info: &ToolInfo, target: &str) -> SecurityTool {
        let runner = NmapTool;
        let arguments = runner.configure_command(target);
        let mut exec = SecurityTool::new(tool_info.name, &arguments);
        exec.executed_at = chrono_like_now();

        let container_id = self
            .sandbox
            .create_isolated_environment(tool_info.category)
            .unwrap_or_else(|_| format!("fallback-{}", tool_info.name.to_lowercase()));
        let _ = self.sandbox.run_command(&container_id, &arguments);
        let _ = self.sandbox.destroy_environment(&container_id);

        match runner.parse_output(target).await {
            Ok(output) => {
                self.latest_nmap_output = Some(output.clone());
                exec.output = output;
            }
            Err(e) => {
                exec.output = format!("[ERROR] {}", e);
                self.latest_nmap_output = Some(exec.output.clone());
            }
        }

        self.execution_history.push(exec.clone());
        exec
    }

    async fn execute_nuclei_with_plan(&mut self, tool_info: &ToolInfo, target: &str) -> SecurityTool {
        let ai_response = self.request_nuclei_plan(target).await;
        let decision = decide_nuclei_plan(
            target,
            self.latest_nmap_output.as_deref(),
            ai_response.as_deref(),
            &self.agent.model,
        );
        self.decision_history.push(decision.clone());

        let runner = NucleiTool;
        let arguments = runner.configure_command_with_plan(target, &decision.plan);
        let mut exec = SecurityTool::new(tool_info.name, &arguments);
        exec.executed_at = chrono_like_now();

        if !decision.plan.should_run {
            exec.output = format!("Nuclei skipped by policy: {}", decision.justification);
            self.execution_history.push(exec.clone());
            return exec;
        }

        let container_id = self
            .sandbox
            .create_isolated_environment(tool_info.category)
            .unwrap_or_else(|_| format!("fallback-{}", tool_info.name.to_lowercase()));
        let _ = self.sandbox.run_command(&container_id, &arguments);
        let _ = self.sandbox.destroy_environment(&container_id);

        match runner.parse_output_with_plan(target, &decision.plan).await {
            Ok(output) => {
                exec.output = output;
            }
            Err(e) => {
                exec.output = format!("[ERROR] {}", e);
            }
        }

        self.execution_history.push(exec.clone());
        exec
    }

    async fn request_nuclei_plan(&self, target: &str) -> Option<String> {
        let prompt = format!(
            "Analyze this Nmap XML and return only JSON with fields should_run, profiles, concurrency, timeout_seconds, justification. Allowed profiles are http-misconfiguration, http-exposed-panels, ssh-exposure, database-exposure, generic. Never invent command flags or shell commands. Target: {}\n\nNmap log:\n{}",
            target,
            self.latest_nmap_output.as_deref().unwrap_or_default()
        );

        self.agent
            .provider
            .execute_prompt(&prompt, &self.agent.model)
            .await
            .ok()
    }

    pub fn build_findings(&mut self) {
        let mut real_findings: Vec<Vulnerability> = Vec::new();
        for exec in &self.execution_history {
            if exec.tool_name == "Nmap" && !exec.output.is_empty() {
                let parsed = crate::orchestrator::nmap_parser::parse_nmap_findings(&exec.output);
                real_findings.extend(parsed);
            }
            if exec.tool_name == "Nuclei" && !exec.output.is_empty() {
                let parsed =
                    crate::orchestrator::nuclei_parser::parse_nuclei_findings(&exec.output);
                real_findings.extend(parsed);
            }
        }
        self.findings = real_findings;
    }

    #[allow(dead_code)]
    pub async fn run_full_pipeline(
        &mut self,
        selected: &[&ToolInfo],
    ) -> Result<Vec<Vulnerability>, anyhow::Error> {
        let target = self.config.target_url.clone();
        for tool in selected {
            if self.cancelled {
                break;
            }
            if self.paused {
                loop {
                    if !self.paused || self.cancelled {
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }
            let _exec = self.execute_tool(tool, &target).await;
        }
        self.build_findings();
        let analysis = self.agent.analyze_logs(&self.findings).await;
        self.last_log = analysis;
        Ok(self.findings.clone())
    }
}

fn chrono_like_now() -> String {
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs();
    let mins = (secs / 60) % 60;
    let hours = (secs / 3600) % 24;
    format!("2026-01-01T{:02}:{:02}:00Z", hours, mins)
}
