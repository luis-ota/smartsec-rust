use crate::ai::agent::AIAgent;
use crate::config::Configuration;
use crate::domain::security_tool::{SecurityTool, SecurityToolRunner, ToolInfo};
use crate::domain::vulnerability::Vulnerability;
use crate::tools::mocks::MockTool;
use crate::tools::nuclei::NucleiTool;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct Orchestrator {
    pub config: Configuration,
    pub agent: AIAgent,
    pub sandbox: Box<dyn crate::orchestrator::sandbox::SandboxManager>,
    pub execution_history: Vec<SecurityTool>,
    pub findings: Vec<Vulnerability>,
    pub paused: bool,
    pub cancelled: bool,
    pub last_log: String,
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
            findings: Vec::new(),
            paused: false,
            cancelled: false,
            last_log: String::new(),
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

    pub fn persist_scan_log(&self) -> Result<std::path::PathBuf> {
        let records = self
            .execution_history
            .iter()
            .map(
                |execution| crate::orchestrator::scan_logger::ToolExecutionRecord {
                    tool_name: execution.tool_name.clone(),
                    arguments: execution
                        .arguments
                        .split_whitespace()
                        .map(str::to_owned)
                        .collect(),
                    executed_at: execution.executed_at.clone(),
                    output_bytes: execution.output.len(),
                    output_sample: execution.output.chars().take(512).collect(),
                },
            )
            .collect();
        let metadata = crate::orchestrator::scan_logger::ScanMetadata::new(
            self.container_id(),
            self.config.target_url.clone(),
            String::new(),
            String::new(),
            self.config.execution_type.to_string(),
            format!("{:?}", self.config.llm.provider),
            records,
            self.findings.clone(),
            self.last_log.clone(),
        );
        crate::orchestrator::scan_logger::save_scan_log(&metadata)
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
        let runner: Box<dyn SecurityToolRunner> =
            if !self.config.demo_mode && tool_info.is_nuclei() && self.config.use_real_nuclei {
                Box::new(NucleiTool)
            } else {
                Box::new(MockTool {
                    name: tool_info.name,
                    description: tool_info.description,
                })
            };

        let arguments = runner.configure_command(target);
        let mut exec = SecurityTool::new(tool_info.name, &arguments);
        exec.executed_at = now_iso8601();

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

    /// Constrói os achados reais a partir da execução dos scanners.
    ///
    /// **Nunca** inclui achados simulados. Para modo demo, use [`build_demo_findings`].
    pub fn build_findings(&mut self) {
        let target = self.config.target_url.clone();
        let mut real_findings: Vec<Vulnerability> = Vec::new();
        for exec in &self.execution_history {
            if exec.tool_name == "Nuclei" && !exec.output.is_empty() {
                let parsed = crate::orchestrator::nuclei_parser::parse_nuclei_findings(
                    &exec.output,
                    &target,
                );
                real_findings.extend(parsed);
            }
            if exec.tool_name == "Nmap" && !exec.output.is_empty() {
                let parsed =
                    crate::orchestrator::nmap_parser::parse_nmap_findings(&exec.output, &target);
                real_findings.extend(parsed);
            }
        }
        self.findings = real_findings;
    }

    /// Constrói achados de demonstração.
    ///
    /// Só deve ser chamada quando `config.demo_mode == true`.
    /// Todos os achados têm `source: FindingSource::Demo`.
    pub fn build_demo_findings(&mut self) {
        let target = self.config.target_url.clone();
        self.findings = crate::domain::demo_findings::demo_all(&target);
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

        if self.config.demo_mode {
            self.build_demo_findings();
        } else {
            self.build_findings();
        }

        let analysis = self.agent.analyze_logs(&self.findings).await;
        self.last_log = analysis;
        Ok(self.findings.clone())
    }
}

fn now_iso8601() -> String {
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs();
    let s = secs % 60;
    let m = (secs / 60) % 60;
    let h = (secs / 3600) % 24;
    format!("2026-01-01T{:02}:{:02}:{:02}Z", h, m, s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Configuration;
    use crate::domain::vulnerability::FindingSource;

    fn make_config(demo: bool) -> Configuration {
        let mut c = Configuration::default();
        c.demo_mode = demo;
        c.target_url = "http://test.local".to_string();
        c
    }

    #[test]
    fn build_findings_never_includes_demo() {
        let mut orch = Orchestrator::new(make_config(false));
        orch.build_findings();
        for f in &orch.findings {
            assert_ne!(
                f.source,
                FindingSource::Demo,
                "Execução real não deve conter achados de demo"
            );
        }
    }

    #[test]
    fn build_demo_findings_only_includes_demo() {
        let mut orch = Orchestrator::new(make_config(true));
        orch.build_demo_findings();
        assert!(!orch.findings.is_empty(), "Modo demo deve ter achados");
        for f in &orch.findings {
            assert_eq!(
                f.source,
                FindingSource::Demo,
                "Modo demo deve ter apenas achados Demo"
            );
        }
    }

    #[test]
    fn real_run_empty_history_produces_no_findings() {
        let mut orch = Orchestrator::new(make_config(false));
        orch.build_findings();
        assert!(
            orch.findings.is_empty(),
            "Sem execuções, não deve haver achados"
        );
    }
}
