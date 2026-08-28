use crate::ai::agent::AIAgent;
use crate::config::Configuration;
use crate::domain::security_tool::{SecurityTool, SecurityToolRunner, ToolInfo};
use crate::domain::vulnerability::Vulnerability;
use crate::orchestrator::sandbox::{ExecutionResult, ExecutionStatus, PodmanExecutor};
use crate::tools::mocks::MockTool;
use crate::tools::nuclei::{NucleiTool, NUCLEI_IMAGE};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
        let real_nuclei = tool_info.is_nuclei() && self.config.use_real_nuclei;
        let runner: Box<dyn SecurityToolRunner> = if real_nuclei {
            Box::new(NucleiTool)
        } else {
            Box::new(MockTool {
                name: tool_info.name,
                description: tool_info.description,
            })
        };

        let arguments = runner.configure_command(target);
        let mut exec = SecurityTool::new(tool_info.name, &arguments);
        exec.executed_at = chrono_like_now();

        if real_nuclei {
            let executor = PodmanExecutor::new(Duration::from_secs(15 * 60));
            exec.output = match executor
                .execute(NUCLEI_IMAGE, &NucleiTool::container_arguments(target))
                .await
            {
                Ok(result) => podman_output(result),
                Err(error) => {
                    format!("[ERRO] Não foi possível iniciar a varredura real: {error:#}")
                }
            };
            self.execution_history.push(exec.clone());
            return exec;
        }

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

    pub fn build_findings(&mut self) {
        let mut real_findings: Vec<Vulnerability> = Vec::new();
        for exec in &self.execution_history {
            if exec.tool_name == "Nuclei" && !exec.output.is_empty() {
                let parsed =
                    crate::orchestrator::nuclei_parser::parse_nuclei_findings(&exec.output);
                real_findings.extend(parsed);
            }
        }
        let mut findings = real_findings;
        findings.extend(Vulnerability::mock_all());
        self.findings = findings;
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

fn podman_output(result: ExecutionResult) -> String {
    let cleanup_error = result
        .cleanup_error
        .map(|error| format!(" Falha na limpeza: {error}"))
        .unwrap_or_default();
    match result.status {
        ExecutionStatus::Succeeded if cleanup_error.is_empty() => result.stdout,
        ExecutionStatus::Succeeded => format!(
            "[ERRO] Scanner concluído em {:.2?}, mas o container {} não foi removido.{}",
            result.duration, result.container_id, cleanup_error
        ),
        ExecutionStatus::Failed(code) => format!(
            "[ERRO] O container {} do scanner encerrou com status {} após {:.2?}: {}{}",
            result.container_id,
            code.map_or_else(|| "desconhecido".to_owned(), |code| code.to_string()),
            result.duration,
            result.stderr.trim(),
            cleanup_error
        ),
        ExecutionStatus::TimedOut => format!(
            "[ERRO] O container {} do scanner excedeu o tempo limite de 15 minutos após {:.2?}.{}",
            result.container_id, result.duration, cleanup_error
        ),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn result(status: ExecutionStatus) -> ExecutionResult {
        ExecutionResult {
            stdout: String::new(),
            stderr: "saída externa".to_owned(),
            status,
            duration: Duration::from_secs(2),
            container_id: "container-123".to_owned(),
            cleanup_error: None,
        }
    }

    #[test]
    fn formats_podman_failures_in_brazilian_portuguese() {
        let failed = podman_output(result(ExecutionStatus::Failed(None)));
        let timed_out = podman_output(result(ExecutionStatus::TimedOut));

        assert!(failed.contains("[ERRO]"));
        assert!(failed.contains("status desconhecido após"));
        assert!(timed_out.contains("excedeu o tempo limite de 15 minutos"));
    }
}
