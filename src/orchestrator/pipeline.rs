use crate::ai::agent::AIAgent;
use crate::config::Configuration;
use crate::domain::security_tool::{SecurityTool, SecurityToolRunner, ToolInfo};
use crate::domain::vulnerability::Vulnerability;
use crate::orchestrator::sandbox::{ExecutionResult, ExecutionStatus, PodmanExecutor};
use crate::tools::mocks::MockTool;
use crate::tools::nmap::{NmapTool, NMAP_IMAGE, NMAP_VERSION};
use crate::tools::nuclei::{NucleiTool, NUCLEI_IMAGE};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
        let real_nuclei = tool_info.is_nuclei() && self.config.use_real_nuclei;
        let real_nmap = tool_info.is_nmap();
        let runner: Box<dyn SecurityToolRunner> = if real_nmap {
            Box::new(NmapTool)
        } else if real_nuclei {
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

        if real_nmap {
            exec.tool_version = Some(NMAP_VERSION.to_owned());
            let executor = PodmanExecutor::new(Duration::from_secs(15 * 60));
            match executor
                .execute(NMAP_IMAGE, &NmapTool::container_arguments(target))
                .await
            {
                Ok(result) => {
                    exec.output = podman_output(result);
                    if exec.output.starts_with("[ERRO]") {
                        exec.execution_error = Some(exec.output.clone());
                    }
                }
                Err(error) => {
                    let message =
                        format!("Não foi possível iniciar a varredura real do Nmap: {error:#}");
                    exec.output = format!("[ERRO] {message}");
                    exec.execution_error = Some(message);
                }
            }
            self.execution_history.push(exec.clone());
            return exec;
        }

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
        for exec in &mut self.execution_history {
            if exec.tool_name == "Nmap" && exec.execution_error.is_none() {
                match crate::orchestrator::nmap_parser::parse_nmap_findings(&exec.output) {
                    Ok(parsed) => real_findings.extend(parsed),
                    Err(error) => {
                        exec.execution_error = Some(format!(
                            "A saída do Nmap não pôde ser interpretada: {error:#}"
                        ));
                    }
                }
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
        let _ = self.persist_scan_log();
        Ok(self.findings.clone())
    }

    /// Salva os metadados e histórico estruturado do scan atual em disco.
    pub fn persist_scan_log(&self) -> anyhow::Result<std::path::PathBuf> {
        let dur = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let secs = dur.as_secs();
        let scan_id = format!("scan_{}", secs);

        let tools_executed = self
            .execution_history
            .iter()
            .map(|e| crate::orchestrator::scan_logger::ToolExecutionRecord {
                tool_name: e.tool_name.clone(),
                arguments: e.arguments.clone(),
                executed_at: e.executed_at.clone(),
                output_bytes: e.output.len(),
                output_sample: e.output.chars().take(200).collect(),
            })
            .collect();

        let metadata = crate::orchestrator::scan_logger::ScanMetadata::new(
            scan_id,
            self.config.target_url.clone(),
            chrono_like_now(),
            chrono_like_now(),
            format!("{}", self.config.execution_type),
            self.config.provider_mode.clone(),
            tools_executed,
            self.findings.clone(),
            self.last_log.clone(),
        );

        crate::orchestrator::scan_logger::save_scan_log(&metadata)
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
            "[ERRO] Varredura concluída em {:.2?}, mas o container {} não foi removido.{}",
            result.duration, result.container_id, cleanup_error
        ),
        ExecutionStatus::Failed(code) => format!(
            "[ERRO] O container {} da varredura encerrou com status {} após {:.2?}: {}{}",
            result.container_id,
            code.map_or_else(|| "desconhecido".to_owned(), |code| code.to_string()),
            result.duration,
            result.stderr.trim(),
            cleanup_error
        ),
        ExecutionStatus::TimedOut => format!(
            "[ERRO] O container {} da varredura excedeu o tempo limite de 15 minutos após {:.2?}.{}",
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
        let mut succeeded_result = result(ExecutionStatus::Succeeded);
        succeeded_result.cleanup_error = Some("detalhe".to_owned());
        let succeeded = podman_output(succeeded_result);
        let failed = podman_output(result(ExecutionStatus::Failed(None)));
        let timed_out = podman_output(result(ExecutionStatus::TimedOut));

        assert!(succeeded.contains("Varredura concluída"));
        assert!(failed.contains("[ERRO]"));
        assert!(failed.contains("da varredura encerrou com status desconhecido após"));
        assert!(timed_out.contains("da varredura excedeu o tempo limite de 15 minutos"));
    }

    #[test]
    fn builds_nmap_findings_only_from_valid_output() {
        let mut orchestrator = Orchestrator::new(Configuration::default());
        let mut execution = SecurityTool::new("Nmap", "nmap");
        execution.output = include_str!("../../tests/fixtures/nmap/open-ports.xml").to_owned();
        execution.tool_version = Some(NMAP_VERSION.to_owned());
        orchestrator.execution_history.push(execution);

        orchestrator.build_findings();

        assert_eq!(orchestrator.findings.len(), 2);
        assert!(orchestrator
            .findings
            .iter()
            .all(|finding| finding.tool == "Nmap" && finding.details.is_some()));
    }

    #[test]
    fn invalid_nmap_xml_produces_an_error_without_findings() {
        let mut orchestrator = Orchestrator::new(Configuration::default());
        let mut execution = SecurityTool::new("Nmap", "nmap");
        execution.output = include_str!("../../tests/fixtures/nmap/invalid.xml").to_owned();
        orchestrator.execution_history.push(execution);

        orchestrator.build_findings();

        assert!(orchestrator.findings.is_empty());
        let error = orchestrator.execution_history[0]
            .execution_error
            .as_deref()
            .unwrap();
        assert!(error.contains("saída do Nmap não pôde ser interpretada"));
    }

    #[test]
    fn failed_nmap_execution_never_produces_findings() {
        let mut orchestrator = Orchestrator::new(Configuration::default());
        let mut execution = SecurityTool::new("Nmap", "nmap");
        execution.output = include_str!("../../tests/fixtures/nmap/open-ports.xml").to_owned();
        execution.execution_error = Some("tempo limite excedido".to_owned());
        orchestrator.execution_history.push(execution);

        orchestrator.build_findings();

        assert!(orchestrator.findings.is_empty());
    }
}
