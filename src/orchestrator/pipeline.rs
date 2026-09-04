use crate::ai::agent::AIAgent;
use crate::config::Configuration;
use crate::domain::security_tool::{SecurityTool, SecurityToolRunner, ToolInfo};
use crate::domain::vulnerability::Vulnerability;
use crate::orchestrator::decision::{decide_nuclei_plan, DecisionRecord};
use crate::orchestrator::sandbox::{ExecutionResult, ExecutionStatus, PodmanExecutor};
use crate::tools::nmap::{NmapTool, NMAP_IMAGE, NMAP_VERSION};
use crate::tools::nuclei::{NucleiTool, NUCLEI_IMAGE, NUCLEI_TEMPLATES_COMMIT, NUCLEI_VERSION};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub struct Orchestrator {
    pub config: Configuration,
    pub agent: AIAgent,
    pub execution_history: Vec<SecurityTool>,
    pub decision_history: Vec<DecisionRecord>,
    pub findings: Vec<Vulnerability>,
    pub paused: bool,
    pub cancelled: bool,
    pub last_log: String,
    started_at: String,
    latest_nmap_output: Option<String>,
}

impl Orchestrator {
    pub fn new(mut config: Configuration) -> Self {
        config.provider_mode = format!("{:?}", config.llm.provider);
        let agent = AIAgent::from_config(&config.llm);
        Self {
            config,
            agent,
            execution_history: Vec::new(),
            decision_history: Vec::new(),
            findings: Vec::new(),
            paused: false,
            cancelled: false,
            last_log: String::new(),
            started_at: now_iso8601(),
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
        if tool_info.is_nmap() {
            return self.execute_nmap(tool_info, target).await;
        }
        if tool_info.is_nuclei() {
            return self.execute_nuclei_with_plan(tool_info, target).await;
        }
        let arguments = format!("{} {target}", tool_info.name);
        let mut exec = SecurityTool::new(tool_info.name, &arguments);
        exec.executed_at = now_iso8601();
        exec.status = "failed".to_string();
        let message = format!(
            "A ferramenta {} ainda não possui executor real e não será emulada",
            tool_info.name
        );
        exec.execution_error = Some(message.clone());
        exec.output = format!("[ERRO] {message}");

        self.execution_history.push(exec.clone());
        exec
    }

    async fn execute_nmap(&mut self, tool_info: &ToolInfo, target: &str) -> SecurityTool {
        let runner = NmapTool;
        let arguments = runner.configure_command(target);
        let mut exec = SecurityTool::new(tool_info.name, &arguments);
        exec.tool_version = Some(NMAP_VERSION.to_owned());
        exec.image = Some(NMAP_IMAGE.to_owned());
        exec.executed_at = now_iso8601();
        let executor = PodmanExecutor::new(Duration::from_secs(15 * 60));
        match executor
            .execute(NMAP_IMAGE, &NmapTool::container_arguments(target))
            .await
        {
            Ok(result) => {
                exec.status = execution_status(&result.status);
                exec.duration_ms = result.duration.as_millis();
                exec.stderr = sanitize(&result.stderr);
                exec.output = podman_output(result);
                self.latest_nmap_output = Some(exec.output.clone());
                if exec.output.starts_with("[ERRO]") {
                    exec.status = "failed".to_string();
                    exec.execution_error = Some(exec.output.clone());
                }
            }
            Err(error) => {
                exec.status = "failed".to_string();
                let message =
                    format!("Não foi possível iniciar a varredura real do Nmap: {error:#}");
                exec.output = format!("[ERRO] {message}");
                self.latest_nmap_output = Some(exec.output.clone());
                exec.execution_error = Some(message);
            }
        }
        self.execution_history.push(exec.clone());
        exec
    }

    async fn execute_nuclei_with_plan(
        &mut self,
        tool_info: &ToolInfo,
        target: &str,
    ) -> SecurityTool {
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
        exec.image = Some(NUCLEI_IMAGE.to_string());
        exec.tool_version = Some(NUCLEI_VERSION.to_string());
        exec.executed_at = now_iso8601();
        if !decision.plan.should_run {
            exec.status = "skipped".to_string();
            exec.output = format!("Nuclei ignorado pela política: {}", decision.justification);
            self.execution_history.push(exec.clone());
            return exec;
        }
        let templates = self.nuclei_templates_path();
        if let Err(error) = validate_templates(
            &templates,
            self.config
                .nuclei_templates_commit
                .as_deref()
                .or(Some(NUCLEI_TEMPLATES_COMMIT)),
        ) {
            exec.status = "failed".to_string();
            exec.execution_error = Some(error.to_string());
            exec.output = format!("[ERRO] {}", error);
            self.execution_history.push(exec.clone());
            return exec;
        }
        let executor = PodmanExecutor::new(Duration::from_secs(15 * 60));
        exec.output = match executor
            .execute_with_mounts(
                NUCLEI_IMAGE,
                &NucleiTool::container_arguments_with_plan(target, &decision.plan),
                &[(templates, "/root/nuclei-templates".to_string())],
            )
            .await
        {
            Ok(result) => {
                exec.status = execution_status(&result.status);
                exec.duration_ms = result.duration.as_millis();
                exec.stderr = sanitize(&result.stderr);
                let output = podman_output(result);
                if exec.status != "succeeded" {
                    exec.execution_error = Some(output.clone());
                }
                output
            }
            Err(error) => {
                exec.status = "failed".to_string();
                exec.execution_error = Some(format!(
                    "Não foi possível iniciar a varredura real do Nuclei: {error:#}"
                ));
                format!(
                    "[ERRO] {}",
                    exec.execution_error.as_deref().unwrap_or_default()
                )
            }
        };
        self.execution_history.push(exec.clone());
        exec
    }

    async fn request_nuclei_plan(&mut self, target: &str) -> Option<String> {
        let prompt = format!(
            "Analyze this Nmap XML and return only JSON with fields should_run, profiles, concurrency, timeout_seconds, justification. Allowed profiles are http-misconfiguration, http-exposed-panels, ssh-exposure, database-exposure, generic. Never invent command flags or shell commands. Target: {target}\n\nNmap log:\n{}",
            self.latest_nmap_output.as_deref().unwrap_or_default()
        );
        self.agent.execute_with_fallback(&prompt).await.ok()
    }

    /// Constrói os achados reais a partir da execução dos scanners.
    ///
    /// Nunca inclui achados simulados.
    pub fn build_findings(&mut self) {
        let target = self.config.target_url.clone();
        let mut real_findings: Vec<Vulnerability> = Vec::new();
        for exec in &mut self.execution_history {
            if exec.tool_name == "Nuclei" && !exec.output.is_empty() {
                let (parsed, errors) =
                    crate::orchestrator::nuclei_parser::parse_nuclei_findings_with_errors(
                        &exec.output,
                        &target,
                    );
                real_findings.extend(parsed);
                if !errors.is_empty() {
                    // A malformed JSONL record is an execution diagnostic, not a clean scan.
                    let message = errors.join("; ");
                    exec.execution_error = Some(message);
                }
            }
            if exec.tool_name == "Nmap" && !exec.output.is_empty() {
                let parsed =
                    crate::orchestrator::nmap_parser::parse_nmap_findings(&exec.output, &target);
                real_findings.extend(parsed);
            }
        }
        self.findings = real_findings;
    }

    fn nuclei_templates_path(&self) -> PathBuf {
        self.config
            .nuclei_templates_path
            .as_deref()
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                dirs::home_dir()
                    .unwrap_or_default()
                    .join("nuclei-templates")
            })
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

    pub fn persist_scan_log(&self) -> anyhow::Result<std::path::PathBuf> {
        let scan_id = format!(
            "scan_{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );
        let tools_executed = self
            .execution_history
            .iter()
            .map(
                |execution| crate::orchestrator::scan_logger::ToolExecutionRecord {
                    tool_name: execution.tool_name.clone(),
                    arguments: sanitize(&execution.arguments)
                        .split_whitespace()
                        .map(str::to_owned)
                        .collect(),
                    executed_at: execution.executed_at.clone(),
                    output_bytes: execution.output.len(),
                    output_sample: sanitize(&execution.output).chars().take(200).collect(),
                    stdout: sanitize(&execution.output),
                    stderr: sanitize(&execution.stderr),
                    status: execution.status.clone(),
                    duration_ms: execution.duration_ms,
                    tool_version: execution.tool_version.clone(),
                    image: execution.image.clone(),
                    execution_error: execution.execution_error.as_deref().map(sanitize),
                },
            )
            .collect();
        let metadata = crate::orchestrator::scan_logger::ScanMetadata::new(
            scan_id,
            self.config.target_url.clone(),
            self.started_at.clone(),
            now_iso8601(),
            self.config.execution_type.to_string(),
            self.config.provider_mode.clone(),
            tools_executed,
            self.findings.clone(),
            self.last_log.clone(),
        );
        let metadata = crate::orchestrator::scan_logger::ScanMetadata {
            decisions: self.decision_history.clone(),
            ..metadata
        };
        crate::orchestrator::scan_logger::save_scan_log(&metadata)
    }
}

fn now_iso8601() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn podman_output(result: ExecutionResult) -> String {
    let cleanup_error = result
        .cleanup_error
        .map(|error| format!(" Falha na limpeza: {error}"))
        .unwrap_or_default();
    match result.status {
        ExecutionStatus::Succeeded if cleanup_error.is_empty() => result.stdout,
        ExecutionStatus::Succeeded => format!(
            "[ERRO] Varredura concluída, mas o container {} não foi removido.{}",
            result.container_id, cleanup_error
        ),
        ExecutionStatus::Failed(code) => format!(
            "[ERRO] O container {} encerrou com status {}: {}{}",
            result.container_id,
            code.map_or_else(|| "desconhecido".to_owned(), |code| code.to_string()),
            result.stderr.trim(),
            cleanup_error
        ),
        ExecutionStatus::TimedOut => format!(
            "[ERRO] O container {} excedeu o tempo limite de 15 minutos.{}",
            result.container_id, cleanup_error
        ),
    }
}

fn execution_status(status: &ExecutionStatus) -> String {
    match status {
        ExecutionStatus::Succeeded => "succeeded".to_string(),
        ExecutionStatus::Failed(code) => format!(
            "failed:{}",
            code.map_or_else(|| "unknown".to_string(), |c| c.to_string())
        ),
        ExecutionStatus::TimedOut => "timeout".to_string(),
    }
}

/// Remove credenciais e tokens antes de persistir ou encaminhar qualquer saída.
fn sanitize(value: &str) -> String {
    let patterns = [
        "api_key",
        "apikey",
        "token",
        "authorization",
        "password",
        "secret",
    ];
    value
        .lines()
        .map(|line| {
            let lower = line.to_ascii_lowercase();
            if patterns.iter().any(|pattern| lower.contains(pattern)) {
                "[REDACTED]"
            } else if let Some(query_start) = line.find('?') {
                // Query strings commonly carry API keys even when no key name is obvious.
                &line[..query_start + 1]
            } else {
                line
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn validate_templates(path: &std::path::Path, expected: Option<&str>) -> anyhow::Result<()> {
    if !path.is_dir() {
        anyhow::bail!(
            "Templates do Nuclei não encontrados em '{}'; configure nuclei_templates_path",
            path.display()
        );
    }
    if let Some(expected) = expected {
        let output = std::process::Command::new("git")
            .args(["-C", &path.to_string_lossy(), "rev-parse", "HEAD"])
            .output()
            .map_err(|error| {
                anyhow::anyhow!("não foi possível validar o commit dos templates: {error}")
            })?;
        let actual = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !output.status.success() || actual != expected {
            anyhow::bail!("commit dos templates do Nuclei divergente: esperado {expected}, encontrado {actual}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Configuration;

    fn make_config() -> Configuration {
        let mut c = Configuration::default();
        c.target_url = "http://test.local".to_string();
        c
    }

    #[test]
    fn real_run_empty_history_produces_no_findings() {
        let mut orch = Orchestrator::new(make_config());
        orch.build_findings();
        assert!(
            orch.findings.is_empty(),
            "Sem execuções, não deve haver achados"
        );
    }
}
