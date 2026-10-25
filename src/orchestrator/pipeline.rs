use crate::ai::agent::AIAgent;
use crate::ai::analysis_service::AnalysisResult;
use crate::ai::analysis_service::AnalysisService;
use crate::code_agent::agent::{CodeAnalysisReport, CodeAnalysisService};
use crate::config::Configuration;
use crate::domain::security_tool::{SecurityTool, SecurityToolRunner};
use crate::domain::vulnerability::Vulnerability;
use crate::orchestrator::control::{ControlChannel, InterruptionReason, RunControl};
use crate::orchestrator::decision::{decide_nuclei_plan, DecisionRecord};
use crate::orchestrator::enrichment::{correlate_and_enrich, EnrichmentSummary};
use crate::orchestrator::nvd::NvdClient;
use crate::orchestrator::sandbox::{self, ExecutionResult, ExecutionStatus, PodmanExecutor};
use crate::orchestrator::scan_logger::{
    AiCheckpoint, CheckpointHandle, CodeAnalysisCheckpoint, CodeCheckpoint, ScanRuntime,
    ToolCheckpoint, MAX_CHECKPOINT_OUTPUT_BYTES, PHASE_ANALYSIS, PHASE_CANCELLED, PHASE_CODE,
    PHASE_COMPLETED, PHASE_RAG, PHASE_TOOLS, TOOL_STATUS_RUNNING,
};
use crate::orchestrator::tmpfs;
use crate::tools::nmap::NmapTool;
use crate::tools::nuclei::{NucleiTool, NUCLEI_TEMPLATES_COMMIT};
use crate::tools::registry::{ParserKind, RegisteredTool, RunnerKind, ToolRegistry};
use crate::tools::ToolManifest;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;

pub struct Orchestrator {
    pub config: Configuration,
    pub agent: AIAgent,
    /// Catálogo validado de ferramentas: resolve runner e parser pelo manifesto,
    /// sem comparar nomes de ferramentas com strings mágicas.
    pub registry: ToolRegistry,
    pub execution_history: Vec<SecurityTool>,
    pub decision_history: Vec<DecisionRecord>,
    pub findings: Vec<Vulnerability>,
    pub code_audit: Option<crate::code_audit::CodeAuditReport>,
    /// Canal de pausa, retomada e cancelamento compartilhado com o executor
    /// Podman e com a interface (REQ14); bandeiras locais de pausa/cancelamento
    /// não chegariam ao processo em execução dentro do container.
    ///
    /// O motivo da interrupção mora no canal, e não no orquestrador: a TUI e a
    /// task de execução são `Orchestrator` distintos ligados só por ele, e o
    /// log estruturado precisa ver o motivo independente de quem grava.
    pub control: ControlChannel,
    pub last_log: String,
    /// Sink opcional que recebe ao vivo cada linha do trace operacional do
    /// Podman (TUI e headless). Quando ausente, o trace segue acumulado em
    /// cada `SecurityTool` para auditoria.
    pub trace_sink: Option<mpsc::UnboundedSender<String>>,
    /// Notifica a interface assim que o plano do Nuclei é validado.
    pub decision_sink: Option<mpsc::UnboundedSender<DecisionRecord>>,
    /// Resumo da correlação e do enriquecimento CVE/NVD (issue #19).
    pub enrichment: EnrichmentSummary,
    started_at: String,
    latest_nmap_output: Option<String>,
    /// Resultado estruturado da última análise da IA, com modelo, provedor
    /// efetivo, fallback, motivo da falha e horário.
    pub last_analysis_result: Option<AnalysisResult>,
    /// Identificador desta execução, compartilhado pela trilha da IA e pelo log.
    pub scan_id: String,
    /// Trilha append-only das ações da IA, gravada durante a fase.
    agent_trail: std::sync::Arc<crate::code_agent::audit_trail::AgentAuditTrail>,
    /// Serviço único de análise, compartilhado pela TUI e pelo modo headless.
    analysis_service: AnalysisService,
    /// Relatório da fase do agente de código, com a localização de cada achado
    /// e o registro auditável de cada chamada de ferramenta.
    pub last_code_report: Option<CodeAnalysisReport>,
    /// Explicações RAG geradas no detalhe do achado (issue #109); o log
    /// estruturado guarda o veredito da mais recente e a contagem.
    pub rag_explanations: Vec<crate::cyberrag::service::ExplanationResult>,
    /// Estado incremental compartilhado com os hooks de streaming e de código.
    runtime: std::sync::Arc<std::sync::Mutex<ScanRuntime>>,
    /// Serializa as gravações do checkpoint, para um flush de streaming não
    /// intercalar com a gravação completa do orquestrador.
    checkpoint_write_lock: std::sync::Arc<std::sync::Mutex<()>>,
    /// Diretório do log; `None` usa [`crate::orchestrator::scan_logger::scans_dir`].
    checkpoint_dir: Option<PathBuf>,
}

impl Orchestrator {
    /// Cria o orquestrador validando a configuração `[[tools]]`; uma
    /// configuração inválida interrompe o fluxo com a mensagem acionável.
    pub fn new(config: Configuration) -> anyhow::Result<Self> {
        let registry = ToolRegistry::with_configured(&config.tools)?;
        Ok(Self::with_registry(config, registry))
    }

    /// Cria o orquestrador com um registry já validado (evita revalidar a
    /// configuração na TUI).
    pub fn with_registry(mut config: Configuration, registry: ToolRegistry) -> Self {
        config.provider_mode = config.llm.provider.label().to_string();
        let agent = AIAgent::from_config(&config.llm);
        let scan_id = Self::novo_scan_id();
        let agent_trail = agent_trail_for(&scan_id);
        Self {
            scan_id,
            agent_trail,
            config,
            agent,
            registry,
            execution_history: Vec::new(),
            decision_history: Vec::new(),
            findings: Vec::new(),
            control: ControlChannel::new(),
            last_log: String::new(),
            trace_sink: None,
            decision_sink: None,
            enrichment: EnrichmentSummary::default(),
            started_at: now_iso8601(),
            latest_nmap_output: None,
            last_analysis_result: None,
            analysis_service: AnalysisService::new(),
            code_audit: None,
            last_code_report: None,
            rag_explanations: Vec::new(),
            runtime: std::sync::Arc::new(std::sync::Mutex::new(ScanRuntime::default())),
            checkpoint_write_lock: std::sync::Arc::new(std::sync::Mutex::new(())),
            checkpoint_dir: None,
        }
    }

    /// Redireciona os checkpoints para um diretório específico.
    ///
    /// O fluxo real usa o diretório padrão de scans; a opção existe para que os
    /// testes não escrevam no diretório de configuração do usuário.
    #[allow(dead_code)]
    pub fn with_checkpoint_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.checkpoint_dir = Some(dir.into());
        self
    }

    /// Reutiliza o `scan_id` de outra instância do orquestrador.
    ///
    /// A TUI cria um orquestrador para a tela e outro para a task; sem herdar o
    /// identificador, cada um gravaria uma trilha de IA e um checkpoint com o
    /// mesmo scan em arquivos diferentes.
    pub fn adopt_scan_id(mut self, scan_id: impl Into<String>) -> Self {
        self.scan_id = scan_id.into();
        self.agent_trail = agent_trail_for(&self.scan_id);
        self
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
        if self.control.is_cancelled() {
            "cancelled"
        } else if self.control.is_paused() {
            "paused"
        } else if self.findings.is_empty() {
            "idle"
        } else {
            "complete"
        }
    }

    /// Solicita o cancelamento cooperativo da execução: a ordem chega ao
    /// container pelo canal compartilhado, ele é encerrado com `podman stop` e
    /// removido com `podman rm --force`, sem depender de `abort()` da task.
    pub fn cancel_execution(&mut self) {
        self.request_cancel();
        // A auditoria do que já existe é gravada antes de a task de execução
        // encerrar; um processo morto depois disto preserva este checkpoint.
        let _ = self.persist_checkpoint_with_reason("cancelado");
    }

    /// Cancela pelo canal **sem** gravar o checkpoint.
    ///
    /// A TUI usa esta forma quando a task do scan está viva: quem possui o
    /// estado real é a task, e ela grava o parcial ao encerrar o laço. Gravar
    /// daqui com o estado da tela apagaria achados já persistidos.
    pub fn request_cancel(&mut self) {
        if self.control.is_cancelled() {
            return;
        }
        self.record_interruption(InterruptionReason::user_cancelled());
        self.control.cancel();
        self.set_runtime_phase(PHASE_CANCELLED);
    }

    /// Solicita a pausa da ferramenta em execução (`podman pause`).
    pub fn pause_execution(&mut self) {
        if self.control.is_cancelled() {
            return;
        }
        self.control.pause();
    }

    /// Retoma a ferramenta pausada (`podman unpause`).
    pub fn resume_execution(&mut self) {
        if self.control.is_cancelled() {
            return;
        }
        self.control.resume();
    }

    /// Grava o motivo da interrupção uma única vez, preservando o primeiro.
    ///
    /// A auditoria precisa de um motivo, não de uma sequência: o primeiro
    /// evento é o que explica por que a varredura parou.
    pub fn record_interruption(&self, reason: InterruptionReason) {
        self.control.record_interruption(reason);
    }

    /// Motivo registrado da interrupção (REQ05 ou REQ14), se houver.
    pub fn interruption(&self) -> Option<InterruptionReason> {
        self.control.interruption()
    }

    /// Indica se a execução foi interrompida por cancelamento ou por sinal.
    pub fn is_cancelled(&self) -> bool {
        self.control.is_cancelled()
    }

    /// Diretório em que o log estruturado desta execução é gravado.
    pub fn scan_log_dir(&self) -> PathBuf {
        self.checkpoint_dir
            .clone()
            .unwrap_or_else(crate::orchestrator::scan_logger::scans_dir)
    }

    /// Grava o estado parcial desta execução no arquivo do scan atual.
    ///
    /// Pode ser chamado a qualquer momento pela TUI (por exemplo, ao solicitar
    /// cancelamento): não exige que o scan tenha terminado e não apaga o que já
    /// está no arquivo. O arquivo é criado desde o primeiro checkpoint, com
    /// permissão 0600.
    #[allow(dead_code)]
    pub fn persist_checkpoint(&self) -> anyhow::Result<PathBuf> {
        self.persist_checkpoint_with_reason(self.checkpoint_reason())
    }

    /// Variante que registra um motivo explícito (`em execução`, `cancelado`).
    pub fn persist_checkpoint_with_reason(&self, reason: &str) -> anyhow::Result<PathBuf> {
        let _guard = self
            .checkpoint_write_lock
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let metadata = self.checkpoint_metadata(reason);
        self.save_metadata(&metadata)
    }

    fn save_metadata(
        &self,
        metadata: &crate::orchestrator::scan_logger::ScanMetadata,
    ) -> anyhow::Result<PathBuf> {
        match &self.checkpoint_dir {
            Some(dir) => crate::orchestrator::scan_logger::save_scan_log_to_dir(metadata, dir),
            None => crate::orchestrator::scan_logger::save_scan_log(metadata),
        }
    }

    fn checkpoint_reason(&self) -> &'static str {
        if self.control.is_cancelled() {
            "cancelado"
        } else {
            "em execução"
        }
    }

    fn checkpoint_metadata(&self, reason: &str) -> crate::orchestrator::scan_logger::ScanMetadata {
        let timestamp = now_iso8601();
        {
            let mut runtime = self
                .runtime
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            if self.control.is_cancelled() {
                runtime.phase = PHASE_CANCELLED.to_string();
            }
            runtime.last_checkpoint_at = timestamp;
            runtime.checkpoint_reason = reason.to_string();
        }
        let mut metadata = self.base_scan_metadata();
        // Um checkpoint não é um scan concluído: deixar `completed_at` vazio
        // impede que o histórico apresente uma execução em andamento como
        // limpa. A gravação final preenche o horário.
        metadata.completed_at.clear();
        metadata
    }

    fn runtime_snapshot(&self) -> ScanRuntime {
        self.runtime
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone()
    }

    fn set_runtime_phase(&mut self, phase: &str) {
        self.runtime
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .phase = phase.to_string();
    }

    fn checkpoint_handle(&self) -> Option<CheckpointHandle> {
        let path = crate::orchestrator::scan_logger::scan_log_path_in_dir(
            &self.scan_id,
            &self.scan_log_dir(),
        )
        .ok()?;
        Some(CheckpointHandle::new(
            path,
            std::sync::Arc::clone(&self.runtime),
            std::sync::Arc::clone(&self.checkpoint_write_lock),
        ))
    }

    fn begin_tool_checkpoint(&mut self, manifest: &ToolManifest, target: &str) {
        let mut runtime = self
            .runtime
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        runtime.phase = PHASE_TOOLS.to_string();
        runtime.current_tool = Some(ToolCheckpoint {
            tool_name: manifest.name.clone(),
            arguments: vec![manifest.name.clone(), target.to_string()],
            started_at: now_iso8601(),
            status: TOOL_STATUS_RUNNING.to_string(),
            output_bytes: 0,
            output_partial: String::new(),
            finished_at: String::new(),
        });
        drop(runtime);
        let _ = self.persist_checkpoint_with_reason(self.checkpoint_reason());
    }

    fn finish_tool_checkpoint(&mut self, execution: &SecurityTool) {
        {
            let mut runtime = self
                .runtime
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            if let Some(tool) = runtime.current_tool.as_mut() {
                tool.status = execution.status.clone();
                tool.output_bytes = execution.output.len();
                tool.finished_at = now_iso8601();
                let final_output = capped_checkpoint_text(&execution.output);
                if tool.output_partial.is_empty() || execution.status == "succeeded" {
                    tool.output_partial = final_output;
                } else {
                    // Falha, timeout e cancelamento preservam o log que já tinha
                    // sido transmitido, além da mensagem final do executor.
                    append_checkpoint_output(&mut tool.output_partial, &final_output);
                }
            }
            if self.control.is_cancelled() {
                runtime.phase = PHASE_CANCELLED.to_string();
            }
        }
        let _ = self.persist_checkpoint_with_reason(self.checkpoint_reason());
    }

    fn begin_ai_checkpoint(&mut self, summary: &str) {
        {
            let mut runtime = self
                .runtime
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            runtime.ai_in_progress = Some(AiCheckpoint {
                started_at: now_iso8601(),
                provider: self.config.provider_mode.clone(),
                model: self.agent.model.clone(),
                prompt_summary: summarize_checkpoint_prompt(summary),
                findings_count: self.findings.len(),
            });
        }
        let _ = self.persist_checkpoint_with_reason(self.checkpoint_reason());
    }

    fn finish_ai_checkpoint(&mut self) {
        {
            let mut runtime = self
                .runtime
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            runtime.ai_in_progress = None;
            if self.control.is_cancelled() {
                runtime.phase = PHASE_CANCELLED.to_string();
            }
        }
        let _ = self.persist_checkpoint_with_reason(self.checkpoint_reason());
    }

    fn podman_executor(&self) -> PodmanExecutor {
        let executor =
            PodmanExecutor::new(Duration::from_secs(15 * 60)).with_control(&self.control);
        match &self.trace_sink {
            Some(sink) => executor.with_log_sink(sink.clone()),
            None => executor,
        }
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

    pub async fn execute_tool(&mut self, manifest: &ToolManifest, target: &str) -> SecurityTool {
        self.begin_tool_checkpoint(manifest, target);
        // O trace do Podman é a única saída disponível enquanto o container
        // roda. Ele é duplicado para o checkpoint a cada poucas linhas, sem
        // impedir que a TUI/headless continue recebendo o fluxo ao vivo.
        let original_sink = self.trace_sink.take();
        let (trace_tx, mut trace_rx) = mpsc::unbounded_channel::<String>();
        let forward = original_sink.clone();
        let stream_checkpoint = self.checkpoint_handle();
        let stream_task = tokio::spawn(async move {
            let mut pending = 0usize;
            loop {
                match tokio::time::timeout(Duration::from_secs(2), trace_rx.recv()).await {
                    Ok(Some(line)) => {
                        if let Some(checkpoint) = &stream_checkpoint {
                            checkpoint.append_tool_log(&line);
                        }
                        if let Some(sink) = &forward {
                            let _ = sink.send(line);
                        }
                        pending += 1;
                        if pending >= 40 {
                            if let Some(checkpoint) = &stream_checkpoint {
                                let _ = checkpoint.flush();
                            }
                            pending = 0;
                        }
                    }
                    Ok(None) => break,
                    // Ferramenta silenciosa: ainda assim o parcial é gravado,
                    // para o último checkpoint não ficar parado no início.
                    Err(_) if pending > 0 => {
                        if let Some(checkpoint) = &stream_checkpoint {
                            let _ = checkpoint.flush();
                        }
                        pending = 0;
                    }
                    Err(_) => {}
                }
            }
            if let Some(checkpoint) = &stream_checkpoint {
                let _ = checkpoint.flush();
            }
        });
        self.trace_sink = Some(trace_tx);
        let execution = self.execute_tool_inner(manifest, target).await;
        self.trace_sink = original_sink;
        let _ = stream_task.await;
        self.finish_tool_checkpoint(&execution);
        execution
    }

    async fn execute_tool_inner(&mut self, manifest: &ToolManifest, target: &str) -> SecurityTool {
        let registered = match self.registry.find(&manifest.name) {
            Some(registered) => registered.clone(),
            None => {
                let arguments = format!("{} {target}", manifest.name);
                let mut exec = SecurityTool::new(&manifest.name, &arguments);
                exec.executed_at = now_iso8601();
                exec.status = "failed".to_string();
                let message = format!(
                    "a ferramenta '{}' não está registrada no catálogo; revise a configuração [[tools]]",
                    manifest.name
                );
                exec.execution_error = Some(message.clone());
                exec.output = format!("[ERRO] {message}");
                self.execution_history.push(exec.clone());
                return exec;
            }
        };
        match registered.runner {
            RunnerKind::Nmap => self.execute_nmap(&registered, target).await,
            RunnerKind::Nuclei => self.execute_nuclei_with_plan(&registered, target).await,
            RunnerKind::Generic => self.execute_generic(&registered, target).await,
            RunnerKind::Repository => self.execute_repository(&registered, target).await,
            RunnerKind::Zap => self.execute_zap(&registered, target).await,
        }
    }

    /// Executa o ZAP com um plano de automação montado em memória.
    ///
    /// O plano é gravado num diretório temporário do host e montado em somente
    /// leitura, como os templates do Nuclei. O job `report` do ZAP sempre
    /// acrescenta a extensão do template ao nome e não tem saída em stdout
    /// (verificado executando o container, `docs/evidence/issue-28-zap.md`),
    /// então o relatório é coletado do diretório de saída antes da remoção.
    async fn execute_zap(&mut self, tool: &RegisteredTool, target: &str) -> SecurityTool {
        let arguments = crate::tools::zap::container_arguments(target).join(" ");
        let mut exec = SecurityTool::new(&tool.manifest.name, &arguments);
        exec.tool_version = Some(tool.manifest.version.clone());
        exec.image = Some(tool.manifest.image.clone());
        exec.executed_at = now_iso8601();

        let plan = zap_plan_dir();
        // O plano de automação é a configuração temporária da execução: a regra
        // do TCC a restringe a tmpfs, então a condição é verificada e não
        // presumida a partir do TMPDIR do ambiente.
        if let Err(error) = tmpfs::ensure_tmpfs(&plan) {
            return self.fail_zap(&mut exec, error.to_string());
        }
        if let Err(error) = std::fs::create_dir(&plan) {
            return self.fail_zap(
                &mut exec,
                format!(
                    "Não foi possível criar o diretório temporário do plano de automação do ZAP em {}: {error}",
                    plan.display()
                ),
            );
        }
        let _plan_dir = PlanDirectory(plan.clone());
        let plan_file = plan.join("scan.yaml");
        if let Err(error) = std::fs::write(&plan_file, crate::tools::zap::automation_plan(target)) {
            return self.fail_zap(
                &mut exec,
                format!(
                    "Não foi possível gravar o plano de automação do ZAP em {}: {error}",
                    plan_file.display()
                ),
            );
        }

        let output = match sandbox::WritableOutput::new(
            crate::tools::zap::ZAP_OUTPUT_DIR,
            crate::tools::zap::ZAP_REPORT_FILE,
        ) {
            Ok(output) => output
                .with_memory(crate::tools::zap::ZAP_MEMORY_LIMIT)
                .with_tmpfs(crate::tools::zap::ZAP_HOME_TMPFS),
            Err(error) => {
                // A mensagem do erro já é acionável e nomeia a regra violada.
                return self.fail_zap(&mut exec, error.to_string());
            }
        };

        let executor = self.podman_executor();
        let result = executor
            .execute_with_artifact(
                &tool.manifest.image,
                &crate::tools::zap::container_arguments(target),
                &[(plan, crate::tools::zap::ZAP_AUTOMATION_DIR.to_string())],
                &output,
            )
            .await;

        match result {
            Ok(result) => {
                exec.podman_trace = result.trace.clone();
                exec.status = execution_status(&result.status);
                exec.duration_ms = result.duration.as_millis();
                exec.stderr = sanitize(&result.stderr);
                let succeeded =
                    result.status == ExecutionStatus::Succeeded && result.cleanup_error.is_none();
                // O relatório coletado é a saída estruturada da ferramenta; o
                // plano de automação e o trace ficam no log operacional.
                let diagnostic = podman_output(result.clone());
                if succeeded {
                    match result.artifact {
                        Some(report) => exec.output = report,
                        None => {
                            // Artefato ausente não é varredura limpa.
                            let message = result.artifact_error.unwrap_or_else(|| {
                                "o ZAP não produziu relatório JSON; a execução precisa ser revisada"
                                    .to_string()
                            });
                            exec.status = "failed".to_string();
                            exec.execution_error = Some(message);
                            exec.output = diagnostic;
                        }
                    }
                } else {
                    exec.execution_error = Some(diagnostic.clone());
                    exec.output = diagnostic;
                }
            }
            Err(error) => {
                let message = format!(
                    "Não foi possível iniciar a varredura real de {}: {error:#}",
                    tool.manifest.name
                );
                exec.status = "failed".to_string();
                exec.execution_error = Some(message.clone());
                exec.output = format!("[ERRO] {message}");
            }
        }
        self.execution_history.push(exec.clone());
        exec
    }

    /// Registra uma falha de preparação do ZAP sem chamar o Podman.
    fn fail_zap(&mut self, exec: &mut SecurityTool, message: String) -> SecurityTool {
        exec.status = "failed".to_string();
        exec.execution_error = Some(message.clone());
        exec.output = format!("[ERRO] {message}");
        self.execution_history.push(exec.clone());
        exec.clone()
    }

    /// Executa o `command_template` do manifesto no executor Podman rootless.
    async fn execute_generic(&mut self, tool: &RegisteredTool, target: &str) -> SecurityTool {
        let arguments = tool.manifest.render_command(target).join(" ");
        let mut exec = SecurityTool::new(&tool.manifest.name, &arguments);
        exec.tool_version = Some(tool.manifest.version.clone());
        exec.image = Some(tool.manifest.image.clone());
        exec.executed_at = now_iso8601();
        let executor = self.podman_executor();
        match executor
            .execute(&tool.manifest.image, &tool.manifest.render_command(target))
            .await
        {
            Ok(result) => {
                exec.podman_trace = result.trace.clone();
                exec.status = execution_status(&result.status);
                exec.duration_ms = result.duration.as_millis();
                exec.stderr = sanitize(&result.stderr);
                exec.output = podman_output(result);
                if exec.output.starts_with("[ERRO]") {
                    exec.status = "failed".to_string();
                    exec.execution_error = Some(exec.output.clone());
                }
            }
            Err(error) => {
                exec.status = "failed".to_string();
                let message = format!(
                    "Não foi possível iniciar a varredura real de {}: {error:#}",
                    tool.manifest.name
                );
                exec.output = format!("[ERRO] {message}");
                exec.execution_error = Some(message);
            }
        }
        self.execution_history.push(exec.clone());
        exec
    }

    /// Executa um runner `repository`: o alvo é um repositório, não um host.
    ///
    /// O repositório local é canonicalizado e montado **somente leitura** em um
    /// ponto fixo do container; um alvo remoto autorizado vira URI, sem mount.
    /// Nenhum caminho do host atravessa o comando, e o repositório nunca é
    /// montado para escrita nem recebe o resultado da varredura.
    /// Usa `project_dir` quando o alvo é web e o scanner exige repositório.
    fn repository_target_for(&self, target: &str) -> (String, Option<String>) {
        let trimmed = target.trim();
        if trimmed.starts_with('/') {
            return (trimmed.to_string(), None);
        }
        let looks_like_git_uri = trimmed.ends_with(".git")
            || trimmed.contains("github.com/")
            || trimmed.contains("gitlab.com/")
            || trimmed.contains("bitbucket.org/");
        if looks_like_git_uri {
            return (trimmed.to_string(), None);
        }
        let Some(project) = self.config.project_dir.as_deref() else {
            return (trimmed.to_string(), None);
        };
        let path = std::path::Path::new(project);
        if !path.is_dir() {
            return (trimmed.to_string(), None);
        }
        let absolute = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        (absolute.display().to_string(), Some(trimmed.to_string()))
    }

    async fn execute_repository(&mut self, tool: &RegisteredTool, target: &str) -> SecurityTool {
        let (repository_target, overridden_from) = self.repository_target_for(target);
        if let Some(original) = overridden_from.as_deref() {
            if let Some(sink) = &self.trace_sink {
                let _ = sink.send(format!(
                    "TruffleHog: alvo web {original}; usando o repositório local {repository_target}"
                ));
            }
        }
        let repository = match crate::tools::repository::resolve(&repository_target) {
            Ok(repository) => repository,
            Err(message) => {
                let mut exec = SecurityTool::new(&tool.manifest.name, &repository_target);
                exec.tool_version = Some(tool.manifest.version.clone());
                exec.image = Some(tool.manifest.image.clone());
                exec.executed_at = now_iso8601();
                exec.status = "failed".to_string();
                exec.output = format!("[ERRO] {message}");
                exec.execution_error = Some(message);
                self.execution_history.push(exec.clone());
                return exec;
            }
        };
        let container_path = repository.container_path().unwrap_or_default();
        let arguments =
            crate::tools::trufflehog::container_arguments(&repository.source_uri(), container_path);
        let mut exec = SecurityTool::new(&tool.manifest.name, &repository_target);
        exec.tool_version = Some(tool.manifest.version.clone());
        exec.image = Some(tool.manifest.image.clone());
        exec.executed_at = now_iso8601();
        let executor = self.podman_executor();
        let mounts = repository.mounts();
        match executor
            .execute_with_mounts(&tool.manifest.image, &arguments, &mounts)
            .await
        {
            Ok(result) => {
                exec.podman_trace = result.trace.clone();
                exec.status = execution_status(&result.status);
                exec.duration_ms = result.duration.as_millis();
                exec.stderr = sanitize(&result.stderr);
                let output = podman_output(result);
                if exec.status != "succeeded" {
                    let lower = output.to_lowercase();
                    if lower.contains("is this a git repository")
                        || lower.contains("git clone failed")
                    {
                        let message = format!(
                            "TruffleHog analisa repositórios Git, não aplicações web. O alvo \
                             \"{repository_target}\" não é um repositório Git. Configure \
                             project_dir no TOML/TUI ou informe o caminho absoluto do repositório."
                        );
                        exec.execution_error = Some(message.clone());
                        exec.output = format!("[ERRO] {message}");
                    } else {
                        exec.execution_error = Some(output.clone());
                        exec.output = output;
                    }
                } else {
                    exec.output = output;
                }
            }
            Err(error) => {
                exec.status = "failed".to_string();
                exec.execution_error = Some(format!(
                    "Não foi possível iniciar a varredura real de {}: {error:#}",
                    tool.manifest.name
                ));
                exec.output = format!(
                    "[ERRO] {}",
                    exec.execution_error.as_deref().unwrap_or_default()
                );
            }
        }
        self.execution_history.push(exec.clone());
        exec
    }

    async fn execute_nmap(&mut self, tool: &RegisteredTool, target: &str) -> SecurityTool {
        let runner = NmapTool;
        let arguments = runner.configure_command(target);
        let mut exec = SecurityTool::new(&tool.manifest.name, &arguments);
        exec.tool_version = Some(tool.manifest.version.clone());
        exec.image = Some(tool.manifest.image.clone());
        exec.executed_at = now_iso8601();
        let executor = self.podman_executor();
        match executor
            .execute(&tool.manifest.image, &NmapTool::container_arguments(target))
            .await
        {
            Ok(result) => {
                exec.podman_trace = result.trace.clone();
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
                let message = format!(
                    "Não foi possível iniciar a varredura real de {}: {error:#}",
                    tool.manifest.name
                );
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
        tool: &RegisteredTool,
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
        if let Some(sink) = &self.decision_sink {
            let _ = sink.send(decision.clone());
        }
        let runner = NucleiTool;
        let arguments = runner.configure_command_with_plan(target, &decision.plan);
        let mut exec = SecurityTool::new(&tool.manifest.name, &arguments);
        exec.image = Some(tool.manifest.image.clone());
        exec.tool_version = Some(tool.manifest.version.clone());
        exec.executed_at = now_iso8601();
        if !decision.plan.should_run {
            exec.status = "skipped".to_string();
            exec.output = format!(
                "{} ignorado pela política: {}",
                tool.manifest.name, decision.justification
            );
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
        let executor = self.podman_executor();
        exec.output = match executor
            .execute_with_mounts(
                &tool.manifest.image,
                &NucleiTool::container_arguments_with_plan(target, &decision.plan),
                &[(templates, "/root/nuclei-templates".to_string())],
            )
            .await
        {
            Ok(result) => {
                exec.podman_trace = result.trace.clone();
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
                    "Não foi possível iniciar a varredura real de {}: {error:#}",
                    tool.manifest.name
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

    /// Interpreta os achados com o serviço único de análise da IA.
    ///
    /// Único caminho para a IA interpretar logs, usado pela TUI e pelo modo
    /// headless (issue #23): concentrar a chamada garante que consentimento,
    /// teto de 45 s (RNF04), validação da resposta e fallback sejam os mesmos
    /// nos dois modos. O serviço é campo do orquestrador, e não instância por
    /// chamada, para os dois receberem a mesma configuração de prazo.
    pub async fn analyze_findings(&mut self) -> AnalysisResult {
        self.set_runtime_phase(PHASE_ANALYSIS);
        {
            let mut runtime = self
                .runtime
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            runtime.current_tool = None;
        }
        let summary = checkpoint_prompt_summary(&self.findings);
        self.begin_ai_checkpoint(&summary);
        self.agent_trail.record_analysis_started(
            &self.config.provider_mode,
            &self.agent.model,
            self.findings.len(),
        );
        let result = self
            .analysis_service
            .analyze(&mut self.agent, &self.findings)
            .await;
        self.finish_ai_checkpoint();
        self.agent_trail.record_analysis_finished(&result);
        self.last_log = result.text.clone();
        self.last_analysis_result = Some(result.clone());
        let _ = self.persist_checkpoint_with_reason(self.checkpoint_reason());
        result
    }

    /// Executa a fase do agente de código, depois dos scanners.
    ///
    /// A fase é **best effort** por desenho: não pode impedir o relatório de ser
    /// gravado. Se o projeto não puder ser aberto, ou se o provedor não suportar
    /// tool calling, cada achado recebe "localização não determinada" com o
    /// motivo registrado, e o pipeline segue para o relatório.
    ///
    /// `run_command` **não** recebe allowlist aqui: o modo é somente leitura por
    /// padrão, e execução de comandos exigiria um opt-in que não existe no
    /// contrato da configuração atual; a ferramenta fica registrada e é recusada
    /// com mensagem acionável.
    pub fn audit_code(&mut self) -> crate::code_audit::CodeAuditReport {
        let report = crate::code_audit::audit_project(
            &self.config.effective_project_dir(),
            crate::code_audit::MAX_FILES,
            crate::code_audit::MAX_FILE_BYTES,
        );

        self.findings.extend(
            report
                .findings
                .iter()
                .map(crate::code_audit::to_vulnerability),
        );
        self.code_audit = Some(report);
        self.code_audit.clone().unwrap_or_default()
    }

    pub async fn analyze_code(
        &mut self,
        progress: Option<&crate::code_agent::progress::EventSender>,
    ) -> CodeAnalysisReport {
        self.set_runtime_phase(PHASE_CODE);
        {
            let mut runtime = self
                .runtime
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            runtime.partial_code_analyses.clear();
            runtime.code_in_progress = None;
            runtime.current_tool = None;
            runtime.ai_in_progress = None;
        }
        let _ = self.persist_checkpoint_with_reason(self.checkpoint_reason());
        let project_dir = self.config.effective_project_dir();
        let report = match CodeAnalysisService::open(
            &project_dir,
            crate::code_agent::CodeAgentLimits::default(),
            Vec::new(),
        ) {
            Ok(service) => {
                let model = self.agent.model.clone();
                let label = self.agent.configured_provider_label();
                // RNF10 é consultado **antes** do primeiro turno: o consentimento
                // da issue #23 para enviar logs precisa cobrir os trechos do
                // código do alvo, o ativo mais sensível; sem a checagem, um
                // provedor remoto sem consentimento receberia o código-fonte.
                if let Some(reason) = self.agent.target_data_block_reason() {
                    self.agent_trail.record_event(
                        &crate::code_agent::progress::CodeAgentEvent::Finished {
                            located: 0,
                            total: self.findings.len(),
                            unavailable_reason: Some(reason.clone()),
                        },
                    );
                    CodeAnalysisReport::blocked(&self.findings, &model, &label, &reason)
                } else {
                    let (tx, mut rx) = mpsc::unbounded_channel();
                    let trail = std::sync::Arc::clone(&self.agent_trail);
                    // Quem lê o canal grava em disco e repassa para a TUI, para
                    // que o headless também registre a fase.
                    let repasse = progress.cloned();
                    let auditor = tokio::spawn(async move {
                        while let Some(event) = rx.recv().await {
                            trail.record_event(&event);
                            if let Some(tui) = &repasse {
                                let _ = tui.send(event);
                            }
                        }
                    });
                    // O relatório final chega tarde demais para a auditoria de
                    // um scan interrompido: cada achado é gravado assim que
                    // termina, no mesmo runtime do checkpoint.
                    let titles = self
                        .findings
                        .iter()
                        .map(|finding| finding.title.clone())
                        .collect::<Vec<_>>();
                    let runtime = std::sync::Arc::clone(&self.runtime);
                    let control = self.control.clone();
                    // O laço do agente precisa enxergar o mesmo canal que o
                    // hook usa: o botão Cancelar chega ao turno do provedor e à
                    // chamada de ferramenta, não só ao container.
                    let agent_control = self.control.clone();
                    let checkpoint = self.checkpoint_handle();
                    let hook = move |event: crate::code_agent::agent::AnalysisEvent<'_>| {
                        {
                            let mut runtime =
                                runtime.lock().unwrap_or_else(|error| error.into_inner());
                            runtime.phase = if control.is_cancelled() {
                                PHASE_CANCELLED
                            } else {
                                PHASE_CODE
                            }
                            .to_string();
                            match event {
                                crate::code_agent::agent::AnalysisEvent::FindingStarted {
                                    finding_index,
                                    finding_title,
                                } => {
                                    runtime.code_in_progress = Some(CodeCheckpoint {
                                        finding_index,
                                        finding_title: finding_title.to_string(),
                                        file: None,
                                        line: None,
                                        started_at: now_iso8601(),
                                    });
                                }
                                crate::code_agent::agent::AnalysisEvent::FindingFinished(
                                    analysis,
                                ) => {
                                    let title = titles
                                        .get(analysis.finding_index)
                                        .cloned()
                                        .unwrap_or_default();
                                    runtime.partial_code_analyses.push(
                                        CodeAnalysisCheckpoint::from_analysis(&title, analysis),
                                    );
                                    runtime.code_in_progress = None;
                                }
                            }
                        }
                        if let Some(checkpoint) = &checkpoint {
                            let _ = checkpoint.flush();
                        }
                    };
                    let report = service
                        .analyze_with_hook(
                            self.agent.provider_handle(),
                            crate::code_agent::agent::CodeAgentContext {
                                model: &model,
                                provider_label: &label,
                                findings: &self.findings,
                                progress: Some(&tx),
                                control: Some(&agent_control),
                            },
                            Some(&hook),
                        )
                        .await;
                    // Sem esta espera a última linha pode não ter sido gravada.
                    drop(tx);
                    let _ = auditor.await;
                    report
                }
            }
            Err(error) => {
                let reason = error.to_string();
                self.agent_trail.record_event(
                    &crate::code_agent::progress::CodeAgentEvent::Finished {
                        located: 0,
                        total: 0,
                        unavailable_reason: Some(reason.clone()),
                    },
                );
                CodeAnalysisReport::unavailable(&project_dir, &reason)
            }
        };
        {
            let mut runtime = self
                .runtime
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            runtime.code_in_progress = None;
            if self.control.is_cancelled() {
                runtime.phase = PHASE_CANCELLED.to_string();
            }
        }
        self.apply_code_report(&report);
        self.last_code_report = Some(report);
        let _ = self.persist_checkpoint_with_reason(self.checkpoint_reason());
        self.last_code_report.clone().unwrap_or_default()
    }

    /// Escreve a localização e a correção no contrato de cada achado.
    ///
    /// O índice do relatório casa com a posição na lista original: gravar o
    /// resultado **sem** reordenar nem reclassificar mantém a severidade
    /// exatamente a que o scanner produziu.
    fn apply_code_report(&mut self, report: &CodeAnalysisReport) {
        for analysis in &report.findings {
            let Some(finding) = self.findings.get_mut(analysis.finding_index) else {
                continue;
            };
            finding.code_location = analysis.location.clone();
            finding.code_remediation = analysis.remediation.clone();
        }
    }

    async fn request_nuclei_plan(&mut self, target: &str) -> Option<String> {
        let prompt = nuclei_plan_prompt(
            target,
            self.latest_nmap_output.as_deref().unwrap_or_default(),
        );
        self.begin_ai_checkpoint(&format!("planejamento do Nuclei para {target}"));
        let result = self
            .analysis_service
            .request(&mut self.agent, &prompt)
            .await;
        self.finish_ai_checkpoint();
        result
    }

    /// Constrói os achados reais a partir da execução dos scanners.
    ///
    /// Nunca inclui achados simulados.
    pub fn build_findings(&mut self) {
        let target = self.config.target_url.clone();
        let mut real_findings: Vec<Vulnerability> = Vec::new();
        for exec in &mut self.execution_history {
            if exec.output.is_empty() {
                continue;
            }
            let Some(registered) = self.registry.find(&exec.tool_name) else {
                continue;
            };
            match registered.parser {
                ParserKind::NucleiJsonl => {
                    let (parsed, errors) =
                        crate::orchestrator::nuclei_parser::parse_nuclei_findings_with_errors(
                            &exec.output,
                            &target,
                        );
                    real_findings.extend(parsed);
                    if !errors.is_empty() {
                        // Registro JSONL malformado é diagnóstico de execução, não varredura limpa.
                        let message = errors.join("; ");
                        exec.execution_error = Some(message);
                    }
                }
                ParserKind::NmapXml => {
                    let (parsed, errors) =
                        crate::orchestrator::nmap_parser::parse_nmap_findings_with_errors(
                            &exec.output,
                            &target,
                        );
                    real_findings.extend(parsed);
                    if exec.execution_error.is_none() && !errors.is_empty() {
                        exec.execution_error = Some(errors.join("; "));
                        exec.status = "failed".to_string();
                    }
                }
                ParserKind::GenericText => {
                    let (parsed, errors) =
                        crate::orchestrator::generic_parser::parse_generic_findings_with_errors(
                            &exec.output,
                            &target,
                            &registered.manifest.name,
                        );
                    real_findings.extend(parsed);
                    if exec.execution_error.is_none() && !errors.is_empty() {
                        exec.execution_error = Some(errors.join("; "));
                        exec.status = "failed".to_string();
                    }
                }
                ParserKind::NiktoJson => {
                    let (parsed, errors) =
                        crate::orchestrator::nikto_parser::parse_nikto_findings_with_errors(
                            &exec.output,
                            &target,
                        );
                    real_findings.extend(parsed);
                    if exec.execution_error.is_none() && !errors.is_empty() {
                        exec.execution_error = Some(errors.join("; "));
                        exec.status = "failed".to_string();
                    }
                }
                ParserKind::SqlmapText => {
                    let (parsed, errors) =
                        crate::orchestrator::sqlmap_parser::parse_sqlmap_findings_with_errors(
                            &exec.output,
                            &target,
                        );
                    real_findings.extend(parsed);
                    if exec.execution_error.is_none() && !errors.is_empty() {
                        exec.execution_error = Some(errors.join("; "));
                        exec.status = "failed".to_string();
                    }
                }
                ParserKind::TruffleHogJsonl => {
                    let (parsed, errors) =
                        crate::orchestrator::trufflehog_parser::parse_trufflehog_findings_with_errors(
                            &exec.output,
                            &target,
                        );
                    real_findings.extend(parsed);
                    if exec.execution_error.is_none() && !errors.is_empty() {
                        exec.execution_error = Some(errors.join("; "));
                        exec.status = "failed".to_string();
                    }
                }
                ParserKind::ZapJson => {
                    let (parsed, errors) =
                        crate::orchestrator::zap_parser::parse_zap_findings_with_errors(
                            &exec.output,
                            &target,
                        );
                    real_findings.extend(parsed);
                    if exec.execution_error.is_none() && !errors.is_empty() {
                        exec.execution_error = Some(errors.join("; "));
                        exec.status = "failed".to_string();
                    }
                }
            }
        }
        self.findings = real_findings;
    }

    /// Correlaciona os achados e enriquece cada grupo com os dados da NVD.
    ///
    /// Roda depois de [`build_findings`](Self::build_findings). A indisponibilidade
    /// da NVD não impede o resultado: os achados voltam consolidados e a causa
    /// fica em `self.enrichment.nvd`, visível na TUI, no headless e no relatório.
    pub async fn correlate_and_enrich_findings(&mut self) {
        let client = NvdClient::new().ok();
        let (findings, summary) =
            correlate_and_enrich(self.findings.clone(), client.as_ref()).await;
        self.findings = findings;
        self.enrichment = summary;
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

    /// Executa as ferramentas selecionadas respeitando pausa, retomada,
    /// cancelamento e a regra automática de interrupção.
    ///
    /// O cancelamento encerra o container em execução de forma cooperativa pelo
    /// canal compartilhado; a pausa e a retomada viram `podman pause` e
    /// `podman unpause` no container real.
    #[allow(dead_code)]
    pub async fn run_full_pipeline(
        &mut self,
        selected: &[&ToolManifest],
    ) -> Result<Vec<Vulnerability>, anyhow::Error> {
        let target = self.config.target_url.clone();
        for tool in selected {
            if self.control.wait_while_paused().await == RunControl::Cancelled {
                break;
            }
            if let Some(reason) = self.interrupt_after_findings(tool.name.as_str()) {
                self.record_interruption(reason);
                break;
            }
            let _exec = self.execute_tool(tool, &target).await;
        }

        if self.control.is_cancelled() {
            self.set_runtime_phase(PHASE_CANCELLED);
            let _ = self.persist_checkpoint_with_reason("cancelado");
        }

        self.build_findings();
        self.correlate_and_enrich_findings().await;

        let analysis = self.analyze_findings().await;
        self.last_log = analysis.text;
        Ok(self.findings.clone())
    }

    /// Avalia a regra automática de interrupção (REQ05) antes da próxima
    /// ferramenta, contando os achados das execuções já concluídas.
    ///
    /// Avaliar **entre** ferramentas evita matar o container que acabou de
    /// produzir a evidência: o relatório preserva tudo o que foi coletado.
    pub fn interrupt_after_findings(&mut self, tool_name: &str) -> Option<InterruptionReason> {
        if self.control.is_cancelled() {
            return None;
        }
        let threshold = self.config.max_critical_findings;
        if threshold == 0 {
            return None;
        }
        self.build_findings();
        let critical = self
            .findings
            .iter()
            .filter(|finding| finding.severity == crate::domain::Severity::Critical)
            .count();
        (critical >= threshold)
            .then(|| InterruptionReason::max_critical_findings(critical, threshold, tool_name))
    }

    /// Trilha de auditoria do scan, com a mesma origem do log estruturado.
    pub fn agent_trail(&self) -> std::sync::Arc<crate::code_agent::audit_trail::AgentAuditTrail> {
        std::sync::Arc::clone(&self.agent_trail)
    }

    /// Gravação final: o runtime passa a `completed` (ou `cancelled`) e
    /// `completed_at` recebe o horário real do encerramento.
    pub fn persist_scan_log(&self) -> anyhow::Result<std::path::PathBuf> {
        let _guard = self
            .checkpoint_write_lock
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let mut metadata = self.scan_metadata();
        metadata.runtime = self.final_runtime();
        self.save_metadata(&metadata)
    }

    /// Log estruturado da execução, ainda não gravado.
    ///
    /// Separado da gravação para que um teste possa conferir o conteúdo sem
    /// escrever no diretório de configuração do usuário.
    pub fn scan_metadata(&self) -> crate::orchestrator::scan_logger::ScanMetadata {
        let mut metadata = self.base_scan_metadata();
        metadata.comparison = crate::orchestrator::scan_logger::comparison_with_previous(
            &self.config.target_url,
            &self.started_at,
            &self.scan_id,
            &self.findings,
        );
        metadata
    }

    /// Metadados sem a comparação com execuções anteriores.
    ///
    /// A comparação lê o diretório inteiro de histórico; fazê-la a cada
    /// checkpoint deixaria a gravação incremental mais cara que o próprio scan.
    fn base_scan_metadata(&self) -> crate::orchestrator::scan_logger::ScanMetadata {
        let scan_id = self.scan_id.clone();
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
                    output_sample: sanitize(
                        &execution.output.chars().take(400).collect::<String>(),
                    )
                    .chars()
                    .take(200)
                    .collect(),
                    stdout: sanitize(&crate::orchestrator::scan_logger::capped_stream(
                        &execution.output,
                    )),
                    stderr: sanitize(&crate::orchestrator::scan_logger::capped_stream(
                        &execution.stderr,
                    )),
                    status: execution.status.clone(),
                    duration_ms: execution.duration_ms,
                    tool_version: execution.tool_version.clone(),
                    image: execution.image.clone(),
                    execution_error: execution.execution_error.clone(),
                    podman_trace: execution
                        .podman_trace
                        .iter()
                        .take(crate::orchestrator::scan_logger::MAX_LOG_TRACE_LINES)
                        .map(|line| {
                            sanitize(&crate::orchestrator::scan_logger::capped_trace_line(line))
                        })
                        .collect(),
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
            decisions: self
                .decision_history
                .iter()
                .map(DecisionRecord::sanitized)
                .collect(),
            enrichment: self.enrichment.clone(),
            interruption: self.control.interruption(),
            ..metadata
        };
        let metadata = match &self.last_analysis_result {
            Some(result) => metadata.with_analysis(result),
            None => metadata,
        };
        let metadata = match &self.last_code_report {
            Some(report) => {
                metadata.with_code_analysis(report, &self.config.effective_project_dir())
            }
            None => metadata,
        };
        let metadata = metadata.with_agent_trail(self.agent_trail.path());
        let metadata = self
            .rag_explanations
            .iter()
            .fold(metadata, |metadata, result| {
                metadata.with_rag_explanation(result)
            });
        crate::orchestrator::scan_logger::ScanMetadata {
            runtime: self.runtime_snapshot(),
            ..metadata
        }
    }

    /// Estado final do runtime, coerente com o motivo da interrupção.
    fn final_runtime(&self) -> ScanRuntime {
        let mut runtime = self.runtime_snapshot();
        let cancelled = self.control.is_cancelled();
        runtime.phase = if cancelled {
            PHASE_CANCELLED
        } else {
            PHASE_COMPLETED
        }
        .to_string();
        if cancelled {
            // O cancelamento preserva o que estava em andamento: zerar aqui
            // esconderia a ferramenta e o log parcial justamente no registro
            // que sobrevive ao encerramento.
            if let Some(tool) = runtime.current_tool.as_mut() {
                if tool.status == TOOL_STATUS_RUNNING {
                    tool.status = "cancelled".to_string();
                    tool.finished_at = now_iso8601();
                }
            }
        } else {
            runtime.current_tool = None;
            runtime.ai_in_progress = None;
            runtime.code_in_progress = None;
        }
        runtime.last_checkpoint_at = now_iso8601();
        runtime.checkpoint_reason = if cancelled {
            "cancelado".to_string()
        } else if self.control.interruption().is_some() {
            "interrompido".to_string()
        } else {
            "concluído".to_string()
        };
        runtime
    }

    /// Registra uma explicação do detalhe do achado para o log estruturado.
    pub fn record_rag_explanation(&mut self, result: &crate::cyberrag::service::ExplanationResult) {
        self.rag_explanations.push(result.clone());
        self.set_runtime_phase(PHASE_RAG);
    }
}

/// Trilha e log estruturado levam o mesmo id para a auditoria poder emendar
/// as ações da IA com o relatório que elas produziram.
impl Orchestrator {
    pub fn novo_scan_id() -> String {
        format!(
            "scan_{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        )
    }
}

fn agent_trail_for(
    scan_id: &str,
) -> std::sync::Arc<crate::code_agent::audit_trail::AgentAuditTrail> {
    let trail = crate::code_agent::audit_trail::AgentAuditTrail::open_default(scan_id)
        .unwrap_or_else(|| {
            // Sem diretório gravável a trilha cai para o temporário: a fase
            // continua e nenhum teste quebra por causa do ambiente.
            let dir = std::env::temp_dir();
            crate::code_agent::audit_trail::AgentAuditTrail::open_in(&dir, scan_id)
                .expect("diretório temporário é gravável")
        });
    std::sync::Arc::new(trail)
}

fn now_iso8601() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// Diretório temporário que recebe o plano de automação do ZAP.
///
/// O plano é gerado em memória e gravado aqui, montado em somente leitura no
/// container; o diretório vive no `TMPDIR` do host, é específico desta execução
/// e é removido ao final.
fn zap_plan_dir() -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "smartsec-zap-plano-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ))
}

/// Remove o diretório do plano de automação ao final da execução, inclusive nos
/// caminhos de erro e de cancelamento.
struct PlanDirectory(std::path::PathBuf);

impl Drop for PlanDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
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
        ExecutionStatus::Cancelled => format!(
            "Execução cancelada: o container {} foi interrompido e removido.{}",
            result.container_id, cleanup_error
        ),
    }
}

fn nuclei_plan_prompt(target: &str, nmap_output: &str) -> String {
    format!(
        "Analise o XML do Nmap e retorne somente JSON válido, sem cercas de código, com os campos should_run (booleano), profiles (lista com ao menos um perfil), concurrency (inteiro de 1 a 50) e timeout_seconds (inteiro de 1 a 10). Os únicos profiles permitidos são http-misconfiguration, http-exposed-panels, ssh-exposure, database-exposure e generic. Não invente flags, comandos nem texto adicional. Alvo: {target}\n\nLog do Nmap:\n{nmap_output}"
    )
}

fn execution_status(status: &ExecutionStatus) -> String {
    match status {
        ExecutionStatus::Succeeded => "succeeded".to_string(),
        ExecutionStatus::Failed(code) => format!(
            "failed:{}",
            code.map_or_else(|| "unknown".to_string(), |c| c.to_string())
        ),
        ExecutionStatus::TimedOut => "timeout".to_string(),
        ExecutionStatus::Cancelled => "cancelled".to_string(),
    }
}

/// Remove credenciais e tokens antes de persistir ou encaminhar qualquer saída.
fn sanitize(value: &str) -> String {
    crate::utils::redaction::sanitize_text(value)
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
            .env_remove("SMARTSEC_API_KEY")
            .output()
            .map_err(|error| {
                anyhow::anyhow!("não foi possível validar o commit dos templates: {error}")
            })?;
        let actual = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !output.status.success() || actual != expected {
            let found = if actual.is_empty() {
                format!(
                    "'{}' não é um clone git; refaça o clone fixado conforme docs/INSTALACAO.md",
                    path.display()
                )
            } else {
                format!("esperado {expected}, encontrado {actual}")
            };
            anyhow::bail!("templates do Nuclei fora do commit fixado: {found}");
        }
    }
    Ok(())
}

/// Recorte inicial usado quando o log final de uma ferramenta vira checkpoint.
fn capped_checkpoint_text(text: &str) -> String {
    if text.len() <= MAX_CHECKPOINT_OUTPUT_BYTES {
        return text.to_string();
    }
    let end = text
        .char_indices()
        .take_while(|(index, _)| *index < MAX_CHECKPOINT_OUTPUT_BYTES)
        .last()
        .map(|(index, _)| index)
        .unwrap_or(0);
    format!("{}\n[... saída limitada no checkpoint ...]", &text[..end])
}

/// Anexa o desfecho ao log parcial, mantendo o fim (o trecho mais recente).
fn append_checkpoint_output(existing: &mut String, text: &str) {
    if !existing.is_empty() {
        existing.push('\n');
    }
    existing.push_str(text);
    if existing.len() <= MAX_CHECKPOINT_OUTPUT_BYTES {
        return;
    }
    let mut start = existing.len() - MAX_CHECKPOINT_OUTPUT_BYTES;
    while !existing.is_char_boundary(start) {
        start += 1;
    }
    let tail = existing[start..].to_string();
    *existing = format!("[... trecho inicial descartado ...]\n{tail}");
}

/// Resumo do turno da IA: quantidade e alguns títulos, nunca o prompt inteiro.
fn checkpoint_prompt_summary(findings: &[Vulnerability]) -> String {
    let titles = findings
        .iter()
        .take(5)
        .map(|finding| crate::utils::redaction::sanitize_text(&finding.title))
        .collect::<Vec<_>>()
        .join("; ");
    summarize_checkpoint_prompt(&format!(
        "análise de {} achado(s): {titles}",
        findings.len()
    ))
}

fn summarize_checkpoint_prompt(summary: &str) -> String {
    let sanitized = crate::utils::redaction::sanitize_text(summary);
    if sanitized.chars().count() <= 300 {
        return sanitized;
    }
    sanitized.chars().take(300).collect::<String>() + "…"
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Configuration;

    fn make_config() -> Configuration {
        Configuration {
            target_url: "http://test.local".to_string(),
            ..Configuration::default()
        }
    }

    #[test]
    fn a_web_target_uses_the_project_dir_for_repository_tools() {
        let mut config = make_config();
        config.project_dir = Some("/tmp".to_string());
        let orchestrator = Orchestrator::new(config).expect("configuração válida");

        let (target, overridden) = orchestrator.repository_target_for("http://169.254.1.2:3000");

        assert_eq!(
            target,
            std::fs::canonicalize("/tmp").unwrap().display().to_string()
        );
        assert_eq!(overridden.as_deref(), Some("http://169.254.1.2:3000"));
    }

    #[test]
    fn a_git_uri_is_not_replaced_by_the_project_dir() {
        let mut config = make_config();
        config.project_dir = Some("/tmp".to_string());
        let orchestrator = Orchestrator::new(config).expect("configuração válida");

        let (target, overridden) =
            orchestrator.repository_target_for("https://github.com/org/repo.git");

        assert_eq!(target, "https://github.com/org/repo.git");
        assert!(overridden.is_none());
    }

    #[test]
    fn nuclei_plan_prompt_states_the_enforced_ranges() {
        let prompt = nuclei_plan_prompt("http://alvo.local", "<nmaprun />");

        assert!(prompt.contains("1 a 50"), "{prompt}");
        assert!(prompt.contains("1 a 10"), "{prompt}");
        assert!(prompt.contains("ao menos um perfil"), "{prompt}");
        assert!(prompt.contains("http://alvo.local"));
    }

    #[test]
    fn new_rejects_invalid_tool_configuration_with_actionable_error() {
        let mut config = make_config();
        config.tools.push(ToolManifest {
            name: "Nmap".to_string(),
            description: "Duplicada".to_string(),
            category: "RECON".to_string(),
            image: "example/nmap:1".to_string(),
            version: "1.0".to_string(),
            runner: crate::tools::registry::RUNNER_GENERIC.to_string(),
            parser: crate::tools::registry::PARSER_GENERIC_TEXT.to_string(),
            command_template: vec!["nmap".to_string(), "{target}".to_string()],
            output_format: "text".to_string(),
            enabled: true,
        });

        let error = Orchestrator::new(config)
            .err()
            .expect("configuração inválida deveria falhar")
            .to_string();

        assert!(
            error.contains("configuração de ferramentas inválida"),
            "{error}"
        );
        assert!(error.contains("duplicada"), "{error}");
        assert!(error.contains("Nmap"), "{error}");
    }

    #[test]
    fn real_run_empty_history_produces_no_findings() {
        let mut orch = Orchestrator::new(make_config()).expect("configuração de teste válida");
        orch.build_findings();
        assert!(
            orch.findings.is_empty(),
            "Sem execuções, não deve haver achados"
        );
    }

    #[test]
    fn build_findings_dispatches_the_parser_registered_for_the_tool() {
        let mut config = make_config();
        config.tools.push(ToolManifest {
            name: "ScannerExemplo".to_string(),
            description: "Scanner de servidores web".to_string(),
            category: "DAST".to_string(),
            image: "example/scanner:1".to_string(),
            version: "1.0".to_string(),
            runner: crate::tools::registry::RUNNER_GENERIC.to_string(),
            parser: crate::tools::registry::PARSER_GENERIC_TEXT.to_string(),
            command_template: vec![
                "scanner".to_string(),
                "-host".to_string(),
                "{target}".to_string(),
            ],
            output_format: "text".to_string(),
            enabled: true,
        });
        let mut orch = Orchestrator::new(config).expect("configuração de teste válida");
        let mut execution = SecurityTool::new("ScannerExemplo", "scanner -host http://test.local");
        execution.output = "Servidor expõe /admin sem autenticação\n".to_string();
        orch.execution_history.push(execution);

        orch.build_findings();

        assert_eq!(orch.findings.len(), 1);
        assert_eq!(orch.findings[0].tool, "ScannerExemplo");
        assert_eq!(orch.findings[0].severity, crate::domain::Severity::Info);
    }

    fn critical_finding(tool: &str, title: &str) -> Vulnerability {
        Vulnerability {
            title: title.to_string(),
            severity: crate::domain::Severity::Critical,
            description: "Descrição".to_string(),
            tool: tool.to_string(),
            recommendation: "Revise".to_string(),
            didactic: "Explicação".to_string(),
            source: crate::domain::vulnerability::FindingSource::Real,
            target: "http://test.local".to_string(),
            evidence: "evidência".to_string(),
            detected_at: "2026-09-30T12:00:00Z".to_string(),
            origins: Vec::new(),
            enrichment: None,
            severity_conflict: None,
            ..Default::default()
        }
    }

    /// Orquestrador com uma execução real do parser que produz severidade
    /// `critical` a partir da saída do próprio scanner.
    fn recording_orchestrator(threshold: usize, tool_name: &str) -> Orchestrator {
        let mut config = make_config();
        config.max_critical_findings = threshold;
        config.tools.push(ToolManifest {
            name: tool_name.to_string(),
            description: "Scanner de teste".to_string(),
            category: "DAST".to_string(),
            image: "example/scanner:1".to_string(),
            version: "1.0".to_string(),
            runner: crate::tools::registry::RUNNER_GENERIC.to_string(),
            parser: crate::tools::registry::PARSER_NUCLEI_JSONL.to_string(),
            command_template: vec!["scan".to_string(), "{target}".to_string()],
            output_format: "jsonl".to_string(),
            enabled: true,
        });
        let mut orchestrator = Orchestrator::new(config).expect("configuração de teste válida");
        let mut execution = SecurityTool::new(tool_name, "scan http://test.local");
        execution.status = "succeeded".to_string();
        execution.output = concat!(
            r#"{"template-id":"CVE-2021-44228","info":{"name":"Log4Shell RCE","severity":"critical"},"matched-at":"http://test.local/","matcher-name":"jndi-injection"}"#,
            "\n"
        )
        .to_string();
        orchestrator.execution_history.push(execution);
        orchestrator
    }

    #[test]
    fn the_automatic_rule_fires_at_the_threshold_and_records_the_reason() {
        let mut orch = recording_orchestrator(1, "ScannerExemplo");

        let reason = orch
            .interrupt_after_findings("Nikto")
            .expect("um achado crítico com limiar 1 deve interromper");

        assert_eq!(reason.rule, "max_critical_findings");
        assert_eq!(reason.threshold, Some(1));
        assert_eq!(reason.critical_count, 1);
        assert_eq!(reason.tool.as_deref(), Some("Nikto"));
        assert!(reason.message.contains("limite de 1"), "{}", reason.message);
        assert!(!orch.is_cancelled(), "a regra não vira cancelamento");
    }

    #[test]
    fn the_automatic_rule_does_not_fire_below_the_threshold_or_when_disabled() {
        // Limiar 2 com um achado crítico: nada acontece.
        assert!(recording_orchestrator(2, "ScannerExemplo")
            .interrupt_after_findings("Nikto")
            .is_none());

        // Limiar 0 significa regra desativada (padrão retrocompatível).
        let mut disabled = recording_orchestrator(0, "ScannerExemplo");
        assert!(disabled.interrupt_after_findings("Nikto").is_none());
    }

    #[test]
    fn the_first_interruption_reason_is_the_one_kept_for_audit() {
        let mut orch = recording_orchestrator(1, "ScannerExemplo");
        let rule = orch
            .interrupt_after_findings("Nikto")
            .expect("a regra deve disparar");
        orch.record_interruption(rule);
        let user = crate::orchestrator::control::InterruptionReason::user_cancelled();
        orch.record_interruption(user.clone());

        let recorded = orch
            .interruption()
            .expect("o motivo precisa ser preservado");
        assert_eq!(recorded.rule, "max_critical_findings");
        assert_ne!(recorded.rule, user.rule);
    }

    #[test]
    fn the_recorded_reason_is_recoverable_from_the_persisted_scan_log() {
        let mut orch = recording_orchestrator(1, "ScannerExemplo");
        let reason = orch
            .interrupt_after_findings("Nikto")
            .expect("a regra deve disparar");
        orch.record_interruption(reason);
        orch.findings = vec![critical_finding("ScannerExemplo", "Achado crítico")];

        let metadata = crate::orchestrator::scan_logger::ScanMetadata {
            interruption: orch.interruption(),
            ..crate::orchestrator::scan_logger::ScanMetadata::new(
                "scan_regra".to_string(),
                "http://test.local".to_string(),
                "2026-09-30T12:00:00Z".to_string(),
                "2026-09-30T12:05:00Z".to_string(),
                "Auto".to_string(),
                "Ollama".to_string(),
                Vec::new(),
                orch.findings.clone(),
                "análise".to_string(),
            )
        };

        let json = serde_json::to_string(&metadata).expect("serialização do log");
        let restored: crate::orchestrator::scan_logger::ScanMetadata =
            serde_json::from_str(&json).expect("leitura do log");
        let interruption = restored
            .interruption
            .expect("o motivo precisa ser persistido");
        assert_eq!(interruption.rule, "max_critical_findings");
        assert_eq!(interruption.threshold, Some(1));
        assert!(interruption.message.contains("limite de 1"));
    }

    #[test]
    fn a_scan_log_written_before_this_feature_still_loads() {
        let metadata = crate::orchestrator::scan_logger::ScanMetadata::new(
            "scan_legacy".to_string(),
            "http://test.local".to_string(),
            "2026-01-01T00:00:00Z".to_string(),
            "2026-01-01T00:05:00Z".to_string(),
            "Auto".to_string(),
            "Ollama".to_string(),
            Vec::new(),
            Vec::new(),
            "análise".to_string(),
        );
        let mut legacy = serde_json::to_value(&metadata).unwrap();
        legacy.as_object_mut().unwrap().remove("interruption");

        let restored: crate::orchestrator::scan_logger::ScanMetadata =
            serde_json::from_value(legacy).expect("histórico antigo precisa continuar legível");

        assert!(restored.interruption.is_none());
    }

    fn checkpoint_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "smartsec-checkpoint-{label}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn checkpoint_orchestrator(label: &str) -> (Orchestrator, PathBuf) {
        let dir = checkpoint_dir(label);
        let mut orchestrator =
            Orchestrator::new(make_config()).expect("configuração de teste válida");
        // Ids válidos são `scan_<dígitos>`; o log usa o id para o histórico.
        orchestrator.scan_id = Orchestrator::novo_scan_id();
        let orchestrator = orchestrator.with_checkpoint_dir(dir.clone());
        (orchestrator, dir)
    }

    #[test]
    fn a_checkpoint_written_before_the_end_is_valid_and_reloads() {
        let (mut orchestrator, dir) = checkpoint_orchestrator("parcial");
        orchestrator.findings = vec![critical_finding("Nuclei", "Achado crítico")];
        let manifest = ToolManifest {
            name: "Nuclei".to_string(),
            ..ToolManifest::default()
        };
        orchestrator.begin_tool_checkpoint(&manifest, "http://test.local");

        let path = orchestrator
            .persist_checkpoint()
            .expect("checkpoint antes do fim");

        assert!(path.exists());
        let loaded = crate::orchestrator::scan_logger::load_scan_log_from_file(&path)
            .expect("o JSON parcial precisa reler");
        assert_eq!(loaded.scan_id, orchestrator.scan_id);
        assert_eq!(loaded.runtime.phase, PHASE_TOOLS);
        assert!(
            loaded.completed_at.is_empty(),
            "checkpoint não pode parecer scan concluído"
        );
        let tool = loaded.runtime.current_tool.expect("ferramenta atual");
        assert_eq!(tool.tool_name, "Nuclei");
        assert_eq!(tool.status, TOOL_STATUS_RUNNING);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_running_tool_and_the_cancellation_keep_status_and_partial_log() {
        let (mut orchestrator, dir) = checkpoint_orchestrator("cancelado");
        let manifest = ToolManifest {
            name: "Nuclei".to_string(),
            ..ToolManifest::default()
        };
        orchestrator.begin_tool_checkpoint(&manifest, "http://test.local");
        let handle = orchestrator
            .checkpoint_handle()
            .expect("handle de checkpoint");
        handle.append_tool_log("linha já transmitida pelo scanner");
        handle.append_tool_log("outra linha antes do cancelamento");
        handle.flush().expect("flush do streaming");

        orchestrator.control.cancel();
        orchestrator.set_runtime_phase(PHASE_CANCELLED);
        let path = orchestrator
            .persist_checkpoint_with_reason("cancelado")
            .expect("checkpoint de cancelamento");

        let loaded = crate::orchestrator::scan_logger::load_scan_log_from_file(&path)
            .expect("o JSON cancelado precisa reler");
        assert_eq!(loaded.runtime.phase, PHASE_CANCELLED);
        assert_eq!(loaded.runtime.checkpoint_reason, "cancelado");
        let tool = loaded
            .runtime
            .current_tool
            .expect("ferramenta em andamento");
        assert_eq!(tool.status, TOOL_STATUS_RUNNING);
        assert!(
            tool.output_partial
                .contains("outra linha antes do cancelamento"),
            "o log parcial precisa sobreviver: {}",
            tool.output_partial
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A gravação final de um scan cancelado não pode apagar a ferramenta que
    /// estava rodando nem transformar o arquivo em um scan limpo.
    #[test]
    fn the_final_log_of_a_cancelled_scan_preserves_the_in_flight_tool() {
        let (mut orchestrator, dir) = checkpoint_orchestrator("cancelado-final");
        let manifest = ToolManifest {
            name: "Nuclei".to_string(),
            ..ToolManifest::default()
        };
        orchestrator.begin_tool_checkpoint(&manifest, "http://test.local");
        orchestrator
            .checkpoint_handle()
            .expect("handle de checkpoint")
            .append_tool_log("evidência parcial antes do cancelamento");
        orchestrator.control.cancel();

        let path = orchestrator
            .persist_scan_log()
            .expect("log final do cancelamento");
        let loaded = crate::orchestrator::scan_logger::load_scan_log_from_file(&path)
            .expect("o JSON final precisa reler");

        assert_eq!(loaded.runtime.phase, PHASE_CANCELLED);
        assert_eq!(loaded.runtime.checkpoint_reason, "cancelado");
        assert!(!loaded.completed_at.is_empty());
        let tool = loaded
            .runtime
            .current_tool
            .expect("a ferramenta em andamento não some no cancelamento");
        assert_eq!(tool.status, "cancelled");
        assert!(tool
            .output_partial
            .contains("evidência parcial antes do cancelamento"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_ai_turn_in_progress_is_recorded_before_the_response() {
        let (mut orchestrator, dir) = checkpoint_orchestrator("ia");
        orchestrator.findings = vec![critical_finding("Nuclei", "Achado crítico")];
        orchestrator.set_runtime_phase(PHASE_ANALYSIS);
        orchestrator.begin_ai_checkpoint("análise de 1 achado: Achado crítico");

        let path = orchestrator.persist_checkpoint().expect("checkpoint da IA");
        let loaded = crate::orchestrator::scan_logger::load_scan_log_from_file(&path)
            .expect("o JSON da IA precisa reler");

        let ai = loaded.runtime.ai_in_progress.expect("turno em andamento");
        assert_eq!(ai.provider, orchestrator.config.provider_mode);
        assert_eq!(ai.model, orchestrator.agent.model);
        assert_eq!(ai.findings_count, 1);
        assert!(ai.prompt_summary.contains("análise de 1 achado"));
        assert!(!ai.prompt_summary.contains("sk-"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn one_of_many_code_analyses_is_visible_before_the_phase_ends() {
        use crate::code_agent::agent::FindingCodeAnalysis;

        let (mut orchestrator, dir) = checkpoint_orchestrator("codigo");
        orchestrator.findings = vec![
            critical_finding("Nuclei", "Primeiro achado"),
            critical_finding("Nuclei", "Segundo achado"),
        ];
        orchestrator.set_runtime_phase(PHASE_CODE);
        let first = FindingCodeAnalysis {
            finding_index: 0,
            location: Some(crate::domain::vulnerability::CodeLocation {
                file: "src/app.py".to_string(),
                line: 4,
                snippet: "raise ValueError".to_string(),
            }),
            remediation: vec!["Valide o usuário".to_string()],
            reason: None,
            model: "gpt-4o".to_string(),
            provider: "OpenAI".to_string(),
            tool_calls: 1,
            fallback_used: false,
        };
        {
            let mut runtime = orchestrator
                .runtime
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            runtime.partial_code_analyses.push(
                crate::orchestrator::scan_logger::CodeAnalysisCheckpoint::from_analysis(
                    "Primeiro achado",
                    &first,
                ),
            );
            runtime.code_in_progress = Some(CodeCheckpoint {
                finding_index: 1,
                finding_title: "Segundo achado".to_string(),
                file: None,
                line: None,
                started_at: "2026-10-24T10:00:00Z".to_string(),
            });
        }

        let path = orchestrator
            .persist_checkpoint()
            .expect("checkpoint do código parcial");
        let loaded = crate::orchestrator::scan_logger::load_scan_log_from_file(&path)
            .expect("o JSON do código precisa reler");

        assert_eq!(loaded.runtime.partial_code_analyses.len(), 1);
        let partial = &loaded.runtime.partial_code_analyses[0];
        assert_eq!(partial.finding_index, 0);
        assert_eq!(partial.file.as_deref(), Some("src/app.py"));
        assert_eq!(partial.line, Some(4));
        assert!(partial.located);
        assert_eq!(
            loaded
                .runtime
                .code_in_progress
                .as_ref()
                .map(|code| code.finding_index),
            Some(1),
            "o achado seguinte continua marcado como em andamento"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A fase do agente de código grava a origem no achado sem reordenar a lista
    /// nem reclassificar a severidade.
    ///
    /// Contrato da issue #76: o scanner é a autoridade da severidade (TCC_SPEC,
    /// seção 7) e o agente apenas aponta onde corrigir; um teste que passasse
    /// mesmo reordenando os achados não provaria nada.
    #[tokio::test]
    async fn the_code_phase_writes_the_location_without_touching_severity() {
        use crate::domain::vulnerability::CodeLocation;
        use crate::domain::vulnerability::FindingSource;

        let mut config = make_config();
        config.project_dir = Some(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/codebase")
                .display()
                .to_string(),
        );
        let mut orch = Orchestrator::new(config).expect("configuração de teste válida");

        let mut first = Vulnerability {
            title: "Autenticação fraca".to_string(),
            severity: crate::domain::Severity::High,
            description: "Descrição".to_string(),
            tool: "Nuclei".to_string(),
            recommendation: "Revise".to_string(),
            didactic: "Explicação".to_string(),
            source: FindingSource::Real,
            target: "http://alvo.local".to_string(),
            evidence: "evidência".to_string(),
            detected_at: "2026-09-30T12:00:00Z".to_string(),
            ..Default::default()
        };
        let mut second = first.clone();
        first.title = "Primeiro achado".to_string();
        second.title = "Segundo achado".to_string();
        second.severity = crate::domain::Severity::Info;
        orch.findings = vec![first, second];

        // Relatório sintético da fase: reproduz o que o agente produz sem
        // depender de provedor, e exercita a escrita no contrato de findings.
        let report = crate::code_agent::agent::CodeAnalysisReport {
            findings: vec![
                crate::code_agent::agent::FindingCodeAnalysis {
                    finding_index: 1,
                    location: Some(CodeLocation {
                        file: "src/nested/deep.py".to_string(),
                        line: 2,
                        snippet: "def login():".to_string(),
                    }),
                    remediation: vec!["Encadeie a auditoria".to_string()],
                    reason: None,
                    model: "gpt-4o".to_string(),
                    provider: "OpenAI".to_string(),
                    tool_calls: 2,
                    fallback_used: false,
                },
                crate::code_agent::agent::FindingCodeAnalysis {
                    finding_index: 0,
                    location: None,
                    remediation: Vec::new(),
                    reason: Some("o provedor não implementa tool calling".to_string()),
                    model: "gpt-4o".to_string(),
                    provider: "OpenAI".to_string(),
                    tool_calls: 0,
                    fallback_used: true,
                },
            ],
            tool_calls: Vec::new(),
            unavailable_reason: None,
        };
        orch.apply_code_report(&report);

        // A ordem original é preservada e cada resultado foi para o índice certo.
        assert_eq!(orch.findings[0].title, "Primeiro achado");
        assert_eq!(orch.findings[1].title, "Segundo achado");
        assert!(orch.findings[0].code_location.is_none());
        assert!(orch.findings[0].code_remediation.is_empty());
        assert_eq!(
            orch.findings[1]
                .code_location
                .as_ref()
                .map(ToString::to_string)
                .as_deref(),
            Some("src/nested/deep.py:2")
        );
        assert_eq!(
            orch.findings[1].code_remediation,
            vec!["Encadeie a auditoria".to_string()]
        );

        // A severidade do scanner não muda.
        assert_eq!(orch.findings[0].severity, crate::domain::Severity::High);
        assert_eq!(orch.findings[1].severity, crate::domain::Severity::Info);
    }

    /// O canal de controle chega ao laço do agente: cancelar antes da fase não
    /// abre nenhum turno e devolve os achados marcados, sem bloquear o scan.
    #[tokio::test]
    async fn a_cancelled_control_reaches_the_code_loop_and_returns_partial() {
        let mut config = make_config();
        // Provedor local: o teste quer exercitar o cancelamento, não a regra de
        // consentimento remoto (RNF10), que bloquearia antes do laço.
        config.llm = crate::config::llm_config::LlmConfig {
            provider: crate::config::llm_config::LlmProviderKind::LlamaCpp,
            base_url: "http://127.0.0.1:11434/v1".to_string(),
            model: "modelo-local".to_string(),
            ..crate::config::llm_config::LlmConfig::default()
        };
        config.project_dir = Some(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/codebase")
                .display()
                .to_string(),
        );
        let mut orch = Orchestrator::new(config).expect("configuração de teste válida");
        orch.findings = vec![Vulnerability {
            title: "Autenticação fraca".to_string(),
            severity: crate::domain::Severity::High,
            description: "Descrição".to_string(),
            tool: "Nuclei".to_string(),
            recommendation: "Revise".to_string(),
            didactic: "Explicação".to_string(),
            source: crate::domain::vulnerability::FindingSource::Real,
            target: "http://alvo.local/api/login".to_string(),
            evidence: "matched-at: /api/login".to_string(),
            detected_at: "2026-09-30T12:00:00Z".to_string(),
            ..Default::default()
        }];
        orch.control.cancel();

        let report = orch.analyze_code(None).await;

        assert!(
            report.tool_calls.is_empty(),
            "nenhuma ferramenta pode rodar"
        );
        assert_eq!(report.findings.len(), 1);
        assert!(
            report.findings[0]
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("cancelado pelo usuário")),
            "{:?}",
            report.findings[0].reason
        );
    }

    #[test]
    fn adopting_a_scan_id_keeps_one_trail_for_the_scan() {
        let orchestrator = Orchestrator::new(make_config()).expect("configuração válida");
        let adopted = Orchestrator::new(make_config())
            .expect("configuração válida")
            .adopt_scan_id(orchestrator.scan_id.clone());

        assert_eq!(adopted.scan_id, orchestrator.scan_id);
        assert_eq!(adopted.agent_trail.path(), orchestrator.agent_trail.path());
    }

    /// Um `--project` que não existe não pode derrubar o scan: a fase registra
    /// o motivo e o fluxo segue até o relatório.
    #[tokio::test]
    async fn an_unreadable_project_reports_the_reason_without_failing_the_scan() {
        let mut config = make_config();
        config.project_dir = Some("/caminho/que/nao/existe".to_string());
        let mut orch = Orchestrator::new(config).expect("configuração de teste válida");
        orch.findings = vec![Vulnerability {
            title: "Achado".to_string(),
            severity: crate::domain::Severity::High,
            description: "Descrição".to_string(),
            tool: "Nuclei".to_string(),
            recommendation: "Revise".to_string(),
            didactic: "Explicação".to_string(),
            source: crate::domain::vulnerability::FindingSource::Real,
            target: "http://alvo.local".to_string(),
            evidence: "evidência".to_string(),
            detected_at: "2026-09-30T12:00:00Z".to_string(),
            ..Default::default()
        }];

        let report = orch.analyze_code(None).await;

        let reason = report
            .unavailable_reason
            .as_deref()
            .expect("a fase precisa registrar o motivo");
        assert!(reason.contains("/caminho/que/nao/existe"), "{reason}");
        assert!(orch.findings[0].code_location.is_none());
        assert_eq!(report.located_count(), 0);
    }

    /// A fase do agente de código grava a trilha mesmo sem TUI e sem achado
    /// localizado: é a auditoria que precisa do motivo da recusa.
    #[tokio::test]
    async fn a_fase_de_codigo_registra_a_trilha_mesmo_sem_interface() {
        let mut config = make_config();
        config.project_dir = Some("/caminho/que/nao/existe".to_string());
        let mut orch = Orchestrator::new(config).expect("configuração de teste válida");

        orch.analyze_code(None).await;

        let registros = crate::code_agent::audit_trail::read_records(orch.agent_trail.path())
            .expect("a trilha existe");
        assert!(
            registros
                .iter()
                .any(|registro| registro["detalhe"]["motivo"].is_string()),
            "a recusa precisa ficar registrada: {registros:?}"
        );
    }

    /// O log estruturado aponta para a trilha, para a auditoria não precisar
    /// adivinhar onde a fase foi registrada.
    #[tokio::test]
    async fn o_log_estruturado_aponta_para_a_trilha_da_ia() {
        let orch = Orchestrator::new(make_config()).expect("configuração de teste válida");

        let metadata = orch.scan_metadata();

        assert!(
            metadata.agent_trail_path.ends_with(".jsonl"),
            "{:?}",
            metadata.agent_trail_path
        );
    }

    /// Sem consentimento remoto, a fase não abre turno nenhum e diz por quê.
    ///
    /// O provedor configurado é um Ollama local por padrão, o que não exige
    /// consentimento; o teste força um provedor remoto sem consentimento.
    #[tokio::test]
    async fn a_remote_provider_without_consent_blocks_the_code_phase() {
        let mut config = make_config();
        config.llm = crate::config::llm_config::LlmConfig {
            provider: crate::config::llm_config::LlmProviderKind::OpenAI,
            base_url: "https://api.openai.com/v1".to_string(),
            model: "gpt-4o".to_string(),
            api_key: "chave-de-teste".to_string(),
            remote_consent: false,
            ..crate::config::llm_config::LlmConfig::default()
        };
        // `validate` exigiria consentimento para um provedor remoto; o
        // orquestrador é construído direto para reproduzir o estado herdado de
        // uma configuração remota sem consentimento.
        let mut orch = Orchestrator::with_registry(
            config,
            ToolRegistry::with_configured(&[]).expect("catálogo padrão"),
        );
        orch.findings = vec![Vulnerability {
            title: "Segredo no código".to_string(),
            severity: crate::domain::Severity::High,
            description: "Descrição".to_string(),
            tool: "Nuclei".to_string(),
            recommendation: "Revise".to_string(),
            didactic: "Explicação".to_string(),
            source: crate::domain::vulnerability::FindingSource::Real,
            target: "http://alvo.local".to_string(),
            evidence: "evidência".to_string(),
            detected_at: "2026-09-30T12:00:00Z".to_string(),
            ..Default::default()
        }];

        let report = orch.analyze_code(None).await;

        assert_eq!(report.tool_calls.len(), 0, "nenhuma ferramenta pode rodar");
        assert!(orch.findings[0].code_location.is_none());
        assert_eq!(report.findings.len(), 1);
        assert!(
            report.findings[0]
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("RNF10")),
            "{:?}",
            report.findings[0].reason
        );
    }

    #[tokio::test]
    async fn execute_tool_reports_an_unregistered_tool_without_podman() {
        let mut orch = Orchestrator::new(make_config()).expect("configuração de teste válida");
        let manifest = ToolManifest {
            name: "Inexistente".to_string(),
            ..ToolManifest::default()
        };

        let execution = orch.execute_tool(&manifest, "http://test.local").await;

        assert_eq!(execution.status, "failed");
        assert!(execution
            .execution_error
            .as_deref()
            .is_some_and(|error| error.contains("não está registrada")));
    }

    fn nikto_execution(output: &str, status: &str) -> SecurityTool {
        let mut execution = SecurityTool::new("Nikto", "nikto.pl -h http://test.local");
        execution.output = output.to_string();
        execution.status = status.to_string();
        execution
    }

    #[test]
    fn build_findings_uses_the_nikto_parser_registered_for_the_builtin_tool() {
        let mut orch = Orchestrator::new(make_config()).expect("configuração de teste válida");
        let report = include_str!("../../tests/fixtures/nikto/relatorio.json");
        orch.execution_history
            .push(nikto_execution(report, "succeeded"));

        orch.build_findings();

        assert_eq!(orch.findings.len(), 5);
        assert!(orch.findings.iter().all(|f| f.tool == "Nikto"));
        assert!(orch
            .findings
            .iter()
            .all(|f| f.source == crate::domain::vulnerability::FindingSource::Real));
        assert!(orch
            .findings
            .iter()
            .any(|f| f.evidence.contains("url: http://test.local/")));
        assert!(orch
            .execution_history
            .iter()
            .all(|execution| execution.execution_error.is_none()));
    }

    #[test]
    fn invalid_nikto_output_marks_the_execution_as_failed() {
        let mut orch = Orchestrator::new(make_config()).expect("configuração de teste válida");
        let invalid = include_str!("../../tests/fixtures/nikto/invalido.json");
        orch.execution_history
            .push(nikto_execution(invalid, "succeeded"));

        orch.build_findings();

        assert!(orch.findings.is_empty());
        let execution = &orch.execution_history[0];
        assert_eq!(execution.status, "failed");
        assert!(execution
            .execution_error
            .as_deref()
            .is_some_and(|error| error.contains("JSON do Nikto inválido")));
    }

    #[test]
    fn a_nikto_target_without_a_web_server_is_reported_as_an_execution_error() {
        let mut orch = Orchestrator::new(make_config()).expect("configuração de teste válida");
        let diagnostic = include_str!("../../tests/fixtures/nikto/sem_servidor.json");
        // O Nikto termina com exit status 0 mesmo sem encontrar servidor web.
        orch.execution_history
            .push(nikto_execution(diagnostic, "succeeded"));

        orch.build_findings();

        assert!(
            orch.findings.is_empty(),
            "diagnóstico do Nikto não pode virar vulnerabilidade: {:?}",
            orch.findings
        );
        let execution = &orch.execution_history[0];
        assert_eq!(execution.status, "failed");
        assert!(execution
            .execution_error
            .as_deref()
            .is_some_and(|error| { error.contains("não encontrou servidor web") }));
    }

    #[test]
    fn a_nikto_failure_keeps_the_original_execution_error() {
        let mut orch = Orchestrator::new(make_config()).expect("configuração de teste válida");
        let mut execution = nikto_execution(
            "[ERRO] O container smartsec-abc encerrou com status 125",
            "failed:125",
        );
        execution.execution_error =
            Some("O container smartsec-abc encerrou com status 125".to_string());
        orch.execution_history.push(execution);

        orch.build_findings();

        let stored = &orch.execution_history[0];
        assert_eq!(stored.status, "failed:125");
        assert!(stored
            .execution_error
            .as_deref()
            .is_some_and(|error| error.contains("encerrou com status 125")));
        assert!(orch.findings.is_empty());
    }

    #[test]
    fn a_nikto_timeout_is_kept_as_timeout_and_produces_no_findings() {
        let mut orch = Orchestrator::new(make_config()).expect("configuração de teste válida");
        let timeout = "[ERRO] O container smartsec-abc excedeu o tempo limite de 15 minutos.";
        let mut execution = nikto_execution(timeout, "timeout");
        execution.execution_error = Some(timeout.to_string());
        orch.execution_history.push(execution);

        orch.build_findings();

        let stored = &orch.execution_history[0];
        assert_eq!(stored.status, "timeout");
        assert!(stored
            .execution_error
            .as_deref()
            .is_some_and(|error| error.contains("tempo limite")));
        assert!(orch.findings.is_empty());
    }

    fn zap_execution(output: &str, status: &str) -> SecurityTool {
        let mut execution = SecurityTool::new(
            "ZAP",
            "zap.sh -Xmx1024m -cmd -autorun /zap/automation/scan.yaml -config spider.scope=http://test.local",
        );
        execution.output = output.to_string();
        execution.status = status.to_string();
        execution
    }

    #[test]
    fn build_findings_uses_the_zap_parser_registered_for_the_builtin_tool() {
        let mut orch = Orchestrator::new(make_config()).expect("configuração de teste válida");
        let report = include_str!("../../tests/fixtures/zap/relatorio.json");
        orch.execution_history
            .push(zap_execution(report, "succeeded"));

        orch.build_findings();

        assert_eq!(orch.findings.len(), 4);
        assert!(orch.findings.iter().all(|f| f.tool == "ZAP"));
        assert!(orch
            .findings
            .iter()
            .all(|f| f.source == crate::domain::vulnerability::FindingSource::Real));
        // A severidade vem do riskcode do ZAP, não do texto do alerta.
        assert_eq!(orch.findings[0].severity, crate::domain::Severity::Medium);
        assert_eq!(orch.findings[2].severity, crate::domain::Severity::Low);
        assert!(orch.findings[0]
            .evidence
            .contains("url: http://169.254.1.2:3000/"));
        assert!(orch
            .execution_history
            .iter()
            .all(|execution| execution.execution_error.is_none()));
    }

    #[test]
    fn invalid_zap_output_marks_the_execution_as_failed() {
        let mut orch = Orchestrator::new(make_config()).expect("configuração de teste válida");
        let invalid = include_str!("../../tests/fixtures/zap/invalido.json");
        orch.execution_history
            .push(zap_execution(invalid, "succeeded"));

        orch.build_findings();

        assert!(orch.findings.is_empty());
        let execution = &orch.execution_history[0];
        assert_eq!(execution.status, "failed");
        assert!(execution
            .execution_error
            .as_deref()
            .is_some_and(|error| error.contains("JSON do ZAP inválido")));
    }

    #[test]
    fn a_zap_missing_artifact_is_kept_as_an_execution_error() {
        let mut orch = Orchestrator::new(make_config()).expect("configuração de teste válida");
        let mut execution = zap_execution(
            "artefato /smartsec-out/zap-report.json não coletado",
            "failed",
        );
        execution.execution_error = Some(
            "o container /smartsec-out/zap-report.json não gerou o relatório; revise o trace do Podman e o plano de automação da ferramenta"
                .to_string(),
        );
        orch.execution_history.push(execution);

        orch.build_findings();

        let stored = &orch.execution_history[0];
        assert_eq!(stored.status, "failed");
        assert!(stored
            .execution_error
            .as_deref()
            .is_some_and(|error| error.contains("não gerou o relatório")));
        // Uma saída que não é relatório nunca vira varredura limpa.
        assert!(orch.findings.is_empty());
    }

    #[test]
    fn a_zap_failure_keeps_the_original_execution_error() {
        let mut orch = Orchestrator::new(make_config()).expect("configuração de teste válida");
        let mut execution = zap_execution(
            "[ERRO] O container smartsec-abc encerrou com status 125",
            "failed:125",
        );
        execution.execution_error =
            Some("O container smartsec-abc encerrou com status 125".to_string());
        orch.execution_history.push(execution);

        orch.build_findings();

        let stored = &orch.execution_history[0];
        assert_eq!(stored.status, "failed:125");
        assert!(stored
            .execution_error
            .as_deref()
            .is_some_and(|error| error.contains("encerrou com status 125")));
        assert!(orch.findings.is_empty());
    }

    #[test]
    fn a_zap_timeout_is_kept_as_timeout_and_produces_no_findings() {
        let mut orch = Orchestrator::new(make_config()).expect("configuração de teste válida");
        let timeout = "[ERRO] O container smartsec-abc excedeu o tempo limite de 15 minutos.";
        let mut execution = zap_execution(timeout, "timeout");
        execution.execution_error = Some(timeout.to_string());
        orch.execution_history.push(execution);

        orch.build_findings();

        let stored = &orch.execution_history[0];
        assert_eq!(stored.status, "timeout");
        assert!(stored
            .execution_error
            .as_deref()
            .is_some_and(|error| error.contains("tempo limite")));
        assert!(orch.findings.is_empty());
    }

    #[test]
    fn nmap_and_nuclei_results_are_unchanged_by_the_nikto_parser() {
        let mut orch = Orchestrator::new(make_config()).expect("configuração de teste válida");

        let mut nmap = SecurityTool::new("Nmap", "nmap -Pn -sT -sV -oX - http://test.local");
        nmap.output = include_str!("../../tests/fixtures/nmap_open.xml").to_string();
        orch.execution_history.push(nmap);

        let mut nuclei = SecurityTool::new("Nuclei", "nuclei -u test.local -jsonl");
        nuclei.output = concat!(
            r#"{"template-id":"http-missing-security-headers","info":{"name":"HTTP Missing Security Headers","severity":"info"},"matched-at":"http://test.local","matcher-name":"content-security-policy"}"#,
            "\n"
        )
        .to_string();
        orch.execution_history.push(nuclei);

        orch.build_findings();

        assert_eq!(orch.findings.len(), 2);
        let nmap_finding = orch
            .findings
            .iter()
            .find(|finding| finding.tool == "Nmap")
            .expect("o achado do Nmap deve continuar presente");
        let nuclei_finding = orch
            .findings
            .iter()
            .find(|finding| finding.tool == "Nuclei")
            .expect("o achado do Nuclei deve continuar presente");
        assert!(nmap_finding.evidence.contains("porta=3000/tcp"));
        assert_eq!(
            nuclei_finding.title,
            "Cabeçalho de segurança ausente — content-security-policy"
        );
        assert!(orch
            .execution_history
            .iter()
            .all(|execution| execution.execution_error.is_none()));
    }

    /// Medido em produção: uma pasta de templates baixada por zip não tem
    /// `.git`, a validação falhava com "encontrado" vazio e o operador não
    /// sabia o que fazer; a mensagem agora diz o remédio.
    #[test]
    fn a_templates_dir_that_is_not_a_git_clone_explains_itself() {
        let dir =
            std::env::temp_dir().join(format!("smartsec-templates-sem-git-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        let error = validate_templates(&dir, Some("b98e6097cb84e73e7a480436062d685a8f898824"))
            .unwrap_err()
            .to_string();

        assert!(error.contains("não é um clone git"), "{error}");
        assert!(error.contains("docs/INSTALACAO.md"), "{error}");
        std::fs::remove_dir_all(&dir).ok();
    }
}
