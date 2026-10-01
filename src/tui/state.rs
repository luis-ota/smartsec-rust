use crate::ai::agent::AIAgent;
use crate::config::execution_type::ExecutionType;
use crate::config::llm_config::LlmProviderKind;
use crate::config::Configuration;
use crate::domain::security_tool::SecurityTool;
use crate::domain::vulnerability::Vulnerability;
use crate::orchestrator::control::RunControl;
use crate::orchestrator::decision::DecisionRecord;
use crate::orchestrator::Orchestrator;
use crate::tools::registry::RunnerKind;
use crate::tools::ToolManifest;
use crate::tui::interaction::{FocusTarget, HitRegion, SemanticAction};
use ratatui::layout::Rect;
use ratatui::text::{Line, Text};
use ratatui::widgets::{Paragraph, Wrap};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::{TryRecvError, TrySendError};
use tokio::task::JoinHandle;

/// Capacidade do canal de eventos da execução.
///
/// Política de drop (documentada em TCC_SPEC.md, seção 7): eventos de
/// controle (`ToolStarted`, `ToolFinished`, `Completed`) são enviados com
/// `send().await` e **nunca** são descartados; o fluxo apenas sofre
/// contrapressão até a TUI drenar o canal, o que acontece a cada quadro, mesmo
/// com uma camada sobreposta aberta. Linhas de log (`ToolLog`) usam
/// `try_send`: sob saturação a linha é descartada e contada em
/// `log_drop_counter`, para que a memória do executor permaneça limitada e a
/// tela nunca trave. A contagem é exibida ao usuário.
const RUN_EVENT_CAPACITY: usize = 256;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AppStep {
    Splash,
    ToolSelect,
    Execution,
    Analysis,
    Results,
    History,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ToolStatus {
    Pending,
    Running,
    /// Container real pausado com `podman pause` (REQ14).
    Paused,
    Done,
    #[allow(dead_code)]
    Failed,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[allow(dead_code)]
pub enum ResultAction {
    ExportMd,
    ExplainDidactic,
    BackToSummary,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AnalysisPhase {
    /// As ferramentas selecionadas ainda estão em execução.
    Scanning,
    /// Os achados foram construídos pelos parsers e estão prontos para a IA.
    Correlating,
    /// A chamada de análise por IA está em andamento.
    Generating,
    Complete,
}

/// Origem de uma ocorrência registrada durante a execução.
///
/// A TUI não reconstrói nem reclassifica erros: cada registro guarda a etapa
/// do pipeline que o produziu, para que a tela diga de onde veio a falha.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RunIssueScope {
    Tool,
    Audit,
    Ai,
    Executor,
    Validation,
    Export,
}

impl RunIssueScope {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Tool => "ferramenta",
            Self::Audit => "auditoria",
            Self::Ai => "IA",
            Self::Executor => "executor",
            Self::Validation => "validação",
            Self::Export => "exportação",
        }
    }

    /// Ocorrências de IA são avisos de proveniência (falha da LLM principal,
    /// uso do modelo local alternativo, resposta descartada por contrato): não
    /// interrompem a execução e não contam como falha.
    pub const fn is_warning(self) -> bool {
        matches!(self, Self::Ai)
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RunIssue {
    pub scope: RunIssueScope,
    pub detail: String,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AiActivity {
    WaitingForEvidence,
    PlanningNuclei,
    PlanReady,
    GeneratingGuidance,
    Complete,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SettingsField {
    Provider,
    BaseUrl,
    ApiKey,
    Model,
    Timeout,
    Retries,
    RemoteConsent,
    FallbackEnabled,
    FallbackBaseUrl,
    FallbackModel,
    /// Diretório do projeto analisado pelo agente de código (issue #76).
    ///
    /// Vive na tela de configurações ao lado do provedor porque é o campo que
    /// decide **o que** o agente de código pode ler: trocá-lo muda o escopo da
    /// fase de análise, e escondê-lo em outro lugar tornaria essa mudança
    /// invisível justamente onde o operador decide o que será lido.
    ProjectDir,
}

pub struct ToolItem {
    pub tool: ToolManifest,
    pub runner: RunnerKind,
    pub selected: bool,
    /// Estado real da ferramenta no pipeline. Não há porcentagem sintética: o
    /// orquestrador só emite `ToolStarted` e `ToolFinished`, e é essa a
    /// informação de progresso que existe.
    pub status: ToolStatus,
}

enum RunEvent {
    ToolStarted(usize),
    /// O container em execução mudou de estado por pausa, retomada ou
    /// cancelamento pedido pelo usuário.
    ToolControl(RunControl),
    ToolLog(String),
    AiDecisionStarted,
    AiDecisionFinished(DecisionRecord),
    ToolFinished {
        index: usize,
        execution: Box<SecurityTool>,
    },
    /// Os parsers concluíram `build_findings`: os achados existem de fato.
    FindingsBuilt {
        count: usize,
    },
    AnalysisProgress {
        elapsed_secs: u64,
    },
    /// Linha de resumo da correlação e do enriquecimento CVE/NVD.
    EnrichmentSummary(String),
    Completed {
        orchestrator: Box<Orchestrator>,
        audit_log: Result<PathBuf, String>,
    },
}

pub struct AppState {
    pub config: Configuration,
    pub orchestrator: Orchestrator,
    pub agent: AIAgent,
    pub step: AppStep,
    pub screen_area: Rect,
    pub should_quit: bool,
    pub tick: u64,
    pub spinner_idx: usize,
    pub tools: Vec<ToolItem>,
    pub tool_cursor: usize,
    pub tool_scroll: usize,
    pub tool_visible_height: usize,
    pub exec_current: usize,
    pub exec_tick: u64,
    pub exec_logs: Vec<String>,
    pub log_scroll: usize,
    pub log_visible_height: usize,
    /// Largura interna usada na última renderização do log (para medir a quebra).
    pub log_width: u16,
    /// Total de linhas visuais do log após a quebra automática do `Paragraph`.
    pub log_total_lines: usize,
    /// Auto-follow do final do log; desligado quando o usuário sobe no histórico.
    pub log_follow: bool,
    pub analysis_phase: AnalysisPhase,
    /// Quantidade de achados já construída pelos parsers no pipeline real.
    pub analysis_findings: usize,
    pub analysis_wait_secs: u64,
    pub ai_activity: AiActivity,
    pub ai_decision: Option<DecisionRecord>,
    pub result_cursor: usize,
    pub result_scroll: usize,
    pub result_detail_vuln: Option<usize>,
    pub detail_scroll: usize,
    pub detail_max_scroll: usize,
    pub md_exported: bool,
    pub exported_report_path: Option<PathBuf>,
    /// Caminho do PDF gerado junto com o Markdown (REQ18).
    pub exported_pdf_path: Option<PathBuf>,
    pub show_report_viewer: bool,
    pub report_content: String,
    pub report_scroll: usize,
    pub report_max_scroll: usize,
    pub show_trace_overlay: bool,
    pub show_didactic: bool,
    pub didactic_scroll: usize,
    pub didactic_max_scroll: usize,
    pub show_settings: bool,
    pub settings_field: SettingsField,
    pub settings_provider_idx: usize,
    pub settings_input_base_url: String,
    pub settings_input_api_key: String,
    pub settings_input_model: String,
    pub settings_input_timeout: String,
    pub settings_input_retries: String,
    pub settings_remote_consent: bool,
    pub settings_fallback_enabled: bool,
    pub settings_input_fallback_base_url: String,
    pub settings_input_fallback_model: String,
    pub settings_input_project_dir: String,
    pub settings_api_key_touched: bool,
    pub settings_error: Option<String>,
    /// Problema de configuracao detectado na abertura da TUI, antes de qualquer
    /// execucao. Vive separado de `settings_error` porque nasce do
    /// carregamento e nao de uma tentativa de salvar, e porque um continua
    /// valendo enquanto o outro so existe ate a proxima edicao.
    pub config_warning: Option<String>,
    pub llm_warning: Option<String>,
    pub audit_log_path: Option<PathBuf>,
    pub history: crate::orchestrator::scan_logger::ScanHistory,
    pub history_dir: PathBuf,
    pub history_cursor: usize,
    pub history_scroll: usize,
    pub history_detail: Option<crate::orchestrator::scan_logger::ScanMetadata>,
    pub history_detail_scroll: usize,
    pub history_detail_max_scroll: usize,
    pub history_error: Option<String>,
    pub history_return_step: AppStep,
    pub run_error: Option<String>,
    /// Aviso de indisponibilidade do enriquecimento CVE/NVD, exibido na TUI.
    pub enrichment_warning: Option<String>,
    /// Primeiro erro por natureza (usado nas linhas de status resumidas).
    /// Todas as ocorrências da execução, na ordem em que foram registradas.
    pub run_issues: Vec<RunIssue>,
    pub exec_cancelled: bool,
    /// Execução pausada com `podman pause`; a retomada usa `podman unpause`.
    pub exec_paused: bool,
    pub show_help_overlay: bool,
    pub show_command_palette: bool,
    pub command_cursor: usize,
    pub settings_scroll: usize,
    pub focus: FocusTarget,
    pub settings_return_focus: FocusTarget,
    pub overlay_return_focus: FocusTarget,
    pub didactic_return_focus: FocusTarget,
    pub hit_regions: Vec<HitRegion>,
    run_receiver: Option<mpsc::Receiver<RunEvent>>,
    run_task: Option<JoinHandle<()>>,
    /// Linhas de log descartadas por saturação do canal (política de drop).
    log_drop_counter: Arc<AtomicU64>,
}

impl AppState {
    /// Inicializa o estado da TUI validando a configuração de ferramentas; uma
    /// configuração inválida impede a entrada na interface com a mensagem
    /// acionável do registry.
    pub fn new(config: Configuration) -> anyhow::Result<Self> {
        let orchestrator = Orchestrator::new(config.clone())?;
        let agent = orchestrator.agent_handle();

        let tools = orchestrator
            .registry
            .tools()
            .iter()
            .map(|registered| ToolItem {
                tool: registered.manifest.clone(),
                runner: registered.runner,
                selected: true,
                status: ToolStatus::Pending,
            })
            .collect();

        let (provider_idx, base_url, api_key, model) = {
            let llm = &config.llm;
            let idx = match llm.provider {
                LlmProviderKind::Ollama => 0,
                LlmProviderKind::NvidiaNim => 1,
                LlmProviderKind::OpenAI => 2,
                LlmProviderKind::Custom => 3,
            };
            (
                idx,
                llm.base_url.clone(),
                llm.api_key.clone(),
                llm.model.clone(),
            )
        };
        let timeout = config.llm.timeout_secs.to_string();
        let retries = config.llm.max_retries.to_string();
        let remote_consent = config.llm.remote_consent;
        let fallback_enabled = config.llm.fallback_enabled;
        let fallback_base_url = config.llm.fallback_base_url.clone();
        let fallback_model = config.llm.fallback_model.clone();
        let project_dir = config
            .project_dir
            .clone()
            .unwrap_or_else(|| config.effective_project_dir().display().to_string());

        Ok(Self {
            config_warning: None,
            config,
            orchestrator,
            agent,
            step: AppStep::Splash,
            screen_area: Rect::default(),
            should_quit: false,
            tick: 0,
            spinner_idx: 0,
            tools,
            tool_cursor: 0,
            tool_scroll: 0,
            tool_visible_height: 8,
            exec_current: 0,
            exec_tick: 0,
            exec_logs: Vec::new(),
            log_scroll: 0,
            log_visible_height: 20,
            log_width: 80,
            log_total_lines: 0,
            log_follow: true,
            analysis_phase: AnalysisPhase::Scanning,
            analysis_findings: 0,
            analysis_wait_secs: 0,
            ai_activity: AiActivity::WaitingForEvidence,
            ai_decision: None,
            result_cursor: 0,
            result_scroll: 0,
            result_detail_vuln: None,
            detail_scroll: 0,
            detail_max_scroll: 0,
            md_exported: false,
            exported_report_path: None,
            exported_pdf_path: None,
            show_report_viewer: false,
            report_content: String::new(),
            report_scroll: 0,
            report_max_scroll: 0,
            show_trace_overlay: false,
            show_didactic: false,
            didactic_scroll: 0,
            didactic_max_scroll: 0,
            show_settings: false,
            settings_field: SettingsField::Provider,
            settings_provider_idx: provider_idx,
            settings_input_base_url: base_url,
            settings_input_api_key: api_key,
            settings_input_model: model,
            settings_input_timeout: timeout,
            settings_input_retries: retries,
            settings_remote_consent: remote_consent,
            settings_fallback_enabled: fallback_enabled,
            settings_input_fallback_base_url: fallback_base_url,
            settings_input_fallback_model: fallback_model,
            settings_input_project_dir: project_dir,
            settings_api_key_touched: false,
            settings_error: None,
            llm_warning: None,
            audit_log_path: None,
            history: crate::orchestrator::scan_logger::ScanHistory::default(),
            history_dir: crate::orchestrator::scan_logger::scans_dir(),
            history_cursor: 0,
            history_scroll: 0,
            history_detail: None,
            history_detail_scroll: 0,
            history_detail_max_scroll: 0,
            history_error: None,
            history_return_step: AppStep::Splash,
            run_error: None,
            enrichment_warning: None,
            run_issues: Vec::new(),
            exec_cancelled: false,
            exec_paused: false,
            show_help_overlay: false,
            show_command_palette: false,
            command_cursor: 0,
            settings_scroll: 0,
            focus: FocusTarget::SplashTarget,
            settings_return_focus: FocusTarget::SplashTarget,
            overlay_return_focus: FocusTarget::SplashTarget,
            didactic_return_focus: FocusTarget::SplashTarget,
            hit_regions: Vec::new(),
            run_receiver: None,
            run_task: None,
            log_drop_counter: Arc::new(AtomicU64::new(0)),
        })
    }

    pub fn begin_frame(&mut self, area: Rect) {
        self.screen_area = area;
        self.hit_regions.clear();
    }

    pub fn register_hit_region(&mut self, area: Rect, action: SemanticAction) {
        if area.width > 0 && area.height > 0 {
            self.hit_regions.push(HitRegion { area, action });
        }
    }

    pub fn action_at(&self, column: u16, row: u16) -> Option<SemanticAction> {
        self.hit_regions
            .iter()
            .rev()
            .find(|region| region.contains(column, row))
            .map(|region| region.action.clone())
    }

    pub fn mode(&self) -> ExecutionType {
        self.config.execution_type
    }

    pub fn set_mode(&mut self, mode: ExecutionType) {
        self.config.execution_type = mode;
    }

    /// Rótulo do estado real do container, lido do canal de controle.
    ///
    /// A tela de execução usa este rótulo para o indicador de pausa: a TUI e o
    /// executor compartilham o mesmo canal, então ele reflete o que o
    /// `podman pause`/`unpause` realmente fez, e não a intenção do usuário.
    pub fn run_control_label(&self) -> &'static str {
        self.orchestrator.control.label()
    }

    pub fn spinner_char(&self) -> &str {
        const SPINNERS: &[&str] = &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
        SPINNERS[self.spinner_idx % SPINNERS.len()]
    }

    /// Achados na ordem de leitura da tela: críticos primeiro (REQ15),
    /// preservando a ordem do pipeline dentro de cada severidade.
    ///
    /// O relatório Markdown continua usando `orchestrator.findings` na ordem
    /// original do pipeline; só a visão da TUI é ordenada por severidade.
    pub fn vulnerabilities(&self) -> Vec<Vulnerability> {
        let mut ordered = self.orchestrator.findings.clone();
        ordered.sort_by_key(|finding| severity_rank(finding.severity));
        ordered
    }

    /// Registra uma ocorrência da execução preservando todas as anteriores.
    ///
    /// `run_error` continua sendo o primeiro erro por natureza, usado nas linhas
    /// de status resumidas; `run_issues` é a lista completa exibida na tela de
    /// Execução e no resumo de Resultados.
    pub fn record_run_issue(&mut self, scope: RunIssueScope, detail: impl Into<String>) {
        let detail = detail.into();
        self.run_issues.push(RunIssue {
            scope,
            detail: detail.clone(),
        });
        if !scope.is_warning() {
            self.run_error.get_or_insert(detail);
        }
    }

    pub fn clear_run_issues(&mut self) {
        self.run_issues.clear();
        self.run_error = None;
    }

    pub fn has_run_issues(&self) -> bool {
        !self.run_issues.is_empty()
    }

    /// Linhas de log perdidas por saturação do canal (política de drop).
    pub fn dropped_log_lines(&self) -> u64 {
        self.log_drop_counter.load(Ordering::Relaxed)
    }

    /// Quantas ferramentas selecionadas já chegaram a um estado terminal real
    /// (`ToolFinished` emitido pelo orquestrador), contando as que falharam.
    pub fn finished_tools(&self) -> (usize, usize) {
        let finished = self
            .tools
            .iter()
            .filter(|tool| {
                tool.selected && matches!(tool.status, ToolStatus::Done | ToolStatus::Failed)
            })
            .count();
        let total = self.tools.iter().filter(|tool| tool.selected).count();
        (finished, total)
    }

    pub fn ai_summary(&self) -> &str {
        if self.agent.last_analysis.is_empty() {
            "[A análise por IA será executada após a varredura]"
        } else {
            &self.agent.last_analysis
        }
    }

    #[allow(dead_code)]
    pub fn agent_last_analysis(&self) -> &str {
        self.ai_summary()
    }

    pub fn tick(&mut self) {
        self.tick += 1;
        self.spinner_idx = (self.spinner_idx + 1) % 10;
        if self.has_blocking_layer() {
            return;
        }
        match self.mode() {
            ExecutionType::Auto => self.advance_auto(),
            ExecutionType::Assisted => self.advance_assisted(),
        }
    }

    /// Drena os eventos do pipeline real.
    ///
    /// Não há contagem de ticks: cada transição de tela acontece no evento que
    /// a justifica. O drain roda mesmo com uma camada sobreposta aberta, para
    /// que o canal limitado não acumule eventos enquanto o usuário está na
    /// ajuda ou nas configurações.
    pub async fn step_tick(&mut self) {
        self.process_run_events().await;
    }

    /// Indica se há uma camada sobreposta capturando a interação.
    ///
    /// Os atalhos de pausa e cancelamento são ignorados enquanto existe uma,
    /// para que `p` e `c` não virem ação dentro de um overlay.
    pub fn has_blocking_layer(&self) -> bool {
        self.show_settings
            || self.show_help_overlay
            || self.show_command_palette
            || self.show_report_viewer
            || self.show_trace_overlay
    }

    async fn process_run_events(&mut self) {
        let Some(mut receiver) = self.run_receiver.take() else {
            return;
        };
        let mut completed = false;
        let mut disconnected = false;
        loop {
            let event = match receiver.try_recv() {
                Ok(event) => event,
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    disconnected = true;
                    break;
                }
            };
            match event {
                RunEvent::ToolStarted(index) => {
                    self.exec_current = index;
                    self.tools[index].status = ToolStatus::Running;
                }
                RunEvent::ToolControl(control) => self.apply_run_control(control),
                RunEvent::ToolLog(line) => {
                    let prefix = self
                        .tools
                        .iter()
                        .find(|tool| tool.status == ToolStatus::Running)
                        .map(|tool| format!("[{}] ", tool.tool.name))
                        .unwrap_or_default();
                    let line = compact_operational_log(&line);
                    for part in line.split('\n') {
                        if part.trim().is_empty() {
                            continue;
                        }
                        self.exec_logs.push(format!("{prefix}{part}"));
                    }
                    const MAX_EXEC_LOGS: usize = 5000;
                    let overflow = self.exec_logs.len().saturating_sub(MAX_EXEC_LOGS);
                    if overflow > 0 {
                        let removed_rows =
                            visual_line_count(&self.exec_logs[..overflow], self.log_width);
                        self.exec_logs.drain(..overflow);
                        self.log_total_lines = self.log_total_lines.saturating_sub(removed_rows);
                        if !self.log_follow {
                            self.log_scroll = self.log_scroll.saturating_sub(removed_rows);
                        }
                    }
                }
                RunEvent::AiDecisionStarted => {
                    self.ai_activity = AiActivity::PlanningNuclei;
                }
                RunEvent::AiDecisionFinished(decision) => {
                    self.ai_activity = AiActivity::PlanReady;
                    self.ai_decision = Some(decision);
                }
                RunEvent::ToolFinished { index, execution } => {
                    let succeeded = execution.execution_error.is_none()
                        && matches!(execution.status.as_str(), "succeeded" | "skipped");
                    self.tools[index].status = if succeeded {
                        ToolStatus::Done
                    } else {
                        ToolStatus::Failed
                    };
                    if let Some(error) = &execution.execution_error {
                        self.record_run_issue(RunIssueScope::Tool, error.clone());
                        self.exec_logs.push(format!(
                            "[{}] FALHA após {:.1}s: {}",
                            self.tools[index].tool.name,
                            execution.duration_ms as f64 / 1_000.0,
                            error
                        ));
                    } else {
                        self.exec_logs.push(format!(
                            "[{}] OK em {:.1}s",
                            self.tools[index].tool.name,
                            execution.duration_ms as f64 / 1_000.0
                        ));
                    }
                    self.orchestrator.execution_history.push(*execution);
                }
                RunEvent::FindingsBuilt { count } => {
                    // Os parsers terminaram: os achados existem de fato e a
                    // análise por IA é a próxima etapa real do pipeline.
                    self.analysis_phase = AnalysisPhase::Correlating;
                    self.analysis_findings = count;
                    if self.step == AppStep::Execution {
                        self.step = AppStep::Analysis;
                        self.focus = FocusTarget::AnalysisCancel;
                    }
                }
                RunEvent::AnalysisProgress { elapsed_secs } => {
                    self.ai_activity = AiActivity::GeneratingGuidance;
                    if self.analysis_phase == AnalysisPhase::Correlating {
                        self.analysis_phase = AnalysisPhase::Generating;
                    }
                    self.analysis_wait_secs = elapsed_secs;
                    if elapsed_secs % 10 == 0 {
                        self.exec_logs
                            .push(format!("[ia] análise em andamento… ({elapsed_secs}s)"));
                    }
                }
                RunEvent::EnrichmentSummary(line) => {
                    // A indisponibilidade da NVD precisa ser visível na TUI,
                    // não silenciosa: a linha já carrega a causa em pt-BR.
                    self.exec_logs.push(format!("[cve/nvd] {line}"));
                    if line.contains("indisponível") {
                        self.enrichment_warning = Some(line.clone());
                    }
                }
                RunEvent::Completed {
                    orchestrator,
                    audit_log,
                } => {
                    self.orchestrator = *orchestrator;
                    let agent_history = self.orchestrator.agent.execution_history.clone();
                    for detail in &agent_history {
                        let detail = crate::utils::redaction::sanitize_text(detail);
                        self.exec_logs.push(format!("[ia] {detail}"));
                        // Ponto de ligação com o serviço de análise com
                        // provenance (issue #23): toda entrada de
                        // `agent.execution_history` vira uma ocorrência visível.
                        self.record_run_issue(RunIssueScope::Ai, detail);
                    }
                    self.llm_warning = agent_history
                        .first()
                        .map(|detail| crate::utils::redaction::sanitize_text(detail));
                    // Cada `ToolFinished` já registrou a falha da ferramenta; aqui o
                    // histórico final apenas confirma o estado exibido.
                    for execution in &self.orchestrator.execution_history {
                        if execution.execution_error.is_none() {
                            continue;
                        }
                        if let Some(tool) = self
                            .tools
                            .iter_mut()
                            .find(|tool| tool.tool.name == execution.tool_name)
                        {
                            tool.status = ToolStatus::Failed;
                        }
                    }
                    self.sync_agent_from_orchestrator();
                    match audit_log {
                        Ok(path) => {
                            self.exec_logs
                                .push(format!("[auditoria] Log salvo em {}", path.display()));
                            self.audit_log_path = Some(path);
                        }
                        Err(error) => {
                            self.record_run_issue(RunIssueScope::Audit, error.clone());
                            self.exec_logs
                                .push(format!("[auditoria] FALHA ao salvar log: {error}"));
                        }
                    }
                    self.analysis_phase = AnalysisPhase::Complete;
                    self.ai_activity = AiActivity::Complete;
                    self.analysis_findings = self.orchestrator.findings.len();
                    // A análise acabou de verdade: sem espera artificial, os
                    // resultados já podem ser revisados.
                    self.step = AppStep::Results;
                    self.focus = FocusTarget::ResultsList;
                    completed = true;
                }
            }
        }
        self.follow_latest_log();
        if completed {
            self.run_task.take();
        } else if disconnected {
            // O `JoinHandle` do executor nunca é aguardado dentro do laço de
            // eventos: o canal já desconectou porque o executor terminou ou
            // foi abortado, e o diagnóstico vem do estado real das ferramentas.
            if let Some(task) = self.run_task.take() {
                task.abort();
            }
            let running = self
                .tools
                .iter()
                .find(|tool| tool.status == ToolStatus::Running)
                .map(|tool| tool.tool.name.clone());
            let detail = match running {
                Some(name) => format!("o executor encerrou durante a execução de {name}"),
                None => "o executor encerrou sem concluir a análise".to_string(),
            };
            self.record_run_issue(RunIssueScope::Executor, detail.clone());
            if let Some(tool) = self
                .tools
                .iter_mut()
                .find(|tool| tool.status == ToolStatus::Running)
            {
                tool.status = ToolStatus::Failed;
            }
            self.exec_logs.push(format!("[executor] FALHA: {detail}"));
            self.step = AppStep::Results;
            self.focus = FocusTarget::ResultsList;
        } else {
            self.run_receiver = Some(receiver);
        }
    }

    /// Reflete na tela o estado do container que o executor realmente aplicou.
    fn apply_run_control(&mut self, control: RunControl) {
        let index = self
            .tools
            .iter()
            .position(|tool| matches!(tool.status, ToolStatus::Running | ToolStatus::Paused));
        match control {
            RunControl::Running => {
                self.exec_paused = false;
                if let Some(tool) = index.map(|index| &mut self.tools[index]) {
                    tool.status = ToolStatus::Running;
                }
            }
            RunControl::Paused => {
                self.exec_paused = true;
                if let Some(tool) = index
                    .map(|index| &mut self.tools[index])
                    .filter(|tool| tool.status == ToolStatus::Running)
                {
                    tool.status = ToolStatus::Paused;
                }
            }
            RunControl::Cancelled => {
                self.exec_paused = false;
            }
        }
    }

    fn follow_latest_log(&mut self) {
        if !self.log_follow {
            return;
        }
        self.log_scroll = self.log_max_scroll();
    }

    /// Limite de scroll considerando as linhas visuais após a quebra automática.
    ///
    /// Antes do primeiro render `log_total_lines` ainda é zero; nesse caso a
    /// quantidade de entradas serve como piso para nunca perder linhas.
    pub fn log_max_scroll(&self) -> usize {
        let total = self.log_total_lines.max(self.exec_logs.len());
        total
            .saturating_sub(self.log_visible_height.max(1))
            .min(u16::MAX as usize)
    }

    fn advance_auto(&mut self) {
        match self.step {
            AppStep::Splash => {}
            // O modo automático inicia a execução sozinho, mas nunca refaz uma
            // execução que o usuário acabou de cancelar: reiniciar é decisão
            // dele, e o cancelamento é registrado na auditoria.
            AppStep::ToolSelect if !self.exec_cancelled => self.start_selected_tools(),
            AppStep::ToolSelect | AppStep::Results => {}
            AppStep::Execution => {
                self.advance_execution();
            }
            // A tela de Análise é movida pelos eventos do pipeline real
            // (`FindingsBuilt` e `Completed`); nada a avançar por contagem.
            AppStep::Analysis => {}
            AppStep::History => {}
        }
    }

    fn advance_assisted(&mut self) {
        match self.step {
            AppStep::Execution => self.advance_execution(),
            AppStep::Analysis => self.advance_execution(),
            _ => {}
        }
    }

    /// Inicia a execução das ferramentas selecionadas.
    ///
    /// Não existe "detecção de catálogo" na TUI: o catálogo vem do registry de
    /// forma síncrona em `AppState::new`, portanto a listagem já está pronta
    /// quando a tela aparece e a execução começa na primeira decisão real do
    /// usuário (modo assistido) ou no primeiro quadro (modo automático).
    pub fn start_selected_tools(&mut self) {
        if self.step != AppStep::ToolSelect || !self.tools.iter().any(|tool| tool.selected) {
            return;
        }
        self.step = AppStep::Execution;
        self.focus = FocusTarget::ExecutionLogs;
        self.init_execution();
    }

    pub fn init_execution(&mut self) {
        for t in &mut self.tools {
            if t.selected {
                t.status = ToolStatus::Pending;
            }
        }
        self.exec_current = 0;
        self.exec_tick = 0;
        self.exec_logs.clear();
        self.log_scroll = 0;
        self.log_total_lines = 0;
        self.log_follow = true;
        self.exec_cancelled = false;
        self.exec_paused = false;
        let registry = self.orchestrator.registry.clone();
        self.orchestrator = Orchestrator::with_registry(self.config.clone(), registry.clone());
        // A task de execução e a TUI compartilham o mesmo canal de controle,
        // para que a pausa e o cancelamento atinjam o container real.
        let control = self.orchestrator.control.clone();
        self.audit_log_path = None;
        self.clear_run_issues();
        self.llm_warning = None;

        self.analysis_phase = AnalysisPhase::Scanning;
        self.analysis_findings = 0;
        self.analysis_wait_secs = 0;
        self.ai_activity = AiActivity::WaitingForEvidence;
        self.ai_decision = None;
        self.log_drop_counter.store(0, Ordering::Relaxed);

        let selected: Vec<_> = self
            .tools
            .iter()
            .enumerate()
            .filter(|(_, tool)| tool.selected)
            .map(|(index, tool)| (index, tool.tool.clone(), tool.runner))
            .collect();
        self.config.active_tools = selected
            .iter()
            .map(|(_, tool, _)| tool.name.to_string())
            .collect();
        let config = self.config.clone();
        let target = config.target_url.clone();
        let (sender, receiver) = mpsc::channel(RUN_EVENT_CAPACITY);
        self.run_receiver = Some(receiver);
        let dropped = Arc::clone(&self.log_drop_counter);
        self.run_task = Some(tokio::spawn(async move {
            let mut orchestrator = Orchestrator::with_registry(config, registry);
            // A task precisa do MESMO canal da TUI: cada `Orchestrator::new`
            // criaria o seu, e a pausa da tela nunca chegaria ao container.
            orchestrator.control = control.clone();
            let control_events = control.subscribe();
            for (index, tool, runner) in selected {
                let is_nuclei = runner == RunnerKind::Nuclei;
                if sender.send(RunEvent::ToolStarted(index)).await.is_err() {
                    return;
                }
                if is_nuclei && sender.send(RunEvent::AiDecisionStarted).await.is_err() {
                    return;
                }
                // Aplica o estado pendente (pausa ou cancelamento pedido antes
                // de a ferramenta começar) e reflete cada mudança na tela.
                let control_task = {
                    let sender = sender.clone();
                    let control_events = control_events.clone();
                    tokio::spawn(async move {
                        let mut control_events = control_events;
                        // O estado corrente é aplicado de imediato: uma pausa
                        // pedida antes de a ferramenta começar não pode ser
                        // perdida por esperar a próxima mudança.
                        let mut state = *control_events.borrow_and_update();
                        loop {
                            if sender.send(RunEvent::ToolControl(state)).await.is_err() {
                                return;
                            }
                            if control_events.changed().await.is_err() {
                                return;
                            }
                            state = *control_events.borrow_and_update();
                        }
                    })
                };
                let (trace_tx, mut trace_rx) = mpsc::unbounded_channel::<String>();
                orchestrator.trace_sink = Some(trace_tx);
                let forwarder = tokio::spawn({
                    let sender = sender.clone();
                    let dropped = Arc::clone(&dropped);
                    async move {
                        while let Some(line) = trace_rx.recv().await {
                            // Política de drop: log nunca bloqueia o executor.
                            match sender.try_send(RunEvent::ToolLog(line)) {
                                Ok(()) => {}
                                Err(TrySendError::Full(_)) => {
                                    dropped.fetch_add(1, Ordering::Relaxed);
                                }
                                Err(TrySendError::Closed(_)) => break,
                            }
                        }
                    }
                });
                let decision_forwarder = if is_nuclei {
                    let (decision_tx, mut decision_rx) = mpsc::unbounded_channel();
                    orchestrator.decision_sink = Some(decision_tx);
                    Some(tokio::spawn({
                        let sender = sender.clone();
                        async move {
                            if let Some(decision) = decision_rx.recv().await {
                                let _ = sender.send(RunEvent::AiDecisionFinished(decision)).await;
                            }
                        }
                    }))
                } else {
                    None
                };
                let execution = orchestrator.execute_tool(&tool, &target).await;
                orchestrator.trace_sink = None;
                orchestrator.decision_sink = None;
                control_task.abort();
                let _ = forwarder.await;
                if let Some(forwarder) = decision_forwarder {
                    let _ = forwarder.await;
                }
                if sender
                    .send(RunEvent::ToolFinished {
                        index,
                        execution: Box::new(execution),
                    })
                    .await
                    .is_err()
                {
                    return;
                }
                // Regra automática de interrupção (REQ05): decide entre
                // ferramentas para não descartar a evidência recém-coletada.
                if let Some(reason) = orchestrator.interrupt_after_findings(tool.name.as_str()) {
                    orchestrator.record_interruption(reason);
                    break;
                }
                if orchestrator.is_cancelled() {
                    break;
                }
            }
            orchestrator.build_findings();
            orchestrator.correlate_and_enrich_findings().await;
            for line in orchestrator.enrichment.lines_pt_br() {
                let _ = sender.send(RunEvent::EnrichmentSummary(line)).await;
            }
            // Quantos achados o pipeline produziu de fato: e este evento, e nao
            // uma contagem de quadros, que move a tela de Análise.
            let findings = orchestrator.findings.len();
            if sender
                .send(RunEvent::FindingsBuilt { count: findings })
                .await
                .is_err()
            {
                return;
            }
            if let Some(reason) = orchestrator.interruption() {
                // Execução interrompida: a auditoria do que já foi coletado vem
                // primeiro, e a IA não é chamada — o operador pediu para parar.
                orchestrator.last_log = reason.message;
                let audit_log = orchestrator
                    .persist_scan_log()
                    .map_err(|error| error.to_string());
                let _ = sender
                    .send(RunEvent::Completed {
                        orchestrator: Box::new(orchestrator),
                        audit_log,
                    })
                    .await;
                return;
            }
            let heartbeat = tokio::spawn({
                let sender = sender.clone();
                async move {
                    let _ = sender
                        .send(RunEvent::AnalysisProgress { elapsed_secs: 0 })
                        .await;
                    let mut elapsed_secs = 0u64;
                    loop {
                        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                        elapsed_secs += 2;
                        if sender
                            .send(RunEvent::AnalysisProgress { elapsed_secs })
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                }
            });
            orchestrator.analyze_findings().await;
            // A fase do agente de código roda depois da análise de logs, pela
            // mesma razão do headless: os achados precisam existir e já estar
            // classificados. O heartbeat continua vivo para que a TUI não fique
            // parada durante a exploração do projeto.
            orchestrator.analyze_code().await;
            heartbeat.abort();
            let audit_log = orchestrator
                .persist_scan_log()
                .map_err(|error| error.to_string());
            let _ = sender
                .send(RunEvent::Completed {
                    orchestrator: Box::new(orchestrator),
                    audit_log,
                })
                .await;
        }));
    }

    pub fn advance_execution(&mut self) {
        if self.exec_cancelled || self.orchestrator.is_cancelled() {
            self.exec_paused = false;
            self.step = AppStep::ToolSelect;
            self.focus = FocusTarget::ToolList;
        }
    }

    /// O relatório usa os achados na ordem do pipeline; a ordenação por
    /// severidade é uma escolha de leitura da tela (REQ15) e não altera o
    /// contrato do relatório.
    pub fn export_md(&self) -> String {
        crate::report::ReportGenerator::compile_report_with_enrichment(
            &self.config,
            &self.orchestrator.findings,
            &self.orchestrator.decision_history,
            &self.orchestrator.enrichment,
            Some(&self.config.effective_project_dir()),
            &self.orchestrator.last_log,
            &self.failed_executions(),
        )
    }

    /// Execuções que terminaram em erro, para a seção de falhas do relatório.
    pub fn failed_executions(&self) -> Vec<SecurityTool> {
        self.orchestrator
            .execution_history
            .iter()
            .filter(|execution| execution.execution_error.is_some())
            .cloned()
            .collect()
    }

    pub fn visible_settings_fields(&self) -> Vec<SettingsField> {
        let mut fields = vec![
            SettingsField::Provider,
            SettingsField::BaseUrl,
            SettingsField::Model,
        ];
        if self.settings_connection_is_remote() {
            fields.extend([SettingsField::ApiKey, SettingsField::RemoteConsent]);
        }
        fields.extend([
            SettingsField::Timeout,
            SettingsField::Retries,
            SettingsField::FallbackEnabled,
        ]);
        fields.push(SettingsField::ProjectDir);
        if self.settings_fallback_enabled {
            fields.extend([SettingsField::FallbackBaseUrl, SettingsField::FallbackModel]);
        }
        fields
    }

    pub fn settings_connection_is_remote(&self) -> bool {
        let provider =
            LlmProviderKind::from_label(LlmProviderKind::all_labels()[self.settings_provider_idx]);
        let mut llm = self.config.llm.clone();
        llm.provider = provider;
        llm.base_url = self.settings_input_base_url.trim().to_string();
        llm.is_remote()
    }

    /// Registra (ou limpa) o aviso de configuracao da abertura.
    pub fn set_config_warning(&mut self, warning: Option<String>) {
        self.config_warning = warning.filter(|text| !text.trim().is_empty());
    }

    /// O aviso mais urgente entre erro de salvamento e problema de abertura.
    pub fn settings_status_error(&self) -> Option<&str> {
        self.settings_error
            .as_deref()
            .or(self.config_warning.as_deref())
    }

    pub fn apply_settings(&mut self) -> Result<(), String> {
        let provider =
            LlmProviderKind::from_label(LlmProviderKind::all_labels()[self.settings_provider_idx]);
        let timeout = self
            .settings_input_timeout
            .trim()
            .parse::<u64>()
            .map_err(|_| "Informe um tempo limite inteiro entre 1 e 45 segundos".to_string())?;
        let retries = self
            .settings_input_retries
            .trim()
            .parse::<u8>()
            .map_err(|_| "Informe uma quantidade de tentativas entre 0 e 3".to_string())?;
        let mut candidate = self.config.clone();
        candidate.llm.provider = provider;
        candidate.llm.base_url = if self.settings_input_base_url.trim().is_empty() {
            provider.default_base_url().to_string()
        } else {
            self.settings_input_base_url.trim().to_string()
        };
        candidate.llm.api_key = self.settings_input_api_key.clone();
        candidate.llm.model = if self.settings_input_model.trim().is_empty() {
            provider.default_model().to_string()
        } else {
            self.settings_input_model.trim().to_string()
        };
        candidate.llm.timeout_secs = timeout;
        candidate.llm.max_retries = retries;
        candidate.llm.remote_consent = self.settings_remote_consent;
        candidate.llm.fallback_enabled = self.settings_fallback_enabled;
        candidate.llm.fallback_base_url = self.settings_input_fallback_base_url.trim().to_string();
        candidate.llm.fallback_model = self.settings_input_fallback_model.trim().to_string();
        candidate.llm.validate()?;
        // O diretório do projeto é validado pelo mesmo sandbox que o agente vai
        // usar: aceitar na tela um caminho que a fase rejeitaria entregaria ao
        // operador a impressão de que a análise de código está configurada.
        let project = self.settings_input_project_dir.trim().to_string();
        let project_path = if project.is_empty() {
            PathBuf::from(".")
        } else {
            PathBuf::from(&project)
        };
        crate::code_agent::workspace::Workspace::open(&project_path)
            .map_err(|error| format!("Diretório do projeto inválido: {error}"))?;
        candidate.project_dir = Some(project);
        candidate.save()?;
        self.config = candidate;
        self.reset_settings_draft();
        self.show_settings = false;
        // Uma configuracao valida foi salva: o aviso de abertura perdeu o
        // objeto e sai, para que a proxima execucao comece limpa.
        self.config_warning = None;
        Ok(())
    }

    pub fn reset_settings_draft(&mut self) {
        self.settings_provider_idx = match self.config.llm.provider {
            LlmProviderKind::Ollama => 0,
            LlmProviderKind::NvidiaNim => 1,
            LlmProviderKind::OpenAI => 2,
            LlmProviderKind::Custom => 3,
        };
        self.settings_input_base_url = self.config.llm.base_url.clone();
        self.settings_input_api_key = self.config.llm.api_key.clone();
        self.settings_input_model = self.config.llm.model.clone();
        self.settings_input_timeout = self.config.llm.timeout_secs.to_string();
        self.settings_input_retries = self.config.llm.max_retries.to_string();
        self.settings_remote_consent = self.config.llm.remote_consent;
        self.settings_fallback_enabled = self.config.llm.fallback_enabled;
        self.settings_input_fallback_base_url = self.config.llm.fallback_base_url.clone();
        self.settings_input_fallback_model = self.config.llm.fallback_model.clone();
        self.settings_input_project_dir = self
            .config
            .project_dir
            .clone()
            .unwrap_or_else(|| self.config.effective_project_dir().display().to_string());
        self.settings_api_key_touched = false;
        self.settings_error = None;
        self.settings_scroll = 0;
        if !self
            .visible_settings_fields()
            .contains(&self.settings_field)
        {
            self.settings_field = SettingsField::Provider;
        }
    }

    /// Cancela a execução em andamento pelo canal de controle compartilhado,
    /// tanto na varredura quanto na análise da IA.
    ///
    /// O container é encerrado de forma cooperativa (`podman stop` seguido de
    /// `podman rm --force`) pelo executor; a task **não** é abortada às cegas,
    /// porque isso impediria a limpeza e a persistência da auditoria. O
    /// cancelamento na tela de Análise também precisa existir: sem isso o
    /// operador ficaria preso na espera pela resposta do modelo.
    pub fn cancel_run(&mut self) {
        if !matches!(self.step, AppStep::Execution | AppStep::Analysis) || self.exec_cancelled {
            return;
        }
        self.exec_cancelled = true;
        self.exec_paused = false;
        self.orchestrator.cancel_execution();
        // A ferramenta em execucao e marcada como cancelada, e nao como falha:
        // o operador pediu para parar, e a distincao importa no relatorio e na
        // auditoria tanto quanto importa na tela.
        if let Some(tool) = self
            .tools
            .iter_mut()
            .find(|tool| matches!(tool.status, ToolStatus::Running | ToolStatus::Paused))
        {
            let name = tool.tool.name.clone();
            tool.status = ToolStatus::Failed;
            self.exec_logs
                .push(format!("[cancelled] {name} CANCELADA pelo operador"));
        }
        self.exec_logs
            .push("X Cancelamento solicitado; encerrando o container".to_string());
        // A auditoria e gravada agora, e nao quando a task termina: o
        // cancelamento e uma decisao do operador e precisa estar registrada
        // mesmo que o container demore a encerrar.
        self.persist_cancelled_run();
        self.follow_latest_log();
    }

    /// Pausa a ferramenta em execução (`podman pause` no container real).
    pub fn pause_run(&mut self) {
        if self.step != AppStep::Execution || self.exec_cancelled || self.exec_paused {
            return;
        }
        self.orchestrator.pause_execution();
        self.exec_paused = true;
        if let Some(tool) = self
            .tools
            .iter_mut()
            .find(|tool| tool.status == ToolStatus::Running)
        {
            tool.status = ToolStatus::Paused;
        }
        self.exec_logs
            .push("‖ Pausa solicitada; o container será pausado".to_string());
        self.follow_latest_log();
    }

    /// Retoma a ferramenta pausada (`podman unpause` no container real).
    pub fn resume_run(&mut self) {
        if self.step != AppStep::Execution || self.exec_cancelled || !self.exec_paused {
            return;
        }
        self.orchestrator.resume_execution();
        self.exec_paused = false;
        if let Some(tool) = self
            .tools
            .iter_mut()
            .find(|tool| tool.status == ToolStatus::Paused)
        {
            tool.status = ToolStatus::Running;
        }
        self.exec_logs
            .push("‖ Retomada solicitada; o container será retomado".to_string());
        self.follow_latest_log();
    }

    /// Encerra a execução antes de sair da TUI, sem deixar container órfão.
    pub async fn shutdown_run(&mut self) {
        if self.run_task.is_none() {
            return;
        }
        if !self.exec_cancelled {
            self.orchestrator.cancel_execution();
        }
        if let Some(task) = self.run_task.take() {
            let completed = tokio::time::timeout(std::time::Duration::from_secs(30), async {
                let _ = task.await;
            })
            .await
            .is_ok();
            if !completed {
                // O executor cooperativo não respondeu: o `abort` é o último
                // recurso, e o guard `ContainerCleanup` ainda remove o
                // container parcial no encerramento da task.
                self.run_error = Some(
                    "A execução não respondeu ao cancelamento e foi interrompida; \
                     confirme com `podman ps -a` que não restou container."
                        .to_string(),
                );
            }
        }
        self.run_receiver = None;
        self.persist_cancelled_run();
    }

    /// Persiste a execução sintética de cancelamento para auditoria.
    ///
    /// A TUI **não** executa nenhum scanner para isso: o registro é fabricado a
    /// partir do estado da tela e serve apenas para deixar claro, no log
    /// estruturado, qual ferramenta estava em execução quando o operador
    /// cancelou. O registro real do container vem do executor, com o trace do
    /// Podman, e é combinado a este.
    fn persist_cancelled_run(&mut self) {
        self.orchestrator.record_interruption(
            crate::orchestrator::control::InterruptionReason::user_cancelled(),
        );
        if let Some(tool) = self.tools.iter().find(|tool| {
            matches!(
                tool.status,
                ToolStatus::Running | ToolStatus::Paused | ToolStatus::Failed
            )
        }) {
            let already_recorded = self
                .orchestrator
                .execution_history
                .iter()
                .any(|execution| execution.status == "cancelled");
            if !already_recorded {
                let mut execution = SecurityTool::new(
                    &tool.tool.name,
                    &format!("{} {}", tool.tool.name, self.config.target_url),
                );
                execution.executed_at =
                    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
                execution.status = "cancelled".to_string();
                execution.execution_error = Some("Execução cancelada pelo usuário".to_string());
                self.orchestrator.execution_history.push(execution);
            }
        }
        if self.orchestrator.last_log.is_empty() {
            self.orchestrator.last_log = "Execução cancelada pelo usuário".to_string();
        }
        match self.orchestrator.persist_scan_log() {
            Ok(path) => self.audit_log_path = Some(path),
            Err(error) => self.record_run_issue(
                RunIssueScope::Audit,
                format!("Execução cancelada; falha ao salvar auditoria: {error}"),
            ),
        }
    }

    pub fn sync_agent_from_orchestrator(&mut self) {
        self.agent.last_analysis = self.orchestrator.last_log.clone();
    }

    /// Carrega o histórico de execuções gravados em disco.
    ///
    /// A leitura não altera nenhum artefato original; registros ilegíveis ficam
    /// em [`ScanHistory::unreadable`](crate::orchestrator::scan_logger::ScanHistory)
    /// e são exibidos ao usuário em vez de sumirem.
    pub fn load_history(&mut self) {
        match crate::orchestrator::scan_logger::list_scan_logs_from_dir(&self.history_dir) {
            Ok(history) => {
                self.history = history;
                self.history_error = None;
            }
            Err(error) => {
                self.history = crate::orchestrator::scan_logger::ScanHistory::default();
                self.history_error = Some(format!("{error:#}"));
            }
        }
        self.history_cursor = self
            .history_cursor
            .min(self.history.records.len().saturating_sub(1));
        self.history_scroll = 0;
    }

    /// Abre o histórico a partir da tela atual, preservando a tela de retorno.
    pub fn open_history(&mut self) {
        self.load_history();
        self.history_return_step = self.step;
        self.history_detail = None;
        self.history_detail_scroll = 0;
        self.history_detail_max_scroll = 0;
        self.step = AppStep::History;
        self.focus = FocusTarget::HistoryList;
    }

    /// Abre o detalhe da execução selecionada, somente leitura.
    pub fn open_history_record(&mut self, index: usize) {
        let Some(record) = self.history.records.get(index).cloned() else {
            self.history_error =
                Some("A execução selecionada não está mais disponível.".to_string());
            return;
        };
        match crate::orchestrator::scan_logger::load_scan_log_from_file(&record.file_path) {
            Ok(metadata) => {
                self.history_error = None;
                self.history_cursor = index;
                self.history_detail = Some(metadata);
                self.history_detail_scroll = 0;
                self.history_detail_max_scroll = 0;
                self.focus = FocusTarget::HistoryDetail;
            }
            Err(error) => {
                self.history_detail = None;
                self.history_error = Some(format!(
                    "Não foi possível abrir {}: {error:#}",
                    record.scan_id
                ));
                self.focus = FocusTarget::HistoryList;
            }
        }
    }

    /// Motivo pelo qual um achado ficou sem origem no código.
    ///
    /// O texto vem do relatório da fase, indexado pela posição do achado, e é
    /// sanitizado porque é um diagnóstico que pode carregar detalhe do
    /// transporte do provedor.
    pub fn code_reason_for_index(&self, index: usize) -> Option<String> {
        self.orchestrator
            .last_code_report
            .as_ref()?
            .findings
            .iter()
            .find(|item| item.finding_index == index)
            .and_then(|item| item.reason.clone())
            .map(|reason| crate::utils::redaction::sanitize_diagnostic(&reason))
    }

    /// Motivo registrado para o achado atualmente aberto no painel de detalhe.
    pub fn code_reason_fallback(&self) -> Option<String> {
        self.code_reason_for_index(self.result_detail_vuln?)
    }

    /// Diretório do projeto analisado pela fase de código, para exibição.
    pub fn project_dir_label(&self) -> String {
        crate::utils::redaction::sanitize_text(
            &self.config.effective_project_dir().display().to_string(),
        )
    }
}

/// Ordem de leitura dos achados: a severidade do scanner é autoritativa
/// (TCC_SPEC.md, seção 7) e a tela apenas a ordena para destacar os críticos.
fn severity_rank(severity: crate::domain::Severity) -> u8 {
    match severity {
        crate::domain::Severity::Critical => 0,
        crate::domain::Severity::High => 1,
        crate::domain::Severity::Medium => 2,
        crate::domain::Severity::Low => 3,
        crate::domain::Severity::Info => 4,
    }
}

/// Conta as linhas visuais de entradas que saíram do log, usando a mesma
/// quebra do `Paragraph` aplicada na renderização. Sem isso, o ajuste do
/// offset no descarte misturaria unidades lógicas e visuais.
fn visual_line_count(lines: &[String], width: u16) -> usize {
    if lines.is_empty() || width == 0 {
        return 0;
    }
    let text = Text::from(
        lines
            .iter()
            .map(|line| Line::from(line.as_str()))
            .collect::<Vec<_>>(),
    );
    Paragraph::new(text)
        .wrap(Wrap { trim: false })
        .line_count(width)
}

fn compact_operational_log(line: &str) -> String {
    let Some(json_start) = line.find('{') else {
        return line.chars().take(600).collect();
    };
    let Ok(json) = serde_json::from_str::<serde_json::Value>(&line[json_start..]) else {
        return line.chars().take(600).collect();
    };
    let Some(template_id) = json.get("template-id").and_then(|value| value.as_str()) else {
        return line.chars().take(600).collect();
    };
    let matcher = json
        .get("matcher-name")
        .and_then(|value| value.as_str())
        .unwrap_or_default();
    let title = crate::orchestrator::nuclei_parser::localized_nuclei_title(template_id, matcher);
    let severity = crate::domain::Severity::from_label(
        json.pointer("/info/severity")
            .and_then(|value| value.as_str())
            .unwrap_or("info"),
    )
    .label_pt_br();
    let endpoint = json
        .get("matched-at")
        .or_else(|| json.get("url"))
        .and_then(|value| value.as_str())
        .map(crate::utils::redaction::sanitize_url)
        .unwrap_or_else(|| "endpoint não informado".to_string());
    let timestamp = &line[..json_start];
    format!("{timestamp}achado · {severity} · {title} · {endpoint}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::vulnerability::FindingSource;
    use crate::domain::Severity;

    fn app() -> AppState {
        AppState::new(Configuration::default()).expect("configuração de teste válida")
    }

    /// Mesmo canal limitado que `init_execution` cria para o executor real.
    fn run_channel() -> (mpsc::Sender<RunEvent>, mpsc::Receiver<RunEvent>) {
        mpsc::channel(RUN_EVENT_CAPACITY)
    }

    async fn feed(app: &mut AppState, sender: &mpsc::Sender<RunEvent>, event: RunEvent) {
        sender.send(event).await.expect("canal aberto");
        app.process_run_events().await;
    }

    fn finding(severity: Severity, title: &str) -> Vulnerability {
        Vulnerability {
            title: title.to_string(),
            severity,
            description: "Descrição".to_string(),
            tool: "Nmap".to_string(),
            recommendation: "Revise".to_string(),
            didactic: "Explicação".to_string(),
            source: FindingSource::Real,
            target: "http://target.local".to_string(),
            evidence: "porta 22 aberta".to_string(),
            detected_at: "2026-09-04T14:00:00Z".to_string(),
            ..Default::default()
        }
    }

    fn orchestrator_with(findings: Vec<Vulnerability>, agent_history: Vec<&str>) -> Orchestrator {
        let mut orchestrator = Orchestrator::new(Configuration::default()).expect("orquestrador");
        orchestrator.findings = findings;
        orchestrator
            .agent
            .execution_history
            .extend(agent_history.into_iter().map(str::to_string));
        orchestrator.last_log = "Análise concluída: 2 achados".to_string();
        orchestrator
    }

    fn failed_execution(tool: &str, error: &str) -> SecurityTool {
        let mut execution = SecurityTool::new(tool, &format!("{tool} http://target.local"));
        execution.status = "failed".to_string();
        execution.duration_ms = 1_500;
        execution.execution_error = Some(error.to_string());
        execution
    }

    fn succeeded_execution(tool: &str) -> SecurityTool {
        let mut execution = SecurityTool::new(tool, &format!("{tool} http://target.local"));
        execution.status = "succeeded".to_string();
        execution.duration_ms = 2_500;
        execution
    }

    #[test]
    fn compacts_nuclei_jsonl_for_the_live_log() {
        let line = r#"[12:00:00] {"template-id":"headers","info":{"name":"Cabeçalhos ausentes","severity":"info"},"matched-at":"http://target.local/path?token=secret","request":"segredo","response":"segredo"}"#;

        let compact = compact_operational_log(line);

        assert!(
            compact.contains("achado · INFORMATIVA · Achado identificado pelo Nuclei — headers")
        );
        assert!(compact.contains("http://target.local/path"));
        assert!(!compact.contains("request"));
        assert!(!compact.contains("response"));
        assert!(!compact.contains("secret"));
    }

    /// Sequência ponta a ponta do pipeline real: início, log, fim, achados,
    /// análise e conclusão. Nenhuma contagem de ticks participa.
    #[tokio::test]
    async fn the_real_event_sequence_reaches_the_results_screen() {
        let mut app = app();
        app.step = AppStep::Execution;
        let (sender, receiver) = run_channel();
        app.run_receiver = Some(receiver);

        let producer = tokio::spawn(async move {
            for event in [
                RunEvent::ToolStarted(0),
                RunEvent::ToolLog("[12:00:01] $ podman create --name smartsec-nmap".to_string()),
                RunEvent::ToolFinished {
                    index: 0,
                    execution: Box::new(succeeded_execution("Nmap")),
                },
                RunEvent::FindingsBuilt { count: 2 },
                RunEvent::AnalysisProgress { elapsed_secs: 0 },
            ] {
                sender.send(event).await.expect("canal aberto");
            }
            sender
                .send(RunEvent::Completed {
                    orchestrator: Box::new(orchestrator_with(
                        vec![
                            finding(Severity::Info, "Versão exposta"),
                            finding(Severity::Critical, "Shell remota aberta"),
                        ],
                        Vec::new(),
                    )),
                    audit_log: Ok(PathBuf::from("/tmp/scan.json")),
                })
                .await
                .expect("canal aberto");
        });
        producer.await.expect("produtor de eventos");

        app.step_tick().await;
        app.step_tick().await;

        assert_eq!(
            app.step,
            AppStep::Results,
            "a análise concluída abre os resultados"
        );
        assert_eq!(app.focus, FocusTarget::ResultsList);
        assert_eq!(app.analysis_phase, AnalysisPhase::Complete);
        assert_eq!(app.tools[0].status, ToolStatus::Done);
        assert_eq!(app.analysis_findings, 2);
        assert_eq!(app.audit_log_path, Some(PathBuf::from("/tmp/scan.json")));
        assert!(app
            .exec_logs
            .iter()
            .any(|line| line.contains("podman create")));
        assert!(app
            .exec_logs
            .iter()
            .any(|line| line.contains("[Nmap] OK em 2.5s")));
        assert!(!app.run_issues.is_empty() || app.run_error.is_none());
    }

    /// A cadência artificial sumiu: quantos quadros passem, a tela só muda
    /// quando o pipeline emite o evento correspondente.
    #[tokio::test]
    async fn the_analysis_transition_waits_for_the_pipeline_and_not_for_ticks() {
        let mut app = app();
        app.step = AppStep::Execution;
        let (sender, receiver) = run_channel();
        app.run_receiver = Some(receiver);

        for _ in 0..200 {
            app.step_tick().await;
        }
        assert_eq!(
            app.step,
            AppStep::Execution,
            "sem evento do pipeline a TUI não avança de tela"
        );
        assert_eq!(app.analysis_phase, AnalysisPhase::Scanning);

        feed(&mut app, &sender, RunEvent::FindingsBuilt { count: 3 }).await;
        assert_eq!(app.step, AppStep::Analysis);
        assert_eq!(app.analysis_phase, AnalysisPhase::Correlating);
        assert_eq!(app.analysis_findings, 3);

        feed(
            &mut app,
            &sender,
            RunEvent::AnalysisProgress { elapsed_secs: 2 },
        )
        .await;
        assert_eq!(
            app.analysis_phase,
            AnalysisPhase::Generating,
            "a fase da IA começa quando a chamada começa"
        );
        assert_eq!(app.analysis_wait_secs, 2);

        feed(
            &mut app,
            &sender,
            RunEvent::Completed {
                orchestrator: Box::new(orchestrator_with(
                    vec![finding(Severity::High, "Serviço administrativo")],
                    Vec::new(),
                )),
                audit_log: Ok(PathBuf::from("/tmp/scan.json")),
            },
        )
        .await;
        assert_eq!(
            app.step,
            AppStep::Results,
            "a análise terminou de verdade: sem espera de 30 ticks"
        );
        assert_eq!(app.analysis_phase, AnalysisPhase::Complete);
        assert_eq!(app.vulnerabilities().len(), 1);
    }

    /// Toda ocorrência é preservada: ferramenta, auditoria e IA.
    #[tokio::test]
    async fn tool_audit_and_ai_failures_are_all_reported() {
        let mut app = app();
        app.step = AppStep::Execution;
        let (sender, receiver) = run_channel();
        app.run_receiver = Some(receiver);

        feed(
            &mut app,
            &sender,
            RunEvent::ToolFinished {
                index: 0,
                execution: Box::new(failed_execution("Nmap", "imagem do container ausente")),
            },
        )
        .await;
        feed(
            &mut app,
            &sender,
            RunEvent::Completed {
                orchestrator: Box::new(orchestrator_with(
                    vec![finding(Severity::Critical, "Shell remota aberta")],
                    vec![
                        "A LLM principal falhou: conexão recusada",
                        "Usando o Ollama local configurado como alternativa",
                    ],
                )),
                audit_log: Err("sem permissão de escrita".to_string()),
            },
        )
        .await;

        let scopes: Vec<RunIssueScope> = app.run_issues.iter().map(|issue| issue.scope).collect();
        assert_eq!(
            scopes,
            vec![
                RunIssueScope::Tool,
                RunIssueScope::Ai,
                RunIssueScope::Ai,
                RunIssueScope::Audit
            ],
            "nenhuma origem pode ser omitida"
        );
        assert_eq!(app.tools[0].status, ToolStatus::Failed);
        assert_eq!(
            app.run_error.as_deref(),
            Some("imagem do container ausente"),
            "o status resumido aponta a primeira falha de execução"
        );
        assert!(
            app.llm_warning
                .is_some_and(|warning| warning.contains("A LLM principal falhou")),
            "o aviso de IA resume a causa raiz registrada pelo agente"
        );

        assert!(app
            .run_issues
            .iter()
            .any(|issue| issue.detail.contains("sem permissão de escrita")));
    }

    #[tokio::test]
    async fn analysis_progress_feeds_the_wait_indicator() {
        let mut app = app();
        app.step = AppStep::Execution;
        let (sender, receiver) = run_channel();
        app.run_receiver = Some(receiver);

        feed(
            &mut app,
            &sender,
            RunEvent::AnalysisProgress { elapsed_secs: 0 },
        )
        .await;
        assert_eq!(app.analysis_wait_secs, 0);
        assert!(app
            .exec_logs
            .last()
            .is_some_and(|line| line == "[ia] análise em andamento… (0s)"));

        feed(
            &mut app,
            &sender,
            RunEvent::AnalysisProgress { elapsed_secs: 2 },
        )
        .await;
        assert_eq!(app.analysis_wait_secs, 2);
        assert_eq!(app.exec_logs.len(), 1, "sem spam a cada heartbeat");

        feed(
            &mut app,
            &sender,
            RunEvent::AnalysisProgress { elapsed_secs: 10 },
        )
        .await;
        assert_eq!(app.analysis_wait_secs, 10);
        assert!(app
            .exec_logs
            .last()
            .is_some_and(|line| line == "[ia] análise em andamento… (10s)"));
    }

    #[tokio::test]
    async fn ai_events_expose_the_real_pipeline_stage() {
        let mut app = app();
        app.step = AppStep::Execution;
        let (sender, receiver) = run_channel();
        app.run_receiver = Some(receiver);

        feed(&mut app, &sender, RunEvent::AiDecisionStarted).await;
        assert_eq!(app.ai_activity, AiActivity::PlanningNuclei);

        let decision = crate::orchestrator::decision::decide_nuclei_plan(
            "http://target.local",
            None,
            None,
            "modelo-local",
        );
        feed(
            &mut app,
            &sender,
            RunEvent::AiDecisionFinished(decision.clone()),
        )
        .await;
        assert_eq!(app.ai_activity, AiActivity::PlanReady);
        assert_eq!(app.ai_decision.as_ref(), Some(&decision));

        feed(
            &mut app,
            &sender,
            RunEvent::AnalysisProgress { elapsed_secs: 2 },
        )
        .await;
        assert_eq!(app.ai_activity, AiActivity::GeneratingGuidance);
    }

    #[tokio::test]
    async fn run_events_update_progress_findings_and_audit_path() {
        let mut app = app();
        app.step = AppStep::Execution;
        let (sender, receiver) = run_channel();
        app.run_receiver = Some(receiver);

        feed(&mut app, &sender, RunEvent::ToolStarted(0)).await;
        assert_eq!(app.tools[0].status, ToolStatus::Running);
        assert!(app.exec_logs.is_empty());
        assert_eq!(
            app.finished_tools(),
            (0, app.tools.iter().filter(|tool| tool.selected).count()),
            "o progresso geral só conta ferramentas em estado terminal"
        );

        feed(
            &mut app,
            &sender,
            RunEvent::ToolLog("[12:00:01] $ podman create --name smartsec-test".to_string()),
        )
        .await;
        assert!(app.exec_logs[0].contains("$ podman create"));
        assert!(app.exec_logs[0].starts_with("[Nmap]"));

        feed(
            &mut app,
            &sender,
            RunEvent::ToolFinished {
                index: 0,
                execution: Box::new(succeeded_execution("Nmap")),
            },
        )
        .await;
        let mut orchestrator =
            Orchestrator::new(Configuration::default()).expect("configuração de teste válida");
        orchestrator.findings.push(Vulnerability {
            title: "Achado real".to_string(),
            severity: Severity::Info,
            description: "Descrição".to_string(),
            tool: "Nmap".to_string(),
            recommendation: "Revise".to_string(),
            didactic: "Explicação".to_string(),
            source: FindingSource::Real,
            target: "http://target.local".to_string(),
            evidence: "porta aberta".to_string(),
            detected_at: "2026-09-04T14:00:00Z".to_string(),
            origins: Vec::new(),
            enrichment: None,
            severity_conflict: None,
            ..Default::default()
        });
        orchestrator.last_log = "Análise real".to_string();
        let audit_path = PathBuf::from("/tmp/scan.json");
        feed(
            &mut app,
            &sender,
            RunEvent::Completed {
                orchestrator: Box::new(orchestrator_with(
                    vec![finding(Severity::Critical, "Achado real")],
                    Vec::new(),
                )),
                audit_log: Ok(audit_path.clone()),
            },
        )
        .await;

        assert_eq!(app.tools[0].status, ToolStatus::Done);
        assert_eq!(app.orchestrator.findings.len(), 1);
        assert_eq!(app.audit_log_path.as_ref(), Some(&audit_path));
        assert_eq!(app.step, AppStep::Results);
        assert_eq!(app.ai_activity, AiActivity::Complete);
        assert_eq!(app.run_error, None);
    }

    /// A lista da TUI põe os críticos no topo sem alterar a severidade do
    /// scanner (REQ15) e sem mexer na ordem do relatório.
    #[test]
    fn critical_findings_come_first_without_touching_severities() {
        let mut app = app();
        app.orchestrator.findings = vec![
            finding(Severity::Info, "Versão exposta"),
            finding(Severity::Medium, "Cabeçalho ausente"),
            finding(Severity::Critical, "Shell remota aberta"),
            finding(Severity::High, "Painel administrativo"),
        ];

        let ordered = app.vulnerabilities();
        let titles: Vec<&str> = ordered.iter().map(|item| item.title.as_str()).collect();

        assert_eq!(
            titles,
            vec![
                "Shell remota aberta",
                "Painel administrativo",
                "Cabeçalho ausente",
                "Versão exposta"
            ]
        );
        assert_eq!(
            app.orchestrator.findings[0].severity,
            Severity::Info,
            "o pipeline mantém a ordem original dos achados"
        );
        assert!(app.export_md().contains("Versão exposta"));
    }

    #[tokio::test]
    async fn disconnected_worker_surfaces_an_error_instead_of_hanging() {
        let mut app = app();
        app.step = AppStep::Execution;
        app.tools[0].status = ToolStatus::Running;
        let (sender, receiver) = run_channel();
        app.run_receiver = Some(receiver);
        app.run_task = Some(tokio::spawn(std::future::pending()));
        drop(sender);

        app.process_run_events().await;

        assert_eq!(app.step, AppStep::Results);
        assert_eq!(app.tools[0].status, ToolStatus::Failed);
        assert!(app.run_error.is_some());
        assert!(app
            .run_issues
            .iter()
            .any(|issue| issue.scope == RunIssueScope::Executor));
        assert!(app.run_task.is_none(), "o JoinHandle é liberado sem await");
    }

    #[test]
    fn cancel_run_stops_the_pipeline_and_keeps_the_audit() {
        let mut app = app();
        app.step = AppStep::Execution;
        app.tools[0].status = ToolStatus::Running;
        app.audit_log_path = None;

        app.cancel_run();

        assert!(app.exec_cancelled);
        assert!(app.orchestrator.control.is_cancelled());
        // O canal nao e descartado: o cancelamento e cooperativo, e o trace da
        // limpeza do container ainda chega pelo executor. O que impede um evento
        // tardio de reabrir a tela e a flag `exec_cancelled`, conferida acima e
        // respeitada por `advance_auto`.
        assert!(
            app.exec_cancelled,
            "o cancelamento precisa barrar o modo automatico"
        );
        assert!(app.exec_logs.iter().any(|line| line.contains("CANCELADA")));
        assert_eq!(
            app.orchestrator
                .execution_history
                .last()
                .map(|execution| execution.status.as_str()),
            Some("cancelled")
        );
        if let Some(path) = app.audit_log_path.clone() {
            let _ = std::fs::remove_file(path);
        }
    }

    /// O cancelamento precisa ser estável: no modo automático a execução não
    /// recomeça sozinha, e o reinício depende de uma ação do usuário.
    #[test]
    fn a_cancelled_run_does_not_restart_itself_in_automatic_mode() {
        let mut app = app();
        app.set_mode(crate::config::execution_type::ExecutionType::Auto);
        app.step = AppStep::Execution;
        app.tools[0].status = ToolStatus::Running;

        app.cancel_run();
        app.tick();

        assert_eq!(
            app.step,
            AppStep::ToolSelect,
            "o cancelamento leva à seleção e a execução não volta sozinha"
        );
        assert!(app.exec_cancelled);
        if let Some(path) = app.audit_log_path.clone() {
            let _ = std::fs::remove_file(path);
        }
    }

    #[tokio::test]
    async fn shutdown_run_aborts_the_executor_without_blocking() {
        let mut app = app();
        app.step = AppStep::Execution;
        app.tools[0].status = ToolStatus::Running;
        app.run_task = Some(tokio::spawn(std::future::pending()));

        app.shutdown_run().await;

        assert!(app.run_task.is_none());
        assert!(app.run_receiver.is_none());
        assert!(app.orchestrator.control.is_cancelled());
        if let Some(path) = app.audit_log_path.clone() {
            let _ = std::fs::remove_file(path);
        }
    }

    /// Sob saturação o log é descartado e contabilizado, nunca bloqueado: a
    /// teclado, o auto-follow e a renderização seguem reagindo.
    #[tokio::test]
    async fn log_pressure_drops_instead_of_blocking_and_is_reported() {
        let mut app = app();
        app.step = AppStep::Execution;
        app.focus = FocusTarget::ExecutionLogs;
        app.log_follow = true;
        let (sender, receiver) = run_channel();
        app.run_receiver = Some(receiver);
        app.log_drop_counter = Arc::new(AtomicU64::new(0));

        let mut delivered = 0usize;
        let mut dropped = 0u64;
        for index in 0..(RUN_EVENT_CAPACITY * 4) {
            match sender.try_send(RunEvent::ToolLog(format!("linha {index}"))) {
                Ok(()) => delivered += 1,
                Err(TrySendError::Full(_)) => dropped += 1,
                Err(TrySendError::Closed(_)) => panic!("canal fechado"),
            }
        }
        assert_eq!(delivered, RUN_EVENT_CAPACITY);
        assert!(dropped > 0);
        app.log_drop_counter.store(dropped, Ordering::Relaxed);

        app.step_tick().await;

        assert_eq!(app.exec_logs.len(), RUN_EVENT_CAPACITY);
        assert_eq!(app.dropped_log_lines(), dropped);
        assert_eq!(
            app.log_scroll,
            app.log_max_scroll(),
            "auto-follow preservado"
        );
        assert!(app.log_follow);
    }

    #[tokio::test]
    async fn new_log_lines_respect_manual_scroll_and_resume_following() {
        let mut app = app();
        app.step = AppStep::Execution;
        app.focus = FocusTarget::ExecutionLogs;
        app.log_visible_height = 10;
        app.log_total_lines = 100;
        app.log_follow = false;
        app.log_scroll = 5;
        let (sender, receiver) = run_channel();
        app.run_receiver = Some(receiver);

        feed(
            &mut app,
            &sender,
            RunEvent::ToolLog("nova linha".to_string()),
        )
        .await;
        assert_eq!(
            app.log_scroll, 5,
            "novas mensagens não podem puxar a tela após o usuário subir"
        );
        assert!(!app.log_follow);

        app.log_follow = true;
        feed(
            &mut app,
            &sender,
            RunEvent::ToolLog("outra linha".to_string()),
        )
        .await;
        assert_eq!(app.log_scroll, app.log_max_scroll());
        assert_eq!(app.log_scroll, 90);
    }

    #[tokio::test]
    async fn draining_old_entries_shifts_the_manual_scroll_by_visual_rows() {
        let mut app = app();
        app.step = AppStep::Execution;
        app.focus = FocusTarget::ExecutionLogs;
        app.log_visible_height = 10;
        app.log_width = 10;
        app.log_total_lines = 200;
        app.exec_logs = vec!["x".repeat(25); 5000];
        app.log_follow = false;
        app.log_scroll = 100;
        let (sender, receiver) = run_channel();
        app.run_receiver = Some(receiver);

        feed(
            &mut app,
            &sender,
            RunEvent::ToolLog("nova linha".to_string()),
        )
        .await;

        assert_eq!(app.exec_logs.len(), 5000);
        assert_eq!(
            app.log_scroll, 97,
            "o offset deve andar pelas linhas visuais removidas, não por entradas"
        );
        assert_eq!(app.log_total_lines, 197);
        assert!(!app.log_follow);
    }

    #[test]
    fn cancel_run_uses_the_control_channel_instead_of_aborting_the_task() {
        let mut app = AppState::new(Configuration::default()).expect("configuração válida");
        app.step = AppStep::Execution;
        app.tools[0].status = ToolStatus::Running;

        app.cancel_run();

        assert!(app.exec_cancelled);
        assert!(
            app.orchestrator.is_cancelled(),
            "o cancelamento precisa chegar ao container pelo canal compartilhado"
        );
        assert!(
            app.run_task.is_none(),
            "não existe task de execução fora da tela de execução"
        );
        let reason = app
            .orchestrator
            .interruption()
            .expect("o cancelamento precisa ser auditável");
        assert_eq!(reason.rule, "cancelado_pelo_usuario");
    }

    #[test]
    fn pause_and_resume_travel_through_the_shared_control_channel() {
        let mut app = AppState::new(Configuration::default()).expect("configuração válida");
        app.step = AppStep::Execution;
        app.tools[0].status = ToolStatus::Running;

        app.pause_run();
        assert!(app.orchestrator.control.is_paused());
        assert_eq!(app.tools[0].status, ToolStatus::Paused);

        // Pausar de novo não muda o pedido.
        app.pause_run();
        assert!(app.orchestrator.control.is_paused());

        app.resume_run();
        assert!(!app.orchestrator.control.is_paused());
        assert_eq!(app.tools[0].status, ToolStatus::Running);

        // O cancelamento encerra a linha: a retomada posterior é ignorada.
        app.cancel_run();
        app.resume_run();
        assert!(app.orchestrator.control.is_cancelled());
    }

    #[test]
    fn run_control_events_drive_the_visible_tool_status() {
        let mut app = AppState::new(Configuration::default()).expect("configuração válida");
        app.step = AppStep::Execution;
        app.tools[0].status = ToolStatus::Running;

        // O executor confirma a pausa de fato aplicada no container.
        app.apply_run_control(crate::orchestrator::control::RunControl::Paused);
        assert!(app.exec_paused);
        assert_eq!(app.tools[0].status, ToolStatus::Paused);

        app.apply_run_control(crate::orchestrator::control::RunControl::Running);
        assert!(!app.exec_paused);
        assert_eq!(app.tools[0].status, ToolStatus::Running);
    }

    #[test]
    fn the_cancelled_run_is_recorded_for_audit_without_creating_findings() {
        let mut app = AppState::new(Configuration::default()).expect("configuração válida");
        app.step = AppStep::Execution;
        app.tools[0].status = ToolStatus::Running;

        app.persist_cancelled_run();

        let cancelled: Vec<_> = app
            .orchestrator
            .execution_history
            .iter()
            .filter(|execution| execution.status == "cancelled")
            .collect();
        assert_eq!(cancelled.len(), 1, "um registro sintético por cancelamento");
        assert!(app.orchestrator.findings.is_empty());
        assert!(
            app.audit_log_path.is_some(),
            "a auditoria precisa ser gravada"
        );
        let log = std::fs::read_to_string(app.audit_log_path.as_ref().unwrap()).unwrap();
        assert!(log.contains("cancelado_pelo_usuario"), "{log}");
    }

    #[test]
    fn log_max_scroll_saturates_at_u16_range() {
        let mut app = app();
        app.log_total_lines = usize::MAX;
        app.log_visible_height = 1;

        assert_eq!(app.log_max_scroll(), u16::MAX as usize);
    }
}
