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
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TryRecvError;
use tokio::task::JoinHandle;

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
    Scanning,
    Correlating,
    Generating,
    Complete,
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
    pub status: ToolStatus,
    pub progress: u16,
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
    pub tool_detecting: bool,
    pub tool_detect_tick: u64,
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
    pub analysis_tick: u64,
    pub analysis_text: String,
    pub analysis_full_text: String,
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
    run_receiver: Option<mpsc::UnboundedReceiver<RunEvent>>,
    run_task: Option<JoinHandle<()>>,
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
                progress: 0,
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
            tool_detecting: true,
            tool_detect_tick: 0,
            exec_current: 0,
            exec_tick: 0,
            exec_logs: Vec::new(),
            log_scroll: 0,
            log_visible_height: 20,
            log_width: 80,
            log_total_lines: 0,
            log_follow: true,
            analysis_phase: AnalysisPhase::Scanning,
            analysis_tick: 0,
            analysis_text: String::new(),
            analysis_full_text: String::new(),
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

    pub fn vulnerabilities(&self) -> Vec<Vulnerability> {
        self.orchestrator.findings.clone()
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

    pub async fn step_tick(&mut self) {
        if self.has_blocking_layer() {
            return;
        }
        self.process_run_events().await;
        if self.step == AppStep::Analysis && self.analysis_phase == AnalysisPhase::Complete {
            if self.analysis_tick > 30 {
                self.step = AppStep::Results;
                self.focus = FocusTarget::ResultsList;
            }
            self.analysis_tick += 1;
        }
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
                    self.tools[index].progress = 100;
                    if let Some(error) = &execution.execution_error {
                        self.run_error.get_or_insert_with(|| error.clone());
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
                RunEvent::AnalysisProgress { elapsed_secs } => {
                    self.ai_activity = AiActivity::GeneratingGuidance;
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
                    let llm_detail = self.orchestrator.agent.execution_history.last().cloned();
                    if let Some(detail) = llm_detail {
                        let detail = crate::utils::redaction::sanitize_text(&detail);
                        self.exec_logs.push(format!("[ia] {detail}"));
                        self.llm_warning = Some(detail);
                    } else {
                        self.llm_warning = None;
                    }
                    for execution in &self.orchestrator.execution_history {
                        let Some(error) = &execution.execution_error else {
                            continue;
                        };
                        self.run_error.get_or_insert_with(|| error.clone());
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
                            self.run_error.get_or_insert_with(|| error.clone());
                            self.exec_logs
                                .push(format!("[auditoria] FALHA ao salvar log: {error}"));
                        }
                    }
                    self.analysis_full_text = self.orchestrator.last_log.clone();
                    self.analysis_text = self.analysis_full_text.clone();
                    self.analysis_phase = AnalysisPhase::Complete;
                    self.ai_activity = AiActivity::Complete;
                    self.analysis_tick = 0;
                    self.step = AppStep::Analysis;
                    self.focus = FocusTarget::AnalysisCancel;
                    completed = true;
                }
            }
        }
        self.follow_latest_log();
        if completed {
            self.run_task.take();
        } else if disconnected {
            let detail = match self.run_task.take() {
                Some(task) => match task.await {
                    Ok(()) => "o executor encerrou sem concluir a análise".to_string(),
                    Err(error) if error.is_panic() => {
                        "o executor interno falhou durante a análise".to_string()
                    }
                    Err(error) => format!("o executor interno foi interrompido: {error}"),
                },
                None => "o executor encerrou sem concluir a análise".to_string(),
            };
            self.run_error = Some(detail.clone());
            if let Some(tool) = self
                .tools
                .iter_mut()
                .find(|tool| tool.status == ToolStatus::Running)
            {
                tool.status = ToolStatus::Failed;
                tool.progress = 100;
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
            AppStep::ToolSelect => {
                if self.tool_detecting {
                    self.tool_detect_tick += 1;
                }
                if self.tool_detect_tick > 50 {
                    self.tool_detecting = false;
                    self.step = AppStep::Execution;
                    self.focus = FocusTarget::ExecutionLogs;
                    self.tool_detect_tick = 0;
                    self.exec_current = 0;
                    self.exec_tick = 0;
                    self.init_execution();
                }
            }
            AppStep::Execution => {
                self.advance_execution();
            }
            AppStep::Analysis => {
                self.advance_analysis();
            }
            AppStep::Results => {}
            AppStep::History => {}
        }
    }

    fn advance_assisted(&mut self) {
        if self.step == AppStep::ToolSelect && self.tool_detecting {
            self.tool_detect_tick += 1;
            if self.tool_detect_tick > 50 {
                self.tool_detecting = false;
                self.tool_detect_tick = 0;
            }
        }
        match self.step {
            AppStep::Execution => self.advance_execution(),
            AppStep::Analysis => self.advance_analysis(),
            _ => {}
        }
    }

    pub fn init_execution(&mut self) {
        for t in &mut self.tools {
            if t.selected {
                t.status = ToolStatus::Pending;
                t.progress = 0;
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
        self.run_error = None;
        self.llm_warning = None;

        self.analysis_phase = AnalysisPhase::Scanning;
        self.analysis_tick = 0;
        self.analysis_text.clear();
        self.analysis_full_text.clear();
        self.analysis_wait_secs = 0;
        self.ai_activity = AiActivity::WaitingForEvidence;
        self.ai_decision = None;

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
        let (sender, receiver) = mpsc::unbounded_channel();
        self.run_receiver = Some(receiver);
        self.run_task = Some(tokio::spawn(async move {
            let mut orchestrator = Orchestrator::with_registry(config, registry);
            // A task precisa do MESMO canal da TUI: cada `Orchestrator::new`
            // criaria o seu, e a pausa da tela nunca chegaria ao container.
            orchestrator.control = control.clone();
            let control_events = control.subscribe();
            for (index, tool, runner) in selected {
                let is_nuclei = runner == RunnerKind::Nuclei;
                if sender.send(RunEvent::ToolStarted(index)).is_err() {
                    return;
                }
                if is_nuclei && sender.send(RunEvent::AiDecisionStarted).is_err() {
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
                            if sender.send(RunEvent::ToolControl(state)).is_err() {
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
                    async move {
                        while let Some(line) = trace_rx.recv().await {
                            if sender.send(RunEvent::ToolLog(line)).is_err() {
                                break;
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
                                let _ = sender.send(RunEvent::AiDecisionFinished(decision));
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
                let _ = sender.send(RunEvent::EnrichmentSummary(line));
            }
            if let Some(reason) = orchestrator.interruption() {
                // Execução interrompida: a auditoria do que já foi coletado vem
                // primeiro, e a IA não é chamada — o operador pediu para parar.
                orchestrator.last_log = reason.message;
                let audit_log = orchestrator
                    .persist_scan_log()
                    .map_err(|error| error.to_string());
                let _ = sender.send(RunEvent::Completed {
                    orchestrator: Box::new(orchestrator),
                    audit_log,
                });
                return;
            }
            let heartbeat = tokio::spawn({
                let sender = sender.clone();
                async move {
                    let _ = sender.send(RunEvent::AnalysisProgress { elapsed_secs: 0 });
                    let mut elapsed_secs = 0u64;
                    loop {
                        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                        elapsed_secs += 2;
                        if sender
                            .send(RunEvent::AnalysisProgress { elapsed_secs })
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
            let _ = sender.send(RunEvent::Completed {
                orchestrator: Box::new(orchestrator),
                audit_log,
            });
        }));
    }

    pub fn advance_execution(&mut self) {
        if self.exec_cancelled || self.orchestrator.is_cancelled() {
            self.exec_paused = false;
            self.step = AppStep::ToolSelect;
            self.focus = FocusTarget::ToolList;
        }
    }

    fn advance_analysis(&mut self) {
        self.analysis_tick += 1;
        let total_chars = self.analysis_full_text.chars().count();
        let visible = (self.analysis_tick as usize * 5).min(total_chars);
        self.analysis_text = self.analysis_full_text.chars().take(visible).collect();
        if visible >= total_chars {
            match self.analysis_phase {
                AnalysisPhase::Scanning => {
                    self.analysis_phase = AnalysisPhase::Correlating;
                    self.analysis_tick = 0;
                }
                AnalysisPhase::Correlating => {
                    self.analysis_phase = AnalysisPhase::Generating;
                    self.analysis_tick = 0;
                }
                AnalysisPhase::Generating => {
                    self.analysis_phase = AnalysisPhase::Complete;
                    self.analysis_tick = 0;
                }
                AnalysisPhase::Complete => {}
            }
        }
    }

    pub fn export_md(&self) -> String {
        crate::report::ReportGenerator::compile_report_with_enrichment(
            &self.config,
            &self.vulnerabilities(),
            &self.orchestrator.decision_history,
            &self.orchestrator.enrichment,
            Some(&self.config.effective_project_dir()),
        )
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

    /// Cancela a execução em andamento pelo canal de controle compartilhado.
    ///
    /// O container é encerrado de forma cooperativa (`podman stop` seguido de
    /// `podman rm --force`) pelo executor; a task **não** é abortada às cegas,
    /// porque isso impediria a limpeza e a persistência da auditoria.
    pub fn cancel_run(&mut self) {
        if self.step != AppStep::Execution || self.exec_cancelled {
            return;
        }
        self.exec_cancelled = true;
        self.exec_paused = false;
        self.orchestrator.cancel_execution();
        if let Some(tool) = self
            .tools
            .iter_mut()
            .find(|tool| matches!(tool.status, ToolStatus::Running | ToolStatus::Paused))
        {
            tool.status = ToolStatus::Failed;
        }
        self.exec_logs
            .push("X Cancelamento solicitado; encerrando o container".to_string());
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
            Err(error) => {
                self.run_error = Some(format!(
                    "Execução cancelada; falha ao salvar auditoria: {error}"
                ))
            }
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

    #[tokio::test]
    async fn analysis_progress_feeds_the_wait_indicator() {
        let mut app =
            AppState::new(Configuration::default()).expect("configuração de teste válida");
        app.step = AppStep::Execution;
        let (sender, receiver) = mpsc::unbounded_channel();
        app.run_receiver = Some(receiver);

        sender
            .send(RunEvent::AnalysisProgress { elapsed_secs: 0 })
            .unwrap();
        app.process_run_events().await;
        assert_eq!(app.analysis_wait_secs, 0);
        assert!(app
            .exec_logs
            .last()
            .is_some_and(|line| line == "[ia] análise em andamento… (0s)"));

        sender
            .send(RunEvent::AnalysisProgress { elapsed_secs: 2 })
            .unwrap();
        app.process_run_events().await;
        assert_eq!(app.analysis_wait_secs, 2);
        assert_eq!(app.exec_logs.len(), 1, "sem spam a cada heartbeat");

        sender
            .send(RunEvent::AnalysisProgress { elapsed_secs: 10 })
            .unwrap();
        app.process_run_events().await;
        assert_eq!(app.analysis_wait_secs, 10);
        assert!(app
            .exec_logs
            .last()
            .is_some_and(|line| line == "[ia] análise em andamento… (10s)"));
    }

    #[tokio::test]
    async fn ai_events_expose_the_real_pipeline_stage() {
        let mut app =
            AppState::new(Configuration::default()).expect("configuração de teste válida");
        app.step = AppStep::Execution;
        let (sender, receiver) = mpsc::unbounded_channel();
        app.run_receiver = Some(receiver);

        sender.send(RunEvent::AiDecisionStarted).unwrap();
        app.process_run_events().await;
        assert_eq!(app.ai_activity, AiActivity::PlanningNuclei);

        let decision = crate::orchestrator::decision::decide_nuclei_plan(
            "http://target.local",
            None,
            None,
            "modelo-local",
        );
        sender
            .send(RunEvent::AiDecisionFinished(decision.clone()))
            .unwrap();
        app.process_run_events().await;
        assert_eq!(app.ai_activity, AiActivity::PlanReady);
        assert_eq!(app.ai_decision.as_ref(), Some(&decision));

        sender
            .send(RunEvent::AnalysisProgress { elapsed_secs: 2 })
            .unwrap();
        app.process_run_events().await;
        assert_eq!(app.ai_activity, AiActivity::GeneratingGuidance);
    }

    #[tokio::test]
    async fn run_events_update_progress_findings_and_audit_path() {
        let mut app =
            AppState::new(Configuration::default()).expect("configuração de teste válida");
        app.step = AppStep::Execution;
        let (sender, receiver) = mpsc::unbounded_channel();
        app.run_receiver = Some(receiver);

        sender.send(RunEvent::ToolStarted(0)).unwrap();
        app.process_run_events().await;
        assert_eq!(app.tools[0].status, ToolStatus::Running);
        assert!(app.exec_logs.is_empty());

        sender
            .send(RunEvent::ToolLog(
                "[12:00:01] $ podman create --name smartsec-test".to_string(),
            ))
            .unwrap();
        app.process_run_events().await;
        assert!(app.exec_logs[0].contains("$ podman create"));
        assert!(app.exec_logs[0].starts_with("[Nmap]"));

        sender
            .send(RunEvent::ToolFinished {
                index: 0,
                execution: Box::new({
                    let mut execution = SecurityTool::new("Nmap", "nmap target.local");
                    execution.status = "succeeded".to_string();
                    execution.duration_ms = 1_500;
                    execution
                }),
            })
            .unwrap();
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
        sender
            .send(RunEvent::Completed {
                orchestrator: Box::new(orchestrator),
                audit_log: Ok(audit_path.clone()),
            })
            .unwrap();

        app.process_run_events().await;

        assert_eq!(app.tools[0].status, ToolStatus::Done);
        assert_eq!(app.orchestrator.findings.len(), 1);
        assert_eq!(app.audit_log_path.as_ref(), Some(&audit_path));
        assert_eq!(app.step, AppStep::Analysis);
        assert_eq!(app.ai_activity, AiActivity::Complete);
    }

    #[tokio::test]
    async fn disconnected_worker_surfaces_an_error_instead_of_hanging() {
        let mut app =
            AppState::new(Configuration::default()).expect("configuração de teste válida");
        app.step = AppStep::Execution;
        app.tools[0].status = ToolStatus::Running;
        let (sender, receiver) = mpsc::unbounded_channel();
        app.run_receiver = Some(receiver);
        drop(sender);

        app.process_run_events().await;

        assert_eq!(app.step, AppStep::Results);
        assert_eq!(app.tools[0].status, ToolStatus::Failed);
        assert!(app.run_error.is_some());
    }

    #[tokio::test]
    async fn new_log_lines_respect_manual_scroll_and_resume_following() {
        let mut app =
            AppState::new(Configuration::default()).expect("configuração de teste válida");
        app.step = AppStep::Execution;
        app.focus = FocusTarget::ExecutionLogs;
        app.log_visible_height = 10;
        app.log_total_lines = 100;
        app.log_follow = false;
        app.log_scroll = 5;
        let (sender, receiver) = mpsc::unbounded_channel();
        app.run_receiver = Some(receiver);

        sender
            .send(RunEvent::ToolLog("nova linha".to_string()))
            .unwrap();
        app.process_run_events().await;
        assert_eq!(
            app.log_scroll, 5,
            "novas mensagens não podem puxar a tela após o usuário subir"
        );
        assert!(!app.log_follow);

        app.log_follow = true;
        sender
            .send(RunEvent::ToolLog("outra linha".to_string()))
            .unwrap();
        app.process_run_events().await;
        assert_eq!(app.log_scroll, app.log_max_scroll());
        assert_eq!(app.log_scroll, 90);
    }

    #[tokio::test]
    async fn draining_old_entries_shifts_the_manual_scroll_by_visual_rows() {
        let mut app =
            AppState::new(Configuration::default()).expect("configuração de teste válida");
        app.step = AppStep::Execution;
        app.focus = FocusTarget::ExecutionLogs;
        app.log_visible_height = 10;
        app.log_width = 10;
        app.log_total_lines = 200;
        app.exec_logs = vec!["x".repeat(25); 5000];
        app.log_follow = false;
        app.log_scroll = 100;
        let (sender, receiver) = mpsc::unbounded_channel();
        app.run_receiver = Some(receiver);

        sender
            .send(RunEvent::ToolLog("nova linha".to_string()))
            .unwrap();
        app.process_run_events().await;

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
        let mut app =
            AppState::new(Configuration::default()).expect("configuração de teste válida");
        app.log_total_lines = usize::MAX;
        app.log_visible_height = 1;

        assert_eq!(app.log_max_scroll(), u16::MAX as usize);
    }
}
