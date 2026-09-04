use crate::ai::agent::AIAgent;
use crate::config::execution_type::ExecutionType;
use crate::config::llm_config::LlmProviderKind;
use crate::config::Configuration;
use crate::domain::security_tool::{SecurityTool, ToolInfo};
use crate::domain::vulnerability::Vulnerability;
use crate::orchestrator::Orchestrator;
use crate::tui::interaction::{FocusTarget, HitRegion, SemanticAction};
use ratatui::layout::Rect;
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
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ToolStatus {
    Pending,
    Running,
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
}

impl SettingsField {
    pub const ALL: [Self; 10] = [
        Self::Provider,
        Self::BaseUrl,
        Self::ApiKey,
        Self::Model,
        Self::Timeout,
        Self::Retries,
        Self::RemoteConsent,
        Self::FallbackEnabled,
        Self::FallbackBaseUrl,
        Self::FallbackModel,
    ];
}

pub struct ToolItem {
    pub tool: ToolInfo,
    pub selected: bool,
    pub status: ToolStatus,
    pub progress: u16,
}

enum RunEvent {
    ToolStarted(usize),
    ToolFinished {
        index: usize,
        execution: Box<SecurityTool>,
    },
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
    pub analysis_phase: AnalysisPhase,
    pub analysis_tick: u64,
    pub analysis_text: String,
    pub analysis_full_text: String,
    pub result_cursor: usize,
    pub result_scroll: usize,
    pub result_detail_vuln: Option<usize>,
    pub detail_scroll: usize,
    pub detail_max_scroll: usize,
    pub md_exported: bool,
    pub show_didactic: bool,
    pub show_detail: bool,
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
    pub llm_warning: Option<String>,
    pub audit_log_path: Option<PathBuf>,
    pub run_error: Option<String>,
    pub exec_cancelled: bool,
    pub show_help_overlay: bool,
    pub show_command_palette: bool,
    pub command_cursor: usize,
    pub settings_scroll: usize,
    pub focus: FocusTarget,
    pub settings_return_focus: FocusTarget,
    pub overlay_return_focus: FocusTarget,
    pub hit_regions: Vec<HitRegion>,
    run_receiver: Option<mpsc::UnboundedReceiver<RunEvent>>,
    run_task: Option<JoinHandle<()>>,
}

impl AppState {
    pub fn new(config: Configuration) -> Self {
        let orchestrator = Orchestrator::new(config.clone());
        let agent = orchestrator.agent_handle();

        let tools = ToolInfo::all()
            .iter()
            .map(|t| ToolItem {
                tool: t.clone(),
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

        Self {
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
            analysis_phase: AnalysisPhase::Scanning,
            analysis_tick: 0,
            analysis_text: String::new(),
            analysis_full_text: String::new(),
            result_cursor: 0,
            result_scroll: 0,
            result_detail_vuln: None,
            detail_scroll: 0,
            detail_max_scroll: 0,
            md_exported: false,
            show_didactic: false,
            show_detail: false,
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
            llm_warning: None,
            audit_log_path: None,
            run_error: None,
            exec_cancelled: false,
            show_help_overlay: false,
            show_command_palette: false,
            command_cursor: 0,
            settings_scroll: 0,
            focus: FocusTarget::SplashTarget,
            settings_return_focus: FocusTarget::SplashTarget,
            overlay_return_focus: FocusTarget::SplashTarget,
            hit_regions: Vec::new(),
            run_receiver: None,
            run_task: None,
        }
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

    fn has_blocking_layer(&self) -> bool {
        self.show_settings || self.show_help_overlay || self.show_command_palette
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
                    self.exec_logs.push(format!(
                        "[{}] Executando {}...",
                        self.tools[index].tool.name, self.tools[index].tool.description
                    ));
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
                RunEvent::Completed {
                    orchestrator,
                    audit_log,
                } => {
                    self.orchestrator = *orchestrator;
                    self.llm_warning = self.orchestrator.agent.execution_history.last().cloned();
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

    fn follow_latest_log(&mut self) {
        let visible = self.log_visible_height.max(1);
        if self.exec_logs.len() > visible {
            self.log_scroll = self.exec_logs.len().saturating_sub(visible);
        }
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
        self.exec_cancelled = false;
        self.orchestrator = Orchestrator::new(self.config.clone());
        self.audit_log_path = None;
        self.run_error = None;
        self.llm_warning = None;

        self.analysis_phase = AnalysisPhase::Scanning;
        self.analysis_tick = 0;
        self.analysis_text.clear();
        self.analysis_full_text.clear();

        let selected: Vec<_> = self
            .tools
            .iter()
            .enumerate()
            .filter(|(_, tool)| tool.selected)
            .map(|(index, tool)| (index, tool.tool.clone()))
            .collect();
        self.config.active_tools = selected
            .iter()
            .map(|(_, tool)| tool.name.to_string())
            .collect();
        let config = self.config.clone();
        let target = config.target_url.clone();
        let (sender, receiver) = mpsc::unbounded_channel();
        self.run_receiver = Some(receiver);
        self.run_task = Some(tokio::spawn(async move {
            let mut orchestrator = Orchestrator::new(config);
            for (index, tool) in selected {
                if sender.send(RunEvent::ToolStarted(index)).is_err() {
                    return;
                }
                let execution = orchestrator.execute_tool(&tool, &target).await;
                if sender
                    .send(RunEvent::ToolFinished {
                        index,
                        execution: Box::new(execution),
                    })
                    .is_err()
                {
                    return;
                }
            }
            orchestrator.build_findings();
            let analysis = orchestrator
                .agent
                .analyze_logs(&orchestrator.findings)
                .await;
            orchestrator.last_log = analysis;
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
        if self.exec_cancelled || self.orchestrator.cancelled {
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
        crate::report::ReportGenerator::compile_report(
            &self.config,
            &self.vulnerabilities(),
            &self.orchestrator.decision_history,
        )
    }

    pub fn apply_settings(&mut self) {
        let provider =
            LlmProviderKind::from_label(LlmProviderKind::all_labels()[self.settings_provider_idx]);
        self.config.llm.provider = provider;
        if self.settings_input_base_url.is_empty() {
            self.config.llm.base_url = provider.default_base_url().to_string();
        } else {
            self.config.llm.base_url = self.settings_input_base_url.clone();
        }
        self.config.llm.api_key = self.settings_input_api_key.clone();
        self.config.llm.timeout_secs = self.settings_input_timeout.parse().unwrap_or(45);
        self.config.llm.max_retries = self.settings_input_retries.parse().unwrap_or(2);
        self.config.llm.remote_consent = self.settings_remote_consent;
        self.config.llm.fallback_enabled = self.settings_fallback_enabled;
        self.config.llm.fallback_base_url = self.settings_input_fallback_base_url.clone();
        self.config.llm.fallback_model = self.settings_input_fallback_model.clone();
        if self.settings_input_model.is_empty() {
            self.config.llm.model = provider.default_model().to_string();
        } else {
            self.config.llm.model = self.settings_input_model.clone();
        }
        self.config.save();
        self.reset_settings_draft();
        self.show_settings = false;
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
        self.settings_scroll = 0;
    }

    pub fn cancel_run(&mut self) {
        if self.step != AppStep::Execution {
            return;
        }
        self.exec_cancelled = true;
        self.orchestrator.cancel_execution();
        if let Some(task) = self.run_task.take() {
            task.abort();
        }
        self.run_receiver = None;
        self.persist_cancelled_run();
        self.exec_logs.push("X Execução CANCELADA".to_string());
        let vh = self.log_visible_height.max(1);
        if self.exec_logs.len() > vh {
            self.log_scroll = self.exec_logs.len().saturating_sub(vh);
        }
    }

    pub async fn shutdown_run(&mut self) {
        self.run_receiver = None;
        if let Some(task) = self.run_task.take() {
            task.abort();
            let _ = task.await;
            self.persist_cancelled_run();
        }
    }

    fn persist_cancelled_run(&mut self) {
        self.orchestrator.cancelled = true;
        if let Some(tool) = self
            .tools
            .iter()
            .find(|tool| tool.status == ToolStatus::Running)
        {
            let mut execution = SecurityTool::new(
                tool.tool.name,
                &format!("{} {}", tool.tool.name, self.config.target_url),
            );
            execution.executed_at =
                chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
            execution.status = "cancelled".to_string();
            execution.execution_error = Some("Execução cancelada pelo usuário".to_string());
            self.orchestrator.execution_history.push(execution);
        }
        self.orchestrator.build_findings();
        self.orchestrator.last_log = "Execução cancelada pelo usuário".to_string();
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::vulnerability::FindingSource;
    use crate::domain::Severity;

    #[tokio::test]
    async fn run_events_update_progress_findings_and_audit_path() {
        let mut app = AppState::new(Configuration::default());
        app.step = AppStep::Execution;
        let (sender, receiver) = mpsc::unbounded_channel();
        app.run_receiver = Some(receiver);

        sender.send(RunEvent::ToolStarted(0)).unwrap();
        app.process_run_events().await;
        assert_eq!(app.tools[0].status, ToolStatus::Running);
        assert!(app.exec_logs[0].contains("Executando"));

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
        let mut orchestrator = Orchestrator::new(Configuration::default());
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
    }

    #[tokio::test]
    async fn disconnected_worker_surfaces_an_error_instead_of_hanging() {
        let mut app = AppState::new(Configuration::default());
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
}
