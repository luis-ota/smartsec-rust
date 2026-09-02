use crate::ai::agent::AIAgent;
use crate::config::execution_type::ExecutionType;
use crate::config::llm_config::LlmProviderKind;
use crate::config::Configuration;
use crate::domain::security_tool::ToolInfo;
use crate::domain::vulnerability::Vulnerability;
use crate::orchestrator::Orchestrator;
use ratatui::layout::Rect;

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
    RealNuclei,
}

pub struct ToolItem {
    pub tool: ToolInfo,
    pub selected: bool,
    pub status: ToolStatus,
    pub progress: u16,
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
    pub result_action_cursor: usize,
    pub result_cursor: usize,
    pub result_scroll: usize,
    pub result_detail_vuln: Option<usize>,
    pub result_focus_list: bool,
    pub md_exported: bool,
    pub show_didactic: bool,
    pub show_detail: bool,
    pub didactic_scroll: usize,
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
    pub settings_real_nuclei: bool,
    pub llm_warning: Option<String>,
    pub exec_paused: bool,
    pub exec_cancelled: bool,
    pub pending_ctrl_x: bool,
    pub pending_ctrl_x_tick: u64,
    pub command_palette_hint: Option<String>,
    pub ai_model_area: Rect,

    // Clickable area tracking
    pub splash_url_rect: Rect,
    pub splash_auto_rect: Rect,
    pub splash_assisted_rect: Rect,
    pub splash_start_rect: Rect,
    pub tools_list_rect: Rect,
    pub tools_run_rect: Rect,
    pub tools_back_rect: Rect,
    pub exec_pause_rect: Rect,
    pub exec_cancel_rect: Rect,
    pub exec_back_rect: Rect,
    pub analysis_back_rect: Rect,
    pub results_list_rect: Rect,
    pub results_export_rect: Rect,
    pub results_didactic_rect: Rect,
    pub results_back_rect: Rect,
    pub results_new_scan_rect: Rect,
    pub didactic_back_rect: Rect,
    pub settings_save_rect: Rect,
    pub settings_cancel_rect: Rect,
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

        let (provider_idx, base_url, api_key, model, real_nuclei) = {
            let llm = &config.llm;
            let idx = match llm.provider {
                LlmProviderKind::Mock => 0,
                LlmProviderKind::Ollama => 1,
                LlmProviderKind::NvidiaNim => 2,
                LlmProviderKind::OpenAI => 3,
                LlmProviderKind::Custom => 4,
            };
            (
                idx,
                llm.base_url.clone(),
                llm.api_key.clone(),
                llm.model.clone(),
                config.use_real_nuclei,
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
            result_action_cursor: 0,
            result_cursor: 0,
            result_scroll: 0,
            result_detail_vuln: None,
            result_focus_list: true,
            md_exported: false,
            show_didactic: false,
            show_detail: false,
            didactic_scroll: 0,
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
            settings_real_nuclei: real_nuclei,
            llm_warning: None,
            exec_paused: false,
            exec_cancelled: false,
            pending_ctrl_x: false,
            pending_ctrl_x_tick: 0,
            command_palette_hint: None,
            ai_model_area: Rect::default(),
            splash_url_rect: Rect::default(),
            splash_auto_rect: Rect::default(),
            splash_assisted_rect: Rect::default(),
            splash_start_rect: Rect::default(),
            tools_list_rect: Rect::default(),
            tools_run_rect: Rect::default(),
            tools_back_rect: Rect::default(),
            exec_pause_rect: Rect::default(),
            exec_cancel_rect: Rect::default(),
            exec_back_rect: Rect::default(),
            analysis_back_rect: Rect::default(),
            results_list_rect: Rect::default(),
            results_export_rect: Rect::default(),
            results_didactic_rect: Rect::default(),
            results_back_rect: Rect::default(),
            results_new_scan_rect: Rect::default(),
            didactic_back_rect: Rect::default(),
            settings_save_rect: Rect::default(),
            settings_cancel_rect: Rect::default(),
        }
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
        if self.orchestrator.findings.is_empty() && self.config.demo_mode {
            crate::domain::demo_findings::demo_all(&self.config.target_url)
        } else {
            self.orchestrator.findings.clone()
        }
    }

    pub fn ai_summary(&self) -> &str {
        if self.agent.last_analysis.is_empty() {
            "[AI analysis will run after execution completes]"
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
        if self.pending_ctrl_x && self.tick.saturating_sub(self.pending_ctrl_x_tick) > 20 {
            self.pending_ctrl_x = false;
            self.command_palette_hint = None;
        }
        match self.mode() {
            ExecutionType::Auto => self.advance_auto(),
            ExecutionType::Assisted => self.advance_assisted(),
        }
    }

    pub async fn step_tick(&mut self) {
        if self.step == AppStep::Execution
            && !self.exec_paused
            && !self.exec_cancelled
            && !self.orchestrator.cancelled
        {
            self.execute_real_tool().await;
        }
        if self.step == AppStep::Analysis && self.analysis_phase == AnalysisPhase::Complete {
            if self.analysis_tick > 30 {
                self.step = AppStep::Results;
            }
            self.analysis_tick += 1;
        }
    }

    async fn execute_real_tool(&mut self) {
        while self.exec_current < self.tools.len()
            && (!self.tools[self.exec_current].selected
                || self.tools[self.exec_current].status == ToolStatus::Done)
        {
            self.exec_current += 1;
        }
        if self.exec_current >= self.tools.len() {
            return;
        }

        let tool = &mut self.tools[self.exec_current];
        tool.status = ToolStatus::Running;
        tool.progress = 10;
        let tool_info = tool.tool.clone();
        let target = self.config.target_url.clone();
        let _ = tool;

        self.exec_logs.push(format!(
            "[{}] Running {}...",
            tool_info.name, tool_info.description
        ));
        let vh = self.log_visible_height.max(1);
        if self.exec_logs.len() > vh {
            self.log_scroll = self.exec_logs.len().saturating_sub(vh);
        }

        let _exec = self.orchestrator.execute_tool(&tool_info, &target).await;

        self.tools[self.exec_current].status = ToolStatus::Done;
        self.tools[self.exec_current].progress = 100;
        self.exec_logs
            .push(format!("[{}] OK Scan complete", tool_info.name));
        let vh = self.log_visible_height.max(1);
        if self.exec_logs.len() > vh {
            self.log_scroll = self.exec_logs.len().saturating_sub(vh);
        }

        self.exec_current += 1;

        let all_done = self
            .tools
            .iter()
            .all(|t| !t.selected || t.status == ToolStatus::Done);
        if all_done {
            self.orchestrator.build_findings();
            self.sync_agent_from_orchestrator();
            self.step = AppStep::Analysis;
            self.analysis_phase = AnalysisPhase::Scanning;
            self.analysis_tick = 0;
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
        self.exec_paused = false;
        self.exec_cancelled = false;
        self.orchestrator.paused = false;
        self.orchestrator.cancelled = false;
        self.orchestrator.execution_history.clear();
        self.orchestrator.findings.clear();

        self.analysis_phase = AnalysisPhase::Scanning;
        self.analysis_tick = 0;
        self.analysis_text.clear();
        self.analysis_full_text = "Running security tools and analyzing outputs...\n\nCross-referencing findings across multiple scanners.\nCorrelating results for false positive reduction.\n\nGenerating severity classifications and remediation priorities.\nCompiling didactic explanations for each vulnerability...".to_string();
    }

    pub fn advance_execution(&mut self) {
        if self.exec_cancelled || self.orchestrator.cancelled {
            self.step = AppStep::ToolSelect;
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
        crate::report::ReportGenerator::compile_report(&self.config, &self.vulnerabilities())
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
        if self.settings_input_model.is_empty() {
            self.config.llm.model = provider.default_model().to_string();
        } else {
            self.config.llm.model = self.settings_input_model.clone();
        }
        self.config.use_real_nuclei = self.settings_real_nuclei;
        self.config.save();
        self.show_settings = false;
    }

    pub fn pause_or_resume(&mut self) {
        if self.step != AppStep::Execution {
            return;
        }
        self.exec_paused = !self.exec_paused;
        if self.exec_paused {
            self.orchestrator.pause_execution();
            self.exec_logs.push("|| Execution PAUSED".to_string());
        } else {
            self.orchestrator.resume_execution();
            self.exec_logs.push("> Execution RESUMED".to_string());
        }
        let vh = self.log_visible_height.max(1);
        if self.exec_logs.len() > vh {
            self.log_scroll = self.exec_logs.len().saturating_sub(vh);
        }
    }

    pub fn cancel_run(&mut self) {
        if self.step != AppStep::Execution {
            return;
        }
        self.exec_cancelled = true;
        self.orchestrator.cancel_execution();
        self.exec_logs.push("X Execution CANCELLED".to_string());
        let vh = self.log_visible_height.max(1);
        if self.exec_logs.len() > vh {
            self.log_scroll = self.exec_logs.len().saturating_sub(vh);
        }
    }

    pub fn sync_agent_from_orchestrator(&mut self) {
        self.agent.last_analysis = self.orchestrator.last_log.clone();
    }
}
