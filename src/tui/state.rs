use crate::config::Configuration;
use crate::config::execution_type::ExecutionType;
use crate::config::llm_config::LlmProviderKind;
use crate::domain::security_tool::ToolInfo;
use crate::domain::vulnerability::Vulnerability;
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
    RealNmap,
}

pub struct ToolItem {
    pub tool: ToolInfo,
    pub selected: bool,
    pub status: ToolStatus,
    pub progress: u16,
}

pub struct AppState {
    pub config: Configuration,
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
    pub settings_real_nmap: bool,
    pub llm_warning: Option<String>,
}

impl AppState {
    pub fn new(config: Configuration) -> Self {
        let tools = ToolInfo::all()
            .iter()
            .map(|t| ToolItem {
                tool: t.clone(),
                selected: true,
                status: ToolStatus::Pending,
                progress: 0,
            })
            .collect();

        let (provider_idx, base_url, api_key, model, real_nmap) = {
            let llm = &config.llm;
            let idx = match llm.provider {
                LlmProviderKind::Mock => 0,
                LlmProviderKind::Ollama => 1,
                LlmProviderKind::NvidiaNim => 2,
                LlmProviderKind::OpenAI => 3,
                LlmProviderKind::Custom => 4,
            };
            (idx, llm.base_url.clone(), llm.api_key.clone(), llm.model.clone(), config.use_real_nmap)
        };

        Self {
            config,
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
            settings_real_nmap: real_nmap,
            llm_warning: None,
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
        Vulnerability::mock_all()
    }

    pub fn tick(&mut self) {
        self.tick += 1;
        self.spinner_idx = (self.spinner_idx + 1) % 10;
        if self.mode() == ExecutionType::Auto {
            self.advance_auto();
        }
    }

    pub async fn step_tick(&mut self) {
        if self.step == AppStep::Analysis && self.analysis_phase == AnalysisPhase::Complete {
            if self.analysis_tick > 30 {
                self.step = AppStep::Results;
            }
            self.analysis_tick += 1;
        }
    }

    fn advance_auto(&mut self) {
        match self.step {
            AppStep::Splash => {}
            AppStep::ToolSelect => {
                if self.tool_detect_tick > 50 {
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
        self.find_first_pending();

        self.analysis_phase = AnalysisPhase::Scanning;
        self.analysis_tick = 0;
        self.analysis_text.clear();
        self.analysis_full_text = "Scanning vulnerability patterns across tool outputs...\n\nDetected SQL injection signatures in login and search endpoints.\nCross-referencing with ZAP and SQLMap findings.\n\nCorrelating XSS findings across reflected and stored variants.\nHeader analysis reveals missing security headers.\n\nDependency scan identified 2 critical CVEs:\n- lodash 4.17.15: CVE-2021-23337 (command injection)\n- openssl-sys 0.9.72: CVE-2023-0286 (buffer overflow)\n\nNetwork analysis: SSH exposed, Docker running as root.\nSession management: cookies without HttpOnly/Secure flags.\n\nPath traversal vulnerability detected in file API.\nIDOR vulnerability in user API (sequential IDs).\nCSRF protection missing on transfer endpoint.\n\nSSRF in preview endpoint — potential cloud metadata access.\nCORS misconfigured with wildcard origin.\nJWT accepts 'none' algorithm — critical auth bypass.\n\nGenerating remediation priorities and didactic explanations...".to_string();
    }

    fn find_first_pending(&mut self) {
        self.exec_current = self
            .tools
            .iter()
            .position(|t| t.selected && t.status == ToolStatus::Pending)
            .unwrap_or(self.tools.len());
    }

    pub fn advance_execution(&mut self) {
        self.exec_tick += 1;
        if self.exec_current >= self.tools.len() {
            return;
        }
        let tool = &mut self.tools[self.exec_current];
        if !tool.selected || tool.status == ToolStatus::Done {
            return;
        }
        tool.status = ToolStatus::Running;
        if self.exec_tick.is_multiple_of(3) && tool.progress < 100 {
            tool.progress = (tool.progress + 10).min(100);
            let log_entry = format!(
                "[{}] {} - progress: {}%",
                tool.tool.name, tool.tool.description, tool.progress
            );
            self.exec_logs.push(log_entry);
            let vh = self.log_visible_height.max(1);
            if self.exec_logs.len() > vh {
                self.log_scroll = self.exec_logs.len().saturating_sub(vh);
            }
        }
        if tool.progress >= 100 {
            tool.status = ToolStatus::Done;
            self.exec_logs.push(format!("[{}] ✓ Scan complete", tool.tool.name));
            let vh = self.log_visible_height.max(1);
            if self.exec_logs.len() > vh {
                self.log_scroll = self.exec_logs.len().saturating_sub(vh);
            }
            self.exec_current += 1;
            self.exec_tick = 0;
            while self.exec_current < self.tools.len()
                && (!self.tools[self.exec_current].selected
                    || self.tools[self.exec_current].status == ToolStatus::Done)
            {
                self.exec_current += 1;
            }
            if self.exec_current >= self.tools.len() {
                self.step = AppStep::Analysis;
                self.analysis_phase = AnalysisPhase::Scanning;
                self.analysis_tick = 0;
            }
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
        let provider = LlmProviderKind::from_label(
            LlmProviderKind::all_labels()[self.settings_provider_idx],
        );
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
        self.config.use_real_nmap = self.settings_real_nmap;
        self.config.save();
        self.show_settings = false;
    }
}
