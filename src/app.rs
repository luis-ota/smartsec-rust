use crate::mock::results::Vulnerability;
use crate::mock::tools::SecurityTool;
use ratatui::layout::Rect;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AppMode {
    Auto,
    Assisted,
}

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
pub enum ResultAction {
    ExportMd,
    ExplainDidactic,
    #[allow(dead_code)]
    ExplainDetail,
    BackToSummary,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AnalysisPhase {
    Scanning,
    Correlating,
    Generating,
    Complete,
}

pub struct ToolItem {
    pub tool: SecurityTool,
    pub selected: bool,
    pub status: ToolStatus,
    pub progress: u16,
}

pub struct AppState {
    pub mode: AppMode,
    pub step: AppStep,
    pub screen_area: Rect,
    pub should_quit: bool,
    pub url_input: String,
    pub url_cursor: usize,
    #[allow(dead_code)]
    pub url_editing: bool,
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
}

impl AppState {
    pub fn new() -> Self {
        let tools = SecurityTool::all()
            .iter()
            .map(|t| ToolItem {
                tool: t.clone(),
                selected: true,
                status: ToolStatus::Pending,
                progress: 0,
            })
            .collect();

        Self {
            mode: AppMode::Assisted,
            step: AppStep::Splash,
            should_quit: false,
            screen_area: Rect::default(),
            url_input: String::new(),
            url_cursor: 0,
            url_editing: true,
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
            result_detail_vuln: None,
            result_scroll: 0,
            result_focus_list: true,
            md_exported: false,
            show_didactic: false,
            show_detail: false,
            didactic_scroll: 0,
        }
    }

    pub fn spinner_char(&self) -> &str {
        const SPINNERS: &[&str] = &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
        SPINNERS[self.spinner_idx % SPINNERS.len()]
    }

    pub fn vulnerabilities(&self) -> Vec<Vulnerability> {
        Vulnerability::mock_all()
    }

    pub fn advance_auto(&mut self) {
        if self.mode != AppMode::Auto {
            return;
        }
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
            self.exec_logs
                .push(format!("[{}] ✓ Scan complete", tool.tool.name));
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
        }
    }

    pub fn advance_analysis(&mut self) {
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
        let vulns = self.vulnerabilities();
        let mut md = String::new();
        md.push_str("# SmartSec - Relatório de Análise de Segurança\n\n");
        md.push_str(&format!("**URL Alvo:** {}\n\n", self.url_input));
        md.push_str(&format!(
            "**Modo:** {}\n\n",
            match self.mode {
                AppMode::Auto => "Automático",
                AppMode::Assisted => "Assistido",
            }
        ));
        md.push_str("## Resumo\n\n");
        md.push_str(&format!("- Total de vulnerabilidades: {}\n", vulns.len()));
        let critical = vulns.iter().filter(|v| v.severity == "CRITICAL").count();
        let high = vulns.iter().filter(|v| v.severity == "HIGH").count();
        let medium = vulns.iter().filter(|v| v.severity == "MEDIUM").count();
        let low = vulns.iter().filter(|v| v.severity == "LOW").count();
        md.push_str(&format!(
            "- Critical: {}\n- High: {}\n- Medium: {}\n- Low: {}\n\n",
            critical, high, medium, low
        ));
        md.push_str("## Pontos Críticos\n\n");
        for v in &vulns {
            if v.severity == "CRITICAL" || v.severity == "HIGH" {
                md.push_str(&format!("### [{}] {}\n\n", v.severity, v.title));
                md.push_str(&format!("{}\n\n", v.description));
                md.push_str(&format!("**Ferramenta:** {}\n\n", v.tool));
                md.push_str(&format!("**Recomendação:** {}\n\n", v.recommendation));
            }
        }
        md.push_str("## Todas as Vulnerabilidades\n\n");
        for v in &vulns {
            md.push_str(&format!("- [{}] {} - {}\n", v.severity, v.title, v.tool));
        }
        md
    }
}
