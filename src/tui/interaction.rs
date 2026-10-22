use crate::config::execution_type::ExecutionType;
use crate::domain::Severity;
use crate::tui::state::SettingsField;
use ratatui::layout::Rect;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FocusTarget {
    SplashTarget,
    SplashAuto,
    SplashAssisted,
    SplashSettings,
    SplashRecent,
    SplashStart,
    ToolList,
    ToolBack,
    ToolRun,
    ExecutionLogs,
    ExecutionPause,
    ExecutionCancel,
    AnalysisCancel,
    ResultsList,
    ResultsNewScan,
    ResultsExport,
    ResultsDetail,
    ResultsBack,
    ResultsExplain,
    DidacticContent,
    DidacticExplain,
    DidacticBack,
    HistoryList,
    HistoryDetail,
    HistoryBack,
    SettingsField(SettingsField),
    SettingsSave,
    SettingsCancel,
    /// Lista de escolhas do passo atual do assistente de primeira execução.
    OnboardingList,
    HelpClose,
    CommandList,
    ReportClose,
    TraceClose,
    /// Botão de fechar do painel "Atividade da IA".
    AiTimelineClose,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SemanticAction {
    SetFocus(FocusTarget),
    FocusNext,
    FocusPrevious,
    MoveUp,
    MoveDown,
    MoveLeft,
    MoveRight,
    Activate,
    Back,
    Quit,
    OpenSettings,
    StartScan,
    SetMode(ExecutionType),
    ToggleTool(usize),
    RunTools,
    ScrollUp,
    ScrollDown,
    /// Pausa a ferramenta em execução (`podman pause` no container real).
    PauseRun,
    /// Retoma a ferramenta pausada (`podman unpause` no container real).
    ResumeRun,
    CancelRun,
    OpenVulnerability(usize),
    FilterSeverity(Severity),
    ExportMarkdown,
    ShowDidactic,
    /// Explicação assistida (RAG) do achado aberto no detalhe.
    ExplainFinding,
    NewScan,
    SelectSettingsField(SettingsField),
    SaveSettings,
    CloseSettings,
    OpenOnboarding,
    /// Ativa o item escolhido do passo atual do assistente.
    OnboardingActivate(usize),
    OnboardingBack,
    OnboardingQuit,
    InsertText(String),
    DeleteBackward,
    ClearText,
    OpenHelp,
    OpenHistory,
    OpenHistoryRecord(usize),
    OpenRecentScan(usize),
    OpenReportViewer,
    OpenTraceability,
    OpenCommandPalette,
    ExecuteCommand(usize),
    /// Abre o painel ao vivo "Atividade da IA" na tela de Execução.
    OpenAiTimeline,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HitRegion {
    pub area: Rect,
    pub action: SemanticAction,
}

impl HitRegion {
    pub fn contains(&self, column: u16, row: u16) -> bool {
        column >= self.area.x
            && column < self.area.x.saturating_add(self.area.width)
            && row >= self.area.y
            && row < self.area.y.saturating_add(self.area.height)
    }
}
