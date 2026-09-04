use crate::config::execution_type::ExecutionType;
use crate::tui::state::SettingsField;
use ratatui::layout::Rect;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FocusTarget {
    SplashTarget,
    SplashAuto,
    SplashAssisted,
    SplashSettings,
    SplashStart,
    ToolList,
    ToolBack,
    ToolRun,
    ExecutionLogs,
    ExecutionBack,
    ExecutionPause,
    ExecutionCancel,
    AnalysisCancel,
    ResultsList,
    ResultsNewScan,
    ResultsExport,
    ResultsDidactic,
    ResultsDetail,
    ResultsBack,
    DidacticContent,
    DidacticBack,
    SettingsField(SettingsField),
    SettingsSave,
    SettingsCancel,
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
    PauseResume,
    CancelRun,
    OpenVulnerability(usize),
    ExportMarkdown,
    ShowDidactic,
    NewScan,
    SelectSettingsField(SettingsField),
    SaveSettings,
    CloseSettings,
    InsertText(String),
    DeleteBackward,
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
