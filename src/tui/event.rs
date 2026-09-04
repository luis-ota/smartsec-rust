use crate::config::execution_type::ExecutionType;
use crate::config::llm_config::LlmProviderKind;
use crate::tui::interaction::{FocusTarget, SemanticAction};
use crate::tui::state::{AppState, AppStep, SettingsField};
use crossterm::event::{
    self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseButton, MouseEvent,
    MouseEventKind,
};
use std::time::Duration;

pub fn handle_events(app: &mut AppState) -> std::io::Result<bool> {
    if !event::poll(Duration::from_millis(50))? {
        return Ok(false);
    }

    let should_quit = match event::read()? {
        Event::Key(key) if key.kind == KeyEventKind::Press => handle_key(app, key),
        Event::Mouse(mouse) => handle_mouse(app, mouse),
        Event::Paste(text) => dispatch_action(app, SemanticAction::InsertText(text)),
        Event::Resize(_, _) => false,
        _ => false,
    };
    Ok(should_quit)
}

fn handle_key(app: &mut AppState, key: KeyEvent) -> bool {
    if matches!(key.code, KeyCode::Char('v') | KeyCode::Char('V'))
        && key.modifiers.contains(KeyModifiers::CONTROL)
    {
        paste_from_clipboard(app);
        return false;
    }

    if app.pending_ctrl_x {
        app.pending_ctrl_x = false;
        app.command_palette_hint = None;
        return key
            .code
            .as_char()
            .and_then(ctrl_x_action)
            .is_some_and(|action| dispatch_action(app, action));
    }

    if key.code == KeyCode::Char('x') && key.modifiers.contains(KeyModifiers::CONTROL) {
        app.pending_ctrl_x = true;
        app.pending_ctrl_x_tick = app.tick;
        app.command_palette_hint =
            Some("C-x _  (c)onfigurações (s)air (p)ausar (x)cancelar (e)xecutar".to_string());
        return false;
    }

    key_action(app, key).is_some_and(|action| dispatch_action(app, action))
}

fn ctrl_x_action(key: char) -> Option<SemanticAction> {
    match key.to_ascii_lowercase() {
        'c' => Some(SemanticAction::OpenSettings),
        's' => Some(SemanticAction::Quit),
        'p' => Some(SemanticAction::PauseResume),
        'x' => Some(SemanticAction::CancelRun),
        'e' => Some(SemanticAction::RunTools),
        _ => None,
    }
}

fn key_action(app: &AppState, key: KeyEvent) -> Option<SemanticAction> {
    let navigation = match key.code {
        KeyCode::Tab => Some(SemanticAction::FocusNext),
        KeyCode::BackTab => Some(SemanticAction::FocusPrevious),
        KeyCode::Up => Some(SemanticAction::MoveUp),
        KeyCode::Down => Some(SemanticAction::MoveDown),
        KeyCode::Left => Some(SemanticAction::MoveLeft),
        KeyCode::Right => Some(SemanticAction::MoveRight),
        KeyCode::Enter | KeyCode::Char(' ') => Some(SemanticAction::Activate),
        KeyCode::Esc => Some(SemanticAction::Back),
        KeyCode::Backspace => Some(SemanticAction::DeleteBackward),
        _ => None,
    };
    if navigation.is_some() {
        return navigation;
    }

    match key.code {
        KeyCode::Char(character) if accepts_text(app) => {
            Some(SemanticAction::InsertText(character.to_string()))
        }
        _ => None,
    }
}

fn accepts_text(app: &AppState) -> bool {
    if app.show_settings {
        return matches!(
            app.focus,
            FocusTarget::SettingsField(
                SettingsField::BaseUrl
                    | SettingsField::ApiKey
                    | SettingsField::Model
                    | SettingsField::Timeout
                    | SettingsField::Retries
                    | SettingsField::FallbackBaseUrl
                    | SettingsField::FallbackModel
            )
        );
    }
    app.step == AppStep::Splash && app.focus == FocusTarget::SplashTarget
}

fn paste_from_clipboard(app: &mut AppState) {
    let Ok(text) = arboard::Clipboard::new().and_then(|mut clipboard| clipboard.get_text()) else {
        return;
    };
    dispatch_action(app, SemanticAction::InsertText(text));
}

fn handle_mouse(app: &mut AppState, mouse: MouseEvent) -> bool {
    let action = match mouse.kind {
        MouseEventKind::ScrollUp => Some(SemanticAction::ScrollUp),
        MouseEventKind::ScrollDown => Some(SemanticAction::ScrollDown),
        MouseEventKind::Down(MouseButton::Left) => app.action_at(mouse.column, mouse.row),
        _ => None,
    };
    action.is_some_and(|action| dispatch_action(app, action))
}

pub(crate) fn dispatch_action(app: &mut AppState, action: SemanticAction) -> bool {
    match action {
        SemanticAction::SetFocus(focus) => set_focus(app, focus),
        SemanticAction::FocusNext => move_focus(app, true),
        SemanticAction::FocusPrevious => move_focus(app, false),
        SemanticAction::MoveUp => move_vertical(app, false),
        SemanticAction::MoveDown => move_vertical(app, true),
        SemanticAction::MoveLeft => move_horizontal(app, false),
        SemanticAction::MoveRight => move_horizontal(app, true),
        SemanticAction::Activate => activate_focus(app),
        SemanticAction::Back => return go_back(app),
        SemanticAction::Quit => return true,
        SemanticAction::OpenSettings => {
            app.overlay_return_focus = app.focus;
            app.show_settings = true;
            app.focus = FocusTarget::SettingsField(app.settings_field);
        }
        SemanticAction::StartScan => start_scan(app),
        SemanticAction::SetMode(mode) => {
            app.set_mode(mode);
            app.focus = match mode {
                ExecutionType::Auto => FocusTarget::SplashAuto,
                ExecutionType::Assisted => FocusTarget::SplashAssisted,
            };
        }
        SemanticAction::ToggleTool(index) => toggle_tool(app, index),
        SemanticAction::RunTools => run_tools(app),
        SemanticAction::ScrollUp => scroll(app, false, 3),
        SemanticAction::ScrollDown => scroll(app, true, 3),
        SemanticAction::PauseResume => app.pause_or_resume(),
        SemanticAction::CancelRun => cancel_execution(app),
        SemanticAction::OpenVulnerability(index) => open_vulnerability(app, index),
        SemanticAction::ExportMarkdown => export_markdown(app),
        SemanticAction::ShowDidactic => {
            app.overlay_return_focus = app.focus;
            app.show_didactic = true;
            app.didactic_scroll = 0;
            app.focus = FocusTarget::DidacticContent;
        }
        SemanticAction::NewScan => new_scan(app),
        SemanticAction::SelectSettingsField(field) => select_settings_field(app, field),
        SemanticAction::SaveSettings => {
            app.apply_settings();
            app.focus = app.overlay_return_focus;
        }
        SemanticAction::CloseSettings => {
            app.show_settings = false;
            app.focus = app.overlay_return_focus;
        }
        SemanticAction::InsertText(text) => insert_text(app, &text),
        SemanticAction::DeleteBackward => delete_backward(app),
    }
    false
}

fn set_focus(app: &mut AppState, focus: FocusTarget) {
    app.focus = focus;
    if let FocusTarget::SettingsField(field) = focus {
        app.settings_field = field;
    }
}

fn focus_order(app: &AppState) -> Vec<FocusTarget> {
    if app.show_settings {
        let mut order: Vec<_> = SettingsField::ALL
            .iter()
            .copied()
            .map(FocusTarget::SettingsField)
            .collect();
        order.extend([FocusTarget::SettingsSave, FocusTarget::SettingsCancel]);
        return order;
    }
    if app.show_didactic || app.show_detail {
        return vec![FocusTarget::DidacticContent, FocusTarget::DidacticBack];
    }
    match app.step {
        AppStep::Splash => vec![
            FocusTarget::SplashTarget,
            FocusTarget::SplashAuto,
            FocusTarget::SplashAssisted,
            FocusTarget::SplashSettings,
            FocusTarget::SplashStart,
        ],
        AppStep::ToolSelect => vec![
            FocusTarget::ToolList,
            FocusTarget::ToolBack,
            FocusTarget::ToolRun,
        ],
        AppStep::Execution => vec![
            FocusTarget::ExecutionLogs,
            FocusTarget::ExecutionBack,
            FocusTarget::ExecutionPause,
            FocusTarget::ExecutionCancel,
        ],
        AppStep::Analysis => vec![FocusTarget::AnalysisCancel],
        AppStep::Results if app.result_detail_vuln.is_some() => {
            vec![FocusTarget::ResultsBack, FocusTarget::ResultsDidactic]
        }
        AppStep::Results => vec![
            FocusTarget::ResultsList,
            FocusTarget::ResultsNewScan,
            FocusTarget::ResultsExport,
            FocusTarget::ResultsDidactic,
        ],
    }
}

fn move_focus(app: &mut AppState, forward: bool) {
    let order = focus_order(app);
    let current = order
        .iter()
        .position(|focus| *focus == app.focus)
        .unwrap_or(0);
    let next = if forward {
        (current + 1) % order.len()
    } else {
        current.checked_sub(1).unwrap_or(order.len() - 1)
    };
    set_focus(app, order[next]);
}

fn move_vertical(app: &mut AppState, down: bool) {
    match app.focus {
        FocusTarget::ToolList => move_tool_cursor(app, down),
        FocusTarget::ResultsList if app.result_detail_vuln.is_none() => {
            move_result_cursor(app, down)
        }
        FocusTarget::ResultsBack | FocusTarget::ResultsDidactic
            if app.result_detail_vuln.is_some() =>
        {
            move_detail_cursor(app, down)
        }
        FocusTarget::ExecutionLogs | FocusTarget::DidacticContent => scroll(app, down, 1),
        FocusTarget::SettingsField(SettingsField::Provider) => move_provider(app, down),
        _ => move_focus(app, down),
    }
}

fn move_horizontal(app: &mut AppState, right: bool) {
    move_focus(app, right);
}

fn activate_focus(app: &mut AppState) {
    let action = match app.focus {
        FocusTarget::SplashTarget | FocusTarget::SplashStart => SemanticAction::StartScan,
        FocusTarget::SplashAuto => SemanticAction::SetMode(ExecutionType::Auto),
        FocusTarget::SplashAssisted => SemanticAction::SetMode(ExecutionType::Assisted),
        FocusTarget::SplashSettings => SemanticAction::OpenSettings,
        FocusTarget::ToolList => SemanticAction::ToggleTool(app.tool_cursor),
        FocusTarget::ToolBack
        | FocusTarget::ExecutionBack
        | FocusTarget::AnalysisCancel
        | FocusTarget::ResultsBack
        | FocusTarget::DidacticBack => SemanticAction::Back,
        FocusTarget::ToolRun => SemanticAction::RunTools,
        FocusTarget::ExecutionPause => SemanticAction::PauseResume,
        FocusTarget::ExecutionCancel => SemanticAction::CancelRun,
        FocusTarget::ExecutionLogs | FocusTarget::DidacticContent => return,
        FocusTarget::ResultsList => SemanticAction::OpenVulnerability(app.result_cursor),
        FocusTarget::ResultsNewScan => SemanticAction::NewScan,
        FocusTarget::ResultsExport => SemanticAction::ExportMarkdown,
        FocusTarget::ResultsDidactic => SemanticAction::ShowDidactic,
        FocusTarget::SettingsField(field) => {
            activate_settings_field(app, field);
            return;
        }
        FocusTarget::SettingsSave => SemanticAction::SaveSettings,
        FocusTarget::SettingsCancel => SemanticAction::CloseSettings,
    };
    dispatch_action(app, action);
}

fn go_back(app: &mut AppState) -> bool {
    if app.show_settings {
        app.show_settings = false;
        app.focus = app.overlay_return_focus;
        return false;
    }
    if app.show_didactic || app.show_detail {
        app.show_didactic = false;
        app.show_detail = false;
        app.didactic_scroll = 0;
        app.focus = app.overlay_return_focus;
        return false;
    }
    if app.result_detail_vuln.is_some() {
        app.result_detail_vuln = None;
        app.focus = FocusTarget::ResultsList;
        return false;
    }

    match app.step {
        AppStep::Splash => return true,
        AppStep::ToolSelect => new_scan(app),
        AppStep::Execution => {
            app.cancel_run();
            app.step = AppStep::ToolSelect;
            app.focus = FocusTarget::ToolList;
        }
        AppStep::Analysis => {
            app.orchestrator.cancelled = true;
            app.step = AppStep::ToolSelect;
            app.tool_detecting = false;
            app.focus = FocusTarget::ToolList;
        }
        AppStep::Results => new_scan(app),
    }
    false
}

fn start_scan(app: &mut AppState) {
    if app.config.target_url.is_empty() {
        app.config.target_url = "http://localhost:8080".to_string();
    }
    app.step = AppStep::ToolSelect;
    app.tool_detecting = true;
    app.tool_detect_tick = 0;
    app.focus = FocusTarget::ToolList;
}

fn run_tools(app: &mut AppState) {
    if app.step == AppStep::ToolSelect
        && !app.tool_detecting
        && app.tools.iter().any(|tool| tool.selected)
    {
        app.step = AppStep::Execution;
        app.focus = FocusTarget::ExecutionLogs;
        app.init_execution();
    }
}

fn toggle_tool(app: &mut AppState, index: usize) {
    if app.step == AppStep::ToolSelect && !app.tool_detecting {
        if let Some(tool) = app.tools.get_mut(index) {
            tool.selected = !tool.selected;
            app.tool_cursor = index;
            app.focus = FocusTarget::ToolList;
            ensure_tool_visible(app);
        }
    }
}

fn move_tool_cursor(app: &mut AppState, down: bool) {
    if app.tools.is_empty() {
        app.tool_cursor = 0;
        app.tool_scroll = 0;
        return;
    }
    if down {
        app.tool_cursor = (app.tool_cursor + 1).min(app.tools.len() - 1);
    } else {
        app.tool_cursor = app.tool_cursor.saturating_sub(1);
    }
    ensure_tool_visible(app);
}

fn ensure_tool_visible(app: &mut AppState) {
    let visible = 8usize;
    if app.tool_cursor < app.tool_scroll {
        app.tool_scroll = app.tool_cursor;
    } else if app.tool_cursor >= app.tool_scroll.saturating_add(visible) {
        app.tool_scroll = app.tool_cursor.saturating_sub(visible - 1);
    }
}

fn move_result_cursor(app: &mut AppState, down: bool) {
    let count = app.vulnerabilities().len();
    if count == 0 {
        app.result_cursor = 0;
        app.result_scroll = 0;
        return;
    }
    if down {
        app.result_cursor = (app.result_cursor + 1).min(count - 1);
    } else {
        app.result_cursor = app.result_cursor.saturating_sub(1);
    }
}

fn move_detail_cursor(app: &mut AppState, down: bool) {
    let count = app.vulnerabilities().len();
    let Some(index) = app.result_detail_vuln else {
        return;
    };
    app.result_detail_vuln = Some(if down {
        (index + 1).min(count.saturating_sub(1))
    } else {
        index.saturating_sub(1)
    });
}

fn open_vulnerability(app: &mut AppState, index: usize) {
    if index < app.vulnerabilities().len() {
        app.result_cursor = index;
        app.result_detail_vuln = Some(index);
        app.focus = FocusTarget::ResultsBack;
    }
}

fn scroll(app: &mut AppState, down: bool, amount: usize) {
    if app.show_didactic || app.show_detail {
        app.didactic_scroll = if down {
            app.didactic_scroll.saturating_add(amount)
        } else {
            app.didactic_scroll.saturating_sub(amount)
        };
        return;
    }
    match app.step {
        AppStep::ToolSelect => {
            for _ in 0..amount {
                move_tool_cursor(app, down);
            }
        }
        AppStep::Execution => {
            app.focus = FocusTarget::ExecutionLogs;
            let max_scroll = app.exec_logs.len().saturating_sub(app.log_visible_height);
            app.log_scroll = if down {
                app.log_scroll.saturating_add(amount).min(max_scroll)
            } else {
                app.log_scroll.saturating_sub(amount)
            };
        }
        AppStep::Results => {
            for _ in 0..amount {
                move_result_cursor(app, down);
            }
            app.focus = FocusTarget::ResultsList;
        }
        _ => {}
    }
}

fn cancel_execution(app: &mut AppState) {
    if app.step == AppStep::Execution {
        app.cancel_run();
    } else if app.step == AppStep::Analysis {
        app.orchestrator.cancelled = true;
        app.step = AppStep::ToolSelect;
        app.focus = FocusTarget::ToolList;
    }
}

fn export_markdown(app: &mut AppState) {
    if app.step == AppStep::Results {
        let _ = std::fs::write("smartsec-report.md", app.export_md());
        app.md_exported = true;
        app.focus = FocusTarget::ResultsExport;
    }
}

fn new_scan(app: &mut AppState) {
    app.step = AppStep::Splash;
    app.result_detail_vuln = None;
    app.show_didactic = false;
    app.show_detail = false;
    app.md_exported = false;
    app.focus = FocusTarget::SplashTarget;
}

fn select_settings_field(app: &mut AppState, field: SettingsField) {
    app.settings_field = field;
    app.focus = FocusTarget::SettingsField(field);
    activate_settings_field(app, field);
}

fn activate_settings_field(app: &mut AppState, field: SettingsField) {
    match field {
        SettingsField::Provider => {
            app.settings_provider_idx =
                (app.settings_provider_idx + 1) % LlmProviderKind::all_labels().len();
            sync_provider_defaults(app);
        }
        SettingsField::RemoteConsent => app.settings_remote_consent = !app.settings_remote_consent,
        SettingsField::FallbackEnabled => {
            app.settings_fallback_enabled = !app.settings_fallback_enabled
        }
        SettingsField::RealNuclei => app.settings_real_nuclei = !app.settings_real_nuclei,
        _ => {}
    }
}

fn move_provider(app: &mut AppState, down: bool) {
    let count = LlmProviderKind::all_labels().len();
    app.settings_provider_idx = if down {
        (app.settings_provider_idx + 1).min(count - 1)
    } else {
        app.settings_provider_idx.saturating_sub(1)
    };
    sync_provider_defaults(app);
}

fn sync_provider_defaults(app: &mut AppState) {
    let labels = LlmProviderKind::all_labels();
    let provider = LlmProviderKind::from_label(labels[app.settings_provider_idx]);
    app.settings_input_base_url = provider.default_base_url().to_string();
    app.settings_input_model = provider.default_model().to_string();
}

fn insert_text(app: &mut AppState, text: &str) {
    if !accepts_text(app) {
        return;
    }
    match app.focus {
        FocusTarget::SplashTarget => app.config.target_url.push_str(text),
        FocusTarget::SettingsField(SettingsField::BaseUrl) => {
            app.settings_input_base_url.push_str(text)
        }
        FocusTarget::SettingsField(SettingsField::ApiKey) => {
            app.settings_input_api_key.push_str(text)
        }
        FocusTarget::SettingsField(SettingsField::Model) => app.settings_input_model.push_str(text),
        FocusTarget::SettingsField(SettingsField::Timeout)
            if text.chars().all(|character| character.is_ascii_digit()) =>
        {
            app.settings_input_timeout.push_str(text)
        }
        FocusTarget::SettingsField(SettingsField::Retries)
            if text.chars().all(|character| character.is_ascii_digit()) =>
        {
            app.settings_input_retries.push_str(text)
        }
        FocusTarget::SettingsField(SettingsField::FallbackBaseUrl) => {
            app.settings_input_fallback_base_url.push_str(text)
        }
        FocusTarget::SettingsField(SettingsField::FallbackModel) => {
            app.settings_input_fallback_model.push_str(text)
        }
        _ => {}
    }
}

fn delete_backward(app: &mut AppState) {
    match app.focus {
        FocusTarget::SplashTarget => {
            app.config.target_url.pop();
        }
        FocusTarget::SettingsField(SettingsField::BaseUrl) => {
            app.settings_input_base_url.pop();
        }
        FocusTarget::SettingsField(SettingsField::ApiKey) => {
            app.settings_input_api_key.pop();
        }
        FocusTarget::SettingsField(SettingsField::Model) => {
            app.settings_input_model.pop();
        }
        FocusTarget::SettingsField(SettingsField::Timeout) => {
            app.settings_input_timeout.pop();
        }
        FocusTarget::SettingsField(SettingsField::Retries) => {
            app.settings_input_retries.pop();
        }
        FocusTarget::SettingsField(SettingsField::FallbackBaseUrl) => {
            app.settings_input_fallback_base_url.pop();
        }
        FocusTarget::SettingsField(SettingsField::FallbackModel) => {
            app.settings_input_fallback_model.pop();
        }
        _ => {}
    }
}

trait KeyCodeChar {
    fn as_char(self) -> Option<char>;
}

impl KeyCodeChar for KeyCode {
    fn as_char(self) -> Option<char> {
        if let KeyCode::Char(character) = self {
            Some(character)
        } else {
            None
        }
    }
}
