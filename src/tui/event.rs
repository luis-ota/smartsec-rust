use crate::config::execution_type::ExecutionType;
use crate::config::llm_config::LlmProviderKind;
use crate::tui::commands::command_items;
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

    if key.code == KeyCode::F(1) {
        return dispatch_action(app, SemanticAction::OpenHelp);
    }

    if app.show_help_overlay {
        if key.code == KeyCode::Char('p') && key.modifiers.contains(KeyModifiers::CONTROL) {
            return dispatch_action(app, SemanticAction::OpenCommandPalette);
        }
        return key_action(app, key).is_some_and(|action| dispatch_action(app, action));
    }
    if app.show_command_palette {
        if key.code == KeyCode::Char('p') && key.modifiers.contains(KeyModifiers::CONTROL) {
            return dispatch_action(app, SemanticAction::Back);
        }
        return key_action(app, key).is_some_and(|action| dispatch_action(app, action));
    }

    if key.code == KeyCode::Char('p') && key.modifiers.contains(KeyModifiers::CONTROL) {
        return dispatch_action(app, SemanticAction::OpenCommandPalette);
    }

    if key.code == KeyCode::Char('?') && !accepts_text(app) {
        return dispatch_action(app, SemanticAction::OpenHelp);
    }

    key_action(app, key).is_some_and(|action| dispatch_action(app, action))
}

fn key_action(app: &AppState, key: KeyEvent) -> Option<SemanticAction> {
    if app.show_help_overlay {
        return match key.code {
            KeyCode::Esc | KeyCode::Enter | KeyCode::Char('?') => Some(SemanticAction::Back),
            _ => None,
        };
    }
    if app.show_command_palette {
        return match key.code {
            KeyCode::Esc => Some(SemanticAction::Back),
            KeyCode::Up | KeyCode::BackTab => Some(SemanticAction::MoveUp),
            KeyCode::Down | KeyCode::Tab => Some(SemanticAction::MoveDown),
            KeyCode::Enter | KeyCode::Char(' ') => {
                Some(SemanticAction::ExecuteCommand(app.command_cursor))
            }
            _ => None,
        };
    }
    let navigation = match key.code {
        KeyCode::Tab => Some(SemanticAction::FocusNext),
        KeyCode::BackTab => Some(SemanticAction::FocusPrevious),
        KeyCode::Up => Some(SemanticAction::MoveUp),
        KeyCode::Down => Some(SemanticAction::MoveDown),
        KeyCode::Left => Some(SemanticAction::MoveLeft),
        KeyCode::Right => Some(SemanticAction::MoveRight),
        KeyCode::Enter | KeyCode::Char(' ') => Some(SemanticAction::Activate),
        KeyCode::Esc => Some(SemanticAction::Back),
        KeyCode::Backspace if app.show_settings => Some(SemanticAction::DeleteBackward),
        KeyCode::Backspace if app.show_didactic => Some(SemanticAction::Back),
        KeyCode::Backspace if app.result_detail_vuln.is_some() => Some(SemanticAction::Back),
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
            app.settings_return_focus = app.focus;
            app.reset_settings_draft();
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
        SemanticAction::CancelRun => cancel_execution(app),
        SemanticAction::OpenVulnerability(index) => open_vulnerability(app, index),
        SemanticAction::ExportMarkdown => export_markdown(app),
        SemanticAction::ShowDidactic => {
            app.didactic_return_focus = app.focus;
            app.show_didactic = true;
            app.didactic_scroll = 0;
            app.focus = FocusTarget::DidacticContent;
        }
        SemanticAction::NewScan => new_scan(app),
        SemanticAction::SelectSettingsField(field) => select_settings_field(app, field),
        SemanticAction::SaveSettings => {
            app.apply_settings();
            app.focus = app.settings_return_focus;
        }
        SemanticAction::CloseSettings => {
            app.reset_settings_draft();
            app.show_settings = false;
            app.focus = app.settings_return_focus;
        }
        SemanticAction::InsertText(text) => insert_text(app, &text),
        SemanticAction::DeleteBackward => delete_backward(app),
        SemanticAction::OpenHelp => open_help(app),
        SemanticAction::OpenCommandPalette => open_command_palette(app),
        SemanticAction::ExecuteCommand(index) => return execute_command(app, index),
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
    if app.show_help_overlay {
        return vec![FocusTarget::HelpClose];
    }
    if app.show_command_palette {
        return vec![FocusTarget::CommandList];
    }
    if app.show_settings {
        let mut order: Vec<_> = SettingsField::ALL
            .iter()
            .copied()
            .map(FocusTarget::SettingsField)
            .collect();
        order.extend([FocusTarget::SettingsSave, FocusTarget::SettingsCancel]);
        return order;
    }
    if app.show_didactic {
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
            FocusTarget::ExecutionCancel,
        ],
        AppStep::Analysis => vec![FocusTarget::AnalysisCancel],
        AppStep::Results if app.result_detail_vuln.is_some() => {
            vec![
                FocusTarget::ResultsDetail,
                FocusTarget::ResultsBack,
                FocusTarget::ResultsDidactic,
            ]
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
        FocusTarget::ResultsDetail => scroll_detail(app, down, 1),
        FocusTarget::ExecutionLogs | FocusTarget::DidacticContent => scroll(app, down, 1),
        FocusTarget::SettingsField(SettingsField::Provider) => move_provider(app, down),
        FocusTarget::CommandList => move_command_cursor(app, down),
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
        FocusTarget::ExecutionCancel if !app.exec_cancelled => SemanticAction::CancelRun,
        FocusTarget::ExecutionCancel => return,
        FocusTarget::ExecutionLogs | FocusTarget::DidacticContent => return,
        FocusTarget::ResultsList => SemanticAction::OpenVulnerability(app.result_cursor),
        FocusTarget::ResultsDetail => return,
        FocusTarget::ResultsNewScan => SemanticAction::NewScan,
        FocusTarget::ResultsExport => SemanticAction::ExportMarkdown,
        FocusTarget::ResultsDidactic => SemanticAction::ShowDidactic,
        FocusTarget::SettingsField(field) => {
            activate_settings_field(app, field);
            return;
        }
        FocusTarget::SettingsSave => SemanticAction::SaveSettings,
        FocusTarget::SettingsCancel => SemanticAction::CloseSettings,
        FocusTarget::HelpClose => SemanticAction::Back,
        FocusTarget::CommandList => SemanticAction::ExecuteCommand(app.command_cursor),
    };
    dispatch_action(app, action);
}

fn go_back(app: &mut AppState) -> bool {
    if app.show_help_overlay {
        app.show_help_overlay = false;
        app.focus = app.overlay_return_focus;
        return false;
    }
    if app.show_command_palette {
        app.show_command_palette = false;
        app.focus = app.overlay_return_focus;
        return false;
    }
    if app.show_settings {
        app.reset_settings_draft();
        app.show_settings = false;
        app.focus = app.settings_return_focus;
        return false;
    }
    if app.show_didactic {
        app.show_didactic = false;
        app.didactic_scroll = 0;
        app.focus = app.didactic_return_focus;
        return false;
    }
    if app.result_detail_vuln.is_some() {
        app.result_detail_vuln = None;
        app.detail_scroll = 0;
        app.detail_max_scroll = 0;
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
    app.config.target_url = app.config.target_url.trim().to_string();
    if let Err(error) = app.config.validate_target() {
        app.run_error = Some(error);
        app.focus = FocusTarget::SplashTarget;
        return;
    }
    app.run_error = None;
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
    let visible = app.tool_visible_height.max(1);
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

fn open_vulnerability(app: &mut AppState, index: usize) {
    if index < app.vulnerabilities().len() {
        app.result_cursor = index;
        app.result_detail_vuln = Some(index);
        app.detail_scroll = 0;
        app.detail_max_scroll = 0;
        app.focus = FocusTarget::ResultsDetail;
    }
}

fn scroll(app: &mut AppState, down: bool, amount: usize) {
    if app.show_help_overlay {
        return;
    }
    if app.show_command_palette {
        move_command_cursor(app, down);
        return;
    }
    if app.show_settings {
        for _ in 0..amount {
            move_focus(app, down);
        }
        return;
    }
    if app.show_didactic {
        app.didactic_scroll = if down {
            app.didactic_scroll
                .saturating_add(amount)
                .min(app.didactic_max_scroll)
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
            if app.result_detail_vuln.is_some() {
                scroll_detail(app, down, amount);
            } else {
                for _ in 0..amount {
                    move_result_cursor(app, down);
                }
                app.focus = FocusTarget::ResultsList;
            }
        }
        _ => {}
    }
}

fn scroll_detail(app: &mut AppState, down: bool, amount: usize) {
    app.detail_scroll = if down {
        app.detail_scroll
            .saturating_add(amount)
            .min(app.detail_max_scroll)
    } else {
        app.detail_scroll.saturating_sub(amount)
    };
}

fn open_help(app: &mut AppState) {
    if app.show_help_overlay {
        return;
    }
    if !app.show_command_palette {
        app.overlay_return_focus = app.focus;
    }
    app.show_command_palette = false;
    app.show_help_overlay = true;
    app.focus = FocusTarget::HelpClose;
}

fn open_command_palette(app: &mut AppState) {
    if !app.show_help_overlay {
        app.overlay_return_focus = app.focus;
    }
    app.show_help_overlay = false;
    app.show_command_palette = true;
    app.command_cursor = 0;
    app.focus = FocusTarget::CommandList;
}

fn move_command_cursor(app: &mut AppState, down: bool) {
    let count = command_items(app).len();
    if count == 0 {
        app.command_cursor = 0;
    } else if down {
        app.command_cursor = (app.command_cursor + 1) % count;
    } else {
        app.command_cursor = app.command_cursor.checked_sub(1).unwrap_or(count - 1);
    }
}

fn execute_command(app: &mut AppState, index: usize) -> bool {
    let Some(item) = command_items(app).get(index).cloned() else {
        return false;
    };
    if !item.enabled {
        return false;
    }
    app.show_command_palette = false;
    app.focus = app.overlay_return_focus;
    dispatch_action(app, item.action)
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
        match std::fs::write("smartsec-report.md", app.export_md()) {
            Ok(()) => app.md_exported = true,
            Err(error) => {
                app.md_exported = false;
                app.run_error = Some(format!("Falha ao exportar relatório: {error}"));
            }
        }
        app.focus = FocusTarget::ResultsExport;
    }
}

fn new_scan(app: &mut AppState) {
    app.step = AppStep::Splash;
    app.result_detail_vuln = None;
    app.detail_scroll = 0;
    app.detail_max_scroll = 0;
    app.show_didactic = false;
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
        FocusTarget::SplashTarget => {
            app.config.target_url.push_str(text);
            app.run_error = None;
        }
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
            app.run_error = None;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Configuration;
    use crate::tui;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    fn app() -> AppState {
        AppState::new(Configuration::default())
    }

    fn finding() -> crate::domain::vulnerability::Vulnerability {
        crate::domain::vulnerability::Vulnerability {
            title: "Achado de teste".to_string(),
            severity: crate::domain::Severity::High,
            description: "Descrição técnica".to_string(),
            tool: "Nuclei".to_string(),
            recommendation: "Aplique a correção".to_string(),
            didactic: "Explicação didática".to_string(),
            source: crate::domain::vulnerability::FindingSource::Real,
            target: "https://exemplo.local".to_string(),
            evidence: "evidência".to_string(),
            detected_at: "2026-09-04T14:00:00Z".to_string(),
        }
    }

    fn press(app: &mut AppState, code: KeyCode) -> bool {
        handle_key(app, KeyEvent::new(code, KeyModifiers::NONE))
    }

    fn click_action(app: &mut AppState, action: &SemanticAction) -> bool {
        let region = app
            .hit_regions
            .iter()
            .find(|region| &region.action == action)
            .expect("a ação deve possuir uma região clicável");
        handle_mouse(
            app,
            MouseEvent {
                kind: MouseEventKind::Down(MouseButton::Left),
                column: region.area.x,
                row: region.area.y,
                modifiers: KeyModifiers::NONE,
            },
        )
    }

    fn render_app(app: &mut AppState, width: u16, height: u16) -> String {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| tui::render(app, frame)).unwrap();
        terminal.backend().to_string()
    }

    #[test]
    fn keyboard_and_mouse_start_scan_are_equivalent() {
        let mut keyboard = app();
        keyboard.config.target_url = "https://exemplo.local".to_string();
        let mut mouse = app();
        mouse.config.target_url = "https://exemplo.local".to_string();
        render_app(&mut mouse, 80, 24);

        assert!(!press(&mut keyboard, KeyCode::Enter));
        assert!(!click_action(&mut mouse, &SemanticAction::StartScan));

        assert_eq!(keyboard.step, mouse.step);
        assert_eq!(keyboard.focus, mouse.focus);
        assert_eq!(keyboard.config.target_url, mouse.config.target_url);
    }

    #[test]
    fn invalid_target_stays_on_splash_and_shows_the_error() {
        let mut app = app();
        app.config.target_url = "ftp://exemplo.local".to_string();

        press(&mut app, KeyCode::Enter);

        assert_eq!(app.step, AppStep::Splash);
        assert!(app.run_error.as_deref().unwrap().contains("HTTP ou HTTPS"));
    }

    #[test]
    fn keyboard_and_mouse_toggle_the_same_tool() {
        let mut keyboard = app();
        keyboard.step = AppStep::ToolSelect;
        keyboard.tool_detecting = false;
        keyboard.focus = FocusTarget::ToolList;
        keyboard.tool_cursor = 1;
        let mut mouse = app();
        mouse.step = AppStep::ToolSelect;
        mouse.tool_detecting = false;
        mouse.tool_cursor = 1;
        render_app(&mut mouse, 80, 16);

        press(&mut keyboard, KeyCode::Char(' '));
        click_action(&mut mouse, &SemanticAction::ToggleTool(1));

        let keyboard_selection: Vec<_> = keyboard.tools.iter().map(|tool| tool.selected).collect();
        let mouse_selection: Vec<_> = mouse.tools.iter().map(|tool| tool.selected).collect();
        assert_eq!(keyboard_selection, mouse_selection);
        assert_eq!(mouse.tool_cursor, 1);
    }

    #[test]
    fn settings_toggle_has_keyboard_and_mouse_parity() {
        let mut keyboard = app();
        keyboard.show_settings = true;
        keyboard.settings_field = SettingsField::RemoteConsent;
        keyboard.focus = FocusTarget::SettingsField(SettingsField::RemoteConsent);
        let mut mouse = app();
        mouse.show_settings = true;
        render_app(&mut mouse, 80, 24);

        press(&mut keyboard, KeyCode::Enter);
        click_action(
            &mut mouse,
            &SemanticAction::SelectSettingsField(SettingsField::RemoteConsent),
        );

        assert_eq!(
            keyboard.settings_remote_consent,
            mouse.settings_remote_consent
        );
        assert_eq!(keyboard.focus, mouse.focus);
    }

    #[test]
    fn tab_and_backtab_cycle_focus_in_both_directions() {
        let mut app = app();
        assert_eq!(app.focus, FocusTarget::SplashTarget);

        press(&mut app, KeyCode::Tab);
        assert_eq!(app.focus, FocusTarget::SplashAuto);
        press(&mut app, KeyCode::BackTab);
        assert_eq!(app.focus, FocusTarget::SplashTarget);
        press(&mut app, KeyCode::BackTab);
        assert_eq!(app.focus, FocusTarget::SplashStart);
    }

    #[test]
    fn escape_closes_overlays_then_goes_back_and_only_quits_on_splash() {
        let mut app = app();
        app.step = AppStep::Results;
        app.focus = FocusTarget::ResultsExport;
        dispatch_action(&mut app, SemanticAction::OpenSettings);

        assert!(!press(&mut app, KeyCode::Esc));
        assert!(!app.show_settings);
        assert_eq!(app.step, AppStep::Results);
        assert_eq!(app.focus, FocusTarget::ResultsExport);

        app.result_detail_vuln = Some(0);
        app.focus = FocusTarget::ResultsBack;
        dispatch_action(&mut app, SemanticAction::ShowDidactic);
        assert!(!press(&mut app, KeyCode::Esc));
        assert!(!app.show_didactic);
        assert!(app.result_detail_vuln.is_some());
        assert!(!press(&mut app, KeyCode::Esc));
        assert!(app.result_detail_vuln.is_none());
        assert_eq!(app.step, AppStep::Results);

        assert!(!press(&mut app, KeyCode::Esc));
        assert_eq!(app.step, AppStep::Splash);
        assert!(press(&mut app, KeyCode::Esc));
    }

    #[test]
    fn nested_help_over_didactic_restores_both_focus_layers() {
        let mut app = app();
        app.step = AppStep::Results;
        app.focus = FocusTarget::ResultsExport;
        dispatch_action(&mut app, SemanticAction::ShowDidactic);
        assert_eq!(app.focus, FocusTarget::DidacticContent);

        dispatch_action(&mut app, SemanticAction::OpenHelp);
        assert!(app.show_help_overlay);
        assert!(!press(&mut app, KeyCode::Esc));
        assert!(!app.show_help_overlay);
        assert!(app.show_didactic);
        assert_eq!(app.focus, FocusTarget::DidacticContent);

        assert!(!press(&mut app, KeyCode::Esc));
        assert!(!app.show_didactic);
        assert_eq!(app.focus, FocusTarget::ResultsExport);
    }

    #[test]
    fn scroll_is_saturating_and_clamped_to_visible_content() {
        let mut app = app();
        app.step = AppStep::Execution;
        app.focus = FocusTarget::ExecutionLogs;
        app.exec_logs = (0..10).map(|index| index.to_string()).collect();
        app.log_visible_height = 3;

        dispatch_action(&mut app, SemanticAction::ScrollUp);
        assert_eq!(app.log_scroll, 0);
        for _ in 0..10 {
            dispatch_action(&mut app, SemanticAction::ScrollDown);
        }
        assert_eq!(app.log_scroll, 7);

        app.show_didactic = true;
        app.didactic_max_scroll = 4;
        app.didactic_scroll = usize::MAX;
        dispatch_action(&mut app, SemanticAction::ScrollDown);
        assert_eq!(app.didactic_scroll, 4);
        dispatch_action(&mut app, SemanticAction::ScrollUp);
        assert_eq!(app.didactic_scroll, 1);
    }

    #[test]
    fn list_navigation_handles_empty_lists_and_hitboxes_include_scroll_offset() {
        let mut empty = app();
        empty.step = AppStep::ToolSelect;
        empty.focus = FocusTarget::ToolList;
        empty.tools.clear();
        dispatch_action(&mut empty, SemanticAction::MoveDown);
        assert_eq!(empty.tool_cursor, 0);
        assert_eq!(empty.tool_scroll, 0);

        let mut app = app();
        app.step = AppStep::ToolSelect;
        app.tool_detecting = false;
        app.tool_cursor = 1;
        app.tool_scroll = 0;
        render_app(&mut app, 80, 16);
        let indices: Vec<_> = app
            .hit_regions
            .iter()
            .filter_map(|region| match region.action {
                SemanticAction::ToggleTool(index) => Some(index),
                _ => None,
            })
            .collect();
        assert_eq!(indices.first(), Some(&0));
        assert!(indices.iter().all(|index| *index >= app.tool_scroll));
    }

    #[test]
    fn result_hitboxes_include_scroll_offset_and_open_the_right_item() {
        let mut app = app();
        app.orchestrator.findings = vec![finding()];
        app.step = AppStep::Results;
        app.result_cursor = app.vulnerabilities().len() - 1;
        render_app(&mut app, 80, 24);

        let first_visible = app
            .hit_regions
            .iter()
            .find_map(|region| match region.action {
                SemanticAction::OpenVulnerability(index) => Some(index),
                _ => None,
            })
            .expect("a lista deve ter ao menos um item visível");
        assert_eq!(first_visible, app.result_scroll);

        click_action(&mut app, &SemanticAction::OpenVulnerability(first_visible));
        assert_eq!(app.result_detail_vuln, Some(first_visible));
        assert_eq!(app.focus, FocusTarget::ResultsDetail);
    }

    #[test]
    fn hit_regions_are_rebuilt_for_each_frame() {
        let mut app = app();
        render_app(&mut app, 80, 24);
        assert!(app
            .hit_regions
            .iter()
            .any(|region| region.action == SemanticAction::StartScan));

        app.step = AppStep::Analysis;
        app.focus = FocusTarget::AnalysisCancel;
        render_app(&mut app, 80, 24);
        assert!(!app
            .hit_regions
            .iter()
            .any(|region| region.action == SemanticAction::StartScan));
        assert!(app
            .hit_regions
            .iter()
            .any(|region| region.action == SemanticAction::Back));
    }

    #[test]
    fn help_opens_contextually_and_escape_restores_focus() {
        let mut app = app();
        app.step = AppStep::Results;
        app.focus = FocusTarget::ResultsExport;

        press(&mut app, KeyCode::Char('?'));
        assert!(app.show_help_overlay);
        assert_eq!(app.focus, FocusTarget::HelpClose);
        assert!(!press(&mut app, KeyCode::Char('?')));
        assert!(!app.show_help_overlay);
        assert_eq!(app.focus, FocusTarget::ResultsExport);
    }

    #[test]
    fn question_mark_is_inserted_in_target_and_text_fields() {
        let mut app = app();
        app.config.target_url = "https://exemplo.local/busca".to_string();
        app.focus = FocusTarget::SplashTarget;

        press(&mut app, KeyCode::Char('?'));
        for character in "q=teste".chars() {
            press(&mut app, KeyCode::Char(character));
        }

        assert_eq!(app.config.target_url, "https://exemplo.local/busca?q=teste");
        assert!(!app.show_help_overlay);

        dispatch_action(&mut app, SemanticAction::OpenSettings);
        app.settings_input_base_url = "https://api.exemplo.local/v1".to_string();
        set_focus(&mut app, FocusTarget::SettingsField(SettingsField::BaseUrl));
        press(&mut app, KeyCode::Char('?'));
        assert_eq!(app.settings_input_base_url, "https://api.exemplo.local/v1?");
        assert!(!app.show_help_overlay);

        app.settings_input_timeout = "45".to_string();
        set_focus(&mut app, FocusTarget::SettingsField(SettingsField::Timeout));
        press(&mut app, KeyCode::Char('?'));
        assert_eq!(app.settings_input_timeout, "45");
        assert!(!app.show_help_overlay);
    }

    #[test]
    fn f1_opens_help_globally_and_footer_is_clickable() {
        let mut keyboard = app();
        keyboard.config.target_url = "https://exemplo.local/?q=teste".to_string();
        keyboard.focus = FocusTarget::SplashTarget;

        press(&mut keyboard, KeyCode::F(1));

        assert!(keyboard.show_help_overlay);
        assert_eq!(keyboard.focus, FocusTarget::HelpClose);
        assert_eq!(keyboard.config.target_url, "https://exemplo.local/?q=teste");

        let mut mouse = app();
        render_app(&mut mouse, 80, 24);
        click_action(&mut mouse, &SemanticAction::OpenHelp);
        assert!(mouse.show_help_overlay);
        assert_eq!(mouse.focus, FocusTarget::HelpClose);
    }

    #[test]
    fn command_palette_is_navigable_and_keyboard_mouse_are_equivalent() {
        let mut keyboard = app();
        handle_key(
            &mut keyboard,
            KeyEvent::new(KeyCode::Char('p'), KeyModifiers::CONTROL),
        );
        assert!(keyboard.show_command_palette);
        press(&mut keyboard, KeyCode::Down);
        assert_eq!(keyboard.command_cursor, 1);
        press(&mut keyboard, KeyCode::Up);
        press(&mut keyboard, KeyCode::Enter);

        let mut mouse = app();
        dispatch_action(&mut mouse, SemanticAction::OpenCommandPalette);
        render_app(&mut mouse, 80, 24);
        click_action(&mut mouse, &SemanticAction::ExecuteCommand(0));

        assert_eq!(keyboard.show_help_overlay, mouse.show_help_overlay);
        assert_eq!(keyboard.show_command_palette, mouse.show_command_palette);
        assert_eq!(keyboard.focus, mouse.focus);
    }

    #[test]
    fn disabled_palette_command_does_not_execute_or_close() {
        let mut app = app();
        app.step = AppStep::ToolSelect;
        app.tool_detecting = true;
        dispatch_action(&mut app, SemanticAction::OpenCommandPalette);
        let run_index = command_items(&app)
            .iter()
            .position(|item| item.action == SemanticAction::RunTools)
            .unwrap();

        dispatch_action(&mut app, SemanticAction::ExecuteCommand(run_index));

        assert_eq!(app.step, AppStep::ToolSelect);
        assert!(app.show_command_palette);
    }

    #[test]
    fn command_from_settings_restores_the_underlying_screen_focus() {
        let mut app = app();
        app.step = AppStep::Results;
        app.focus = FocusTarget::ResultsExport;
        dispatch_action(&mut app, SemanticAction::OpenSettings);
        dispatch_action(&mut app, SemanticAction::OpenCommandPalette);
        let cancel_index = command_items(&app)
            .iter()
            .position(|item| item.action == SemanticAction::CloseSettings)
            .unwrap();

        dispatch_action(&mut app, SemanticAction::ExecuteCommand(cancel_index));

        assert!(!app.show_settings);
        assert!(!app.show_command_palette);
        assert_eq!(app.step, AppStep::Results);
        assert_eq!(app.focus, FocusTarget::ResultsExport);
    }

    #[test]
    fn help_blocks_scroll_and_cancelled_actions_stay_disabled() {
        let mut app = app();
        app.step = AppStep::Execution;
        app.focus = FocusTarget::ExecutionLogs;
        app.exec_logs = (0..10).map(|index| index.to_string()).collect();
        app.log_visible_height = 2;
        dispatch_action(&mut app, SemanticAction::OpenHelp);
        dispatch_action(&mut app, SemanticAction::ScrollDown);
        assert_eq!(app.log_scroll, 0);

        dispatch_action(&mut app, SemanticAction::Back);
        app.exec_cancelled = true;
        app.focus = FocusTarget::ExecutionCancel;
        dispatch_action(&mut app, SemanticAction::Activate);
        assert!(app.exec_cancelled);
    }

    #[tokio::test]
    async fn blocking_layers_suspend_and_resume_underlying_transitions() {
        let mut app = app();
        app.set_mode(ExecutionType::Auto);
        app.step = AppStep::ToolSelect;
        app.focus = FocusTarget::ToolList;
        app.tool_detecting = true;
        app.tool_detect_tick = 50;
        dispatch_action(&mut app, SemanticAction::OpenSettings);

        app.tick();
        app.step_tick().await;
        assert_eq!(app.step, AppStep::ToolSelect);
        assert_eq!(app.tool_detect_tick, 50);
        dispatch_action(&mut app, SemanticAction::CloseSettings);
        assert_eq!(app.focus, FocusTarget::ToolList);
        app.tick();
        assert_eq!(app.step, AppStep::Execution);

        app.step = AppStep::Analysis;
        app.focus = FocusTarget::AnalysisCancel;
        app.analysis_phase = crate::tui::state::AnalysisPhase::Complete;
        app.analysis_tick = 31;
        dispatch_action(&mut app, SemanticAction::OpenHelp);
        app.tick();
        app.step_tick().await;
        assert_eq!(app.step, AppStep::Analysis);
        assert_eq!(app.analysis_tick, 31);
        dispatch_action(&mut app, SemanticAction::Back);
        assert_eq!(app.focus, FocusTarget::AnalysisCancel);
        app.step_tick().await;
        assert_eq!(app.step, AppStep::Results);
        assert_eq!(app.focus, FocusTarget::ResultsList);
    }

    #[test]
    fn long_vulnerability_detail_scrolls_with_keyboard_and_mouse() {
        let mut app = app();
        let mut finding = finding();
        finding.description = "Descrição técnica extensa com evidência reproduzível. ".repeat(30);
        finding.recommendation = "Aplique a correção indicada e valide novamente. ".repeat(30);
        app.orchestrator.findings = vec![finding];
        app.step = AppStep::Results;
        dispatch_action(&mut app, SemanticAction::OpenVulnerability(0));

        let screen = render_app(&mut app, 80, 24);
        assert!(app.detail_max_scroll > 0);
        assert!(screen.contains("↑↓ rolar · linhas"));

        press(&mut app, KeyCode::Down);
        assert_eq!(app.detail_scroll, 1);
        assert_eq!(app.result_detail_vuln, Some(0));
        handle_mouse(
            &mut app,
            MouseEvent {
                kind: MouseEventKind::ScrollDown,
                column: 40,
                row: 10,
                modifiers: KeyModifiers::NONE,
            },
        );
        assert_eq!(app.detail_scroll, 4);
        for _ in 0..app.detail_max_scroll + 1 {
            dispatch_action(&mut app, SemanticAction::ScrollDown);
        }
        assert_eq!(app.detail_scroll, app.detail_max_scroll);

        app.detail_scroll = 0;
        dispatch_action(&mut app, SemanticAction::ScrollUp);
        assert_eq!(app.detail_scroll, 0);
        assert_eq!(app.result_detail_vuln, Some(0));
    }

    #[test]
    fn cancelling_settings_discards_draft_before_reopening() {
        let mut app = app();
        app.config.llm.base_url = "https://api.persistida.local/v1".to_string();
        app.config.llm.model = "modelo-persistido".to_string();
        app.config.llm.remote_consent = false;
        dispatch_action(&mut app, SemanticAction::OpenSettings);
        app.settings_input_base_url = "https://rascunho.local/v1".to_string();
        app.settings_input_model = "modelo-rascunho".to_string();
        app.settings_remote_consent = true;

        dispatch_action(&mut app, SemanticAction::CloseSettings);

        assert!(!app.show_settings);
        assert_eq!(app.config.llm.model, "modelo-persistido");
        assert_eq!(
            app.settings_input_base_url,
            "https://api.persistida.local/v1"
        );
        assert_eq!(app.settings_input_model, "modelo-persistido");
        assert!(!app.settings_remote_consent);

        dispatch_action(&mut app, SemanticAction::OpenSettings);
        assert_eq!(
            app.settings_input_base_url,
            "https://api.persistida.local/v1"
        );
        assert_eq!(app.settings_input_model, "modelo-persistido");
        assert!(!app.settings_remote_consent);

        app.settings_input_model = "outro-rascunho".to_string();
        press(&mut app, KeyCode::Esc);
        assert_eq!(app.settings_input_model, "modelo-persistido");
    }
}
