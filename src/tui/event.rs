use crate::config::execution_type::ExecutionType;
use crate::config::llm_config::LlmProviderKind;
use crate::tui::state::{AppState, AppStep, SettingsField};
use crossterm::event::{
    self, Event, KeyCode, KeyEventKind, KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
};
use ratatui::layout::Rect;
use std::time::Duration;

pub fn handle_events(app: &mut AppState) -> std::io::Result<bool> {
    if event::poll(Duration::from_millis(50))? {
        match event::read()? {
            Event::Key(key) => {
                if key.kind == KeyEventKind::Press {
                    return Ok(handle_key(app, key));
                }
            }
            Event::Mouse(mouse) => {
                handle_mouse(app, mouse);
            }
            Event::Paste(text) => {
                if app.show_settings {
                    handle_settings_paste(app, &text);
                } else if app.step == AppStep::Splash {
                    app.config.target_url.push_str(&text);
                }
            }
            Event::Resize(_, _) => {}
            _ => {}
        }
    }
    Ok(false)
}

fn handle_key(app: &mut AppState, key: event::KeyEvent) -> bool {
    if let KeyCode::Char('v') | KeyCode::Char('V') = key.code {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        let shift = key.modifiers.contains(KeyModifiers::SHIFT);
        if ctrl && shift {
            paste_from_clipboard(app);
            return false;
        }
        if ctrl {
            paste_from_clipboard(app);
            return false;
        }
    }

    if app.show_settings {
        return handle_settings_key(app, key);
    }

    if app.pending_ctrl_x {
        app.pending_ctrl_x = false;
        app.command_palette_hint = None;
        if let KeyCode::Char(c) = key.code {
            return dispatch_ctrl_x(app, c, key.modifiers);
        }
        return false;
    }

    if let KeyCode::Char('x') = key.code {
        if key.modifiers.contains(KeyModifiers::CONTROL) {
            app.pending_ctrl_x = true;
            app.pending_ctrl_x_tick = app.tick;
            app.command_palette_hint =
                Some("C-x _  (s)ettings (q)uit (p)ause (c)ancel (r)un".to_string());
            return false;
        }
    }

    match app.step {
        AppStep::Splash => handle_splash_key(app, key),
        AppStep::ToolSelect => handle_tool_select_key(app, key),
        AppStep::Execution => handle_execution_key(app, key),
        AppStep::Analysis => handle_analysis_key(key),
        AppStep::Results => handle_results_key(app, key),
    }
}

fn paste_from_clipboard(app: &mut AppState) {
    let text = match arboard::Clipboard::new().and_then(|mut cb| cb.get_text()) {
        Ok(t) => t,
        Err(_) => return,
    };
    if app.show_settings {
        handle_settings_paste(app, &text);
    } else if app.step == AppStep::Splash {
        app.config.target_url.push_str(&text);
    }
}

fn dispatch_ctrl_x(app: &mut AppState, c: char, _modifiers: KeyModifiers) -> bool {
    match c {
        's' | 'S' => {
            app.show_settings = true;
        }
        'q' | 'Q' => {
            return true;
        }
        'p' | 'P' => {
            if app.step == AppStep::Execution {
                app.pause_or_resume();
            }
        }
        'c' | 'C' => {
            if app.step == AppStep::Execution {
                app.cancel_run();
            }
        }
        'r' | 'R' => {
            if app.step == AppStep::ToolSelect {
                if !app.tool_detecting {
                    let has_selected = app.tools.iter().any(|t| t.selected);
                    if has_selected {
                        app.step = AppStep::Execution;
                        app.init_execution();
                    }
                }
            } else if app.step == AppStep::Splash {
                if app.config.target_url.is_empty() {
                    app.config.target_url = "http://localhost:8080".to_string();
                }
                app.step = AppStep::ToolSelect;
                app.tool_detecting = true;
                app.tool_detect_tick = 0;
            }
        }
        _ => {}
    }
    false
}

fn handle_splash_key(app: &mut AppState, key: event::KeyEvent) -> bool {
    match key.code {
        KeyCode::Tab | KeyCode::BackTab => {
            app.set_mode(match app.mode() {
                ExecutionType::Auto => ExecutionType::Assisted,
                ExecutionType::Assisted => ExecutionType::Auto,
            });
        }
        KeyCode::Enter => {
            if app.config.target_url.is_empty() {
                app.config.target_url = "http://localhost:8080".to_string();
            }
            app.step = AppStep::ToolSelect;
            app.tool_detecting = true;
            app.tool_detect_tick = 0;
        }
        KeyCode::Char(c) => {
            app.config.target_url.push(c);
        }
        KeyCode::Backspace => {
            let len = app.config.target_url.chars().count();
            if len > 0 {
                let s: String = app.config.target_url.chars().take(len - 1).collect();
                app.config.target_url = s;
            }
        }
        KeyCode::Esc => return true,
        _ => {}
    }
    false
}

fn handle_tool_select_key(app: &mut AppState, key: event::KeyEvent) -> bool {
    if app.mode() == ExecutionType::Auto {
        if key.code == KeyCode::Esc {
            return true;
        }
        return false;
    }
    match key.code {
        KeyCode::Up => {
            if app.tool_cursor > 0 {
                app.tool_cursor -= 1;
                ensure_tool_visible(app);
            }
        }
        KeyCode::Down => {
            if app.tool_cursor < app.tools.len() - 1 {
                app.tool_cursor += 1;
                ensure_tool_visible(app);
            }
        }
        KeyCode::Char(' ') => {
            if !app.tool_detecting {
                app.tools[app.tool_cursor].selected = !app.tools[app.tool_cursor].selected;
            }
        }
        KeyCode::Enter => {
            if !app.tool_detecting {
                let has_selected = app.tools.iter().any(|t| t.selected);
                if has_selected {
                    app.step = AppStep::Execution;
                    app.init_execution();
                }
            }
        }
        KeyCode::Esc => return true,
        _ => {}
    }
    false
}

fn handle_execution_key(_app: &mut AppState, key: event::KeyEvent) -> bool {
    if key.code == KeyCode::Esc {
        return true;
    }
    false
}

fn handle_analysis_key(key: event::KeyEvent) -> bool {
    if key.code == KeyCode::Esc {
        return true;
    }
    false
}

fn handle_results_key(app: &mut AppState, key: event::KeyEvent) -> bool {
    if app.show_didactic || app.show_detail {
        match key.code {
            KeyCode::Esc | KeyCode::Backspace => {
                app.show_didactic = false;
                app.show_detail = false;
                app.result_detail_vuln = None;
                app.didactic_scroll = 0;
            }
            KeyCode::Up => {
                if app.didactic_scroll > 0 {
                    app.didactic_scroll -= 1;
                }
            }
            KeyCode::Down => {
                app.didactic_scroll += 1;
            }
            _ => {}
        }
        return false;
    }
    if app.result_detail_vuln.is_some() {
        return handle_results_detail_key(app, key);
    }
    match key.code {
        KeyCode::Up => {
            app.result_focus_list = true;
            if app.result_cursor > 0 {
                app.result_cursor -= 1;
            }
        }
        KeyCode::Down => {
            app.result_focus_list = true;
            let vulns = app.vulnerabilities();
            if app.result_cursor + 1 < vulns.len() {
                app.result_cursor += 1;
            }
        }
        KeyCode::Left => {
            app.result_focus_list = false;
            if app.result_action_cursor > 0 {
                app.result_action_cursor -= 1;
            }
        }
        KeyCode::Right => {
            app.result_focus_list = false;
            if app.result_action_cursor < 1 {
                app.result_action_cursor += 1;
            }
        }
        KeyCode::Enter => {
            if app.result_focus_list {
                app.result_detail_vuln = Some(app.result_cursor);
                app.result_action_cursor = 0;
            } else {
                match app.result_action_cursor {
                    0 => {
                        let md = app.export_md();
                        let _ = std::fs::write("smartsec-report.md", md);
                        app.md_exported = true;
                    }
                    1 => {
                        app.show_didactic = true;
                        app.didactic_scroll = 0;
                    }
                    _ => {}
                }
            }
        }
        KeyCode::Tab => {
            app.result_focus_list = !app.result_focus_list;
        }
        KeyCode::Esc => return true,
        _ => {}
    }
    false
}

fn handle_results_detail_key(app: &mut AppState, key: event::KeyEvent) -> bool {
    match key.code {
        KeyCode::Up => {
            if let Some(idx) = app.result_detail_vuln {
                if idx > 0 {
                    app.result_detail_vuln = Some(idx - 1);
                }
            }
        }
        KeyCode::Down => {
            if let Some(idx) = app.result_detail_vuln {
                let vulns = app.vulnerabilities();
                if idx + 1 < vulns.len() {
                    app.result_detail_vuln = Some(idx + 1);
                }
            }
        }
        KeyCode::Esc | KeyCode::Backspace => {
            app.result_detail_vuln = None;
        }
        _ => {}
    }
    false
}

fn handle_settings_key(app: &mut AppState, key: event::KeyEvent) -> bool {
    match key.code {
        KeyCode::Esc => {
            app.show_settings = false;
        }
        KeyCode::Tab => {
            app.settings_field = match app.settings_field {
                SettingsField::Provider => SettingsField::BaseUrl,
                SettingsField::BaseUrl => SettingsField::ApiKey,
                SettingsField::ApiKey => SettingsField::Model,
                SettingsField::Model => SettingsField::Timeout,
                SettingsField::Timeout => SettingsField::Retries,
                SettingsField::Retries => SettingsField::RemoteConsent,
                SettingsField::RemoteConsent => SettingsField::FallbackEnabled,
                SettingsField::FallbackEnabled => SettingsField::FallbackBaseUrl,
                SettingsField::FallbackBaseUrl => SettingsField::FallbackModel,
                SettingsField::FallbackModel => SettingsField::RealNuclei,
                SettingsField::RealNuclei => SettingsField::Provider,
            };
        }
        KeyCode::BackTab => {
            app.settings_field = match app.settings_field {
                SettingsField::Provider => SettingsField::RealNuclei,
                SettingsField::BaseUrl => SettingsField::Provider,
                SettingsField::ApiKey => SettingsField::BaseUrl,
                SettingsField::Model => SettingsField::ApiKey,
                SettingsField::Timeout => SettingsField::Model,
                SettingsField::Retries => SettingsField::Timeout,
                SettingsField::RemoteConsent => SettingsField::Retries,
                SettingsField::FallbackEnabled => SettingsField::RemoteConsent,
                SettingsField::FallbackBaseUrl => SettingsField::FallbackEnabled,
                SettingsField::FallbackModel => SettingsField::FallbackBaseUrl,
                SettingsField::RealNuclei => SettingsField::FallbackModel,
            };
        }
        KeyCode::Enter => match app.settings_field {
            SettingsField::Provider => {
                let labels = LlmProviderKind::all_labels();
                app.settings_provider_idx = (app.settings_provider_idx + 1) % labels.len();
                let provider = LlmProviderKind::from_label(labels[app.settings_provider_idx]);
                app.settings_input_base_url = provider.default_base_url().to_string();
                app.settings_input_model = provider.default_model().to_string();
            }
            SettingsField::RealNuclei => {
                app.settings_real_nuclei = !app.settings_real_nuclei;
            }
            SettingsField::RemoteConsent => {
                app.settings_remote_consent = !app.settings_remote_consent;
            }
            SettingsField::FallbackEnabled => {
                app.settings_fallback_enabled = !app.settings_fallback_enabled;
            }
            _ => {
                app.apply_settings();
            }
        },
        KeyCode::Up => {
            if matches!(app.settings_field, SettingsField::Provider)
                && app.settings_provider_idx > 0
            {
                app.settings_provider_idx -= 1;
                let labels = LlmProviderKind::all_labels();
                let provider = LlmProviderKind::from_label(labels[app.settings_provider_idx]);
                app.settings_input_base_url = provider.default_base_url().to_string();
                app.settings_input_model = provider.default_model().to_string();
            }
        }
        KeyCode::Down => {
            if matches!(app.settings_field, SettingsField::Provider) {
                let labels = LlmProviderKind::all_labels();
                if app.settings_provider_idx + 1 < labels.len() {
                    app.settings_provider_idx += 1;
                    let provider = LlmProviderKind::from_label(labels[app.settings_provider_idx]);
                    app.settings_input_base_url = provider.default_base_url().to_string();
                    app.settings_input_model = provider.default_model().to_string();
                }
            }
        }
        KeyCode::Char(c) => match app.settings_field {
            SettingsField::BaseUrl => app.settings_input_base_url.push(c),
            SettingsField::ApiKey => app.settings_input_api_key.push(c),
            SettingsField::Model => app.settings_input_model.push(c),
            SettingsField::Timeout if c.is_ascii_digit() => app.settings_input_timeout.push(c),
            SettingsField::Retries if c.is_ascii_digit() => app.settings_input_retries.push(c),
            SettingsField::FallbackBaseUrl => app.settings_input_fallback_base_url.push(c),
            SettingsField::FallbackModel => app.settings_input_fallback_model.push(c),
            SettingsField::RealNuclei => {
                if c == ' ' {
                    app.settings_real_nuclei = !app.settings_real_nuclei;
                }
            }
            SettingsField::RemoteConsent => {
                if c == ' ' {
                    app.settings_remote_consent = !app.settings_remote_consent;
                }
            }
            SettingsField::FallbackEnabled => {
                if c == ' ' {
                    app.settings_fallback_enabled = !app.settings_fallback_enabled;
                }
            }
            SettingsField::Provider | SettingsField::Timeout | SettingsField::Retries => {}
        },
        KeyCode::Backspace => match app.settings_field {
            SettingsField::BaseUrl => {
                let len = app.settings_input_base_url.chars().count();
                if len > 0 {
                    let s: String = app.settings_input_base_url.chars().take(len - 1).collect();
                    app.settings_input_base_url = s;
                }
            }
            SettingsField::ApiKey => {
                let len = app.settings_input_api_key.chars().count();
                if len > 0 {
                    let s: String = app.settings_input_api_key.chars().take(len - 1).collect();
                    app.settings_input_api_key = s;
                }
            }
            SettingsField::Model => {
                let len = app.settings_input_model.chars().count();
                if len > 0 {
                    let s: String = app.settings_input_model.chars().take(len - 1).collect();
                    app.settings_input_model = s;
                }
            }
            SettingsField::Timeout => pop_char(&mut app.settings_input_timeout),
            SettingsField::Retries => pop_char(&mut app.settings_input_retries),
            SettingsField::FallbackBaseUrl => pop_char(&mut app.settings_input_fallback_base_url),
            SettingsField::FallbackModel => pop_char(&mut app.settings_input_fallback_model),
            _ => {}
        },
        _ => {}
    }
    false
}

fn handle_settings_paste(app: &mut AppState, text: &str) {
    match app.settings_field {
        SettingsField::BaseUrl => app.settings_input_base_url.push_str(text),
        SettingsField::ApiKey => app.settings_input_api_key.push_str(text),
        SettingsField::Model => app.settings_input_model.push_str(text),
        SettingsField::Timeout if text.chars().all(|c| c.is_ascii_digit()) => {
            app.settings_input_timeout.push_str(text)
        }
        SettingsField::Retries if text.chars().all(|c| c.is_ascii_digit()) => {
            app.settings_input_retries.push_str(text)
        }
        SettingsField::FallbackBaseUrl => app.settings_input_fallback_base_url.push_str(text),
        SettingsField::FallbackModel => app.settings_input_fallback_model.push_str(text),
        _ => {}
    }
}

fn pop_char(value: &mut String) {
    value.pop();
}

fn handle_mouse(app: &mut AppState, mouse: MouseEvent) {
    match mouse.kind {
        MouseEventKind::ScrollUp => match app.step {
            AppStep::ToolSelect => {
                if app.tool_cursor > 0 {
                    app.tool_cursor -= 1;
                    ensure_tool_visible(app);
                }
            }
            AppStep::Execution => {
                if app.log_scroll > 0 {
                    app.log_scroll -= 3;
                }
            }
            AppStep::Results => {
                if app.show_didactic || app.show_detail {
                    if app.didactic_scroll > 0 {
                        app.didactic_scroll -= 3;
                    }
                } else if app.result_cursor > 0 {
                    app.result_cursor -= 1;
                }
            }
            _ => {}
        },
        MouseEventKind::ScrollDown => match app.step {
            AppStep::ToolSelect => {
                if app.tool_cursor < app.tools.len() - 1 {
                    app.tool_cursor += 1;
                    ensure_tool_visible(app);
                }
            }
            AppStep::Execution => {
                app.log_scroll += 3;
            }
            AppStep::Results => {
                if app.show_didactic || app.show_detail {
                    app.didactic_scroll += 3;
                } else {
                    let vulns = app.vulnerabilities();
                    if app.result_cursor + 1 < vulns.len() {
                        app.result_cursor += 1;
                    }
                }
            }
            _ => {}
        },
        MouseEventKind::Down(MouseButton::Left) => {
            handle_click(app, mouse.column, mouse.row);
        }
        _ => {}
    }
}

fn handle_click(app: &mut AppState, col: u16, row: u16) {
    if app.show_settings {
        handle_settings_click(app, col, row);
        return;
    }
    match app.step {
        AppStep::Splash => handle_splash_click(app, col, row),
        AppStep::ToolSelect => handle_tool_select_click(app, col, row),
        AppStep::Execution => handle_execution_click(app, col, row),
        AppStep::Analysis => handle_analysis_click(app, col, row),
        AppStep::Results => handle_results_click(app, col, row),
    }
}

fn handle_splash_click(app: &mut AppState, col: u16, row: u16) {
    if in_rect(col, row, app.splash_url_rect) {
        return;
    }
    if in_rect(col, row, app.splash_start_rect) {
        if app.config.target_url.is_empty() {
            app.config.target_url = "http://localhost:8080".to_string();
        }
        app.step = AppStep::ToolSelect;
        app.tool_detecting = true;
        app.tool_detect_tick = 0;
        return;
    }
    if in_rect(col, row, app.splash_auto_rect) {
        app.set_mode(ExecutionType::Auto);
        return;
    }
    if in_rect(col, row, app.splash_assisted_rect) {
        app.set_mode(ExecutionType::Assisted);
        return;
    }
    if in_rect(col, row, app.ai_model_area) {
        app.show_settings = true;
    }
}

fn in_rect(col: u16, row: u16, r: Rect) -> bool {
    col >= r.x
        && col < r.x.saturating_add(r.width)
        && row >= r.y
        && row < r.y.saturating_add(r.height)
}

fn handle_tool_select_click(app: &mut AppState, col: u16, row: u16) {
    if app.tool_detecting {
        return;
    }
    if in_rect(col, row, app.tools_back_rect) {
        app.step = AppStep::Splash;
        app.tool_detecting = true;
        app.tool_detect_tick = 0;
        return;
    }
    if in_rect(col, row, app.tools_list_rect) {
        let inner_y = app.tools_list_rect.y + 1;
        let _item_h = 1u16;
        let relative_row = row.saturating_sub(inner_y);
        let idx = relative_row / _item_h;
        let idx = idx as usize;
        if idx < app.tools.len() {
            app.tool_cursor = idx;
            app.tools[idx].selected = !app.tools[idx].selected;
        }
        return;
    }
    if in_rect(col, row, app.tools_run_rect) {
        let has_selected = app.tools.iter().any(|t| t.selected);
        if has_selected {
            app.step = AppStep::Execution;
            app.init_execution();
        }
    }
}

fn handle_execution_click(app: &mut AppState, col: u16, row: u16) {
    if in_rect(col, row, app.exec_back_rect) {
        app.cancel_run();
        return;
    }
    if in_rect(col, row, app.exec_pause_rect) {
        app.pause_or_resume();
        return;
    }
    if in_rect(col, row, app.exec_cancel_rect) {
        app.cancel_run();
    }
}

fn handle_analysis_click(app: &mut AppState, col: u16, row: u16) {
    if in_rect(col, row, app.analysis_back_rect) {
        app.orchestrator.cancelled = true;
        app.step = AppStep::ToolSelect;
        app.tool_detecting = false;
    }
}

fn handle_results_click(app: &mut AppState, col: u16, row: u16) {
    if app.show_didactic {
        if in_rect(col, row, app.didactic_back_rect) {
            app.show_didactic = false;
            app.didactic_scroll = 0;
        }
        return;
    }
    if app.show_detail {
        return;
    }
    if app.result_detail_vuln.is_some() {
        if in_rect(col, row, app.results_back_rect) {
            app.result_detail_vuln = None;
            app.result_action_cursor = 0;
            return;
        }
        if in_rect(col, row, app.results_didactic_rect) {
            app.show_didactic = true;
            app.didactic_scroll = 0;
            return;
        }
        return;
    }
    if in_rect(col, row, app.results_new_scan_rect) {
        app.step = AppStep::Splash;
        app.result_detail_vuln = None;
        app.show_didactic = false;
        app.md_exported = false;
        return;
    }
    if in_rect(col, row, app.results_export_rect) {
        let md = app.export_md();
        let _ = std::fs::write("smartsec-report.md", md);
        app.md_exported = true;
        return;
    }
    if in_rect(col, row, app.results_didactic_rect) {
        app.show_didactic = true;
        app.didactic_scroll = 0;
        return;
    }
    if in_rect(col, row, app.results_list_rect) {
        let inner_y = app.results_list_rect.y + 1;
        let relative_row = row.saturating_sub(inner_y);
        let idx = relative_row as usize;
        let vulns = app.vulnerabilities();
        if idx < vulns.len() {
            app.result_cursor = idx;
            app.result_focus_list = true;
            app.result_detail_vuln = Some(idx);
        }
    }
}

fn handle_settings_click(app: &mut AppState, col: u16, row: u16) {
    if in_rect(col, row, app.settings_save_rect) {
        app.apply_settings();
        return;
    }
    if in_rect(col, row, app.settings_cancel_rect) {
        app.show_settings = false;
    }
}

fn ensure_tool_visible(app: &mut AppState) {
    if app.tool_cursor < app.tool_scroll {
        app.tool_scroll = app.tool_cursor;
    }
    let visible = 8;
    if app.tool_cursor >= app.tool_scroll + visible {
        app.tool_scroll = app.tool_cursor - visible + 1;
    }
}
