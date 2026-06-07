use crate::config::execution_type::ExecutionType;
use crate::config::llm_config::LlmProviderKind;
use crate::tui::state::{AppState, AppStep, SettingsField};
use crossterm::event::{
    self, Event, KeyCode, KeyEventKind, KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
};
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
        KeyCode::Left => {
            if app.result_action_cursor > 0 {
                app.result_action_cursor -= 1;
            }
        }
        KeyCode::Right => {
            if app.result_action_cursor < 1 {
                app.result_action_cursor += 1;
            }
        }
        KeyCode::Enter => match app.result_action_cursor {
            0 => {
                app.result_detail_vuln = None;
                app.result_action_cursor = 0;
            }
            1 => {
                app.show_didactic = true;
                app.didactic_scroll = 0;
            }
            _ => {}
        },
        KeyCode::Esc | KeyCode::Backspace => {
            app.result_detail_vuln = None;
            app.result_action_cursor = 0;
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
                SettingsField::Model => SettingsField::RealNmap,
                SettingsField::RealNmap => SettingsField::Provider,
            };
        }
        KeyCode::BackTab => {
            app.settings_field = match app.settings_field {
                SettingsField::Provider => SettingsField::RealNmap,
                SettingsField::BaseUrl => SettingsField::Provider,
                SettingsField::ApiKey => SettingsField::BaseUrl,
                SettingsField::Model => SettingsField::ApiKey,
                SettingsField::RealNmap => SettingsField::Model,
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
            SettingsField::RealNmap => {
                app.settings_real_nmap = !app.settings_real_nmap;
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
            SettingsField::RealNmap => {
                if c == ' ' {
                    app.settings_real_nmap = !app.settings_real_nmap;
                }
            }
            SettingsField::Provider => {}
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
        _ => {}
    }
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
        return;
    }
    match app.step {
        AppStep::Splash => handle_splash_click(app, col, row),
        AppStep::Results => handle_results_click(app, col, row),
        _ => {}
    }
}

fn handle_splash_click(_app: &mut AppState, _col: u16, _row: u16) {}

fn handle_results_click(app: &mut AppState, _col: u16, _row: u16) {
    if app.show_didactic || app.show_detail {}
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
