use crate::app::{AppMode, AppState};
use crossterm::event::{
    self, Event, KeyCode, KeyEventKind, MouseButton, MouseEvent, MouseEventKind,
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
            Event::Resize(_, _) => {}
            _ => {}
        }
    }
    Ok(false)
}

fn handle_key(app: &mut AppState, key: event::KeyEvent) -> bool {
    match app.step {
        crate::app::AppStep::Splash => handle_splash_key(app, key),
        crate::app::AppStep::ToolSelect => handle_tool_select_key(app, key),
        crate::app::AppStep::Execution => handle_execution_key(key),
        crate::app::AppStep::Analysis => handle_analysis_key(key),
        crate::app::AppStep::Results => handle_results_key(app, key),
    }
}

fn handle_splash_key(app: &mut AppState, key: event::KeyEvent) -> bool {
    match key.code {
        KeyCode::Tab | KeyCode::BackTab => {
            app.mode = match app.mode {
                AppMode::Auto => AppMode::Assisted,
                AppMode::Assisted => AppMode::Auto,
            };
        }
        KeyCode::Enter => {
            if app.url_input.is_empty() {
                app.url_input = "http://localhost:8080".to_string();
            }
            app.step = crate::app::AppStep::ToolSelect;
            app.tool_detecting = true;
            app.tool_detect_tick = 0;
        }
        KeyCode::Char(c) => {
            let before: String = app.url_input.chars().take(app.url_cursor).collect();
            let after: String = app.url_input.chars().skip(app.url_cursor).collect();
            app.url_input = format!("{}{}{}", before, c, after);
            app.url_cursor += 1;
        }
        KeyCode::Backspace => {
            if app.url_cursor > 0 {
                let before: String = app.url_input.chars().take(app.url_cursor - 1).collect();
                let after: String = app.url_input.chars().skip(app.url_cursor).collect();
                app.url_input = format!("{}{}", before, after);
                app.url_cursor -= 1;
            }
        }
        KeyCode::Delete => {
            let len = app.url_input.chars().count();
            if app.url_cursor < len {
                let before: String = app.url_input.chars().take(app.url_cursor).collect();
                let after: String = app.url_input.chars().skip(app.url_cursor + 1).collect();
                app.url_input = format!("{}{}", before, after);
            }
        }
        KeyCode::Left => {
            if app.url_cursor > 0 {
                app.url_cursor -= 1;
            }
        }
        KeyCode::Right => {
            if app.url_cursor < app.url_input.chars().count() {
                app.url_cursor += 1;
            }
        }
        KeyCode::Home => {
            app.url_cursor = 0;
        }
        KeyCode::End => {
            app.url_cursor = app.url_input.chars().count();
        }
        KeyCode::Esc => return true,
        _ => {}
    }
    false
}

fn handle_tool_select_key(app: &mut AppState, key: event::KeyEvent) -> bool {
    if app.mode == AppMode::Auto {
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
        KeyCode::Char('a') => {
            if !app.tool_detecting {
                let name = "CustomTool";
                let exists = app.tools.iter().any(|t| t.tool.name == name);
                if !exists {
                    use crate::mock::tools::SecurityTool;
                    app.tools.push(crate::app::ToolItem {
                        tool: SecurityTool {
                            name: "CustomTool",
                            description: "Custom security tool",
                            category: "Custom",
                        },
                        selected: true,
                        status: crate::app::ToolStatus::Pending,
                        progress: 0,
                    });
                }
            }
        }
        KeyCode::Char('d') => {
            if !app.tool_detecting && app.tools.len() > 1 {
                app.tools.remove(app.tool_cursor);
                if app.tool_cursor >= app.tools.len() && app.tool_cursor > 0 {
                    app.tool_cursor -= 1;
                }
                ensure_tool_visible(app);
            }
        }
        KeyCode::Enter => {
            if !app.tool_detecting {
                let has_selected = app.tools.iter().any(|t| t.selected);
                if has_selected {
                    app.step = crate::app::AppStep::Execution;
                    app.init_execution();
                }
            }
        }
        KeyCode::Esc => return true,
        _ => {}
    }
    false
}

fn handle_execution_key(key: event::KeyEvent) -> bool {
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
    let actions = if app.result_detail_vuln.is_some() {
        &[
            crate::app::ResultAction::BackToSummary,
            crate::app::ResultAction::ExplainDidactic,
        ][..]
    } else {
        &[
            crate::app::ResultAction::ExportMd,
            crate::app::ResultAction::ExplainDidactic,
        ][..]
    };
    match key.code {
        KeyCode::Left => {
            if app.result_action_cursor > 0 {
                app.result_action_cursor -= 1;
            }
        }
        KeyCode::Right => {
            if app.result_action_cursor < actions.len() - 1 {
                app.result_action_cursor += 1;
            }
        }
        KeyCode::Enter => {
            let action = actions.get(app.result_action_cursor).copied();
            match action {
                Some(crate::app::ResultAction::ExportMd) => {
                    let md = app.export_md();
                    let _ = std::fs::write("smartsec-report.md", md);
                    app.md_exported = true;
                }
                Some(crate::app::ResultAction::ExplainDidactic) => {
                    app.show_didactic = true;
                    app.didactic_scroll = 0;
                }
                Some(crate::app::ResultAction::ExplainDetail) => {
                    app.show_detail = true;
                    app.didactic_scroll = 0;
                }
                Some(crate::app::ResultAction::BackToSummary) => {
                    app.result_detail_vuln = None;
                    app.result_action_cursor = 0;
                }
                None => {}
            }
        }
        KeyCode::Up => {
            if app.result_detail_vuln.is_none() && app.result_scroll > 0 {
                app.result_scroll -= 1;
            }
        }
        KeyCode::Down => {
            if app.result_detail_vuln.is_none() {
                app.result_scroll += 1;
            }
        }
        KeyCode::Esc => return true,
        _ => {}
    }
    false
}

fn handle_mouse(app: &mut AppState, mouse: MouseEvent) {
    match mouse.kind {
        MouseEventKind::ScrollUp => match app.step {
            crate::app::AppStep::ToolSelect => {
                if app.tool_cursor > 0 {
                    app.tool_cursor -= 1;
                    ensure_tool_visible(app);
                }
            }
            crate::app::AppStep::Execution => {
                if app.log_scroll > 0 {
                    app.log_scroll -= 3;
                }
            }
            crate::app::AppStep::Results => {
                if app.show_didactic || app.show_detail {
                    if app.didactic_scroll > 0 {
                        app.didactic_scroll -= 3;
                    }
                } else if app.result_scroll > 0 {
                    app.result_scroll -= 3;
                }
            }
            _ => {}
        },
        MouseEventKind::ScrollDown => match app.step {
            crate::app::AppStep::ToolSelect => {
                if app.tool_cursor < app.tools.len() - 1 {
                    app.tool_cursor += 1;
                    ensure_tool_visible(app);
                }
            }
            crate::app::AppStep::Execution => {
                app.log_scroll += 3;
            }
            crate::app::AppStep::Results => {
                if app.show_didactic || app.show_detail {
                    app.didactic_scroll += 3;
                } else {
                    app.result_scroll += 3;
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
    match app.step {
        crate::app::AppStep::Splash => handle_splash_click(app, col, row),
        crate::app::AppStep::ToolSelect => handle_tool_click(app, row),
        crate::app::AppStep::Results => handle_results_click(app, col, row),
        _ => {}
    }
}

fn handle_splash_click(app: &mut AppState, col: u16, row: u16) {
    let center = crate::ui::centered_rect(70, 70, app.screen_area);
    let chunks = ratatui::layout::Layout::vertical([
        ratatui::layout::Constraint::Length(11),
        ratatui::layout::Constraint::Length(2),
        ratatui::layout::Constraint::Length(3),
        ratatui::layout::Constraint::Length(2),
        ratatui::layout::Constraint::Length(1),
        ratatui::layout::Constraint::Length(3),
        ratatui::layout::Constraint::Length(2),
        ratatui::layout::Constraint::Length(1),
    ])
    .split(center);

    let mode_area = chunks[4];
    if row == mode_area.y {
        let auto_start = mode_area.x as usize + "Mode: ".len() + 1;
        let auto_end = auto_start + " AUTO ".len();
        let assisted_start = auto_end + " / ".len() + 1;
        let assisted_end = assisted_start + " ASSISTED ".len();
        if (auto_start..auto_end).contains(&(col as usize)) {
            app.mode = AppMode::Auto;
        } else if (assisted_start..assisted_end).contains(&(col as usize)) {
            app.mode = AppMode::Assisted;
        }
    }
}

fn handle_tool_click(app: &mut AppState, row: u16) {
    if app.mode == AppMode::Auto || app.tool_detecting {
        return;
    }
    let list_start = 6u16;
    if row >= list_start {
        let idx = (row - list_start) as usize + app.tool_scroll;
        if idx < app.tools.len() {
            app.tool_cursor = idx;
            app.tools[idx].selected = !app.tools[idx].selected;
        }
    }
}

fn handle_results_click(app: &mut AppState, col: u16, row: u16) {
    if app.show_didactic || app.show_detail {
        return;
    }
    if app.result_detail_vuln.is_none() {
        let list_start = 8u16;
        if row >= list_start && row < list_start + 10 {
            let idx = (row - list_start) as usize + app.result_scroll;
            let vulns = app.vulnerabilities();
            if idx < vulns.len() {
                app.result_detail_vuln = Some(idx);
                app.result_action_cursor = 0;
            }
        }
        let action_y = list_start + 12;
        if row == action_y {
            if col < 20 {
                let md = app.export_md();
                let _ = std::fs::write("smartsec-report.md", md);
                app.md_exported = true;
            } else if col < 44 {
                app.show_didactic = true;
                app.didactic_scroll = 0;
            }
        }
    } else {
        let action_y = 6u16;
        if row == action_y {
            if col < 20 {
                app.result_detail_vuln = None;
                app.result_action_cursor = 0;
            } else if col < 44 {
                app.show_didactic = true;
                app.didactic_scroll = 0;
            }
        }
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
