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
            Event::Paste(text) => {
                if app.step == crate::app::AppStep::Splash {
                    app.url_input.push_str(&text);
                    app.url_cursor = app.url_input.chars().count();
                }
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

    if app.result_detail_vuln.is_some() {
        return handle_results_detail_key(app, key);
    }

    let actions = &[
        crate::app::ResultAction::ExportMd,
        crate::app::ResultAction::ExplainDidactic,
    ][..];

    match key.code {
        KeyCode::Up => {
            app.result_focus_list = true;
            if app.result_cursor > 0 {
                app.result_cursor -= 1;
                let visible = 8;
                if app.result_cursor < app.result_scroll {
                    app.result_scroll = app.result_cursor;
                } else if app.result_cursor >= app.result_scroll + visible {
                    app.result_scroll = app.result_cursor - visible + 1;
                }
            }
        }
        KeyCode::Down => {
            app.result_focus_list = true;
            let vulns = app.vulnerabilities();
            if app.result_cursor + 1 < vulns.len() {
                app.result_cursor += 1;
                let visible = 8;
                if app.result_cursor >= app.result_scroll + visible {
                    app.result_scroll = app.result_cursor - visible + 1;
                }
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
            if app.result_action_cursor < actions.len() - 1 {
                app.result_action_cursor += 1;
            }
        }
        KeyCode::Enter => {
            if app.result_focus_list {
                app.result_detail_vuln = Some(app.result_cursor);
                app.result_action_cursor = 0;
            } else {
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
    let actions = &[
        crate::app::ResultAction::BackToSummary,
        crate::app::ResultAction::ExplainDidactic,
    ][..];
    match key.code {
        KeyCode::Up => {
            if let Some(idx) = app.result_detail_vuln
                && idx > 0
            {
                app.result_detail_vuln = Some(idx - 1);
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
            if app.result_action_cursor < actions.len() - 1 {
                app.result_action_cursor += 1;
            }
        }
        KeyCode::Enter => {
            let action = actions.get(app.result_action_cursor).copied();
            match action {
                Some(crate::app::ResultAction::BackToSummary) => {
                    app.result_detail_vuln = None;
                    app.result_action_cursor = 0;
                }
                Some(crate::app::ResultAction::ExplainDidactic) => {
                    app.show_didactic = true;
                    app.didactic_scroll = 0;
                }
                Some(crate::app::ResultAction::ExplainDetail) => {
                    app.show_detail = true;
                    app.didactic_scroll = 0;
                }
                _ => {}
            }
        }
        KeyCode::Esc | KeyCode::Backspace => {
            app.result_detail_vuln = None;
            app.result_action_cursor = 0;
        }
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
                } else if app.result_cursor > 0 {
                    app.result_cursor -= 1;
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
    if click_esc_quit(app, col, row) {
        app.should_quit = true;
        return;
    }
    match app.step {
        crate::app::AppStep::Splash => handle_splash_click(app, col, row),
        crate::app::AppStep::ToolSelect => handle_tool_click(app, col, row),
        crate::app::AppStep::Execution => handle_execution_click(app, col, row),
        crate::app::AppStep::Analysis => handle_analysis_click(app, col, row),
        crate::app::AppStep::Results => handle_results_click(app, col, row),
    }
}

fn handle_splash_click(app: &mut AppState, col: u16, row: u16) {
    let content_chunks = ratatui::layout::Layout::vertical([
        ratatui::layout::Constraint::Min(3),
        ratatui::layout::Constraint::Length(3),
    ])
    .split(app.screen_area);
    let content_area = content_chunks[0];
    let center = crate::ui::centered_rect(70, 70, content_area);

    let logo_height = 11u16;
    let chunks = ratatui::layout::Layout::vertical([
        ratatui::layout::Constraint::Length(logo_height),
        ratatui::layout::Constraint::Length(2),
        ratatui::layout::Constraint::Length(3),
        ratatui::layout::Constraint::Length(2),
        ratatui::layout::Constraint::Length(1),
        ratatui::layout::Constraint::Length(5),
        ratatui::layout::Constraint::Length(2),
        ratatui::layout::Constraint::Length(2),
    ])
    .split(center);

    let mode_area = chunks[4];
    let text_width = "Mode: AUTO / ASSISTED [Tab to switch]".len() as u16;
    let text_start_x = mode_area.x + mode_area.width.saturating_sub(text_width) / 2;

    if row == mode_area.y {
        let auto_start = text_start_x as usize + "Mode: ".len();
        let auto_end = auto_start + " AUTO ".len();
        let assisted_start = auto_end + " / ".len();
        let assisted_end = assisted_start + " ASSISTED ".len();
        if (auto_start..auto_end).contains(&(col as usize)) {
            app.mode = AppMode::Auto;
        } else if (assisted_start..assisted_end).contains(&(col as usize)) {
            app.mode = AppMode::Assisted;
        }
    }

    let url_area = chunks[6];
    if row >= url_area.y && row < url_area.y + url_area.height {
        let inner_x = url_area.x + 1;
        let inner_w = url_area.width.saturating_sub(2) as usize;
        if col >= inner_x && ((col - inner_x) as usize) < inner_w {
            let char_pos = (col - inner_x) as usize;
            app.url_cursor = char_pos.min(app.url_input.chars().count());
        }
    }

    let hint_area = chunks[7];
    if row >= hint_area.y && row < hint_area.y + hint_area.height {
        if app.url_input.is_empty() {
            app.url_input = "http://localhost:8080".to_string();
        }
        app.step = crate::app::AppStep::ToolSelect;
        app.tool_detecting = true;
        app.tool_detect_tick = 0;
    }
}

fn click_esc_quit(app: &AppState, _col: u16, row: u16) -> bool {
    if app.step == crate::app::AppStep::Splash {
        let content_chunks = ratatui::layout::Layout::vertical([
            ratatui::layout::Constraint::Min(3),
            ratatui::layout::Constraint::Length(3),
        ])
        .split(app.screen_area);
        let status_bar_y = content_chunks[1].y;
        row >= status_bar_y && row < status_bar_y + 3
    } else {
        let footer_y = app.screen_area.bottom().saturating_sub(3);
        row >= footer_y && row < app.screen_area.bottom()
    }
}

fn handle_tool_click(app: &mut AppState, col: u16, row: u16) {
    if app.mode == AppMode::Auto || app.tool_detecting {
        return;
    }
    let outer_chunks = ratatui::layout::Layout::vertical([
        ratatui::layout::Constraint::Length(3),
        ratatui::layout::Constraint::Min(3),
        ratatui::layout::Constraint::Length(3),
    ])
    .split(app.screen_area);
    let body_area = outer_chunks[1];
    let body_chunks = ratatui::layout::Layout::horizontal([
        ratatui::layout::Constraint::Percentage(55),
        ratatui::layout::Constraint::Percentage(45),
    ])
    .split(body_area);
    let list_block_area = body_chunks[0];
    let list_inner_y = list_block_area.y + 1;
    let list_inner_h = list_block_area.height.saturating_sub(2);

    if row >= list_inner_y && row < list_inner_y + list_inner_h {
        let idx = (row - list_inner_y) as usize + app.tool_scroll;
        if idx < app.tools.len() {
            app.tool_cursor = idx;
            app.tools[idx].selected = !app.tools[idx].selected;
        }
    }

    let footer_area = outer_chunks[2];
    let footer_inner_y = footer_area.y + 1;
    if row == footer_inner_y {
        let enter_label = "Enter";
        let mode_text = match app.mode {
            AppMode::Auto => "AUTO",
            AppMode::Assisted => "ASSISTED",
        };
        let prefix = format!(" ◆ {} │ ", mode_text);
        let nav = "↑↓ Navigate Space Toggle a Add d Remove ";
        let enter_start_x = footer_area.x as usize + prefix.len() + nav.len();
        let enter_end_x = enter_start_x + enter_label.len();
        if (enter_start_x..enter_end_x).contains(&(col as usize)) {
            let has_selected = app.tools.iter().any(|t| t.selected);
            if has_selected {
                app.step = crate::app::AppStep::Execution;
                app.init_execution();
            }
        }
    }
}

fn handle_execution_click(app: &mut AppState, col: u16, row: u16) {
    let outer_chunks = ratatui::layout::Layout::vertical([
        ratatui::layout::Constraint::Length(3),
        ratatui::layout::Constraint::Min(3),
        ratatui::layout::Constraint::Length(3),
    ])
    .split(app.screen_area);
    let footer_area = outer_chunks[2];
    let _ = (col, row, footer_area);
}

fn handle_analysis_click(app: &mut AppState, col: u16, row: u16) {
    let outer_chunks = ratatui::layout::Layout::vertical([
        ratatui::layout::Constraint::Length(3),
        ratatui::layout::Constraint::Min(3),
        ratatui::layout::Constraint::Length(3),
    ])
    .split(app.screen_area);
    let footer_area = outer_chunks[2];
    let _ = (col, row, footer_area);
}

fn handle_results_click(app: &mut AppState, col: u16, row: u16) {
    if app.show_didactic || app.show_detail {
        return;
    }
    let outer_chunks = ratatui::layout::Layout::vertical([
        ratatui::layout::Constraint::Length(3),
        ratatui::layout::Constraint::Min(3),
        ratatui::layout::Constraint::Length(3),
    ])
    .split(app.screen_area);

    if app.result_detail_vuln.is_none() {
        let body_area = outer_chunks[1];
        let body_chunks = ratatui::layout::Layout::horizontal([
            ratatui::layout::Constraint::Percentage(35),
            ratatui::layout::Constraint::Percentage(65),
        ])
        .split(body_area);
        let list_block_area = body_chunks[1];
        let list_inner_y = list_block_area.y + 1;
        let list_inner_h = list_block_area.height.saturating_sub(2);

        if row >= list_inner_y && row < list_inner_y + list_inner_h {
            let idx = (row - list_inner_y) as usize + app.result_scroll;
            let vulns = app.vulnerabilities();
            if idx < vulns.len() {
                app.result_cursor = idx;
                app.result_detail_vuln = Some(idx);
                app.result_action_cursor = 0;
            }
        }

        let footer_area = outer_chunks[2];
        let footer_inner_y = footer_area.y + 1;
        if row == footer_inner_y {
            let actions: &[crate::app::ResultAction] = &[
                crate::app::ResultAction::ExportMd,
                crate::app::ResultAction::ExplainDidactic,
            ];
            let labels = ["Export .md", "Explain Didactic"];
            let mut x = footer_area.x + 2;
            for (i, label) in labels.iter().enumerate() {
                let btn_w = label.len() as u16 + 2;
                if col >= x && col < x + btn_w {
                    app.result_action_cursor = i;
                    match actions[i] {
                        crate::app::ResultAction::ExportMd => {
                            let md = app.export_md();
                            let _ = std::fs::write("smartsec-report.md", md);
                            app.md_exported = true;
                        }
                        crate::app::ResultAction::ExplainDidactic => {
                            app.show_didactic = true;
                            app.didactic_scroll = 0;
                        }
                        _ => {}
                    }
                    break;
                }
                x += btn_w + 1;
            }
        }
    } else {
        let footer_area = outer_chunks[2];
        let footer_inner_y = footer_area.y + 1;
        if row == footer_inner_y {
            let actions: &[crate::app::ResultAction] = &[
                crate::app::ResultAction::BackToSummary,
                crate::app::ResultAction::ExplainDidactic,
            ];
            let labels = ["← Back", "Explain Didactic"];
            let mut x = footer_area.x + 2;
            for (i, label) in labels.iter().enumerate() {
                let btn_w = label.len() as u16 + 2;
                if col >= x && col < x + btn_w {
                    app.result_action_cursor = i;
                    match actions[i] {
                        crate::app::ResultAction::BackToSummary => {
                            app.result_detail_vuln = None;
                            app.result_action_cursor = 0;
                        }
                        crate::app::ResultAction::ExplainDidactic => {
                            app.show_didactic = true;
                            app.didactic_scroll = 0;
                        }
                        _ => {}
                    }
                    break;
                }
                x += btn_w + 1;
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
