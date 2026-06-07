use crate::config::execution_type::ExecutionType;
use crate::tui::state::{AppState, ToolStatus};
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Style, Stylize},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, List, ListItem, ListState, Paragraph, Wrap},
    Frame,
};

pub fn render(app: &mut AppState, frame: &mut Frame, area: Rect) {
    let bg = Block::default().style(Style::default().bg(Color::Rgb(8, 8, 16)));
    frame.render_widget(bg, area);
    let chunks = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(3),
        Constraint::Length(3),
    ])
    .split(area);
    render_header(app, frame, chunks[0]);
    render_tools(app, frame, chunks[1]);
    render_footer(app, frame, chunks[2]);
}

fn render_header(app: &AppState, frame: &mut Frame, area: Rect) {
    let block = Block::default()
        .borders(Borders::BOTTOM)
        .border_style(Style::default().fg(Color::DarkGray))
        .style(Style::default().bg(Color::Rgb(20, 20, 40)));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let detecting = app.tool_detecting;
    let spinner = app.spinner_char();
    let title = if detecting {
        format!(
            "{} Analyzing project at: {} ...",
            spinner, app.config.target_url
        )
    } else {
        format!("✓ Analysis complete — {} tools identified", app.tools.len())
    };
    let title_color = if detecting { Color::Cyan } else { Color::Green };

    let header = Paragraph::new(Line::from(vec![
        Span::styled(" ◆ ", Style::default().fg(Color::Cyan)),
        Span::styled("Tool Selection", Style::default().fg(Color::White).bold()),
        Span::styled(" ", Style::default()),
        Span::styled(title, Style::default().fg(title_color)),
    ]))
    .style(Style::default().bg(Color::Rgb(20, 20, 40)));
    frame.render_widget(header, inner);
}

fn render_tools(app: &mut AppState, frame: &mut Frame, area: Rect) {
    let chunks =
        Layout::horizontal([Constraint::Percentage(55), Constraint::Percentage(45)]).split(area);
    render_tool_list(app, frame, chunks[0]);
    render_tool_detail(app, frame, chunks[1]);
}

fn render_tool_list(app: &mut AppState, frame: &mut Frame, area: Rect) {
    let block = Block::default()
        .borders(Borders::all())
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(Line::from(vec![Span::styled(
            " Security Tools ",
            Style::default().fg(Color::Cyan).bold(),
        )]))
        .style(Style::default().bg(Color::Rgb(12, 12, 24)));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let items: Vec<ListItem> = app
        .tools
        .iter()
        .enumerate()
        .map(|(i, t)| {
            let is_cursor = i == app.tool_cursor && app.mode() == ExecutionType::Assisted;
            let check = if t.selected { "●" } else { "○" };
            let check_color = if t.selected {
                Color::Green
            } else {
                Color::DarkGray
            };
            let name_style = if is_cursor {
                Style::default().fg(Color::White).bold()
            } else {
                Style::default().fg(Color::Gray)
            };
            let line = Line::from(vec![
                Span::styled(format!(" {} ", check), Style::default().fg(check_color)),
                Span::styled(format!("{:<12}", t.tool.name), name_style),
                Span::styled(
                    format!("[{}]", t.tool.category),
                    Style::default().fg(Color::DarkGray).italic(),
                ),
            ]);
            let bg = if is_cursor {
                Color::Rgb(30, 30, 60)
            } else {
                Color::Rgb(12, 12, 24)
            };
            ListItem::new(line).style(Style::default().bg(bg))
        })
        .collect();

    let mut state = ListState::default();
    if app.mode() == ExecutionType::Assisted && !app.tool_detecting {
        state.select(Some(app.tool_cursor));
    }
    let list = List::new(items)
        .style(Style::default().bg(Color::Rgb(12, 12, 24)))
        .highlight_style(Style::default().bg(Color::Rgb(30, 30, 60)));
    frame.render_stateful_widget(list, inner, &mut state);
}

fn render_tool_detail(app: &AppState, frame: &mut Frame, area: Rect) {
    let block = Block::default()
        .borders(Borders::all())
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(Line::from(vec![Span::styled(
            " Details ",
            Style::default().fg(Color::Cyan).bold(),
        )]))
        .style(Style::default().bg(Color::Rgb(12, 12, 24)));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    if app.tool_cursor >= app.tools.len() {
        return;
    }
    let tool = &app.tools[app.tool_cursor];
    let selected_count = app.tools.iter().filter(|t| t.selected).count();
    let total = app.tools.len();

    let status_span = match tool.status {
        ToolStatus::Pending => Span::styled("○ Pending", Style::default().fg(Color::DarkGray)),
        ToolStatus::Running => Span::styled(
            format!("{} Running", app.spinner_char()),
            Style::default().fg(Color::Yellow),
        ),
        ToolStatus::Done => Span::styled("✓ Complete", Style::default().fg(Color::Green)),
        ToolStatus::Failed => Span::styled("✗ Failed", Style::default().fg(Color::Red)),
    };

    let detail = ratatui::text::Text::from(vec![
        Line::from(""),
        Line::from(vec![
            Span::styled(" Name: ", Style::default().fg(Color::DarkGray)),
            Span::styled(tool.tool.name, Style::default().fg(Color::White).bold()),
        ]),
        Line::from(vec![
            Span::styled(" Type: ", Style::default().fg(Color::DarkGray)),
            Span::styled(tool.tool.category, Style::default().fg(Color::Cyan)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled(" ", Style::default()),
            Span::styled(tool.tool.description, Style::default().fg(Color::Gray)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled(" Status: ", Style::default().fg(Color::DarkGray)),
            status_span,
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled(" Selected: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("{}/{}", selected_count, total),
                Style::default().fg(Color::Green),
            ),
        ]),
    ]);
    let para = Paragraph::new(detail)
        .style(Style::default().bg(Color::Rgb(12, 12, 24)))
        .wrap(Wrap { trim: true });
    frame.render_widget(para, inner);
}

fn render_footer(app: &AppState, frame: &mut Frame, area: Rect) {
    let bar = Block::default()
        .borders(Borders::TOP)
        .border_style(Style::default().fg(Color::DarkGray))
        .style(Style::default().bg(Color::Rgb(20, 20, 40)));
    let inner = bar.inner(area);
    frame.render_widget(bar, area);

    let mode_text = match app.mode() {
        ExecutionType::Auto => "AUTO",
        ExecutionType::Assisted => "ASSISTED",
    };

    if app.tool_detecting {
        let footer = Paragraph::new(Line::from(vec![
            Span::styled(
                format!(" ◆ {} ", mode_text),
                Style::default().fg(Color::Cyan).bold(),
            ),
            Span::styled(" │ ", Style::default().fg(Color::DarkGray)),
            Span::styled("Detecting tools...", Style::default().fg(Color::Cyan)),
        ]))
        .style(Style::default().bg(Color::Rgb(20, 20, 40)));
        frame.render_widget(footer, inner);
    } else if app.mode() == ExecutionType::Auto {
        let footer = Paragraph::new(Line::from(vec![
            Span::styled(
                format!(" ◆ {} ", mode_text),
                Style::default().fg(Color::Cyan).bold(),
            ),
            Span::styled(" │ ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                "Proceeding automatically...",
                Style::default().fg(Color::Cyan),
            ),
        ]))
        .style(Style::default().bg(Color::Rgb(20, 20, 40)));
        frame.render_widget(footer, inner);
    } else {
        let footer = Paragraph::new(Line::from(vec![
            Span::styled(
                format!(" ◆ {} ", mode_text),
                Style::default().fg(Color::Green).bold(),
            ),
            Span::styled(" │ ", Style::default().fg(Color::DarkGray)),
            Span::styled("↑↓", Style::default().fg(Color::White)),
            Span::styled(" Navigate ", Style::default().fg(Color::DarkGray)),
            Span::styled("Space", Style::default().fg(Color::White)),
            Span::styled(" Toggle ", Style::default().fg(Color::DarkGray)),
            Span::styled("Enter", Style::default().fg(Color::White)),
            Span::styled(" Run ", Style::default().fg(Color::DarkGray)),
            Span::styled("Esc", Style::default().fg(Color::White)),
            Span::styled(" Quit", Style::default().fg(Color::DarkGray)),
        ]))
        .style(Style::default().bg(Color::Rgb(20, 20, 40)));
        frame.render_widget(footer, inner);
    }
}
