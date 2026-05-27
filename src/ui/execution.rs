use crate::app::{AppMode, AppState, ToolStatus};
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Style, Stylize},
    text::{Line, Span, Text},
    widgets::{Block, BorderType, Borders, Gauge, Paragraph, Wrap},
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
    render_body(app, frame, chunks[1]);
    render_footer(app, frame, chunks[2]);
}

fn render_header(app: &AppState, frame: &mut Frame, area: Rect) {
    let block = Block::default()
        .borders(Borders::BOTTOM)
        .border_style(Style::default().fg(Color::DarkGray))
        .style(Style::default().bg(Color::Rgb(20, 20, 40)));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let done = app
        .tools
        .iter()
        .filter(|t| t.status == ToolStatus::Done)
        .count();
    let total = app.tools.iter().filter(|t| t.selected).count();
    let running = app
        .tools
        .iter()
        .filter(|t| t.status == ToolStatus::Running)
        .count();
    let overall_pct = if total > 0 { done * 100 / total } else { 0 };

    let header = Paragraph::new(Line::from(vec![
        Span::styled(" ◆ ", Style::default().fg(Color::Cyan)),
        Span::styled("Execution", Style::default().fg(Color::White).bold()),
        Span::styled(
            format!("  {} Running  ", running),
            Style::default().fg(Color::Yellow),
        ),
        Span::styled(
            format!("{} Done  ", done),
            Style::default().fg(Color::Green),
        ),
        Span::styled(
            format!("({}% complete)", overall_pct),
            Style::default().fg(Color::DarkGray),
        ),
    ]))
    .style(Style::default().bg(Color::Rgb(20, 20, 40)));
    frame.render_widget(header, inner);
}

fn render_body(app: &mut AppState, frame: &mut Frame, area: Rect) {
    let chunks =
        Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)]).split(area);

    render_progress_list(app, frame, chunks[0]);
    render_logs(app, frame, chunks[1]);
}

fn render_progress_list(app: &AppState, frame: &mut Frame, area: Rect) {
    let block = Block::default()
        .borders(Borders::all())
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(Line::from(vec![Span::styled(
            " Scan Progress ",
            Style::default().fg(Color::Cyan).bold(),
        )]))
        .style(Style::default().bg(Color::Rgb(12, 12, 24)));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let selected_tools: Vec<_> = app.tools.iter().filter(|t| t.selected).collect();
    if selected_tools.is_empty() {
        return;
    }

    let tool_height = 3u16;
    let available = inner.height.saturating_sub(1);
    let max_visible = (available / tool_height).max(1) as usize;
    let start = if app.exec_current >= max_visible {
        app.exec_current.saturating_sub(max_visible / 2)
    } else {
        0
    };

    for i in 0..max_visible {
        let idx = start + i;
        let Some(tool) = selected_tools.get(idx) else {
            break;
        };
        let y = inner.y + 1 + (i as u16) * tool_height;
        let rect = Rect::new(
            inner.x + 1,
            y,
            inner.width.saturating_sub(2),
            tool_height.min(available.saturating_sub(i as u16 * tool_height)),
        );

        let (icon, icon_color) = match tool.status {
            ToolStatus::Pending => ("○", Color::DarkGray),
            ToolStatus::Running => (app.spinner_char(), Color::Yellow),
            ToolStatus::Done => ("✓", Color::Green),
        };

        let name_line = Paragraph::new(Line::from(vec![
            Span::styled(format!("{} ", icon), Style::default().fg(icon_color)),
            Span::styled(tool.tool.name, Style::default().fg(Color::White).bold()),
            Span::styled(
                format!(" [{}]", tool.tool.category),
                Style::default().fg(Color::DarkGray),
            ),
        ]))
        .style(Style::default().bg(Color::Rgb(12, 12, 24)));
        frame.render_widget(name_line, Rect::new(rect.x, rect.y, rect.width, 1));

        if tool.status == ToolStatus::Running || tool.status == ToolStatus::Done {
            let gauge_color = if tool.progress >= 100 {
                Color::Green
            } else {
                Color::Cyan
            };
            let gauge = Gauge::default()
                .gauge_style(Style::default().fg(gauge_color).bg(Color::Rgb(30, 30, 50)))
                .percent(tool.progress)
                .label(Span::styled(
                    format!("{}%", tool.progress),
                    Style::default().fg(Color::White),
                ));
            frame.render_widget(gauge, Rect::new(rect.x, rect.y + 1, rect.width, 1));
        }
    }
}

fn render_logs(app: &mut AppState, frame: &mut Frame, area: Rect) {
    let block = Block::default()
        .borders(Borders::all())
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(Line::from(vec![Span::styled(
            " Output Log ",
            Style::default().fg(Color::Cyan).bold(),
        )]))
        .style(Style::default().bg(Color::Rgb(8, 12, 8)));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    if app.exec_logs.is_empty() {
        let waiting = Paragraph::new(Line::from(Span::styled(
            "Waiting for scan output...",
            Style::default().fg(Color::DarkGray).italic(),
        )))
        .alignment(ratatui::layout::Alignment::Center)
        .style(Style::default().bg(Color::Rgb(8, 12, 8)));
        frame.render_widget(waiting, inner);
        return;
    }

    let visible_height = inner.height.saturating_sub(2) as usize;
    let total = app.exec_logs.len();
    let max_scroll = total.saturating_sub(visible_height);
    let scroll = app.log_scroll.min(max_scroll);

    let visible_lines: Vec<Line> = app
        .exec_logs
        .iter()
        .skip(scroll)
        .take(visible_height)
        .map(|log| {
            let is_done = log.contains("✓");
            let color = if is_done {
                Color::Green
            } else {
                Color::Rgb(0, 180, 0)
            };
            Line::from(Span::styled(log.clone(), Style::default().fg(color)))
        })
        .collect();

    let log_text = Text::from(visible_lines);
    let logs = Paragraph::new(log_text)
        .style(Style::default().bg(Color::Rgb(8, 12, 8)))
        .wrap(Wrap { trim: false });
    frame.render_widget(logs, inner);
}

fn render_footer(app: &AppState, frame: &mut Frame, area: Rect) {
    let bar = Block::default()
        .borders(Borders::TOP)
        .border_style(Style::default().fg(Color::DarkGray))
        .style(Style::default().bg(Color::Rgb(20, 20, 40)));
    let inner = bar.inner(area);
    frame.render_widget(bar, area);

    let all_done = app
        .tools
        .iter()
        .all(|t| !t.selected || t.status == ToolStatus::Done);
    let status = if all_done {
        "All scans complete — proceeding to analysis..."
    } else {
        "Running security scans..."
    };

    let footer = Paragraph::new(Line::from(vec![
        Span::styled(
            format!(
                " ◆ {} ",
                match app.mode {
                    AppMode::Auto => "AUTO",
                    AppMode::Assisted => "ASSISTED",
                }
            ),
            Style::default().fg(Color::Cyan).bold(),
        ),
        Span::styled(" │ ", Style::default().fg(Color::DarkGray)),
        Span::styled(status, Style::default().fg(Color::Yellow)),
    ]))
    .style(Style::default().bg(Color::Rgb(20, 20, 40)));
    frame.render_widget(footer, inner);
}
