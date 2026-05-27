use crate::app::{AppMode, AppState};
use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Layout, Rect},
    style::{Color, Style, Stylize},
    text::{Line, Span, Text},
    widgets::{Block, BorderType, Borders, Paragraph},
};

pub fn render(app: &mut AppState, frame: &mut Frame, area: Rect) {
    let bg = Block::default().style(Style::default().bg(Color::Rgb(8, 8, 16)));
    frame.render_widget(bg, area);

    let chunks = Layout::vertical([Constraint::Min(3), Constraint::Length(3)]).split(area);

    render_content(app, frame, chunks[0]);
    render_status_bar(app, frame, chunks[1]);
}

fn render_content(app: &AppState, frame: &mut Frame, area: Rect) {
    let center = super::centered_rect(80, 100, area);

    let chunks = Layout::vertical([
        Constraint::Length(8),
        Constraint::Length(1),
        Constraint::Length(2),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(3),
        Constraint::Min(1),
    ])
    .split(center);

    let logo = Paragraph::new(Text::from(build_logo())).alignment(Alignment::Center);
    frame.render_widget(logo, chunks[0]);

    let subtitle = Paragraph::new(Line::from(Span::styled(
        "Security Analysis Platform — Rust TUI Prototype",
        Style::default().fg(Color::DarkGray).italic(),
    )))
    .alignment(Alignment::Center);
    frame.render_widget(subtitle, chunks[2]);

    let auto_style = if app.mode == AppMode::Auto {
        Style::default().fg(Color::Black).bg(Color::Cyan).bold()
    } else {
        Style::default().fg(Color::DarkGray)
    };
    let assisted_style = if app.mode == AppMode::Assisted {
        Style::default().fg(Color::Black).bg(Color::Green).bold()
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let mode_line = Line::from(vec![
        Span::styled("  Mode: ", Style::default().fg(Color::White)),
        Span::styled(" AUTO ", auto_style),
        Span::styled(" / ", Style::default().fg(Color::DarkGray)),
        Span::styled(" ASSISTED ", assisted_style),
        Span::styled(
            "  [Tab to switch]",
            Style::default().fg(Color::DarkGray).italic(),
        ),
    ]);
    let mode_para = Paragraph::new(mode_line).alignment(Alignment::Center);
    frame.render_widget(mode_para, chunks[4]);

    let url_block = Block::default()
        .borders(Borders::all())
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::Cyan))
        .title(Line::from(vec![Span::styled(
            " Target URL ",
            Style::default().fg(Color::Cyan).bold(),
        )]))
        .style(Style::default().bg(Color::Rgb(16, 16, 32)));
    let url_inner = url_block.inner(chunks[5]);
    frame.render_widget(url_block, chunks[5]);

    let cursor_char = if app.tick % 10 < 5 { "█" } else { "▎" };
    let display_url = if app.url_input.is_empty() {
        format!(
            " {}{}",
            cursor_char,
            "http://example.com"
                .chars()
                .take(url_inner.width.saturating_sub(3) as usize)
                .collect::<String>()
        )
    } else {
        let before: String = app.url_input.chars().take(app.url_cursor).collect();
        let after: String = app.url_input.chars().skip(app.url_cursor).collect();
        format!(" {}{}{}", before, cursor_char, after)
    };

    let cursor_color = if app.url_input.is_empty() {
        Color::Rgb(60, 60, 80)
    } else {
        Color::White
    };
    let url_text = Paragraph::new(Line::from(vec![Span::styled(
        display_url,
        Style::default().fg(cursor_color),
    )]))
    .style(Style::default().bg(Color::Rgb(16, 16, 32)));
    frame.render_widget(url_text, url_inner);

    let hint = Paragraph::new(Line::from(Span::styled(
        "Press Enter to start analysis",
        Style::default().fg(Color::DarkGray),
    )))
    .alignment(Alignment::Center);
    frame.render_widget(hint, chunks[6]);
}

fn render_status_bar(app: &AppState, frame: &mut Frame, area: Rect) {
    let bar = Block::default()
        .borders(Borders::TOP)
        .border_style(Style::default().fg(Color::DarkGray))
        .style(Style::default().bg(Color::Rgb(20, 20, 40)));
    let inner = bar.inner(area);
    frame.render_widget(bar, area);

    let mode_text = match app.mode {
        AppMode::Auto => "AUTO",
        AppMode::Assisted => "ASSISTED",
    };
    let mode_color = match app.mode {
        AppMode::Auto => Color::Cyan,
        AppMode::Assisted => Color::Green,
    };

    let status = Paragraph::new(Line::from(vec![
        Span::styled(
            " SMARTSEC ",
            Style::default().fg(Color::Black).bg(Color::Cyan).bold(),
        ),
        Span::styled(" v0.1.0 ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            format!(" ◆ {} ", mode_text),
            Style::default().fg(mode_color).bold(),
        ),
        Span::styled(
            " │ Esc: Quit  Tab: Switch Mode  Enter: Start ",
            Style::default().fg(Color::DarkGray),
        ),
    ]))
    .style(Style::default().bg(Color::Rgb(20, 20, 40)));
    frame.render_widget(status, inner);
}

fn build_logo() -> Vec<Line<'static>> {
    let c1 = Style::default().fg(Color::Cyan).bold();
    let c2 = Style::default().fg(Color::Rgb(0, 100, 120));

    vec![
        Line::from(""),
        Line::from(vec![Span::styled(
            "  ____  ___  ___  __ _ _   _  ___  __ _  ___ ",
            c1,
        )]),
        Line::from(vec![Span::styled(
            " / __|/ _ \\/ __|/ _` | | | |/ _ \\/ _` |/ __|",
            c1,
        )]),
        Line::from(vec![Span::styled(
            "| (__| (_) \\__ \\ (_| | |_| |  __/ (_| | (__ ",
            c1,
        )]),
        Line::from(vec![Span::styled(
            " \\___|\\___/|___/\\__,_|\\__, |\\___|\\__,_|\\___|",
            c1,
        )]),
        Line::from(vec![Span::styled(
            "                       |___/                 ",
            c1,
        )]),
        Line::from(""),
        Line::from(vec![Span::styled(
            "              ◆ Secure by Design ◆           ",
            c2,
        )]),
    ]
}
