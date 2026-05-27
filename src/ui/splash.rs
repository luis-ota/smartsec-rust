use crate::app::{AppMode, AppState};
use ratatui::{
    layout::{Alignment, Constraint, Layout, Rect},
    style::{Color, Style, Stylize},
    text::{Line, Span, Text},
    widgets::{Block, BorderType, Borders, Paragraph},
    Frame,
};

pub fn render(app: &mut AppState, frame: &mut Frame, area: Rect) {
    let bg = Block::default().style(Style::default().bg(Color::Rgb(8, 8, 16)));
    frame.render_widget(bg, area);

    let chunks = Layout::vertical([Constraint::Min(3), Constraint::Length(3)]).split(area);

    render_content(app, frame, chunks[0]);
    render_status_bar(app, frame, chunks[1]);
}

fn render_content(app: &AppState, frame: &mut Frame, area: Rect) {
    let center = super::centered_rect(70, 70, area);

    let logo_lines = build_logo();
    let logo_height = logo_lines.len() as u16;

    let chunks = Layout::vertical([
        Constraint::Length(logo_height),
        Constraint::Length(2),
        Constraint::Length(3),
        Constraint::Length(2),
        Constraint::Length(1),
        Constraint::Length(3),
        Constraint::Length(2),
        Constraint::Length(1),
    ])
    .split(center);

    let logo = Paragraph::new(Text::from(logo_lines)).alignment(Alignment::Center);
    frame.render_widget(logo, chunks[0]);

    let subtitle = Paragraph::new(Line::from(Span::styled(
        "Security Analysis Platform",
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
        Span::styled("Mode: ", Style::default().fg(Color::White)),
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
    let url_inner = url_block.inner(chunks[6]);
    frame.render_widget(url_block, chunks[6]);

    let cursor_char = if app.tick % 10 < 5 { "█" } else { "▎" };
    let display_url = if app.url_input.is_empty() {
        cursor_char.to_string()
    } else {
        let before: String = app.url_input.chars().take(app.url_cursor).collect();
        let after: String = app.url_input.chars().skip(app.url_cursor).collect();
        format!("{}{}{}", before, cursor_char, after)
    };

    let url_text = Paragraph::new(Line::from(vec![
        Span::styled("  ", Style::default()),
        Span::styled(display_url, Style::default().fg(Color::White)),
    ]))
    .style(Style::default().bg(Color::Rgb(16, 16, 32)));
    frame.render_widget(url_text, url_inner);

    let hint = Paragraph::new(Line::from(Span::styled(
        "Press Enter to start analysis",
        Style::default().fg(Color::DarkGray),
    )))
    .alignment(Alignment::Center);
    frame.render_widget(hint, chunks[7]);
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
    let bold = Style::default().fg(Color::Cyan).bold();
    let dim = Style::default().fg(Color::Rgb(0, 80, 100));

    vec![
        Line::from(""),
        Line::from(vec![Span::styled(
            "  ███████╗██╗   ██╗███████╗██╗  ██╗███████╗███████╗████████╗",
            bold,
        )]),
        Line::from(vec![Span::styled(
            "  ██╔════╝╚██╗ ██╔╝██╔════╝██║  ██║██╔════╝██╔════╝╚══██╔══╝",
            bold,
        )]),
        Line::from(vec![Span::styled(
            "  ███████╗ ╚████╔╝ ███████╗███████║█████╗  ███████╗   ██║   ",
            bold,
        )]),
        Line::from(vec![Span::styled(
            "  ╚════██║  ╚██╔╝  ╚════██║██╔══██║██╔══╝  ╚════██║   ██║   ",
            bold,
        )]),
        Line::from(vec![Span::styled(
            "  ███████║   ██║   ███████║██║  ██║███████╗███████║   ██║   ",
            bold,
        )]),
        Line::from(vec![Span::styled(
            "  ╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝   ╚═╝   ",
            bold,
        )]),
        Line::from(vec![Span::styled(
            "                    ╔═══════════════╗                         ",
            dim,
        )]),
        Line::from(vec![Span::styled(
            "                    ║  S E C U R E  ║                         ",
            dim,
        )]),
        Line::from(vec![Span::styled(
            "                    ╚═══════════════╝                         ",
            dim,
        )]),
    ]
}
