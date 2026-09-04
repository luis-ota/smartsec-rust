use crate::config::execution_type::ExecutionType;
use crate::tui::interaction::{FocusTarget, SemanticAction};
use crate::tui::state::AppState;
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

fn render_content(app: &mut AppState, frame: &mut Frame, area: Rect) {
    let center = crate::tui::centered_rect(80, 100, area);
    let chunks = Layout::vertical([
        Constraint::Length(8),
        Constraint::Length(1),
        Constraint::Length(2),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(3),
        Constraint::Length(3),
        Constraint::Min(1),
    ])
    .split(center);

    let logo = Paragraph::new(Text::from(build_logo())).alignment(Alignment::Center);
    frame.render_widget(logo, chunks[0]);

    let subtitle = Paragraph::new(Line::from(Span::styled(
        "Security Analysis Platform - Rust TUI Prototype",
        Style::default().fg(Color::DarkGray).italic(),
    )))
    .alignment(Alignment::Center);
    frame.render_widget(subtitle, chunks[2]);

    let auto_style = if app.mode() == ExecutionType::Auto {
        Style::default().fg(Color::Black).bg(Color::Cyan).bold()
    } else {
        Style::default().fg(Color::DarkGray)
    };
    let assisted_style = if app.mode() == ExecutionType::Assisted {
        Style::default().fg(Color::Black).bg(Color::Green).bold()
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let mode_line = Line::from(vec![
        Span::styled(" Mode: ", Style::default().fg(Color::White)),
        Span::styled(" AUTO ", auto_style),
        Span::styled(" / ", Style::default().fg(Color::DarkGray)),
        Span::styled(" ASSISTED ", assisted_style),
        Span::styled(
            " [Tab to switch]",
            Style::default().fg(Color::DarkGray).italic(),
        ),
    ]);
    let mode_para = Paragraph::new(mode_line).alignment(Alignment::Center);
    frame.render_widget(mode_para, chunks[4]);

    let mode_total_w = 42u16;
    let mode_center_offset = (chunks[4].width.saturating_sub(mode_total_w)) / 2;
    app.register_hit_region(
        Rect::new(chunks[4].x + mode_center_offset, chunks[4].y, 6, 1),
        SemanticAction::SetMode(ExecutionType::Auto),
    );
    app.register_hit_region(
        Rect::new(chunks[4].x + mode_center_offset + 17, chunks[4].y, 10, 1),
        SemanticAction::SetMode(ExecutionType::Assisted),
    );

    let provider_label =
        crate::config::llm_config::LlmProviderKind::all_labels()[app.settings_provider_idx];
    let model_display = if app.config.llm.model.is_empty() {
        "not configured".to_string()
    } else {
        app.config.llm.model.clone()
    };

    let ai_block = Block::default()
        .borders(Borders::all())
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::Yellow))
        .title(Line::from(vec![Span::styled(
            " AI Model ",
            Style::default().fg(Color::Yellow).bold(),
        )]))
        .style(Style::default().bg(Color::Rgb(16, 16, 32)));
    let ai_inner = ai_block.inner(chunks[5]);
    frame.render_widget(ai_block, chunks[5]);

    let ai_text = Paragraph::new(Line::from(vec![
        Span::styled(provider_label, Style::default().fg(Color::White).bold()),
        Span::styled(" / ", Style::default().fg(Color::DarkGray)),
        Span::styled(model_display, Style::default().fg(Color::Cyan)),
        Span::styled(
            "  [click to configure]",
            Style::default().fg(Color::DarkGray).italic(),
        ),
    ]))
    .style(Style::default().bg(Color::Rgb(16, 16, 32)));
    frame.render_widget(ai_text, ai_inner);

    app.register_hit_region(chunks[5], SemanticAction::OpenSettings);

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

    let cursor_char = if app.tick % 10 < 5 { "|" } else { " " };
    let display_url = if app.config.target_url.is_empty() {
        format!(
            "{}{}",
            "http://example.com"
                .chars()
                .take(url_inner.width.saturating_sub(2) as usize)
                .collect::<String>(),
            cursor_char
        )
    } else {
        format!("{}{}", app.config.target_url, cursor_char)
    };
    let cursor_color = if app.config.target_url.is_empty() {
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

    app.register_hit_region(
        chunks[6],
        SemanticAction::SetFocus(FocusTarget::SplashTarget),
    );
    app.register_hit_region(chunks[7], SemanticAction::StartScan);

    let hint = Paragraph::new(Line::from(vec![
        Span::styled("Enter", Style::default().fg(Color::White)),
        Span::styled(" Start  ", Style::default().fg(Color::DarkGray)),
        Span::styled("Tab", Style::default().fg(Color::White)),
        Span::styled(" Mode  ", Style::default().fg(Color::DarkGray)),
        Span::styled("C-x", Style::default().fg(Color::Cyan).bold()),
        Span::styled(" Commands  ", Style::default().fg(Color::DarkGray)),
        Span::styled("Esc", Style::default().fg(Color::White)),
        Span::styled(" Quit", Style::default().fg(Color::DarkGray)),
    ]))
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

    let mode_text = match app.mode() {
        ExecutionType::Auto => "AUTO",
        ExecutionType::Assisted => "ASSISTED",
    };
    let mode_color = match app.mode() {
        ExecutionType::Auto => Color::Cyan,
        ExecutionType::Assisted => Color::Green,
    };

    let provider_label =
        crate::config::llm_config::LlmProviderKind::all_labels()[app.settings_provider_idx];
    let model_short = if app.config.llm.model.len() > 20 {
        format!("{}...", &app.config.llm.model[..17])
    } else {
        app.config.llm.model.clone()
    };

    let status = Paragraph::new(Line::from(vec![
        Span::styled(
            " SMARTSEC ",
            Style::default().fg(Color::Black).bg(Color::Cyan).bold(),
        ),
        Span::styled(" v0.2.0 ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            format!(" * {} ", mode_text),
            Style::default().fg(mode_color).bold(),
        ),
        Span::styled(
            format!("| AI: {} ", model_short),
            Style::default().fg(Color::Yellow),
        ),
        Span::styled(
            format!("({}) ", provider_label),
            Style::default().fg(Color::DarkGray),
        ),
        Span::styled(
            "| Esc: Quit Tab: Mode Enter: Start C-x: Cmds ",
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
            "  ███████╗███╗   ███╗ █████╗ ██████╗ ████████╗    ███████╗███████╗ ██████╗",
            c1,
        )]),
        Line::from(vec![Span::styled(
            "  ██╔════╝████╗ ████║██╔══██╗██╔══██╗╚══██╔══╝    ██╔════╝██╔════╝██╔════╝",
            c1,
        )]),
        Line::from(vec![Span::styled(
            "  ███████╗██╔████╔██║███████║██████╔╝   ██║       ███████╗█████╗  ██║     ",
            c1,
        )]),
        Line::from(vec![Span::styled(
            "  ╚════██║██║╚██╔╝██║██╔══██║██╔══██╗   ██║       ╚════██║██╔══╝  ██║     ",
            c1,
        )]),
        Line::from(vec![Span::styled(
            "  ███████║██║ ╚═╝ ██║██║  ██║██║  ██║   ██║       ███████║███████╗╚██████╗",
            c1,
        )]),
        Line::from(vec![Span::styled(
            "  ╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝       ╚══════╝╚══════╝ ╚═════╝",
            c1,
        )]),
        Line::from(""),
        Line::from(vec![Span::styled(
            "        Security Analysis Platform         ",
            c2,
        )]),
    ]
}
