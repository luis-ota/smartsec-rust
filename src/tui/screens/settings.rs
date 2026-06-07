use crate::config::llm_config::LlmProviderKind;
use crate::tui::state::{AppState, SettingsField};
use ratatui::{
    layout::{Alignment, Rect},
    style::{Color, Style, Stylize},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Clear, Paragraph, Wrap},
    Frame,
};

pub fn render(app: &mut AppState, frame: &mut Frame, area: Rect) {
    frame.render_widget(Clear, area);
    let bg = Block::default().style(Style::default().bg(Color::Rgb(8, 8, 16)));
    frame.render_widget(bg, area);

    let popup = crate::tui::centered_rect(70, 70, area);
    let block = Block::default()
        .borders(Borders::all())
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::Cyan))
        .title(Line::from(vec![Span::styled(
            " ⚙ Settings ",
            Style::default().fg(Color::Cyan).bold(),
        )]))
        .style(Style::default().bg(Color::Rgb(12, 12, 24)));
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let labels = LlmProviderKind::all_labels();
    let provider_label = labels[app.settings_provider_idx];
    let nmap_status = if app.settings_real_nmap {
        "● Enabled"
    } else {
        "○ Disabled"
    };
    let _nmap_color = if app.settings_real_nmap {
        Color::Green
    } else {
        Color::DarkGray
    };

    let fields = [
        ("Provider", provider_label, SettingsField::Provider),
        (
            "Base URL",
            &app.settings_input_base_url,
            SettingsField::BaseUrl,
        ),
        (
            "API Key",
            &app.settings_input_api_key,
            SettingsField::ApiKey,
        ),
        ("Model", &app.settings_input_model, SettingsField::Model),
        ("Real Nmap", nmap_status, SettingsField::RealNmap),
    ];

    let mut lines: Vec<Line> = vec![Line::from("")];

    for (label, value, field) in &fields {
        let is_active = app.settings_field == *field;
        let label_style = if is_active {
            Style::default().fg(Color::Cyan).bold()
        } else {
            Style::default().fg(Color::DarkGray)
        };
        let value_style = if is_active {
            Style::default().fg(Color::White)
        } else {
            Style::default().fg(Color::Gray)
        };
        let cursor = if is_active { " ▸ " } else { "   " };

        lines.push(Line::from(vec![
            Span::styled(cursor, Style::default().fg(Color::Cyan)),
            Span::styled(format!("{:<12}", format!("{}:", label)), label_style),
            Span::styled(value.to_string(), value_style),
        ]));
        lines.push(Line::from(""));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled(
            " Tab ",
            Style::default().fg(Color::Black).bg(Color::Cyan).bold(),
        ),
        Span::styled(" Switch Field  ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            " Enter ",
            Style::default().fg(Color::Black).bg(Color::Cyan).bold(),
        ),
        Span::styled(" Select/Apply  ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            " Esc ",
            Style::default().fg(Color::Black).bg(Color::Cyan).bold(),
        ),
        Span::styled(" Close", Style::default().fg(Color::DarkGray)),
    ]));

    if let Some(ref warning) = app.llm_warning {
        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            Span::styled(" ⚠ ", Style::default().fg(Color::Yellow)),
            Span::styled(warning.clone(), Style::default().fg(Color::Yellow)),
        ]));
    }

    let para = Paragraph::new(lines)
        .style(Style::default().bg(Color::Rgb(12, 12, 24)))
        .wrap(Wrap { trim: true })
        .alignment(Alignment::Left);
    frame.render_widget(para, inner);
}
