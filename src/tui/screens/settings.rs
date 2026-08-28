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

    let popup = crate::tui::centered_rect(78, 94, area);
    let block = Block::default()
        .borders(Borders::all())
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::Cyan))
        .title(Line::from(vec![Span::styled(
            " Settings ",
            Style::default().fg(Color::Cyan).bold(),
        )]))
        .style(Style::default().bg(Color::Rgb(12, 12, 24)));
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let labels = LlmProviderKind::all_labels();
    let provider_label = labels[app.settings_provider_idx];
    let nuclei_status = if app.settings_real_nuclei {
        "[X] Enabled"
    } else {
        "[ ] Disabled"
    };
    let _nuclei_color = if app.settings_real_nuclei {
        Color::Green
    } else {
        Color::DarkGray
    };

    let api_key = if app.settings_input_api_key.is_empty() {
        "(not set)".to_string()
    } else {
        "********".to_string()
    };
    let consent = checkbox(app.settings_remote_consent);
    let fallback = checkbox(app.settings_fallback_enabled);
    let fields = vec![
        (
            "Provider",
            provider_label.to_string(),
            SettingsField::Provider,
        ),
        (
            "Base URL",
            app.settings_input_base_url.clone(),
            SettingsField::BaseUrl,
        ),
        ("API Key", api_key, SettingsField::ApiKey),
        (
            "Model",
            app.settings_input_model.clone(),
            SettingsField::Model,
        ),
        (
            "Timeout (s)",
            app.settings_input_timeout.clone(),
            SettingsField::Timeout,
        ),
        (
            "Retries",
            app.settings_input_retries.clone(),
            SettingsField::Retries,
        ),
        ("Remote consent", consent, SettingsField::RemoteConsent),
        ("Local fallback", fallback, SettingsField::FallbackEnabled),
        (
            "Fallback URL",
            app.settings_input_fallback_base_url.clone(),
            SettingsField::FallbackBaseUrl,
        ),
        (
            "Fallback model",
            app.settings_input_fallback_model.clone(),
            SettingsField::FallbackModel,
        ),
        (
            "Real Nuclei",
            nuclei_status.to_string(),
            SettingsField::RealNuclei,
        ),
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
            Span::styled(value.clone(), value_style),
        ]));
        lines.push(Line::from(""));
    }

    lines.push(Line::from(""));
    let save_w = 10u16;
    let cancel_w = 12u16;
    let buttons_y = inner.y + inner.height.saturating_sub(3);
    let save_x = inner.x + inner.width.saturating_sub(save_w + cancel_w + 4);
    let cancel_x = save_x + save_w + 2;
    app.settings_save_rect = Rect::new(save_x, buttons_y, save_w, 1);
    app.settings_cancel_rect = Rect::new(cancel_x, buttons_y, cancel_w, 1);
    lines.push(Line::from(""));

    if let Some(ref warning) = app.llm_warning {
        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            Span::styled(" WARN: ", Style::default().fg(Color::Yellow)),
            Span::styled(warning.clone(), Style::default().fg(Color::Yellow)),
        ]));
    }

    let para = Paragraph::new(lines)
        .style(Style::default().bg(Color::Rgb(12, 12, 24)))
        .wrap(Wrap { trim: true })
        .alignment(Alignment::Left);
    frame.render_widget(para, inner);

    let save_btn = Paragraph::new(Line::from(vec![Span::styled(
        " [ Save ] ",
        Style::default()
            .fg(Color::White)
            .bg(Color::Rgb(0, 120, 0))
            .bold(),
    )]))
    .style(Style::default().bg(Color::Rgb(12, 12, 24)));
    frame.render_widget(save_btn, app.settings_save_rect);

    let cancel_btn = Paragraph::new(Line::from(vec![Span::styled(
        " [ Cancel ] ",
        Style::default()
            .fg(Color::White)
            .bg(Color::Rgb(160, 30, 30))
            .bold(),
    )]))
    .style(Style::default().bg(Color::Rgb(12, 12, 24)));
    frame.render_widget(cancel_btn, app.settings_cancel_rect);
}

fn checkbox(enabled: bool) -> String {
    if enabled {
        "[X] Enabled".to_string()
    } else {
        "[ ] Disabled".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::execution_type::ExecutionType;
    use crate::config::llm_config::LlmConfig;
    use crate::config::Configuration;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    #[test]
    fn masks_api_key_in_settings_screen() {
        let config = Configuration {
            target_url: String::new(),
            active_tools: Vec::new(),
            provider_mode: "OpenAI".to_string(),
            execution_type: ExecutionType::Assisted,
            llm: LlmConfig {
                api_key: "secret-value".to_string(),
                ..LlmConfig::default()
            },
            use_real_nuclei: false,
        };
        let mut app = AppState::new(config);
        let backend = TestBackend::new(100, 40);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal
            .draw(|frame| render(&mut app, frame, frame.area()))
            .unwrap();
        let screen = terminal.backend().to_string();

        assert!(!screen.contains("secret-value"));
        assert!(screen.contains("********"));
    }
}
