use crate::config::llm_config::LlmProviderKind;
use crate::tui::chrome::{self, ACCENT, DANGER, SURFACE, TEXT};
use crate::tui::interaction::{FocusTarget, SemanticAction};
use crate::tui::state::{AppState, SettingsField};
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Style, Stylize},
    text::{Line, Span, Text},
    widgets::Paragraph,
    Frame,
};

pub fn render(app: &mut AppState, frame: &mut Frame, area: Rect) {
    let status = app
        .llm_warning
        .clone()
        .unwrap_or_else(|| "Revise as opções e salve para aplicar".to_string());
    let shell = chrome::render_shell(app, frame, area, "Configurações", &status);
    let rows = Layout::vertical([Constraint::Min(1), Constraint::Length(2)]).split(shell.content);
    render_form(app, frame, rows[0]);
    render_actions(app, frame, rows[1]);
}

fn render_form(app: &mut AppState, frame: &mut Frame, area: Rect) {
    let fields = settings_fields(app);
    let focused_index = match app.focus {
        FocusTarget::SettingsField(field) => SettingsField::ALL
            .iter()
            .position(|candidate| *candidate == field),
        _ => None,
    };
    let block = chrome::panel("Provedor e execução", focused_index.is_some());
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let warning_height = u16::from(app.llm_warning.is_some());
    let visible = inner.height.saturating_sub(warning_height).max(1) as usize;
    let max_scroll = fields.len().saturating_sub(visible);
    app.settings_scroll = app.settings_scroll.min(max_scroll);
    if let Some(index) = focused_index {
        if index < app.settings_scroll {
            app.settings_scroll = index;
        } else if index >= app.settings_scroll.saturating_add(visible) {
            app.settings_scroll = index.saturating_sub(visible - 1);
        }
    }

    let mut lines = Vec::new();
    for row in 0..visible.min(fields.len().saturating_sub(app.settings_scroll)) {
        let index = app.settings_scroll + row;
        let (label, value, field) = &fields[index];
        let active = app.focus == FocusTarget::SettingsField(*field);
        let value_width = inner.width.saturating_sub(25) as usize;
        let value = chrome::truncate_width(value, value_width);
        lines.push(
            Line::from(vec![
                Span::styled(
                    format!("{} {:<20}", if active { ">" } else { " " }, label),
                    Style::default().bold(),
                ),
                Span::styled(value, Style::default()),
                Span::styled(if active { "▏" } else { "" }, Style::default().bold()),
            ])
            .style(
                Style::default()
                    .fg(if active { Color::Black } else { TEXT })
                    .bg(if active { ACCENT } else { SURFACE }),
            ),
        );
        app.register_hit_region(
            Rect::new(inner.x, inner.y + row as u16, inner.width, 1),
            SemanticAction::SelectSettingsField(*field),
        );
    }
    frame.render_widget(
        Paragraph::new(Text::from(lines)).style(Style::default().bg(SURFACE)),
        Rect::new(
            inner.x,
            inner.y,
            inner.width,
            inner.height.saturating_sub(warning_height),
        ),
    );
    if let Some(warning) = &app.llm_warning {
        frame.render_widget(
            Paragraph::new(format!("aviso  {warning}"))
                .style(Style::default().fg(DANGER).bg(SURFACE)),
            Rect::new(
                inner.x,
                inner.y + inner.height.saturating_sub(1),
                inner.width,
                1,
            ),
        );
    }
}

fn settings_fields(app: &AppState) -> Vec<(&'static str, String, SettingsField)> {
    let provider = LlmProviderKind::all_labels()[app.settings_provider_idx].to_string();
    let api_key = if app.settings_input_api_key.is_empty() {
        "(não definida)".to_string()
    } else {
        "********".to_string()
    };
    vec![
        ("Provedor", provider, SettingsField::Provider),
        (
            "URL base",
            app.settings_input_base_url.clone(),
            SettingsField::BaseUrl,
        ),
        ("Chave de API", api_key, SettingsField::ApiKey),
        (
            "Modelo",
            app.settings_input_model.clone(),
            SettingsField::Model,
        ),
        (
            "Tempo limite (s)",
            app.settings_input_timeout.clone(),
            SettingsField::Timeout,
        ),
        (
            "Tentativas",
            app.settings_input_retries.clone(),
            SettingsField::Retries,
        ),
        (
            "Consentimento remoto",
            checkbox(app.settings_remote_consent),
            SettingsField::RemoteConsent,
        ),
        (
            "Alternativa local",
            checkbox(app.settings_fallback_enabled),
            SettingsField::FallbackEnabled,
        ),
        (
            "URL alternativa",
            app.settings_input_fallback_base_url.clone(),
            SettingsField::FallbackBaseUrl,
        ),
        (
            "Modelo alternativo",
            app.settings_input_fallback_model.clone(),
            SettingsField::FallbackModel,
        ),
        (
            "Nuclei real",
            if app.settings_real_nuclei {
                "[x] Ativo".to_string()
            } else {
                "[ ] Inativo".to_string()
            },
            SettingsField::RealNuclei,
        ),
    ]
}

fn render_actions(app: &mut AppState, frame: &mut Frame, area: Rect) {
    let columns = Layout::horizontal([
        Constraint::Length(11),
        Constraint::Min(1),
        Constraint::Length(11),
    ])
    .split(area);
    let cancel_focused = app.focus == FocusTarget::SettingsCancel;
    let save_focused = app.focus == FocusTarget::SettingsSave;
    chrome::render_button(
        app,
        frame,
        columns[0],
        "Cancelar",
        SemanticAction::CloseSettings,
        chrome::ButtonState::secondary(cancel_focused),
    );
    chrome::render_button(
        app,
        frame,
        columns[2],
        "Salvar",
        SemanticAction::SaveSettings,
        chrome::ButtonState::primary(save_focused),
    );
}

fn checkbox(enabled: bool) -> String {
    if enabled {
        "[x] Sim".to_string()
    } else {
        "[ ] Não".to_string()
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
            nuclei_templates_path: None,
            nuclei_templates_commit: None,
            demo_mode: false,
            output_file: None,
            show_help: false,
            show_version: false,
        };
        let mut app = AppState::new(config);
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal
            .draw(|frame| render(&mut app, frame, frame.area()))
            .unwrap();
        let screen = terminal.backend().to_string();

        assert!(!screen.contains("secret-value"));
        assert!(screen.contains("********"));
        assert!(screen.contains("Configurações"));
        assert!(screen.contains("Integrado"));
        assert!(screen.contains("Consentimento remoto"));
        assert!(screen.contains("Alternativa local"));
        assert!(screen.contains("Nuclei real"));
        assert!(screen.contains("Cancelar"));
        assert!(screen.contains("Salvar"));
    }

    #[test]
    fn scrolls_form_to_keep_focused_field_visible() {
        let mut app = AppState::new(Configuration::default());
        app.show_settings = true;
        app.settings_field = SettingsField::RealNuclei;
        app.focus = FocusTarget::SettingsField(SettingsField::RealNuclei);
        let backend = TestBackend::new(80, 12);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal
            .draw(|frame| render(&mut app, frame, frame.area()))
            .unwrap();
        let screen = terminal.backend().to_string();

        assert!(app.settings_scroll > 0);
        assert!(screen.contains("Nuclei real"));
    }
}
