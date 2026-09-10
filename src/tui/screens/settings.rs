use crate::config::llm_config::LlmProviderKind;
use crate::tui::chrome::{self, ACCENT, DANGER, MUTED, SURFACE, SURFACE_ACTIVE, TEXT};
use crate::tui::interaction::{FocusTarget, SemanticAction};
use crate::tui::state::{AppState, SettingsField};
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Style, Stylize},
    text::{Line, Span, Text},
    widgets::Paragraph,
    Frame,
};

struct FieldView {
    field: SettingsField,
    label: &'static str,
    value: String,
    hint: &'static str,
}

pub fn render(app: &mut AppState, frame: &mut Frame, area: Rect) {
    let status = app.settings_error.clone().unwrap_or_else(|| {
        if app.settings_connection_is_remote() {
            "Conexão remota · HTTPS, chave e consentimento obrigatórios".to_string()
        } else {
            "Conexão local · nenhum dado será enviado para fora da máquina".to_string()
        }
    });
    let shell = chrome::render_shell(app, frame, area, "Configurações de IA", &status);
    let rows = Layout::vertical([
        Constraint::Length(2),
        Constraint::Min(4),
        Constraint::Length(2),
    ])
    .split(shell.content);
    render_intro(app, frame, rows[0]);
    if rows[1].width >= 72 && rows[1].height >= 12 {
        render_columns(app, frame, rows[1]);
    } else {
        render_compact_form(app, frame, rows[1]);
    }
    render_actions(app, frame, rows[2]);
}

fn render_intro(app: &AppState, frame: &mut Frame, area: Rect) {
    let detail = app
        .settings_error
        .as_deref()
        .unwrap_or("Tab navega · ← → altera seleções · espaço alterna · ctrl+u limpa o campo");
    let detail_color = if app.settings_error.is_some() {
        DANGER
    } else {
        MUTED
    };
    frame.render_widget(
        Paragraph::new(Text::from(vec![
            Line::styled(
                "Defina o provedor e os limites. Opções não aplicáveis ficam ocultas.",
                Style::default().fg(TEXT).bold(),
            ),
            Line::styled(detail, Style::default().fg(detail_color)),
        ]))
        .style(Style::default().bg(chrome::BACKGROUND)),
        area,
    );
}

fn render_columns(app: &mut AppState, frame: &mut Frame, area: Rect) {
    let columns = Layout::horizontal([
        Constraint::Percentage(50),
        Constraint::Length(1),
        Constraint::Percentage(50),
    ])
    .split(area);
    let primary = primary_fields(app);
    let reliability = reliability_fields(app);
    render_section(app, frame, columns[0], "Conexão principal", &primary);
    render_section(app, frame, columns[2], "Confiabilidade", &reliability);
}

fn render_section(
    app: &mut AppState,
    frame: &mut Frame,
    area: Rect,
    title: &str,
    fields: &[FieldView],
) {
    let focused = fields
        .iter()
        .any(|view| app.focus == FocusTarget::SettingsField(view.field));
    let block = chrome::panel(title, focused);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let visible = fields.len().min((inner.height / 2) as usize);
    for (row, view) in fields.iter().take(visible).enumerate() {
        let y = inner.y + row as u16 * 2;
        render_field(app, frame, Rect::new(inner.x, y, inner.width, 2), view);
    }
}

fn render_field(app: &mut AppState, frame: &mut Frame, area: Rect, view: &FieldView) {
    let active = app.focus == FocusTarget::SettingsField(view.field);
    let label_width = area.width.saturating_sub(view.hint.len() as u16 + 2) as usize;
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(
                chrome::truncate_width(view.label, label_width),
                Style::default()
                    .fg(if active { TEXT } else { MUTED })
                    .bold(),
            ),
            Span::styled(
                format!("  {}", view.hint),
                Style::default().fg(if active { ACCENT } else { MUTED }),
            ),
        ]))
        .style(Style::default().bg(SURFACE)),
        Rect::new(area.x, area.y, area.width, 1),
    );
    let value = chrome::truncate_width(&view.value, area.width.saturating_sub(4) as usize);
    let value_line = Line::from(vec![
        Span::styled(
            if active { " › " } else { "   " },
            Style::default().fg(ACCENT),
        ),
        Span::styled(value, Style::default().fg(TEXT)),
        Span::styled(
            if active && is_text_field(view.field) {
                "▏"
            } else {
                ""
            },
            Style::default().fg(ACCENT).bold(),
        ),
    ]);
    frame.render_widget(
        Paragraph::new(value_line).style(
            Style::default()
                .bg(if active { SURFACE_ACTIVE } else { SURFACE })
                .fg(TEXT),
        ),
        Rect::new(area.x, area.y + 1, area.width, 1),
    );
    app.register_hit_region(area, SemanticAction::SelectSettingsField(view.field));
}

fn render_compact_form(app: &mut AppState, frame: &mut Frame, area: Rect) {
    let fields = all_visible_fields(app);
    let focused_index = fields
        .iter()
        .position(|view| app.focus == FocusTarget::SettingsField(view.field));
    let block = chrome::panel("Configuração", focused_index.is_some());
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let visible = inner.height.max(1) as usize;
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
        let view = &fields[app.settings_scroll + row];
        let active = app.focus == FocusTarget::SettingsField(view.field);
        let value_width = inner.width.saturating_sub(24) as usize;
        lines.push(
            Line::from(vec![
                Span::styled(
                    format!("{} {:<18}", if active { "›" } else { " " }, view.label),
                    Style::default().bold(),
                ),
                Span::styled(
                    chrome::truncate_width(&view.value, value_width),
                    Style::default(),
                ),
            ])
            .style(
                Style::default()
                    .fg(if active { Color::Black } else { TEXT })
                    .bg(if active { ACCENT } else { SURFACE }),
            ),
        );
        app.register_hit_region(
            Rect::new(inner.x, inner.y + row as u16, inner.width, 1),
            SemanticAction::SelectSettingsField(view.field),
        );
    }
    frame.render_widget(
        Paragraph::new(Text::from(lines)).style(Style::default().bg(SURFACE)),
        inner,
    );
}

fn primary_fields(app: &AppState) -> Vec<FieldView> {
    let mut fields = vec![field_view(app, SettingsField::Provider)];
    fields.extend([
        field_view(app, SettingsField::BaseUrl),
        field_view(app, SettingsField::Model),
    ]);
    if app.settings_connection_is_remote() {
        fields.extend([
            field_view(app, SettingsField::ApiKey),
            field_view(app, SettingsField::RemoteConsent),
        ]);
    }
    fields
}

fn reliability_fields(app: &AppState) -> Vec<FieldView> {
    let mut fields = vec![
        field_view(app, SettingsField::Timeout),
        field_view(app, SettingsField::Retries),
        field_view(app, SettingsField::FallbackEnabled),
    ];
    if app.settings_fallback_enabled {
        fields.extend([
            field_view(app, SettingsField::FallbackBaseUrl),
            field_view(app, SettingsField::FallbackModel),
        ]);
    }
    fields
}

fn all_visible_fields(app: &AppState) -> Vec<FieldView> {
    app.visible_settings_fields()
        .into_iter()
        .map(|field| field_view(app, field))
        .collect()
}

fn field_view(app: &AppState, field: SettingsField) -> FieldView {
    let (label, value, hint) = match field {
        SettingsField::Provider => (
            "Provedor",
            LlmProviderKind::all_labels()[app.settings_provider_idx].to_string(),
            "← →",
        ),
        SettingsField::BaseUrl => (
            "URL base",
            empty_label(&app.settings_input_base_url),
            "editar",
        ),
        SettingsField::ApiKey => {
            let value = if app.settings_input_api_key.is_empty() {
                "Não definida".to_string()
            } else if app.settings_api_key_touched {
                format!(
                    "•••••••• · nova chave com {} caracteres",
                    app.settings_input_api_key.chars().count()
                )
            } else {
                "•••••••• · configurada; digite para substituir".to_string()
            };
            ("Chave de API", value, "secreto")
        }
        SettingsField::Model => ("Modelo", empty_label(&app.settings_input_model), "editar"),
        SettingsField::Timeout => (
            "Tempo limite",
            format!("{} segundos · máximo 45", app.settings_input_timeout),
            "editar",
        ),
        SettingsField::Retries => (
            "Retentativas",
            format!("{} · máximo 3", app.settings_input_retries),
            "editar",
        ),
        SettingsField::RemoteConsent => (
            "Envio remoto",
            toggle_label(app.settings_remote_consent, "Consentido", "Bloqueado"),
            "espaço",
        ),
        SettingsField::FallbackEnabled => (
            "Alternativa local",
            toggle_label(app.settings_fallback_enabled, "Ativada", "Desativada"),
            "espaço",
        ),
        SettingsField::FallbackBaseUrl => (
            "URL alternativa",
            empty_label(&app.settings_input_fallback_base_url),
            "editar",
        ),
        SettingsField::FallbackModel => (
            "Modelo alternativo",
            empty_label(&app.settings_input_fallback_model),
            "editar",
        ),
    };
    FieldView {
        field,
        label,
        value,
        hint,
    }
}

fn empty_label(value: &str) -> String {
    if value.is_empty() {
        "Não definido".to_string()
    } else {
        value.to_string()
    }
}

fn toggle_label(enabled: bool, enabled_label: &str, disabled_label: &str) -> String {
    format!(
        "{} {}",
        if enabled { "[x]" } else { "[ ]" },
        if enabled {
            enabled_label
        } else {
            disabled_label
        }
    )
}

fn is_text_field(field: SettingsField) -> bool {
    matches!(
        field,
        SettingsField::BaseUrl
            | SettingsField::ApiKey
            | SettingsField::Model
            | SettingsField::Timeout
            | SettingsField::Retries
            | SettingsField::FallbackBaseUrl
            | SettingsField::FallbackModel
    )
}

fn render_actions(app: &mut AppState, frame: &mut Frame, area: Rect) {
    let columns = Layout::horizontal([
        Constraint::Length(12),
        Constraint::Length(1),
        Constraint::Length(14),
        Constraint::Min(1),
        Constraint::Length(18),
    ])
    .split(area);
    chrome::render_button(
        app,
        frame,
        columns[0],
        "Descartar",
        SemanticAction::CloseSettings,
        chrome::ButtonState::secondary(app.focus == FocusTarget::SettingsCancel),
    );
    chrome::render_button(
        app,
        frame,
        columns[2],
        "Limpar campo",
        SemanticAction::ClearText,
        chrome::ButtonState::secondary(false),
    );
    chrome::render_button(
        app,
        frame,
        columns[4],
        "Salvar alterações",
        SemanticAction::SaveSettings,
        chrome::ButtonState::primary(app.focus == FocusTarget::SettingsSave),
    );
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
    fn masks_api_key_and_hides_remote_fields_for_local_provider() {
        let config = Configuration {
            target_url: String::new(),
            active_tools: Vec::new(),
            provider_mode: "OpenAI".to_string(),
            execution_type: ExecutionType::Assisted,
            llm: LlmConfig {
                api_key: "secret-value".to_string(),
                ..LlmConfig::default()
            },
            nuclei_templates_path: None,
            nuclei_templates_commit: None,
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
        assert!(screen.contains("Configurações de IA"));
        assert!(screen.contains("Conexão principal"));
        assert!(screen.contains("Confiabilidade"));
        assert!(screen.contains("Ollama"));
        assert!(!screen.contains("Chave de API"));
        assert!(!screen.contains("Envio remoto"));
        assert!(screen.contains("Descartar"));
        assert!(screen.contains("Salvar alterações"));
    }

    #[test]
    fn shows_masked_key_and_consent_for_remote_provider() {
        let mut app = AppState::new(Configuration::default());
        app.settings_provider_idx = 2;
        app.settings_input_base_url = "https://api.openai.com/v1".to_string();
        app.settings_input_api_key = "secret-value".to_string();
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal
            .draw(|frame| render(&mut app, frame, frame.area()))
            .unwrap();
        let screen = terminal.backend().to_string();

        assert!(screen.contains("Chave de API"));
        assert!(screen.contains("••••••••"));
        assert!(screen.contains("Envio remoto"));
        assert!(!screen.contains("secret-value"));
    }

    #[test]
    fn exposes_mouse_regions_for_every_keyboard_action_at_80x24() {
        let mut app = AppState::new(Configuration::default());
        app.settings_provider_idx = 2;
        app.settings_input_base_url = "https://api.openai.com/v1".to_string();
        let expected_fields = app.visible_settings_fields();
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal
            .draw(|frame| render(&mut app, frame, frame.area()))
            .unwrap();

        for field in expected_fields {
            assert!(app
                .hit_regions
                .iter()
                .any(|region| { region.action == SemanticAction::SelectSettingsField(field) }));
        }
        assert!(app
            .hit_regions
            .iter()
            .any(|region| region.action == SemanticAction::SaveSettings));
        assert!(app
            .hit_regions
            .iter()
            .any(|region| region.action == SemanticAction::CloseSettings));
        assert!(app
            .hit_regions
            .iter()
            .any(|region| region.action == SemanticAction::ClearText));
    }

    #[test]
    fn compact_layout_scrolls_to_the_focused_conditional_field() {
        let mut app = AppState::new(Configuration::default());
        app.show_settings = true;
        app.settings_fallback_enabled = true;
        app.settings_field = SettingsField::FallbackModel;
        app.focus = FocusTarget::SettingsField(SettingsField::FallbackModel);
        let backend = TestBackend::new(80, 12);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal
            .draw(|frame| render(&mut app, frame, frame.area()))
            .unwrap();
        let screen = terminal.backend().to_string();

        assert!(app.settings_scroll > 0);
        assert!(screen.contains("Modelo alternativo"));
    }
}
