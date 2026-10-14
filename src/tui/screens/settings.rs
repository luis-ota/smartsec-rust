use crate::config::llm_config::LlmProviderKind;
use crate::tui::chrome::{self, ACCENT, DANGER, MUTED, SURFACE, SURFACE_ACTIVE, TEXT, WARNING};
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
    let status = app
        .settings_status_error()
        .map(str::to_string)
        .unwrap_or_else(|| {
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
    // O mesmo limiar decide o desenho e a navegação: as setas só podem andar em
    // eixos de coluna quando existe coluna desenhada.
    app.settings_two_columns = rows[1].width >= 72 && rows[1].height >= 12;
    if app.settings_two_columns {
        render_columns(app, frame, rows[1]);
    } else {
        render_compact_form(app, frame, rows[1]);
    }
    render_actions(app, frame, rows[2]);
}

fn render_intro(app: &AppState, frame: &mut Frame, area: Rect) {
    let title = Line::styled(
        "Defina o provedor e os limites. Opções não aplicáveis ficam ocultas.",
        Style::default().fg(TEXT).bold(),
    );
    let detail = if let Some(error) = app.settings_status_error() {
        Line::styled(error, Style::default().fg(DANGER))
    } else if let Some(field) = app.settings_editing {
        Line::from(vec![
            Span::styled(
                format!("Editando {} ", field_label(field)),
                Style::default().fg(ACCENT).bold(),
            ),
            Span::styled(
                "· enter ou esc saem do campo; nada é descartado",
                Style::default().fg(MUTED),
            ),
        ])
    } else {
        status_line(app)
    };
    frame.render_widget(
        Paragraph::new(Text::from(vec![title, detail]))
            .style(Style::default().bg(chrome::BACKGROUND)),
        area,
    );
}

/// Rodapé da tela: com rascunho pendente a prioridade é avisar que o `esc`
/// descarta algo, porque é isso que o operador precisa saber antes de teclar.
fn status_line(app: &AppState) -> Line<'static> {
    let dirty = app.settings_dirty_count();
    if dirty > 0 {
        return Line::from(vec![
            Span::styled("• ", Style::default().fg(WARNING).bold()),
            Span::styled(pending_label(dirty), Style::default().fg(WARNING).bold()),
            Span::styled(" · esc descarta o rascunho", Style::default().fg(MUTED)),
        ]);
    }
    Line::styled(
        "Tab navega · setas movem · enter aciona ou edita · esc descarta",
        Style::default().fg(MUTED),
    )
}

fn pending_label(count: usize) -> String {
    if count == 1 {
        "1 alteração não salva".to_string()
    } else {
        format!("{count} alterações não salvas")
    }
}

fn render_columns(app: &mut AppState, frame: &mut Frame, area: Rect) {
    let columns = Layout::horizontal([
        Constraint::Percentage(50),
        Constraint::Length(1),
        Constraint::Percentage(50),
    ])
    .split(area);
    let [primary, reliability] = app.settings_columns();
    let primary: Vec<FieldView> = primary.into_iter().map(|f| field_view(app, f)).collect();
    let reliability: Vec<FieldView> = reliability
        .into_iter()
        .map(|f| field_view(app, f))
        .collect();
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
    let focused_field = app.focused_settings_field();
    let focused = fields.iter().any(|view| focused_field == Some(view.field));
    let capacity = (area.height.saturating_sub(2) / 2).max(1) as usize;
    let first = window_start(
        fields
            .iter()
            .position(|view| focused_field == Some(view.field)),
        capacity,
        fields.len(),
    );
    let visible = fields.len().min(capacity);
    let title = section_title(title, first, visible, fields.len());
    let block = chrome::panel(&title, focused);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    for (row, view) in fields.iter().skip(first).take(visible).enumerate() {
        let y = inner.y + row as u16 * 2;
        render_field(app, frame, Rect::new(inner.x, y, inner.width, 2), view);
    }
}

/// Primeira linha visível de uma seção: o campo em foco nunca sai da janela e a
/// janela só rola o necessário para mantê-lo visível.
fn window_start(focused_index: Option<usize>, capacity: usize, total: usize) -> usize {
    let capacity = capacity.max(1);
    focused_index
        .map(|index| index.saturating_sub(capacity - 1))
        .unwrap_or(0)
        .min(total.saturating_sub(capacity))
}

fn section_title(title: &str, first: usize, visible: usize, total: usize) -> String {
    if total > visible {
        format!(
            "{title} · campos {}-{} de {total}",
            first + 1,
            first + visible
        )
    } else {
        title.to_string()
    }
}

fn render_field(app: &mut AppState, frame: &mut Frame, area: Rect, view: &FieldView) {
    let active = app.focused_settings_field() == Some(view.field);
    let editing = app.settings_editing == Some(view.field);
    let changed = app.settings_field_changed(view.field);
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
        // A marca de alteração pendente vive na coluna livre à esquerda do
        // marcador de foco, para não deslocar o valor quando o campo é focado.
        Span::styled(
            if changed { "•" } else { " " },
            Style::default().fg(WARNING).bold(),
        ),
        Span::styled(
            if active { "›" } else { " " },
            Style::default().fg(ACCENT).bold(),
        ),
        Span::raw(" "),
        Span::styled(value, Style::default().fg(TEXT)),
        Span::styled(
            if editing { "▏" } else { "" },
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
        .position(|view| app.focused_settings_field() == Some(view.field));
    let entry = chrome::panel("Configuração", focused_index.is_some()).inner(area);
    let inner_height = entry.height.max(1) as usize;
    let max_scroll = fields.len().saturating_sub(inner_height);
    app.settings_scroll = app.settings_scroll.min(max_scroll);
    if let Some(index) = focused_index {
        if index < app.settings_scroll {
            app.settings_scroll = index;
        } else if index >= app.settings_scroll.saturating_add(inner_height) {
            app.settings_scroll = index.saturating_sub(inner_height - 1);
        }
    }

    let visible = inner_height.min(fields.len().saturating_sub(app.settings_scroll));
    let title = section_title("Configuração", app.settings_scroll, visible, fields.len());
    let block = chrome::panel(&title, focused_index.is_some());
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let mut lines = Vec::new();
    for row in 0..visible {
        let view = &fields[app.settings_scroll + row];
        let active = app.focused_settings_field() == Some(view.field);
        let changed = app.settings_field_changed(view.field);
        let value_width = inner.width.saturating_sub(24) as usize;
        lines.push(
            Line::from(vec![
                Span::styled(
                    if changed { "•" } else { " " },
                    Style::default().fg(WARNING).bold(),
                ),
                Span::styled(
                    // O rótulo tem coluna fixa de 18 e um espaço de separação,
                    // para o valor começar sempre na mesma coluna.
                    format!(
                        "{} {:<18} ",
                        if active { "›" } else { " " },
                        chrome::truncate_width(view.label, 18)
                    ),
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

fn all_visible_fields(app: &AppState) -> Vec<FieldView> {
    app.visible_settings_fields()
        .into_iter()
        .map(|field| field_view(app, field))
        .collect()
}

fn field_view(app: &AppState, field: SettingsField) -> FieldView {
    FieldView {
        field,
        label: field_label(field),
        value: field_value(app, field),
        hint: field_hint(app, field),
    }
}

fn field_label(field: SettingsField) -> &'static str {
    match field {
        SettingsField::Provider => "Provedor",
        SettingsField::BaseUrl => "URL base",
        SettingsField::ApiKey => "Chave de API",
        SettingsField::Model => "Modelo",
        SettingsField::Timeout => "Tempo limite",
        SettingsField::Retries => "Retentativas",
        SettingsField::RemoteConsent => "Envio remoto",
        SettingsField::FallbackEnabled => "Alternativa local",
        SettingsField::FallbackBaseUrl => "URL alternativa",
        SettingsField::FallbackModel => "Modelo alternativo",
        SettingsField::ProjectDir => "Projeto analisado",
    }
}

fn field_value(app: &AppState, field: SettingsField) -> String {
    match field {
        SettingsField::Provider => {
            LlmProviderKind::all_labels()[app.settings_provider_idx].to_string()
        }
        SettingsField::BaseUrl => empty_label(&app.settings_input_base_url),
        SettingsField::ApiKey => {
            if app.settings_input_api_key.is_empty() {
                "Não definida".to_string()
            } else if app.settings_api_key_touched {
                format!(
                    "•••••••• · nova chave com {} caracteres",
                    app.settings_input_api_key.chars().count()
                )
            } else {
                "•••••••• · configurada; digite para substituir".to_string()
            }
        }
        SettingsField::Model => empty_label(&app.settings_input_model),
        SettingsField::Timeout => {
            format!("{} segundos · máximo 45", app.settings_input_timeout)
        }
        SettingsField::Retries => format!("{} · máximo 3", app.settings_input_retries),
        SettingsField::RemoteConsent => {
            toggle_label(app.settings_remote_consent, "Consentido", "Bloqueado")
        }
        SettingsField::FallbackEnabled => {
            toggle_label(app.settings_fallback_enabled, "Ativada", "Desativada")
        }
        SettingsField::FallbackBaseUrl => empty_label(&app.settings_input_fallback_base_url),
        SettingsField::FallbackModel => empty_label(&app.settings_input_fallback_model),
        SettingsField::ProjectDir => app.settings_input_project_dir.clone(),
    }
}

/// Dica da linha do campo: em repouso descreve o campo, e em foco diz o que as
/// teclas fazem agora — é o que separa "focado" de "editando".
fn field_hint(app: &AppState, field: SettingsField) -> &'static str {
    if app.focused_settings_field() != Some(field) {
        return match field {
            SettingsField::Provider => "enter troca",
            SettingsField::ApiKey => "secreto",
            SettingsField::RemoteConsent | SettingsField::FallbackEnabled => "espaço",
            SettingsField::ProjectDir => "read-only",
            _ => "editar",
        };
    }
    if field == SettingsField::Provider {
        return "enter troca";
    }
    if field.is_toggle() {
        return "espaço alterna";
    }
    if app.settings_editing == Some(field) {
        "editando"
    } else {
        "enter edita"
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

fn render_actions(app: &mut AppState, frame: &mut Frame, area: Rect) {
    let columns = Layout::horizontal([
        Constraint::Length(12),
        Constraint::Length(1),
        Constraint::Length(14),
        Constraint::Min(1),
        Constraint::Length(18),
    ])
    .split(area);
    // Sem campo de texto em foco não há o que limpar: um botão apagado é mais
    // honesto do que um clique que não faz nada.
    let clear_enabled = app
        .focused_settings_field()
        .is_some_and(SettingsField::is_text);
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
        chrome::ButtonState::secondary(false).enabled(clear_enabled),
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

    fn app() -> AppState {
        AppState::new(Configuration::default()).expect("configuração de teste válida")
    }

    /// Criterio de aceite 2: salvar uma configuracao valida remove o aviso.
    ///
    /// Testa `commit_settings`, nao `apply_settings`: o `apply` termina em
    /// `save`, que grava no config.toml real e no keyring do sistema — foi o
    /// que quebrou no CI. O `commit` e onde o aviso decide, sem tocar o ambiente.
    #[test]
    fn saving_a_valid_configuration_clears_the_opening_warning() {
        let mut app = app();
        app.set_config_warning(Some("IA: credenciais obrigatórias".to_string()));
        assert!(app.config_warning.is_some());

        app.commit_settings(Configuration::default());

        assert!(
            app.config_warning.is_none(),
            "o aviso de abertura sobreviveu a uma configuracao valida: {:?}",
            app.config_warning
        );
        assert!(!app.show_settings, "a tela de configuracao deveria fechar");
    }

    /// Um aviso vazio nao e aviso. Sem esta guarda, um `set_config_warning("")`
    /// deixaria a linha de status exibindo um espaco em branco com a cor de
    /// erro, que e pior do que nao exibir nada.
    #[test]
    fn a_blank_warning_is_treated_as_no_warning() {
        let mut app = app();

        app.set_config_warning(Some("   \n  ".to_string()));

        assert!(app.config_warning.is_none());
        assert!(app.settings_status_error().is_none());
    }

    /// O aviso de abertura e o erro de salvamento disputam a mesma linha, e o
    /// erro de salvamento e mais recente: ele tem a precedencia.
    #[test]
    fn a_save_error_takes_precedence_over_the_opening_warning() {
        let mut app = app();
        app.set_config_warning(Some("IA: credenciais obrigatórias".to_string()));
        app.settings_error = Some("IA: consentimento não aceito".to_string());

        assert_eq!(
            app.settings_status_error(),
            Some("IA: consentimento não aceito")
        );
    }

    use crate::config::execution_type::ExecutionType;
    use crate::config::llm_config::LlmConfig;
    use crate::config::Configuration;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    fn draw(app: &mut AppState, width: u16, height: u16) -> String {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| render(app, frame, frame.area()))
            .unwrap();
        terminal.backend().to_string()
    }

    /// O campo do projeto precisa aparecer na tela de configuração com o valor
    /// efetivo, para que o operador veja qual árvore será analisada.
    #[test]
    fn shows_the_project_directory_field_with_its_effective_value() {
        let mut app = AppState::new(Configuration::default()).expect("configuração válida");

        let screen = draw(&mut app, 80, 24);

        assert!(screen.contains("Projeto analisado"), "{screen}");
        assert!(
            screen.contains("read-only"),
            "a dica precisa deixar claro que o agente só lê o projeto: {screen}"
        );
        assert!(
            screen.lines().any(|line| line.contains('.')),
            "o valor padrão precisa ser o diretório atual"
        );
    }

    /// O campo do projeto é navegável por mouse como os demais (RNF07).
    #[test]
    fn the_project_field_exposes_a_mouse_region() {
        let mut app = AppState::new(Configuration::default()).expect("configuração válida");

        draw(&mut app, 80, 24);

        assert!(app.hit_regions.iter().any(|region| {
            region.action == SemanticAction::SelectSettingsField(SettingsField::ProjectDir)
        }));
    }

    /// Um caminho que a fase do agente rejeitaria não pode ser salvo pela TUI.
    #[test]
    fn an_invalid_project_directory_is_refused_with_an_actionable_message() {
        let mut app = AppState::new(Configuration {
            llm: crate::config::llm_config::remote_de_teste(),
            ..Configuration::default()
        })
        .expect("configuração válida");
        app.show_settings = true;
        app.settings_input_project_dir = "/caminho/que/nao/existe".to_string();

        let error = app.apply_settings().unwrap_err();

        assert!(error.contains("Diretório do projeto inválido"), "{error}");
        assert!(error.contains("não encontrado"), "{error}");
    }

    /// O campo volta ao valor efetivo ao reabrir a tela, para que o operador
    /// veja o padrão real e não um vazio enganoso.
    #[test]
    fn reopening_the_settings_shows_the_effective_project_directory() {
        let mut app = AppState::new(Configuration::default()).expect("configuração válida");
        app.settings_input_project_dir = "/outro/caminho".to_string();

        app.reset_settings_draft();

        assert_eq!(app.settings_input_project_dir, ".");
    }

    #[test]
    fn masks_api_key_and_hides_remote_fields_for_local_provider() {
        let config = Configuration {
            target_url: String::new(),
            active_tools: Vec::new(),
            provider_mode: "OpenAI".to_string(),
            execution_type: ExecutionType::Assisted,
            llm: LlmConfig {
                api_key: "secret-value".to_string(),
                ..crate::config::llm_config::local_de_teste()
            },
            nuclei_templates_path: None,
            nuclei_templates_commit: None,
            tools: Vec::new(),
            output_file: None,
            output_dir: None,
            max_critical_findings: 0,
            project_dir: None,
            show_help: false,
            show_version: false,
        };
        let mut app = AppState::new(config).expect("configuração de teste válida");
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
        assert!(screen.contains("llama.cpp"));
        assert!(!screen.contains("Chave de API"));
        assert!(!screen.contains("Envio remoto"));
        assert!(screen.contains("Descartar"));
        assert!(screen.contains("Salvar alterações"));
    }

    #[test]
    fn shows_masked_key_and_consent_for_remote_provider() {
        let mut app =
            AppState::new(Configuration::default()).expect("configuração de teste válida");
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
        let mut app =
            AppState::new(Configuration::default()).expect("configuração de teste válida");
        app.settings_provider_idx = 2;
        app.settings_input_base_url = "https://api.openai.com/v1".to_string();
        // O botão de limpar só existe com um campo de texto em foco; aqui o alvo
        // é o conjunto de regiões clicáveis do teclado, então o foco é de campo.
        app.focus = FocusTarget::SettingsField(SettingsField::BaseUrl);
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
        let mut app =
            AppState::new(Configuration::default()).expect("configuração de teste válida");
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

    /// Fora de um campo de texto não há o que limpar: o botão fica apagado em vez
    /// de responder a um clique sem efeito.
    #[test]
    fn the_clear_button_is_disabled_without_a_text_field_in_focus() {
        let mut app =
            AppState::new(Configuration::default()).expect("configuração de teste válida");
        app.show_settings = true;
        app.focus = FocusTarget::SettingsSave;

        let screen = draw(&mut app, 80, 24);

        assert!(screen.contains("Limpar campo"), "{screen}");
        assert!(
            !app.hit_regions
                .iter()
                .any(|region| region.action == SemanticAction::ClearText),
            "sem campo de texto em foco o botão não pode ser clicável"
        );
    }

    /// O cursor de digitação só existe com o campo aberto: a tela não pode
    /// prometer uma edição que o `enter` ainda não abriu.
    #[test]
    fn the_cursor_only_appears_while_the_field_is_open_for_editing() {
        let mut app =
            AppState::new(Configuration::default()).expect("configuração de teste válida");
        app.show_settings = true;
        app.focus = FocusTarget::SettingsField(SettingsField::BaseUrl);

        let screen = draw(&mut app, 80, 24);

        assert!(screen.contains("enter edita"), "{screen}");
        assert!(
            !screen.contains('▏'),
            "sem edição não existe cursor: {screen}"
        );

        app.settings_editing = Some(SettingsField::BaseUrl);
        let screen = draw(&mut app, 80, 24);

        assert!(screen.contains('▏'), "{screen}");
        assert!(screen.contains("Editando URL base"), "{screen}");
        assert!(screen.contains("editando"), "{screen}");
    }

    /// O campo alterado ganha uma marca própria: o operador vê o que ainda não
    /// foi gravado sem precisar abrir o arquivo de configuração.
    #[test]
    fn a_changed_field_is_marked_until_the_draft_is_saved() {
        let mut app =
            AppState::new(Configuration::default()).expect("configuração de teste válida");
        app.show_settings = true;
        app.settings_input_base_url = "https://rascunho.local/v1".to_string();

        let screen = draw(&mut app, 80, 24);
        let lines: Vec<&str> = screen.lines().collect();
        let label_row = lines
            .iter()
            .position(|line| line.contains("│URL base"))
            .expect("o campo precisa estar visível");
        // O `TestBackend` imprime cada linha entre aspas; a marca de alteração é
        // a primeira coluna interna do painel, depois da borda.
        assert!(
            lines[label_row + 1]
                .trim_start_matches('"')
                .starts_with("│•"),
            "a linha do valor marca o campo alterado: {screen}"
        );
        assert!(screen.contains("1 alteração não salva"), "{screen}");

        app.commit_settings(Configuration::default());

        let screen = draw(&mut app, 80, 24);
        assert!(
            !screen.contains("alteração não salva"),
            "depois de salvar não existe pendência: {screen}"
        );
    }

    /// Em terminal baixo a coluna de confiabilidade não cabe inteira: o painel
    /// rola até o campo em foco e anuncia a faixa visível.
    #[test]
    fn a_short_terminal_scrolls_the_column_and_shows_the_visible_range() {
        let mut app =
            AppState::new(Configuration::default()).expect("configuração de teste válida");
        app.show_settings = true;
        app.settings_fallback_enabled = true;
        app.settings_field = SettingsField::FallbackModel;
        app.focus = FocusTarget::SettingsField(SettingsField::FallbackModel);

        let screen = draw(&mut app, 100, 20);

        assert!(screen.contains("Modelo alternativo"), "{screen}");
        assert!(screen.contains("2-6 de 6"), "{screen}");
    }

    /// No formulário compacto a rolagem também precisa ser anunciada, senão o
    /// operador não sabe que existem campos fora da tela.
    #[test]
    fn the_compact_form_announces_the_visible_range() {
        let mut app =
            AppState::new(Configuration::default()).expect("configuração de teste válida");
        app.show_settings = true;

        let screen = draw(&mut app, 80, 12);

        assert!(screen.contains("1-3 de 9"), "{screen}");
    }
}
