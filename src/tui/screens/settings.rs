use crate::config::llm_config::LlmProviderKind;
use crate::config::llm_config::{MAX_RETRIES, MAX_TIMEOUT_SECS};
use crate::tui::chrome::{
    self, ACCENT, BORDER, DANGER, MUTED, SUCCESS, SURFACE, SURFACE_ACTIVE, SURFACE_HOVER, TEXT,
    WARNING,
};
use crate::tui::interaction::{FocusTarget, SemanticAction};
use crate::tui::state::{AppState, SettingsField};
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Style, Stylize},
    text::{Line, Span, Text},
    widgets::Paragraph,
    Frame,
};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

/// Rótulo, valor e dica de um campo. O valor pode ser um exemplo (campo vazio),
/// e aí sai em cinza para não passar por conteúdo já definido.
struct FieldView {
    field: SettingsField,
    label: &'static str,
    value: String,
    placeholder: bool,
    hint: &'static str,
}

impl FieldView {
    /// Interruptores ocupam uma linha (o estado cabe nela); campos de texto
    /// ocupam duas, porque o valor precisa da largura inteira da coluna.
    fn height(&self) -> u16 {
        if self.field.is_toggle() {
            1
        } else {
            2
        }
    }
}

/// Uma linha da coluna: título de grupo ou campo.
enum ColumnRow {
    Group(&'static str),
    Field(FieldView),
}

impl ColumnRow {
    fn height(&self) -> u16 {
        match self {
            Self::Group(_) => 1,
            Self::Field(view) => view.height(),
        }
    }

    fn field(&self) -> Option<SettingsField> {
        match self {
            Self::Group(_) => None,
            Self::Field(view) => Some(view.field),
        }
    }
}

pub fn render(app: &mut AppState, frame: &mut Frame, area: Rect) {
    let shell = chrome::render_shell(app, frame, area, "Configurar IA", &shell_status(app));
    // Em terminal pequeno o resumo e a ajuda encurtam para o formulário não
    // desaparecer: a tela continua utilizável em 80x12.
    let compact = shell.content.height < 14;
    let rows = if compact {
        Layout::vertical([
            Constraint::Length(1),
            Constraint::Min(3),
            Constraint::Length(3),
            Constraint::Length(1),
        ])
        .split(shell.content)
    } else {
        Layout::vertical([
            Constraint::Length(2),
            Constraint::Min(4),
            Constraint::Length(4),
            Constraint::Length(1),
        ])
        .split(shell.content)
    };
    render_summary(app, frame, rows[0]);
    // O mesmo limiar decide o desenho e a navegação: as setas só podem andar em
    // eixos de coluna quando existe coluna desenhada.
    app.settings_two_columns = rows[1].width >= 72 && rows[1].height >= 8;
    if app.settings_two_columns {
        render_columns(app, frame, rows[1]);
    } else {
        render_compact_form(app, frame, rows[1]);
    }
    render_help(app, frame, rows[2]);
    render_actions(app, frame, rows[3]);
}

/// Rodapé do quadro: diz em uma linha o que está valendo agora, sem repetir o
/// resumo do rascunho que já aparece no topo.
fn shell_status(app: &AppState) -> String {
    if app.settings_status_error().is_some() {
        return "Problema na configuração — veja o aviso acima".to_string();
    }
    if app.settings_connection_is_remote() {
        "Envio remoto · só com consentimento".to_string()
    } else {
        "Conexão local · nada sai da máquina".to_string()
    }
}

fn render_summary(app: &AppState, frame: &mut Frame, area: Rect) {
    let prefix = "Se salvar: ";
    let summary = app.settings_summary(area.width.saturating_sub(prefix.width() as u16) as usize);
    let summary_line = Line::from(vec![
        Span::styled(prefix, Style::default().fg(MUTED).bold()),
        Span::styled(summary, Style::default().fg(TEXT)),
    ]);
    // Em terminal de poucas linhas o erro tem precedência sobre o resumo: é ele
    // que diz o que fazer antes de salvar.
    let (first, second) = if area.height >= 2 {
        (summary_line, Some(situation_line(app)))
    } else if app.settings_status_error().is_some() {
        (situation_line(app), None)
    } else {
        (summary_line, None)
    };
    frame.render_widget(
        Paragraph::new(first).style(Style::default().bg(chrome::BACKGROUND)),
        Rect::new(area.x, area.y, area.width, 1),
    );
    if let Some(second) = second {
        frame.render_widget(
            Paragraph::new(second).style(Style::default().bg(chrome::BACKGROUND)),
            Rect::new(area.x, area.y + 1, area.width, 1),
        );
    }
}

/// Segunda linha do topo: o que impede de salvar vem antes do que é apenas
/// aviso, porque é isso que o operador precisa resolver primeiro.
fn situation_line(app: &AppState) -> Line<'static> {
    if let Some(error) = app.settings_status_error() {
        return Line::from(vec![
            Span::styled("⚠ ", Style::default().fg(DANGER).bold()),
            Span::styled(error.to_string(), Style::default().fg(DANGER)),
        ]);
    }
    if let Some(field) = app.settings_editing {
        return Line::from(vec![
            Span::styled(
                format!("Editando {} ", field_label(field)),
                Style::default().fg(ACCENT).bold(),
            ),
            Span::styled(
                "· enter ou esc fecham o campo; nada é descartado",
                Style::default().fg(MUTED),
            ),
        ]);
    }
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
    let [left, right] = app.settings_column_groups();
    render_column(app, frame, columns[0], &left);
    render_column(app, frame, columns[2], &right);
}

fn column_rows(app: &AppState, groups: &[(&'static str, Vec<SettingsField>)]) -> Vec<ColumnRow> {
    let mut rows = Vec::new();
    for (title, fields) in groups {
        rows.push(ColumnRow::Group(title));
        rows.extend(
            fields
                .iter()
                .map(|field| ColumnRow::Field(field_view(app, *field))),
        );
    }
    rows
}

fn render_column(
    app: &mut AppState,
    frame: &mut Frame,
    area: Rect,
    groups: &[(&'static str, Vec<SettingsField>)],
) {
    let rows = column_rows(app, groups);
    let focused = app.focused_settings_field();
    let focus_index = rows.iter().position(|row| row.field() == focused);
    let block = chrome::panel("", focus_index.is_some());
    let inner = block.inner(area);
    let start = window_start(&rows, focus_index, inner.height);
    let end = fit_end(&rows, start, inner.height);
    let footer = scroll_footer(start, end, rows.len());
    let block = if footer.is_empty() {
        block
    } else {
        block.title_bottom(
            Line::styled(format!(" {footer} "), Style::default().fg(MUTED))
                .alignment(ratatui::layout::Alignment::Right),
        )
    };
    frame.render_widget(block, area);

    let mut y = inner.y;
    for row in rows.iter().skip(start) {
        if y + row.height() > inner.y + inner.height {
            break;
        }
        let rect = Rect::new(inner.x, y, inner.width, row.height());
        match row {
            ColumnRow::Group(title) => render_group(frame, rect, title),
            ColumnRow::Field(view) => render_field(app, frame, rect, view),
        }
        y += row.height();
    }
}

/// Primeira linha visível de uma coluna: o campo em foco nunca sai da janela e
/// a janela só rola o necessário para mantê-lo inteiro.
fn window_start(rows: &[ColumnRow], focus: Option<usize>, height: u16) -> usize {
    let Some(focus) = focus else {
        return 0;
    };
    let mut start = 0;
    loop {
        if focus < start {
            return focus;
        }
        let end = fit_end(rows, start, height);
        if focus < end {
            return start;
        }
        start += 1;
        if start > focus {
            return focus;
        }
    }
}

/// Índice exclusivo da última linha que cabe a partir de `start`.
fn fit_end(rows: &[ColumnRow], start: usize, height: u16) -> usize {
    let mut used = 0;
    let mut end = start;
    for row in rows.iter().skip(start) {
        if used + row.height() > height {
            break;
        }
        used += row.height();
        end += 1;
    }
    end
}

/// A coluna rolou: sem isto o operador não sabe que existem campos fora da
/// janela, e a rolagem por foco pareceria um salto sem causa.
fn scroll_footer(start: usize, end: usize, total: usize) -> String {
    match (start > 0, end < total) {
        (false, false) => String::new(),
        (false, true) => "▼ mais campos abaixo".to_string(),
        (true, false) => "▲ mais campos acima".to_string(),
        (true, true) => "▲▼ mais campos".to_string(),
    }
}

fn render_group(frame: &mut Frame, area: Rect, title: &str) {
    let used = title.width() + 2;
    let rule = "─".repeat(area.width.saturating_sub(used as u16) as usize);
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(format!(" {title} "), Style::default().fg(TEXT).bold()),
            Span::styled(rule, Style::default().fg(BORDER)),
        ]))
        .style(Style::default().bg(SURFACE)),
        area,
    );
}

fn render_field(app: &mut AppState, frame: &mut Frame, area: Rect, view: &FieldView) {
    let active = app.focused_settings_field() == Some(view.field);
    if view.field.is_toggle() {
        render_toggle(app, frame, area, view, active);
    } else {
        render_text_field(app, frame, area, view, active);
    }
    app.register_hit_region(area, SemanticAction::SelectSettingsField(view.field));
}

fn render_text_field(
    app: &AppState,
    frame: &mut Frame,
    area: Rect,
    view: &FieldView,
    active: bool,
) {
    let editing = app.settings_editing == Some(view.field);
    let label = chrome::truncate_width(view.label, area.width as usize);
    let hint = view.hint;
    let padding = area
        .width
        .saturating_sub(label.width() as u16 + hint.width() as u16)
        .max(1) as usize;
    let hovered = app.mouse_over(area);
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(
                label,
                Style::default()
                    .fg(if active { TEXT } else { MUTED })
                    .bold(),
            ),
            Span::raw(" ".repeat(padding)),
            Span::styled(
                hint.to_string(),
                Style::default().fg(if active { ACCENT } else { MUTED }),
            ),
        ]))
        .style(Style::default().bg(if hovered && !active {
            SURFACE_HOVER
        } else {
            SURFACE
        })),
        Rect::new(area.x, area.y, area.width, 1),
    );
    // Em edição o valor rola para o fim: o que o operador acabou de digitar é o
    // que ele precisa ver, e a URL é mais longa que a coluna.
    let value_width = area.width.saturating_sub(4) as usize;
    let value = if editing {
        truncate_left(&view.value, value_width)
    } else {
        chrome::truncate_width(&view.value, value_width)
    };
    let value_style = if view.placeholder {
        Style::default().fg(MUTED)
    } else {
        Style::default().fg(TEXT)
    };
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            // A marca de alteração pendente vive na coluna livre à esquerda do
            // marcador de foco, para não deslocar o valor quando o campo é focado.
            Span::styled(
                if app.settings_field_changed(view.field) {
                    "•"
                } else {
                    " "
                },
                Style::default().fg(WARNING).bold(),
            ),
            Span::styled(
                if active { "›" } else { " " },
                Style::default().fg(ACCENT).bold(),
            ),
            Span::raw(" "),
            Span::styled(value, value_style),
            Span::styled(
                if editing { "▏" } else { "" },
                Style::default().fg(ACCENT).bold(),
            ),
        ]))
        .style(
            Style::default()
                .bg(if active {
                    SURFACE_ACTIVE
                } else if hovered {
                    SURFACE_HOVER
                } else {
                    SURFACE
                })
                .fg(TEXT),
        ),
        Rect::new(area.x, area.y + 1, area.width, 1),
    );
}

/// Interruptor numa linha: o estado já é o valor, e a dica de tecla fica na
/// ajuda do campo em foco, que tem espaço para explicá-la.
fn render_toggle(app: &AppState, frame: &mut Frame, area: Rect, view: &FieldView, active: bool) {
    let label = chrome::truncate_width(view.label, area.width as usize);
    let value_width = view.value.width();
    let padding = area
        .width
        .saturating_sub(3 + label.width() as u16 + value_width as u16)
        .max(1) as usize;
    let on = view.value.starts_with("[x]");
    let hovered = app.mouse_over(area);
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(
                if app.settings_field_changed(view.field) {
                    "•"
                } else {
                    " "
                },
                Style::default().fg(WARNING).bold(),
            ),
            Span::styled(
                if active { "›" } else { " " },
                Style::default().fg(ACCENT).bold(),
            ),
            Span::raw(" "),
            Span::styled(
                label,
                Style::default()
                    .fg(if active { TEXT } else { MUTED })
                    .bold(),
            ),
            Span::raw(" ".repeat(padding)),
            Span::styled(
                view.value.clone(),
                Style::default().fg(if on { SUCCESS } else { MUTED }),
            ),
        ]))
        .style(
            Style::default()
                .bg(if active {
                    SURFACE_ACTIVE
                } else if hovered {
                    SURFACE_HOVER
                } else {
                    SURFACE
                })
                .fg(TEXT),
        ),
        area,
    );
}

/// Formulário de terminal pequeno: uma lista única, na mesma ordem de
/// tabulação, com os títulos de grupo como linhas próprias.
fn render_compact_form(app: &mut AppState, frame: &mut Frame, area: Rect) {
    let [left, right] = app.settings_column_groups();
    let rows: Vec<ColumnRow> = left
        .iter()
        .chain(right.iter())
        .flat_map(|(title, fields)| {
            std::iter::once(ColumnRow::Group(title)).chain(
                fields
                    .iter()
                    .map(|field| ColumnRow::Field(field_view(app, *field))),
            )
        })
        .collect();
    let focus_index = rows
        .iter()
        .position(|row| row.field() == app.focused_settings_field());
    let entry = chrome::panel("Configuração", focus_index.is_some()).inner(area);
    let height = entry.height.max(1) as usize;
    let max_scroll = rows.len().saturating_sub(height);
    app.settings_scroll = app.settings_scroll.min(max_scroll);
    if let Some(index) = focus_index {
        if index < app.settings_scroll {
            app.settings_scroll = index;
        } else if index >= app.settings_scroll.saturating_add(height) {
            app.settings_scroll = index.saturating_add(1).saturating_sub(height);
        }
    }
    let title = compact_title(&rows, app.settings_scroll, height);
    let block = chrome::panel(&title, focus_index.is_some());
    let inner = block.inner(area);
    frame.render_widget(block, area);

    for (offset, row) in rows
        .iter()
        .skip(app.settings_scroll)
        .take(height)
        .enumerate()
    {
        let rect = Rect::new(inner.x, inner.y + offset as u16, inner.width, 1);
        match row {
            ColumnRow::Group(group) => render_group(frame, rect, group),
            ColumnRow::Field(view) => render_compact_field(app, frame, rect, view),
        }
        if let Some(field) = row.field() {
            app.register_hit_region(rect, SemanticAction::SelectSettingsField(field));
        }
    }
}

fn render_compact_field(app: &AppState, frame: &mut Frame, area: Rect, view: &FieldView) {
    let active = app.focused_settings_field() == Some(view.field);
    let changed = app.settings_field_changed(view.field);
    let hovered = app.mouse_over(area);
    let value_width = area.width.saturating_sub(24) as usize;
    frame.render_widget(
        Paragraph::new(Line::from(vec![
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
        ]))
        .style(
            Style::default()
                .fg(if active { Color::Black } else { TEXT })
                .bg(if active {
                    ACCENT
                } else if hovered {
                    SURFACE_HOVER
                } else {
                    SURFACE
                }),
        ),
        area,
    );
}

/// O título anuncia a faixa de campos visível em números de campo (não de
/// linhas), porque é assim que o operador conta o que já viu.
fn compact_title(rows: &[ColumnRow], start: usize, height: usize) -> String {
    let total = rows.iter().filter(|row| row.field().is_some()).count();
    if rows.len() <= height {
        return "Configuração".to_string();
    }
    let before = rows
        .iter()
        .take(start)
        .filter(|row| row.field().is_some())
        .count();
    let visible = rows
        .iter()
        .skip(start)
        .take(height)
        .filter(|row| row.field().is_some())
        .count();
    let first = before + 1;
    let last = before + visible;
    if first == last {
        return format!("Configuração · campo {first} de {total}");
    }
    format!("Configuração · campos {first}-{last} de {total}")
}

/// Ajuda do campo em foco: o que é, para que serve e um exemplo. Fica sempre
/// visível para a tela não exigir documentação externa.
fn render_help(app: &AppState, frame: &mut Frame, area: Rect) {
    let (title, explanation, example) = match app.focused_settings_field() {
        Some(field) => {
            let (explanation, example) = field_help(field);
            (
                format!("Ajuda · {}", field_label(field)),
                explanation,
                example,
            )
        }
        None => (
            "Ajuda".to_string(),
            "A tela agrupa os campos por assunto; o rodapé explica o campo em foco.",
            "tab navega · setas movem · enter edita ou alterna",
        ),
    };
    let value = app
        .focused_settings_field()
        .map(|field| field_value_full(app, field))
        .unwrap_or_default();
    let detail = if value.trim().is_empty() {
        format!("Ex.: {example}")
    } else {
        format!("Atual: {value}  ·  Ex.: {example}")
    };
    let lines = vec![
        Line::styled(explanation.to_string(), Style::default().fg(TEXT)),
        Line::styled(detail, Style::default().fg(MUTED)),
    ];
    if area.height >= 4 {
        let block = chrome::panel(&title, false);
        let inner = block.inner(area);
        frame.render_widget(block, area);
        frame.render_widget(
            Paragraph::new(Text::from(lines)).style(Style::default().bg(SURFACE)),
            inner,
        );
    } else {
        frame.render_widget(
            Paragraph::new(Line::styled(title, Style::default().fg(ACCENT).bold()))
                .style(Style::default().bg(SURFACE)),
            Rect::new(area.x, area.y, area.width, 1),
        );
        frame.render_widget(
            Paragraph::new(Text::from(lines)).style(Style::default().bg(SURFACE)),
            Rect::new(
                area.x,
                area.y + 1,
                area.width,
                area.height.saturating_sub(1),
            ),
        );
    }
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

fn field_view(app: &AppState, field: SettingsField) -> FieldView {
    let (value, placeholder) = field_value(app, field);
    FieldView {
        field,
        label: field_label(field),
        value,
        placeholder,
        hint: field_hint(app, field),
    }
}

fn field_label(field: SettingsField) -> &'static str {
    match field {
        SettingsField::Provider => "Provedor de IA",
        SettingsField::BaseUrl => "Endereço do serviço",
        SettingsField::ApiKey => "Chave de acesso",
        SettingsField::Model => "Modelo da IA",
        SettingsField::Timeout => "Tempo limite",
        SettingsField::Retries => "Tentativas extras",
        SettingsField::RemoteConsent => "Envio remoto",
        SettingsField::FallbackEnabled => "IA local de reserva",
        SettingsField::FallbackBaseUrl => "Endereço local",
        SettingsField::FallbackModel => "Modelo local",
        SettingsField::ProjectDir => "Pasta do projeto",
    }
}

/// Valor exibido e se ele é apenas um exemplo (campo vazio).
fn field_value(app: &AppState, field: SettingsField) -> (String, bool) {
    match field {
        SettingsField::Provider => {
            let provider = LlmProviderKind::all_labels()[app.settings_provider_idx];
            if app.settings_effective_base_url().trim().is_empty() {
                (format!("{provider} · sem endereço"), false)
            } else if app.settings_connection_is_remote() {
                (format!("{provider} · serviço na internet"), false)
            } else {
                (format!("{provider} · na sua máquina"), false)
            }
        }
        SettingsField::BaseUrl => {
            let provider = app.settings_provider();
            let default = provider.default_base_url();
            let example = if default.is_empty() {
                "https://api.exemplo.com/v1"
            } else {
                default
            };
            placeholder_value(&app.settings_input_base_url, example)
        }
        SettingsField::ApiKey => {
            if app.settings_input_api_key.is_empty() {
                ("cole aqui a chave recebida do provedor".to_string(), true)
            } else if app.settings_api_key_touched {
                (
                    format!(
                        "•••••••• · nova chave com {} caracteres",
                        app.settings_input_api_key.chars().count()
                    ),
                    false,
                )
            } else {
                (
                    "•••••••• · guardada no arquivo local 0600".to_string(),
                    false,
                )
            }
        }
        SettingsField::Model => {
            let provider = app.settings_provider();
            let default = provider.default_model();
            let example = if default.is_empty() {
                "gpt-4o"
            } else {
                default
            };
            placeholder_value(&app.settings_input_model, example)
        }
        SettingsField::Timeout => (
            format!(
                "{} segundos · máximo {MAX_TIMEOUT_SECS}",
                app.settings_input_timeout
            ),
            false,
        ),
        SettingsField::Retries => (
            format!(
                "{} tentativas extras · máximo {MAX_RETRIES}",
                app.settings_input_retries
            ),
            false,
        ),
        SettingsField::RemoteConsent => (
            toggle_label(app.settings_remote_consent, "Autorizado", "Bloqueado"),
            false,
        ),
        SettingsField::FallbackEnabled => (
            toggle_label(app.settings_fallback_enabled, "Ligada", "Desligada"),
            false,
        ),
        SettingsField::FallbackBaseUrl => placeholder_value(
            &app.settings_input_fallback_base_url,
            "http://localhost:8080/v1",
        ),
        SettingsField::FallbackModel => placeholder_value(
            &app.settings_input_fallback_model,
            "Meta-Llama-3.1-8B-Instruct-Q4_K_M.gguf",
        ),
        SettingsField::ProjectDir => {
            placeholder_value(&app.settings_input_project_dir, "/home/voce/meu-projeto")
        }
    }
}

/// Valor completo do campo, sem o corte da coluna: é o que a ajuda mostra para
/// o operador conferir o que digitou sem abrir o arquivo de configuração.
fn field_value_full(app: &AppState, field: SettingsField) -> String {
    match field {
        SettingsField::ApiKey => {
            if app.settings_input_api_key.is_empty() {
                "nenhuma chave definida".to_string()
            } else {
                "•••••••• (a chave não aparece na tela)".to_string()
            }
        }
        other => {
            let (value, placeholder) = field_value(app, other);
            if placeholder {
                String::new()
            } else {
                value
            }
        }
    }
}

fn placeholder_value(value: &str, example: &str) -> (String, bool) {
    if value.trim().is_empty() {
        (format!("ex.: {example}"), true)
    } else {
        (value.to_string(), false)
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

/// O que o campo é, para que serve e um exemplo — em linguagem de quem não
/// conhece o pipeline de IA.
fn field_help(field: SettingsField) -> (&'static str, &'static str) {
    match field {
        SettingsField::Provider => (
            "Quem responde às análises: um serviço na internet ou um modelo na sua máquina.",
            "NVIDIA NIM, OpenAI, llama.cpp ou Personalizado (enter troca)",
        ),
        SettingsField::BaseUrl => (
            "Endereço do serviço que responde pela IA. É para lá que os dados são enviados.",
            "https://integrate.api.nvidia.com/v1",
        ),
        SettingsField::ApiKey => (
            "Chave de acesso do provedor, como uma senha; fica no arquivo local 0600 (auth.json).",
            "nvapi-… (NVIDIA) ou sk-… (OpenAI); copie a chave do site do provedor",
        ),
        SettingsField::Model => (
            "Nome do modelo que faz a análise. Vazio usa o padrão do provedor escolhido.",
            "meta/llama-3.1-405b-instruct (NVIDIA) ou gpt-4o (OpenAI)",
        ),
        SettingsField::Timeout => (
            "Tempo máximo que o SmartSec espera por resposta da IA antes de desistir.",
            "45 (máximo permitido; um valor menor desiste antes)",
        ),
        SettingsField::Retries => (
            "Quantas tentativas extras o SmartSec faz quando a IA falha ou demora.",
            "2 (de 0 a 3; cada nova tentativa espera um pouco mais)",
        ),
        SettingsField::RemoteConsent => (
            "Espaço alterna. Autoriza o envio de achados, logs e código ao provedor.",
            "sem marcar, nada sai da máquina e a IA remota não é usada",
        ),
        SettingsField::FallbackEnabled => (
            "Espaço alterna. Se a IA principal falhar, usa o modelo local (llama.cpp).",
            "exige um llama.cpp respondendo na máquina",
        ),
        SettingsField::FallbackBaseUrl => (
            "Endereço do modelo local de reserva; precisa ser local, sem sair da máquina.",
            "http://localhost:8080/v1",
        ),
        SettingsField::FallbackModel => (
            "Modelo local que responde quando a IA principal cai.",
            "Meta-Llama-3.1-8B-Instruct-Q4_K_M.gguf (o arquivo carregado no llama-server)",
        ),
        SettingsField::ProjectDir => (
            "Pasta do projeto que a IA pode ler para apontar onde corrigir cada falha.",
            "/home/voce/meu-projeto (use . para analisar a pasta atual)",
        ),
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

/// Fim do valor, com reticências na frente: durante a digitação o que importa é
/// a parte recém-digitada, que fica fora da coluna quando o texto é longo.
fn truncate_left(value: &str, max_width: usize) -> String {
    if value.width() <= max_width {
        return value.to_string();
    }
    if max_width <= 1 {
        return "…".chars().take(max_width).collect();
    }
    let mut kept: Vec<char> = Vec::new();
    let mut width = 1;
    for character in value.chars().rev() {
        let character_width = character.width().unwrap_or(0);
        if width + character_width > max_width {
            break;
        }
        width += character_width;
        kept.push(character);
    }
    kept.reverse();
    format!("…{}", kept.into_iter().collect::<String>())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::execution_type::ExecutionType;
    use crate::config::llm_config::{LlmConfig, LlmProviderKind};
    use crate::config::Configuration;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    /// Configuração explícita: `Configuration::default()` lê o keyring da
    /// máquina, e um teste de desenho não pode depender do ambiente.
    fn config_with(llm: LlmConfig) -> Configuration {
        Configuration {
            target_url: String::new(),
            active_tools: Vec::new(),
            provider_mode: "Custom".to_string(),
            execution_type: ExecutionType::Assisted,
            llm,
            nuclei_templates_path: None,
            nuclei_templates_commit: None,
            tools: Vec::new(),
            output_file: None,
            output_dir: None,
            max_critical_findings: 0,
            project_dir: None,
            show_help: false,
            show_version: false,
        }
    }

    fn app() -> AppState {
        AppState::new(config_with(LlmConfig::default())).expect("configuração de teste válida")
    }

    fn remote_app() -> AppState {
        let provider = LlmProviderKind::NvidiaNim;
        AppState::new(config_with(LlmConfig {
            provider,
            base_url: provider.default_base_url().to_string(),
            model: provider.default_model().to_string(),
            api_key: "chave-de-teste".to_string(),
            remote_consent: true,
            ..LlmConfig::default()
        }))
        .expect("configuração de teste válida")
    }

    fn local_app() -> AppState {
        let provider = LlmProviderKind::LlamaCpp;
        AppState::new(config_with(LlmConfig {
            provider,
            base_url: provider.default_base_url().to_string(),
            model: provider.default_model().to_string(),
            ..LlmConfig::default()
        }))
        .expect("configuração de teste válida")
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

        app.commit_settings(config_with(LlmConfig::default()));

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

    fn draw(app: &mut AppState, width: u16, height: u16) -> String {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| render(app, frame, frame.area()))
            .unwrap();
        terminal.backend().to_string()
    }

    /// Texto puro do quadro, sem as aspas do `TestBackend`: é o que permite
    /// medir a largura das linhas.
    fn render_snapshot(app: &mut AppState, width: u16, height: u16) -> String {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| render(app, frame, frame.area()))
            .unwrap();
        let buffer = terminal.backend().buffer().clone();
        (0..height)
            .map(|row| {
                (0..width)
                    .map(|column| buffer[(column, row)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// O campo do projeto precisa aparecer na tela de configuração com o valor
    /// efetivo, para que o operador veja qual árvore será analisada.
    #[test]
    fn shows_the_project_directory_field_with_its_effective_value() {
        let mut app = app();

        let screen = draw(&mut app, 80, 24);

        assert!(screen.contains("Pasta do projeto"), "{screen}");
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
        let mut app = app();

        draw(&mut app, 80, 24);

        assert!(app.hit_regions.iter().any(|region| {
            region.action == SemanticAction::SelectSettingsField(SettingsField::ProjectDir)
        }));
    }

    /// Um caminho que a fase do agente rejeitaria não pode ser salvo pela TUI, e
    /// a mensagem precisa dizer o que fazer, não só o que está errado.
    #[test]
    fn an_invalid_project_directory_is_refused_with_an_actionable_message() {
        let mut app = remote_app();
        app.show_settings = true;
        app.settings_input_project_dir = "/caminho/que/nao/existe".to_string();

        let error = app.apply_settings().unwrap_err();

        assert!(error.contains("Diretório do projeto inválido"), "{error}");
        assert!(error.contains("não encontrado"), "{error}");
        assert!(
            error.contains("escolha uma pasta existente"),
            "o erro precisa dizer o que fazer: {error}"
        );
    }

    /// O campo volta ao valor efetivo ao reabrir a tela, para que o operador
    /// veja o padrão real e não um vazio enganoso.
    #[test]
    fn reopening_the_settings_shows_the_effective_project_directory() {
        let mut app = app();
        app.settings_input_project_dir = "/outro/caminho".to_string();

        app.reset_settings_draft();

        assert_eq!(app.settings_input_project_dir, ".");
    }

    #[test]
    fn masks_api_key_and_hides_remote_fields_for_local_provider() {
        let mut app = local_app();
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal
            .draw(|frame| render(&mut app, frame, frame.area()))
            .unwrap();
        let screen = terminal.backend().to_string();

        assert!(!screen.contains("chave-de-teste"), "{screen}");
        assert!(screen.contains("Configurar IA"), "{screen}");
        assert!(screen.contains("Quem responde"), "{screen}");
        assert!(screen.contains("Segurança e limites"), "{screen}");
        assert!(screen.contains("llama.cpp"), "{screen}");
        assert!(!screen.contains("Chave de acesso"), "{screen}");
        assert!(!screen.contains("Envio remoto"), "{screen}");
        assert!(screen.contains("Descartar"), "{screen}");
        assert!(screen.contains("Salvar alterações"), "{screen}");
    }

    #[test]
    fn shows_masked_key_and_consent_for_remote_provider() {
        let mut app = remote_app();

        let screen = draw(&mut app, 80, 24);

        assert!(screen.contains("Chave de acesso"), "{screen}");
        assert!(screen.contains("••••••••"), "{screen}");
        assert!(screen.contains("Envio remoto"), "{screen}");
        assert!(!screen.contains("chave-de-teste"), "{screen}");
    }

    #[test]
    fn exposes_mouse_regions_for_every_keyboard_action_at_80x24() {
        let mut app = remote_app();
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
            .any(|region| { region.action == SemanticAction::SaveSettings }));
        assert!(app
            .hit_regions
            .iter()
            .any(|region| { region.action == SemanticAction::CloseSettings }));
        assert!(app
            .hit_regions
            .iter()
            .any(|region| { region.action == SemanticAction::ClearText }));
    }

    #[test]
    fn compact_layout_scrolls_to_the_focused_conditional_field() {
        let mut app = remote_app();
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
        assert!(screen.contains("Modelo local"), "{screen}");
    }

    /// Fora de um campo de texto não há o que limpar: o botão fica apagado em vez
    /// de responder a um clique sem efeito.
    #[test]
    fn the_clear_button_is_disabled_without_a_text_field_in_focus() {
        let mut app = app();
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
        let mut app = app();
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
        assert!(screen.contains("Editando Endereço do serviço"), "{screen}");
        assert!(screen.contains("editando"), "{screen}");
    }

    /// O campo alterado ganha uma marca própria: o operador vê o que ainda não
    /// foi gravado sem precisar abrir o arquivo de configuração.
    #[test]
    fn a_changed_field_is_marked_until_the_draft_is_saved() {
        let mut app = app();
        app.show_settings = true;
        app.settings_input_base_url = "https://rascunho.local/v1".to_string();

        let screen = draw(&mut app, 80, 24);
        let lines: Vec<&str> = screen.lines().collect();
        let label_row = lines
            .iter()
            .position(|line| line.contains("│Endereço do serviço"))
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

        app.commit_settings(config_with(LlmConfig::default()));

        let screen = draw(&mut app, 80, 24);
        assert!(
            !screen.contains("alteração não salva"),
            "depois de salvar não existe pendência: {screen}"
        );
    }

    /// Em terminal baixo a coluna não cabe inteira: o painel rola até o campo em
    /// foco e anuncia que existem campos fora da janela.
    #[test]
    fn a_short_terminal_scrolls_the_column_and_announces_more_fields() {
        let mut app = remote_app();
        app.show_settings = true;
        app.settings_fallback_enabled = true;
        app.settings_field = SettingsField::FallbackModel;
        app.focus = FocusTarget::SettingsField(SettingsField::FallbackModel);

        let screen = draw(&mut app, 100, 20);

        assert!(screen.contains("Modelo local"), "{screen}");
        assert!(
            screen.contains("mais campos"),
            "a coluna rolada precisa avisar que há mais campos: {screen}"
        );
    }

    /// No formulário compacto a rolagem também precisa ser anunciada, senão o
    /// operador não sabe que existem campos fora da tela.
    #[test]
    fn the_compact_form_announces_the_visible_range() {
        let mut app = app();
        app.show_settings = true;

        let screen = draw(&mut app, 80, 12);

        assert!(screen.contains("Configuração · campo"), "{screen}");
        assert!(screen.contains(" de 9"), "{screen}");
    }

    /// Cada assunto tem título próprio: é o que substitui "Confiabilidade", que
    /// não dizia nada a quem nunca viu o projeto.
    #[test]
    fn the_groups_name_the_purpose_of_each_field_at_80x24() {
        let mut app = remote_app();
        app.show_settings = true;
        app.settings_fallback_enabled = true;

        let screen = render_snapshot(&mut app, 80, 24);

        assert_eq!(screen.lines().count(), 24, "{screen}");
        assert!(screen.lines().all(|line| line.width() <= 80), "{screen}");
        for group in [
            "Quem responde",
            "O que analisar",
            "Segurança e limites",
            "Alternativa local",
        ] {
            assert!(screen.contains(group), "falta o grupo {group}: {screen}");
        }
        for field in app.visible_settings_fields() {
            let label = field_label(field);
            assert!(
                screen.contains(label),
                "o campo {label} não aparece na tela: {screen}"
            );
        }
        assert!(screen.contains("Se salvar:"), "{screen}");
    }

    /// O campo vazio mostra um exemplo em cinza: sem isso o operador não sabe o
    /// formato esperado, e com a cor do texto ele pareceria conteúdo já definido.
    #[test]
    fn an_empty_field_shows_its_example_in_gray() {
        let mut app = remote_app();
        app.show_settings = true;
        app.settings_input_model.clear();
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal
            .draw(|frame| render(&mut app, frame, frame.area()))
            .unwrap();
        let buffer = terminal.backend().buffer().clone();

        let row = app
            .hit_regions
            .iter()
            .find(|region| {
                region.action == SemanticAction::SelectSettingsField(SettingsField::Model)
            })
            .expect("o campo do modelo precisa estar visível")
            .area;
        let value_row = row.y + 1;
        let text: String = (0..80)
            .map(|column| buffer[(column, value_row)].symbol())
            .collect();
        assert!(text.contains("ex.:"), "o exemplo precisa aparecer: {text}");
        let column = text.find("ex.:").expect("coluna do exemplo") as u16;
        assert_eq!(
            buffer[(column, value_row)].fg,
            MUTED,
            "o exemplo é cinza para não passar por valor definido"
        );
    }

    /// A ajuda acompanha o campo em foco e sempre traz um exemplo: é o que
    /// permite usar a tela sem consultar documentação.
    #[test]
    fn the_help_area_explains_the_focused_field_with_an_example() {
        let mut app = remote_app();
        app.show_settings = true;
        app.focus = FocusTarget::SettingsField(SettingsField::BaseUrl);

        let screen = draw(&mut app, 80, 24);

        assert!(screen.contains("Ajuda · Endereço do serviço"), "{screen}");
        assert!(
            screen.contains("Endereço do serviço que responde pela IA"),
            "{screen}"
        );
        assert!(screen.contains("Ex.:"), "{screen}");
        assert!(
            screen.contains("https://integrate.api.nvidia.com/v1"),
            "{screen}"
        );

        app.focus = FocusTarget::SettingsField(SettingsField::Timeout);
        let timeout_screen = draw(&mut app, 80, 24);

        assert!(
            timeout_screen.contains("Ajuda · Tempo limite"),
            "{timeout_screen}"
        );
        assert!(
            timeout_screen.contains("Tempo máximo que o SmartSec espera"),
            "{timeout_screen}"
        );
        assert!(
            !timeout_screen.contains("Endereço do serviço que responde pela IA"),
            "a ajuda precisa mudar com o foco: {timeout_screen}"
        );
    }

    /// O interruptor não tem dica na linha (não cabe), então a ajuda é quem diz
    /// como alternar.
    #[test]
    fn the_help_of_a_toggle_says_how_to_change_it() {
        let mut app = remote_app();
        app.show_settings = true;
        app.focus = FocusTarget::SettingsField(SettingsField::RemoteConsent);

        let screen = draw(&mut app, 80, 24);

        assert!(screen.contains("Ajuda · Envio remoto"), "{screen}");
        assert!(screen.contains("Espaço alterna"), "{screen}");
    }

    #[test]
    fn the_summary_marks_an_environment_key_as_session_only() {
        let mut app = remote_app();
        app.config.llm.credential_from_env = true;
        app.show_settings = true;
        app.reset_settings_draft();

        let screen = draw(&mut app, 100, 24);

        assert!(
            screen.contains("chave da sessão (SMARTSEC_API_KEY)"),
            "{screen}"
        );
    }

    /// O resumo responde "o que acontece se eu salvar" no estado do rascunho.
    #[test]
    fn the_summary_says_what_the_draft_will_do() {
        let mut remoto = remote_app();
        remoto.show_settings = true;

        let screen = draw(&mut remoto, 80, 24);
        assert!(screen.contains("Se salvar: IA: NVIDIA NIM"), "{screen}");
        assert!(screen.contains("chave salva"), "{screen}");
        assert!(screen.contains("envio remoto permitido"), "{screen}");

        // Com largura sobrando o modelo entra no resumo; em 80 colunas ele cede
        // lugar para o aviso de envio, que decide a privacidade do operador.
        let completo = remoto.settings_summary(120);
        assert!(
            completo.contains("meta/llama-3.1-405b-instruct"),
            "{completo}"
        );
        let provider_at = completo.find("NVIDIA NIM").expect("provedor no resumo");
        let model_at = completo.find("meta/").expect("modelo no resumo");
        assert!(
            provider_at < model_at,
            "o modelo vem logo depois do provedor: {completo}"
        );

        remoto.settings_remote_consent = false;
        let screen = draw(&mut remoto, 80, 24);
        assert!(screen.contains("envio remoto bloqueado"), "{screen}");

        remoto.settings_input_api_key.clear();
        let screen = draw(&mut remoto, 80, 24);
        assert!(screen.contains("sem chave"), "{screen}");

        let mut local = local_app();
        local.show_settings = true;
        let screen = draw(&mut local, 80, 24);
        assert!(screen.contains("nada sai da máquina"), "{screen}");

        let mut desligada = app();
        desligada.show_settings = true;
        let screen = draw(&mut desligada, 80, 24);
        assert!(screen.contains("IA desligada"), "{screen}");
    }

    /// O resumo também marca o que o rascunho tem de inválido, e o erro diz o
    /// que fazer para resolver.
    #[test]
    fn the_summary_marks_draft_problems_and_the_error_tells_what_to_do() {
        let mut app = remote_app();
        app.show_settings = true;
        app.settings_input_timeout = "999".to_string();
        app.settings_error = app.settings_candidate().err();
        app.focus = FocusTarget::SettingsField(SettingsField::Timeout);

        let screen = draw(&mut app, 80, 24);

        assert!(screen.contains("tempo limite inválido"), "{screen}");
        assert!(screen.contains("entre 1 e 45"), "{screen}");
        assert!(
            screen.contains("use um número"),
            "o erro precisa dizer o que fazer: {screen}"
        );
    }

    /// Sem chave a mensagem aponta a correção, não só a falta.
    #[test]
    fn a_missing_key_is_reported_with_the_next_step() {
        let mut app = remote_app();
        app.show_settings = true;
        app.settings_input_api_key.clear();
        app.settings_error = app.settings_candidate().err();

        let screen = draw(&mut app, 80, 24);

        assert!(screen.contains("Credenciais obrigatórias"), "{screen}");
        assert!(screen.contains("informe a chave de acesso"), "{screen}");
    }

    /// Um valor longo em edição rola para o fim: o operador precisa ver o que
    /// acabou de digitar, e a coluna é mais estreita que a URL.
    #[test]
    fn a_long_value_in_editing_keeps_the_typed_end_visible() {
        let mut app = remote_app();
        app.show_settings = true;
        app.focus = FocusTarget::SettingsField(SettingsField::BaseUrl);
        app.settings_editing = Some(SettingsField::BaseUrl);
        app.settings_input_base_url =
            "https://integrate.api.nvidia.com/v1/extra-digitado".to_string();

        let screen = draw(&mut app, 80, 24);

        assert!(screen.contains("extra-digitado"), "{screen}");
    }

    /// O resumo é cortado por partes inteiras, nunca no meio de uma palavra.
    #[test]
    fn the_summary_drops_whole_parts_when_the_width_is_small() {
        let mut app = remote_app();
        app.settings_fallback_enabled = true;

        let summary = app.settings_summary(40);

        assert!(summary.starts_with("IA: NVIDIA NIM"), "{summary}");
        assert!(!summary.ends_with(" ·"), "{summary}");
        assert!(summary.width() <= 40, "{summary}");
    }
}
