use crate::config::execution_type::ExecutionType;
use crate::tui::chrome::{self, ACCENT, MUTED, SURFACE, TEXT};
use crate::tui::interaction::{FocusTarget, SemanticAction};
use crate::tui::state::AppState;
use ratatui::{
    layout::{Alignment, Constraint, Flex, Layout, Rect},
    style::{Color, Style, Stylize},
    text::{Line, Span},
    widgets::Paragraph,
    Frame,
};

pub fn render(app: &mut AppState, frame: &mut Frame, area: Rect) {
    let shell = chrome::render_shell(
        app,
        frame,
        area,
        "Nova análise",
        "Pronto para configurar a análise",
    );
    let content = if shell.content.width > 72 {
        let horizontal = Layout::horizontal([
            Constraint::Length(6),
            Constraint::Min(1),
            Constraint::Length(6),
        ])
        .split(shell.content);
        horizontal[1]
    } else {
        shell.content
    };
    let page = Layout::vertical([Constraint::Min(1), Constraint::Length(2)]).split(content);
    let form = Layout::vertical([Constraint::Length(15)])
        .flex(Flex::Center)
        .split(page[0])[0];
    let rows = Layout::vertical([
        Constraint::Length(3),
        Constraint::Length(1),
        Constraint::Length(3),
        Constraint::Length(1),
        Constraint::Length(3),
        Constraint::Length(1),
        Constraint::Length(3),
    ])
    .split(form);

    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("SMART", Style::default().fg(TEXT).bold()),
            Span::styled("SEC", Style::default().fg(ACCENT).bold()),
            Span::styled(
                "  análise de segurança assistida",
                Style::default().fg(MUTED),
            ),
        ]))
        .alignment(Alignment::Center),
        rows[0],
    );

    render_target(app, frame, rows[2]);
    render_modes(app, frame, rows[4]);
    render_model(app, frame, rows[6]);

    let buttons = Layout::horizontal([
        Constraint::Min(1),
        Constraint::Length(16),
        Constraint::Length(1),
        Constraint::Length(12),
    ])
    .split(page[1]);
    chrome::render_button(
        app,
        frame,
        buttons[1],
        "Configurar IA",
        SemanticAction::OpenSettings,
        chrome::ButtonState::secondary(app.focus == FocusTarget::SplashSettings),
    );
    chrome::render_button(
        app,
        frame,
        buttons[3],
        "Iniciar",
        SemanticAction::StartScan,
        chrome::ButtonState::primary(app.focus == FocusTarget::SplashStart),
    );
}

fn render_target(app: &mut AppState, frame: &mut Frame, area: Rect) {
    let focused = app.focus == FocusTarget::SplashTarget;
    let block = chrome::panel("Alvo", focused);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let value = if app.config.target_url.is_empty() {
        "http://exemplo.local"
    } else {
        &app.config.target_url
    };
    let prefix = if focused { "> " } else { "  " };
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(prefix, Style::default().fg(ACCENT).bold()),
            Span::styled(
                chrome::truncate_width(value, inner.width.saturating_sub(3) as usize),
                Style::default().fg(if app.config.target_url.is_empty() {
                    MUTED
                } else {
                    TEXT
                }),
            ),
        ]))
        .style(Style::default().bg(SURFACE)),
        inner,
    );
    app.register_hit_region(area, SemanticAction::SetFocus(FocusTarget::SplashTarget));
}

fn render_modes(app: &mut AppState, frame: &mut Frame, area: Rect) {
    let columns =
        Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)]).split(area);
    for (column, mode, label, focus) in [
        (
            columns[0],
            ExecutionType::Auto,
            "Automático · fluxo contínuo",
            FocusTarget::SplashAuto,
        ),
        (
            columns[1],
            ExecutionType::Assisted,
            "Assistido · escolha manual",
            FocusTarget::SplashAssisted,
        ),
    ] {
        let focused = app.focus == focus;
        let selected = app.mode() == mode;
        let block = chrome::panel(if selected { "Modo selecionado" } else { "Modo" }, focused);
        let inner = block.inner(column);
        frame.render_widget(block, column);
        frame.render_widget(
            Paragraph::new(format!("{} {label}", if selected { "[x]" } else { "[ ]" })).style(
                Style::default()
                    .fg(if focused { Color::Black } else { TEXT })
                    .bg(if focused { ACCENT } else { SURFACE })
                    .bold(),
            ),
            inner,
        );
        app.register_hit_region(column, SemanticAction::SetMode(mode));
    }
}

fn render_model(app: &mut AppState, frame: &mut Frame, area: Rect) {
    let focused = app.focus == FocusTarget::SplashSettings;
    let block = chrome::panel("Modelo de IA", focused);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let provider =
        crate::config::llm_config::LlmProviderKind::all_labels()[app.settings_provider_idx];
    let model = if app.config.llm.model.is_empty() {
        "não configurado"
    } else {
        &app.config.llm.model
    };
    frame.render_widget(
        Paragraph::new(format!("  {provider}  /  {model}")).style(
            Style::default()
                .fg(if focused { TEXT } else { MUTED })
                .bg(SURFACE),
        ),
        inner,
    );
    app.register_hit_region(area, SemanticAction::OpenSettings);
}
