use crate::config::environment::{ConnectionCheck, FindingLevel};
use crate::config::onboarding::OnboardingStep;
use crate::tui::chrome::{self, ACCENT, DANGER, MUTED, SUCCESS, SURFACE, TEXT, WARNING};
use crate::tui::interaction::{FocusTarget, SemanticAction};
use crate::tui::state::AppState;
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Style, Stylize},
    text::{Line, Span, Text},
    widgets::{Paragraph, Wrap},
    Frame,
};

/// Quantas escolhas o passo atual oferece ao operador.
pub fn option_count(app: &AppState) -> usize {
    match app.onboarding_step() {
        Some(OnboardingStep::Environment) | Some(OnboardingStep::Credential) => 1,
        Some(OnboardingStep::Provider) => {
            crate::config::llm_config::LlmProviderKind::all_labels().len() + 1
        }
        Some(OnboardingStep::Consent) | Some(OnboardingStep::Connection) => 2,
        None => 1,
    }
}

pub fn render(app: &mut AppState, frame: &mut Frame, area: Rect) {
    let status = app
        .onboarding_error
        .clone()
        .or_else(|| app.onboarding.as_ref().map(|state| state.status()))
        .unwrap_or_default();
    let shell = chrome::render_shell(app, frame, area, "Primeira configuração", &status);
    let rows = Layout::vertical([
        Constraint::Length(2),
        Constraint::Min(1),
        Constraint::Length(2),
    ])
    .split(shell.content);
    render_intro(app, frame, rows[0]);
    match app.onboarding_step() {
        Some(OnboardingStep::Environment) => render_environment(app, frame, rows[1]),
        Some(OnboardingStep::Provider) => render_provider(app, frame, rows[1]),
        Some(OnboardingStep::Credential) => render_credential(app, frame, rows[1]),
        Some(OnboardingStep::Consent) => render_consent(app, frame, rows[1]),
        Some(OnboardingStep::Connection) => render_connection(app, frame, rows[1]),
        None => {}
    }
    render_actions(app, frame, rows[2]);
}

fn render_intro(app: &AppState, frame: &mut Frame, area: Rect) {
    let step = app.onboarding_step().unwrap_or(OnboardingStep::Environment);
    let title = format!(
        "Passo {}/{} · {}",
        step.number(),
        OnboardingStep::total(),
        step.label()
    );
    frame.render_widget(
        Paragraph::new(Text::from(vec![
            Line::styled(title, Style::default().fg(TEXT).bold()),
            Line::styled(
                step_hint(step),
                Style::default().fg(if app.onboarding_error.is_some() {
                    DANGER
                } else {
                    MUTED
                }),
            ),
        ]))
        .style(Style::default().bg(chrome::BACKGROUND)),
        area,
    );
}

fn step_hint(step: OnboardingStep) -> &'static str {
    match step {
        OnboardingStep::Environment => "Verificamos a máquina antes de perguntar qualquer coisa.",
        OnboardingStep::Provider => {
            "Escolha quem interpreta os logs: esta máquina ou um provedor remoto."
        }
        OnboardingStep::Credential => {
            "A chave é gravada no cofre do sistema e nunca no arquivo de configuração."
        }
        OnboardingStep::Consent => "Nada sai da máquina sem a sua autorização explícita (RNF10).",
        OnboardingStep::Connection => {
            "O teste é opcional: uma chamada mínima para confirmar credencial e endpoint."
        }
    }
}

fn render_environment(app: &mut AppState, frame: &mut Frame, area: Rect) {
    let block = chrome::panel("O que encontramos nesta máquina", true);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let Some(state) = app.onboarding.as_ref() else {
        return;
    };
    let Some(report) = state.environment.as_ref() else {
        frame.render_widget(
            Paragraph::new(" Verificando o ambiente…")
                .style(Style::default().fg(MUTED).bg(SURFACE)),
            inner,
        );
        return;
    };
    let mut lines = Vec::new();
    for finding in report.findings() {
        let color = match finding.level {
            FindingLevel::Info => SUCCESS,
            FindingLevel::Attention => WARNING,
            FindingLevel::Blocker => DANGER,
        };
        lines.push(Line::styled(
            format!("● {}", finding.title),
            Style::default().fg(color).bold(),
        ));
        lines.push(Line::styled(
            format!("   {}", finding.detail),
            Style::default().fg(MUTED),
        ));
    }
    let first_row = Paragraph::new(Text::from(lines.clone()))
        .wrap(Wrap { trim: false })
        .line_count(inner.width) as u16;
    lines.push(Line::from(""));
    lines.push(option_line(app, 0, "Continuar"));
    frame.render_widget(
        Paragraph::new(Text::from(lines))
            .style(Style::default().bg(SURFACE))
            .wrap(Wrap { trim: false }),
        inner,
    );
    register_list(app, inner, first_row + 1, 1);
}

fn render_provider(app: &mut AppState, frame: &mut Frame, area: Rect) {
    let block = chrome::panel("Provedor de IA", true);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let labels = crate::config::llm_config::LlmProviderKind::all_labels();
    let mut lines = Vec::new();
    for (index, label) in labels.iter().enumerate() {
        lines.push(option_line(app, index, label));
    }
    lines.push(Line::from(""));
    lines.push(option_line(app, labels.len(), "Continuar com esta escolha"));
    let continue_row = labels.len() as u16 + 1;
    lines.push(Line::from(""));
    if let Some(environment) = app
        .onboarding
        .as_ref()
        .and_then(|state| state.environment.clone())
    {
        match &environment.local_llm {
            Some(endpoint) => lines.push(Line::styled(
                format!("Detectado: {} em {}", endpoint.name, endpoint.base_url),
                Style::default().fg(SUCCESS),
            )),
            None => lines.push(Line::styled(
                "Nenhuma IA local foi detectada nesta máquina.",
                Style::default().fg(MUTED),
            )),
        }
    }
    frame.render_widget(
        Paragraph::new(Text::from(lines))
            .style(Style::default().bg(SURFACE))
            .wrap(Wrap { trim: false }),
        inner,
    );
    register_list(app, inner, 0, labels.len());
    register_option(app, inner, continue_row, labels.len());
}

fn render_credential(app: &mut AppState, frame: &mut Frame, area: Rect) {
    let block = chrome::panel("Credencial do provedor remoto", true);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let typed = app.settings_input_api_key.chars().count();
    let value = if typed == 0 {
        "Nenhuma chave digitada ainda".to_string()
    } else {
        format!("•••••••• {typed} caracteres")
    };
    let intro = vec![
        Line::styled(
            "A chave nunca é gravada no arquivo de configuração.",
            Style::default().fg(MUTED),
        ),
        Line::styled(format!("  {}  ▏", value), Style::default().fg(TEXT).bold()),
    ];
    let first_row = Paragraph::new(Text::from(intro.clone()))
        .wrap(Wrap { trim: false })
        .line_count(inner.width) as u16;
    let mut lines = intro;
    lines.push(Line::from(""));
    lines.push(option_line(app, 0, "Continuar"));
    frame.render_widget(
        Paragraph::new(Text::from(lines))
            .style(Style::default().bg(SURFACE))
            .wrap(Wrap { trim: false }),
        inner,
    );
    register_list(app, inner, first_row + 1, 1);
}

fn render_consent(app: &mut AppState, frame: &mut Frame, area: Rect) {
    let block = chrome::panel("Consentimento para IA remota", true);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let prompt = app
        .onboarding
        .as_ref()
        .map(|state| state.consent_prompt())
        .unwrap_or_default();
    let intro = vec![Line::styled(prompt, Style::default().fg(TEXT))];
    let first_row = Paragraph::new(Text::from(intro.clone()))
        .wrap(Wrap { trim: false })
        .line_count(inner.width) as u16;
    let mut lines = intro;
    lines.push(Line::from(""));
    lines.push(option_line(app, 0, "Aceitar e usar o provedor remoto"));
    lines.push(option_line(app, 1, "Recusar e usar o modelo local"));
    frame.render_widget(
        Paragraph::new(Text::from(lines))
            .style(Style::default().bg(SURFACE))
            .wrap(Wrap { trim: false }),
        inner,
    );
    register_list(app, inner, first_row + 1, 2);
}

fn render_connection(app: &mut AppState, frame: &mut Frame, area: Rect) {
    let block = chrome::panel("Teste de conexão", true);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let mut lines = Vec::new();
    if let Some(state) = app.onboarding.as_ref() {
        let (text, color) = match &state.connection {
            ConnectionCheck::NotRun => ("Teste ainda não executado.", MUTED),
            ConnectionCheck::Running => ("Chamando o provedor…", WARNING),
            ConnectionCheck::Succeeded(detail) => (detail.as_str(), SUCCESS),
            ConnectionCheck::Failed(detail) => (detail.as_str(), DANGER),
        };
        lines.push(Line::styled(
            format!("  {text}"),
            Style::default().fg(color),
        ));
    }
    let first_row = Paragraph::new(Text::from(lines.clone()))
        .wrap(Wrap { trim: false })
        .line_count(inner.width) as u16;
    lines.push(Line::from(""));
    lines.push(option_line(app, 0, "Testar a conexão agora"));
    lines.push(option_line(app, 1, "Concluir e salvar a configuração"));
    frame.render_widget(
        Paragraph::new(Text::from(lines))
            .style(Style::default().bg(SURFACE))
            .wrap(Wrap { trim: false }),
        inner,
    );
    register_list(app, inner, first_row + 1, 2);
}

fn option_line(app: &AppState, index: usize, label: &str) -> Line<'static> {
    let selected = app.onboarding_cursor == index;
    let focused = app.focus == FocusTarget::OnboardingList;
    let active = selected && focused;
    Line::from(vec![
        Span::styled(
            if selected { "› " } else { "  " },
            Style::default().fg(ACCENT),
        ),
        Span::styled(
            label.to_string(),
            Style::default()
                .fg(if active { Color::Black } else { TEXT })
                .bold(),
        ),
    ])
    .style(Style::default().bg(if active { ACCENT } else { SURFACE }))
}

/// Registra as escolhas a partir da linha em que começam.
///
/// `first_row` existe porque a lista de opções raramente ocupa a tela inteira:
/// sem ele, clicar num texto explicativo valeria como ativar a primeira opção.
fn register_list(app: &mut AppState, inner: Rect, first_row: u16, count: usize) {
    for offset in 0..count {
        register_option(app, inner, first_row + offset as u16, offset);
    }
}

fn register_option(app: &mut AppState, inner: Rect, row: u16, index: usize) {
    if row < inner.height {
        app.register_hit_region(
            Rect::new(inner.x, inner.y + row, inner.width, 1),
            SemanticAction::OnboardingActivate(index),
        );
    }
}

fn render_actions(app: &mut AppState, frame: &mut Frame, area: Rect) {
    let columns = Layout::horizontal([
        Constraint::Length(10),
        Constraint::Min(1),
        Constraint::Length(10),
        Constraint::Length(1),
        Constraint::Length(18),
    ])
    .split(area);
    let first_step = app.onboarding_step() == Some(OnboardingStep::Environment);
    chrome::render_button(
        app,
        frame,
        columns[0],
        "Voltar",
        SemanticAction::OnboardingBack,
        chrome::ButtonState::secondary(app.focus == FocusTarget::OnboardingList)
            .enabled(!first_step),
    );
    chrome::render_button(
        app,
        frame,
        columns[2],
        "Sair",
        SemanticAction::OnboardingQuit,
        chrome::ButtonState::secondary(false),
    );
    chrome::render_button(
        app,
        frame,
        columns[4],
        "Configurar IA",
        SemanticAction::OpenSettings,
        chrome::ButtonState::secondary(false),
    );
}
