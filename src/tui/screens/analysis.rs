use crate::tui::chrome::{self, ACCENT, MUTED, SUCCESS, SURFACE, TEXT};
use crate::tui::interaction::{FocusTarget, SemanticAction};
use crate::tui::state::{AnalysisPhase, AppState};
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Style, Stylize},
    text::{Line, Span, Text},
    widgets::{Gauge, Paragraph, Wrap},
    Frame,
};

pub fn render(app: &mut AppState, frame: &mut Frame, area: Rect) {
    let (label, ratio) = stage_state(app);
    let status = format!("IA em processamento · {label}");
    let shell = chrome::render_shell(app, frame, area, "Análise", &status);
    let rows = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(1),
        Constraint::Length(2),
    ])
    .split(shell.content);
    render_stage(app, frame, rows[0], &label, ratio);
    render_activity(app, frame, rows[1]);
    render_actions(app, frame, rows[2]);
}

/// Etapa real do pipeline e progresso mensurável.
///
/// O rótulo vem do estado observado pelo orquestrador (ferramentas concluídas,
/// achados construídos, chamada de IA em curso) e o medidor só é fechado em
/// `100` quando a etapa terminou de fato. Enquanto a IA trabalha não há
/// porcentagem a mostrar, porque o pipeline não produz uma: o medidor fica
/// indeterminado e a tela informa o tempo real decorrido.
fn stage_state(app: &AppState) -> (String, Option<f64>) {
    match app.analysis_phase {
        AnalysisPhase::Scanning => {
            let (done, total) = app.finished_tools();
            let ratio = (done as f64 / total.max(1) as f64).clamp(0.0, 1.0);
            (
                format!("varredura em andamento · {done}/{total} concluídas"),
                Some(ratio),
            )
        }
        AnalysisPhase::Correlating => (
            format!("{} achados em correlação", app.analysis_findings),
            None,
        ),
        AnalysisPhase::Generating => (
            format!("gerando orientações · {}s", app.analysis_wait_secs),
            None,
        ),
        AnalysisPhase::Complete => ("concluída".to_string(), Some(1.0)),
    }
}
fn render_stage(app: &AppState, frame: &mut Frame, area: Rect, label: &str, ratio: Option<f64>) {
    let block = chrome::panel("Progresso da análise", false);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let color = if app.analysis_phase == AnalysisPhase::Complete {
        SUCCESS
    } else {
        ACCENT
    };
    let caption = match ratio {
        Some(value) => format!("{label} · {:.0}%", value * 100.0),
        None => label.to_string(),
    };
    match ratio {
        Some(value) => frame.render_widget(
            Gauge::default()
                .gauge_style(Style::default().fg(color).bg(SURFACE))
                .ratio(value)
                .label(caption),
            inner,
        ),
        // Sem porcentagem inventada: enquanto a etapa não produz um valor
        // mensurável, a tela mostra o estado real e o tempo decorrido.
        None => frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(app.spinner_char(), Style::default().fg(color)),
                Span::styled(format!(" {caption}"), Style::default().fg(TEXT)),
            ]))
            .style(Style::default().bg(SURFACE)),
            inner,
        ),
    }
}

fn render_activity(app: &AppState, frame: &mut Frame, area: Rect) {
    let block = chrome::panel("Atividade", false);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let mut lines = vec![
        Line::from(vec![
            Span::styled(app.spinner_char(), Style::default().fg(ACCENT)),
            Span::styled(
                " As orientações da IA não alteram a severidade dos scanners",
                Style::default().fg(TEXT).bold(),
            ),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("modelo  ", Style::default().fg(MUTED)),
            Span::styled(&app.config.llm.model, Style::default().fg(TEXT)),
            Span::raw("   "),
            Span::styled("achados  ", Style::default().fg(MUTED)),
            Span::styled(app.analysis_findings.to_string(), Style::default().fg(TEXT)),
        ]),
        Line::from(vec![
            Span::styled("espera  ", Style::default().fg(MUTED)),
            Span::styled(
                format!("{}s", app.analysis_wait_secs),
                Style::default().fg(TEXT),
            ),
        ]),
    ];
    for issue in app
        .run_issues
        .iter()
        .filter(|issue| issue.scope.is_warning())
    {
        lines.push(Line::styled(
            chrome::truncate_width(&format!("IA: {}", issue.detail), inner.width as usize),
            Style::default().fg(MUTED),
        ));
    }
    frame.render_widget(
        Paragraph::new(Text::from(lines))
            .style(Style::default().bg(SURFACE))
            .wrap(Wrap { trim: false }),
        inner,
    );
}

fn render_actions(app: &mut AppState, frame: &mut Frame, area: Rect) {
    let columns = Layout::horizontal([Constraint::Min(1), Constraint::Length(12)]).split(area);
    let focused = app.focus == FocusTarget::AnalysisCancel;
    chrome::render_button(
        app,
        frame,
        columns[1],
        "Cancelar",
        SemanticAction::Back,
        chrome::ButtonState::secondary(focused),
    );
}
