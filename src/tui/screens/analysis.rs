use crate::tui::chrome::{self, ACCENT, MUTED, SUCCESS, SURFACE, TEXT};
use crate::tui::interaction::{FocusTarget, SemanticAction};
use crate::tui::state::{AnalysisPhase, AppState};
use ratatui::{
    layout::{Alignment, Constraint, Layout, Rect},
    style::{Style, Stylize},
    text::{Line, Span, Text},
    widgets::{Gauge, Paragraph},
    Frame,
};

pub fn render(app: &mut AppState, frame: &mut Frame, area: Rect) {
    let (phase, percent) = phase_state(app.analysis_phase);
    let status = if app.analysis_phase == AnalysisPhase::Complete {
        "Análise concluída; abrindo resultados".to_string()
    } else {
        format!("IA em processamento · {phase}")
    };
    let shell = chrome::render_shell(app, frame, area, "Análise", &status);
    let rows = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(1),
        Constraint::Length(2),
    ])
    .split(shell.content);
    render_phase(app, frame, rows[0], phase, percent);
    render_output(app, frame, rows[1]);
    render_actions(app, frame, rows[2]);
}

fn render_phase(app: &AppState, frame: &mut Frame, area: Rect, phase: &str, percent: u16) {
    let block = chrome::panel("Progresso da análise", false);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let color = if app.analysis_phase == AnalysisPhase::Complete {
        SUCCESS
    } else {
        ACCENT
    };
    let gauge = Gauge::default()
        .gauge_style(Style::default().fg(color).bg(SURFACE))
        .percent(percent)
        .label(format!("{phase} · {percent}%"));
    frame.render_widget(gauge, inner);
}

fn render_output(app: &AppState, frame: &mut Frame, area: Rect) {
    let block = chrome::panel("Atividade", false);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let mut lines = vec![Line::from(vec![
        Span::styled(
            if app.analysis_phase == AnalysisPhase::Complete {
                "● "
            } else {
                app.spinner_char()
            },
            Style::default().fg(ACCENT),
        ),
        Span::styled(
            if app.analysis_phase == AnalysisPhase::Complete {
                "Correlação finalizada"
            } else {
                "Interpretando evidências e reduzindo falsos positivos"
            },
            Style::default().fg(TEXT).bold(),
        ),
    ])];
    lines.push(Line::from(""));
    for line in app
        .analysis_text
        .lines()
        .take(inner.height.saturating_sub(2) as usize)
    {
        lines.push(Line::styled(
            chrome::truncate_width(line, inner.width as usize),
            Style::default().fg(MUTED),
        ));
    }
    frame.render_widget(
        Paragraph::new(Text::from(lines)).style(Style::default().bg(SURFACE)),
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
        if app.analysis_phase == AnalysisPhase::Complete {
            "Voltar"
        } else {
            "Cancelar"
        },
        SemanticAction::Back,
        chrome::ButtonState::secondary(focused),
    );
    if app.analysis_phase == AnalysisPhase::Complete {
        frame.render_widget(
            Paragraph::new("Resultados prontos")
                .alignment(Alignment::Right)
                .style(Style::default().fg(SUCCESS)),
            columns[0],
        );
    }
}

fn phase_state(phase: AnalysisPhase) -> (&'static str, u16) {
    match phase {
        AnalysisPhase::Scanning => ("examinando resultados", 25),
        AnalysisPhase::Correlating => ("correlacionando achados", 55),
        AnalysisPhase::Generating => ("gerando recomendações", 85),
        AnalysisPhase::Complete => ("concluída", 100),
    }
}
