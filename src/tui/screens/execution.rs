use crate::tui::chrome::{self, ACCENT, DANGER, MUTED, SUCCESS, SURFACE, TEXT, WARNING};
use crate::tui::interaction::{FocusTarget, SemanticAction};
use crate::tui::state::{AppState, ToolStatus};
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::Style,
    text::{Line, Span, Text},
    widgets::Paragraph,
    Frame,
};

pub fn render(app: &mut AppState, frame: &mut Frame, area: Rect) {
    let done = app
        .tools
        .iter()
        .filter(|tool| tool.selected && tool.status == ToolStatus::Done)
        .count();
    let total = app.tools.iter().filter(|tool| tool.selected).count();
    let status = if app.exec_cancelled {
        "Execução cancelada; retornando às ferramentas".to_string()
    } else if app.exec_paused {
        format!("Execução pausada · {done}/{total} concluídas")
    } else if total > 0 && done == total {
        "Varredura concluída; preparando análise".to_string()
    } else {
        format!("Executando varredura · {done}/{total} concluídas")
    };
    let shell = chrome::render_shell(app, frame, area, "Execução", &status);
    let rows = Layout::vertical([Constraint::Min(1), Constraint::Length(2)]).split(shell.content);
    if rows[0].width < 100 {
        let stacked = Layout::vertical([Constraint::Length(8), Constraint::Min(1)]).split(rows[0]);
        render_progress(app, frame, stacked[0]);
        render_logs(app, frame, stacked[1]);
    } else {
        let columns = Layout::horizontal([Constraint::Percentage(42), Constraint::Percentage(58)])
            .split(rows[0]);
        render_progress(app, frame, columns[0]);
        render_logs(app, frame, columns[1]);
    }
    render_actions(app, frame, rows[1]);
}

fn render_progress(app: &AppState, frame: &mut Frame, area: Rect) {
    let block = chrome::panel("Progresso", false);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let selected: Vec<_> = app.tools.iter().filter(|tool| tool.selected).collect();
    if selected.is_empty() {
        frame.render_widget(
            Paragraph::new("Nenhuma ferramenta selecionada.")
                .style(Style::default().fg(MUTED).bg(SURFACE)),
            inner,
        );
        return;
    }
    let max_visible = inner.height as usize;
    let current = selected
        .iter()
        .position(|tool| tool.status == ToolStatus::Running)
        .unwrap_or_else(|| selected.len().saturating_sub(1).min(app.exec_current));
    let start = current
        .saturating_sub(max_visible.saturating_sub(1))
        .min(selected.len().saturating_sub(max_visible));
    let lines: Vec<_> = selected
        .iter()
        .skip(start)
        .take(max_visible)
        .map(|tool| {
            let (symbol, color) = match tool.status {
                ToolStatus::Pending => ("○", MUTED),
                ToolStatus::Running => (app.spinner_char(), ACCENT),
                ToolStatus::Done => ("●", SUCCESS),
                ToolStatus::Failed => ("×", DANGER),
            };
            Line::from(vec![
                Span::styled(format!("{symbol} "), Style::default().fg(color)),
                Span::styled(format!("{:<12}", tool.tool.name), Style::default().fg(TEXT)),
                Span::styled(format!("{:>3}%", tool.progress), Style::default().fg(color)),
            ])
        })
        .collect();
    frame.render_widget(
        Paragraph::new(Text::from(lines)).style(Style::default().bg(SURFACE)),
        inner,
    );
}

fn render_logs(app: &mut AppState, frame: &mut Frame, area: Rect) {
    let focused = app.focus == FocusTarget::ExecutionLogs;
    let block = chrome::panel("Log de saída", focused);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    app.log_visible_height = inner.height.max(1) as usize;
    app.log_scroll = app
        .log_scroll
        .min(app.exec_logs.len().saturating_sub(app.log_visible_height));
    if app.exec_logs.is_empty() {
        let message = if app.exec_paused {
            "Execução pausada antes de produzir saída."
        } else {
            "Aguardando a primeira saída da varredura..."
        };
        frame.render_widget(
            Paragraph::new(message).style(Style::default().fg(MUTED).bg(SURFACE)),
            inner,
        );
        return;
    }
    let lines: Vec<_> = app
        .exec_logs
        .iter()
        .skip(app.log_scroll)
        .take(app.log_visible_height)
        .map(|log| {
            let color = if log.contains("FALHA") || log.contains("CANCELADA") {
                DANGER
            } else if log.contains("OK") {
                SUCCESS
            } else if log.contains("PAUSADA") {
                WARNING
            } else {
                MUTED
            };
            Line::styled(
                chrome::truncate_width(log, inner.width as usize),
                Style::default().fg(color),
            )
        })
        .collect();
    frame.render_widget(
        Paragraph::new(Text::from(lines)).style(Style::default().bg(SURFACE)),
        inner,
    );
    app.register_hit_region(area, SemanticAction::SetFocus(FocusTarget::ExecutionLogs));
}

fn render_actions(app: &mut AppState, frame: &mut Frame, area: Rect) {
    let columns = Layout::horizontal([
        Constraint::Length(10),
        Constraint::Min(1),
        Constraint::Length(10),
        Constraint::Length(1),
        Constraint::Length(11),
    ])
    .split(area);
    let back_focused = app.focus == FocusTarget::ExecutionBack;
    let pause_focused = app.focus == FocusTarget::ExecutionPause;
    let cancel_focused = app.focus == FocusTarget::ExecutionCancel;
    chrome::render_button(
        app,
        frame,
        columns[0],
        "Voltar",
        SemanticAction::Back,
        chrome::ButtonState::secondary(back_focused),
    );
    chrome::render_button(
        app,
        frame,
        columns[2],
        if app.exec_paused { "Retomar" } else { "Pausar" },
        SemanticAction::PauseResume,
        if app.exec_paused {
            chrome::ButtonState::primary(pause_focused)
        } else {
            chrome::ButtonState::secondary(pause_focused)
        }
        .enabled(!app.exec_cancelled),
    );
    chrome::render_button(
        app,
        frame,
        columns[4],
        "Cancelar",
        SemanticAction::CancelRun,
        chrome::ButtonState::secondary(cancel_focused).enabled(!app.exec_cancelled),
    );
}
