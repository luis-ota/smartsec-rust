use crate::tui::chrome::{self, ACCENT, DANGER, MUTED, SUCCESS, SURFACE, TEXT};
use crate::tui::interaction::{FocusTarget, SemanticAction};
use crate::tui::state::{AppState, ToolStatus};
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::Style,
    text::{Line, Span, Text},
    widgets::{Paragraph, Wrap},
    Frame,
};

pub fn render(app: &mut AppState, frame: &mut Frame, area: Rect) {
    let completed = app
        .tools
        .iter()
        .filter(|tool| {
            tool.selected && matches!(tool.status, ToolStatus::Done | ToolStatus::Failed)
        })
        .count();
    let total = app.tools.iter().filter(|tool| tool.selected).count();
    let percent = completed
        .saturating_mul(100)
        .checked_div(total)
        .unwrap_or(0) as u16;
    let status = if app.exec_cancelled {
        "Execução cancelada; retornando às ferramentas".to_string()
    } else if total > 0 && completed == total {
        "Varredura concluída; preparando análise".to_string()
    } else {
        format!("Executando varredura · {completed}/{total} concluídas · {percent}%")
    };
    let shell = chrome::render_shell(app, frame, area, "Execução", &status);
    let progress_height = (total as u16).saturating_add(2).clamp(3, 6);
    let rows = Layout::vertical([
        Constraint::Length(progress_height),
        Constraint::Min(3),
        Constraint::Length(2),
    ])
    .split(shell.content);
    render_progress(app, frame, rows[0], percent);
    render_logs(app, frame, rows[1]);
    render_actions(app, frame, rows[2]);
}

fn render_progress(app: &AppState, frame: &mut Frame, area: Rect, percent: u16) {
    let title = format!("Progresso geral · {percent}%");
    let block = chrome::panel(&title, false);
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
            let (symbol, color, status) = match tool.status {
                ToolStatus::Pending => ("○", MUTED, "aguardando"),
                ToolStatus::Running => (app.spinner_char(), ACCENT, "executando"),
                ToolStatus::Done => ("●", SUCCESS, "concluída"),
                ToolStatus::Failed => ("×", DANGER, "falhou"),
            };
            Line::from(vec![
                Span::styled(format!("{symbol} "), Style::default().fg(color)),
                Span::styled(format!("{:<12}", tool.tool.name), Style::default().fg(TEXT)),
                Span::styled(status, Style::default().fg(color)),
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
        let message = "Aguardando a primeira saída da varredura...";
        frame.render_widget(
            Paragraph::new(message).style(Style::default().fg(MUTED).bg(SURFACE)),
            inner,
        );
        return;
    }
    let lines: Vec<_> = app
        .exec_logs
        .iter()
        .map(|log| {
            let color = if log.contains("FALHA")
                || log.contains("CANCELADA")
                || log.contains("falhou")
                || log.contains("interrompido")
            {
                DANGER
            } else if log.contains("OK")
                || log.contains("concluído")
                || log.contains("criado")
                || log.contains("removido")
                || log.contains("verificado")
                || log.contains("[auditoria] Log salvo")
            {
                SUCCESS
            } else if log.contains("] $ ") {
                TEXT
            } else {
                MUTED
            };
            Line::styled(log.as_str(), Style::default().fg(color))
        })
        .collect();
    frame.render_widget(
        Paragraph::new(Text::from(lines))
            .style(Style::default().bg(SURFACE))
            .wrap(Wrap { trim: false })
            .scroll((app.log_scroll as u16, 0)),
        inner,
    );
    app.register_hit_region(area, SemanticAction::SetFocus(FocusTarget::ExecutionLogs));
}

fn render_actions(app: &mut AppState, frame: &mut Frame, area: Rect) {
    let columns = Layout::horizontal([
        Constraint::Length(10),
        Constraint::Min(1),
        Constraint::Length(11),
    ])
    .split(area);
    let back_focused = app.focus == FocusTarget::ExecutionBack;
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
        "Cancelar",
        SemanticAction::CancelRun,
        chrome::ButtonState::secondary(cancel_focused).enabled(!app.exec_cancelled),
    );
}
