use crate::orchestrator::decision::DecisionSource;
use crate::tui::chrome::{self, ACCENT, DANGER, MUTED, SUCCESS, SURFACE, TEXT, WARNING};
use crate::tui::interaction::{FocusTarget, SemanticAction};
use crate::tui::state::{AiActivity, AppState, ToolStatus};
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Style, Stylize},
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
        format!(
            "Preparando análise da IA {} · {}s",
            app.spinner_char(),
            app.analysis_wait_secs
        )
    } else {
        format!("Executando varredura · {completed}/{total} concluídas · {percent}%")
    };
    let shell = chrome::render_shell(app, frame, area, "Execução", &status);
    let progress_height = (total as u16).saturating_add(2).clamp(3, 6);
    let rows = Layout::vertical([
        Constraint::Length(progress_height),
        Constraint::Length(4),
        Constraint::Min(3),
        Constraint::Length(2),
    ])
    .split(shell.content);
    render_progress(app, frame, rows[0], percent);
    render_ai_activity(app, frame, rows[1]);
    render_logs(app, frame, rows[2]);
    render_actions(app, frame, rows[3]);
}

fn render_ai_activity(app: &AppState, frame: &mut Frame, area: Rect) {
    let block = chrome::panel("Atuação da IA", false);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let (symbol, color, title, detail) = match app.ai_activity {
        AiActivity::WaitingForEvidence => (
            "○ ",
            MUTED,
            "Aguardando evidências do Nmap",
            format!("modelo configurado: {}", app.config.llm.model),
        ),
        AiActivity::PlanningNuclei => (
            app.spinner_char(),
            ACCENT,
            "IA definindo o plano do Nuclei",
            format!(
                "{} · perfis e limites serão validados pela política segura",
                app.config.llm.model
            ),
        ),
        AiActivity::PlanReady => {
            let decision = app.ai_decision.as_ref();
            let source = decision.map(|record| &record.source);
            let title = if source == Some(&DecisionSource::Ai) {
                "Plano da IA aceito pela política"
            } else {
                "Política local assumiu a decisão"
            };
            let color = if source == Some(&DecisionSource::Ai) {
                SUCCESS
            } else {
                WARNING
            };
            let detail = decision.map_or_else(
                || "parâmetros seguros aplicados ao Nuclei".to_string(),
                |record| {
                    format!(
                        "{} paralelos · timeout {}s · {}",
                        record
                            .parameters
                            .get("concurrency")
                            .map_or("?", String::as_str),
                        record
                            .parameters
                            .get("timeout_seconds")
                            .map_or("?", String::as_str),
                        record
                            .parameters
                            .get("templates")
                            .map_or("", String::as_str)
                    )
                },
            );
            ("● ", color, title, detail)
        }
        AiActivity::GeneratingGuidance => (
            app.spinner_char(),
            ACCENT,
            "IA gerando orientações de remediação",
            format!(
                "{} · {}s · severidades dos scanners permanecem imutáveis",
                app.config.llm.model, app.analysis_wait_secs
            ),
        ),
        AiActivity::Complete => (
            "● ",
            SUCCESS,
            "Orientações processadas",
            "resultado validado e pronto para auditoria".to_string(),
        ),
    };

    let detail = chrome::truncate_width(&detail, inner.width as usize);
    frame.render_widget(
        Paragraph::new(Text::from(vec![
            Line::from(vec![
                Span::styled(symbol, Style::default().fg(color).bold()),
                Span::styled(title, Style::default().fg(TEXT).bold()),
            ]),
            Line::styled(detail, Style::default().fg(MUTED)),
        ]))
        .style(Style::default().bg(SURFACE)),
        inner,
    );
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
    app.log_width = inner.width.max(1);
    if app.exec_logs.is_empty() {
        app.log_total_lines = 0;
        app.log_scroll = 0;
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
    let paragraph = Paragraph::new(Text::from(lines))
        .style(Style::default().bg(SURFACE))
        .wrap(Wrap { trim: false });
    app.log_total_lines = paragraph.line_count(inner.width);
    let max_scroll = app.log_max_scroll();
    app.log_scroll = if app.log_follow {
        max_scroll
    } else {
        app.log_scroll.min(max_scroll)
    };
    let scroll = app.log_scroll.min(u16::MAX as usize) as u16;
    frame.render_widget(paragraph.scroll((scroll, 0)), inner);
    app.register_hit_region(area, SemanticAction::SetFocus(FocusTarget::ExecutionLogs));
}

fn render_actions(app: &mut AppState, frame: &mut Frame, area: Rect) {
    let columns = Layout::horizontal([Constraint::Min(1), Constraint::Length(22)]).split(area);
    let cancel_focused = app.focus == FocusTarget::ExecutionCancel;
    frame.render_widget(
        Paragraph::new("↑↓ percorre os logs · esc também cancela")
            .style(Style::default().fg(MUTED)),
        columns[0],
    );
    chrome::render_button(
        app,
        frame,
        columns[1],
        "Cancelar varredura",
        SemanticAction::CancelRun,
        chrome::ButtonState::secondary(cancel_focused).enabled(!app.exec_cancelled),
    );
}
