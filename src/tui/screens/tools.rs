use crate::tui::chrome::{self, ACCENT, DANGER, MUTED, SUCCESS, SURFACE, TEXT};
use crate::tui::interaction::{FocusTarget, SemanticAction};
use crate::tui::state::{AppState, ToolStatus};
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Style, Stylize},
    text::{Line, Span, Text},
    widgets::Paragraph,
    Frame,
};

pub fn render(app: &mut AppState, frame: &mut Frame, area: Rect) {
    let selected = app.tools.iter().filter(|tool| tool.selected).count();
    let status = if app.tool_detecting {
        "Detectando ferramentas compatíveis...".to_string()
    } else if app.tools.is_empty() {
        "Nenhuma ferramenta disponível".to_string()
    } else {
        format!("{selected} de {} ferramentas selecionadas", app.tools.len())
    };
    let shell = chrome::render_shell(app, frame, area, "Ferramentas", &status);
    let rows = Layout::vertical([Constraint::Min(1), Constraint::Length(2)]).split(shell.content);
    if rows[0].width < 100 {
        let stacked = Layout::vertical([Constraint::Percentage(58), Constraint::Percentage(42)])
            .split(rows[0]);
        render_tool_list(app, frame, stacked[0]);
        render_tool_detail(app, frame, stacked[1]);
    } else {
        let columns = Layout::horizontal([Constraint::Percentage(58), Constraint::Percentage(42)])
            .split(rows[0]);
        render_tool_list(app, frame, columns[0]);
        render_tool_detail(app, frame, columns[1]);
    }
    render_actions(app, frame, rows[1]);
}

fn render_tool_list(app: &mut AppState, frame: &mut Frame, area: Rect) {
    let focused = app.focus == FocusTarget::ToolList;
    let block = chrome::panel("Ferramentas de segurança", focused);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    app.tool_visible_height = inner.height.max(1) as usize;

    if app.tool_detecting {
        frame.render_widget(
            Paragraph::new(format!(
                " {} Verificando catálogo e disponibilidade...",
                app.spinner_char()
            ))
            .style(Style::default().fg(ACCENT).bg(SURFACE)),
            inner,
        );
        return;
    }
    if app.tools.is_empty() {
        frame.render_widget(
            Paragraph::new(" Nenhuma ferramenta foi encontrada. Volte e revise a configuração.")
                .style(Style::default().fg(MUTED).bg(SURFACE)),
            inner,
        );
        return;
    }

    let mut lines = Vec::new();
    let visible = inner
        .height
        .min(app.tools.len().saturating_sub(app.tool_scroll) as u16);
    for row in 0..visible {
        let index = app.tool_scroll + row as usize;
        let line = {
            let tool = &app.tools[index];
            let current = index == app.tool_cursor;
            let active = focused && current;
            let state = if tool.selected { "[x]" } else { "[ ]" };
            let prefix = if current { ">" } else { " " };
            Line::from(vec![
                Span::styled(format!("{prefix} {state} "), Style::default()),
                Span::styled(format!("{:<12}", tool.tool.name), Style::default().bold()),
                Span::styled(tool.tool.category, Style::default()),
            ])
            .style(
                Style::default()
                    .fg(if active { Color::Black } else { TEXT })
                    .bg(if active { ACCENT } else { SURFACE }),
            )
        };
        lines.push(line);
        app.register_hit_region(
            Rect::new(inner.x, inner.y + row, inner.width, 1),
            SemanticAction::ToggleTool(index),
        );
    }
    frame.render_widget(
        Paragraph::new(Text::from(lines)).style(Style::default().bg(SURFACE)),
        inner,
    );
}

fn render_tool_detail(app: &AppState, frame: &mut Frame, area: Rect) {
    let block = chrome::panel("Contexto", false);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let Some(tool) = app.tools.get(app.tool_cursor) else {
        frame.render_widget(
            Paragraph::new("Selecione uma ferramenta para ver os detalhes.")
                .style(Style::default().fg(MUTED).bg(SURFACE)),
            inner,
        );
        return;
    };
    let (status, color) = match tool.status {
        ToolStatus::Pending => ("pendente", MUTED),
        ToolStatus::Running => ("em execução", ACCENT),
        ToolStatus::Done => ("concluída", SUCCESS),
        ToolStatus::Failed => ("falhou", DANGER),
    };
    let lines = vec![
        Line::styled(tool.tool.name, Style::default().fg(TEXT).bold()),
        Line::styled(tool.tool.description, Style::default().fg(MUTED)),
        Line::from(""),
        Line::from(vec![
            Span::styled("estado  ", Style::default().fg(MUTED)),
            Span::styled(status, Style::default().fg(color).bold()),
        ]),
    ];
    frame.render_widget(
        Paragraph::new(Text::from(lines)).style(Style::default().bg(SURFACE)),
        inner,
    );
}

fn render_actions(app: &mut AppState, frame: &mut Frame, area: Rect) {
    let columns = Layout::horizontal([
        Constraint::Length(10),
        Constraint::Min(1),
        Constraint::Length(12),
    ])
    .split(area);
    chrome::render_button(
        app,
        frame,
        columns[0],
        "Voltar",
        SemanticAction::Back,
        chrome::ButtonState::secondary(app.focus == FocusTarget::ToolBack),
    );
    chrome::render_button(
        app,
        frame,
        columns[2],
        "Executar",
        SemanticAction::RunTools,
        chrome::ButtonState::primary(app.focus == FocusTarget::ToolRun)
            .enabled(!app.tool_detecting && app.tools.iter().any(|tool| tool.selected)),
    );
}
