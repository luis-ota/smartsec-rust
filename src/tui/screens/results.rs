use crate::domain::Severity;
use crate::tui::chrome::{self, ACCENT, DANGER, MUTED, SUCCESS, SURFACE, TEXT, WARNING};
use crate::tui::interaction::{FocusTarget, SemanticAction};
use crate::tui::state::AppState;
use crate::utils::helpers::wrap_text;
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Style, Stylize},
    text::{Line, Span, Text},
    widgets::Paragraph,
    Frame,
};

pub fn render(app: &mut AppState, frame: &mut Frame, area: Rect) {
    let vulnerabilities = app.vulnerabilities();
    let critical = vulnerabilities
        .iter()
        .filter(|item| item.severity == Severity::Critical)
        .count();
    let status = if let Some(error) = &app.run_error {
        format!(
            "Execução concluída com falhas · {}",
            chrome::truncate_width(error, 60)
        )
    } else if let Some(warning) = &app.llm_warning {
        format!(
            "Execução concluída com alternativa local · {}",
            chrome::truncate_width(warning, 50)
        )
    } else if app.md_exported {
        "Relatório Markdown exportado".to_string()
    } else if vulnerabilities.is_empty() {
        "Análise concluída sem vulnerabilidades".to_string()
    } else {
        format!("{} achados · {} críticos", vulnerabilities.len(), critical)
    };
    let title = if app.show_didactic {
        "Explicação didática"
    } else if app.result_detail_vuln.is_some() {
        "Detalhe do achado"
    } else {
        "Resultados"
    };
    let shell = chrome::render_shell(app, frame, area, title, &status);
    if app.show_didactic {
        render_didactic(app, frame, shell.content);
    } else if let Some(index) = app.result_detail_vuln {
        render_detail(app, frame, shell.content, index);
    } else {
        render_overview(app, frame, shell.content);
    }
}

fn render_overview(app: &mut AppState, frame: &mut Frame, area: Rect) {
    let rows = Layout::vertical([Constraint::Min(1), Constraint::Length(2)]).split(area);
    if rows[0].width < 120 {
        let stacked = Layout::vertical([Constraint::Length(6), Constraint::Min(1)]).split(rows[0]);
        render_summary(app, frame, stacked[0]);
        render_list(app, frame, stacked[1]);
    } else {
        let columns = Layout::horizontal([Constraint::Percentage(34), Constraint::Percentage(66)])
            .split(rows[0]);
        render_summary(app, frame, columns[0]);
        render_list(app, frame, columns[1]);
    }
    render_overview_actions(app, frame, rows[1]);
}

fn render_summary(app: &AppState, frame: &mut Frame, area: Rect) {
    let block = chrome::panel("Resumo", false);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let vulnerabilities = app.vulnerabilities();
    let counts = |severity| {
        vulnerabilities
            .iter()
            .filter(|item| item.severity == severity)
            .count()
    };
    let critical = counts(Severity::Critical);
    let high = counts(Severity::High);
    let medium = counts(Severity::Medium);
    let low = counts(Severity::Low);
    let info = counts(Severity::Info);
    let lines = if let Some(error) = &app.run_error {
        vec![
            Line::styled(
                chrome::truncate_width(error, inner.width as usize),
                Style::default().fg(DANGER).bold(),
            ),
            Line::from(vec![
                metric("críticas", critical, DANGER),
                Span::raw("   "),
                metric("altas", high, Color::Rgb(220, 130, 90)),
                Span::raw("   "),
                metric("médias", medium, WARNING),
            ]),
            Line::from(vec![
                metric("baixas", low, ACCENT),
                Span::raw("   "),
                metric("informativas", info, MUTED),
            ]),
            Line::styled(
                app.audit_log_path.as_ref().map_or_else(
                    || "Log de auditoria indisponível".to_string(),
                    |path| format!("Auditoria: {}", path.display()),
                ),
                Style::default().fg(MUTED),
            ),
        ]
    } else if vulnerabilities.is_empty() {
        vec![
            Line::styled(
                "Nenhum achado identificado.",
                Style::default().fg(SUCCESS).bold(),
            ),
            Line::styled(
                "Exporte o relatório ou inicie uma nova análise.",
                Style::default().fg(MUTED),
            ),
        ]
    } else {
        vec![
            Line::from(vec![
                metric("críticas", critical, DANGER),
                Span::raw("   "),
                metric("altas", high, Color::Rgb(220, 130, 90)),
                Span::raw("   "),
                metric("médias", medium, WARNING),
            ]),
            Line::from(vec![
                metric("baixas", low, ACCENT),
                Span::raw("   "),
                metric("informativas", info, MUTED),
            ]),
            Line::from(vec![
                Span::styled("alvo  ", Style::default().fg(MUTED)),
                Span::styled(
                    chrome::truncate_width(
                        &app.config.target_url,
                        (inner.width as usize).saturating_sub(7),
                    ),
                    Style::default().fg(TEXT),
                ),
            ]),
            Line::styled(
                app.audit_log_path.as_ref().map_or_else(
                    || "auditoria  aguardando persistência".to_string(),
                    |path| format!("auditoria  {}", path.display()),
                ),
                Style::default().fg(MUTED),
            ),
        ]
    };
    frame.render_widget(
        Paragraph::new(Text::from(lines)).style(Style::default().bg(SURFACE)),
        inner,
    );
}

fn metric(label: &str, value: usize, color: Color) -> Span<'_> {
    Span::styled(
        format!("{value} {label}"),
        Style::default().fg(color).bold(),
    )
}

fn render_list(app: &mut AppState, frame: &mut Frame, area: Rect) {
    let focused = app.focus == FocusTarget::ResultsList;
    let block = chrome::panel("Achados", focused);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if inner.width == 0 || inner.height == 0 {
        return;
    }
    let vulnerabilities = app.vulnerabilities();
    if vulnerabilities.is_empty() {
        app.result_cursor = 0;
        app.result_scroll = 0;
        frame.render_widget(
            Paragraph::new("Nenhuma vulnerabilidade para revisar.")
                .style(Style::default().fg(MUTED).bg(SURFACE)),
            inner,
        );
        return;
    }
    let visible = inner.height as usize;
    app.result_cursor = app.result_cursor.min(vulnerabilities.len() - 1);
    let max_scroll = vulnerabilities.len().saturating_sub(visible);
    app.result_scroll = app.result_scroll.min(max_scroll);
    if app.result_cursor < app.result_scroll {
        app.result_scroll = app.result_cursor;
    } else if app.result_cursor >= app.result_scroll.saturating_add(visible) {
        app.result_scroll = app.result_cursor.saturating_sub(visible - 1);
    }

    let mut lines = Vec::new();
    for row in 0..visible.min(vulnerabilities.len().saturating_sub(app.result_scroll)) {
        let index = app.result_scroll + row;
        let item = &vulnerabilities[index];
        let current = index == app.result_cursor;
        let active = current && focused;
        lines.push(
            Line::from(vec![
                Span::styled(if current { "> " } else { "  " }, Style::default().bold()),
                Span::styled(
                    format!("{:<8}", severity_label(item.severity)),
                    Style::default().bold(),
                ),
                Span::styled(
                    chrome::truncate_width(&item.title, inner.width.saturating_sub(12) as usize),
                    Style::default(),
                ),
            ])
            .style(
                Style::default()
                    .fg(if active {
                        Color::Black
                    } else {
                        severity_color(item.severity)
                    })
                    .bg(if active { ACCENT } else { SURFACE }),
            ),
        );
        app.register_hit_region(
            Rect::new(inner.x, inner.y + row as u16, inner.width, 1),
            SemanticAction::OpenVulnerability(index),
        );
    }
    frame.render_widget(
        Paragraph::new(Text::from(lines)).style(Style::default().bg(SURFACE)),
        inner,
    );
}

fn render_overview_actions(app: &mut AppState, frame: &mut Frame, area: Rect) {
    let columns = Layout::horizontal([
        Constraint::Length(13),
        Constraint::Min(1),
        Constraint::Length(12),
        Constraint::Length(1),
        Constraint::Length(12),
    ])
    .split(area);
    let new_focused = app.focus == FocusTarget::ResultsNewScan;
    let export_focused = app.focus == FocusTarget::ResultsExport;
    let didactic_focused = app.focus == FocusTarget::ResultsDidactic;
    chrome::render_button(
        app,
        frame,
        columns[0],
        "Nova análise",
        SemanticAction::NewScan,
        chrome::ButtonState::secondary(new_focused),
    );
    chrome::render_button(
        app,
        frame,
        columns[2],
        if app.md_exported {
            "Exportado"
        } else {
            "Exportar"
        },
        SemanticAction::ExportMarkdown,
        chrome::ButtonState::primary(export_focused),
    );
    chrome::render_button(
        app,
        frame,
        columns[4],
        "Explicação",
        SemanticAction::ShowDidactic,
        chrome::ButtonState::secondary(didactic_focused),
    );
}

fn render_detail(app: &mut AppState, frame: &mut Frame, area: Rect, index: usize) {
    let rows = Layout::vertical([Constraint::Min(1), Constraint::Length(2)]).split(area);
    let focused = app.focus == FocusTarget::ResultsDetail;
    let block = chrome::panel("Evidência e recomendação", focused);
    let inner = block.inner(rows[0]);
    frame.render_widget(block, rows[0]);
    let vulnerabilities = app.vulnerabilities();
    if let Some(item) = vulnerabilities.get(index) {
        let mut lines = vec![
            Line::from(vec![
                Span::styled(
                    format!("{}  ", severity_label(item.severity)),
                    Style::default().fg(severity_color(item.severity)).bold(),
                ),
                Span::styled(&item.title, Style::default().fg(TEXT).bold()),
            ]),
            Line::styled(
                format!("ferramenta  {}", item.tool),
                Style::default().fg(MUTED),
            ),
            Line::from(""),
            Line::styled("Descrição", Style::default().fg(TEXT).bold()),
        ];
        append_wrapped(&mut lines, &item.description, inner.width as usize, MUTED);
        lines.push(Line::from(""));
        lines.push(Line::styled(
            "Recomendação",
            Style::default().fg(TEXT).bold(),
        ));
        append_wrapped(
            &mut lines,
            &item.recommendation,
            inner.width as usize,
            SUCCESS,
        );
        let has_scroll = lines.len() > inner.height as usize;
        let indicator_height = u16::from(has_scroll);
        let viewport = Rect::new(
            inner.x,
            inner.y,
            inner.width,
            inner.height.saturating_sub(indicator_height),
        );
        let visible = viewport.height.max(1) as usize;
        app.detail_max_scroll = lines.len().saturating_sub(visible);
        app.detail_scroll = app.detail_scroll.min(app.detail_max_scroll);
        let total = lines.len();
        let visible_lines: Vec<_> = lines
            .into_iter()
            .skip(app.detail_scroll)
            .take(visible)
            .collect();
        frame.render_widget(
            Paragraph::new(Text::from(visible_lines)).style(Style::default().bg(SURFACE)),
            viewport,
        );
        if has_scroll {
            let first = app.detail_scroll + 1;
            let last = (app.detail_scroll + visible).min(total);
            frame.render_widget(
                Paragraph::new(format!("↑↓ rolar · linhas {first}-{last} de {total}"))
                    .alignment(ratatui::layout::Alignment::Right)
                    .style(Style::default().fg(ACCENT).bg(SURFACE)),
                Rect::new(
                    inner.x,
                    inner.y + inner.height.saturating_sub(1),
                    inner.width,
                    1,
                ),
            );
        }
    } else {
        app.detail_scroll = 0;
        app.detail_max_scroll = 0;
        frame.render_widget(
            Paragraph::new("O achado selecionado não está mais disponível.")
                .style(Style::default().fg(DANGER).bg(SURFACE)),
            inner,
        );
    }
    app.register_hit_region(
        rows[0],
        SemanticAction::SetFocus(FocusTarget::ResultsDetail),
    );
    let actions = Layout::horizontal([
        Constraint::Length(10),
        Constraint::Min(1),
        Constraint::Length(13),
    ])
    .split(rows[1]);
    chrome::render_button(
        app,
        frame,
        actions[0],
        "Voltar",
        SemanticAction::Back,
        chrome::ButtonState::secondary(app.focus == FocusTarget::ResultsBack),
    );
    chrome::render_button(
        app,
        frame,
        actions[2],
        "Explicação",
        SemanticAction::ShowDidactic,
        chrome::ButtonState::primary(app.focus == FocusTarget::ResultsDidactic),
    );
}

fn render_didactic(app: &mut AppState, frame: &mut Frame, area: Rect) {
    let rows = Layout::vertical([Constraint::Min(1), Constraint::Length(2)]).split(area);
    let focused = app.focus == FocusTarget::DidacticContent;
    let block = chrome::panel("Em linguagem direta", focused);
    let inner = block.inner(rows[0]);
    frame.render_widget(block, rows[0]);
    let vulnerabilities = app.vulnerabilities();
    let mut lines = Vec::new();
    if let Some(index) = app.result_detail_vuln {
        if let Some(item) = vulnerabilities.get(index) {
            lines.push(Line::styled(&item.title, Style::default().fg(TEXT).bold()));
            lines.push(Line::from(""));
            append_wrapped(&mut lines, &item.didactic, inner.width as usize, MUTED);
        }
    } else if vulnerabilities.is_empty() {
        lines.push(Line::styled(
            "Não há achados que precisem de explicação.",
            Style::default().fg(SUCCESS),
        ));
    } else {
        for item in &vulnerabilities {
            lines.push(Line::styled(&item.title, Style::default().fg(TEXT).bold()));
            append_wrapped(&mut lines, &item.didactic, inner.width as usize, MUTED);
            lines.push(Line::from(""));
        }
    }
    let visible = inner.height.max(1) as usize;
    app.didactic_max_scroll = lines.len().saturating_sub(visible);
    app.didactic_scroll = app.didactic_scroll.min(app.didactic_max_scroll);
    let visible_lines: Vec<_> = lines
        .into_iter()
        .skip(app.didactic_scroll)
        .take(visible)
        .collect();
    frame.render_widget(
        Paragraph::new(Text::from(visible_lines)).style(Style::default().bg(SURFACE)),
        inner,
    );
    app.register_hit_region(
        rows[0],
        SemanticAction::SetFocus(FocusTarget::DidacticContent),
    );
    let actions = Layout::horizontal([Constraint::Length(10), Constraint::Min(1)]).split(rows[1]);
    chrome::render_button(
        app,
        frame,
        actions[0],
        "Voltar",
        SemanticAction::Back,
        chrome::ButtonState::secondary(app.focus == FocusTarget::DidacticBack),
    );
}

fn append_wrapped<'a>(lines: &mut Vec<Line<'a>>, value: &'a str, width: usize, color: Color) {
    for paragraph in value.split("\n\n") {
        for line in wrap_text(paragraph, width.max(1)) {
            lines.push(Line::styled(line, Style::default().fg(color)));
        }
    }
}

fn severity_label(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "CRÍTICA",
        Severity::High => "ALTA",
        Severity::Medium => "MÉDIA",
        Severity::Low => "BAIXA",
        Severity::Info => "INFO",
    }
}

fn severity_color(severity: Severity) -> Color {
    match severity {
        Severity::Critical => DANGER,
        Severity::High => Color::Rgb(220, 130, 90),
        Severity::Medium => WARNING,
        Severity::Low => ACCENT,
        Severity::Info => MUTED,
    }
}
