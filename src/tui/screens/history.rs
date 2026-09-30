use crate::orchestrator::scan_logger::{ScanMetadata, ScanRecordSummary};
use crate::tui::chrome::{self, DANGER, MUTED, SUCCESS, SURFACE, TEXT, WARNING};
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

/// Quantidade de linhas usadas por execução na listagem do histórico.
const ROWS_PER_RECORD: usize = 2;

/// Concordância de número nos textos da tela de histórico.
fn plural(count: usize, singular: &str, plural: &str) -> String {
    if count == 1 {
        format!("{count} {singular}")
    } else {
        format!("{count} {plural}")
    }
}

pub fn render(app: &mut AppState, frame: &mut Frame, area: Rect) {
    let shell = chrome::render_shell(app, frame, area, "Histórico", &status(app));
    let rows = Layout::vertical([Constraint::Min(1), Constraint::Length(2)]).split(shell.content);
    if app.history_detail.is_some() {
        render_detail(app, frame, rows[0]);
    } else {
        render_list(app, frame, rows[0]);
    }
    render_actions(app, frame, rows[1]);
}

fn status(app: &AppState) -> String {
    if let Some(error) = &app.history_error {
        return format!(
            "Consulta ao histórico falhou · {}",
            chrome::truncate_width(error, 44)
        );
    }
    if app.history_detail.is_some() {
        return "Detalhe da execução · esc volta para a lista".to_string();
    }
    if app.history.is_empty() {
        return "Nenhuma execução registrada ainda".to_string();
    }
    let unreadable = app.history.unreadable.len();
    if unreadable == 0 {
        plural(
            app.history.records.len(),
            "execução no histórico",
            "execuções no histórico",
        )
    } else {
        format!(
            "{} · {}",
            plural(app.history.records.len(), "execução", "execuções"),
            plural(unreadable, "ilegível", "ilegíveis")
        )
    }
}

fn render_list(app: &mut AppState, frame: &mut Frame, area: Rect) {
    let focused = app.focus == FocusTarget::HistoryList;
    let block = chrome::panel("Execuções anteriores", focused);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if inner.width == 0 || inner.height == 0 {
        return;
    }

    if let Some(error) = &app.history_error {
        frame.render_widget(
            Paragraph::new(format!(" {}", error)).wrap(ratatui::widgets::Wrap { trim: false }),
            inner,
        );
        return;
    }

    if !app.history.directory_exists {
        frame.render_widget(
            Paragraph::new(
                " Nenhuma execução registrada.\n Execute uma análise para criar o histórico.",
            )
            .style(Style::default().fg(MUTED).bg(SURFACE)),
            inner,
        );
        return;
    }

    if app.history.records.is_empty() {
        frame.render_widget(
            Paragraph::new(" O histórico está vazio: nenhuma execução foi registrada.")
                .style(Style::default().fg(MUTED).bg(SURFACE)),
            inner,
        );
        return;
    }

    // Registros ilegíveis nunca somem: reservam a última linha da listagem.
    let warning_height = u16::from(!app.history.unreadable.is_empty());
    let viewport = Rect::new(
        inner.x,
        inner.y,
        inner.width,
        inner.height.saturating_sub(warning_height),
    );

    let visible_records = (viewport.height as usize / ROWS_PER_RECORD).max(1);
    app.history_cursor = app.history_cursor.min(app.history.records.len() - 1);
    ensure_history_visible(app, visible_records);

    let mut lines = Vec::new();
    for (row, index) in (app.history_scroll..app.history.records.len())
        .take(visible_records)
        .enumerate()
    {
        let current = index == app.history_cursor;
        let active = current && focused;
        lines.extend(record_lines(
            &app.history.records[index],
            current,
            active,
            viewport.width as usize,
        ));
        app.register_hit_region(
            Rect::new(
                viewport.x,
                viewport.y + (row * ROWS_PER_RECORD) as u16,
                viewport.width,
                ROWS_PER_RECORD as u16,
            ),
            SemanticAction::OpenHistoryRecord(index),
        );
    }
    frame.render_widget(
        Paragraph::new(Text::from(lines)).style(Style::default().bg(SURFACE)),
        viewport,
    );

    if !app.history.unreadable.is_empty() {
        let names: Vec<_> = app
            .history
            .unreadable
            .iter()
            .take(2)
            .map(|record| record.file_name.clone())
            .collect();
        frame.render_widget(
            Paragraph::new(chrome::truncate_width(
                &format!(
                    " {}: {}",
                    plural(
                        app.history.unreadable.len(),
                        "registro ilegível",
                        "registros ilegíveis"
                    ),
                    names.join(", ")
                ),
                inner.width as usize,
            ))
            .style(Style::default().fg(WARNING).bg(SURFACE)),
            Rect::new(
                inner.x,
                inner.y + inner.height.saturating_sub(1),
                inner.width,
                1,
            ),
        );
    }
}

/// Mantém a execução em foco dentro da janela visível da listagem.
fn ensure_history_visible(app: &mut AppState, visible_records: usize) {
    let visible = visible_records.max(1);
    if app.history_cursor < app.history_scroll {
        app.history_scroll = app.history_cursor;
    } else if app.history_cursor >= app.history_scroll.saturating_add(visible) {
        app.history_scroll = app.history_cursor.saturating_sub(visible - 1);
    }
}

fn record_lines(
    record: &ScanRecordSummary,
    current: bool,
    active: bool,
    width: usize,
) -> Vec<Line<'static>> {
    let background = if active { chrome::ACCENT } else { SURFACE };
    let foreground = if active { Color::Black } else { TEXT };
    let counts = &record.severity_counts;
    // Colunas fixas da segunda linha: 4 + alvo + 2 + "N ach." + 2 + "C0 A0 M0 B0 I0".
    let counts_width = 15;
    vec![
        Line::from(vec![
            Span::styled(if current { "> " } else { "  " }, Style::default().bold()),
            Span::styled(record.scan_id.clone(), Style::default().bold()),
            Span::styled(
                format!("  {}", record.completed_at),
                Style::default().fg(if active { Color::Black } else { MUTED }),
            ),
        ])
        .style(Style::default().fg(foreground).bg(background)),
        Line::from(vec![
            Span::styled("    ", Style::default()),
            Span::styled(
                chrome::truncate_width(
                    &record.target_url,
                    width.saturating_sub(counts_width + 14).max(8),
                ),
                Style::default().fg(if active { Color::Black } else { MUTED }),
            ),
            Span::styled(
                format!("  {} ach.", counts.total()),
                Style::default()
                    .fg(severity_color(counts.critical, active))
                    .bold(),
            ),
            Span::styled(
                format!(
                    "  C{} A{} M{} B{} I{}",
                    counts.critical, counts.high, counts.medium, counts.low, counts.info
                ),
                Style::default().fg(if active { Color::Black } else { MUTED }),
            ),
        ])
        .style(Style::default().fg(foreground).bg(background)),
    ]
}

fn severity_color(critical: usize, active: bool) -> Color {
    if active {
        Color::Black
    } else if critical > 0 {
        DANGER
    } else {
        SUCCESS
    }
}

fn render_detail(app: &mut AppState, frame: &mut Frame, area: Rect) {
    let focused = app.focus == FocusTarget::HistoryDetail;
    let block = chrome::panel("Detalhe da execução", focused);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let Some(metadata) = app.history_detail.as_ref() else {
        frame.render_widget(
            Paragraph::new(" Selecione uma execução para ver o detalhe.")
                .style(Style::default().fg(MUTED).bg(SURFACE)),
            inner,
        );
        return;
    };

    let width = inner.width.max(20) as usize;
    let mut lines = Vec::new();
    for line in detail_lines(metadata, width) {
        lines.push(line);
    }
    let has_scroll = lines.len() > inner.height as usize;
    let viewport = Rect::new(
        inner.x,
        inner.y,
        inner.width,
        inner.height.saturating_sub(u16::from(has_scroll)),
    );
    let visible = viewport.height.max(1) as usize;
    app.history_detail_max_scroll = lines.len().saturating_sub(visible);
    app.history_detail_scroll = app.history_detail_scroll.min(app.history_detail_max_scroll);
    let total = lines.len();
    let first = app.history_detail_scroll + 1;
    let last = (app.history_detail_scroll + visible).min(total);
    let visible_lines: Vec<_> = lines
        .into_iter()
        .skip(app.history_detail_scroll)
        .take(visible)
        .collect();
    frame.render_widget(
        Paragraph::new(Text::from(visible_lines)).style(Style::default().bg(SURFACE)),
        viewport,
    );
    if has_scroll {
        frame.render_widget(
            Paragraph::new(format!("↑↓ rolar · linhas {first}-{last} de {total}"))
                .alignment(ratatui::layout::Alignment::Right)
                .style(Style::default().fg(chrome::ACCENT).bg(SURFACE)),
            Rect::new(
                inner.x,
                inner.y + inner.height.saturating_sub(1),
                inner.width,
                1,
            ),
        );
    }
    app.register_hit_region(area, SemanticAction::SetFocus(FocusTarget::HistoryDetail));
}

fn detail_lines(metadata: &ScanMetadata, width: usize) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::from(vec![
            Span::styled(metadata.scan_id.clone(), Style::default().fg(TEXT).bold()),
            Span::styled(
                format!("  {}", metadata.execution_type),
                Style::default().fg(MUTED),
            ),
        ]),
        Line::styled(
            format!("alvo  {}", metadata.target_url),
            Style::default().fg(MUTED),
        ),
        Line::styled(
            format!(
                "conclusão  {}   início  {}",
                metadata.completed_at, metadata.started_at
            ),
            Style::default().fg(MUTED),
        ),
        Line::styled(
            format!("provedor IA  {}", metadata.llm_provider),
            Style::default().fg(MUTED),
        ),
    ];

    lines.push(Line::from(""));
    lines.push(Line::styled(
        "Ferramentas executadas",
        Style::default().fg(TEXT).bold(),
    ));
    if metadata.tools_executed.is_empty() {
        lines.push(Line::styled(
            "  nenhuma ferramenta registrada",
            Style::default().fg(MUTED),
        ));
    }
    for execution in &metadata.tools_executed {
        lines.push(Line::styled(
            format!(
                "  {:<12} {:<10} {} ms",
                execution.tool_name, execution.status, execution.duration_ms
            ),
            Style::default().fg(MUTED),
        ));
        if let Some(error) = &execution.execution_error {
            for wrapped in wrap_text(&format!("erro: {error}"), width.saturating_sub(4).max(10)) {
                lines.push(Line::styled(
                    format!("    {wrapped}"),
                    Style::default().fg(DANGER),
                ));
            }
        }
    }

    lines.push(Line::from(""));
    lines.push(Line::styled("Achados", Style::default().fg(TEXT).bold()));
    if metadata.findings.is_empty() {
        lines.push(Line::styled(
            "  nenhum achado registrado",
            Style::default().fg(MUTED),
        ));
    }
    for finding in &metadata.findings {
        let title = finding
            .get("title")
            .and_then(|value| value.as_str())
            .unwrap_or("(achado sem título)");
        let severity = crate::domain::Severity::from_label(
            finding
                .get("severity")
                .and_then(|value| value.as_str())
                .unwrap_or("Info"),
        )
        .label_pt_br();
        lines.push(Line::from(vec![
            Span::styled(format!("  {severity:<12}"), Style::default().fg(WARNING)),
            Span::styled(
                chrome::truncate_width(title, width.saturating_sub(14)),
                Style::default().fg(TEXT),
            ),
        ]));
    }

    lines.push(Line::from(""));
    lines.push(Line::styled(
        "Análise da IA",
        Style::default().fg(TEXT).bold(),
    ));
    if metadata.agent_analysis.trim().is_empty() {
        lines.push(Line::styled(
            "  sem análise registrada",
            Style::default().fg(MUTED),
        ));
    } else {
        for wrapped in wrap_text(&metadata.agent_analysis, width.saturating_sub(2)) {
            lines.push(Line::styled(
                format!("  {wrapped}"),
                Style::default().fg(MUTED),
            ));
        }
    }

    if !metadata.decisions.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::styled(
            format!("Decisões ({})", metadata.decisions.len()),
            Style::default().fg(TEXT).bold(),
        ));
        for decision in &metadata.decisions {
            lines.push(Line::styled(
                format!("  {} · {}", decision.model, decision.justification),
                Style::default().fg(MUTED),
            ));
        }
    }

    lines
}

fn render_actions(app: &mut AppState, frame: &mut Frame, area: Rect) {
    let columns = Layout::horizontal([
        Constraint::Length(10),
        Constraint::Min(1),
        Constraint::Length(10),
    ])
    .split(area);
    chrome::render_button(
        app,
        frame,
        columns[0],
        "Voltar",
        SemanticAction::Back,
        chrome::ButtonState::secondary(app.focus == FocusTarget::HistoryBack),
    );
    let has_selection = app.history_detail.is_some() || !app.history.records.is_empty();
    chrome::render_button(
        app,
        frame,
        columns[2],
        if app.history_detail.is_some() {
            "Voltar"
        } else {
            "Abrir"
        },
        if app.history_detail.is_some() {
            SemanticAction::Back
        } else {
            SemanticAction::OpenHistoryRecord(app.history_cursor)
        },
        chrome::ButtonState::primary(app.focus == FocusTarget::HistoryList).enabled(has_selection),
    );
}
