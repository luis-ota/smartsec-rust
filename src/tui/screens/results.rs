use crate::config::execution_type::ExecutionType;
use crate::domain::Severity;
use crate::tui::interaction::SemanticAction;
use crate::tui::state::AppState;
use crate::utils::helpers::wrap_text;
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Style, Stylize},
    text::{Line, Span, Text},
    widgets::{Block, BorderType, Borders, Clear, Paragraph, Wrap},
    Frame,
};

pub fn render(app: &mut AppState, frame: &mut Frame, area: Rect) {
    let bg = Block::default().style(Style::default().bg(Color::Rgb(8, 8, 16)));
    frame.render_widget(bg, area);

    if app.show_didactic {
        render_didactic(app, frame, area);
        return;
    }
    if app.show_detail {
        render_detail(app, frame, area);
        return;
    }

    let chunks = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(3),
        Constraint::Length(3),
    ])
    .split(area);
    render_header(app, frame, chunks[0]);
    render_body(app, frame, chunks[1]);
    render_footer(app, frame, chunks[2]);
}

fn render_header(app: &AppState, frame: &mut Frame, area: Rect) {
    let block = Block::default()
        .borders(Borders::BOTTOM)
        .border_style(Style::default().fg(Color::DarkGray))
        .style(Style::default().bg(Color::Rgb(20, 20, 40)));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let vulns = app.vulnerabilities();
    let crit = vulns
        .iter()
        .filter(|v| v.severity == Severity::Critical)
        .count();
    let high = vulns
        .iter()
        .filter(|v| v.severity == Severity::High)
        .count();
    let header = Paragraph::new(Line::from(vec![
        Span::styled(" | ", Style::default().fg(Color::Green)),
        Span::styled("Resultados", Style::default().fg(Color::White).bold()),
        Span::styled(
            format!(" {} vulnerabilidades encontradas", vulns.len()),
            Style::default().fg(Color::Yellow),
        ),
        Span::styled(
            format!(" ({} críticas, {} altas)", crit, high),
            Style::default().fg(Color::Red),
        ),
    ]))
    .style(Style::default().bg(Color::Rgb(20, 20, 40)));
    frame.render_widget(header, inner);
}

fn render_body(app: &mut AppState, frame: &mut Frame, area: Rect) {
    if let Some(idx) = app.result_detail_vuln {
        render_vuln_detail(app, frame, area, idx);
    } else {
        let chunks = Layout::horizontal([Constraint::Percentage(35), Constraint::Percentage(65)])
            .split(area);
        render_summary(app, frame, chunks[0]);
        render_vuln_list(app, frame, chunks[1]);
    }
}

fn render_summary(app: &AppState, frame: &mut Frame, area: Rect) {
    let block = Block::default()
        .borders(Borders::all())
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(Line::from(vec![Span::styled(
            " Resumo ",
            Style::default().fg(Color::Cyan).bold(),
        )]))
        .style(Style::default().bg(Color::Rgb(12, 12, 24)));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let vulns = app.vulnerabilities();
    let crit = vulns
        .iter()
        .filter(|v| v.severity == Severity::Critical)
        .count();
    let high = vulns
        .iter()
        .filter(|v| v.severity == Severity::High)
        .count();
    let med = vulns
        .iter()
        .filter(|v| v.severity == Severity::Medium)
        .count();
    let low = vulns.iter().filter(|v| v.severity == Severity::Low).count();
    let total = vulns.len();
    let bar_max = 10usize;
    let crit_w = crit * bar_max / total.max(1);
    let high_w = high * bar_max / total.max(1);
    let med_w = med * bar_max / total.max(1);
    let low_w = low * bar_max / total.max(1);

    let summary = Text::from(vec![
        Line::from(""),
        Line::from(vec![
            Span::styled(" Alvo: ", Style::default().fg(Color::DarkGray)),
            Span::styled(&app.config.target_url, Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled(" Modo: ", Style::default().fg(Color::DarkGray)),
            Span::styled(app.mode().to_string(), Style::default().fg(Color::Cyan)),
        ]),
        Line::from(""),
        Line::from(vec![Span::styled(
            " Distribuição por severidade",
            Style::default().fg(Color::White).bold(),
        )]),
        Line::from(""),
        Line::from(vec![
            Span::styled(" CRÍTICA ", Style::default().fg(Color::Magenta).bold()),
            Span::styled("█".repeat(crit_w), Style::default().fg(Color::Magenta)),
            Span::styled(format!(" {}", crit), Style::default().fg(Color::Magenta)),
        ]),
        Line::from(vec![
            Span::styled(" ALTA ", Style::default().fg(Color::Red).bold()),
            Span::styled("█".repeat(high_w), Style::default().fg(Color::Red)),
            Span::styled(format!(" {}", high), Style::default().fg(Color::Red)),
        ]),
        Line::from(vec![
            Span::styled(" MÉDIA ", Style::default().fg(Color::Yellow).bold()),
            Span::styled("█".repeat(med_w), Style::default().fg(Color::Yellow)),
            Span::styled(format!(" {}", med), Style::default().fg(Color::Yellow)),
        ]),
        Line::from(vec![
            Span::styled(" BAIXA ", Style::default().fg(Color::Cyan).bold()),
            Span::styled("█".repeat(low_w), Style::default().fg(Color::Cyan)),
            Span::styled(format!(" {}", low), Style::default().fg(Color::Cyan)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled(
                " Ferramentas usadas: ",
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(
                app.tools.iter().filter(|t| t.selected).count().to_string(),
                Style::default().fg(Color::Green),
            ),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled(
                "AVISO: ação imediata necessária para ",
                Style::default().fg(Color::Red),
            ),
            Span::styled(
                format!("{} achados críticos", crit),
                Style::default().fg(Color::Magenta).bold(),
            ),
            Span::styled("", Style::default().fg(Color::Red)),
        ]),
    ]);
    let para = Paragraph::new(summary)
        .style(Style::default().bg(Color::Rgb(12, 12, 24)))
        .wrap(Wrap { trim: true });
    frame.render_widget(para, inner);
}

fn render_vuln_list(app: &mut AppState, frame: &mut Frame, area: Rect) {
    let block = Block::default()
        .borders(Borders::all())
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(Line::from(vec![Span::styled(
            " Vulnerabilidades ",
            Style::default().fg(Color::Red).bold(),
        )]))
        .style(Style::default().bg(Color::Rgb(12, 12, 24)));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let vulns = app.vulnerabilities();
    let visible_h = inner.height.saturating_sub(2) as usize;
    let max_scroll = vulns.len().saturating_sub(visible_h);
    app.result_scroll = app.result_scroll.min(max_scroll);
    if app.result_cursor < app.result_scroll {
        app.result_scroll = app.result_cursor;
    } else if app.result_cursor >= app.result_scroll + visible_h {
        app.result_scroll = app.result_cursor - visible_h + 1;
    }

    for row in 0..visible_h.min(vulns.len().saturating_sub(app.result_scroll)) {
        app.register_hit_region(
            Rect::new(inner.x, inner.y + row as u16, inner.width, 1),
            SemanticAction::OpenVulnerability(app.result_scroll + row),
        );
    }

    let mut lines: Vec<Line> = Vec::new();
    for (i, v) in vulns
        .iter()
        .enumerate()
        .skip(app.result_scroll)
        .take(visible_h)
    {
        let sev_color = v.severity.color();
        let is_cursor = i == app.result_cursor;
        let title_style = if is_cursor {
            Style::default().fg(Color::White).bold()
        } else {
            Style::default().fg(Color::Gray)
        };
        let bg = if is_cursor {
            Color::Rgb(30, 30, 60)
        } else {
            Color::Rgb(12, 12, 24)
        };
        let prefix = if is_cursor { " > " } else { "   " };
        lines.push(
            Line::from(vec![
                Span::styled(prefix.to_string(), Style::default().fg(Color::Cyan)),
                Span::styled(
                    format!("[{}] ", severity_label(v.severity)),
                    Style::default().fg(sev_color).bold(),
                ),
                Span::styled(v.title.as_str(), title_style),
                Span::styled(
                    format!(" ({})", v.tool),
                    Style::default().fg(Color::DarkGray),
                ),
            ])
            .style(Style::default().bg(bg)),
        );
    }
    let para = Paragraph::new(Text::from(lines))
        .style(Style::default().bg(Color::Rgb(12, 12, 24)))
        .wrap(Wrap { trim: true });
    frame.render_widget(para, inner);
}

fn render_vuln_detail(app: &AppState, frame: &mut Frame, area: Rect, idx: usize) {
    let vulns = app.vulnerabilities();
    if idx >= vulns.len() {
        return;
    }
    let v = &vulns[idx];
    let sev_color = v.severity.color();

    let block = Block::default()
        .borders(Borders::all())
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(sev_color))
        .title(Line::from(vec![
            Span::styled(
                format!(" [{}] ", severity_label(v.severity)),
                Style::default().fg(sev_color).bold(),
            ),
            Span::styled(v.title.as_str(), Style::default().fg(Color::White).bold()),
        ]))
        .style(Style::default().bg(Color::Rgb(12, 12, 24)));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let detail = Text::from(vec![
        Line::from(""),
        Line::from(vec![
            Span::styled(" Severidade: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                severity_label(v.severity),
                Style::default().fg(sev_color).bold(),
            ),
        ]),
        Line::from(vec![
            Span::styled(" Ferramenta: ", Style::default().fg(Color::DarkGray)),
            Span::styled(v.tool.as_str(), Style::default().fg(Color::Cyan)),
        ]),
        Line::from(""),
        Line::from(vec![Span::styled(
            " Descrição",
            Style::default().fg(Color::White).bold(),
        )]),
        Line::from(vec![Span::styled(
            format!(" {}", v.description),
            Style::default().fg(Color::Gray),
        )]),
        Line::from(""),
        Line::from(vec![Span::styled(
            " Recomendação",
            Style::default().fg(Color::White).bold(),
        )]),
        Line::from(vec![Span::styled(
            format!(" {}", v.recommendation),
            Style::default().fg(Color::Green),
        )]),
    ]);
    let para = Paragraph::new(detail)
        .style(Style::default().bg(Color::Rgb(12, 12, 24)))
        .wrap(Wrap { trim: true });
    frame.render_widget(para, inner);
}

fn render_didactic(app: &mut AppState, frame: &mut Frame, area: Rect) {
    frame.render_widget(Clear, area);
    let block = Block::default()
        .borders(Borders::all())
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::Cyan))
        .title(Line::from(vec![Span::styled(
            " Explicação didática ",
            Style::default().fg(Color::Cyan).bold(),
        )]))
        .style(Style::default().bg(Color::Rgb(12, 12, 24)));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let vulns = app.vulnerabilities();
    let mut lines: Vec<Line> = Vec::new();

    if let Some(idx) = app.result_detail_vuln {
        if idx < vulns.len() {
            let v = &vulns[idx];
            lines.push(Line::from(vec![
                Span::styled(
                    format!(" [{}] ", severity_label(v.severity)),
                    Style::default().fg(v.severity.color()).bold(),
                ),
                Span::styled(v.title.as_str(), Style::default().fg(Color::White).bold()),
            ]));
            lines.push(Line::from(""));
            lines.push(Line::from(vec![Span::styled(
                " O que isso significa?",
                Style::default().fg(Color::Cyan).bold(),
            )]));
            lines.push(Line::from(""));
            for p in v.didactic.split("\n\n") {
                for word_line in wrap_text(p, inner.width.saturating_sub(4) as usize) {
                    lines.push(Line::from(vec![
                        Span::styled(" ", Style::default()),
                        Span::styled(word_line, Style::default().fg(Color::Gray)),
                    ]));
                }
                lines.push(Line::from(""));
            }
        }
    } else {
        lines.push(Line::from(vec![Span::styled(
            " SmartSec — Explicação Didática",
            Style::default().fg(Color::Cyan).bold(),
        )]));
        lines.push(Line::from(""));
        for v in &vulns {
            lines.push(Line::from(vec![
                Span::styled(
                    format!(" [{}] ", severity_label(v.severity)),
                    Style::default().fg(v.severity.color()).bold(),
                ),
                Span::styled(v.title.as_str(), Style::default().fg(Color::White).bold()),
            ]));
            lines.push(Line::from(""));
            for p in v.didactic.split("\n\n") {
                for word_line in wrap_text(p, inner.width.saturating_sub(4) as usize) {
                    lines.push(Line::from(vec![
                        Span::styled(" ", Style::default()),
                        Span::styled(word_line, Style::default().fg(Color::Gray)),
                    ]));
                }
                lines.push(Line::from(""));
            }
            lines.push(Line::from(vec![Span::styled(
                " ─────────────────────────────────",
                Style::default().fg(Color::DarkGray),
            )]));
            lines.push(Line::from(""));
        }
    }

    lines.push(Line::from(vec![Span::styled(" ", Style::default())]));

    let visible_h = inner.height.saturating_sub(3) as usize;
    let max_scroll = lines.len().saturating_sub(visible_h);
    app.didactic_max_scroll = max_scroll;
    app.didactic_scroll = app.didactic_scroll.min(max_scroll);
    let visible: Vec<Line> = lines
        .into_iter()
        .skip(app.didactic_scroll)
        .take(visible_h)
        .collect();
    let para = Paragraph::new(Text::from(visible))
        .style(Style::default().bg(Color::Rgb(12, 12, 24)))
        .wrap(Wrap { trim: false });
    frame.render_widget(para, inner);

    let btn_w = 8u16;
    let btn_x = area.x + area.width.saturating_sub(btn_w + 3);
    let btn_y = area.y + area.height.saturating_sub(2);
    let back_area = Rect::new(btn_x, btn_y, btn_w, 1);
    app.register_hit_region(back_area, SemanticAction::Back);
    let back_btn = Paragraph::new(Line::from(vec![Span::styled(
        " Voltar ",
        Style::default()
            .fg(Color::White)
            .bg(Color::Rgb(0, 120, 140))
            .bold(),
    )]))
    .style(Style::default().bg(Color::Rgb(12, 12, 24)));
    frame.render_widget(back_btn, back_area);
}

fn render_detail(app: &mut AppState, frame: &mut Frame, area: Rect) {
    frame.render_widget(Clear, area);
    let block = Block::default()
        .borders(Borders::all())
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::Yellow))
        .title(Line::from(vec![Span::styled(
            " Análise detalhada ",
            Style::default().fg(Color::Yellow).bold(),
        )]))
        .style(Style::default().bg(Color::Rgb(12, 12, 24)));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let vulns = app.vulnerabilities();
    let mut lines: Vec<Line> = Vec::new();
    if let Some(idx) = app.result_detail_vuln {
        if idx < vulns.len() {
            let v = &vulns[idx];
            lines.push(Line::from(vec![
                Span::styled(
                    format!(" [{}] ", severity_label(v.severity)),
                    Style::default().fg(v.severity.color()).bold(),
                ),
                Span::styled(v.title.as_str(), Style::default().fg(Color::White).bold()),
            ]));
            lines.push(Line::from(""));
            lines.push(Line::from(vec![Span::styled(
                " Detalhes técnicos",
                Style::default().fg(Color::Yellow).bold(),
            )]));
            lines.push(Line::from(vec![Span::styled(
                format!(" {}", v.description),
                Style::default().fg(Color::Gray),
            )]));
            lines.push(Line::from(""));
            lines.push(Line::from(vec![Span::styled(
                " Recomendação",
                Style::default().fg(Color::Green).bold(),
            )]));
            lines.push(Line::from(vec![Span::styled(
                format!(" {}", v.recommendation),
                Style::default().fg(Color::Green),
            )]));
        }
    }
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled(
            " Esc ",
            Style::default().fg(Color::Black).bg(Color::Cyan).bold(),
        ),
        Span::styled(" para voltar", Style::default().fg(Color::DarkGray)),
    ]));
    let para = Paragraph::new(lines)
        .style(Style::default().bg(Color::Rgb(12, 12, 24)))
        .wrap(Wrap { trim: true });
    frame.render_widget(para, inner);
}

fn render_footer(app: &mut AppState, frame: &mut Frame, area: Rect) {
    let bar = Block::default()
        .borders(Borders::TOP)
        .border_style(Style::default().fg(Color::DarkGray))
        .style(Style::default().bg(Color::Rgb(20, 20, 40)));
    let inner = bar.inner(area);
    frame.render_widget(bar, area);

    let in_detail = app.result_detail_vuln.is_some();

    let export_w = 13u16;
    let didactic_w = 10u16;
    let new_scan_w = 14u16;
    let didactic_x = area.x + area.width.saturating_sub(didactic_w + 2);
    let export_x = didactic_x.saturating_sub(export_w + 2);
    let new_scan_x = export_x.saturating_sub(new_scan_w + 2);
    let back_w = 8u16;
    let didactic_w = 10u16;
    let didactic_x = area.x + area.width.saturating_sub(didactic_w + 2);
    let back_x = didactic_x.saturating_sub(back_w + 4);

    if in_detail {
        let back_area = Rect::new(back_x, area.y + 1, back_w, 1);
        let didactic_area = Rect::new(didactic_x, area.y + 1, didactic_w, 1);
        app.register_hit_region(back_area, SemanticAction::Back);
        app.register_hit_region(didactic_area, SemanticAction::ShowDidactic);
    } else {
        app.register_hit_region(
            Rect::new(new_scan_x, area.y + 1, new_scan_w, 1),
            SemanticAction::NewScan,
        );
        app.register_hit_region(
            Rect::new(export_x, area.y + 1, export_w, 1),
            SemanticAction::ExportMarkdown,
        );
        app.register_hit_region(
            Rect::new(didactic_x, area.y + 1, didactic_w, 1),
            SemanticAction::ShowDidactic,
        );
    }

    let spans = vec![
        Span::styled(
            format!(
                " | {} ",
                match app.mode() {
                    ExecutionType::Auto => "AUTOMÁTICO",
                    ExecutionType::Assisted => "ASSISTIDO",
                }
            ),
            Style::default().fg(Color::Cyan).bold(),
        ),
        Span::styled(" │ ", Style::default().fg(Color::DarkGray)),
        Span::styled("↑↓", Style::default().fg(Color::White)),
        Span::styled(" Navegar ", Style::default().fg(Color::DarkGray)),
        Span::styled("Enter", Style::default().fg(Color::White)),
        Span::styled(" Selecionar ", Style::default().fg(Color::DarkGray)),
        Span::styled("Esc", Style::default().fg(Color::White)),
        Span::styled(" Voltar", Style::default().fg(Color::DarkGray)),
    ];
    let footer =
        Paragraph::new(Line::from(spans)).style(Style::default().bg(Color::Rgb(20, 20, 40)));
    frame.render_widget(footer, inner);

    let export_label = if app.md_exported {
        " OK Exportado "
    } else {
        " Exportar .md "
    };
    let didactic_label = " Didática ";

    if in_detail {
        let back_area = Rect::new(back_x, area.y + 1, back_w, 1);
        let back_btn = Paragraph::new(Line::from(vec![Span::styled(
            " Voltar ",
            Style::default()
                .fg(Color::White)
                .bg(Color::Rgb(0, 120, 140))
                .bold(),
        )]))
        .style(Style::default().bg(Color::Rgb(20, 20, 40)));
        frame.render_widget(back_btn, back_area);
    } else {
        let new_scan_area = Rect::new(new_scan_x, area.y + 1, new_scan_w, 1);
        let export_area = Rect::new(export_x, area.y + 1, export_w, 1);
        let new_scan_btn = Paragraph::new(Line::from(vec![Span::styled(
            " Nova análise ",
            Style::default()
                .fg(Color::White)
                .bg(Color::Rgb(0, 80, 140))
                .bold(),
        )]))
        .style(Style::default().bg(Color::Rgb(20, 20, 40)));
        frame.render_widget(new_scan_btn, new_scan_area);

        let export_btn = Paragraph::new(Line::from(vec![Span::styled(
            export_label,
            Style::default()
                .fg(Color::White)
                .bg(Color::Rgb(0, 120, 0))
                .bold(),
        )]))
        .style(Style::default().bg(Color::Rgb(20, 20, 40)));
        frame.render_widget(export_btn, export_area);
    }

    let didactic_btn = Paragraph::new(Line::from(vec![Span::styled(
        didactic_label,
        Style::default()
            .fg(Color::White)
            .bg(Color::Rgb(120, 40, 120))
            .bold(),
    )]))
    .style(Style::default().bg(Color::Rgb(20, 20, 40)));
    frame.render_widget(
        didactic_btn,
        Rect::new(didactic_x, area.y + 1, didactic_w, 1),
    );
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
