use crate::config::execution_type::ExecutionType;
use crate::domain::Severity;
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
        Span::styled(" ◆ ", Style::default().fg(Color::Green)),
        Span::styled("Results", Style::default().fg(Color::White).bold()),
        Span::styled(
            format!(" {} vulns found", vulns.len()),
            Style::default().fg(Color::Yellow),
        ),
        Span::styled(
            format!(" ({} critical, {} high)", crit, high),
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
            " Summary ",
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
            Span::styled(" Target: ", Style::default().fg(Color::DarkGray)),
            Span::styled(&app.config.target_url, Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled(" Mode: ", Style::default().fg(Color::DarkGray)),
            Span::styled(app.mode().to_string(), Style::default().fg(Color::Cyan)),
        ]),
        Line::from(""),
        Line::from(vec![Span::styled(
            " Severity Breakdown",
            Style::default().fg(Color::White).bold(),
        )]),
        Line::from(""),
        Line::from(vec![
            Span::styled(" CRITICAL ", Style::default().fg(Color::Magenta).bold()),
            Span::styled("█".repeat(crit_w), Style::default().fg(Color::Magenta)),
            Span::styled(format!(" {}", crit), Style::default().fg(Color::Magenta)),
        ]),
        Line::from(vec![
            Span::styled(" HIGH ", Style::default().fg(Color::Red).bold()),
            Span::styled("█".repeat(high_w), Style::default().fg(Color::Red)),
            Span::styled(format!(" {}", high), Style::default().fg(Color::Red)),
        ]),
        Line::from(vec![
            Span::styled(" MEDIUM ", Style::default().fg(Color::Yellow).bold()),
            Span::styled("█".repeat(med_w), Style::default().fg(Color::Yellow)),
            Span::styled(format!(" {}", med), Style::default().fg(Color::Yellow)),
        ]),
        Line::from(vec![
            Span::styled(" LOW ", Style::default().fg(Color::Cyan).bold()),
            Span::styled("█".repeat(low_w), Style::default().fg(Color::Cyan)),
            Span::styled(format!(" {}", low), Style::default().fg(Color::Cyan)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled(" Tools used: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                app.tools.iter().filter(|t| t.selected).count().to_string(),
                Style::default().fg(Color::Green),
            ),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled(
                " ⚠ Immediate action required for ",
                Style::default().fg(Color::Red),
            ),
            Span::styled(
                format!("{} critical", crit),
                Style::default().fg(Color::Magenta).bold(),
            ),
            Span::styled(" findings", Style::default().fg(Color::Red)),
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
            " Vulnerabilities ",
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
                    format!("[{}] ", v.severity.label()),
                    Style::default().fg(sev_color).bold(),
                ),
                Span::styled(v.title, title_style),
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
                format!(" [{}] ", v.severity.label()),
                Style::default().fg(sev_color).bold(),
            ),
            Span::styled(v.title, Style::default().fg(Color::White).bold()),
        ]))
        .style(Style::default().bg(Color::Rgb(12, 12, 24)));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let action_labels = ["← Back", "Explain Didactic"];
    let mut action_spans: Vec<Span> = Vec::new();
    for (i, label) in action_labels.iter().enumerate() {
        let is_selected = app.result_action_cursor == i;
        let style = if is_selected {
            Style::default().fg(Color::Black).bg(Color::Cyan).bold()
        } else {
            Style::default().fg(Color::DarkGray)
        };
        action_spans.push(Span::styled(format!(" {} ", label), style));
        if i < action_labels.len() - 1 {
            action_spans.push(Span::styled(" ", Style::default()));
        }
    }

    let detail = Text::from(vec![
        Line::from(""),
        Line::from(vec![
            Span::styled(" Severity: ", Style::default().fg(Color::DarkGray)),
            Span::styled(v.severity.label(), Style::default().fg(sev_color).bold()),
        ]),
        Line::from(vec![
            Span::styled(" Tool: ", Style::default().fg(Color::DarkGray)),
            Span::styled(v.tool, Style::default().fg(Color::Cyan)),
        ]),
        Line::from(""),
        Line::from(vec![Span::styled(
            " Description",
            Style::default().fg(Color::White).bold(),
        )]),
        Line::from(vec![Span::styled(
            format!(" {}", v.description),
            Style::default().fg(Color::Gray),
        )]),
        Line::from(""),
        Line::from(vec![Span::styled(
            " Recommendation",
            Style::default().fg(Color::White).bold(),
        )]),
        Line::from(vec![Span::styled(
            format!(" {}", v.recommendation),
            Style::default().fg(Color::Green),
        )]),
        Line::from(""),
        Line::from(action_spans),
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
            " Didactic Explanation ",
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
                    format!(" [{}] ", v.severity.label()),
                    Style::default().fg(v.severity.color()).bold(),
                ),
                Span::styled(v.title, Style::default().fg(Color::White).bold()),
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
                    format!(" [{}] ", v.severity.label()),
                    Style::default().fg(v.severity.color()).bold(),
                ),
                Span::styled(v.title, Style::default().fg(Color::White).bold()),
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

    lines.push(Line::from(vec![
        Span::styled(
            " Esc ",
            Style::default().fg(Color::Black).bg(Color::Cyan).bold(),
        ),
        Span::styled(" to go back", Style::default().fg(Color::DarkGray)),
    ]));

    let visible_h = inner.height.saturating_sub(2) as usize;
    let max_scroll = lines.len().saturating_sub(visible_h);
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
}

fn render_detail(app: &mut AppState, frame: &mut Frame, area: Rect) {
    frame.render_widget(Clear, area);
    let block = Block::default()
        .borders(Borders::all())
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::Yellow))
        .title(Line::from(vec![Span::styled(
            " Detailed Analysis ",
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
                    format!(" [{}] ", v.severity.label()),
                    Style::default().fg(v.severity.color()).bold(),
                ),
                Span::styled(v.title, Style::default().fg(Color::White).bold()),
            ]));
            lines.push(Line::from(""));
            lines.push(Line::from(vec![Span::styled(
                " Technical Details",
                Style::default().fg(Color::Yellow).bold(),
            )]));
            lines.push(Line::from(vec![Span::styled(
                format!(" {}", v.description),
                Style::default().fg(Color::Gray),
            )]));
            lines.push(Line::from(""));
            lines.push(Line::from(vec![Span::styled(
                " Recommendation",
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
        Span::styled(" to go back", Style::default().fg(Color::DarkGray)),
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

    let action_labels: Vec<&str> = if app.result_detail_vuln.is_some() {
        vec!["← Back", "Explain Didactic"]
    } else {
        vec![
            if app.md_exported {
                "✓ Exported .md"
            } else {
                "Export .md"
            },
            "Explain Didactic",
        ]
    };

    let mut spans: Vec<Span> = vec![
        Span::styled(
            format!(
                " ◆ {} ",
                match app.mode() {
                    ExecutionType::Auto => "AUTO",
                    ExecutionType::Assisted => "ASSISTED",
                }
            ),
            Style::default().fg(Color::Cyan).bold(),
        ),
        Span::styled(" │ ", Style::default().fg(Color::DarkGray)),
    ];
    for (i, label) in action_labels.iter().enumerate() {
        let is_sel = !app.result_focus_list && app.result_action_cursor == i;
        let style = if is_sel {
            Style::default().fg(Color::Black).bg(Color::Cyan).bold()
        } else {
            Style::default().fg(Color::DarkGray)
        };
        spans.push(Span::styled(format!(" {} ", label), style));
        if i < action_labels.len() - 1 {
            spans.push(Span::styled(" ", Style::default()));
        }
    }
    spans.push(Span::styled(" │ ", Style::default().fg(Color::DarkGray)));
    spans.push(Span::styled("↑↓", Style::default().fg(Color::White)));
    spans.push(Span::styled(
        " Navigate ",
        Style::default().fg(Color::DarkGray),
    ));
    spans.push(Span::styled("Enter", Style::default().fg(Color::White)));
    spans.push(Span::styled(
        " Select ",
        Style::default().fg(Color::DarkGray),
    ));
    spans.push(Span::styled("Tab", Style::default().fg(Color::White)));
    spans.push(Span::styled(
        " Switch ",
        Style::default().fg(Color::DarkGray),
    ));
    spans.push(Span::styled("Esc", Style::default().fg(Color::White)));
    spans.push(Span::styled(" Quit", Style::default().fg(Color::DarkGray)));

    let footer =
        Paragraph::new(Line::from(spans)).style(Style::default().bg(Color::Rgb(20, 20, 40)));
    frame.render_widget(footer, inner);
}
