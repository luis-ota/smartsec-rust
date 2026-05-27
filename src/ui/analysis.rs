use crate::app::{AnalysisPhase, AppMode, AppState};
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Style, Stylize},
    text::{Line, Span, Text},
    widgets::{Block, BorderType, Borders, Paragraph, Wrap},
    Frame,
};

pub fn render(app: &mut AppState, frame: &mut Frame, area: Rect) {
    let bg = Block::default().style(Style::default().bg(Color::Rgb(8, 8, 16)));
    frame.render_widget(bg, area);

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

    let spinner = app.spinner_char();
    let (label, color) = match app.analysis_phase {
        AnalysisPhase::Scanning => ("Scanning results", Color::Cyan),
        AnalysisPhase::Correlating => ("Correlating findings", Color::Yellow),
        AnalysisPhase::Generating => ("Generating recommendations", Color::Magenta),
        AnalysisPhase::Complete => ("Analysis complete", Color::Green),
    };

    let header = Paragraph::new(Line::from(vec![
        Span::styled(" ◆ ", Style::default().fg(Color::Magenta)),
        Span::styled("AI Analysis", Style::default().fg(Color::White).bold()),
        Span::styled(
            format!("  {} {}", spinner, label),
            Style::default().fg(color),
        ),
    ]))
    .style(Style::default().bg(Color::Rgb(20, 20, 40)));
    frame.render_widget(header, inner);
}

fn render_body(app: &mut AppState, frame: &mut Frame, area: Rect) {
    let chunks =
        Layout::horizontal([Constraint::Percentage(40), Constraint::Percentage(60)]).split(area);

    render_neural_viz(app, frame, chunks[0]);
    render_analysis_text(app, frame, chunks[1]);
}

fn render_neural_viz(app: &AppState, frame: &mut Frame, area: Rect) {
    let block = Block::default()
        .borders(Borders::all())
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::Rgb(60, 0, 80)))
        .title(Line::from(vec![Span::styled(
            " Neural Processing ",
            Style::default().fg(Color::Magenta).bold(),
        )]))
        .style(Style::default().bg(Color::Rgb(8, 4, 16)));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let h = inner.height as usize;
    let w = inner.width as usize;
    let t = app.tick;

    let nodes = [
        (2, 3),
        (4, 7),
        (2, 11),
        (6, 3),
        (6, 11),
        (10, 5),
        (10, 9),
        (14, 3),
        (14, 7),
        (14, 11),
        (18, 5),
        (18, 9),
    ];
    let edges = [
        (0, 1),
        (0, 3),
        (1, 2),
        (1, 4),
        (3, 5),
        (3, 1),
        (4, 6),
        (5, 7),
        (5, 8),
        (6, 8),
        (6, 9),
        (7, 10),
        (8, 10),
        (9, 11),
        (10, 11),
    ];

    let mut lines: Vec<Line> = Vec::with_capacity(h);
    for row in 0..h {
        let mut spans: Vec<Span> = Vec::new();
        for col in 0..w.min(30) {
            let mut ch = " ";
            let mut color = Color::Rgb(20, 10, 30);

            for &(a, b) in &edges {
                if a < nodes.len() && b < nodes.len() {
                    let (ar, ac) = nodes[a];
                    let (br, bc) = nodes[b];
                    if ar < h && br < h && ac < 30 && bc < 30 {
                        let mid_r = (ar + br) / 2;
                        let mid_c = (ac + bc) / 2;
                        if row == mid_r && col == mid_c {
                            let pulse = (t + a as u64 * 7) % 20;
                            if pulse < 10 {
                                ch = "─";
                                color =
                                    Color::Rgb(80 + (pulse * 12) as u8, 0, 120 + (pulse * 8) as u8);
                            } else {
                                ch = "·";
                                color = Color::Rgb(30, 0, 50);
                            }
                        }
                    }
                }
            }

            for (ni, &(nr, nc)) in nodes.iter().enumerate() {
                if nr < h && nc < 30 && row == nr && col == nc {
                    let pulse = (t + ni as u64 * 5) % 15;
                    if pulse < 8 {
                        ch = "●";
                        color = Color::Magenta;
                    } else {
                        ch = "○";
                        color = Color::Rgb(60, 0, 80);
                    }
                }
            }

            spans.push(Span::styled(ch.to_string(), Style::default().fg(color)));
        }
        lines.push(Line::from(spans));
    }

    let viz = Paragraph::new(Text::from(lines)).style(Style::default().bg(Color::Rgb(8, 4, 16)));
    frame.render_widget(viz, inner);
}

fn render_analysis_text(app: &AppState, frame: &mut Frame, area: Rect) {
    let block = Block::default()
        .borders(Borders::all())
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(Line::from(vec![Span::styled(
            " Analysis Output ",
            Style::default().fg(Color::Cyan).bold(),
        )]))
        .style(Style::default().bg(Color::Rgb(12, 12, 24)));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let phase_label = match app.analysis_phase {
        AnalysisPhase::Scanning => "▸ Phase 1: Vulnerability Pattern Scanning",
        AnalysisPhase::Correlating => "▸ Phase 2: Cross-tool Result Correlation",
        AnalysisPhase::Generating => "▸ Phase 3: Recommendation Generation",
        AnalysisPhase::Complete => "✓ Analysis Complete",
    };
    let phase_color = match app.analysis_phase {
        AnalysisPhase::Scanning => Color::Cyan,
        AnalysisPhase::Correlating => Color::Yellow,
        AnalysisPhase::Generating => Color::Magenta,
        AnalysisPhase::Complete => Color::Green,
    };

    let spinner = app.spinner_char();
    let mut text_lines = vec![
        Line::from(vec![
            Span::styled(format!("{} ", spinner), Style::default().fg(phase_color)),
            Span::styled(phase_label, Style::default().fg(phase_color).bold()),
        ]),
        Line::from(""),
    ];

    for line in app.analysis_text.lines() {
        if !line.is_empty() {
            text_lines.push(Line::from(vec![
                Span::styled("  ", Style::default()),
                Span::styled(line, Style::default().fg(Color::Gray)),
            ]));
        } else {
            text_lines.push(Line::from(""));
        }
    }

    if app.analysis_phase == AnalysisPhase::Complete {
        text_lines.push(Line::from(""));
        text_lines.push(Line::from(vec![
            Span::styled("  ✓ ", Style::default().fg(Color::Green)),
            Span::styled(
                "Proceeding to results...",
                Style::default().fg(Color::Green),
            ),
        ]));
    }

    let para = Paragraph::new(Text::from(text_lines))
        .style(Style::default().bg(Color::Rgb(12, 12, 24)))
        .wrap(Wrap { trim: true });
    frame.render_widget(para, inner);
}

fn render_footer(app: &AppState, frame: &mut Frame, area: Rect) {
    let bar = Block::default()
        .borders(Borders::TOP)
        .border_style(Style::default().fg(Color::DarkGray))
        .style(Style::default().bg(Color::Rgb(20, 20, 40)));
    let inner = bar.inner(area);
    frame.render_widget(bar, area);

    let spinner = app.spinner_char();
    let msg = match app.analysis_phase {
        AnalysisPhase::Complete => "Analysis finished",
        _ => "AI is processing scan results...",
    };

    let footer = Paragraph::new(Line::from(vec![
        Span::styled(
            format!(
                " ◆ {} ",
                match app.mode {
                    AppMode::Auto => "AUTO",
                    AppMode::Assisted => "ASSISTED",
                }
            ),
            Style::default().fg(Color::Cyan).bold(),
        ),
        Span::styled(" │ ", Style::default().fg(Color::DarkGray)),
        Span::styled(format!("{} ", spinner), Style::default().fg(Color::Magenta)),
        Span::styled(msg, Style::default().fg(Color::Magenta)),
    ]))
    .style(Style::default().bg(Color::Rgb(20, 20, 40)));
    frame.render_widget(footer, inner);
}
