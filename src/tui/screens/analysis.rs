use crate::config::execution_type::ExecutionType;
use crate::tui::state::{AnalysisPhase, AppState};
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Style, Stylize},
    text::{Line, Span, Text},
    widgets::{Block, BorderType, Borders, Paragraph, Wrap},
    Frame,
};

#[allow(dead_code)]
struct NeuralNode {
    layer: usize,
    index: usize,
    x_pct: f32,
    y_pct: f32,
}

#[allow(dead_code)]
struct NeuralEdge {
    from: usize,
    to: usize,
}

fn build_network() -> (Vec<NeuralNode>, Vec<NeuralEdge>) {
    let layers = [("IN", 4), ("H1", 5), ("H2", 5), ("OUT", 3)];
    let mut nodes = Vec::new();
    let mut edges = Vec::new();
    let num_layers = layers.len();
    let mut layer_start = Vec::new();
    for (li, (_name, count)) in layers.iter().enumerate() {
        layer_start.push(nodes.len());
        for ni in 0..*count {
            let x_pct = (li as f32 + 0.5) / num_layers as f32;
            let spacing = 1.0 / (*count as f32 + 1.0);
            let y_pct = (ni as f32 + 1.0) * spacing;
            nodes.push(NeuralNode {
                layer: li,
                index: ni,
                x_pct,
                y_pct,
            });
        }
    }
    for li in 0..num_layers - 1 {
        let cur_start = layer_start[li];
        let next_start = layer_start[li + 1];
        let cur_count = layers[li].1;
        let next_count = layers[li + 1].1;
        for ci in 0..cur_count {
            let targets: Vec<usize> = if next_count <= cur_count {
                (0..next_count).collect()
            } else {
                let offset = (ci * next_count / cur_count).min(next_count - 1);
                let end = (offset + 1).min(next_count - 1);
                (offset..=end).collect()
            };
            for ni in targets {
                edges.push(NeuralEdge {
                    from: cur_start + ci,
                    to: next_start + ni,
                });
            }
        }
    }
    (nodes, edges)
}

fn line_cells(r1: f32, c1: f32, r2: f32, c2: f32) -> Vec<(usize, usize)> {
    let dr = r2 - r1;
    let dc = c2 - c1;
    let steps = (dr.abs().max(dc.abs())).max(1.0).ceil() as usize;
    let mut cells = Vec::with_capacity(steps + 1);
    for i in 0..=steps {
        let t = if steps > 0 {
            i as f32 / steps as f32
        } else {
            0.0
        };
        let r = (r1 + dr * t).round() as usize;
        let c = (c1 + dc * t).round() as usize;
        cells.push((r, c));
    }
    cells
}

fn edge_char(dr: f32, dc: f32) -> &'static str {
    if dc.abs() < 0.01 {
        "│"
    } else if dr.abs() < 0.01 {
        "─"
    } else if (dr / dc) > 0.0 {
        "╲"
    } else {
        "╱"
    }
}

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
            format!(" {} {}", spinner, label),
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

fn render_neural_viz(app: &mut AppState, frame: &mut Frame, area: Rect) {
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
    if h < 4 || w < 6 {
        return;
    }

    let t = app.tick;
    let (nodes, edges) = build_network();
    let layer_labels = ["IN", "H1", "H2", "OUT"];
    let margin_top = 2usize;
    let margin_bottom = 1usize;
    let margin_lr = 2usize;
    let usable_h = h.saturating_sub(margin_top + margin_bottom);
    let usable_w = w.saturating_sub(2 * margin_lr);
    if usable_h == 0 || usable_w == 0 {
        return;
    }

    let node_positions: Vec<(usize, usize)> = nodes
        .iter()
        .map(|n| {
            let c = margin_lr + (n.x_pct * usable_w as f32).round() as usize;
            let r = margin_top + (n.y_pct * usable_h as f32).round() as usize;
            (r.min(h - 1), c.min(w - 1))
        })
        .collect();

    let mut grid = vec![vec![(vec![' '], Color::Rgb(20, 10, 30)); w]; h];

    for (ei, edge) in edges.iter().enumerate() {
        let (r1, c1) = node_positions[edge.from];
        let (r2, c2) = node_positions[edge.to];
        let cells = line_cells(r1 as f32, c1 as f32, r2 as f32, c2 as f32);
        let dr = (r2 as f32) - (r1 as f32);
        let dc = (c2 as f32) - (c1 as f32);
        let base_ch = edge_char(dr, dc);
        let total = cells.len().max(1);
        let travel_period = 30u64;
        let speed_offset = (ei as u64 * 7) % travel_period;
        let signal_pos =
            ((t + speed_offset) % travel_period) as usize * total / travel_period as usize;

        for (ci, &(r, c)) in cells.iter().enumerate() {
            if r >= h || c >= w {
                continue;
            }
            let is_node = node_positions.iter().any(|&(nr, nc)| nr == r && nc == c);
            if is_node {
                continue;
            }
            let dist_from_signal = ci.abs_diff(signal_pos);
            let (ch, color) = if dist_from_signal == 0 {
                ('◆', Color::Rgb(255, 100, 255))
            } else if dist_from_signal <= 2 {
                ('●', Color::Rgb(180, 50, 200))
            } else if dist_from_signal <= 5 {
                (base_ch.chars().next().unwrap(), Color::Rgb(100, 20, 140))
            } else {
                let pulse = (t + ei as u64 * 3) % 20;
                if pulse < 10 {
                    (base_ch.chars().next().unwrap(), Color::Rgb(50, 10, 70))
                } else {
                    ('·', Color::Rgb(30, 5, 45))
                }
            };
            grid[r][c] = (vec![ch], color);
        }
    }

    for (ni, &(r, c)) in node_positions.iter().enumerate() {
        if r >= h || c >= w {
            continue;
        }
        let pulse = (t + ni as u64 * 5) % 20;
        let (ch, color) = if pulse < 5 {
            ('●', Color::Rgb(255, 80, 255))
        } else if pulse < 10 {
            ('◉', Color::Rgb(200, 50, 220))
        } else if pulse < 15 {
            ('○', Color::Rgb(120, 30, 160))
        } else {
            ('◌', Color::Rgb(60, 15, 90))
        };
        grid[r][c] = (vec![ch], color);
    }

    for (li, label) in layer_labels.iter().enumerate() {
        let x_pct = (li as f32 + 0.5) / layer_labels.len() as f32;
        let c = margin_lr + (x_pct * usable_w as f32).round() as usize;
        let c_start = c.saturating_sub(label.len() / 2);
        if c_start + label.len() <= w && margin_top > 1 {
            let row = 0;
            for (i, ch) in label.chars().enumerate() {
                let col = c_start + i;
                if col < w {
                    grid[row][col] = (vec![ch], Color::Rgb(60, 30, 80));
                }
            }
        }
    }

    let mut lines: Vec<Line> = Vec::with_capacity(h);
    for grid_row in grid.iter().take(h) {
        let mut spans: Vec<Span> = Vec::new();
        for (chars, color) in grid_row.iter().take(w) {
            let style = Style::default().fg(*color).bg(Color::Rgb(8, 4, 16));
            let s: String = chars.iter().collect();
            spans.push(Span::styled(s, style));
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
                Span::styled(" ", Style::default()),
                Span::styled(line, Style::default().fg(Color::Gray)),
            ]));
        } else {
            text_lines.push(Line::from(""));
        }
    }
    if app.analysis_phase == AnalysisPhase::Complete {
        text_lines.push(Line::from(""));
        text_lines.push(Line::from(vec![
            Span::styled(" ✓ ", Style::default().fg(Color::Green)),
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
                match app.mode() {
                    ExecutionType::Auto => "AUTO",
                    ExecutionType::Assisted => "ASSISTED",
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
