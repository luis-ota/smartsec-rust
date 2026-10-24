use crate::tui::chrome::{
    ACCENT, MUTED, SUCCESS, SURFACE, SURFACE_ACTIVE, SURFACE_HOVER, TEXT, TEXT_SOFT, WARNING,
};
use crate::tui::commands::command_items;
use crate::tui::interaction::SemanticAction;
use crate::tui::state::{AiTimelineOrigin, AppState, AppStep};
use ratatui::{
    layout::{Alignment, Constraint, Layout, Rect},
    style::{Color, Style, Stylize},
    text::{Line, Span, Text},
    widgets::{Block, Borders, Clear, Paragraph},
    Frame,
};

pub fn render_help(app: &mut AppState, frame: &mut Frame, area: Rect) {
    app.hit_regions.clear();
    let popup = centered_fixed(area, 68, 19);
    frame.render_widget(Clear, popup);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(ACCENT))
        .title(" Ajuda ")
        .title_style(Style::default().fg(Color::White).bold())
        .style(Style::default().bg(SURFACE));
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let context = if app.show_settings {
        "Campos agrupados por assunto; o rodapé explica o campo em foco."
    } else {
        match app.step {
            AppStep::Splash => "Defina o alvo, o modo de execução e inicie a análise.",
            AppStep::ToolSelect => {
                "Escolha as ferramentas; a recomendação vem do perfil do projeto."
            }
            AppStep::Execution => {
                "Acompanhe o progresso, pause (p), retome (p) ou cancele (c) a execução."
            }
            AppStep::Analysis => "Aguarde a correlação dos achados e a geração das recomendações.",
            AppStep::Results => "Revise os achados, abra detalhes e exporte o relatório.",
            AppStep::History => "Consulte execuções anteriores e abra o detalhe de cada uma.",
        }
    };
    let lines = if app.show_settings {
        vec![
            Line::styled(context, Style::default().fg(Color::Gray)),
            Line::from(""),
            shortcut("setas", "mover na coluna (↑↓) ou trocar de coluna (←→)"),
            shortcut("enter", "abrir o campo para digitar ou trocar a seleção"),
            shortcut("espaço", "alternar as opções liga/desliga"),
            shortcut("ctrl+u", "limpar o campo de texto em foco"),
            shortcut("esc", "sair do campo em edição ou descartar o rascunho"),
            shortcut("tab", "percorrer campos, descartar e salvar"),
            Line::from(""),
            shortcut("f1", "abrir ajuda em qualquer contexto"),
            shortcut("ctrl+p", "abrir a paleta de comandos"),
            shortcut("ctrl+t", "liberar o mouse para selecionar e copiar"),
            Line::from(""),
            Line::styled(
                "O resumo no topo diz o que será aplicado ao salvar.",
                Style::default().fg(Color::DarkGray),
            ),
            Line::styled(
                "O mouse oferece as mesmas ações do teclado.",
                Style::default().fg(Color::DarkGray),
            ),
        ]
    } else {
        vec![
            Line::styled(context, Style::default().fg(Color::Gray)),
            Line::from(""),
            shortcut("tab / shift+tab", "mover o foco"),
            shortcut("setas", "navegar ou rolar"),
            shortcut("enter / espaço", "acionar o item em foco ou abrir o campo"),
            shortcut("p", "pausar ou retomar a execução"),
            shortcut("c", "cancelar a execução em andamento"),
            shortcut("i", "abrir a atividade da IA (ou clique no bloco)"),
            shortcut("ctrl+u", "limpar o campo de texto em foco"),
            shortcut("esc", "sair do campo em edição ou voltar"),
            shortcut("f1", "abrir ajuda em qualquer contexto"),
            shortcut("f2", "rastreabilidade da Sprint 1"),
            shortcut("h", "consultar o histórico de execuções"),
            shortcut("ctrl+p", "abrir a paleta de comandos"),
            shortcut("ctrl+t", "liberar o mouse para selecionar e copiar"),
            Line::from(""),
            Line::styled(
                "O mouse oferece as mesmas ações disponíveis pelo teclado.",
                Style::default().fg(Color::DarkGray),
            ),
        ]
    };
    frame.render_widget(
        Paragraph::new(Text::from(lines)).style(Style::default().bg(SURFACE)),
        inner,
    );

    let close_area = Rect::new(
        inner.x,
        inner.y + inner.height.saturating_sub(1),
        inner.width,
        1,
    );
    app.register_hit_region(close_area, SemanticAction::Back);
    frame.render_widget(
        Paragraph::new("enter ou esc  fechar")
            .alignment(Alignment::Right)
            .style(
                Style::default()
                    .fg(ACCENT)
                    .bg(if app.mouse_over_overlay(close_area) {
                        SURFACE_HOVER
                    } else {
                        SURFACE
                    }),
            ),
        close_area,
    );
}

pub fn render_command_palette(app: &mut AppState, frame: &mut Frame, area: Rect) {
    app.hit_regions.clear();
    let items = command_items(app);
    app.command_cursor = app.command_cursor.min(items.len().saturating_sub(1));
    let height = (items.len() as u16 + 4).min(area.height.saturating_sub(2));
    let popup = centered_fixed(area, 64, height.max(6));
    frame.render_widget(Clear, popup);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(ACCENT))
        .title(" Comandos ")
        .title_style(Style::default().fg(Color::White).bold())
        .style(Style::default().bg(SURFACE));
    let inner = block.inner(popup);
    frame.render_widget(block, popup);
    let chunks = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(1),
        Constraint::Length(1),
    ])
    .split(inner);
    frame.render_widget(
        Paragraph::new("Selecione uma ação")
            .style(Style::default().fg(Color::DarkGray).bg(SURFACE)),
        chunks[0],
    );

    let mut lines = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        let selected = index == app.command_cursor;
        let row_area = Rect::new(chunks[1].x, chunks[1].y + index as u16, chunks[1].width, 1);
        let clickable = item.enabled && index < chunks[1].height as usize;
        let hovered = clickable && app.mouse_over_overlay(row_area);
        let foreground = if !item.enabled {
            Color::DarkGray
        } else if selected {
            Color::Black
        } else {
            Color::Gray
        };
        let background = if selected {
            ACCENT
        } else if hovered {
            SURFACE_HOVER
        } else {
            SURFACE
        };
        let prefix = if selected { "> " } else { "  " };
        lines.push(
            Line::from(vec![
                Span::styled(prefix, Style::default().fg(foreground)),
                Span::styled(item.label, Style::default().fg(foreground)),
                Span::styled(
                    if item.shortcut.is_empty() {
                        String::new()
                    } else {
                        format!("  {}", item.shortcut)
                    },
                    Style::default().fg(foreground),
                ),
            ])
            .style(Style::default().bg(background)),
        );
        if clickable {
            app.register_hit_region(row_area, SemanticAction::ExecuteCommand(index));
        }
    }
    frame.render_widget(
        Paragraph::new(Text::from(lines)).style(Style::default().bg(SURFACE)),
        chunks[1],
    );
    frame.render_widget(
        Paragraph::new("↑↓ navegar  enter executar  esc fechar")
            .alignment(Alignment::Right)
            .style(Style::default().fg(Color::DarkGray).bg(SURFACE)),
        chunks[2],
    );
}

pub fn render_report_viewer(app: &mut AppState, frame: &mut Frame, area: Rect) {
    use ratatui::widgets::Wrap;
    let path_label = app.exported_report_path.as_ref().map_or_else(
        || "arquivo indisponível".to_string(),
        |path| format!("arquivo  {}", path.display()),
    );
    let content_lines: Vec<&str> = app.report_content.lines().collect();
    let popup = centered_fixed(area, 76, (content_lines.len() + 7).clamp(8, 22) as u16);
    frame.render_widget(Clear, popup);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(ACCENT))
        .title(" Relatório exportado ")
        .title_style(Style::default().fg(Color::White).bold())
        .style(Style::default().bg(SURFACE));
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let rows = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(1),
        Constraint::Length(1),
    ])
    .split(inner);
    frame.render_widget(
        Paragraph::new(crate::tui::chrome::truncate_width(
            &path_label,
            rows[0].width as usize,
        ))
        .style(Style::default().fg(Color::DarkGray).bg(SURFACE)),
        rows[0],
    );

    let visible = rows[1].height.max(1) as usize;
    app.report_max_scroll = content_lines.len().saturating_sub(visible);
    app.report_scroll = app.report_scroll.min(app.report_max_scroll);
    let body: Vec<Line> = content_lines
        .into_iter()
        .skip(app.report_scroll)
        .take(visible)
        .map(|line| Line::styled(line, Style::default().fg(Color::Gray)))
        .collect();
    frame.render_widget(
        Paragraph::new(Text::from(body))
            .style(Style::default().bg(SURFACE))
            .wrap(Wrap { trim: false }),
        rows[1],
    );

    app.register_hit_region(rows[2], SemanticAction::Back);
    frame.render_widget(
        Paragraph::new("↑↓ rolar · enter ou esc  voltar")
            .alignment(Alignment::Right)
            .style(
                Style::default()
                    .fg(ACCENT)
                    .bg(if app.mouse_over_overlay(rows[2]) {
                        SURFACE_HOVER
                    } else {
                        SURFACE
                    }),
            ),
        rows[2],
    );
}

/// Painel ao vivo "Atividade da IA": o que a IA fez e está fazendo durante a
/// execução, sem o ruído das saídas das ferramentas de varredura.
pub fn render_ai_timeline(app: &mut AppState, frame: &mut Frame, area: Rect) {
    use ratatui::widgets::Wrap;
    app.hit_regions.clear();
    let popup = centered_fixed(
        area,
        area.width.saturating_sub(4).clamp(60, 110),
        area.height.saturating_sub(2).clamp(12, 24),
    );
    frame.render_widget(Clear, popup);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(ACCENT))
        .title(" Atividade da IA ")
        .title_style(Style::default().fg(Color::White).bold())
        .style(Style::default().bg(SURFACE));
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let rows = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(1),
        Constraint::Length(8),
        Constraint::Length(1),
    ])
    .split(inner);
    frame.render_widget(
        Paragraph::new(format!(
            "{} ação(ões) registradas · horário local",
            app.ai_timeline.len()
        ))
        .style(Style::default().fg(MUTED).bg(SURFACE)),
        rows[0],
    );

    let visible = rows[1].height.max(1) as usize;
    app.ai_timeline_max_scroll = app.ai_timeline.len().saturating_sub(visible);
    app.ai_timeline_scroll = if app.ai_timeline_follow {
        app.ai_timeline_max_scroll
    } else {
        app.ai_timeline_scroll.min(app.ai_timeline_max_scroll)
    };
    let detail_index = if app.ai_timeline_follow {
        app.ai_timeline.len().saturating_sub(1)
    } else {
        app.ai_timeline_scroll
    };
    if app.ai_timeline.is_empty() {
        frame.render_widget(
            Paragraph::new(
                "A IA ainda não agiu nesta execução; ela atua antes do Nuclei \
                 (planejamento) e depois das ferramentas (análise e agente de código).",
            )
            .wrap(Wrap { trim: false })
            .style(Style::default().fg(MUTED).bg(SURFACE)),
            rows[1],
        );
    } else {
        let first = app.ai_timeline_scroll;
        let body: Vec<Line> = app
            .ai_timeline
            .iter()
            .skip(first)
            .take(visible)
            .enumerate()
            .map(|(offset, entry)| {
                let index = first + offset;
                let selected = index == detail_index;
                let origin_color = match entry.origin {
                    AiTimelineOrigin::Planning => ACCENT,
                    AiTimelineOrigin::Ai => SUCCESS,
                    AiTimelineOrigin::Code => WARNING,
                };
                let row_style = if selected {
                    Style::default().bg(SURFACE_ACTIVE)
                } else {
                    Style::default().bg(SURFACE)
                };
                let mut line = Line::from(vec![
                    Span::styled(
                        if selected { "> " } else { "  " },
                        row_style.fg(ACCENT).bold(),
                    ),
                    Span::styled(format!("{} ", entry.time), row_style.fg(MUTED)),
                    Span::styled(
                        format!("{:<12} ", entry.origin.label()),
                        row_style.fg(origin_color).bold(),
                    ),
                    Span::styled(
                        crate::tui::chrome::truncate_width(
                            entry.text.lines().next().unwrap_or(""),
                            rows[1].width.saturating_sub(24) as usize,
                        ),
                        row_style.fg(TEXT),
                    ),
                ]);
                if selected {
                    line = line.style(row_style.bold());
                }
                line
            })
            .collect();
        frame.render_widget(
            Paragraph::new(Text::from(body)).style(Style::default().bg(SURFACE)),
            rows[1],
        );
    }

    let mut detail_lines = vec![Line::styled(
        "Detalhe completo da ação selecionada",
        Style::default().fg(ACCENT).bold(),
    )];
    if let Some(entry) = app
        .ai_timeline
        .get(detail_index)
        .or_else(|| app.ai_timeline.last())
    {
        detail_lines.push(Line::styled(
            format!("{} · {}", entry.time, entry.origin.label()),
            Style::default().fg(TEXT_SOFT),
        ));
        for line in entry.text.lines() {
            detail_lines.push(Line::styled(line.to_string(), Style::default().fg(TEXT)));
        }
    } else {
        detail_lines.push(Line::styled(
            "nenhuma ação registrada ainda".to_string(),
            Style::default().fg(TEXT_SOFT),
        ));
    }
    let detail_block = Paragraph::new(detail_lines)
        .wrap(Wrap { trim: false })
        .style(Style::default().fg(TEXT).bg(SURFACE));
    frame.render_widget(detail_block, rows[2]);

    app.register_hit_region(rows[3], SemanticAction::Back);
    frame.render_widget(
        Paragraph::new("↑↓ seleciona · enter ou esc  fechar")
            .alignment(Alignment::Right)
            .style(Style::default().fg(ACCENT).bg(SURFACE)),
        rows[3],
    );
}

fn shortcut<'a>(key: &'a str, description: &'a str) -> Line<'a> {
    Line::from(vec![
        Span::styled(format!("{key:<18}"), Style::default().fg(ACCENT).bold()),
        Span::styled(description, Style::default().fg(Color::Gray)),
    ])
}

pub(crate) fn centered_fixed(area: Rect, width: u16, height: u16) -> Rect {
    let width = width.min(area.width.saturating_sub(2)).max(1);
    let height = height.min(area.height.saturating_sub(2)).max(1);
    Rect::new(
        area.x + area.width.saturating_sub(width) / 2,
        area.y + area.height.saturating_sub(height) / 2,
        width,
        height,
    )
}
