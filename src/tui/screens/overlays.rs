use crate::tui::chrome::{
    ACCENT, SUCCESS, SURFACE, SURFACE_ACTIVE, SURFACE_HOVER, TEXT, TEXT_SOFT, WARNING,
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
use unicode_width::UnicodeWidthStr;

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

/// Painel de revisão "Atividade da IA": o que a IA fez e está fazendo durante a
/// execução, sem o ruído das saídas das ferramentas de varredura. A lista tem
/// seleção própria e o `enter` abre o evento em tela cheia dentro do painel.
pub fn render_ai_timeline(app: &mut AppState, frame: &mut Frame, area: Rect) {
    app.hit_regions.clear();
    let popup = centered_fixed(
        area,
        area.width.saturating_sub(4).clamp(60, 120),
        area.height.saturating_sub(2).clamp(12, 32),
    );
    // Limpa a área inteira, não só o popup: sem isso, os painéis da tela de
    // origem aparecem nas bordas e parecem fazer parte da revisão da IA.
    frame.render_widget(Clear, area);
    frame.render_widget(Clear, popup);
    let title = if app.ai_timeline_detail_open {
        " Atividade da IA · detalhe do evento "
    } else {
        " Atividade da IA · revisão "
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(ACCENT))
        .title(title)
        .title_style(Style::default().fg(Color::White).bold())
        .style(Style::default().bg(SURFACE));
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    if app.ai_timeline_detail_open {
        render_ai_timeline_detail(app, frame, inner);
    } else {
        render_ai_timeline_list(app, frame, inner);
    }
}

fn render_ai_timeline_list(app: &mut AppState, frame: &mut Frame, inner: Rect) {
    use ratatui::widgets::Wrap;

    render_ai_timeline_header(app, frame, Rect::new(inner.x, inner.y, inner.width, 1));

    let body_area = Rect::new(
        inner.x,
        inner.y.saturating_add(1),
        inner.width,
        inner.height.saturating_sub(2),
    );
    let footer_area = Rect::new(
        inner.x,
        inner.y + inner.height.saturating_sub(1),
        inner.width,
        1,
    );

    if app.ai_timeline.is_empty() {
        let list_block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(ACCENT))
            .title(" Ações ")
            .title_style(Style::default().fg(TEXT).bold())
            .style(Style::default().bg(SURFACE));
        let list_inner = list_block.inner(body_area);
        frame.render_widget(list_block, body_area);
        frame.render_widget(
            Paragraph::new(Text::from(vec![
                Line::styled(
                    "A IA ainda não agiu nesta execução.",
                    Style::default().fg(TEXT).bold(),
                ),
                Line::from(""),
                Line::styled(
                    "Ela atua antes do Nuclei (planejamento) e depois das ferramentas",
                    Style::default().fg(TEXT_SOFT),
                ),
                Line::styled(
                    "(análise e agente de código).",
                    Style::default().fg(TEXT_SOFT),
                ),
            ]))
            .wrap(Wrap { trim: false })
            .style(Style::default().bg(SURFACE)),
            list_inner,
        );
        render_ai_timeline_footer(app, frame, footer_area, None, "esc fecha");
        return;
    }

    // A lista ocupa o espaço restante; o detalhe resumido ganha um painel fixo
    // para não competir com as linhas da lista em 80x24.
    let detail_height = (body_area.height.saturating_sub(1) * 45 / 100).clamp(6, 14);
    let chunks =
        Layout::vertical([Constraint::Min(2), Constraint::Length(detail_height)]).split(body_area);
    let list_area = chunks[0];
    let detail_area = chunks[1];

    let list_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(ACCENT))
        .title(" Ações ")
        .title_style(Style::default().fg(TEXT).bold())
        .style(Style::default().bg(SURFACE));
    let list_inner = list_block.inner(list_area);
    frame.render_widget(list_block, list_area);

    let length = app.ai_timeline.len();
    let visible = list_inner.height.max(1) as usize;
    app.ai_timeline_visible_height = visible;
    app.ai_timeline_max_scroll = length.saturating_sub(visible);
    if app.ai_timeline_follow {
        app.ai_timeline_selected = length - 1;
        app.ai_timeline_scroll = app.ai_timeline_max_scroll;
    } else {
        app.ai_timeline_reveal_selection();
    }
    app.ai_timeline_selected = app.ai_timeline_selected.min(length - 1);

    let first = app.ai_timeline_scroll.min(app.ai_timeline_max_scroll);
    let text_width = list_inner.width.saturating_sub(26) as usize;
    let mut lines = Vec::with_capacity(visible);
    for offset in 0..visible {
        let index = first + offset;
        let Some(entry) = app.ai_timeline.get(index) else {
            break;
        };
        let selected = index == app.ai_timeline_selected;
        let origin_color = ai_origin_color(entry.origin);
        let row_style = if selected {
            Style::default().bg(SURFACE_ACTIVE).fg(TEXT).bold()
        } else {
            Style::default().bg(SURFACE).fg(TEXT)
        };
        let first_line = entry.text.lines().next().unwrap_or("");
        lines.push(Line::from(vec![
            Span::styled(
                if selected { "> " } else { "  " },
                row_style.fg(origin_color).bold(),
            ),
            Span::styled(
                format!("{}  ", entry.time),
                row_style.fg(if selected { TEXT } else { TEXT_SOFT }),
            ),
            Span::styled(
                format!("{:<12}  ", entry.origin.label()),
                row_style.fg(origin_color).bold(),
            ),
            Span::styled(
                crate::tui::chrome::truncate_width(first_line, text_width),
                row_style.fg(TEXT),
            ),
        ]));
    }
    frame.render_widget(
        Paragraph::new(Text::from(lines)).style(Style::default().bg(SURFACE)),
        list_inner,
    );

    render_ai_selected_detail(app, frame, detail_area);

    let indicator = if length > visible {
        let last = (first + visible).min(length);
        Some(format!("↑↓ rolar · {}-{} de {}", first + 1, last, length))
    } else {
        None
    };
    render_ai_timeline_footer(app, frame, footer_area, indicator, "enter abre · esc fecha");
}

fn render_ai_timeline_header(app: &AppState, frame: &mut Frame, area: Rect) {
    let (planning, ai, code) = app.ai_timeline_origin_counts();
    let line = Line::from(vec![
        Span::styled(
            format!("{} ação(ões) registradas", app.ai_timeline.len()),
            Style::default().fg(TEXT).bold(),
        ),
        Span::styled("  ·  ", Style::default().fg(TEXT_SOFT)),
        Span::styled(
            format!("planejamento {planning}"),
            Style::default().fg(ACCENT).bold(),
        ),
        Span::styled("  ·  ", Style::default().fg(TEXT_SOFT)),
        Span::styled(format!("IA {ai}"), Style::default().fg(SUCCESS).bold()),
        Span::styled("  ·  ", Style::default().fg(TEXT_SOFT)),
        Span::styled(
            format!("código {code}"),
            Style::default().fg(WARNING).bold(),
        ),
    ]);
    frame.render_widget(
        Paragraph::new(line).style(Style::default().bg(SURFACE)),
        area,
    );
}

fn render_ai_selected_detail(app: &AppState, frame: &mut Frame, area: Rect) {
    use ratatui::widgets::Wrap;

    let entry = app.ai_timeline.get(app.ai_timeline_selected);
    let border = entry.map_or(ACCENT, |entry| ai_origin_color(entry.origin));
    let title = entry.map_or_else(
        || " Evento selecionado ".to_string(),
        |entry| {
            format!(
                " Evento selecionado · {} · {} ",
                entry.origin.label(),
                entry.time
            )
        },
    );
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border))
        .title(title)
        .title_style(Style::default().fg(TEXT).bold())
        .style(Style::default().bg(SURFACE));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let body = entry.map_or_else(
        || {
            Text::from(Line::styled(
                "nenhuma ação registrada ainda".to_string(),
                Style::default().fg(TEXT_SOFT),
            ))
        },
        |entry| {
            Text::from(
                entry
                    .text
                    .lines()
                    .map(|line| Line::styled(line.to_string(), Style::default().fg(TEXT)))
                    .collect::<Vec<_>>(),
            )
        },
    );
    frame.render_widget(
        Paragraph::new(body)
            .wrap(Wrap { trim: false })
            .style(Style::default().bg(SURFACE)),
        inner,
    );
}

fn render_ai_timeline_detail(app: &mut AppState, frame: &mut Frame, inner: Rect) {
    use ratatui::widgets::Wrap;

    let length = app.ai_timeline.len();
    let index = app.ai_timeline_selected.min(length.saturating_sub(1));
    let Some(entry) = app.ai_timeline.get(index) else {
        render_ai_timeline_footer(app, frame, inner, None, "esc fecha");
        return;
    };

    let header_area = Rect::new(inner.x, inner.y, inner.width, 1);
    let body_area = Rect::new(
        inner.x,
        inner.y.saturating_add(1),
        inner.width,
        inner.height.saturating_sub(2),
    );
    let footer_area = Rect::new(
        inner.x,
        inner.y + inner.height.saturating_sub(1),
        inner.width,
        1,
    );
    let origin_color = ai_origin_color(entry.origin);
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("Evento ", Style::default().fg(TEXT_SOFT)),
            Span::styled(
                format!("{} de {}", index + 1, length),
                Style::default().fg(TEXT).bold(),
            ),
            Span::styled("  ·  ", Style::default().fg(TEXT_SOFT)),
            Span::styled(entry.time.clone(), Style::default().fg(TEXT).bold()),
            Span::styled("  ·  ", Style::default().fg(TEXT_SOFT)),
            Span::styled(
                entry.origin.label().to_string(),
                Style::default().fg(origin_color).bold(),
            ),
            Span::styled("  ·  texto completo", Style::default().fg(TEXT_SOFT)),
        ]))
        .style(Style::default().bg(SURFACE)),
        header_area,
    );

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(origin_color))
        .title(" Texto completo ")
        .title_style(Style::default().fg(TEXT).bold())
        .style(Style::default().bg(SURFACE));
    let body_inner = block.inner(body_area);
    frame.render_widget(block, body_area);

    let paragraph = Paragraph::new(entry.text.clone())
        .wrap(Wrap { trim: false })
        .style(Style::default().fg(TEXT).bg(SURFACE));
    let total_lines = paragraph.line_count(body_inner.width);
    let visible = body_inner.height.max(1) as usize;
    app.ai_timeline_detail_max_scroll = total_lines.saturating_sub(visible);
    app.ai_timeline_detail_scroll = app
        .ai_timeline_detail_scroll
        .min(app.ai_timeline_detail_max_scroll);
    frame.render_widget(
        paragraph.scroll((app.ai_timeline_detail_scroll as u16, 0)),
        body_inner,
    );

    let indicator = if total_lines > visible {
        let first = app.ai_timeline_detail_scroll + 1;
        let last = (app.ai_timeline_detail_scroll + visible).min(total_lines);
        Some(format!("↑↓ rolar · {first}-{last} de {total_lines}"))
    } else {
        None
    };
    render_ai_timeline_footer(app, frame, footer_area, indicator, "esc volta à lista");
}

fn render_ai_timeline_footer(
    app: &mut AppState,
    frame: &mut Frame,
    area: Rect,
    indicator: Option<String>,
    hint: &str,
) {
    let hint_width = (hint.width() as u16).min(area.width);
    let hint_area = Rect::new(
        area.x + area.width.saturating_sub(hint_width),
        area.y,
        hint_width,
        1,
    );
    if let Some(indicator) = indicator {
        let indicator_width = area.width.saturating_sub(hint_width + 1);
        if indicator_width > 0 {
            frame.render_widget(
                Paragraph::new(crate::tui::chrome::truncate_width(
                    &indicator,
                    indicator_width as usize,
                ))
                .style(Style::default().fg(TEXT_SOFT).bg(SURFACE)),
                Rect::new(area.x, area.y, indicator_width, 1),
            );
        }
    }
    let hovered = app.mouse_over_overlay(hint_area);
    frame.render_widget(
        Paragraph::new(hint).alignment(Alignment::Right).style(
            Style::default()
                .fg(if hovered { Color::White } else { ACCENT })
                .bg(if hovered { SURFACE_HOVER } else { SURFACE })
                .bold(),
        ),
        hint_area,
    );
    app.register_hit_region(hint_area, SemanticAction::Back);
}

fn ai_origin_color(origin: AiTimelineOrigin) -> Color {
    match origin {
        AiTimelineOrigin::Planning => ACCENT,
        AiTimelineOrigin::Ai => SUCCESS,
        AiTimelineOrigin::Code => WARNING,
    }
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
