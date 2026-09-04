use crate::tui::commands::command_items;
use crate::tui::interaction::SemanticAction;
use crate::tui::state::{AppState, AppStep};
use ratatui::{
    layout::{Alignment, Constraint, Layout, Rect},
    style::{Color, Style, Stylize},
    text::{Line, Span, Text},
    widgets::{Block, Borders, Clear, Paragraph},
    Frame,
};

const SURFACE: Color = Color::Rgb(18, 20, 24);
const ACCENT: Color = Color::Rgb(70, 190, 200);

pub fn render_help(app: &mut AppState, frame: &mut Frame, area: Rect) {
    app.hit_regions.clear();
    let popup = centered_fixed(area, 68, 18);
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
        "Configure o provedor de IA, consentimento e opções de execução."
    } else {
        match app.step {
            AppStep::Splash => "Defina o alvo, o modo de execução e inicie a análise.",
            AppStep::ToolSelect => "Escolha as ferramentas que serão executadas contra o alvo.",
            AppStep::Execution => "Acompanhe o progresso, pause ou cancele a execução.",
            AppStep::Analysis => "Aguarde a correlação dos achados e a geração das recomendações.",
            AppStep::Results => "Revise os achados, abra detalhes e exporte o relatório.",
        }
    };
    let lines = vec![
        Line::styled(context, Style::default().fg(Color::Gray)),
        Line::from(""),
        shortcut("tab / shift+tab", "mover o foco"),
        shortcut("setas", "navegar ou rolar"),
        shortcut("enter / espaço", "acionar o item em foco"),
        shortcut("esc", "fechar ou voltar"),
        shortcut("f1", "abrir ajuda em qualquer contexto"),
        shortcut("ctrl+p", "abrir a paleta de comandos"),
        Line::from(""),
        Line::styled(
            "O mouse oferece as mesmas ações disponíveis pelo teclado.",
            Style::default().fg(Color::DarkGray),
        ),
    ];
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
            .style(Style::default().fg(ACCENT).bg(SURFACE)),
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
        let foreground = if !item.enabled {
            Color::DarkGray
        } else if selected {
            Color::Black
        } else {
            Color::Gray
        };
        let background = if selected { ACCENT } else { SURFACE };
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
        if item.enabled && index < chunks[1].height as usize {
            app.register_hit_region(
                Rect::new(chunks[1].x, chunks[1].y + index as u16, chunks[1].width, 1),
                SemanticAction::ExecuteCommand(index),
            );
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

fn shortcut<'a>(key: &'a str, description: &'a str) -> Line<'a> {
    Line::from(vec![
        Span::styled(format!("{key:<18}"), Style::default().fg(ACCENT).bold()),
        Span::styled(description, Style::default().fg(Color::Gray)),
    ])
}

fn centered_fixed(area: Rect, width: u16, height: u16) -> Rect {
    let width = width.min(area.width.saturating_sub(2)).max(1);
    let height = height.min(area.height.saturating_sub(2)).max(1);
    Rect::new(
        area.x + area.width.saturating_sub(width) / 2,
        area.y + area.height.saturating_sub(height) / 2,
        width,
        height,
    )
}
