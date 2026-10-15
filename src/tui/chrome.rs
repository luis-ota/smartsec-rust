use crate::tui::interaction::SemanticAction;
use crate::tui::state::{AppState, AppStep};
use ratatui::{
    layout::{Alignment, Constraint, Layout, Rect},
    style::{Color, Style, Stylize},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
    Frame,
};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

pub const BACKGROUND: Color = Color::Rgb(10, 12, 15);
pub const SURFACE: Color = Color::Rgb(17, 20, 24);
pub const SURFACE_ACTIVE: Color = Color::Rgb(28, 34, 39);
/// Fundo de hover: mais claro que `SURFACE` sem competir com o foco.
pub const SURFACE_HOVER: Color = Color::Rgb(42, 51, 59);
pub const BORDER: Color = Color::Rgb(55, 62, 68);
pub const TEXT: Color = Color::Rgb(224, 229, 232);
pub const MUTED: Color = Color::Rgb(125, 134, 140);
pub const ACCENT: Color = Color::Rgb(70, 190, 200);
/// Realce do botão primário sob o mouse: o mesmo accent, mais claro.
pub const ACCENT_HOVER: Color = Color::Rgb(132, 230, 240);
pub const SUCCESS: Color = Color::Rgb(92, 184, 122);
pub const WARNING: Color = Color::Rgb(215, 174, 87);
pub const DANGER: Color = Color::Rgb(220, 100, 100);

pub struct ShellAreas {
    pub content: Rect,
}

pub struct ButtonState {
    pub focused: bool,
    pub primary: bool,
    pub enabled: bool,
}

impl ButtonState {
    pub const fn primary(focused: bool) -> Self {
        Self {
            focused,
            primary: true,
            enabled: true,
        }
    }

    pub const fn secondary(focused: bool) -> Self {
        Self {
            focused,
            primary: false,
            enabled: true,
        }
    }

    pub const fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }
}

pub fn render_shell(
    app: &mut AppState,
    frame: &mut Frame,
    area: Rect,
    title: &str,
    status: &str,
) -> ShellAreas {
    frame.render_widget(
        Block::default().style(Style::default().bg(BACKGROUND)),
        area,
    );
    let chunks = Layout::vertical([
        Constraint::Length(2),
        Constraint::Min(1),
        Constraint::Length(1),
    ])
    .split(area);
    render_header(app, frame, chunks[0], title);
    render_status_bar(app, frame, chunks[2], status);
    ShellAreas { content: chunks[1] }
}

fn render_header(app: &AppState, frame: &mut Frame, area: Rect, title: &str) {
    let step = match app.step {
        AppStep::Splash => "01",
        AppStep::ToolSelect => "02",
        AppStep::Execution => "03",
        AppStep::Analysis => "04",
        AppStep::Results => "05",
        AppStep::History => "06",
    };
    let left = format!(" SmartSec  /  {title}");
    let target_width = area.width.saturating_sub(left.width() as u16 + 10) as usize;
    let target = if app.config.target_url.is_empty() {
        "sem alvo".to_string()
    } else {
        truncate_width(&app.config.target_url, target_width)
    };
    let header = Line::from(vec![
        Span::styled(
            " SmartSec ",
            Style::default().fg(Color::Black).bg(ACCENT).bold(),
        ),
        Span::styled(" / ", Style::default().fg(BORDER)),
        Span::styled(title.to_string(), Style::default().fg(TEXT).bold()),
        Span::styled(format!("  {step}/06"), Style::default().fg(MUTED)),
        Span::styled(format!("  {target}"), Style::default().fg(MUTED)),
    ]);
    let block = Block::default()
        .borders(Borders::BOTTOM)
        .border_style(Style::default().fg(BORDER))
        .style(Style::default().bg(SURFACE));
    frame.render_widget(Paragraph::new(header).block(block), area);
}

fn render_status_bar(app: &mut AppState, frame: &mut Frame, area: Rect, status: &str) {
    const HELP: &str = "f1 ajuda";
    const COMMANDS: &str = "ctrl+p comandos";
    let right_width = HELP.width() + 2 + COMMANDS.width() + 1;
    let right_x = area.x + area.width.saturating_sub(right_width as u16);
    let help_area = Rect::new(right_x, area.y, HELP.width() as u16, 1);
    let commands_area = Rect::new(
        right_x + HELP.width() as u16 + 2,
        area.y,
        COMMANDS.width() as u16,
        1,
    );
    // Coluna de separação: sem ela o status encosta no atalho ("obrigatóriof1 ajuda").
    let status_width = area.width.saturating_sub(right_width as u16 + 4) as usize;
    let status = truncate_width(status, status_width);
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(" ", Style::default().bg(SURFACE)),
            Span::styled("● ", Style::default().fg(status_color(app)).bg(SURFACE)),
            Span::styled(status, Style::default().fg(MUTED).bg(SURFACE)),
        ]))
        .style(Style::default().bg(SURFACE)),
        area,
    );
    let shortcut_style = |hovered: bool| {
        Style::default()
            .fg(if hovered { ACCENT } else { TEXT })
            .bg(if hovered { SURFACE_HOVER } else { SURFACE })
    };
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(HELP, shortcut_style(app.mouse_over(help_area))),
            Span::styled("  ", Style::default().fg(MUTED)),
            Span::styled(COMMANDS, shortcut_style(app.mouse_over(commands_area))),
            Span::raw(" "),
        ]))
        .alignment(Alignment::Right)
        .style(Style::default().bg(SURFACE)),
        area,
    );
    app.register_hit_region(help_area, SemanticAction::OpenHelp);
    app.register_hit_region(commands_area, SemanticAction::OpenCommandPalette);
}

fn status_color(app: &AppState) -> Color {
    if app.exec_cancelled {
        DANGER
    } else if app.llm_warning.is_some() || app.run_error.is_some() {
        WARNING
    } else {
        SUCCESS
    }
}

pub fn panel<'a>(title: &'a str, focused: bool) -> Block<'a> {
    Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(if focused { ACCENT } else { BORDER }))
        .title(format!(" {title} "))
        .title_style(
            Style::default()
                .fg(if focused { TEXT } else { MUTED })
                .bold(),
        )
        .style(Style::default().bg(SURFACE))
}

/// Painel cuja área inteira é clicável: a borda e o título acendem sob o mouse
/// sem alterar o layout nem o realce de foco do teclado.
pub fn panel_hover<'a>(title: &'a str, focused: bool, hovered: bool) -> Block<'a> {
    if hovered && !focused {
        panel(title, focused)
            .border_style(Style::default().fg(ACCENT))
            .title_style(Style::default().fg(ACCENT).bold())
    } else {
        panel(title, focused)
    }
}

pub fn render_button(
    app: &mut AppState,
    frame: &mut Frame,
    area: Rect,
    label: &str,
    action: SemanticAction,
    state: ButtonState,
) {
    let hovered = state.enabled && app.mouse_over(area);
    let (foreground, background) = if !state.enabled {
        (MUTED, SURFACE)
    } else if state.primary {
        (Color::Black, if hovered { ACCENT_HOVER } else { ACCENT })
    } else if state.focused {
        (if hovered { ACCENT } else { TEXT }, SURFACE_ACTIVE)
    } else if hovered {
        (ACCENT, SURFACE_HOVER)
    } else {
        (MUTED, SURFACE)
    };
    frame.render_widget(
        Paragraph::new(format!(
            " {}{label} ",
            if state.focused { "> " } else { "" }
        ))
        .alignment(Alignment::Center)
        .style(Style::default().fg(foreground).bg(background).bold()),
        area,
    );
    if state.enabled {
        app.register_hit_region(area, action);
    }
}

pub fn truncate_width(value: &str, max_width: usize) -> String {
    if value.width() <= max_width {
        return value.to_string();
    }
    if max_width <= 1 {
        return "…".chars().take(max_width).collect();
    }
    let mut output = String::new();
    let mut width = 0;
    for character in value.chars() {
        let character_width = character.width().unwrap_or(0);
        if width + character_width > max_width - 1 {
            break;
        }
        output.push(character);
        width += character_width;
    }
    output.push('…');
    output
}

#[cfg(test)]
mod tests {
    use super::truncate_width;
    use unicode_width::UnicodeWidthStr;

    #[test]
    fn truncates_unicode_without_slicing_bytes() {
        let value = truncate_width("https://exemplo.dev/ação", 12);
        assert!(value.width() <= 12);
        assert!(value.ends_with('…'));
    }
}
