pub mod event;
pub mod interaction;
pub mod screens;
pub mod state;

use crate::tui::state::AppState;
use ratatui::{
    layout::Rect,
    style::{Color, Style, Stylize},
    text::{Line, Span},
    widgets::{Paragraph, Wrap},
    Frame,
};

pub fn render(app: &mut AppState, frame: &mut Frame) {
    let area = frame.area();
    app.begin_frame(area);

    if app.show_settings {
        screens::settings::render(app, frame, area);
    } else {
        match app.step {
            AppStep::Splash => screens::splash::render(app, frame, area),
            AppStep::ToolSelect => screens::tools::render(app, frame, area),
            AppStep::Execution => screens::execution::render(app, frame, area),
            AppStep::Analysis => screens::analysis::render(app, frame, area),
            AppStep::Results => screens::results::render(app, frame, area),
        }
    }

    if app.command_palette_hint.is_some() {
        render_command_palette(app, frame, area);
    }
}

fn render_command_palette(app: &AppState, frame: &mut Frame, area: Rect) {
    let hint = app.command_palette_hint.as_deref().unwrap_or("C-x _");
    let palette_height: u16 = 3;
    let palette_area = Rect {
        x: area.x,
        y: area.y + area.height.saturating_sub(palette_height),
        width: area.width,
        height: palette_height,
    };
    let line = Line::from(vec![
        Span::styled(" ▸ ", Style::default().fg(Color::Cyan).bold()),
        Span::styled(hint, Style::default().fg(Color::White).bold()),
    ]);
    let para = Paragraph::new(line)
        .style(Style::default().bg(Color::Rgb(20, 20, 40)))
        .wrap(Wrap { trim: false });
    frame.render_widget(para, palette_area);
}

use crate::tui::state::AppStep;

pub fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_w = r.width * percent_x / 100;
    let popup_h = r.height * percent_y / 100;
    Rect {
        x: r.x + (r.width.saturating_sub(popup_w)) / 2,
        y: r.y + (r.height.saturating_sub(popup_h)) / 2,
        width: popup_w.max(1),
        height: popup_h.max(1),
    }
}
