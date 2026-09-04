pub mod commands;
pub mod event;
pub mod interaction;
pub mod screens;
pub mod state;

use crate::tui::state::AppState;
use ratatui::{layout::Rect, Frame};

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

    if app.show_help_overlay {
        screens::overlays::render_help(app, frame, area);
    } else if app.show_command_palette {
        screens::overlays::render_command_palette(app, frame, area);
    }
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
