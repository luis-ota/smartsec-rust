pub mod analysis;
pub mod execution;
pub mod results;
pub mod splash;
pub mod tools;

use crate::app::{AppState, AppStep};
use ratatui::{layout::Rect, Frame};

pub fn render(app: &mut AppState, frame: &mut Frame) {
    let area = frame.area();
    app.screen_area = area;
    match app.step {
        AppStep::Splash => splash::render(app, frame, area),
        AppStep::ToolSelect => tools::render(app, frame, area),
        AppStep::Execution => execution::render(app, frame, area),
        AppStep::Analysis => analysis::render(app, frame, area),
        AppStep::Results => results::render(app, frame, area),
    }
}

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
