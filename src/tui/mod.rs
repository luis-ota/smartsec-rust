pub mod chrome;
pub mod commands;
pub mod event;
pub mod interaction;
pub mod screens;
pub mod state;

#[cfg(test)]
mod snapshot_tests;

use crate::tui::state::AppState;
use ratatui::Frame;

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
