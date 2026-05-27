mod app;
mod event;
mod mock;
mod ui;

use app::{AppMode, AppState, AppStep};
use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::io;

fn main() -> io::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = AppState::new();
    if app.mode == AppMode::Auto {
        app.url_input = "http://localhost:8080".to_string();
    }

    let result = run_app(&mut terminal, &mut app);

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    result
}

fn run_app(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut AppState,
) -> io::Result<()> {
    loop {
        terminal.draw(|f| ui::render(app, f))?;

        let should_quit = event::handle_events(app)?;
        if should_quit || app.should_quit {
            return Ok(());
        }

        app.tick += 1;
        if app.tick.is_multiple_of(3) {
            app.spinner_idx = (app.spinner_idx + 1) % 10;
        }

        match app.step {
            AppStep::Splash => {
                if app.mode == AppMode::Auto && app.tick > 5 {
                    app.url_input = "http://localhost:8080".to_string();
                    app.step = AppStep::ToolSelect;
                    app.tool_detecting = true;
                    app.tool_detect_tick = 0;
                }
            }
            AppStep::ToolSelect => {
                app.tool_detect_tick += 1;
                if app.tool_detect_tick > 30 {
                    app.tool_detecting = false;
                }
                if app.mode == AppMode::Auto {
                    app.advance_auto();
                }
            }
            AppStep::Execution => {
                app.advance_execution();
                if app.mode == AppMode::Auto {
                    app.advance_auto();
                }
            }
            AppStep::Analysis => {
                app.advance_analysis();
                if app.mode == AppMode::Auto {
                    app.advance_auto();
                }
            }
            AppStep::Results => {}
        }
    }
}
