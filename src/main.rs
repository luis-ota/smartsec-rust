//! SmartSec - Security Analysis Platform
//!
//! Entry point: `CommandLineInterface::main`.

mod ai;
mod config;
mod domain;
mod llm;
mod orchestrator;
mod report;
mod tools;
mod tui;
mod utils;

use anyhow::Result;
use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{Terminal, backend::CrosstermBackend};
use std::io;

/// CommandLineInterface (per class diagram).
///
/// Responsible for parsing arguments, initializing configuration, and
/// displaying the TUI. The actual analysis work is delegated to the
/// [`orchestrator::Orchestrator`].
pub struct CommandLineInterface {
    pub arguments: Vec<String>,
}

impl CommandLineInterface {
    pub fn new(arguments: Vec<String>) -> Self {
        Self { arguments }
    }

    pub async fn run(self) -> Result<()> {
        let initial_config = config::Configuration::load(&self.arguments)?;
        Self::display_tui(initial_config).await
    }

    async fn display_tui(initial_config: config::Configuration) -> Result<()> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;

        let mut app = tui::state::AppState::new(initial_config);
        let result = Self::tui_loop(&mut terminal, &mut app).await;

        disable_raw_mode()?;
        execute!(
            terminal.backend_mut(),
            LeaveAlternateScreen,
            DisableMouseCapture
        )?;
        terminal.show_cursor()?;

        result
    }

    async fn tui_loop(
        terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
        app: &mut tui::state::AppState,
    ) -> Result<()> {
        loop {
            terminal.draw(|f| tui::render(app, f))?;

            let should_quit = tui::event::handle_events(app)?;
            if should_quit || app.should_quit {
                return Ok(());
            }

            app.tick();
            app.step_tick().await;

            if app.should_quit {
                return Ok(());
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let cli = CommandLineInterface::new(arguments);
    cli.run().await
}
