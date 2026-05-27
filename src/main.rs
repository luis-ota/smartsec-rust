mod app;
mod event;
mod mock;
mod ui;

use app::{AppMode, AppState, AppStep};
use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{Terminal, backend::CrosstermBackend};
use std::io;

fn main() -> io::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = AppState::new();

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
            AppStep::Splash => {}
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
                if app
                    .tools
                    .iter()
                    .all(|t| !t.selected || t.status == crate::app::ToolStatus::Done)
                    && app.exec_tick > 10
                {
                    app.step = crate::app::AppStep::Analysis;
                    app.analysis_phase = crate::app::AnalysisPhase::Scanning;
                    app.analysis_tick = 0;
                    app.analysis_text.clear();
                    app.analysis_full_text =
                        "Analisando padrões de vulnerabilidade across multiple scan results...\n\n\
                    Correlacionando achados com base de dados CVE/NVD...\n\n\
                    Identificando vetores de ataque e superfícies de exposição...\n\n\
                    Gerando recomendações de mitigação priorizadas por severidade...\n\n\
                    Concluindo análise de risco consolidada."
                            .to_string();
                }
                if app.mode == AppMode::Auto {
                    app.advance_auto();
                }
            }
            AppStep::Analysis => {
                app.advance_analysis();
                if app.analysis_phase == crate::app::AnalysisPhase::Complete
                    && app.analysis_tick > 20
                {
                    app.step = crate::app::AppStep::Results;
                }
                if app.mode == AppMode::Auto {
                    app.advance_auto();
                }
            }
            AppStep::Results => {}
        }
    }
}
