//! SmartSec - Security Analysis Platform
//!
//! Entry point: `CommandLineInterface::main`.
//!
//! Supports two modes:
//! - TUI mode (default): interactive terminal UI
//! - Headless mode: invoked with `--auto --url <target>` — runs the full
//!   pipeline and prints a summary report to stdout without launching the TUI.

mod ai;
mod config;
mod domain;
mod llm;
mod orchestrator;
mod report;
mod tools;
mod tui;
mod utils;

use crate::config::execution_type::ExecutionType;
use crate::domain::security_tool::ToolInfo;
use crate::domain::Severity;
use crate::orchestrator::Orchestrator;
use anyhow::Result;
use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
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
        if let Some(url) = extract_arg(&self.arguments, "--url") {
            let mut initial_config = config::Configuration::load(&[])?;
            initial_config.target_url = url;
            initial_config.execution_type = ExecutionType::Auto;
            if self.arguments.iter().any(|a| a == "--auto") {
                return Self::run_headless(initial_config).await;
            }
            return Self::display_tui(initial_config).await;
        }

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

    pub async fn run_headless(config: config::Configuration) -> Result<()> {
        if let Err(e) = config.validate_target() {
            eprintln!("[smartsec] invalid target: {}", e);
            std::process::exit(2);
        }

        println!("═══════════════════════════════════════════════════════════");
        println!("  SmartSec — Headless Analysis");
        println!("═══════════════════════════════════════════════════════════");
        println!("  Target: {}", config.target_url);
        println!("  Mode:   {}", config.execution_type);
        println!("  LLM:    {:?} ({})", config.llm.provider, config.llm.model);
        println!(
            "  Nmap:   {}",
            if config.use_real_nmap {
                "REAL execution"
            } else {
                "MOCK execution"
            }
        );
        println!();

        let mut orchestrator = Orchestrator::new(config.clone());
        let all_tools = ToolInfo::all();
        let selected: Vec<&ToolInfo> = all_tools.iter().collect();

        println!("[1/3] Running security tools...");
        let total = selected.len();
        for (i, tool) in selected.iter().enumerate() {
            if orchestrator.cancelled {
                println!("  ✖ Cancelled.");
                return Ok(());
            }
            if orchestrator.paused {
                loop {
                    if !orchestrator.paused || orchestrator.cancelled {
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }
            print!("  [{:>2}/{:>2}] {:<12} ", i + 1, total, tool.name);
            use std::io::Write;
            let _ = std::io::stdout().flush();
            let exec = orchestrator.execute_tool(tool, &config.target_url).await;
            println!(
                "✓ ({}, {} bytes output)",
                exec.executed_at,
                exec.output.len()
            );
        }
        println!();

        orchestrator.build_findings();
        let analysis = orchestrator
            .agent
            .analyze_logs(&orchestrator.findings)
            .await;
        orchestrator.last_log = analysis.clone();

        println!(
            "[2/3] AI analysis ({} findings):",
            orchestrator.findings.len()
        );
        for line in analysis.lines() {
            println!("  │ {}", line);
        }
        println!();

        let report =
            crate::report::ReportGenerator::compile_report(&config, &orchestrator.findings);
        let crit = orchestrator
            .findings
            .iter()
            .filter(|v| v.severity == Severity::Critical)
            .count();
        let high = orchestrator
            .findings
            .iter()
            .filter(|v| v.severity == Severity::High)
            .count();
        let med = orchestrator
            .findings
            .iter()
            .filter(|v| v.severity == Severity::Medium)
            .count();
        let low = orchestrator
            .findings
            .iter()
            .filter(|v| v.severity == Severity::Low)
            .count();

        println!("[3/3] Summary");
        println!("───────────────────────────────────────────────────────────");
        println!("  Total findings: {}", orchestrator.findings.len());
        println!(
            "  CRITICAL: {}   HIGH: {}   MEDIUM: {}   LOW: {}",
            crit, high, med, low
        );
        println!();
        println!("  Next step: {}", orchestrator.determine_next_step());
        println!("  Container: {}", orchestrator.container_id());
        println!();
        println!("═══════════════════════════════════════════════════════════");
        println!("  ✓ Relatório exportado: smartsec-report.md (simulado)");
        println!("  ✓ Análise concluída.");
        println!("═══════════════════════════════════════════════════════════");

        let _ = report;
        Ok(())
    }
}

fn extract_arg(args: &[String], flag: &str) -> Option<String> {
    let pos = args.iter().position(|a| a == flag)?;
    args.get(pos + 1).cloned()
}

#[tokio::main]
async fn main() -> Result<()> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let cli = CommandLineInterface::new(arguments);
    cli.run().await
}
